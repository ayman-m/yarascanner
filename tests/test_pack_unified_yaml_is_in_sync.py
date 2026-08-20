"""The shipped yml must carry the same Python the tests and py_compile see.

An XSOAR automation IS its yml: the tenant runs whatever sits under that file's `script:`
key, never `Scripts/<Name>/<Name>.py`. Every embedded copy is therefore a second copy of
the source, and this repo already proved it can drift silently and in the worst direction:


differed by exactly the `_READ_LIMIT = 50000` truncation guard, i.e. the guard that stops
the fast path merging 50,000 of a 60,000-row scan and then deleting the only copy of the
other 10,000. The .py had it. The deliverable did not. Every test in this suite was green
throughout, because every test reads the .py.

So the invariant is asserted directly, not inferred: for every automation, each embedded
copy is byte-identical to its `.py`, and the metadata around it is the same metadata. The
regeneration is `tools/build_pack_unified.py`; this is its `--check` plus the structural
assertions a checksum alone would not explain.
"""
import os
import subprocess
import sys

import pytest
import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOL = os.path.join(_REPO, "tools", "build_pack_unified.py")
_PACK = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement")
_SCRIPTS = os.path.join(_PACK, "Scripts")
_UNIFIED = os.path.join(_PACK, "unified")

sys.path.insert(0, os.path.join(_REPO, "tools"))
import build_pack_unified as B  # noqa: E402


def _names():
    return [n for n, _, _ in B.automations()]


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_the_generator_reports_no_drift():
    """The single gate. Run it the way an operator would, as a subprocess, so a failure
    tells them the exact command that fixes it."""
    p = subprocess.run([sys.executable, _TOOL, "--check"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr or p.stdout


@pytest.mark.parametrize("name", _names())
def test_every_automation_ships_a_unified_yml(name):
    """`unified/` is the console-Import set. An automation missing from it is one the
    operator cannot deliver that way at all — which is how YaraConsolidateFast stood (before it was removed)
    before the summary variant was packaged."""
    assert os.path.exists(os.path.join(_UNIFIED, "%s.yml" % name))


@pytest.mark.parametrize("name", _names())
def test_the_unified_script_is_byte_identical_to_the_python(name):
    doc = _load(os.path.join(_UNIFIED, "%s.yml" % name))
    src = _read(os.path.join(_SCRIPTS, name, "%s.py" % name))
    assert doc["script"] == src, (
        "unified/%s.yml carries different Python from %s.py — the tenant would run code no "
        "test in this suite has ever seen. Run tools/build_pack_unified.py" % (name, name))


@pytest.mark.parametrize("name", _names())
def test_an_embedded_scripts_side_yml_is_the_same_file_as_the_unified_one(name):
    """`YaraConsolidateSummary` is self-contained on
    the Scripts side as well, so they are uploadable without a `.py` beside them. Three
    copies of one script only stay honest if two of them are generated from the third."""
    side = os.path.join(_SCRIPTS, name, "%s.yml" % name)
    if _load(side).get("script") == "-":
        pytest.skip("%s ships the split form; it has no second copy to drift" % name)
    assert _read(side) == _read(os.path.join(_UNIFIED, "%s.yml" % name))


@pytest.mark.parametrize("name", _names())
def test_the_unified_yml_only_adds_the_script_to_the_scripts_side_metadata(name):
    """Guards against the generator quietly becoming a reformatter: everything except
    `script` must survive the round trip unchanged, so args, outputs, defaults, timeout,
    dockerimage and fromversion are never invented here."""
    side = _load(os.path.join(_SCRIPTS, name, "%s.yml" % name))
    uni = _load(os.path.join(_UNIFIED, "%s.yml" % name))
    assert set(side) == set(uni)
    for key in sorted(set(side) - {"script"}):
        assert side[key] == uni[key], "%s: %s differs between the two ymls" % (name, key)
    assert uni["name"] == name and uni["commonfields"]["id"] == name


def test_the_generator_reproduces_a_file_it_did_not_write():
    """Fidelity check, not a tautology. `unified/YaraConsolidateApply.yml` was hand-built
    before this generator existed; rendering it must return the same bytes. If it does not,
    every other assertion here is only measuring the generator against itself."""
    name = "YaraConsolidateApply"
    rendered = B.render(os.path.join(_SCRIPTS, name, "%s.yml" % name),
                        os.path.join(_SCRIPTS, name, "%s.py" % name))
    assert rendered == _read(os.path.join(_UNIFIED, "%s.yml" % name))
