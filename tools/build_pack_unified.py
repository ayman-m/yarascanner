#!/usr/bin/env python3
r"""Rebuild the YaraDatasetManagement pack's unified automation YAMLs from their `.py`.

WHY THIS EXISTS
===============

An XSOAR automation is delivered as ONE yml whose `script:` key carries the whole Python
body. This pack keeps the Python in `Scripts/<Name>/<Name>.py` for review, tests and
`py_compile`, and the deliverable in `unified/<Name>.yml`. That is two copies of the same
source, and the second one is the one the tenant actually runs.

It had already drifted, silently, and in the worst possible direction:

    Scripts/YaraConsolidateFast/YaraConsolidateFast.yml   (embedded copy, shipped)
    Scripts/YaraConsolidateFast/YaraConsolidateFast.py    (reviewed, tested)

differed by exactly the `_READ_LIMIT = 50000` truncation guard -- the guard that stops the
fast path merging 50,000 of a scan's 60,000 rows and then deleting the only copy of the
other 10,000. The tests, `py_compile` and every reader saw the guarded file; the tenant
would have received the unguarded one. Nothing in the repo compared them.

So: nothing hand-edits an embedded script again. This regenerates every embedded copy from
its `.py`, and `--check` fails when any of them is stale. `tests/test_pack_unified_yaml_is_in_sync.py`
runs `--check`.

FIDELITY
========
This is not a reformatter. Run against the four unified YAMLs that existed before it, it
reproduces all four BYTE FOR BYTE -- that equivalence is what makes it safe to point at the
delivery directory, and `--check` would report any byte of churn as drift. The yml metadata
(args, outputs, comment, timeout, dockerimage, fromversion, ...) is read from, and never
invented by, `Scripts/<Name>/<Name>.yml`; only the `script:` key is replaced.

USAGE
    python3 tools/build_pack_unified.py                      # rewrite what is stale
    python3 tools/build_pack_unified.py --check              # exit 1 if anything is stale
    python3 tools/build_pack_unified.py --embed <Name> ...   # also embed into the Scripts yml

TWO FORMS OF `Scripts/<Name>/<Name>.yml`, both maintained here:
  * `script: '-'`   split form: metadata only, the `.py` sits beside it. `demisto-sdk`
                    unifies the pair at upload time.
  * embedded        self-contained: uploadable as-is, and what `--embed` converts a split
                    file into. Once embedded, this script keeps it fresh for ever after.
Either way `unified/<Name>.yml` is always written embedded -- that directory is the
console-Import set, and console Import has no `.py` to pair anything with.
"""
import argparse
import os
import sys

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.join(_HERE, "..", "xdr", "Packs", "YaraDatasetManagement")
SCRIPTS = os.path.join(PACK, "Scripts")
UNIFIED = os.path.join(PACK, "unified")


class _Literal(str):
    """A str dumped as a `|` literal block -- the only readable way to carry Python in yml."""


def _rep_literal(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.add_representer(_Literal, _rep_literal)


def automations():
    """Every `Scripts/<Name>/` holding both a `<Name>.yml` and a `<Name>.py`."""
    out = []
    for name in sorted(os.listdir(SCRIPTS)):
        d = os.path.join(SCRIPTS, name)
        if not os.path.isdir(d) or name.startswith("__"):
            continue
        ymlp = os.path.join(d, "%s.yml" % name)
        pyp = os.path.join(d, "%s.py" % name)
        if os.path.exists(ymlp) and os.path.exists(pyp):
            out.append((name, ymlp, pyp))
    return out


def render(ymlp, pyp):
    """The metadata of `ymlp`, with `script:` replaced by the current body of `pyp`.

    `sort_keys=False` preserves the key order the file already has (dumping alphabetically
    would reorder `type`/`subtype`/`dockerimage` and churn every line); `width` is set past
    any real line so a long `comment:` or argument description is never folded; and
    `allow_unicode` keeps the em dashes as em dashes instead of `\\u2014` escapes.
    """
    with open(ymlp, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    with open(pyp, encoding="utf-8") as fh:
        doc["script"] = _Literal(fh.read())
    return yaml.dump(doc, sort_keys=False, default_flow_style=False,
                     width=10 ** 9, allow_unicode=True)


def _write_if_changed(path, text, check, stale, wrote):
    old = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    if old == text:
        return
    if check:
        stale.append(path)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    wrote.append(path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="write nothing; exit 1 naming every file that is out of date")
    ap.add_argument("--embed", action="append", default=[], metavar="NAME",
                    help="also embed the script into Scripts/NAME/NAME.yml (one-time "
                         "conversion from the split 'script: -' form; afterwards it is "
                         "kept fresh automatically)")
    a = ap.parse_args(argv)

    if not os.path.isdir(UNIFIED):
        os.makedirs(UNIFIED)

    stale, wrote = [], []
    for name, ymlp, pyp in automations():
        text = render(ymlp, pyp)
        _write_if_changed(os.path.join(UNIFIED, "%s.yml" % name), text, a.check, stale, wrote)
        # The Scripts-side yml is only rewritten when it ALREADY embeds a script (or is
        # being converted now). A split 'script: -' file is left exactly as it is: it has
        # no second copy to go stale, which is the whole problem this script exists for.
        with open(ymlp, encoding="utf-8") as fh:
            embedded_here = yaml.safe_load(fh).get("script") not in ("-", "", None)
        if embedded_here or name in a.embed:
            _write_if_changed(ymlp, text, a.check, stale, wrote)

    if a.check:
        if stale:
            sys.stderr.write(
                "STALE - these embedded copies no longer match their .py:\n%s\n"
                "Run: python3 tools/build_pack_unified.py\n"
                % "\n".join("  " + os.path.relpath(p) for p in stale))
            return 1
        print("unified YAMLs are in sync with their .py (%d automation(s))"
              % len(automations()))
        return 0

    for p in wrote:
        print("wrote %s" % os.path.relpath(p))
    if not wrote:
        print("nothing to do - every embedded copy already matches its .py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
