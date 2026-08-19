#!/usr/bin/env python3
"""YARA_EXTRA_SKIP_PATHS: the supported way to exclude a path, in both editions.

Every skip list is a Python literal mid-file, inside the config class rather than the
top-of-file config block. A site running CrowdStrike or SentinelOne, a large build-artifact
tree, or an unusual mount layout therefore had NO supported way to exclude it — we added
/opt/traps for the Cortex agent ourselves, but a customer could only edit the script's
internals or accept scanning their own EDR.

Two properties make an extension point safe here, and both are load-bearing:

ADDITIVE. Appended, never substituted. A replace-style knob lets one deployer's typo
silently drop the Cortex agent paths, and nothing visible changes — the scan just starts
walking /opt/traps again.

BOUNDED. Entries are forced to "/x/" so they match whole path COMPONENTS. This is not
tidiness: an unbounded "cyvera" matches any path containing that substring anywhere, so
anyone able to name a directory could hide arbitrary content inside it. That exact
regression was introduced and caught during this branch's skip-list work, which is why it
is pinned rather than trusted.

A lone "/" is rejected outright — it appears in every absolute path and would disable the
entire scan while reporting success.
"""
import base64
import importlib
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]
RULE_B64 = base64.b64encode(b'rule t { strings: $a = "AAAA" condition: $a }').decode()


def _mod(edition, env=None):
    """Reload the edition AND keep `env` live for the caller.

    _extra_skip_fragments reads os.environ when it is CALLED, not at import, so the patch
    has to outlive the reload — an earlier version of this harness let it lapse and every
    assertion silently compared against an empty environment.
    """
    patcher = mock.patch.dict(os.environ, env or {}, clear=False)
    patcher.start()
    m = importlib.reload(importlib.import_module(edition))
    return m, patcher


def _predicate(edition, env):
    m, patcher = _mod(edition, env)
    try:
        with mock.patch("platform.system", return_value="Linux"), mock.patch("os.makedirs"):
            cfg = m.ScanConfig(RULE_B64, scan_folder="/tmp")
    finally:
        patcher.stop()
    holder = type("H", (), {})()
    holder.config = cfg
    holder.scan_active = True

    def check(path):
        with mock.patch("platform.system", return_value="Linux"):
            return m.YaraScanner._is_special_file(holder, path)
    return check, cfg


@pytest.fixture(autouse=True)
def _restore():
    yield
    for name in EDITIONS:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


# ------------------------------------------------------------- normalisation
@pytest.mark.parametrize("edition", EDITIONS)
@pytest.mark.parametrize("raw,expected", [
    ("/opt/crowdstrike/", ("/opt/crowdstrike/",)),
    ("sentinelone", ("/sentinelone/",)),               # both separators supplied
    ("  /opt/x  ", ("/opt/x/",)),                      # whitespace tolerated
    ("a,b", ("/a/", "/b/")),                           # comma separated
    ("dup,dup", ("/dup/",)),                           # de-duplicated
    ("", ()),                                          # empty is not an error
])
def test_normalisation(edition, raw, expected):
    m, patcher = _mod(edition, {"YARA_EXTRA_SKIP_PATHS": raw})
    try:
        assert m._extra_skip_fragments() == expected
    finally:
        patcher.stop()


@pytest.mark.parametrize("edition", EDITIONS)
def test_lone_separator_is_rejected(edition):
    """"/" matches every absolute path; accepting it would silently scan nothing."""
    m, patcher = _mod(edition, {"YARA_EXTRA_SKIP_PATHS": "/"})
    try:
        assert m._extra_skip_fragments() == ()
    finally:
        patcher.stop()


@pytest.mark.parametrize("edition", EDITIONS)
def test_lone_separator_does_not_poison_valid_siblings(edition):
    m, patcher = _mod(edition, {"YARA_EXTRA_SKIP_PATHS": "/opt/good/,/,other"})
    try:
        assert m._extra_skip_fragments() == ("/opt/good/", "/other/")
    finally:
        patcher.stop()


# ------------------------------------------------------------------ additive
@pytest.mark.parametrize("edition", EDITIONS)
def test_builtin_fragments_survive(edition):
    """The Cortex agent paths must not be replaceable by a deployer's list."""
    _, cfg_without = _predicate(edition, {})
    _, cfg_with = _predicate(edition, {"YARA_EXTRA_SKIP_PATHS": "/opt/crowdstrike/"})
    for fragment in cfg_without.skip_path_fragments:
        assert fragment in cfg_with.skip_path_fragments, (
            f"{edition}: built-in fragment {fragment!r} was dropped — the knob is "
            f"substituting rather than appending")
    assert "/opt/crowdstrike/" in cfg_with.skip_path_fragments


# ------------------------------------------------------------------- bounded
@pytest.mark.parametrize("edition", EDITIONS)
@pytest.mark.parametrize("path,should_skip", [
    ("/opt/crowdstrike/falcon.log", True),
    ("/usr/lib/crowdstrike/agent.so", True),      # matches anywhere as a component
    ("/opt/crowdstrike", True),                   # bare directory root (os.walk yields it)
    ("/opt/crowdstrike-backup/payload.bin", False),   # prefix sibling NOT swallowed
    ("/opt/notcrowdstrike/payload.bin", False),
    ("/home/u/crowdstrike.txt", False),           # a FILE named alike is still scanned
    ("/usr/bin/python3", False),
])
def test_component_boundary_is_enforced(edition, path, should_skip):
    check, _ = _predicate(edition, {"YARA_EXTRA_SKIP_PATHS": "crowdstrike"})
    assert check(path) is should_skip, (
        f"{edition}: {path} skip={check(path)} want={should_skip}. An unbounded fragment "
        f"is an evasion vector — anyone who can name a directory could hide files in it.")


@pytest.mark.parametrize("edition", EDITIONS)
def test_absent_knob_changes_nothing(edition):
    check, cfg = _predicate(edition, {})
    assert cfg.skip_path_fragments, f"{edition}: built-in fragments disappeared"
    assert check("/usr/bin/python3") is False
