#!/usr/bin/env python3
"""The macOS case-sensitivity probe must run ONCE per process, not once per file.

`_is_case_sensitive_fs()` decides whether paths should be case-folded. On Darwin it
answers by experiment: create `/tmp/CaSe_TeSt_YaRa_<pid>`, write to it, stat the
lowercased name, unlink. Four filesystem operations.

It is called from `_get_real_path()`, which `scan_file()` calls for EVERY file that gets
past the pre-checks. So on macOS the probe runs once per scanned file. A live run on
OfficeiMac scanned 48,921 files — roughly 49,000 create/write/stat/unlink cycles in /tmp,
to re-answer a question whose answer cannot change while the process is alive.

Three reasons this is worth fixing rather than merely documenting:

  COST        four syscalls plus a write per file, on the host being scanned.
  SIDE EFFECT it is the scanner's only per-file WRITE. A tool that reads the disk to look
              for malware should not leave ~49,000 file creations behind on a whole-machine
              scan; another EDR watching /tmp has every reason to find that interesting.
  HONESTY     the capability was filed unobservable. A counter makes it observable, and
              caching makes the number worth reporting: 1, not 48,921.

Filesystem case sensitivity is a property of the mount, so a process-lifetime cache is
correct. The counter is kept anyway — it is what distinguishes "cached, ran once" from
"never ran because the platform branch was skipped", which are different states that both
show zero probe files on disk.

Both editions carry independent copies of this function and both were uncached, so the
test is parametrised over the pair rather than duplicated.
"""
import importlib
import os
import platform
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


@pytest.fixture(params=EDITIONS)
def mod(request):
    m = importlib.reload(importlib.import_module(request.param))
    yield m
    importlib.reload(importlib.import_module(request.param))


def test_probe_runs_once_across_many_calls(mod):
    """The defining property: N calls must not mean N filesystem probes."""
    opened = []
    real_open = open

    def counting_open(path, *a, **kw):
        if "CaSe_TeSt_YaRa" in str(path):
            opened.append(path)
            return mock.mock_open(read_data="test")(path, *a, **kw)
        return real_open(path, *a, **kw)

    with mock.patch("platform.system", return_value="Darwin"), \
         mock.patch("builtins.open", counting_open), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.remove"):
        for _ in range(500):
            mod._is_case_sensitive_fs()

    assert len(opened) == 1, (
        f"the probe touched the filesystem {len(opened)} times for 500 calls. It is called "
        f"once per scanned file, so a 48,921-file macOS scan performs that many "
        f"create/write/stat/unlink cycles in /tmp to re-answer an unchanging question")


def test_repeated_calls_agree(mod):
    """Caching must not change the answer, only how often it is computed."""
    with mock.patch("platform.system", return_value="Darwin"), \
         mock.patch("builtins.open", mock.mock_open()), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.remove"):
        first = mod._is_case_sensitive_fs()
        assert all(mod._is_case_sensitive_fs() is first for _ in range(20))


def test_probe_count_is_exposed(mod):
    """A counter distinguishes 'cached after one run' from 'never ran'.

    Both leave zero probe files on disk, so the filesystem cannot tell them apart.
    """
    assert hasattr(mod, "case_probe_count"), (
        "no probe counter — a cached probe and a skipped platform branch are "
        "indistinguishable from outside")
    assert mod.case_probe_count() == 0, "nothing should have probed at import"

    with mock.patch("platform.system", return_value="Darwin"), \
         mock.patch("builtins.open", mock.mock_open()), \
         mock.patch("os.path.exists", return_value=True), \
         mock.patch("os.remove"):
        mod._is_case_sensitive_fs()
        mod._is_case_sensitive_fs()
    assert mod.case_probe_count() == 1


def test_non_darwin_platforms_never_probe(mod):
    """Windows and Linux answer from policy, so they must not touch the disk at all."""
    name = mod.__name__
    for system, expected in (("Windows", False), ("Linux", True)):
        importlib.reload(importlib.import_module(name))
        m = sys.modules[name]
        with mock.patch("platform.system", return_value=system):
            assert m._is_case_sensitive_fs() is expected
        assert m.case_probe_count() == 0, (
            f"{system} performed a filesystem probe it does not need")


def test_probe_failure_is_cached_too(mod):
    """A probe that raises must not be retried per file — that is the worst case.

    An unwritable /tmp would otherwise mean an exception per scanned file.
    """
    attempts = []

    def failing_open(path, *a, **kw):
        if "CaSe_TeSt_YaRa" in str(path):
            attempts.append(path)
            raise PermissionError("read-only /tmp")
        return open(path, *a, **kw)

    with mock.patch("platform.system", return_value="Darwin"), \
         mock.patch("builtins.open", failing_open):
        results = [mod._is_case_sensitive_fs() for _ in range(50)]

    assert len(attempts) == 1, (
        f"a failing probe was retried {len(attempts)} times; on an unwritable /tmp that is "
        f"one exception per scanned file")
    assert all(r is False for r in results), "the documented fallback is False"
