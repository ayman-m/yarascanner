#!/usr/bin/env python3
"""YARA_THREADS must be honoured, in both editions.

XSIAM read the knob, range-validated it, and then threw it away:

    configured_workers = _env_number("YARA_THREADS", default_workers, cast=int, minimum=1)
    self.max_workers = max(1, min(2, configured_workers))       # <- discarded

So `YARA_THREADS=8` on a 32-core server silently produced 2. The variable is listed in the
Deployment Guide's tuning table, which makes it the worst kind of control: one that exists,
is documented, accepts input, and does nothing — failing silently at both ends.

The cap was not arbitrary. It was correct while impact was controlled by the old system-CPU
pause loop, where more workers meant more contention the loop then had to fight. The CPU
governor replaced that loop and bounds the scanner's OWN share directly, so the reason for
welding throughput to impact is gone — as XDR already documented when it removed the same
cap: "a 32-core server scanned no faster than a laptop, permanently."

Impact is still bounded. That is the governor's job, and test_cpu_governor_parity.py pins
it. This file only pins that the operator's stated worker count survives.
"""
import base64
import importlib
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]
RULE = base64.b64encode(b'rule t { strings: $a = "AAAA" condition: $a }').decode()


def _config(module_name, env):
    """Build a real ScanConfig under `env`, without touching the filesystem."""
    with mock.patch.dict(os.environ, env, clear=False):
        mod = importlib.import_module(module_name)
        importlib.reload(mod)
        with mock.patch("os.makedirs"):
            return mod.ScanConfig(RULE, scan_folder=os.path.dirname(__file__))


@pytest.fixture(autouse=True)
def _restore_modules():
    yield
    for name in EDITIONS:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


@pytest.mark.parametrize("edition", EDITIONS)
@pytest.mark.parametrize("requested", ["4", "8", "16"])
def test_requested_worker_count_survives(edition, requested):
    cfg = _config(edition, {"YARA_THREADS": requested})
    assert cfg.max_workers == int(requested), (
        f"{edition}: asked for {requested} workers, got {cfg.max_workers}. A documented "
        f"knob that accepts input and discards it is worse than no knob.")


@pytest.mark.parametrize("edition", EDITIONS)
def test_no_two_worker_ceiling(edition):
    """The specific regression: a hard min(2, ...) that ignores the machine."""
    cfg = _config(edition, {"YARA_THREADS": "12"})
    assert cfg.max_workers > 2, (
        f"{edition}: max_workers capped at {cfg.max_workers}; the min(2, ...) ceiling is back")


@pytest.mark.parametrize("edition", EDITIONS)
def test_absent_knob_still_yields_a_sane_default(edition):
    cfg = _config(edition, {})
    assert cfg.max_workers >= 1, f"{edition}: default worker count is not positive"


@pytest.mark.parametrize("edition", EDITIONS)
def test_queue_size_tracks_worker_count(edition):
    """scan_queue_size defaults to max_workers * 2; it must not stay sized for 2 workers."""
    cfg = _config(edition, {"YARA_THREADS": "8"})
    assert cfg.scan_queue_size >= cfg.max_workers, (
        f"{edition}: queue of {cfg.scan_queue_size} for {cfg.max_workers} workers starves them")
