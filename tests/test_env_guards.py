#!/usr/bin/env python3
"""Env-var tuning must never kill a scan, and must never silently scan nothing.

Two failure shapes are pinned here, both P1 because the operator's only signal is a
result line that looks fine:

  1. UNPARSEABLE — a typo like YARA_MAX_MB=128MB raised ValueError inside ScanConfig,
     which main() constructs BEFORE LogManager exists. The scan died with no local log
     recording why, no telemetry event and no dataset row. The helper that exists to
     prevent exactly this (_env_number) was applied to the undocumented module-level
     knobs and withheld from the ones the Deployment Guide tells deployers to set.

  2. OUT OF RANGE — a value that parses but is nonsensical. YARA_MAX_MB=-1 made
     max_file_bytes negative, so every file failed the size check and the scan reported
     "completed" having scanned nothing. Parsing successfully is not the same as being
     usable, so range is checked too.

Both editions are covered: the XSIAM and XDR scanners carry independent copies of this
configuration code, and the bug was present in both.
"""
import importlib
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


def _config(module_name, env):
    """Build a real ScanConfig for `module_name` under `env`.

    os.makedirs is stubbed because ScanConfig eagerly creates its working tree and these
    tests must not touch the filesystem (see tests/test_skip_predicate.py for what
    happens when they do). The module is reloaded so module-level env reads re-evaluate.
    """
    import base64
    rule = base64.b64encode(b'rule t { strings: $a = "AAAA" condition: $a }').decode()
    with mock.patch.dict(os.environ, env, clear=False):
        mod = importlib.import_module(module_name)
        importlib.reload(mod)
        with mock.patch("os.makedirs"):
            cfg = mod.ScanConfig(rule, scan_folder=os.path.dirname(__file__))
        return mod, cfg


@pytest.fixture(autouse=True)
def _restore_modules():
    """Reload both editions cleanly after each test so a patched env cannot leak."""
    yield
    for name in EDITIONS:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


# ------------------------------------------------------- unparseable values
@pytest.mark.parametrize("edition", EDITIONS)
@pytest.mark.parametrize("var,bad", [
    ("YARA_MAX_MB", "128MB"),
    ("YARA_THREADS", "auto"),
    ("YARA_QUEUE_SIZE", "unlimited"),
    ("YARA_PROGRESS_LOG_SECS", "30s"),
    ("YARA_QUEUE_BACKOFF_SECS", "quarter"),
])
def test_unparseable_env_does_not_kill_the_scan(edition, var, bad):
    """A deployer typo must degrade to the default, not raise out of ScanConfig."""
    _, cfg = _config(edition, {var: bad})
    assert cfg is not None


@pytest.mark.parametrize("edition", EDITIONS)
def test_unparseable_max_mb_falls_back_to_a_usable_default(edition):
    _, cfg = _config(edition, {"YARA_MAX_MB": "128MB"})
    assert cfg.max_file_mb == 64, "must fall back to the documented default"
    assert cfg.max_file_bytes == 64 * 1024 * 1024


# ------------------------------------------------------- out-of-range values
@pytest.mark.parametrize("edition", EDITIONS)
def test_negative_max_mb_does_not_skip_every_file(edition):
    """Regression: YARA_MAX_MB=-1 made max_file_bytes negative, so every file failed the
    size check and the scan reported success having scanned nothing."""
    _, cfg = _config(edition, {"YARA_MAX_MB": "-1"})
    assert cfg.max_file_bytes >= 0, "a negative cap silently excludes every file"
    assert cfg.max_file_mb == 64, "out-of-range must fall back to the default"


@pytest.mark.parametrize("edition", EDITIONS)
def test_zero_max_mb_still_means_unlimited(edition):
    """0 is a documented, legitimate value meaning no size cap — it must survive."""
    _, cfg = _config(edition, {"YARA_MAX_MB": "0"})
    assert cfg.max_file_mb == 0
    assert cfg.max_file_bytes == 0


@pytest.mark.parametrize("edition", EDITIONS)
def test_negative_backoff_cannot_busy_spin(edition):
    """A negative sleep makes Event.wait() return immediately — a hot loop on the host."""
    _, cfg = _config(edition, {"YARA_QUEUE_BACKOFF_SECS": "-5"})
    assert cfg.queue_backoff_secs >= 0


@pytest.mark.parametrize("edition", EDITIONS)
def test_valid_values_are_still_honoured(edition):
    """The guards must not flatten legitimate tuning into the defaults."""
    _, cfg = _config(edition, {"YARA_MAX_MB": "256", "YARA_PROGRESS_LOG_SECS": "45"})
    assert cfg.max_file_mb == 256
    assert cfg.max_file_bytes == 256 * 1024 * 1024
    assert cfg.log_interval == 45


# ------------------------------------------------------- module-level (import time)
@pytest.mark.parametrize("edition", EDITIONS)
def test_module_import_survives_bad_module_level_knobs(edition):
    """XDR reads ~25 tuning knobs at MODULE level, so a typo there crashes at import -
    before ScanConfig, before LogManager, before anything can report why."""
    bad = {
        "YARA_LOOKUP_BATCH": "five hundred",
        "YARA_CANCEL_POLL_SECS": "5s",
        "YARA_LOG_KEEP": "ten",
        "YARA_HEARTBEAT_SECS": "10m",
        "YARA_MAX_MATCH_SAMPLES": "50 files",
        "YARA_MAX_ALERT_OFFSETS": "fifty",
    }
    with mock.patch.dict(os.environ, bad, clear=False):
        mod = importlib.import_module(edition)
        importlib.reload(mod)
        assert mod is not None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
