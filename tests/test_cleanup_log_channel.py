#!/usr/bin/env python3
"""The cleanup-scheduling trail must actually be emitted, in both editions.

`CleanupManager` read `self.config.log_manager` at nine call sites. `ScanConfig` never
assigns that attribute — log_manager lives on LogManager, StatisticsManager, the uploaders
and YaraScanner, never on the config object — so `hasattr(self.config, 'log_manager')` was
permanently False and every one of those calls was dead.

That matters more than a missing log line: cleanup installs a scheduled task (Windows), a
LaunchDaemon (macOS) or a systemd unit (Linux) on the endpoint being scanned. Installing a
persistent artefact on a customer machine with no record of having done so is the kind of
thing an auditor asks about.

The same dead guard also hid a second cleanup suppressor — "more than 50% of log events
were errors". It was deleted rather than repaired: an error RATIO conflates a noisy scan
with a broken one, so a healthy scan of a locked-down host (hundreds of legitimate
permission errors) would have had its diagnostics preserved forever, while a scan that
died for one catastrophic reason would not clear the bar at all.

Pinned here:
  1. A log_manager passed in is used.
  2. Without one, the trail still reaches the root logger (which now has a disk sink).
  3. A raising log_manager cannot take the scan down with it.
  4. The dead ratio-suppressor is gone and does not come back.
"""
import importlib
import inspect
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


class _Recorder:
    def __init__(self, explode=False):
        self.system, self.errors, self.explode = [], [], explode

    def log_system(self, message, data=None):
        if self.explode:
            raise RuntimeError("uploader is down")
        self.system.append(message)

    def log_error(self, message, data=None):
        if self.explode:
            raise RuntimeError("uploader is down")
        self.errors.append(message)


def _manager(edition, log_manager):
    mod = importlib.import_module(edition)
    return mod.CleanupManager(object(), log_manager)


@pytest.mark.parametrize("edition", EDITIONS)
def test_log_manager_receives_the_trail(edition):
    rec = _Recorder()
    cm = _manager(edition, rec)

    cm._log("Windows cleanup task scheduled successfully")
    cm._log("Failed to schedule cleanup: boom", level="error")

    assert rec.system == ["Windows cleanup task scheduled successfully"], (
        f"{edition}: the system channel did not receive the cleanup trail")
    assert rec.errors == ["Failed to schedule cleanup: boom"]


@pytest.mark.parametrize("edition", EDITIONS)
def test_falls_back_to_root_logger(edition, caplog):
    """An unparented CleanupManager must still leave a record."""
    cm = _manager(edition, None)
    with caplog.at_level(logging.INFO):
        cm._log("Linux cleanup service scheduled successfully")

    assert any("Linux cleanup service scheduled" in r.message for r in caplog.records), (
        f"{edition}: no log_manager AND no root-logger fallback = a silent install")


@pytest.mark.parametrize("edition", EDITIONS)
def test_a_broken_log_manager_cannot_kill_the_scan(edition, caplog):
    cm = _manager(edition, _Recorder(explode=True))
    with caplog.at_level(logging.INFO):
        cm._log("Cleanup script decoded and ready for scheduling")  # must not raise

    assert any("Cleanup script decoded" in r.message for r in caplog.records), (
        f"{edition}: a failing log_manager swallowed the record instead of falling back")


@pytest.mark.parametrize("edition", EDITIONS)
def test_dead_error_ratio_suppressor_stays_deleted(edition):
    mod = importlib.import_module(edition)
    src = inspect.getsource(mod.CleanupManager.schedule_final_cleanup)

    assert "get_upload_statistics" not in src, (
        f"{edition}: the error-ratio cleanup suppressor is back. It was unreachable "
        f"(config.log_manager is never assigned) AND wrong (an error ratio conflates a "
        f"noisy scan with a broken one).")
    assert "error_ratio" not in src


@pytest.mark.parametrize("edition", EDITIONS)
def test_config_log_manager_is_late_bound_for_errorlogger(edition):
    """ErrorLogger is built inside ScanConfig, so its channel must be bound later.

    Without this, a rule that fails to compile produces no telemetry error event carrying
    the rule name, error type and line number — the local processing log is the only trace.
    """
    mod = importlib.import_module(edition)
    src = inspect.getsource(mod)
    assert "config.log_manager = log_manager" in src, (
        f"{edition}: nothing binds log_manager onto config, so ErrorLogger's "
        f"compilation-failure telemetry is dead again")
