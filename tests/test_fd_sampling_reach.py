#!/usr/bin/env python3
"""FD leak sampling must actually sample, on every file, exactly once each.

The check lived at the END of scan_file, after six early returns:

    5092  return False, "No read permission"
    5095  return False, "Special system file"
    5101  return False, "Junction/symlink duplicate"
    5105  return False, "Not a regular file"
    5109  return False, "File too large"
    5162  return True,  "Scanned and matched"     <- every MATCHED file
    5164  if self.fd_monitoring_enabled: ...      <- only clean unmatched files reach here

So it ran only on files that were scanned and did not match. Three consequences, each
independently enough to make the monitor useless when it matters most:

REACH        On the Round 2 flood — 8,003 files, 4,002 of them matching — over half the
             scan bypassed the counter entirely. On a ruleset that matches everything the
             sampler never runs at all. FD monitoring goes quiet exactly when the scanner
             is opening the most handles.

RACE         `self.files_since_fd_check += 1` ran unlocked from every worker thread. A
             read-modify-write race silently drops increments, so the effective interval
             is longer than 1000 and non-deterministic — the monitor under-samples by an
             amount nobody can predict or notice.

SILENCE      The only outputs were threshold breaches (>100 growth, >900 open). A healthy
             sample emitted nothing, so "sampled 40 times, all fine" and "never sampled"
             produced identical evidence. That is why the capability was filed
             unobservable.

The fix is to sample on files PROCESSED rather than on files that happened to survive to
the end, under the existing counter lock, and to record that a sample happened.
"""
import importlib
import os
import sys
import threading
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITION = "xsiam_yara_scanner"


@pytest.fixture()
def mod():
    m = importlib.reload(importlib.import_module(EDITION))
    yield m
    importlib.reload(importlib.import_module(EDITION))


def _scanner(mod, interval=5):
    """A YaraScanner shell carrying only what FD sampling touches."""
    s = object.__new__(mod.YaraScanner)
    s.fd_monitoring_enabled = True
    s.fd_check_interval = interval
    s.files_since_fd_check = 0
    s.initial_fd_count = 10
    s.fd_samples_taken = 0
    s.last_fd_count = None
    s.lock_counts = threading.Lock()
    s.log_manager = mock.MagicMock()
    return s


def test_sampler_helper_exists(mod):
    assert hasattr(mod.YaraScanner, "_maybe_sample_fds"), (
        "FD sampling is inlined at the end of scan_file, after the matched and skipped "
        "early returns, so it cannot be reached for most files or tested on its own")


def test_every_file_advances_the_counter_regardless_of_outcome(mod):
    """A matched file and a skipped file must count the same as a clean one."""
    s = _scanner(mod, interval=1000)
    for _ in range(30):
        s._maybe_sample_fds()
    assert s.files_since_fd_check == 30, (
        "files did not advance the sampling counter; on a flood scan where most files "
        "match, the sampler would never fire")


def test_a_sample_is_taken_on_the_interval(mod):
    s = _scanner(mod, interval=5)
    with mock.patch("platform.system", return_value="Linux"):
        proc = mock.MagicMock()
        proc.num_fds.return_value = 42
        with mock.patch("psutil.Process", return_value=proc):
            for _ in range(12):
                s._maybe_sample_fds()
    assert s.fd_samples_taken == 2, f"expected 2 samples in 12 files at interval 5, got {s.fd_samples_taken}"
    assert s.last_fd_count == 42, "a healthy sample must still record the FD count"


def test_healthy_samples_are_recorded_not_silent(mod):
    """The distinction the capability turned on: sampled-and-fine vs never-sampled.

    Both emit no warning, so only a counter separates them.
    """
    s = _scanner(mod, interval=2)
    with mock.patch("platform.system", return_value="Linux"):
        proc = mock.MagicMock()
        proc.num_fds.return_value = 12          # +2 over initial: no threshold breached
        with mock.patch("psutil.Process", return_value=proc):
            for _ in range(6):
                s._maybe_sample_fds()
    assert s.fd_samples_taken == 3
    assert s.last_fd_count == 12


def test_concurrent_workers_do_not_lose_increments(mod):
    """The unlocked += silently dropped counts across threads.

    Under-sampling by a non-deterministic amount is worse than a wrong interval: it
    cannot be reasoned about from the configuration.
    """
    s = _scanner(mod, interval=10_000_000)      # never fires; only the counter is tested
    n_threads, per_thread = 8, 500

    def worker():
        for _ in range(per_thread):
            s._maybe_sample_fds()

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert s.files_since_fd_check == n_threads * per_thread, (
        f"lost {n_threads * per_thread - s.files_since_fd_check} increments to a race; "
        f"the effective sampling interval is longer than configured and unpredictable")


def test_disabled_monitor_does_nothing(mod):
    s = _scanner(mod, interval=1)
    s.fd_monitoring_enabled = False
    for _ in range(10):
        s._maybe_sample_fds()
    assert s.fd_samples_taken == 0
    assert s.files_since_fd_check == 0


def test_sampling_failure_does_not_break_the_scan(mod):
    """psutil raising must not propagate — a scan is worth more than its FD telemetry."""
    s = _scanner(mod, interval=1)
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("psutil.Process", side_effect=OSError("no /proc")):
        for _ in range(3):
            s._maybe_sample_fds()          # must not raise
    assert s.fd_samples_taken == 0, "a failed read must not count as a sample taken"
