#!/usr/bin/env python3
"""Per-worker throughput reporting must be bounded by TIME, not by file count alone.

The trigger is `files_processed % 100 == 0`, which ties log volume directly to how many
files the host has. Measured on a live endpoint: a 323,261-file scan of /usr,/var wrote
3,260 `Worker Performance |` lines — 99.5% of a 390 KB performance log. The six governor
samples and five resource samples an operator actually needs to diagnose a scan were
buried in it. Extrapolated to a 10M-file server that is ~100,000 lines and ~12 MB, on the
endpoint's own disk, per run.

This is the same unbounded-growth shape the alert directory already had, and it gets the
same treatment: bound it, and bound it on the axis that matters. Per-worker throughput is
a sampled gauge, so the useful question is "what is throughput doing now", asked at a
human cadence — not once per 100 files, which on a fast scan is dozens of times a second.

So the 100-file trigger becomes the SAMPLING point and a per-worker time gate decides
whether the sample is written, at the same 30 s cadence the governor and progress
heartbeats already use. Volume then scales with scan DURATION rather than file count:
r1a's 3,260 lines become ~12.

Two properties are load-bearing:

FIRST SAMPLE ALWAYS LANDS. A short scan must still produce a throughput reading, so the
gate has to pass on a worker's first report rather than waiting out one full interval.

0 DISABLES THE GATE. Matching every other bound in this file, 0 means "no rate limit" —
the pre-existing every-100-files behaviour, kept reachable for anyone who wants it.
"""
import importlib
import os
import sys
import time
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


def _mod(edition, env=None):
    patcher = mock.patch.dict(os.environ, env or {}, clear=False)
    patcher.start()
    try:
        return importlib.reload(importlib.import_module(edition))
    finally:
        patcher.stop()


@pytest.fixture(autouse=True)
def _restore():
    yield
    for name in EDITIONS:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


@pytest.mark.parametrize("edition", EDITIONS)
def test_knob_exists_with_a_30s_default(edition):
    m = _mod(edition)
    assert hasattr(m, "WORKER_REPORT_MIN_SECS"), (
        "no time gate on per-worker throughput reporting — log volume still scales with "
        "file count, so a 10M-file host writes ~100,000 lines per run")
    assert m.WORKER_REPORT_MIN_SECS == 30, (
        f"default should match the governor/progress heartbeat cadence of 30 s, "
        f"got {m.WORKER_REPORT_MIN_SECS}")


@pytest.mark.parametrize("edition", EDITIONS)
def test_env_override_is_honoured(edition):
    m = _mod(edition, {"YARA_WORKER_REPORT_SECS": "5"})
    assert m.WORKER_REPORT_MIN_SECS == 5


@pytest.mark.parametrize("edition", EDITIONS)
def test_zero_disables_the_gate(edition):
    m = _mod(edition, {"YARA_WORKER_REPORT_SECS": "0"})
    assert m.WORKER_REPORT_MIN_SECS == 0, (
        "0 must mean 'no rate limit', matching every other bound in this file")


def _gate(m, last_report, now, interval):
    """The decision under test, exercised through the helper the worker calls."""
    return m._worker_report_due(last_report, now, interval)


@pytest.mark.parametrize("edition", EDITIONS)
def test_first_sample_always_lands(edition):
    """A short scan must still produce one throughput reading per worker."""
    m = _mod(edition)
    assert _gate(m, 0.0, 1000.0, 30) is True, (
        "a worker's first report was suppressed — short scans would emit no throughput "
        "sample at all")


@pytest.mark.parametrize("edition", EDITIONS)
def test_second_sample_within_the_interval_is_suppressed(edition):
    m = _mod(edition)
    assert _gate(m, 1000.0, 1005.0, 30) is False


@pytest.mark.parametrize("edition", EDITIONS)
def test_sample_after_the_interval_is_emitted(edition):
    m = _mod(edition)
    assert _gate(m, 1000.0, 1031.0, 30) is True


@pytest.mark.parametrize("edition", EDITIONS)
def test_zero_interval_emits_every_time(edition):
    """With the gate off, behaviour is exactly the old every-100-files reporting."""
    m = _mod(edition)
    assert _gate(m, 1000.0, 1000.01, 0) is True


@pytest.mark.parametrize("edition", EDITIONS)
def test_volume_scales_with_duration_not_file_count(edition):
    """The property the fix exists for, stated as arithmetic.

    Two scans of the same DURATION emit the same number of reports even when one
    processes fifty times as many files.
    """
    m = _mod(edition)

    def emitted(n_files, duration_secs, interval=30):
        last, count, now = 0.0, 0, 0.0
        per_file = duration_secs / n_files
        for i in range(1, n_files + 1):
            now += per_file
            if i % 100:
                continue
            if m._worker_report_due(last, now, interval):
                count += 1
                last = now
        return count

    slow = emitted(6_000, 180.0)      # a modest host
    fast = emitted(300_000, 180.0)    # r1a's actual file count, same wall time
    assert abs(slow - fast) <= 1, (
        f"report count still tracks file count: {slow} vs {fast} for equal durations")
    assert fast <= 8, (
        f"a 180 s scan should emit ~6 reports per worker at a 30 s cadence, got {fast}")
