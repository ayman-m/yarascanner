#!/usr/bin/env python3
"""The governor must report how often it actually sampled.

_sample_governor is rate-limited by throttle_check_interval_secs: a call arriving sooner
than that returns without reading CPU. Nothing reported how many readings the governor
actually took, or how far apart they were, so the cadence could only be inferred from the
spacing of log LINES — which measures the emission policy (a change threshold plus a 30 s
heartbeat), not the sampling rate. Those are different numbers, and on a scan where the
governor's readings are steady they diverge completely: the emission threshold suppresses
lines while sampling continues underneath.

That gap is why the capability sat unverifiable. An operator asking "is the governor
actually watching, or has it gone quiet?" could not tell a healthy scan from one where
sampling had stalled, because both look identical from the outside.

Two counters close it, both derived where the readings are consumed rather than where
they are logged:

  samples_taken           monotonic count of accepted readings
  secs_since_last_sample  gap between the last two, so a stalled sampler shows a gap that
                          grows without bound instead of simply producing fewer lines

The first sample has no predecessor, so its gap is None rather than 0.0 — a zero there
would read as "sampled twice instantaneously" and hide a cold start.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITION = "xsiam_yara_scanner"


@pytest.fixture()
def mod():
    m = importlib.reload(importlib.import_module(EDITION))
    yield m
    importlib.reload(importlib.import_module(EDITION))


def _gov(mod, **kw):
    return mod.CpuGovernor(policy="headroom", **kw)


def test_stats_exposes_the_sampling_counters(mod):
    g = _gov(mod)
    s = g.stats()
    assert "samples_taken" in s, (
        "the governor reports no sample count, so cadence can only be inferred from log "
        "line spacing — which measures the emission policy, not the sampling rate")
    assert "secs_since_last_sample" in s


def test_counters_start_empty(mod):
    g = _gov(mod)
    s = g.stats()
    assert s["samples_taken"] == 0
    assert s["secs_since_last_sample"] is None, (
        "a governor that has never sampled must not report a gap of 0.0 — that reads as "
        "'sampled twice instantaneously'")


def test_each_accepted_reading_increments_the_count(mod):
    g = _gov(mod, cpu_count=4)
    for _ in range(3):
        g.update(40.0, 60.0)
    assert g.stats()["samples_taken"] == 3


def test_gap_is_none_on_the_first_sample_then_measured(mod):
    g = _gov(mod, cpu_count=4)
    g.update(40.0, 60.0)
    assert g.stats()["secs_since_last_sample"] is None, (
        "the first reading has no predecessor to measure against")
    g.update(40.0, 60.0)
    gap = g.stats()["secs_since_last_sample"]
    assert isinstance(gap, float) and gap >= 0.0


def test_a_disabled_governor_does_not_count(mod):
    """`none` policy takes no readings, so the counter must stay at zero.

    Otherwise a disabled governor would look like a busy one.
    """
    g = mod.CpuGovernor(policy="none")
    g.update(40.0, 60.0)
    assert g.stats()["samples_taken"] == 0


def test_gap_grows_when_sampling_stalls(mod):
    """The signal an operator actually needs: a stalled sampler shows a growing gap.

    Fewer log lines alone cannot distinguish "steady readings, nothing worth emitting"
    from "sampling stopped", which is exactly the ambiguity this closes.
    """
    g = _gov(mod, cpu_count=4)
    stamps = [1000.0, 1005.0, 1400.0]
    for t in stamps:
        g.update(40.0, 60.0, now=t)
    assert g.stats()["secs_since_last_sample"] == pytest.approx(395.0), (
        "a 395 s stall must surface as a 395 s gap, not merely as missing lines")
