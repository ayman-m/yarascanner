#!/usr/bin/env python3
"""Cap knobs must agree on what 0 means, and retention must be reachable.

Two footguns pinned here.

1. TWIN KNOBS, OPPOSITE ZEROS (XSIAM). MAX_MATCH_SAMPLES_PER_FINDING and
   MAX_ALERT_OFFSETS_PER_FINDING are named alike, defaulted alike (50), and cap the same
   kind of thing — yet 0 used to mean "no cap" on one and "sample nothing" on the other,
   because the first's consumer was a bare `if len(sample) < CAP`. The source comment
   called it a footgun and guarded it with minimum=1, which papered over the mismatch
   rather than fixing it. The consumer now short-circuits on <= 0, matching the XDR
   edition's CONFIG_LOOKUP_ROWS_PER_FINDING_MAX idiom, so both agree: 0 = no cap.

   Aligning them surfaced a sharper bug on the twin. MAX_ALERT_OFFSETS_PER_FINDING had no
   `minimum=` at all, just `max(0, value)` — so a mistyped `-5` was clamped onto 0, which
   on that knob means UNBOUNDED. A stray minus sign silently removed the very cap that
   exists to stop a 220 MB alert file. Both now take minimum=0, so 0 stays deliberate and
   negatives fall back to the documented default like every other guarded knob.

2. RETENTION AS A SIGNATURE DEFAULT (XSIAM). `_prune_old_scan_logs(keep_scans=2)` put the
   policy in a method signature — invisible in the config block and unreachable without
   editing the body. Two runs is also thin: the previous run is often exactly what you
   need to diagnose the current one, and a diagnostics log now shares that directory.

3. XDR's per-finding row cap was a bare literal where XSIAM exposed both equivalents,
   making XDR strictly less tunable on the axis that drives per-finding upload volume.
"""
import importlib
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reload(module_name, env):
    with mock.patch.dict(os.environ, env, clear=False):
        mod = importlib.import_module(module_name)
        return importlib.reload(mod)


@pytest.fixture(autouse=True)
def _restore():
    yield
    for name in ("xsiam_yara_scanner", "xdr_yara_scanner"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])


# ------------------------------------------------- twin knobs agree on zero
def test_zero_means_no_cap_on_both_xsiam_twins():
    mod = _reload("xsiam_yara_scanner",
                  {"YARA_MAX_MATCH_SAMPLES": "0", "YARA_MAX_ALERT_OFFSETS": "0"})
    assert mod.MAX_MATCH_SAMPLES_PER_FINDING == 0, (
        "0 was coerced back to the default; the twins still disagree on what 0 means")
    assert mod.MAX_ALERT_OFFSETS_PER_FINDING == 0


def test_sampling_consumer_short_circuits_on_zero():
    """The bare `len(sample) < CAP` form is what made 0 mean 'sample nothing'."""
    import inspect
    mod = _reload("xsiam_yara_scanner", {})
    src = inspect.getsource(mod)
    assert "MAX_MATCH_SAMPLES_PER_FINDING <= 0 or len(_offsets_sample)" in src, (
        "the sampling consumer no longer short-circuits on <= 0, so 0 silently means "
        "'collect no offsets at all' again")


@pytest.mark.parametrize("value,expected", [("1", 1), ("25", 25), ("500", 500)])
def test_positive_cap_values_are_honoured(value, expected):
    mod = _reload("xsiam_yara_scanner", {"YARA_MAX_MATCH_SAMPLES": value})
    assert mod.MAX_MATCH_SAMPLES_PER_FINDING == expected


@pytest.mark.parametrize("knob,attr", [
    ("YARA_MAX_MATCH_SAMPLES", "MAX_MATCH_SAMPLES_PER_FINDING"),
    ("YARA_MAX_ALERT_OFFSETS", "MAX_ALERT_OFFSETS_PER_FINDING"),
])
def test_negative_cap_falls_back_to_default_not_to_unbounded(knob, attr):
    """A typo must not silently mean "no cap".

    YARA_MAX_ALERT_OFFSETS had no `minimum=`, so `max(0, -5)` clamped a negative straight
    onto 0 — which on this knob means UNBOUNDED. A mistyped minus sign therefore removed
    the very cap that exists to stop a 220 MB alert file. Out-of-range must fall back to
    the documented default, as every other guarded knob in this file does.
    """
    mod = _reload("xsiam_yara_scanner", {knob: "-5"})
    assert getattr(mod, attr) == 50, (
        f"{knob}=-5 produced {getattr(mod, attr)}; 0 would mean unbounded")


# ------------------------------------------------------------- retention
def test_xsiam_retention_is_a_reachable_constant():
    mod = _reload("xsiam_yara_scanner", {})
    assert hasattr(mod, "LOG_KEEP_SCANS"), (
        "retention is back to being a method-signature default")
    assert mod.LOG_KEEP_SCANS == 10


def test_xsiam_retention_env_override():
    mod = _reload("xsiam_yara_scanner", {"YARA_LOG_KEEP": "3"})
    assert mod.LOG_KEEP_SCANS == 3


def test_retention_default_matches_across_editions():
    """Divergent retention between editions is a support trap, not a feature."""
    x = _reload("xsiam_yara_scanner", {})
    d = _reload("xdr_yara_scanner", {})
    assert x.LOG_KEEP_SCANS == d.LOG_KEEP_SCANS, (
        f"XSIAM keeps {x.LOG_KEEP_SCANS} runs, XDR keeps {d.LOG_KEEP_SCANS}")


def test_prune_signature_uses_the_constant():
    import inspect
    mod = _reload("xsiam_yara_scanner", {})
    sig = inspect.signature(mod.CleanupManager._prune_old_scan_logs)
    assert sig.parameters["keep_scans"].default == mod.LOG_KEEP_SCANS


# --------------------------------------------------------- XDR row cap
def test_xdr_row_cap_is_env_reachable():
    mod = _reload("xdr_yara_scanner", {"YARA_LOOKUP_ROWS_PER_FINDING": "7"})
    assert mod.CONFIG_LOOKUP_ROWS_PER_FINDING_MAX == 7, (
        "the per-finding dataset row cap is a bare literal again")


def test_xdr_row_cap_default_unchanged():
    mod = _reload("xdr_yara_scanner", {})
    assert mod.CONFIG_LOOKUP_ROWS_PER_FINDING_MAX == 50
