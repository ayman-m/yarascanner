"""Unit tests for CpuGovernor.

Imported from xdr_yara_scanner because the scanner must remain ONE self-contained
file - Action Center uploads a single script, so the governor cannot live in a
separate module.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from xdr_yara_scanner import CpuGovernor  # noqa: E402


# --------------------------------------------------------------- target computation
def test_budget_policy_target_is_the_budget():
    g = CpuGovernor(policy="budget", budget_pct=25.0, cpu_count=8)
    assert g.compute_target(others_pct=0.0) == 25.0
    assert g.compute_target(others_pct=90.0) == 25.0   # budget ignores others


def test_headroom_policy_shrinks_as_others_grow():
    g = CpuGovernor(policy="headroom", headroom_pct=30.0, floor_pct=5.0, cpu_count=8)
    assert g.compute_target(others_pct=0.0) == 70.0    # 100 - 30 - 0
    assert g.compute_target(others_pct=40.0) == 30.0   # 100 - 30 - 40


def test_headroom_never_goes_below_floor():
    """The anti-stall guarantee: under crushing external load the scan still advances.

    This is the exact condition that made the OLD design park 285s of a 347s scan -
    it waited for a resume threshold that sustained external load never let it reach.
    """
    g = CpuGovernor(policy="headroom", headroom_pct=30.0, floor_pct=5.0, cpu_count=8)
    assert g.compute_target(others_pct=95.0) == 5.0
    assert g.compute_target(others_pct=200.0) == 5.0


def test_policy_none_disables():
    g = CpuGovernor(policy="none", cpu_count=8)
    assert g.enabled is False
    assert g.compute_target(others_pct=0.0) is None


def test_normalise_own_divides_by_core_count():
    """psutil returns % of ONE core. 400% on 8 cores is 50% of the machine.

    Skipping this division throttles the scanner to 1/N of the configured budget,
    and does so INVISIBLY - the scan still works and still reports success, it is
    just N times slower than promised. Highest-risk detail in the design.
    """
    g = CpuGovernor(policy="budget", budget_pct=25.0, cpu_count=8)
    assert g.normalise_own(400.0) == 50.0
    assert g.normalise_own(0.0) == 0.0


def test_normalise_own_survives_zero_core_count():
    g = CpuGovernor(policy="budget", cpu_count=0)
    assert g.normalise_own(100.0) == 100.0   # degrade to raw, never divide by zero


# ------------------------------------------------------------------- control loop
def test_update_raises_ratio_when_over_target():
    g = CpuGovernor(policy="budget", budget_pct=20.0, cpu_count=8)
    start = g.sleep_ratio
    g.update(own_raw_pct=8 * 60.0, system_pct=60.0)   # 60% of machine vs 20% target
    assert g.sleep_ratio > start


def test_update_lowers_ratio_when_under_target():
    g = CpuGovernor(policy="budget", budget_pct=50.0, cpu_count=8)
    g.sleep_ratio = 5.0
    g.update(own_raw_pct=8 * 10.0, system_pct=10.0)   # 10% of machine vs 50% target
    assert g.sleep_ratio < 5.0


def test_ratio_never_negative_or_above_max():
    g = CpuGovernor(policy="budget", budget_pct=50.0, cpu_count=8)
    for _ in range(500):
        g.update(own_raw_pct=0.0, system_pct=0.0)
    assert g.sleep_ratio == 0.0
    for _ in range(500):
        g.update(own_raw_pct=8 * 100.0, system_pct=100.0)
    assert g.sleep_ratio <= CpuGovernor.RATIO_MAX


def test_others_is_system_minus_own():
    """Reacting to load it did NOT cause is the entire bug being fixed here."""
    g = CpuGovernor(policy="headroom", headroom_pct=30.0, cpu_count=8)
    g.update(own_raw_pct=8 * 10.0, system_pct=70.0)   # own 10%, so others = 60%
    assert g.last_others == pytest.approx(60.0)
    assert g.last_target == pytest.approx(10.0)       # 100 - 30 - 60


# -------------------------------------------------------------------------- pacing
def test_pace_sleeps_proportional_to_work():
    g = CpuGovernor(policy="budget", budget_pct=20.0, cpu_count=8)
    g.sleep_ratio = 2.0
    slept = g.pace(0.01)
    assert slept == pytest.approx(0.02, abs=0.005)


def test_pace_is_noop_when_disabled():
    g = CpuGovernor(policy="none", cpu_count=8)
    assert g.pace(1.0) == 0.0


def test_pace_respects_cap():
    g = CpuGovernor(policy="budget", cpu_count=8)
    g.sleep_ratio = CpuGovernor.RATIO_MAX
    assert g.pace(10.0) <= CpuGovernor.PACE_CAP_SECS


def test_stats_shape():
    g = CpuGovernor(policy="headroom", cpu_count=8)
    g.update(own_raw_pct=80.0, system_pct=50.0)
    s = g.stats()
    for k in ("policy", "target", "own", "others", "ratio", "slept_secs", "floor_hits"):
        assert k in s
