#!/usr/bin/env python3
"""CPU governance PARITY between the two editions — pure, no agent, no network.

tests/throttle/test_cpu_governor.py already covers the governor's internals in depth
against the XDR edition. This file asserts the far narrower thing that matters after the
port: that BOTH editions expose the same governor with the same guarantees, and that the
XSIAM design it replaced is genuinely gone rather than merely bypassed.

The XSIAM edition used to pause on SYSTEM CPU crossing a threshold: a quantity the scanner
cannot control. Measured on 8-core Linux, that design parked 285s of a 347s scan waiting
for a resume condition that could never arrive, while protecting the competing workload by
-3% to +1% versus not throttling at all — it punished itself for load it did not cause.

XDR replaced it with a governor that bounds the scanner's OWN share and reacts to external
load by SHRINKING that share rather than stopping. Delivery differs completely between the
editions, but CPU governance is a property of scanning, so it must not.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


def _gov(edition, **kw):
    import importlib
    m = importlib.import_module(edition)
    kw.setdefault("policy", "headroom")
    kw.setdefault("headroom_pct", 30)
    kw.setdefault("floor_pct", 5)
    kw.setdefault("cpu_count", 8)
    return m, m.CpuGovernor(**kw)


@pytest.mark.parametrize("edition", EDITIONS)
def test_both_editions_have_a_governor(edition):
    """Parity: CPU governance is shared surface, not delivery-specific."""
    m, g = _gov(edition)
    for meth in ("update", "pace", "stats", "compute_target"):
        assert hasattr(g, meth), f"{edition} governor missing {meth}()"


@pytest.mark.parametrize("edition", EDITIONS)
def test_heavy_external_load_floors_but_never_stalls(edition):
    """THE regression the governor exists to prevent.

    Under load the scanner did not cause, the old design paused indefinitely. The governor
    must shrink its target to the floor — never below, and never to zero — so the scan
    keeps making progress.
    """
    m, g = _gov(edition)
    g.update(20, 94)                      # 20% ours, 94% total: someone else owns the box
    s = g.stats()
    assert s["target"] == 5.0, f"target must clamp to the floor, got {s['target']}"
    assert s["floor_hits"] >= 1, "hitting the floor must be recorded, not silent"
    assert g.enabled, "the governor must not disable itself under load"


@pytest.mark.parametrize("edition", EDITIONS)
def test_idle_host_gets_a_generous_target(edition):
    """On a quiet machine the scanner should be allowed to work, not creep."""
    m, g = _gov(edition)
    g.update(10, 15)
    assert g.stats()["target"] > 40, "an idle host should yield a large share"


@pytest.mark.parametrize("edition", EDITIONS)
def test_pace_is_bounded_and_proportional(edition):
    """A single pace must never become an unbounded stall."""
    m, g = _gov(edition)
    g.sleep_ratio = m.CpuGovernor.RATIO_MAX * 10        # absurd, as a runaway would be
    slept = g.pace(60.0)                                 # a very slow file
    assert slept <= m.CpuGovernor.PACE_CAP_SECS, (
        f"one pace slept {slept}s, above the {m.CpuGovernor.PACE_CAP_SECS}s cap")


@pytest.mark.parametrize("edition", EDITIONS)
def test_duty_cycle_has_a_floor(edition):
    """RATIO_MAX bounds the error term, so the scanner always retains some duty cycle."""
    m, _ = _gov(edition)
    min_duty = 100.0 / (1.0 + m.CpuGovernor.RATIO_MAX)
    assert min_duty > 1.0, f"minimum duty cycle {min_duty:.2f}% is effectively a stall"


@pytest.mark.parametrize("edition", EDITIONS)
def test_policy_none_disables_cleanly(edition):
    m, g = _gov(edition, policy="none")
    assert not g.enabled
    assert g.pace(10.0) == 0.0, "a disabled governor must never sleep"


@pytest.mark.parametrize("edition", EDITIONS)
def test_budget_policy_is_fixed_not_adaptive(edition):
    """budget promises a ceiling regardless of what else runs — that is its whole point."""
    m, g = _gov(edition, policy="budget", budget_pct=25)
    g.update(5, 10)
    idle = g.stats()["target"]
    g.update(5, 90)
    busy = g.stats()["target"]
    assert idle == busy == 25.0, f"budget must not move with load: {idle} vs {busy}"


def test_xsiam_no_longer_pauses_on_system_cpu():
    """The replaced design must be gone, not merely bypassed.

    Leaving the old threshold knobs in place would let a deployer set YARA_LIGHT_HIGH_CPU
    and reasonably believe it still governs anything.
    """
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "xsiam", "xsiam_yara_scanner.py"), encoding="utf-8").read()
    assert "_maybe_throttle_scanning" not in src, "the system-CPU pause loop still exists"
    for dead in ("YARA_LIGHT_HIGH_CPU", "YARA_LIGHT_CRITICAL_CPU", "YARA_LIGHT_SLEEP_SECS"):
        assert dead not in src, f"{dead} still present but no longer governs anything"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
