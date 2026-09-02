#!/usr/bin/env python3
"""`max_datasets` - draining a large fleet in operator-chosen slices.

The fan-in fixed the read phase, and that turned out not to be the whole problem for full
mode: a single ruleset group of ~55,000 rows died mid-write with an HTTP 500 after roughly
19,500 had landed, and the run overshot the 900-second task limit at 109%. Reads got 24x
faster and the pass still could not finish. So the size of one pass has to be something an
operator can choose.

It cannot be chosen automatically, and that is a finding rather than an omission. The dataset
listing - the one tenant call that costs no query - carries "Total Events", "Total Size
Stored", "Average Event Size" and "Average Daily Size", and the platform populates NONE of
them for LOOKUP datasets. Checked against a live tenant: 0 of 446 LOOKUP datasets had any,
while RAW and SYSTEM datasets did, and `xdr_data` reported 18.8M events against a YARA shard's
None. Every YARA dataset is a LOOKUP. "Last Updated" is populated, so a bounded pass can order
by it but cannot size itself by anything.

The rail that matters here is not the bound, it is what the bound implies. `stale = held -
observed` reads a scan's absence from the sources as proof it was superseded. A pass that
deliberately skipped shards has not observed their scans, so running stale removal would
delete the consolidated rows of every host it chose not to read this time - turning a
throughput control into a data-loss bug. A bounded pass therefore sets sources_complete False,
the same rail an unreadable source sets, for the same reason.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateSummary as S, YaraConsolidateApply as A, FakeTenant, _run_automation,
)

HOSTS = ["h%02d_%06x" % (i, 0xaa0000 + i) for i in range(6)]
MATCHES = ["yara_scanner_matches_v4_%s" % h for h in HOSTS]
SCANS = ["yara_scanner_scans_v4_%s_202609" % h for h in HOSTS]


def _tenant(**kw):
    rows = {ds: {"scan%02d" % i: 3} for i, ds in enumerate(MATCHES + SCANS)}
    return FakeTenant(names=MATCHES + SCANS, scans=rows, **kw)


# ------------------------------------------------------- the listing's limits

@pytest.mark.parametrize("mod", [S, A])
def test_the_listing_gives_freshness_but_never_size(mod):
    """Pinning what the endpoint actually supplies, because the whole reason `max_datasets`
    is an operator control rather than an automatic one is that size is unavailable. If a
    future platform version starts populating Total Events for lookups, this is where someone
    should notice that auto-sizing became possible."""
    class Listing:
        def get_datasets(self):
            return [{"Dataset Name": "yara_scanner_matches_v4_a_aa0001", "Type": "LOOKUP",
                     "Last Updated": 1788220800000, "Total Events": None,
                     "Total Size Stored": None, "Average Event Size": None}]
    got = mod._dataset_last_updated(Listing())
    assert got == {"yara_scanner_matches_v4_a_aa0001": 1788220800000}


@pytest.mark.parametrize("mod", [S, A])
def test_an_unreadable_listing_does_not_break_the_pass(mod):
    """Ordering is a nicety; losing it must not stop the run."""
    class Broken:
        def get_datasets(self):
            raise RuntimeError("listing unavailable")
    assert mod._dataset_last_updated(Broken()) == {}


@pytest.mark.parametrize("mod", [S, A])
def test_a_dataset_without_a_timestamp_is_simply_absent(mod):
    class Partial:
        def get_datasets(self):
            return [{"Dataset Name": "a", "Last Updated": None},
                    {"Dataset Name": "b", "Last Updated": "not-a-number"},
                    {"Dataset Name": "c", "Last Updated": 5}]
    assert mod._dataset_last_updated(Partial()) == {"c": 5}


# ------------------------------------------------------------ the bound holds

def test_a_bound_limits_how_many_shards_are_read():
    t = _tenant()
    _run_automation(S, {"execute": "false", "schema_version": "4", "max_datasets": "2"}, t)
    read = [c for c in t.calls if c.startswith("xql:") and "_matches_v4_" in c]
    assert len(read) == 2, "expected 2 matches reads, got %d: %r" % (len(read), read)


def test_a_bound_larger_than_the_fleet_changes_nothing():
    """No truncation means no reason to give up stale removal, so the pass stays a normal one
    and the fan-in stays available."""
    t = _tenant()
    _run_automation(S, {"execute": "false", "schema_version": "4", "max_datasets": "99"}, t)
    assert [c for c in t.calls if "_matches_v4_*" in c], (
        "a non-truncating bound withdrew the fan-in: %r" % t.calls)


def test_no_bound_reads_everything():
    t = _tenant()
    _run_automation(S, {"execute": "false", "schema_version": "4"}, t)
    assert [c for c in t.calls if "_matches_v4_*" in c]


def test_a_bounded_pass_cannot_use_the_fanin():
    """Not a special case - a wildcard cannot express "these 2 of 6", so the fan-in guard's
    set-equality test withdraws it on its own. Asserted because a future change that made the
    wildcard fire on a subset would silently read shards the operator excluded."""
    t = _tenant()
    _run_automation(S, {"execute": "false", "schema_version": "4", "max_datasets": "2"}, t)
    assert not [c for c in t.calls if "_matches_v4_*" in c]


@pytest.mark.parametrize("bad", ["0", "-1"])
def test_a_nonsense_bound_is_rejected_not_rounded(bad):
    """Zero would read nothing and report a clean pass over an empty fleet."""
    t = _tenant()
    with pytest.raises(Exception):
        _run_automation(S, {"execute": "false", "schema_version": "4", "max_datasets": bad}, t)


# ---------------------------------------------- the rail the bound implies

def test_a_bounded_pass_never_removes_rows_from_a_target():
    """The reason this feature is dangerous without the rail.

    The target is seeded holding a scan no source has, so `held - observed` is non-empty and
    stale removal WOULD fire on an unbounded pass. Bounded, it must not - every scan in a
    shard the pass skipped looks equally superseded, so a 2-of-6 pass with removal live would
    delete four hosts' consolidated rows.
    """
    target = "yara_scanner_summary_v4_rules_90149530ddc2"
    rows = {ds: {"scan%02d" % i: 3} for i, ds in enumerate(MATCHES + SCANS)}
    rows[target] = {"a_long_gone_scan_yara_90149530ddc2": 7}
    t = FakeTenant(names=MATCHES + SCANS + [target], scans=rows)
    _run_automation(S, {"execute": "true", "schema_version": "4", "max_datasets": "2"}, t)
    removals = [c for c in t.calls if c.startswith("remove_lookup_data")]
    assert not removals, "a bounded pass removed rows: %r" % removals


def test_an_unbounded_pass_is_the_one_that_reconciles():
    """The bound must not become a permanent off-switch: the same tenant, unbounded, is where
    reconciliation is allowed to happen. Asserted as "the bounded notice is absent" rather
    than "a removal occurred", because whether there is anything to remove depends on gating
    this test deliberately does not set up."""
    t = _tenant()
    _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    assert not [c for c in t.calls if "bounded" in c.lower()]


# ------------------------------------------------- auto-sizing when unbounded

def test_an_explicit_bound_beats_the_estimate():
    """The operator's number is used as given. Estimation exists for when they have not got
    one, not to second-guess one they have."""
    sizes = {"a": 10, "b": 10, "c": 10}
    taken, left, rows, why = A._plan_pass(["a", "b", "c"], sizes, {}, 2, 15000, lambda *x: None)
    assert taken == ["a", "b"] and left == 1 and "max_datasets=2" in why


def test_with_no_bound_the_budget_decides():
    sizes = {"a": 6000, "b": 6000, "c": 6000}
    taken, left, rows, why = A._plan_pass(["a", "b", "c"], sizes, {}, None, 15000,
                                          lambda *x: None)
    assert taken == ["a", "b"] and left == 1 and rows == 12000 and "budget" in why


def test_one_oversized_dataset_still_makes_progress():
    """A dataset bigger than the whole budget must be attempted, not deferred forever - the
    alternative is a fleet that never drains and a pass that reports success doing nothing."""
    taken, left, rows, _ = A._plan_pass(["big", "small"], {"big": 99999, "small": 1}, {},
                                        None, 15000, lambda *x: None)
    assert taken == ["big"] and left == 1


def test_a_fleet_inside_the_budget_is_taken_whole():
    """And therefore stays a complete pass, which is what keeps stale removal available."""
    taken, left, rows, _ = A._plan_pass(["a", "b"], {"a": 10, "b": 10}, {}, None, 15000,
                                        lambda *x: None)
    assert left == 0 and rows == 20


def test_unknown_sizes_fall_back_to_taking_everything():
    """If the count query failed, the pass behaves exactly as it did before this feature -
    degraded to the old behaviour rather than to an arbitrary slice."""
    taken, left, rows, why = A._plan_pass(["a", "b"], {}, {}, None, 15000, lambda *x: None)
    assert taken == ["a", "b"] and left == 0 and "unknown" in why


def test_oldest_touched_datasets_are_taken_first():
    """So repeated passes drain a backlog instead of re-reading the same head every time."""
    taken, _, _, _ = A._plan_pass(["new", "old"], {"new": 1, "old": 1},
                                  {"new": 200, "old": 100}, 1, 15000, lambda *x: None)
    assert taken == ["old"]


def test_the_row_counter_maps_scans_back_to_their_dataset():
    """One aggregate sizes the whole fleet. The hostname is what resolves a row to the dataset
    the scanner wrote it to, since XQL exposes no dataset column."""
    class C:
        def xql(self, q, limit=None):
            return [{"scan_id": "s1", "hostname": "xdr-agent", "n": 161},
                    {"scan_id": "s2", "hostname": "xdragent2", "n": 425}]
    got = A._rows_per_dataset(C(), "yara_scanner_matches_v4_*", "4", lambda *x: None)
    assert got == {"yara_scanner_matches_v4_xdr_agent_cd7e9b": 161,
                   "yara_scanner_matches_v4_xdragent2_2fd370": 425}


def test_a_failed_count_is_not_fatal():
    class C:
        def xql(self, q, limit=None):
            raise RuntimeError("nope")
    assert A._rows_per_dataset(C(), "w*", "4", lambda *x: None) == {}


def test_the_progress_line_says_whether_to_run_again():
    """A caller - human or playbook - branches on this, so it must distinguish "done" from
    "done with the part I looked at"."""
    assert "nothing is pending" in A._progress_line(
        {"datasets_total": 5, "datasets_taken": 5, "datasets_remaining": 0})
    assert "RE-RUN" in A._progress_line(
        {"datasets_total": 5, "datasets_taken": 2, "datasets_remaining": 3})
