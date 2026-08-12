#!/usr/bin/env python3
"""Unit tests for dataset consolidation logic — pure, no network.

The consolidation functions take a `client` with a small interface (xql, get_datasets,
create_lookup_dataset, add_lookup_data, delete_dataset, action_status). Here that client
is a deterministic fake, so gate logic and verify-before-delete are tested exhaustively
without a tenant. Live behaviour is validated separately against the real API.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xdr_consolidate import (  # noqa: E402
    parse_shard, group_shards_by_scan, shard_is_terminal, newest_row_age_ok,
    plan_consolidation, build_terminal_map, TERMINAL_LIFECYCLE, TERMINAL_ACTION,
)


# --------------------------------------------------------------- name parsing
def test_parse_shard_matches():
    p = parse_shard("yara_scanner_matches_v2_winhost01_ab12cd_202608")
    assert p["kind"] == "matches"
    assert p["host"] == "winhost01_ab12cd"
    assert p["month"] == "202608"


def test_parse_shard_scans():
    p = parse_shard("yara_scanner_scans_v2_linux7_ff00aa_202608")
    assert p["kind"] == "scans"
    assert p["host"] == "linux7_ff00aa"


def test_parse_shard_rejects_consolidated_target():
    # a per-scan target must never be re-consumed as a source
    assert parse_shard("yara_scanner_matches_v2_scan_abc123") is None


def test_parse_shard_rejects_foreign():
    assert parse_shard("some_other_dataset") is None
    assert parse_shard("yara_scanner_matches_v2") is None  # no host/month


# ------------------------------------------------------- grouping by scan_id
def test_group_shards_by_scan():
    rows_by_ds = {
        "yara_scanner_matches_v2_h1_aa_202608": [{"scan_id": "S1"}, {"scan_id": "S1"}],
        "yara_scanner_matches_v2_h2_bb_202608": [{"scan_id": "S1"}],
        "yara_scanner_matches_v2_h3_cc_202608": [{"scan_id": "S2"}],
    }
    groups = group_shards_by_scan(rows_by_ds, kind="matches")
    assert set(groups) == {"S1", "S2"}
    assert len(groups["S1"]) == 2
    assert groups["S1"]["yara_scanner_matches_v2_h1_aa_202608"] == 2


# --------------------------------------------------------- terminal gate (A)
def test_shard_terminal_by_lifecycle():
    for st in TERMINAL_LIFECYCLE:
        assert shard_is_terminal(latest_status=st, action_state=None) is True
    for st in ("initiated", "running"):
        assert shard_is_terminal(latest_status=st, action_state=None) is False


def test_shard_terminal_by_action_even_if_lifecycle_stuck():
    # console Cancel hard-kills -> lifecycle stuck at "running", but the action is ABORTED.
    # Gate B must rescue it, else the shard is never processed.
    assert shard_is_terminal(latest_status="running", action_state="ABORTED") is True
    for st in TERMINAL_ACTION:
        assert shard_is_terminal(latest_status="running", action_state=st) is True


def test_shard_not_terminal_when_both_pending():
    assert shard_is_terminal(latest_status="running", action_state="PENDING") is False
    assert shard_is_terminal(latest_status=None, action_state="IN_PROGRESS") is False


def test_terminal_action_includes_partial_and_with_errors_states():
    # Edge case #2: this repo's OTHER two live-verified "terminal Action Center state" sets
    # (xdr_action_center.py's TERMINAL_STATES, xdr-yara-scan-test's xdr_lib.wait_action)
    # already include COMPLETED_WITH_ERRORS/COMPLETED_PARTIAL as terminal. TERMINAL_ACTION
    # must not silently disagree, or a host whose action ended in one of those states never
    # gets rescued by Gate B and its shard is deferred forever.
    assert {"COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"} <= TERMINAL_ACTION
    assert shard_is_terminal(latest_status="running", action_state="COMPLETED_WITH_ERRORS") is True
    assert shard_is_terminal(latest_status="running", action_state="COMPLETED_PARTIAL") is True


# ------------------------------------------------------ quiet-period gate
def test_newest_row_age_gate():
    now_ms = 1_000_000_000
    quiet = 120
    assert newest_row_age_ok(newest_ms=now_ms - 200_000, now_ms=now_ms, quiet_secs=quiet) is True
    assert newest_row_age_ok(newest_ms=now_ms - 10_000, now_ms=now_ms, quiet_secs=quiet) is False
    assert newest_row_age_ok(newest_ms=None, now_ms=now_ms, quiet_secs=quiet) is True  # no rows -> not blocked


# ---------------------------------------- terminal map (lifecycle lives in scans shards)
def test_terminal_map_from_scans_shards():
    # matches rows carry NO status; terminality must come from the scans shards, keyed by
    # (scan_id, host), and apply to matches consolidation for the same host.
    scans_rows = {
        "yara_scanner_scans_v2_hostA_aa0001": [
            {"scan_id": "S1", "status": "initiated", "event_timestamp_ms": 100},
            {"scan_id": "S1", "status": "completed", "event_timestamp_ms": 300},
        ],
        "yara_scanner_scans_v2_hostB_bb0002": [
            {"scan_id": "S1", "status": "running", "event_timestamp_ms": 200},
        ],
    }
    tmap = build_terminal_map(scans_rows)
    assert tmap[("S1", "hostA_aa0001")]["terminal"] is True   # latest is completed
    assert tmap[("S1", "hostA_aa0001")]["newest_ms"] == 300
    assert tmap[("S1", "hostB_bb0002")]["terminal"] is False  # still running


def test_terminal_map_action_center_rescues_stuck_running():
    # console-cancelled host: lifecycle stuck at running, but Action Center says ABORTED.
    scans_rows = {
        "yara_scanner_scans_v2_hostC_cc0003": [
            {"scan_id": "S1", "status": "running", "event_timestamp_ms": 200},
        ],
    }
    tmap = build_terminal_map(scans_rows, action_state_for=lambda h: "ABORTED")
    assert tmap[("S1", "hostC_cc0003")]["terminal"] is True


# ------------------------------------------------------ plan (verify-before-delete)
def test_plan_marks_deletable_only_when_counts_match():
    plan = plan_consolidation(
        scan_id="S1",
        source_counts={"ds_a": 10, "ds_b": 5},
        target_count=15,
    )
    assert plan["ok"] is True
    assert plan["target_count"] == 15
    assert plan["source_total"] == 15
    assert set(plan["deletable"]) == {"ds_a", "ds_b"}


def test_plan_refuses_delete_on_count_mismatch():
    plan = plan_consolidation(
        scan_id="S1",
        source_counts={"ds_a": 10, "ds_b": 5},
        target_count=12,   # 3 rows short — something did not land
    )
    assert plan["ok"] is False
    assert plan["deletable"] == []   # nothing deleted when verification fails


def test_plan_row_ceiling_refuses_oversize():
    plan = plan_consolidation(
        scan_id="S1",
        source_counts={"ds_a": 400_000, "ds_b": 400_000},
        target_count=0,
        row_ceiling=500_000,
    )
    assert plan["ok"] is False
    assert plan["reason"] == "row_ceiling_exceeded"
    assert plan["deletable"] == []


# ============================================================================
# Orchestration tests with an in-memory fake client (no network)
# ============================================================================
import xdr_consolidate as C  # noqa: E402


class FakeClient:
    """In-memory datasets. Single-writer, so no collision to model — that is the point."""
    def __init__(self):
        self.ds = {}   # name -> list[rows]

    def get_datasets(self):
        return [{"dataset_name": n} for n in self.ds]

    def create_lookup_dataset(self, name, schema):
        # Mirror the real API: a fresh create returns {"dataset_name": ...}, re-creating an
        # existing dataset returns {"status": "exists"} instead — verified live, and what the
        # consolidation lock relies on to detect another run already holding it.
        if name in self.ds:
            return {"status": "exists"}
        self.ds[name] = []
        return {"dataset_name": name}

    def add_lookup_data(self, name, rows):
        # Mirror the real API: a row is SKIPPED if it carries a field outside the schema
        # (here any "_"-prefixed system column), OR if a 'number' field (offset) holds a
        # non-numeric value — the exact two failure modes seen live. Coercion must fix both.
        def ok(r):
            if any(k.startswith("_") for k in r):
                return False
            if "offset" in r and not isinstance(r["offset"], (int, float)):
                return False
            return True
        good = [r for r in rows if ok(r)]
        self.ds.setdefault(name, []).extend(good)
        return {"rows added": len(good), "rows skipped": len(rows) - len(good)}

    def delete_dataset(self, name, force=False):
        self.ds.pop(name, None)
        return {"status": "deleted"}

    def remove_lookup_data(self, name, filters):
        # Mirror the real API: OR across filter dicts, AND within a dict (exact match).
        # An unknown dataset is a harmless no-op (0 deleted), not an error.
        if name not in self.ds:
            return {"deleted": 0}
        def matches(row):
            return any(all(row.get(k) == v for k, v in f.items()) for f in filters)
        before = len(self.ds[name])
        self.ds[name] = [r for r in self.ds[name] if not matches(r)]
        return {"deleted": before - len(self.ds[name])}

    def xql(self, query, limit=1000):
        name = query.split("dataset = ", 1)[1].split(" ", 1)[0].strip()
        rows = self.ds.get(name, [])
        if "by scan_id" in query:   # _scan_stats aggregation
            agg = {}
            for r in rows:
                sid = r.get("scan_id")
                n, newest = agg.get(sid, (0, 0))
                agg[sid] = (n + 1, max(newest, int(r.get("event_timestamp_ms") or 0)))
            return [{"scan_id": s, "n": n, "newest": nw} for s, (n, nw) in agg.items()]
        if "comp count()" in query:
            return [{"n": len(rows)}]
        def readback(r):
            # Mirror XQL read-back: add a system column, and return numbers as strings
            # (offset comes back as text) so coercion is exercised.
            out = dict(r, _insert_time=1)
            if "offset" in out:
                out["offset"] = str(out["offset"])
            return out
        if "filter scan_id" in query:   # _rows_for_scan
            want = query.split('filter scan_id = "', 1)[1].split('"', 1)[0]
            return [readback(r) for r in rows if r.get("scan_id") == want]
        return [readback(r) for r in rows]


def _seed(fc, ds, rows):
    fc.ds[ds] = list(rows)


def _m(scan, host, n, ts=1000):
    return [{"scan_id": scan, "hostname": host, "rule": "R", "filename": "f%d" % i,
             "event_timestamp_ms": ts} for i in range(n)]


def _s(scan, host, status, ts=1000):
    return [{"scan_id": scan, "hostname": host, "status": status, "event_timestamp_ms": ts}]


NOW = 10_000_000


def test_orchestration_happy_path_matches():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 40))
    _seed(fc, "yara_scanner_matches_v2_hostb_bb0002", _m("S1", "hostb", 25))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S1", "hostb", "completed"))
    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 65
    assert "yara_scanner_matches_v2_hosta_aa0001" not in fc.ds   # shards deleted
    assert "yara_scanner_matches_v2_hostb_bb0002" not in fc.ds


def test_orchestration_defers_when_a_host_is_running():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 40))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "running"))
    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s1" not in fc.ds       # no target
    assert "yara_scanner_matches_v2_hosta_aa0001" in fc.ds      # shard preserved


def test_orchestration_keeps_shard_holding_an_unconsolidated_second_scan():
    # THE data-loss case: one shard holds S1 (done) and S2 (still running). Consolidating S1
    # must NOT delete the shard, or S2's rows are destroyed before S2 is ever consolidated.
    fc = FakeClient()
    shard = "yara_scanner_matches_v2_hostx_cc0003"
    _seed(fc, shard, _m("S1", "hostx", 10) + _m("S2", "hostx", 7))
    _seed(fc, "yara_scanner_scans_v2_hostx_cc0003",
          _s("S1", "hostx", "completed") + _s("S2", "hostx", "running"))
    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by = {p["scan_id"]: p for p in plans}
    assert by["S1"]["ok"] is True
    assert by["S2"]["reason"] == "host_not_terminal"
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10   # S1 consolidated
    assert shard in fc.ds                                        # shard KEPT (S2 not done)
    # S1's rows are stripped out immediately once verified (edge case #51a) — only S2's 7
    # rows remain, not all 17; leaving S1's rows here too would double-count S1 in any
    # dashboard querying the yara_scanner_matches* wildcard until S2 also finishes.
    assert len(fc.ds[shard]) == 7


RNOW = 1_800_000_000_000   # realistic epoch-ms so RNOW - 48h stays positive


def test_orchestration_abandoned_scan_consolidated_after_cutoff():
    # A non-terminal scan whose newest row is older than the cutoff is treated as abandoned
    # (console-Cancel orphan) and consolidated, so its shard stops being blocked.
    fc = FakeClient()
    old = RNOW - 48 * 3600 * 1000   # 48h old, past the 24h cutoff
    _seed(fc, "yara_scanner_matches_v2_hostz_ee0009", _m("S9", "hostz", 12, ts=old))
    _seed(fc, "yara_scanner_scans_v2_hostz_ee0009", _s("S9", "hostz", "running", ts=old))
    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s9"]) == 12   # findings preserved
    assert "yara_scanner_matches_v2_hostz_ee0009" not in fc.ds   # shard now deletable


def test_orchestration_recent_nonterminal_still_defers():
    # The same running scan, but only 1h old, is still deferred — it might be active.
    fc = FakeClient()
    recent = RNOW - 3600 * 1000
    _seed(fc, "yara_scanner_matches_v2_hostz_ee0009", _m("S9", "hostz", 12, ts=recent))
    _seed(fc, "yara_scanner_scans_v2_hostz_ee0009", _s("S9", "hostz", "running", ts=recent))
    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s9" not in fc.ds
    assert "yara_scanner_matches_v2_hostz_ee0009" in fc.ds   # shard preserved


def test_orchestration_idempotent_second_run_no_duplicates():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 30))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    n_after_first = len(fc.ds["yara_scanner_matches_v2_scan_s1"])
    # re-seed the shard (simulate it not yet deleted) and run again
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 30))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == n_after_first == 30   # no dup


# ------------------------------------------------- check_consolidation_status (read-only)
def test_check_status_reports_eligible_when_scan_finished_and_settled():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    status = C.check_consolidation_status(fc, kinds=("matches",), quiet_secs=1, now_ms=NOW,
                                          log=lambda *a: None)
    assert status["any_in_progress"] is False
    assert status["eligible_count"] == 1
    assert status["eligible_scan_ids"] == ["S1"]
    assert status["pending_scan_ids"] == []
    assert status["blocked_count"] == 0


def test_check_status_reports_in_progress_when_scan_running():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "running"))
    status = C.check_consolidation_status(fc, kinds=("matches",), quiet_secs=1, now_ms=NOW,
                                          abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert status["any_in_progress"] is True
    assert status["eligible_count"] == 0
    assert status["pending_scan_ids"] == ["S1"]


def test_check_status_never_writes_or_deletes():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    before = {k: list(v) for k, v in fc.ds.items()}
    C.check_consolidation_status(fc, kinds=("matches", "scans"), quiet_secs=1, now_ms=NOW,
                                 log=lambda *a: None)
    assert fc.ds == before   # no target created, no shard deleted — pure read


def test_check_status_eligible_requires_both_kinds_ready():
    # S1's matches shard is done, but its scans shard shows still running - a status check
    # that only looked at one kind would wrongly call this eligible.
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "running"))
    status = C.check_consolidation_status(fc, kinds=("matches", "scans"), quiet_secs=1,
                                          now_ms=NOW, abandoned_after_secs=24 * 3600,
                                          log=lambda *a: None)
    assert status["eligible_count"] == 0
    assert "S1" in status["pending_scan_ids"]


# ------------------------------------------------------------- consolidate_all (mutating)
def test_consolidate_all_matches_existing_behavior():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 40))
    _seed(fc, "yara_scanner_matches_v2_hostb_bb0002", _m("S1", "hostb", 25))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S1", "hostb", "completed"))
    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert result["consolidated_count"] == 1
    assert result["consolidated_scan_ids"] == ["S1"]
    assert result["deferred_count"] == 0
    assert result["failed_count"] == 0
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 65


def test_consolidate_all_dry_run_reports_nothing_consolidated():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    result = C.consolidate_all(fc, kinds=("matches",), dry_run=True, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert result["consolidated_count"] == 0        # dry-run never sets ok=True
    assert "yara_scanner_matches_v2_scan_s1" not in fc.ds   # nothing written


def test_consolidate_all_reports_deferred_and_failed_separately():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "running"))
    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW, abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert result["consolidated_count"] == 0
    assert result["deferred_count"] == 1
    assert result["deferred_scan_ids"] == ["S1"]
    assert result["failed_count"] == 0


# --------------------------------------------------------- schema-version isolation (v2/v3)
def test_parse_shard_v3():
    p = parse_shard("yara_scanner_matches_v3_winhost01_ab12cd_202608")
    assert p["kind"] == "matches"
    assert p["ver"] == "3"
    assert p["host"] == "winhost01_ab12cd"


def _m3(scan, host, n, ts=1000):
    # v3 row shape: aggregated per (rule, file) finding, not per offset.
    return [{"scan_id": scan, "hostname": host, "rule": "R", "filename": "f%d" % i,
              "match_count": 5, "truncated": False, "offsets": "[]", "strings": "[]",
              "string_ids": "{}", "event_timestamp_ms": ts} for i in range(n)]


def test_run_consolidation_v2_ignores_v3_shards():
    # A v2 and a v3 shard for the SAME scan/host both exist (mid-rollout tenant). Consolidating
    # ver="2" must touch only the v2 shard — mixing the two under one schema would silently
    # mis-project v3's aggregated fields onto v2's per-offset columns (or vice versa).
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_matches_v3_hosta_aa0001", _m3("S1", "hosta", 4))
    _seed(fc, "yara_scanner_scans_v3_hosta_aa0001", _s("S1", "hosta", "completed"))

    plans = C.run_consolidation(fc, "matches", ver="2", quiet_secs=1, dry_run=False,
                                now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10
    assert "yara_scanner_matches_v2_hosta_aa0001" not in fc.ds     # v2 shard consolidated away
    assert "yara_scanner_matches_v3_hosta_aa0001" in fc.ds         # v3 shard untouched
    assert len(fc.ds["yara_scanner_matches_v3_hosta_aa0001"]) == 4  # and unmodified


def test_run_consolidation_v3_uses_v3_target_and_schema():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v3_hostb_bb0002", _m3("S2", "hostb", 7))
    _seed(fc, "yara_scanner_scans_v3_hostb_bb0002", _s("S2", "hostb", "completed"))

    plans = C.run_consolidation(fc, "matches", ver="3", quiet_secs=1, dry_run=False,
                                now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert "yara_scanner_matches_v3_scan_s2" in fc.ds
    assert len(fc.ds["yara_scanner_matches_v3_scan_s2"]) == 7
    row = fc.ds["yara_scanner_matches_v3_scan_s2"][0]
    assert "match_count" in row and "offset" not in row   # v3 fields, not v2's


def test_check_consolidation_status_covers_both_versions_by_default():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_matches_v3_hostb_bb0002", _m3("S2", "hostb", 3))
    _seed(fc, "yara_scanner_scans_v3_hostb_bb0002", _s("S2", "hostb", "completed"))

    status = C.check_consolidation_status(fc, quiet_secs=1, now_ms=NOW, log=lambda *a: None)
    assert status["eligible_scan_ids"] == ["S1", "S2"]


def test_consolidate_all_processes_matches_before_scans():
    # Real bug found live: consolidating "scans" before "matches" deletes the ONLY source of
    # terminal-lifecycle truth (the scans shard) before the matches pass ever reads it. The
    # matches pass then rebuilds its OWN terminal map from whatever scans shards still exist
    # -- finds none for this host -- and defers a scan that has, in fact, already finished.
    # A single host/single scan is the minimal case: nothing else keeps the scans shard alive.
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    result = C.consolidate_all(fc, dry_run=False, quiet_secs=1, now_ms=NOW, log=lambda *a: None)
    assert result["consolidated_scan_ids"] == ["S1"]
    assert result["deferred_count"] == 0, (
        "matches deferred as 'not terminal' because scans consolidation ran (and deleted its "
        "source) first -- kinds must process matches before scans")
    assert "yara_scanner_matches_v2_scan_s1" in fc.ds
    assert "yara_scanner_scans_v2_scan_s1" in fc.ds


def test_consolidate_all_reports_why_a_scan_failed():
    # Edge case #19: failed_scan_ids alone can't tell row_ceiling_exceeded (safe, just
    # oversized) apart from count_mismatch (a real integrity concern) - failed_reasons must
    # carry plan_consolidation's own reason string through.
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               row_ceiling=5, now_ms=NOW, log=lambda *a: None)
    assert result["failed_scan_ids"] == ["S1"]
    assert result["failed_reasons"] == {"S1": "row_ceiling_exceeded"}


def test_check_consolidation_status_reports_why_a_scan_is_blocked():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    status = C.check_consolidation_status(fc, kinds=("matches",), quiet_secs=1,
                                          row_ceiling=5, now_ms=NOW, log=lambda *a: None)
    assert status["blocked_scan_ids"] == ["S1"]
    assert status["blocked_reasons"] == {"S1": "row_ceiling_exceeded"}


def test_consolidate_all_covers_both_versions_by_default():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_matches_v3_hostb_bb0002", _m3("S2", "hostb", 3))
    _seed(fc, "yara_scanner_scans_v3_hostb_bb0002", _s("S2", "hostb", "completed"))

    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert result["consolidated_scan_ids"] == ["S1", "S2"]
    assert "yara_scanner_matches_v2_scan_s1" in fc.ds
    assert "yara_scanner_matches_v3_scan_s2" in fc.ds


# --------------------------------------------------------------- overlap guard (edge case #31)
def test_acquire_lock_fresh():
    fc = FakeClient()
    assert C.acquire_consolidation_lock(fc, now_ms=NOW, log=lambda *a: None) is True
    assert C._LOCK_DATASET in fc.ds
    assert fc.ds[C._LOCK_DATASET][0]["started_ms"] == NOW


def test_acquire_lock_blocked_when_already_held():
    fc = FakeClient()
    assert C.acquire_consolidation_lock(fc, now_ms=NOW, log=lambda *a: None) is True
    # a second run, moments later, must NOT also acquire
    assert C.acquire_consolidation_lock(fc, now_ms=NOW + 1000, log=lambda *a: None) is False


def test_acquire_lock_steals_stale_lock():
    fc = FakeClient()
    assert C.acquire_consolidation_lock(fc, now_ms=NOW, log=lambda *a: None) is True
    # a crashed run's lock, found MUCH later - past the staleness window
    later = NOW + (C.DEFAULT_LOCK_STALE_SECS + 60) * 1000
    assert C.acquire_consolidation_lock(fc, now_ms=later, log=lambda *a: None) is True
    assert fc.ds[C._LOCK_DATASET][0]["started_ms"] == later  # re-stamped to the new holder


def test_release_lock_allows_reacquire():
    fc = FakeClient()
    C.acquire_consolidation_lock(fc, now_ms=NOW, log=lambda *a: None)
    C.release_consolidation_lock(fc, log=lambda *a: None)
    assert C._LOCK_DATASET not in fc.ds
    assert C.acquire_consolidation_lock(fc, now_ms=NOW + 1000, log=lambda *a: None) is True


def test_consolidate_all_skips_when_locked_by_another_run():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    C.acquire_consolidation_lock(fc, now_ms=NOW, holder="other-run", log=lambda *a: None)

    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW + 1000, log=lambda *a: None)
    assert result == {"consolidated_count": 0, "consolidated_scan_ids": [],
                       "deferred_count": 0, "deferred_scan_ids": [],
                       "failed_count": 0, "failed_scan_ids": [], "failed_reasons": {},
                       "lock_held_by_other_run": True}
    assert "yara_scanner_matches_v2_scan_s1" not in fc.ds   # nothing touched


def test_consolidate_all_dry_run_ignores_lock():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    C.acquire_consolidation_lock(fc, now_ms=NOW, holder="other-run", log=lambda *a: None)

    result = C.consolidate_all(fc, kinds=("matches",), dry_run=True, quiet_secs=1,
                               now_ms=NOW + 1000, log=lambda *a: None)
    assert result["lock_held_by_other_run"] is False   # dry runs never even check


def test_consolidate_all_releases_lock_after_completing():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))

    result = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert result["lock_held_by_other_run"] is False
    assert result["consolidated_scan_ids"] == ["S1"]
    assert C._LOCK_DATASET not in fc.ds   # released, a following run isn't blocked
    assert C.acquire_consolidation_lock(fc, now_ms=NOW + 1000, log=lambda *a: None) is True


# ------------------ per-scan row-level source cleanup (edge case #51a) ------------------
# Once an individual scan_id's target is verified, its rows must be stripped from every
# source shard it came from RIGHT AWAY (via client.remove_lookup_data), rather than waiting
# for the whole shard to become deletable -- otherwise a dashboard querying the
# yara_scanner_matches* wildcard double-counts that scan for as long as any OTHER scan
# sharing the shard is still unfinished.
class SpyClient(FakeClient):
    """FakeClient that also records remove_lookup_data/delete_dataset calls, in order, so
    tests can assert WHICH datasets were cleaned up and that cleanup happens before the
    eventual whole-shard delete -- not just infer it from final dataset membership, which
    can't tell "removed by the new per-scan cleanup" apart from "removed by the pre-existing
    whole-shard delete" when a shard holds only one scan."""
    def __init__(self):
        super().__init__()
        self.calls = []

    def remove_lookup_data(self, name, filters):
        self.calls.append(("remove_lookup_data", name, filters))
        return super().remove_lookup_data(name, filters)

    def delete_dataset(self, name, force=False):
        self.calls.append(("delete_dataset", name))
        return super().delete_dataset(name, force=force)


class RemoveFailsClient(FakeClient):
    """remove_lookup_data always raises, to exercise the required try/except around the new
    cleanup calls. Records that it was actually invoked, so a test using this client can't
    pass vacuously just because the implementation never calls remove_lookup_data at all."""
    def __init__(self):
        super().__init__()
        self.remove_attempts = 0

    def remove_lookup_data(self, name, filters):
        self.remove_attempts += 1
        raise RuntimeError("simulated remove_lookup_data failure")


def test_fresh_write_removes_scan_rows_from_source_shard_same_run():
    # PATH B: a scan that verifies via a fresh write this run must have its source rows
    # stripped out immediately, as part of THIS run_consolidation call.
    fc = SpyClient()
    shard = "yara_scanner_matches_v2_hosta_aa0001"
    _seed(fc, shard, _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10

    remove_calls = [c for c in fc.calls if c[0] == "remove_lookup_data"]
    assert remove_calls == [("remove_lookup_data", shard, [{"scan_id": "S1"}])]
    delete_calls = [c for c in fc.calls if c[0] == "delete_dataset" and c[1] == shard]
    assert delete_calls, "shard should still become fully deletable once its only scan is verified"
    assert fc.calls.index(remove_calls[0]) < fc.calls.index(delete_calls[0]), (
        "row-level cleanup must happen before the eventual whole-shard delete")


def test_shard_with_second_pending_scan_keeps_shard_but_drops_ready_scans_rows():
    # A shard holding TWO scan_ids, only one ready this run: the shard must SURVIVE (the
    # other scan still needs it) but the ready scan's rows must already be gone -- not left
    # duplicated in the shard until the other scan also finishes.
    fc = FakeClient()
    shard = "yara_scanner_matches_v2_hostx_cc0003"
    _seed(fc, shard, _m("S1", "hostx", 10) + _m("S2", "hostx", 7))
    _seed(fc, "yara_scanner_scans_v2_hostx_cc0003",
          _s("S1", "hostx", "completed") + _s("S2", "hostx", "running"))

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by = {p["scan_id"]: p for p in plans}
    assert by["S1"]["ok"] is True
    assert by["S2"]["reason"] == "host_not_terminal"

    assert shard in fc.ds                                   # kept: S2 still pending
    remaining = fc.ds[shard]
    assert len(remaining) == 7
    assert all(r["scan_id"] == "S2" for r in remaining), (
        "S1's rows must be stripped out immediately even though the shard itself survives")
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10


def test_dry_run_never_calls_remove_lookup_data_or_mutates_shard():
    fc = SpyClient()
    shard = "yara_scanner_matches_v2_hosta_aa0001"
    _seed(fc, shard, _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    before = list(fc.ds[shard])

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=True, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["reason"] == "dry_run"
    assert fc.ds[shard] == before   # byte-identical, untouched
    assert not any(c[0] == "remove_lookup_data" for c in fc.calls)


def test_remove_lookup_data_failure_does_not_crash_or_flip_ok():
    fc = RemoveFailsClient()
    shard = "yara_scanner_matches_v2_hosta_aa0001"
    _seed(fc, shard, _m("S1", "hosta", 10))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True   # target write was already safely verified
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10
    assert fc.remove_attempts >= 1, "cleanup must actually have been attempted (and failed)"
    # the failed cleanup must not block the eventual whole-shard delete either
    assert shard not in fc.ds


def test_path_a_idempotent_reverify_also_removes_source_rows():
    # PATH A: the target already holds exactly this scan's rows (a prior run wrote+verified
    # it but its cleanup call failed). This run must take the idempotent short-circuit AND
    # retry the cleanup -- otherwise a retry of a previously-failed cleanup never happens.
    # A second, not-yet-ready scan in the same shard keeps the shard alive so the row-level
    # effect is observable separately from the eventual whole-shard delete.
    fc = FakeClient()
    shard = "yara_scanner_matches_v2_hostx_cc0003"
    _seed(fc, shard, _m("S1", "hostx", 10) + _m("S2", "hostx", 7))
    _seed(fc, "yara_scanner_scans_v2_hostx_cc0003",
          _s("S1", "hostx", "completed") + _s("S2", "hostx", "running"))
    # Pre-seed S1's per-scan target as already complete.
    fc.ds["yara_scanner_matches_v2_scan_s1"] = _m("S1", "hostx", 10)

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by = {p["scan_id"]: p for p in plans}
    assert by["S1"]["ok"] is True
    assert by["S1"]["reason"] != "dry_run"
    assert by["S2"]["reason"] == "host_not_terminal"
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 10   # unchanged, not doubled

    assert shard in fc.ds                                   # kept: S2 still pending
    remaining = fc.ds[shard]
    assert len(remaining) == 7
    assert all(r["scan_id"] == "S2" for r in remaining), (
        "PATH A (idempotent re-verify) must ALSO trigger the row-level cleanup")


def test_scan_spanning_two_source_shards_gets_cleanup_on_both():
    # A scan whose run straddles a monthly-rotation boundary can have rows in two shards for
    # the same host. Cleanup must be applied to EVERY source, not just the first.
    fc = SpyClient()
    shard1 = "yara_scanner_matches_v2_hosta_aa0001_202607"
    shard2 = "yara_scanner_matches_v2_hosta_aa0001_202608"
    _seed(fc, shard1, _m("S1", "hosta", 5))
    _seed(fc, shard2, _m("S1", "hosta", 3))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))

    plans = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 8

    remove_targets = sorted(c[1] for c in fc.calls if c[0] == "remove_lookup_data")
    assert remove_targets == sorted([shard1, shard2]), (
        "a scan spanning two source shards must get cleanup applied to BOTH, not just one")


# ---------- review follow-up: scoping and idempotency of the row-level cleanup ----------
def test_scans_kind_cleanup_does_not_strip_terminal_lifecycle_row():
    # Review finding (major #2): the row-level cleanup must be scoped to kind=="matches"
    # only. A "scans" shard's rows are the SOLE source of build_terminal_map's lifecycle
    # signal for every scan_id on that host -- stripping a verified scan's status row out
    # from under a still-pending sibling scan sharing the same shard would make a LATER,
    # separate run_consolidation call lose its terminal signal entirely and misclassify a
    # cleanly-finished scan as stuck (until the 24h abandoned-scan cutoff bails it out).
    fc = SpyClient()
    scans_shard = "yara_scanner_scans_v2_hostb_bb0002"
    _seed(fc, scans_shard, _s("S1", "hostb", "completed") + _s("S2", "hostb", "running"))

    plans = C.run_consolidation(fc, "scans", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by = {p["scan_id"]: p for p in plans}
    assert by["S1"]["ok"] is True
    assert by["S2"]["reason"] == "host_not_terminal"

    assert not any(c[0] == "remove_lookup_data" for c in fc.calls), (
        "kind=='scans' must never call the row-level cleanup -- it would strip a scan's "
        "terminal-lifecycle row out from under a still-pending sibling on the same shard")
    assert scans_shard in fc.ds
    assert len(fc.ds[scans_shard]) == 2   # both S1's and S2's status rows still intact

    # A LATER, separate run_consolidation call for "matches" on the same scan must still see
    # S1 as terminal via its lifecycle row, which the scans-kind cleanup must not have touched.
    matches_shard = "yara_scanner_matches_v2_hostb_bb0002"
    _seed(fc, matches_shard, _m("S1", "hostb", 5))
    plans2 = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    assert plans2[0]["ok"] is True, (
        "S1's matches consolidation must not defer as non-terminal -- its lifecycle row in "
        "the scans shard must have survived the earlier scans-kind cleanup")


class SelectiveRemoveFailsClient(FakeClient):
    """remove_lookup_data raises for one specific dataset name, a bounded number of times,
    then behaves normally -- models a TRANSIENT failure on ONE of a multi-shard scan's
    sources (a network blip on that call only), not a permanently broken client."""
    def __init__(self, fail_for, fail_times=1):
        super().__init__()
        self.fail_for = fail_for
        self.fail_times = fail_times
        self._fail_count = 0

    def remove_lookup_data(self, name, filters):
        if name == self.fail_for and self._fail_count < self.fail_times:
            self._fail_count += 1
            raise RuntimeError("simulated transient remove_lookup_data failure")
        return super().remove_lookup_data(name, filters)


def test_partial_cleanup_failure_does_not_cause_permanent_count_mismatch():
    # Review findings (blocker #1 / major #3): S1's rows live in shard_a (S1 only) and
    # shard_b (S1 + still-pending S2). remove_lookup_data fails ONCE, only on shard_b. Run 1:
    # S1 verifies; cleanup succeeds on shard_a, which then becomes wholly deletable (S1 was
    # its only scan) and IS whole-deleted in the same run's deletion pass; cleanup on shard_b
    # fails (caught, logged), leaving shard_b's S1 rows in place (S2 keeps the shard alive
    # regardless). A naive re-derivation of src_total from currently-live shards on run 2
    # would then see only shard_b's count -- permanently smaller than the target's actual,
    # correct row count -- misreport count_mismatch forever, never retry the failed cleanup
    # again, and leave shard_b undeletable even after S2 later finishes.
    shard_a = "yara_scanner_matches_v2_hosta_aa0001"
    shard_b = "yara_scanner_matches_v2_hostb_bb0002"
    fc = SelectiveRemoveFailsClient(fail_for=shard_b, fail_times=1)
    _seed(fc, shard_a, _m("S1", "hosta", 5))
    _seed(fc, shard_b, _m("S1", "hostb", 3) + _m("S2", "hostb", 4))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002",
          _s("S1", "hostb", "completed") + _s("S2", "hostb", "running"))

    plans1 = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by1 = {p["scan_id"]: p for p in plans1}
    assert by1["S1"]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 8
    assert shard_a not in fc.ds          # fully cleaned + whole-deleted (S1 was its only scan)
    assert shard_b in fc.ds              # S1's cleanup failed here; S2 keeps it alive anyway
    assert len(fc.ds[shard_b]) == 7      # S1's 3 rows NOT removed (cleanup call failed)

    # Run 2: identical inputs (S2 still running, nothing else changed). Must stay verified --
    # NOT flip to count_mismatch -- and must retry (and this time succeed at) the cleanup
    # that failed on shard_b.
    plans2 = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by2 = {p["scan_id"]: p for p in plans2}
    assert by2["S1"]["ok"] is True
    assert by2["S1"]["reason"] != "count_mismatch"
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 8   # unchanged -- not rewritten/duplicated
    assert shard_b in fc.ds                                     # S2 still pending, shard survives
    assert all(r["scan_id"] == "S2" for r in fc.ds[shard_b]), (
        "run 2 must have retried and succeeded at removing S1's stale rows from shard_b")

    # Run 3, once S2 also finishes: shard_b must finally become whole-deletable.
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002",
          _s("S1", "hostb", "completed") + _s("S2", "hostb", "completed"))
    plans3 = C.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW, log=lambda *a: None)
    by3 = {p["scan_id"]: p for p in plans3}
    assert by3["S2"]["ok"] is True
    assert shard_b not in fc.ds, (
        "shard_b must not be a permanent zombie -- once every scan sharing it is verified, "
        "it must still become whole-deletable")


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
