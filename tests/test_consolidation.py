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
        self.ds.setdefault(name, [])
        return {"status": "ok"}

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
    assert len(fc.ds[shard]) == 17                              # S2 rows intact


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


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
