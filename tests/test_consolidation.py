#!/usr/bin/env python3
"""Unit tests for dataset consolidation logic — pure, no network.

The consolidation functions take a `client` with a small interface (xql, get_datasets,
create_lookup_dataset, add_lookup_data, delete_dataset, action_status). Here that client
is a deterministic fake, so gate logic and verify-before-delete are tested exhaustively
without a tenant. Live behaviour is validated separately against the real API.
"""
import ast
import os
import re
import sys

import pytest

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


def test_terminal_map_newest_ms_is_skew_proof_and_never_raises():
    # newest_ms sits in the same entry as `terminal`, so it is the obvious value for a future
    # caller to reach for as a freshness signal. It must therefore be computed the same
    # skew-proof way the gates are (edge case #6), not from the bare endpoint stamp — and a
    # non-numeric stamp must degrade to "no signal" rather than raise ValueError and abort the
    # whole consolidation pass.
    scans_rows = {
        "yara_scanner_scans_v2_hostA_aa0001": [
            {"scan_id": "S1", "status": "running", "event_timestamp_ms": 100,
             "_insert_time": 900},                        # endpoint clock behind
            {"scan_id": "S2", "status": "running", "event_timestamp_ms": "n/a"},
        ],
    }
    tmap = build_terminal_map(scans_rows)
    assert tmap[("S1", "hostA_aa0001")]["newest_ms"] == 900   # server stamp wins
    assert tmap[("S2", "hostA_aa0001")]["newest_ms"] is None  # unreadable -> no signal
    assert tmap[("S2", "hostA_aa0001")]["status"] == "running"


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

    # `comp count() as n, max(<col>) as <alias>[, ...] by scan_id` — parsed out of the query
    # text rather than assumed, so the fake can only return a column production ACTUALLY asked
    # for, under the alias it was actually asked for. Hardcoding the output keys here made the
    # whole skew fix untestable: reverting the query to the pre-fix form, or renaming the
    # alias, left the suite green while the fix was 100% disabled in production.
    _AGG_MAX_RE = re.compile(
        r"max\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)")
    _AGG_COUNT_RE = re.compile(r"count\(\s*\)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)")

    def xql(self, query, limit=1000):
        name = query.split("dataset = ", 1)[1].split(" ", 1)[0].strip()
        rows = self.ds.get(name, [])
        if "by scan_id" in query:   # _scan_stats aggregation
            # The two "newest" signals the live tenant can supply, each returned ONLY if the
            # query asked for it:
            #   max(event_timestamp_ms) — stamped ON THE ENDPOINT, so it moves with (and lies
            #                             with) that endpoint's system clock.
            #   max(_insert_time)       — the platform's own server-side ingest stamp, immune
            #                             to endpoint clock skew.
            # A seeded row without _insert_time contributes nothing, so the alias comes back
            # None — how a platform/dataset that does not surface the column degrades.
            wants = self._AGG_MAX_RE.findall(query)
            count_alias = self._AGG_COUNT_RE.findall(query)
            agg = {}
            for r in rows:
                sid = r.get("scan_id")
                cur = agg.setdefault(sid, {"n": 0, "max": {}})
                cur["n"] += 1
                for col, alias in wants:
                    v = r.get(col)
                    if v is None:
                        continue
                    v = int(float(v))
                    prev = cur["max"].get(alias)
                    cur["max"][alias] = v if prev is None else max(prev, v)
            out = []
            for sid, cur in agg.items():
                row = {"scan_id": sid}
                for alias in count_alias:
                    row[alias] = cur["n"]
                for _col, alias in wants:
                    row[alias] = cur["max"].get(alias)
                out.append(row)
            return out
        if "comp count()" in query:
            return [{"n": len(rows)}]
        def readback(r):
            # Mirror XQL read-back: system columns come back on every row, and numbers come
            # back as strings (offset comes back as text live) so coercion is exercised. A row
            # seeded with its own _insert_time keeps it — that is the server-side ingest stamp
            # the skew-proof "newest" calculation leans on — and it is stringified like every
            # other number, since that is the one type behaviour this repo has live evidence of.
            out = dict(r)
            out.setdefault("_insert_time", 1)
            out["_insert_time"] = str(out["_insert_time"])
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


# ------------------------------------------- endpoint clock skew (edge case #6)
# event_timestamp_ms is stamped ON THE ENDPOINT, so an endpoint whose system clock runs
# BEHIND writes rows that look older than they are. Both time gates (quiet period, abandoned
# cutoff) measured age from that stamp alone, so such a host's LIVE scan could be declared
# abandoned/settled and have its shard consolidated + deleted out from under it. The fix
# takes max(event_timestamp_ms, _insert_time) with implausible values discarded first;
# _insert_time is server-stamped at ingest, so it stays ~"now" while the scan is uploading.
#
# These tests were checked against deliberate mutations of the implementation — each of the
# following was introduced and confirmed to make this block FAIL, so the block discriminates
# the fix from its absence rather than merely co-existing with it:
#   _newest_ms returning the endpoint stamp alone (fix neutralised)  -> 8 failures
#   _newest_ms as a bare max() with no plausibility guards           -> 3 failures
#   the comp stage reverted to its pre-fix, event_timestamp_ms-only form -> 9 failures
#   the srv_newest alias renamed in the query only                   -> 9 failures
#   _gate_scan's `settled` backstop removed                          -> 1 failure
#   _as_ms trimmed to a single int() attempt                         -> 1 failure
def _skewed(rows, srv_ms):
    """Rows as an endpoint with a behind-running clock wrote them: the caller already set a
    stale event_timestamp_ms; srv_ms is when the platform ACTUALLY ingested them."""
    return [dict(r, _insert_time=srv_ms) for r in rows]


def test_as_ms_accepts_every_shape_xql_returns_and_never_raises():
    # _as_ms is the single choke point for every stamp the gates read. XQL read-back is known
    # (live, see _coerce_row) to hand numbers back as strings and as floats, so trimming this
    # to a bare int() would silently drop the server stamp — disabling the skew fix with a
    # green suite. Anything unreadable must degrade to None, never raise: a stamp this can't
    # parse must not abort a whole consolidation pass.
    assert C._as_ms(1799999995000) == 1799999995000
    assert C._as_ms(1799999995000.0) == 1799999995000
    assert C._as_ms("1799999995000") == 1799999995000
    assert C._as_ms("1799999995000.0") == 1799999995000
    assert C._as_ms("1.8e12") == 1800000000000
    assert C._as_ms("2026-08-10T09:46:56.000Z") == 1786355216000   # ISO form, if it ever comes
    assert C._as_ms("2026-08-10T09:46:56") == 1786355216000        # naive -> read as UTC
    assert C._as_ms(None) is None
    assert C._as_ms("") is None
    assert C._as_ms("n/a") is None
    assert C._as_ms(True) is None       # a bool is an int in Python; as a stamp it is garbage


def test_scan_stats_query_actually_asks_the_tenant_for_insert_time():
    # The alias/column pair the fix depends on. Reverting the query to the pre-fix form or
    # renaming the alias disables the protection completely in production, so pin the request
    # itself, not just what a fake chooses to answer with.
    seen = []

    class QuerySpy(FakeClient):
        def xql(self, query, limit=1000):
            seen.append(query)
            return super().xql(query, limit=limit)

    fc = QuerySpy()
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011", _m("S1", "hostk", 1))
    C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011")
    assert any("max(_insert_time) as srv_newest" in q and "by scan_id" in q for q in seen), seen


def test_scan_stats_prefers_server_insert_time_when_endpoint_clock_is_behind():
    fc = FakeClient()
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011",
          _skewed(_m("S1", "hostk", 4, ts=stale), fresh))
    st = C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011")["S1"]
    assert st.count == 4
    assert st.newest == fresh       # the server-side stamp wins — the rows are seconds old
    assert st.ep_newest == stale    # the endpoint stamp is kept separately for the backstop


def test_scan_stats_keeps_endpoint_stamp_when_it_is_the_newer_of_the_two():
    # Endpoint stamp AHEAD of ingest but within SKEW_TOLERANCE_MS: that is ordinary
    # clock jitter, not a wrong clock, so max() keeps it (only ever delays consolidation).
    fc = FakeClient()
    ingested = RNOW - 5000
    ahead = ingested + 60_000        # 1 minute — inside the 5-minute tolerance
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011",
          _skewed(_m("S1", "hostk", 2, ts=ahead), ingested))
    assert C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011",
                         now_ms=RNOW)["S1"].newest == ahead


def test_scan_stats_discards_endpoint_stamp_far_ahead_of_the_ingest_stamp():
    # Clock AHEAD by an hour. A row cannot be authored after the platform ingested it, so the
    # endpoint stamp is discarded rather than maxed in. Keeping it would make now_ms - newest
    # NEGATIVE forever: quiet period never satisfied, abandoned cutoff never reached, shard
    # never deletable — the stuck-forever failure the cutoff exists to prevent.
    fc = FakeClient()
    ahead, ingested = RNOW + 3600 * 1000, RNOW - 5000
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011",
          _skewed(_m("S1", "hostk", 2, ts=ahead), ingested))
    assert C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011",
                         now_ms=RNOW)["S1"].newest == ingested


def test_scan_stats_discards_a_server_stamp_in_an_implausible_unit():
    # If a platform ever returned _insert_time in microseconds, a bare max() would adopt a
    # value ~57,000 years ahead and stall EVERY scan on the tenant forever. A stamp far in the
    # future of this run's own clock is dropped in favour of the endpoint's, i.e. it degrades
    # to pre-fix behaviour instead of to a fleet-wide deadlock.
    fc = FakeClient()
    ts = RNOW - 7000
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011",
          _skewed(_m("S1", "hostk", 2, ts=ts), RNOW * 1000))   # microseconds by mistake
    assert C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011",
                         now_ms=RNOW)["S1"].newest == ts


def test_scan_stats_falls_back_to_event_timestamp_without_insert_time():
    # No _insert_time at all (older platform / column absent) -> exactly today's behaviour.
    fc = FakeClient()
    ts = RNOW - 7000
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011", _m("S1", "hostk", 3, ts=ts))
    assert C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011")["S1"] == (3, ts, ts)


def test_scan_stats_logs_when_the_skew_protection_is_inactive():
    # A silently-inactive protection is the worst outcome of the two failure shapes here, so
    # a shard that returns no usable _insert_time must say so in the run log.
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hostk_ab0011", _m("S1", "hostk", 2, ts=RNOW - 7000))
    lines = []
    C._scan_stats(fc, "yara_scanner_matches_v2_hostk_ab0011", log=lines.append)
    assert any("INACTIVE" in ln and "_insert_time" in ln for ln in lines), lines
    # and the healthy case must NOT cry wolf
    fc2 = FakeClient()
    _seed(fc2, "yara_scanner_matches_v2_hostk_ab0011",
          _skewed(_m("S1", "hostk", 2, ts=RNOW - 7000), RNOW - 5000))
    quiet = []
    C._scan_stats(fc2, "yara_scanner_matches_v2_hostk_ab0011", log=quiet.append)
    assert not any("INACTIVE" in ln for ln in quiet), quiet


def test_stats_from_rows_prefers_server_insert_time_when_endpoint_clock_is_behind():
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    rows = _skewed(_s("S1", "hostk", "running", ts=stale), fresh)
    assert C._stats_from_rows(rows)["S1"] == (1, fresh, stale)
    # the same rows as XQL read-back actually returns them — numbers stringified
    as_text = [{k: (str(v) if k in ("event_timestamp_ms", "_insert_time") else v)
                for k, v in r.items()} for r in rows]
    assert C._stats_from_rows(as_text)["S1"] == (1, fresh, stale)


def test_stats_from_rows_falls_back_to_event_timestamp_without_insert_time():
    ts = RNOW - 7000
    rows = _s("S1", "hostk", "running", ts=ts)
    assert C._stats_from_rows(rows)["S1"] == (1, ts, ts)
    # a present-but-null _insert_time must degrade the same way, not crash or win
    rows_null = [dict(r, _insert_time=None) for r in rows]
    assert C._stats_from_rows(rows_null)["S1"] == (1, ts, ts)
    # an unreadable one likewise — degrade to the endpoint stamp, never raise
    rows_junk = [dict(r, _insert_time="n/a") for r in rows]
    assert C._stats_from_rows(rows_junk)["S1"] == (1, ts, ts)


def test_orchestration_clock_behind_endpoint_is_not_swept_as_abandoned():
    # THE data-loss case: a live scan on a host whose clock is 48h behind. Its rows LOOK
    # older than the 24h abandoned cutoff, but the platform ingested them seconds ago.
    fc = FakeClient()
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    shard = "yara_scanner_matches_v2_hostskew_dd0004"
    _seed(fc, shard, _skewed(_m("S7", "hostskew", 9, ts=stale), fresh))
    _seed(fc, "yara_scanner_scans_v2_hostskew_dd0004",
          _skewed(_s("S7", "hostskew", "running", ts=stale), fresh))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s7" not in fc.ds   # nothing written
    assert len(fc.ds[shard]) == 9                           # shard and its rows survive


def test_orchestration_clock_behind_endpoint_still_blocked_by_quiet_period():
    # Same skew, but the host DID report terminal, so the abandoned cutoff is not what is
    # protecting it — the quiet period is. Its uploader may still be draining, so a stale
    # event_timestamp_ms must not let the shard be consolidated + deleted early.
    fc = FakeClient()
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    shard = "yara_scanner_matches_v2_hostskew_dd0004"
    _seed(fc, shard, _skewed(_m("S7", "hostskew", 9, ts=stale), fresh))
    _seed(fc, "yara_scanner_scans_v2_hostskew_dd0004",
          _skewed(_s("S7", "hostskew", "completed", ts=stale), fresh))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "within_quiet_period"
    assert "yara_scanner_matches_v2_scan_s7" not in fc.ds
    assert len(fc.ds[shard]) == 9


def test_orchestration_genuinely_stale_scan_is_still_abandoned_and_consolidated():
    # The over-correction guard: when BOTH stamps are old (a real orphan — nothing has been
    # ingested for 48h either), the gates must still fire exactly as before. The fix must not
    # amount to "never sweep anything".
    fc = FakeClient()
    stale = RNOW - 48 * 3600 * 1000
    shard = "yara_scanner_matches_v2_hostold_dd0005"
    _seed(fc, shard, _skewed(_m("S8", "hostold", 6, ts=stale), stale))
    _seed(fc, "yara_scanner_scans_v2_hostold_dd0005",
          _skewed(_s("S8", "hostold", "running", ts=stale), stale))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s8"]) == 6   # findings preserved
    assert shard not in fc.ds                                   # shard now deletable


def test_orchestration_scans_kind_clock_behind_endpoint_is_not_swept_as_abandoned():
    # Same protection on the scans-kind path, which reads already-pulled rows
    # (_stats_from_rows) instead of the aggregation (_scan_stats).
    fc = FakeClient()
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    shard = "yara_scanner_scans_v2_hostskew_dd0004"
    _seed(fc, shard, _skewed(_s("S7", "hostskew", "running", ts=stale), fresh))
    plans = C.run_consolidation(fc, "scans", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_scans_v2_scan_s7" not in fc.ds
    assert len(fc.ds[shard]) == 1


def test_orchestration_scans_kind_genuinely_stale_is_still_abandoned():
    fc = FakeClient()
    stale = RNOW - 48 * 3600 * 1000
    shard = "yara_scanner_scans_v2_hostold_dd0005"
    _seed(fc, shard, _skewed(_s("S8", "hostold", "running", ts=stale), stale))
    plans = C.run_consolidation(fc, "scans", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_scans_v2_scan_s8"]) == 1
    assert shard not in fc.ds


def test_orchestration_clock_ahead_endpoint_does_not_stall_forever():
    # The OTHER skew direction, and the one a bare max() would make permanent: an endpoint
    # whose clock reads a year into the future. now_ms - event_timestamp_ms is negative, so
    # the quiet period could never be satisfied and the abandoned cutoff could never fire —
    # the scan would be un-consolidatable and its shard un-deletable for as long as the tenant
    # exists. The ingest stamp is trustworthy by construction, so it governs instead.
    fc = FakeClient()
    ahead, ingested = RNOW + 365 * 24 * 3600 * 1000, RNOW - 10 * 24 * 3600 * 1000
    shard = "yara_scanner_matches_v2_hostfuture_dd0006"
    _seed(fc, shard, _skewed(_m("S6", "hostfuture", 4, ts=ahead), ingested))
    _seed(fc, "yara_scanner_scans_v2_hostfuture_dd0006",
          _skewed(_s("S6", "hostfuture", "completed", ts=ahead), ingested))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s6"]) == 4
    assert shard not in fc.ds


def test_orchestration_backstop_stops_a_sibling_cleanup_deferring_the_cutoff_forever():
    # The abandoned cutoff's whole job is to guarantee nothing blocks cleanup forever, and it
    # now measures against max(event_timestamp_ms, _insert_time). _insert_time is only "when
    # the endpoint's row was ingested" as long as nothing rewrites the shard — but this tool
    # rewrites shards itself (row-level cleanup of a sibling scan). If the platform implements
    # that as a rewrite, an orphan's server stamp is re-armed every pass and its age never
    # reaches the cutoff. Past the backstop the ENDPOINT stamp alone (which nothing but the
    # endpoint can re-arm) is enough to call it abandoned.
    fc = FakeClient()
    ep_old = RNOW - 8 * 24 * 3600 * 1000        # endpoint wrote nothing for 8 days
    srv_bumped = RNOW - 1000                    # ...but a sibling's cleanup re-stamped it 1s ago
    shard = "yara_scanner_matches_v2_hostzombie_dd0007"
    _seed(fc, shard, _skewed(_m("S5", "hostzombie", 3, ts=ep_old), srv_bumped))
    _seed(fc, "yara_scanner_scans_v2_hostzombie_dd0007",
          _skewed(_s("S5", "hostzombie", "running", ts=ep_old), srv_bumped))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds["yara_scanner_matches_v2_scan_s5"]) == 3   # findings preserved
    assert shard not in fc.ds                                   # and the shard stops being a zombie


def test_orchestration_backstop_does_not_fire_within_a_plausible_skew():
    # The backstop must not undo the fix it backs up: a clock 3 days behind is well inside the
    # skew range this protects against, so a live scan on such a host must still be deferred.
    fc = FakeClient()
    ep_old, srv_fresh = RNOW - 3 * 24 * 3600 * 1000, RNOW - 5000
    shard = "yara_scanner_matches_v2_hostslow_dd0008"
    _seed(fc, shard, _skewed(_m("S4", "hostslow", 3, ts=ep_old), srv_fresh))
    _seed(fc, "yara_scanner_scans_v2_hostslow_dd0008",
          _skewed(_s("S4", "hostslow", "running", ts=ep_old), srv_fresh))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s4" not in fc.ds
    assert len(fc.ds[shard]) == 3


def test_orchestration_scan_spanning_a_healthy_and_a_skewed_host_defers_entirely():
    # Multi-host blast radius: a scan spanning a cleanly-finished host and one whose clock is
    # 48h behind and is still running. _gate_scan walks EVERY source, so the whole scan must
    # defer — and crucially the healthy host's shard must not be deleted either, since its
    # rows are only safe to drop once the scan's target holds every host's rows.
    fc = FakeClient()
    stale, fresh = RNOW - 48 * 3600 * 1000, RNOW - 5000
    old = RNOW - 6 * 3600 * 1000
    healthy = "yara_scanner_matches_v2_hostgood_aa0021"
    skewed = "yara_scanner_matches_v2_hostbad_bb0022"
    _seed(fc, healthy, _skewed(_m("S3", "hostgood", 5, ts=old), old))
    _seed(fc, skewed, _skewed(_m("S3", "hostbad", 4, ts=stale), fresh))
    _seed(fc, "yara_scanner_scans_v2_hostgood_aa0021",
          _skewed(_s("S3", "hostgood", "completed", ts=old), old))
    _seed(fc, "yara_scanner_scans_v2_hostbad_bb0022",
          _skewed(_s("S3", "hostbad", "running", ts=stale), fresh))
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s3" not in fc.ds
    assert len(fc.ds[healthy]) == 5 and len(fc.ds[skewed]) == 4


def test_orchestration_scan_with_no_readable_stamps_at_all_still_defers():
    # The degenerate case: neither stamp is readable on any row, so newest is None. None is
    # "no signal", NOT "settled" — a non-terminal scan must still defer rather than be swept.
    fc = FakeClient()
    shard = "yara_scanner_matches_v2_hostnots_cc0033"
    rows = [{k: v for k, v in r.items() if k != "event_timestamp_ms"}
            for r in _m("S2", "hostnots", 3)]
    _seed(fc, shard, rows)
    _seed(fc, "yara_scanner_scans_v2_hostnots_cc0033",
          [{k: v for k, v in r.items() if k != "event_timestamp_ms"}
           for r in _s("S2", "hostnots", "running")])
    plans = C.run_consolidation(fc, "matches", quiet_secs=900, dry_run=False, now_ms=RNOW,
                                abandoned_after_secs=24 * 3600, log=lambda *a: None)
    assert plans[0]["reason"] == "host_not_terminal"
    assert "yara_scanner_matches_v2_scan_s2" not in fc.ds
    assert len(fc.ds[shard]) == 3


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


def test_consolidate_all_dry_run_does_not_report_its_plans_as_failures():
    """A dry-run plan carries ok=None and reason="dry_run". Falling through to the else branch
    counted every previewed scan as FAILED: a healthy preview of three scans reported
    failed_count=3 with all three in failed_scan_ids, against docs that say to alarm only on
    failed_count. Observed live before the fix. They belong in their own bucket."""
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 5))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    result = C.consolidate_all(fc, kinds=("matches",), dry_run=True, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert result["failed_count"] == 0
    assert result["failed_scan_ids"] == []
    assert result["failed_reasons"] == {}
    assert result["would_count"] == 1               # previewed, not failed
    assert result["would_scan_ids"] == ["S1"]


def test_the_lock_held_result_carries_every_key_the_normal_result_does():
    """consolidate_all has two return sites. A key added to one and not the other is a
    KeyError waiting for whichever caller reads it on the stand-down path."""
    fc = FakeClient()
    C.acquire_consolidation_lock(fc, now_ms=NOW, holder="someone-else", log=lambda *a: None)
    held = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                             now_ms=NOW + 1000, log=lambda *a: None)
    assert held["lock_held_by_other_run"] is True
    fc2 = FakeClient()
    normal = C.consolidate_all(fc2, kinds=("matches",), dry_run=False, quiet_secs=1,
                               now_ms=NOW, log=lambda *a: None)
    assert sorted(held) == sorted(normal), (
        "return sites disagree: only in lock-held=%s, only in normal=%s"
        % (sorted(set(held) - set(normal)), sorted(set(normal) - set(held))))


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
                      # A pass that never ran cannot have left work behind; the key must
                      # still be present so callers can read it unconditionally.
                      "stopped_early": False,
                       "deferred_count": 0, "deferred_scan_ids": [],
                       "failed_count": 0, "failed_scan_ids": [], "failed_reasons": {},
                       # Same rule for the dry-run preview counters: a stand-down previewed
                       # nothing, but the keys are present so a caller never has to branch on
                       # which return site it got.
                       "would_count": 0, "would_scan_ids": [],
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


# ---------------- shipping copies must not drift from this module (edge case #6 follow-up) --
# Each of the six automations under Packs/YaraDatasetManagement/Scripts/ hand-carries a copy
# of this core logic — it has to, because an automation must be self-contained: the tenant
# does not resolve cross-script imports. Those six files, not xdr_consolidate.py, are what
# actually executes on the tenant, and none of them can be imported here as a plain module
# without the platform globals, so compare their gate logic structurally instead: same
# signature, same statements, ignoring comments and docstrings.
#
# Edge case #6 shipped fixed in one copy and unfixed in another precisely because nothing
# checked this. The gate used to compare xdr_consolidate.py against ONE library file that no
# tenant executes, which left the same hazard open six ways over: a fix could land in the CLI,
# be faithfully copied into that library, and still miss every file that runs. SHIPPING is
# imported rather than restated so this gate and the data-management gate can never disagree
# about what "ships" means.
from test_pack_data_management import SHIPPING, SHIPPING_PATHS  # noqa: E402

_XDR_CONSOLIDATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xdr", "xdr_consolidate.py")

# The whole ported core: every gate helper (these decide whether a live scan's shard gets
# deleted) plus the orchestration around them, which the pack's header calls a verbatim port.
_SHARED_GATE_FUNCS = (
    "_as_ms", "_newest_ms", "_max_ms", "newest_row_age_ok", "_scan_stats",
    "_warn_if_no_server_stamp", "_stats_from_rows", "_gate_scan", "build_terminal_map",
    "shard_is_terminal", "plan_consolidation", "parse_shard", "target_name", "_coerce_row",
    "_cleanup_verified_scan_rows", "_rows_of", "_rows_for_scan", "_added", "_count",
    "_delete_many", "_list_yara_datasets", "matches_schema_for", "_read_lock",
    "acquire_consolidation_lock", "release_consolidation_lock",
    "run_consolidation", "check_consolidation_status", "consolidate_all",
    "_is_live_overwrite_dataset")
_SHARED_CONSTS = ("SKEW_TOLERANCE_MS", "DEFAULT_SKEW_BACKSTOP_SECS", "DEFAULT_QUIET_SECS",
                  "DEFAULT_ABANDONED_SECS", "TERMINAL_LIFECYCLE", "TERMINAL_ACTION",
                  "_PREFIX", "_SHARD_RE", "MATCHES_SCHEMA", "MATCHES_SCHEMA_V3",
                  "SCANS_SCHEMA", "_MATCHES_SCHEMAS_BY_VER", "KNOWN_MATCHES_SCHEMA_VERSIONS",
                  "_WRITE_BATCH", "DELETE_CONCURRENCY", "DEFAULT_ROW_CEILING",
                  "_LOCK_DATASET", "_LOCK_SCHEMA", "DEFAULT_LOCK_STALE_SECS",
                  "DEFAULT_MAX_SCANS_PER_PASS")


def _logic_index(path):
    """{name: normalised source} for the shared functions and constants in a file, with
    docstrings and comments stripped so only executable logic is compared."""
    with open(path) as fh:
        tree = ast.parse(fh.read())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _SHARED_GATE_FUNCS:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]      # drop the docstring; wording may differ between copies
            out[node.name] = "def %s(%s):\n%s" % (
                node.name, ast.unparse(node.args),
                "\n".join(ast.unparse(s) for s in body))
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in _SHARED_CONSTS:
            out[node.targets[0].id] = ast.unparse(node)
    return out


@pytest.mark.parametrize("automation", SHIPPING)
def test_pack_copy_gate_logic_matches_xdr_consolidate(automation):
    """THE DRIFT GATE, one case per shipping automation.

    47 names — every gate helper that decides whether a live scan's shard gets deleted, plus
    the orchestration around them, plus the constants they read — compared statement by
    statement against xdr_consolidate.py in all six files that run on the tenant. A fix that
    lands in the CLI and misses even one automation fails here, naming that automation.
    """
    mine = _logic_index(_XDR_CONSOLIDATE)
    pack = _logic_index(SHIPPING_PATHS[automation])
    missing = sorted(set(_SHARED_GATE_FUNCS + _SHARED_CONSTS) - set(mine))
    assert not missing, "test is stale — not found in xdr_consolidate.py: %s" % missing
    for name in sorted(mine):
        assert name in pack, (
            "%s is missing from %s — the tenant runs THAT file, so a fix that lands only in "
            "xdr_consolidate.py does nothing on the tenant"
            % (name, SHIPPING_PATHS[automation]))
        assert pack[name] == mine[name], (
            "%s has drifted between xdr_consolidate.py and %s:\n--- xdr_consolidate\n%s"
            "\n--- %s\n%s" % (name, automation, mine[name], automation, pack[name]))


# ---------------- the lock is gated by who TAKES it, not by SHIPPING membership -----------
# acquire_consolidation_lock / release_consolidation_lock are already in _SHARED_GATE_FUNCS
# above, so the gate does compare them - but only across SHIPPING, the five automations that
# carry the consolidation core. YaraWipeAllDatasets is deliberately NOT in SHIPPING (it has no
# selection rules, no schema_version, no retention window to compare - see the comment above
# OTHER_AUTOMATIONS in test_pack_data_management.py), yet it takes the SAME lock on the SAME
# dataset as every other destructive pass.
#
# That gap was not theoretical. The wipe's copy had drifted: it lost `unreadable_is_held` and
# `on_takeover`, the two knobs xdr_consolidate.py's own docstring says exist "for callers whose
# cost of a WRONG takeover is irreversible (dataset deletion)". That describes the wipe and
# nothing else in the pack, so the guard was missing from the single place it mattered most -
# an unreadable lock row is the ordinary add_data create-lag window right after another run
# took the lock, and reading it as stale let a wipe delete every source dataset out from under
# a consolidation pass still in flight. The whole suite stayed green throughout.
#
# So gate on the property that actually matters: if a file takes the lock, its lock code must
# match the canonical. Membership of SHIPPING is irrelevant to that, and discovering the files
# from the filesystem means a new lock-taking automation is covered the day it lands.
_LOCK_NAMES = ("_read_lock", "acquire_consolidation_lock", "release_consolidation_lock",
               "_LOCK_DATASET", "_LOCK_SCHEMA", "DEFAULT_LOCK_STALE_SECS")

_PACK_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "xdr", "Packs", "YaraDatasetManagement", "Scripts")


def _lock_bearing_automations():
    """Every automation in the pack that defines acquire_consolidation_lock."""
    found = []
    for d in sorted(os.listdir(_PACK_SCRIPTS)):
        path = os.path.join(_PACK_SCRIPTS, d, "%s.py" % d)
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            tree = ast.parse(fh.read())
        if any(isinstance(n, ast.FunctionDef) and n.name == "acquire_consolidation_lock"
               for n in tree.body):
            found.append(d)
    return found


def test_the_lock_gate_covers_more_than_shipping():
    """The gate above is the reason this one exists; if the two ever coincide, say so.

    If every lock-bearing automation were in SHIPPING, this file's parametrisation would be
    redundant with test_pack_copy_gate_logic_matches_xdr_consolidate and could be deleted.
    It is not: YaraWipeAllDatasets takes the lock and is not in SHIPPING. Assert that, so
    that a future refactor which folds it into SHIPPING is forced to revisit this comment
    rather than leaving a silently-duplicated gate behind."""
    bearers = set(_lock_bearing_automations())
    assert bearers, "no automation defines acquire_consolidation_lock — gate is stale"
    outside = sorted(bearers - set(SHIPPING))
    assert outside == ["YaraWipeAllDatasets"], (
        "lock-bearing automations outside SHIPPING changed: %s. This gate exists because "
        "SHIPPING does not cover every file that takes the lock — re-check that assumption."
        % outside)


@pytest.mark.parametrize("automation", _lock_bearing_automations())
def test_lock_matches_xdr_consolidate_in_every_automation_that_takes_it(automation):
    """THE LOCK GATE, one case per lock-bearing automation, SHIPPING or not.

    Compares only the lock surface, because an automation outside SHIPPING legitimately
    carries none of the rest of the consolidation core.
    """
    canonical = _logic_index(_XDR_CONSOLIDATE)
    mine = {k: v for k, v in canonical.items() if k in _LOCK_NAMES}
    missing = sorted(set(_LOCK_NAMES) - set(mine))
    assert not missing, "test is stale — not found in xdr_consolidate.py: %s" % missing

    path = os.path.join(_PACK_SCRIPTS, automation, "%s.py" % automation)
    pack = {k: v for k, v in _logic_index(path).items() if k in _LOCK_NAMES}
    for name in sorted(mine):
        assert name in pack, (
            "%s is missing from %s — that file takes the consolidation lock, so a lock fix "
            "landing only in xdr_consolidate.py does nothing there" % (name, automation))
        assert pack[name] == mine[name], (
            "%s has drifted between xdr_consolidate.py and %s.\n"
            "The lock is shared code in EVERY file that takes it — a copy that cannot "
            "express unreadable_is_held/on_takeover cannot protect an irreversible pass.\n"
            "--- xdr_consolidate\n%s\n--- %s\n%s"
            % (name, automation, mine[name], automation, pack[name]))


def _scanstat_src(path):
    with open(path) as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "_ScanStat"):
            return ast.unparse(node)
    return None


@pytest.mark.parametrize("automation", SHIPPING)
def test_pack_copy_uses_the_same_scan_stat_shape(automation):
    # _ScanStat's field ORDER is load-bearing in every copy (run_consolidation unpacks it by
    # attribute, _gate_scan's backstop reads ep_newest), and it is a call, not a def, so the
    # comparison above does not cover it.
    assert _scanstat_src(_XDR_CONSOLIDATE) is not None
    assert _scanstat_src(SHIPPING_PATHS[automation]) == _scanstat_src(_XDR_CONSOLIDATE), (
        "_ScanStat has drifted between xdr_consolidate.py and %s" % automation)


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
