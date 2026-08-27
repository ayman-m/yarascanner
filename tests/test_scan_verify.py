#!/usr/bin/env python3
"""YaraScanVerify: did the wave we just dispatched actually start?

Measured on the tenant (launch 10:36:44 UTC, three hosts):
    initiated row      +17s / +19s / +20s     <- the signal
    match rows landing ~+136s                 <- soft evidence only
    first running row  +619s / +620s          <- 10.3 min, OUTSIDE any short window

So `initiated` is what a five-minute gate can rely on. The heartbeat cannot be it: at
SCANS_HEARTBEAT_SECS = 600 the first one lands at roughly double the budget, and a gate that
waits for it either false-alarms every wave or stops being short.

Match rows are positive evidence only. Presence proves the whole path works; absence proves
nothing, because a clean host legitimately has none. Failing a host for that would alarm on
exactly the hosts that are fine.
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import _install_xsoar_stubs  # noqa: E402

_install_xsoar_stubs()

_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                   "YaraScanVerify", "YaraScanVerify.py")
spec = importlib.util.spec_from_file_location("YaraScanVerify", _PY)
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

DISPATCH = 1_000_000_000_000


class FakeClient:
    """Answers the two comp queries the verifier makes."""

    def __init__(self, scans=(), matches=()):
        self.scans = list(scans)      # (hostname, status, ts)
        self.matches = list(matches)  # (hostname, n)
        self.queries = []

    def xql(self, query, limit=1000):
        self.queries.append(query)
        if "yara_scanner_scans" in query:
            return [{"hostname": h, "status": s, "ts": t} for h, s, t in self.scans]
        return [{"hostname": h, "n": n} for h, n in self.matches]


def test_every_host_started_is_ok():
    c = FakeClient(scans=[("a", "initiated", DISPATCH + 17000),
                          ("b", "initiated", DISPATCH + 19000)])
    r = V.verify_wave(c, ["a", "b"], DISPATCH)
    assert r["verdict"] == "ok"
    assert r["started"] == ["a", "b"] and r["not_started"] == []


def test_a_host_with_no_row_is_reported_not_started():
    c = FakeClient(scans=[("a", "initiated", DISPATCH + 17000)])
    r = V.verify_wave(c, ["a", "b"], DISPATCH)
    assert r["verdict"] == "partial"
    assert r["not_started"] == ["b"]


def test_no_host_starting_is_wave_dead_not_merely_partial():
    """The case the gate exists for: a bad rule pack or a bad script_uid kills the whole wave,
    and the operator should learn in minutes rather than never."""
    c = FakeClient(scans=[])
    r = V.verify_wave(c, ["a", "b", "c"], DISPATCH)
    assert r["verdict"] == "wave_dead"
    assert r["not_started"] == ["a", "b", "c"]


def test_a_row_from_BEFORE_dispatch_does_not_count_as_started():
    """Without the dispatch bound, a host scanned yesterday looks healthy today - the wave
    would report ok having actually started nothing."""
    c = FakeClient(scans=[("a", "completed", DISPATCH - 86_400_000)])
    r = V.verify_wave(c, ["a"], DISPATCH)
    assert r["verdict"] == "wave_dead"
    assert r["not_started"] == ["a"]
    assert any(str(DISPATCH) in q for q in c.queries), "the query must bound on dispatch time"


def test_a_terminal_row_also_counts_as_started():
    """A short scan can finish inside the window - measured, a Linux host completed at +253s.
    Treating only `initiated` as proof would call that host not-started."""
    c = FakeClient(scans=[("a", "completed", DISPATCH + 253000)])
    r = V.verify_wave(c, ["a"], DISPATCH)
    assert r["verdict"] == "ok" and r["started"] == ["a"]


def test_match_rows_are_evidence_but_never_the_verdict():
    """Absence of matches must not fail a host: a clean host legitimately has none."""
    c = FakeClient(scans=[("a", "initiated", DISPATCH + 17000)], matches=[])
    r = V.verify_wave(c, ["a"], DISPATCH)
    assert r["verdict"] == "ok", "no matches must not fail a started host"
    assert r["match_rows"] == {}
    c2 = FakeClient(scans=[("a", "initiated", DISPATCH + 17000)], matches=[("a", 122)])
    r2 = V.verify_wave(c2, ["a"], DISPATCH)
    assert r2["match_rows"] == {"a": 122}
    assert r2["verdict"] == "ok"


def test_hostnames_are_matched_case_insensitively():
    """core-get-endpoints and the scanner disagree on case often enough that an exact match
    would report a started host as missing."""
    c = FakeClient(scans=[("XDR-Agent", "initiated", DISPATCH + 17000)])
    r = V.verify_wave(c, ["xdr-agent"], DISPATCH)
    assert r["verdict"] == "ok", r


def test_an_unreadable_dataset_is_unknown_not_a_failed_wave():
    """A query failing is not evidence the scan failed. Calling it wave_dead would page an
    analyst about a healthy wave whenever XQL hiccups."""
    class Boom(FakeClient):
        def xql(self, query, limit=1000):
            raise RuntimeError("tenant hiccup")
    r = V.verify_wave(Boom(), ["a"], DISPATCH)
    assert r["verdict"] == "unknown"
    assert r["error"]
