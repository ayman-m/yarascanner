#!/usr/bin/env python3
"""A second, independent guard: the live v4 overwrite dataset must never be touched by the
deletion/cleanup pass, even if it somehow reaches that pass through a channel other than the
shard-enumeration filter this repo relies on today.

Context: on 2026-08-21, two live overwrite datasets (yara_scanner_matches_v4_xdr_agent_cd7e9b,
yara_scanner_matches_v4_xdragent2_2fd370) were deleted during a live consolidation pass. The
deployed parse_shard correctly excludes their names — confirmed by fetching the exact deployed
source — and a faithful local reproduction (multi-version, with and without a "prior
contamination" scenario matching the tenant's real shard layout) could not reproduce the loss:
the enumeration-time exclusion held in every scenario tried.

The leading theory is residual state from an EARLIER pass that ran before parse_shard carried
the v4 exclusion at all: one target dataset was found to already hold exactly the row count a
pre-fix run would have written (1097 rows, matching source data recorded earlier in the same
session), which independently explains the one count_mismatch failure observed today as safe,
expected behavior when resuming after a partial prior run. That does not fully close the
timeline for the two deletions, and this repo has exactly ONE place standing between "this
dataset's name entered a scan's shard list somehow" and "delete_dataset() runs on it" —
parse_shard, called once, at enumeration. A single point of protection for an irreversible
action is a real gap regardless of what actually happened.

This file adds and proves a SECOND, independent check, directly at the point of the
destructive calls, that does not trust `shards`/`shard_scans` membership to have been built
correctly. It must hold even when a caller hands it membership state where the live dataset's
name is ALREADY present — the exact shape a stale-enumeration bug would produce.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_consolidate as C  # noqa: E402
from test_consolidation import FakeClient, _seed, _m, NOW  # noqa: E402

LIVE = "yara_scanner_matches_v4_xdr_agent_cd7e9b"
DATED = "yara_scanner_matches_v4_xdr_agent_cd7e9b_202608"
SCAN = "xdr-agent_20260821_091609_176687_yara_00d70ca8dd0e"


def test_is_live_overwrite_dataset_recognises_the_pattern():
    assert C._is_live_overwrite_dataset("yara_scanner_matches_v4_xdr_agent_cd7e9b") is True
    assert C._is_live_overwrite_dataset("yara_scanner_matches_v4_xdr_agent_cd7e9b_202608") is False
    assert C._is_live_overwrite_dataset("yara_scanner_scans_v4_xdr_agent_cd7e9b") is False
    assert C._is_live_overwrite_dataset("yara_scanner_matches_v2_xdr_agent_cd7e9b") is False
    assert C._is_live_overwrite_dataset("yara_scanner_matches_v4_scan_s1") is False


def test_cleanup_never_strips_rows_from_the_live_dataset_even_if_told_to():
    """Simulates the exact shape a stale-enumeration bug would produce: the live dataset's
    name handed in as a legitimate SOURCE for a verified scan. The row-level cleanup step
    must refuse it regardless of what its caller believed."""
    fc = FakeClient()
    _seed(fc, LIVE, _m(SCAN, "xdr-agent", 5))
    C._cleanup_verified_scan_rows(fc, [LIVE, DATED], SCAN, log=lambda *a: None)
    assert len(fc.ds[LIVE]) == 5, "the live dataset's rows were stripped despite the guard"


def test_the_delete_pass_never_deletes_the_live_dataset_even_if_told_to():
    """Same shape, at the OTHER destructive call site: shard_scans built (by a hypothetical
    caller bug) as if the live dataset were a fully-verified, deletable shard."""
    fc = FakeClient()
    _seed(fc, LIVE, _m(SCAN, "xdr-agent", 5))
    to_delete = [LIVE]           # what a stale-enumeration bug would hand to the delete pass
    C._delete_many(fc, to_delete, log=lambda *a: None)
    assert LIVE in fc.ds, "the live overwrite dataset was deleted"
    assert len(fc.ds[LIVE]) == 5


def test_a_genuinely_deletable_shard_is_unaffected():
    """The new guard must not become a second place that quietly breaks ordinary deletion."""
    fc = FakeClient()
    _seed(fc, DATED, _m(SCAN, "xdr-agent", 3))
    C._delete_many(fc, [DATED], log=lambda *a: None)
    assert DATED not in fc.ds


def test_end_to_end_the_live_dataset_survives_even_with_corrupted_shard_scans(monkeypatch):
    """Forces the exact failure shape at the highest level: patches parse_shard to (wrongly)
    include the live dataset as an ordinary shard, as a stand-in for whatever enumeration bug
    might exist, and proves the dataset still survives a real consolidate_all() call because
    the second guard catches what the first one, in this simulation, does not."""
    fc = FakeClient()
    _seed(fc, LIVE, _m(SCAN, "xdr-agent", 5))
    _seed(fc, "yara_scanner_scans_v4_xdr_agent_cd7e9b_202608",
         [{"scan_id": SCAN, "hostname": "xdr-agent", "status": "completed",
           "event_timestamp_ms": 1000}])

    real_parse_shard = C.parse_shard

    def leaky_parse_shard(name):
        if name == LIVE:
            return {"kind": "matches", "ver": "4", "host": "xdr_agent_cd7e9b", "month": None}
        return real_parse_shard(name)

    monkeypatch.setattr(C, "parse_shard", leaky_parse_shard)
    C.consolidate_all(fc, kinds=("matches",), vers=("4",), dry_run=False, quiet_secs=1,
                      now_ms=NOW, log=lambda *a: None)
    assert LIVE in fc.ds, "the live dataset was destroyed even with the enumeration guard bypassed"
    assert len(fc.ds[LIVE]) == 5
