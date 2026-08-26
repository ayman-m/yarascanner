#!/usr/bin/env python3
"""YaraConsolidateSummary must read the v4+ live overwrite dataset, not just dated leftovers.

Confirmed live on emea (2026-08-21): a dry run against real tenant data produced

    written: 0 | skipped: 0 | ... XQL calls: 1 (+1 dataset listing)

one query total, meaning zero matches shards were even selected to query. main() built
match_ds from parse_shard's list alone. parse_shard deliberately returns None for an
unsuffixed v4 matches dataset - correct for Apply/Fast, where that exclusion is what stops
the permanent per-host dataset from being merged into a per-scan target and deleted - but
Summary reuses the SAME exclusion despite never deleting anything. Since matches stopped
rotating at v4, a current-scanner host's findings live ONLY in that one dataset, so Summary
was structurally unable to produce a row for any host running the current scanner.

_matches_shard_for_read is the fix: parse_shard's answer where it says yes, plus the live
overwrite pattern it deliberately excludes, for this READ-ONLY path only. Apply/Fast/Status/
Report/Cleanup are untouched - this function exists only in YaraConsolidateSummary.py, not
in the drift-gated shared core (confirmed: summarise_shard/match_ds appear in no other
shipping file and not in xdr_consolidate.py).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateSummary as S, FakeTenant, _run_automation, NOW_YYYYMM,
)

LIVE = "yara_scanner_matches_v4_xdr_agent_cd7e9b"
DATED = "yara_scanner_matches_v4_xdr_agent_cd7e9b_202608"
TARGET = "yara_scanner_matches_v4_scan_s1"
SCANS = "yara_scanner_scans_v4_xdr_agent_cd7e9b_202608"


# ------------------------------------------------------------- _matches_shard_for_read

def test_the_live_overwrite_dataset_is_a_valid_v4_read_source():
    p = S._matches_shard_for_read(LIVE, "4")
    assert p is not None and p["kind"] == "matches" and p["host"] == "xdr_agent_cd7e9b"
    assert p["month"] is None


def test_wrong_version_is_still_excluded():
    """The read-only widening must not become "any matches dataset, any version"."""
    assert S._matches_shard_for_read(LIVE, "2") is None
    assert S._matches_shard_for_read(LIVE, "3") is None


def test_a_dated_v4_matches_dataset_is_still_included():
    """parse_shard already accepts this one; the widened function must not change that."""
    p = S._matches_shard_for_read(DATED, "4")
    assert p is not None and p["month"] == "202608"


def test_an_older_schema_unsuffixed_dataset_is_still_included():
    """On v2/v3 matches really did rotate, so parse_shard already accepts an unsuffixed name
    there without needing the live-overwrite fallback at all."""
    assert S._matches_shard_for_read("yara_scanner_matches_v2_hosta_aa0001", "2") is not None


def test_a_per_scan_target_is_never_a_read_source():
    """The one thing that must stay excluded no matter what: re-consuming consolidation's
    own output as if it were a fresh source."""
    assert S._matches_shard_for_read(TARGET, "4") is None


def test_a_scans_kind_dataset_is_never_returned_as_matches():
    assert S._matches_shard_for_read(SCANS, "4") is None


# ------------------------------------------------------------- summarise_shard's guard

def test_summarise_shard_accepts_the_live_dataset_instead_of_raising():
    calls = {"n": 0}

    class _Client:
        def xql(self, query, limit=None):
            calls["n"] += 1
            return []

    S.summarise_shard(_Client(), LIVE, "4", qcount=[0], log=lambda *a: None)
    assert calls["n"] == 1, "summarise_shard raised instead of querying the live dataset"


# ------------------------------------------------------------- end-to-end selection

def test_main_selects_the_live_dataset_for_summarisation(monkeypatch):
    """The regression this file exists to catch: reproduces the live symptom (zero shards
    selected) and proves it's fixed, without needing to fake the JSON-array-expand XQL
    summary query itself - that's summarise_shard's own concern, isolated here by recording
    which dataset names main() hands it."""
    seen = []
    real = S.summarise_shard

    def spy(client, dataset, ver, qcount, log, findings=None):
        seen.append(dataset)
        return [], "primary"

    monkeypatch.setattr(S, "summarise_shard", spy)
    t = FakeTenant(names=[LIVE, SCANS])
    _run_automation(S, {"schema_version": "4", "execute": "false"}, t)
    assert LIVE in seen, "the live overwrite dataset was never handed to summarise_shard"


# ---------------------------------------------------------------- grouping by ruleset
# Round: testing showed the script named "consolidate" produced one summary dataset per
# HOST - the same count it started with. scan_id is "{hostname}_{run_id}_yara_{hash}", so
# keying a target on it can only ever be per-host. The ruleset hash is the shared component.

H1 = "yara_scanner_matches_v4_hosta_aa0001"
H2 = "yara_scanner_matches_v4_hostb_bb0002"
S1 = "hosta_20260825_100000_000001_yara_deadbeef1234"
S2 = "hostb_20260825_100002_000002_yara_deadbeef1234"   # SAME ruleset hash
TGT = "yara_scanner_summary_v4_rules_deadbeef1234"


def test_the_ruleset_hash_is_extracted_from_a_scan_id():
    assert S.rule_hash_of(S1) == "deadbeef1234"
    assert S.rule_hash_of(S2) == S.rule_hash_of(S1), "both hosts must land in one group"
    assert S.rule_hash_of("no-hash-here") is None
    assert S.rule_hash_of(None) is None


def test_the_target_is_named_per_ruleset_not_per_scan():
    t = S.summary_target_for_rules("4", "deadbeef1234")
    assert t == TGT
    assert "_scan_" not in t, "a per-scan name is a per-host name - that was the bug"


def test_two_hosts_on_one_ruleset_write_to_a_single_dataset():
    """The whole point: N hosts -> 1 dataset, not N."""
    t = FakeTenant(names=[H1, H2])
    t.rows = {}
    created = []
    real_create = t.create_lookup_dataset

    def spy(name, schema):
        if name.startswith("yara_scanner_summary_"):
            created.append(name)
        return real_create(name, schema)
    t.create_lookup_dataset = spy
    assert S.summary_target_for_rules("4", S.rule_hash_of(S1)) == \
           S.summary_target_for_rules("4", S.rule_hash_of(S2)), \
        "two hosts scanned with one ruleset must resolve to ONE target name"


# ------------------------------------------------- summary datasets must be visible + safe
# Testing found the pack's OWN summary output invisible to YaraReport and described by
# YaraCleanup as "not a YARA dataset name". YARA_OWNED_RE only listed matches|scans, so a
# dataset the pack creates was neither reported nor managed - unbounded growth nobody could
# see. Visibility must NOT come at the cost of deletion candidacy.

SUMMARY_DS = "yara_scanner_summary_v4_rules_90149530ddc2"


def test_a_summary_dataset_is_recognised_as_pack_owned():
    from test_pack_data_management import YaraReport as R
    assert R.YARA_OWNED_RE.match(SUMMARY_DS), "invisible to the inventory"


def test_a_current_version_summary_is_not_classified_as_legacy():
    """Without this, delete_legacy=true points at the pack's own consolidated output."""
    from test_pack_data_management import YaraCleanup as K
    K.set_schema_version("4")          # main() always calls this - it REASSIGNS CURRENT_RE
    assert K.CURRENT_RE.match(SUMMARY_DS), "would land in the legacy bucket"
    assert not K.CURRENT_RE.match("yara_scanner_summary_v3_rules_abc123"), \
        "an older-schema summary should still read as legacy"


def test_a_summary_dataset_is_never_a_deletion_candidate():
    """Safety rail 5: NAME_RE must keep refusing to parse it, so no retention rule can
    select it. Labelling recognises it; the selector still cannot touch it."""
    from test_pack_data_management import YaraCleanup as K
    assert K.parse_dataset_name(SUMMARY_DS) is None
    assert K.is_pack_output_dataset(SUMMARY_DS)
    assert not K.is_pack_output_dataset("yara_scanner_matches_v4_hosta_aa0001")


# ------------------------------------------------- the FULL consolidated output, same rules
# Adding a new dataset kind reintroduced the exact gap that had just been closed for
# `summary`: yara_scanner_full_v4_rules_<hash> was invisible to YaraReport and unmanaged by
# YaraCleanup, because YARA_OWNED_RE listed matches|scans|summary and nothing added `full`.
# Any future kind must be added in all four places or it repeats.

FULL_DS = "yara_scanner_full_v4_rules_90149530ddc2"


def test_a_full_dataset_is_recognised_as_pack_owned():
    from test_pack_data_management import YaraReport as R
    assert R.YARA_OWNED_RE.match(FULL_DS), "invisible to the inventory"


def test_a_current_version_full_dataset_is_not_classified_as_legacy():
    from test_pack_data_management import YaraCleanup as K
    K.set_schema_version("4")          # main() always calls this - it REASSIGNS CURRENT_RE
    assert K.CURRENT_RE.match(FULL_DS), "would land in the legacy bucket, which delete_legacy targets"
    assert not K.CURRENT_RE.match("yara_scanner_full_v3_rules_abc123"), \
        "an older-schema full dataset should still read as legacy"


def test_a_full_dataset_is_never_a_deletion_candidate():
    from test_pack_data_management import YaraCleanup as K
    assert K.parse_dataset_name(FULL_DS) is None, "safety rail 5 must still refuse to parse it"
    assert K.is_pack_output_dataset(FULL_DS)


def test_both_consolidated_kinds_are_covered_by_one_helper():
    """summary and full are the same class of thing - this pack's own output - and must not
    drift apart into two half-maintained special cases."""
    from test_pack_data_management import YaraCleanup as K
    assert K.is_pack_output_dataset("yara_scanner_summary_v4_rules_deadbeef")
    assert K.is_pack_output_dataset("yara_scanner_full_v4_rules_deadbeef")
    assert not K.is_pack_output_dataset("yara_scanner_matches_v4_hosta_aa0001")
    assert not K.is_pack_output_dataset("yara_scanner_scans_v4_hosta_aa0001_202608")
