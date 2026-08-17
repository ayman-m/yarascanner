"""Unit tests for xdr_data_management. No real tenant access - the two functions that take a
client (filter_recently_written, filter_unconsolidated) are driven by an in-memory fake."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xdr_data_management import months_between, parse_dataset_name  # noqa: E402


# ------------------------------------------------------------------- name parsing
def test_parse_full_rotated_name():
    d = parse_dataset_name("yara_scanner_matches_v2_winhost01_202607")
    assert d["kind"] == "matches"
    assert d["version"] == 2
    assert d["host"] == "winhost01"
    assert d["month"] == "202607"


def test_parse_scans_kind():
    assert parse_dataset_name("yara_scanner_scans_v2_h_202601")["kind"] == "scans"


def test_parse_unrotated_name_has_no_month():
    d = parse_dataset_name("yara_scanner_matches_v2_winhost01")
    assert d["month"] is None
    assert d["host"] == "winhost01"


def test_parse_bare_name_has_no_host_or_month():
    d = parse_dataset_name("yara_scanner_matches_v2")
    assert d["host"] is None and d["month"] is None


def test_parse_rejects_foreign_dataset():
    """Anything outside the contract must be untouchable - rail 3."""
    assert parse_dataset_name("some_other_dataset_v2_202607") is None
    assert parse_dataset_name("yara_scanner_something_v2") is None


def test_parse_rejects_empty_and_none():
    assert parse_dataset_name("") is None
    assert parse_dataset_name(None) is None


def test_six_digit_host_is_read_as_a_month():
    """Genuinely ambiguous in the naming contract: a host segment that is exactly six
    digits is indistinguishable from a rotation month. We resolve it AS a month, because
    the worst outcome of that reading is declining to delete something that looks recent -
    whereas reading it as a host could delete a whole host's history."""
    d = parse_dataset_name("yara_scanner_matches_v2_202601")
    assert d["month"] == "202601"
    assert d["host"] is None


def test_an_implausible_six_digit_group_is_a_host_not_a_month():
    """The ambiguity above only resolves towards "recent" for a PLAUSIBLE YYYYMM. "123456"
    read as a month is year 1234 - an age older than any retention window, so a bare \\d{6}
    would resolve the ambiguity towards DELETING, the exact opposite of the stated rule.
    Anything outside 20xx/01-12 is therefore part of the host name, which reads as unrotated
    and is never a candidate."""
    d = parse_dataset_name("yara_scanner_matches_v2_123456")
    assert d["month"] is None and d["host"] == "123456"
    d = parse_dataset_name("yara_scanner_matches_v2_h_202613")   # month 13
    assert d["month"] is None and d["host"] == "h_202613"


def test_a_timestamp_tail_does_not_crash_month_arithmetic():
    """A scan_id of the shape <host>_<YYYYMMDD>_<HHMMSS> ends in six digits that are not a
    month at all. Under a bare \\d{6} "143025" parsed as month 30 of year 1430 and raised
    ValueError out of months_between - aborting the mutating prune AND the read-only report,
    which is documented as safe to run from a poll loop."""
    d = parse_dataset_name("yara_scanner_matches_v2_scan_winserver01_20260812_143025")
    assert d["month"] is None
    assert months_between("202601", "202607") == 6      # still works for real months


def test_a_consolidated_per_scan_target_is_flagged_and_never_a_month():
    """xdr_consolidate's OUTPUT (…_v<N>_scan_<slug>) is not a rotation shard: no month by
    design, immutable, and once the sources were deleted it is a scan's only copy. A slug
    ending in month-shaped digits must not make it look like an ancient rotated dataset."""
    d = parse_dataset_name("yara_scanner_matches_v2_scan_winserver01_20260812_110501")
    assert d["scan_target"] is True
    assert d["month"] is None                            # NOT read as year 1105
    assert parse_dataset_name("yara_scanner_matches_v2_h_202601")["scan_target"] is False


def test_a_consolidated_target_is_never_a_rotation_candidate():
    name = "yara_scanner_matches_v2_scan_winserver01_20260812_110501"
    cands, skipped = select_rotated_for_deletion([name], older_than_months=6,
                                                 now_yyyymm="202607")
    assert cands == []
    assert any("per-scan consolidated target" in s for s in skipped)
    assert not any("CONFIG_LOOKUP_ROTATION" in s for s in skipped)


# --------------------------------------------------------------- month arithmetic
def test_months_between_same_month_is_zero():
    assert months_between("202607", "202607") == 0


def test_months_between_within_year():
    assert months_between("202601", "202607") == 6


def test_months_between_across_year_boundary():
    assert months_between("202511", "202602") == 3


def test_months_between_negative_when_future():
    assert months_between("202608", "202607") == -1


# ------------------------------------------------------- candidate selection + rails
from xdr_data_management import (  # noqa: E402
    select_legacy_for_deletion, select_rotated_for_deletion)


def test_selects_old_rotated_months():
    names = ["yara_scanner_matches_v2_h_202601", "yara_scanner_scans_v2_h_202601"]
    cands, _ = select_rotated_for_deletion(names, older_than_months=3, now_yyyymm="202607")
    assert sorted(cands) == sorted(names)


def test_never_deletes_the_current_month():
    """Rail 1. delete_dataset on a dataset a scan is WRITING to does not error the scan -
    it keeps POSTing rows to a name that no longer exists and gets HTTP 400 per batch.
    Silent, partial data loss across a fleet, found days later as a dashboard gap."""
    names = ["yara_scanner_matches_v2_h_202607"]
    cands, skipped = select_rotated_for_deletion(names, older_than_months=0,
                                                 now_yyyymm="202607")
    assert cands == []
    assert any("current month" in s for s in skipped)


def test_keeps_months_inside_the_window():
    names = ["yara_scanner_matches_v2_h_202605"]      # 2 months old
    cands, _ = select_rotated_for_deletion(names, older_than_months=6, now_yyyymm="202607")
    assert cands == []


def test_boundary_is_strictly_older_than():
    """Exactly N months old is KEPT; older than N is deleted."""
    at_boundary = ["yara_scanner_matches_v2_h_202601"]   # exactly 6 months
    beyond = ["yara_scanner_matches_v2_h_202512"]        # 7 months
    assert select_rotated_for_deletion(at_boundary, 6, "202607")[0] == []
    assert select_rotated_for_deletion(beyond, 6, "202607")[0] == beyond


def test_unrotated_datasets_are_never_candidates():
    """No month means rotation is off. Deleting such a dataset destroys ALL history for
    that host, not one month - same API call, categorically different blast radius."""
    names = ["yara_scanner_matches_v2_h"]
    cands, skipped = select_rotated_for_deletion(names, older_than_months=1,
                                                 now_yyyymm="202607")
    assert cands == []
    assert any("not rotated" in s for s in skipped)


def test_foreign_names_are_never_candidates():
    names = ["some_other_dataset_202601"]
    cands, _ = select_rotated_for_deletion(names, older_than_months=1, now_yyyymm="202607")
    assert cands == []


def test_future_month_is_never_deleted():
    """Clock skew on one endpoint must not make a dataset look ancient."""
    names = ["yara_scanner_matches_v2_h_202612"]
    cands, skipped = select_rotated_for_deletion(names, older_than_months=0,
                                                 now_yyyymm="202607")
    assert cands == []
    assert any("future" in s for s in skipped)


def test_legacy_selection_passes_rotated_legacy_names_through():
    names = ["yara_scanner_matches_v1_h_202601", "yara_scanner_scans_v1_h_202601"]
    cands, skipped = select_legacy_for_deletion(names, now_yyyymm="202607")
    assert sorted(cands) == sorted(names) and skipped == []


def test_legacy_selection_handles_empty():
    assert select_legacy_for_deletion([]) == ([], [])
    assert select_legacy_for_deletion(None) == ([], [])


def test_legacy_selection_refuses_everything_while_a_newer_schema_exists():
    """A newer-schema dataset existing at all proves the assumed current version is stale -
    which means the 'legacy' bucket may be full of live data. xdr_action_center.py's
    prune-datasets already refused on exactly this signal; this brings the two into line."""
    cands, skipped = select_legacy_for_deletion(["yara_scanner_matches_v1_h_202601"],
                                                newer_names=["yara_scanner_matches_v9_h"],
                                                now_yyyymm="202607")
    assert cands == []
    assert any("NEWER schema" in s and "cannot be trusted" in s for s in skipped)


def test_legacy_selection_never_takes_an_unsuffixed_dataset():
    """Same rail as the rotated path, same reason: an unsuffixed dataset holds ALL
    pre-rotation history for that host, whatever schema it is on."""
    cands, skipped = select_legacy_for_deletion(["yara_scanner_matches_v1_h"],
                                                now_yyyymm="202607")
    assert cands == []
    assert any("ALL pre-rotation history" in s for s in skipped)


def test_legacy_selection_never_takes_the_current_or_a_future_month():
    """Mid-rollout, endpoints still on the old scanner are WRITING to legacy-schema shards."""
    cands, skipped = select_legacy_for_deletion(
        ["yara_scanner_matches_v1_h_202607", "yara_scanner_matches_v1_h_202612"],
        now_yyyymm="202607")
    assert cands == []
    assert any("current month" in s for s in skipped)
    assert any("future" in s for s in skipped)


def test_legacy_selection_never_takes_a_consolidated_target():
    cands, skipped = select_legacy_for_deletion(["yara_scanner_matches_v1_scan_abc_123456"],
                                                now_yyyymm="202607")
    assert cands == []
    assert any("consolidated target" in s for s in skipped)


def test_legacy_selection_protects_an_unversioned_unsuffixed_shard():
    """The rails were gated on `parse_dataset_name(...) is not None`, and that parse REQUIRES
    the _vN segment — so the oldest names inside the yara_scanner_ contract
    ("yara_scanner_scans_hostA") skipped every rail and went straight onto the delete list,
    while their versioned sibling ("..._v1_hostA") was correctly protected. That exempted
    exactly the least replaceable data: an unsuffixed dataset holds ALL of a host's
    pre-rotation history."""
    cands, skipped = select_legacy_for_deletion(["yara_scanner_scans_hostA"],
                                                now_yyyymm="202608")
    assert cands == []
    assert any("ALL pre-rotation history" in s for s in skipped)


def test_legacy_selection_applies_month_rails_to_unversioned_shards_too():
    """Same gap, the month half: an unversioned shard dated in the current month is being
    written to right now, and must not be deletable just because it has no _vN."""
    cands, skipped = select_legacy_for_deletion(
        ["yara_scanner_scans_hostA_202608", "yara_scanner_scans_hostA_202601"],
        now_yyyymm="202608")
    assert cands == ["yara_scanner_scans_hostA_202601"]   # ancient rotated month still goes
    assert any("current month" in s for s in skipped)


def test_legacy_selection_still_allows_genuinely_ancient_unversioned_names():
    """The rails must not make --delete-legacy vacuous: a pre-versioning name that predates
    the whole naming contract has no month to check and is still a candidate (the live
    recency/consolidation rails run after this and remain its last line of defence)."""
    cands, skipped = select_legacy_for_deletion(["yara_matches_old"], now_yyyymm="202607")
    assert cands == ["yara_matches_old"] and skipped == []


# ------------------------------------------- abandoned vs genuinely-unrotated datasets
from xdr_data_management import has_rotated_sibling  # noqa: E402


def test_unsuffixed_with_rotated_siblings_is_abandoned():
    """Found live: unsuffixed datasets sitting beside _YYYYMM ones are pre-rotation
    leftovers, NOT a rotation=none deployment. Telling the operator to enable a setting
    that is already enabled sends them looking in the wrong place."""
    names = ["yara_scanner_matches_v2_h", "yara_scanner_matches_v2_h_202607"]
    assert has_rotated_sibling("yara_scanner_matches_v2_h", names) is True
    _, skipped = select_rotated_for_deletion(names, older_than_months=99,
                                             now_yyyymm="202608")
    assert any("abandoned pre-rotation" in s for s in skipped)
    assert not any("set CONFIG_LOOKUP_ROTATION" in s for s in skipped)


def test_unsuffixed_alone_is_genuinely_unrotated():
    names = ["yara_scanner_matches_v2_h"]
    assert has_rotated_sibling("yara_scanner_matches_v2_h", names) is False
    _, skipped = select_rotated_for_deletion(names, older_than_months=99,
                                             now_yyyymm="202608")
    assert any("set CONFIG_LOOKUP_ROTATION" in s for s in skipped)


def test_sibling_check_ignores_different_host():
    names = ["yara_scanner_matches_v2_hostA", "yara_scanner_matches_v2_hostB_202607"]
    assert has_rotated_sibling("yara_scanner_matches_v2_hostA", names) is False


def test_sibling_check_requires_exactly_six_digits():
    names = ["yara_scanner_matches_v2_h", "yara_scanner_matches_v2_h_20260"]
    assert has_rotated_sibling("yara_scanner_matches_v2_h", names) is False


# --------------------------------------------------------- recency + consolidation-state gates
from xdr_data_management import filter_recently_written, filter_unconsolidated  # noqa: E402

NOW = 10_000_000_000  # arbitrary fixed "now", in ms


class FakeXqlClient:
    """Responds to an XQL query by matching a configured substring - just enough to drive
    filter_recently_written/filter_unconsolidated without a real tenant."""
    def __init__(self, responses):
        self.responses = responses  # {substring: canned_result_list}
        self.calls = []

    def xql(self, query, limit=1000):
        self.calls.append(query)
        for key, result in self.responses.items():
            if key in query:
                return result
        return []


def test_filter_recently_written_drops_a_shard_still_being_written_to():
    c = FakeXqlClient({
        "dataset = ds_recent | comp max": [{"newest": NOW - 1000}],       # 1s ago
    })
    survivors, skipped = filter_recently_written(c, ["ds_recent"], min_quiet_secs=3600, now_ms=NOW)
    assert survivors == []
    assert any("ds_recent" in s and "may still be writing" in s for s in skipped)


def test_filter_recently_written_keeps_a_genuinely_quiet_shard():
    c = FakeXqlClient({
        "dataset = ds_old | comp max": [{"newest": NOW - 7200 * 1000}],   # 2h ago
    })
    survivors, skipped = filter_recently_written(c, ["ds_old"], min_quiet_secs=3600, now_ms=NOW)
    assert survivors == ["ds_old"]
    assert skipped == []


def test_filter_recently_written_keeps_a_shard_with_no_rows_at_all():
    # No rows -> nothing to protect against, matches newest_row_age_ok's own semantics
    # elsewhere in this project.
    c = FakeXqlClient({"dataset = ds_empty | comp max": []})
    survivors, skipped = filter_recently_written(c, ["ds_empty"], min_quiet_secs=3600, now_ms=NOW)
    assert survivors == ["ds_empty"]


def test_filter_recently_written_skips_to_be_safe_on_query_error():
    class ErrorClient:
        def xql(self, query, limit=1000):
            raise RuntimeError("tenant hiccup")
    survivors, skipped = filter_recently_written(ErrorClient(), ["ds_x"], min_quiet_secs=3600, now_ms=NOW)
    assert survivors == []
    assert any("could not check recency" in s for s in skipped)


def test_filter_unconsolidated_drops_a_shard_with_a_never_verified_scan():
    shard = "yara_scanner_matches_v2_hostx_ab1234_202607"
    c = FakeXqlClient({
        "dataset = %s | comp count() as n by scan_id" % shard: [{"scan_id": "S1", "n": 463}],
        # target exists but only 0 rows landed - never actually verified/consolidated
        "dataset = yara_scanner_matches_v2_scan_s1 | comp count": [{"n": 0}],
    })
    survivors, skipped = filter_unconsolidated(c, [shard])
    assert survivors == []
    assert any("S1" in s and "would lose data" in s for s in skipped)


def test_filter_unconsolidated_keeps_a_fully_verified_shard():
    shard = "yara_scanner_matches_v2_hostx_ab1234_202607"
    c = FakeXqlClient({
        "dataset = %s | comp count() as n by scan_id" % shard: [{"scan_id": "S1", "n": 463}],
        "dataset = yara_scanner_matches_v2_scan_s1 | comp count": [{"n": 463}],  # matches exactly
    })
    survivors, skipped = filter_unconsolidated(c, [shard])
    assert survivors == [shard]
    assert skipped == []


def test_filter_unconsolidated_keeps_an_already_empty_shard():
    shard = "yara_scanner_matches_v2_hostx_ab1234_202607"
    c = FakeXqlClient({"dataset = %s | comp count() as n by scan_id" % shard: []})
    survivors, skipped = filter_unconsolidated(c, [shard])
    assert survivors == [shard]


def test_filter_unconsolidated_passes_through_names_outside_the_naming_contract():
    # Not this function's job to gate foreign names - select_rotated_for_deletion already
    # excludes them before this ever runs, but stay safe if called with one anyway.
    survivors, skipped = filter_unconsolidated(FakeXqlClient({}), ["not_a_yara_dataset"])
    assert survivors == ["not_a_yara_dataset"]
