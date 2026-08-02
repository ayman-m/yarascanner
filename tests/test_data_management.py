"""Unit tests for xdr_data_management. Pure functions only - no tenant access."""
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
    d = parse_dataset_name("yara_scanner_matches_v2_123456")
    assert d["month"] == "123456"
    assert d["host"] is None


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


def test_legacy_selection_passes_names_through():
    names = ["yara_scanner_matches_v1_h", "yara_scanner_scans_h"]
    assert sorted(select_legacy_for_deletion(names)) == sorted(names)


def test_legacy_selection_handles_empty():
    assert select_legacy_for_deletion([]) == []
    assert select_legacy_for_deletion(None) == []


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
