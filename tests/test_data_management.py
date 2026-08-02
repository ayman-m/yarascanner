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
