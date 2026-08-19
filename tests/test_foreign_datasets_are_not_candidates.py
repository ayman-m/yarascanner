#!/usr/bin/env python3
"""Only datasets this tool owns may be read, merged or deleted. Criterion D1.5.

Found by mutation audit. Dropping the `^` anchor from `_SHARD_RE` in both copies left the
entire suite green -- and an unanchored pattern makes any dataset whose name merely
CONTAINS the scanner prefix a candidate:

    customer_yara_scanner_matches_v3_host_abc123   would parse, and be eligible for DELETION

The anchor was already correct; nothing verified it. This is the asymmetric one in Round 4.
Failing to select one of our own datasets leaves a shard behind, which the next pass picks
up. Selecting someone else's deletes a customer's data, and consolidation deletes sources
after merging them.

`parse_shard` is the only thing standing between a tenant-wide dataset listing and the
delete path, so its rejections matter more than its acceptances -- which is why most of
this file is negative cases.
"""
import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management  # noqa: F401

import YaraConsolidateCommon as pack_common
import xdr_consolidate as xc

IMPLS = [
    pytest.param(xc, id="xdr_consolidate"),
    pytest.param(pack_common, id="pack"),
]

OURS = [
    ("yara_scanner_matches_v3_host_abc123", "matches", "host_abc123", None),
    ("yara_scanner_scans_v3_host_abc123", "scans", "host_abc123", None),
    ("yara_scanner_matches_v3_host_abc123_202608", "matches", "host_abc123", "202608"),
    ("yara_scanner_scans_v2_win-box-01_0f9e8d", "scans", "win-box-01_0f9e8d", None),
]

FOREIGN = [
    # The mutation this file exists for: prefix embedded, not leading.
    ("customer_yara_scanner_matches_v3_host_abc123", "prefix embedded mid-name"),
    ("backup_of_yara_scanner_scans_v3_host_abc123", "someone's backup of our dataset"),
    ("x_yara_scanner_matches_v3_h_abc123", "single-character prefix"),
    # Trailing junk: the `$` anchor is the other half of the same protection.
    ("yara_scanner_matches_v3_host_abc123_backup", "our name with a suffix appended"),
    ("yara_scanner_matches_v3_host_abc123_202608_old", "rotated name with junk appended"),
    # Shape violations.
    ("yara_scanner_findings_v3_host_abc123", "a kind we do not own"),
    ("yara_scanner_matches_host_abc123", "no version segment"),
    ("yara_scanner_matches_vX_host_abc123", "non-numeric version"),
    ("yara_scanner_matches_v3_host_abc12", "5-char shard suffix, not 6"),
    ("yara_scanner_matches_v3_host_ABC123", "uppercase hex in the shard suffix"),
    ("yara_scanner_matches_v3_host_ghijkl", "non-hex shard suffix"),
    ("YARA_SCANNER_MATCHES_V3_HOST_ABC123", "uppercased whole name"),
    ("yara_scanner_matches_v3_host_abc123_20260", "5-digit month"),
    ("yara_scanner_matches_v3_host_abc123_2026081", "7-digit month"),
]


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("name,kind,host,month", OURS)
def test_our_own_shards_are_recognised(impl, name, kind, host, month):
    """The positive control. Without it, a pattern matching NOTHING passes every negative
    case below and the tool silently stops consolidating anything."""
    p = impl.parse_shard(name)
    assert p is not None, f"{name} is one of ours and was not recognised"
    assert p["kind"] == kind
    assert p["host"] == host
    assert p["month"] == month


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("name,why", FOREIGN)
def test_foreign_datasets_are_rejected(impl, name, why):
    assert impl.parse_shard(name) is None, (
        f"{name} was accepted as one of ours ({why}) -- it becomes a candidate for reading "
        f"and DELETION, and consolidation deletes sources after merging them")


@pytest.mark.parametrize("impl", IMPLS)
def test_the_tools_own_lock_dataset_is_not_a_shard(impl):
    """Self-protection. The lock lives under the same `yara_scanner_` prefix, so a loosened
    pattern would let a pass consolidate and delete the very marker guarding it against a
    concurrent pass."""
    assert impl.parse_shard(impl._LOCK_DATASET) is None, (
        f"the consolidation lock dataset ({impl._LOCK_DATASET}) parses as a per-host shard")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_per_scan_target_is_not_itself_a_shard(impl):
    """Consolidation's OUTPUT must not be mistaken for its INPUT on the next pass, or a
    second run would treat the merged target as a source and fold it into itself."""
    target = impl.target_name("matches", "3", "deadbeefcafe")
    assert impl.parse_shard(target) is None, (
        f"the per-scan target {target} parses as a per-host shard, so a later pass would "
        f"treat consolidated output as an unconsolidated source")


@pytest.mark.parametrize("impl", IMPLS)
def test_rejection_is_by_pattern_not_by_luck(impl):
    """Guards the specific mutation: an unanchored pattern still rejects most junk, so a
    thin negative set can pass while the anchor is gone. This asserts the anchor itself by
    taking a name that DOES parse and proving a prefix breaks it."""
    good = "yara_scanner_matches_v3_host_abc123"
    assert impl.parse_shard(good) is not None
    assert impl.parse_shard("z" + good) is None, "leading text did not break the match"
    assert impl.parse_shard(good + "z") is None, "trailing text did not break the match"
