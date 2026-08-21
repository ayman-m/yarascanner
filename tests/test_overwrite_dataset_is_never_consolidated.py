#!/usr/bin/env python3
"""The v4 per-host matches dataset is not a consolidation source.

Since b7eb105 the scanner writes matches to a PERMANENT per-host dataset with no month and
replaces it wholesale at the start of every scan:

    self.matches_dataset = f"{PREFIX}_matches{_ver}{_suffix}"        # no rotation, ever
    self.scans_dataset   = f"{PREFIX}_scans{_ver}{_suffix}{_rot}"    # still monthly

parse_shard only ever excluded per-scan TARGETS (`…_scan_<id>`), so it accepted
`yara_scanner_matches_v4_<host>_<hash>` as an ordinary rotation shard. Consolidation would
therefore merge each live per-host dataset into `yara_scanner_matches_v4_scan_<scan_id>` and
delete the host dataset — turning one bounded dataset per host into one dataset per scan,
forever. That is exactly the unbounded growth the overwrite model was introduced to remove,
and the scanner would simply recreate the host dataset for consolidation to eat again.

Caught before it ran: on the emea tenant v2 had 83 per-scan targets and v3 had 17, but v4
had 0 — the backlog pass died before it reached v4.

Two boundaries matter and are asserted below:
  * a DATED v4 matches dataset (…_202608) predates the overwrite model and is ordinary
    consolidatable debris — excluding it would strand those leftovers permanently;
  * SCANS still rotates monthly at v4, so it is unaffected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_consolidate as C  # noqa: E402
from test_consolidation import FakeClient, _seed, _m, _s, NOW  # noqa: E402


def test_the_live_v4_matches_dataset_is_not_a_shard():
    assert C.parse_shard("yara_scanner_matches_v4_xdr_agent_cd7e9b") is None
    assert C.parse_shard("yara_scanner_matches_v4_xdragent2_2fd370") is None


def test_a_dated_v4_matches_dataset_is_still_a_shard():
    """Pre-overwrite leftovers must stay reachable, or they can never be cleaned up."""
    got = C.parse_shard("yara_scanner_matches_v4_xdr_agent_cd7e9b_202608")
    assert got is not None and got["month"] == "202608" and got["kind"] == "matches"


def test_scans_is_unaffected_at_v4():
    """CONFIG_LOOKUP_ROTATION governs the scans datasets and they still rotate; excluding
    them would strand every lifecycle shard."""
    got = C.parse_shard("yara_scanner_scans_v4_xdragent2_2fd370")
    assert got is not None and got["kind"] == "scans" and got["ver"] == "4"


@pytest.mark.parametrize("name", [
    "yara_scanner_matches_v2_hosta_aa0001",
    "yara_scanner_matches_v3_hosta_aa0001",
])
def test_older_schemas_still_shard_unsuffixed_matches(name):
    """On v2/v3 matches really did rotate, so an unsuffixed one is a genuine shard. A tenant
    mid-rollout holds both models at once."""
    assert C.parse_shard(name) is not None


def test_per_scan_targets_are_still_excluded():
    """The original exclusion must survive: a consolidated target can never be re-consumed."""
    assert C.parse_shard("yara_scanner_matches_v2_scan_s1") is None
    assert C.parse_shard("yara_scanner_matches_v4_scan_s1") is None


def test_consolidation_leaves_the_live_v4_dataset_alone():
    """The property that actually protects the tenant, asserted on the datasets themselves."""
    fc = FakeClient()
    live = "yara_scanner_matches_v4_xdr_agent_cd7e9b"
    _seed(fc, live, _m("S1", "xdr-agent", 20))
    _seed(fc, "yara_scanner_scans_v4_xdr_agent_cd7e9b_202608", _s("S1", "xdr-agent", "completed"))
    C.consolidate_all(fc, kinds=("matches",), vers=("4",), dry_run=False, quiet_secs=1,
                      now_ms=NOW, log=lambda *a: None)
    assert live in fc.ds, "the live per-host overwrite dataset was consolidated away"
    assert len(fc.ds[live]) == 20, "its rows were stripped"
    assert not [d for d in fc.ds if d.startswith("yara_scanner_matches_v4_scan_")], \
        "a per-scan target was created from the overwrite dataset"
