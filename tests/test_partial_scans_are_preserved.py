#!/usr/bin/env python3
"""A cancelled or failed scan's findings are REAL findings and must be consolidated.

Round 4 criteria D3.1 and D3.2.

`TERMINAL_LIFECYCLE` is {"completed", "cancelled", "failed"}, but before this file the
strings "cancelled" and "failed" appeared NOWHERE in tests/test_consolidation.py.
Measured, not assumed:

  narrow it in xdr_consolidate.py alone  -> 1 of 74 existing tests fails
  narrow it in EVERY copy in tandem      -> 74 of 74 existing tests PASS

The one test that fires on the single-copy edit is
`test_pack_copy_gate_logic_matches_xdr_consolidate`, which compares the source TEXT of the
copies. It guards DRIFT between them, so it cannot see a change applied to all of them --
and a consistency check can only ever prove the copies agree, never that what they agree on
is correct. So the behaviour itself was untested in every copy at once.

The consequence of that mutation: every cancelled or failed scan is permanently
non-terminal, so its per-host shard is never consolidated, never cleaned up, and its
findings sit stranded on a dataset nobody merges -- the exact failure this subsystem
exists to prevent, one keystroke away from being undetectable.

Why these two states are terminal at all, and must stay so:

  cancelled  an operator stopping a scan does not un-find what it already found. A scan
             cancelled 80% through a filesystem has 80% of a real answer in it.
  failed     a scan that died is the case you MOST want the evidence from.

Every test here runs against xdr_consolidate.py AND all six shipping automations. Those six
are what execute on the tenant, so a guarantee proven only in xdr_consolidate.py is not a
guarantee -- and one proven in five of the six is not one either.

The abandoned path (a scan that never reports any terminal state) is covered separately by
test_consolidation.py's cutoff tests; this file is about scans that DID report, with a
status other than success.
"""
import pytest

# Importing this module installs the XSOAR stubs (demistomock / CommonServerPython) and
# puts the pack's script dirs on sys.path. Reused rather than restubbed here: a second
# stub is one more thing that can drift from the platform surface it stands in for.
import test_pack_data_management

import xdr_consolidate as xc

# xdr_consolidate.py plus ALL SIX automations that ship (test_pack_data_management.SHIPPING).
# Each of the six inlines this logic verbatim -- the tenant does not resolve cross-script
# imports, so an automation has to be self-contained -- and it is those six copies, not
# xdr_consolidate.py, that execute. A behaviour proven only in the CLI is not a guarantee, and
# a behaviour proven in five of six is not one either.
IMPLS = test_pack_data_management.impls(xc)


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("status", ["completed", "cancelled", "failed"])
def test_every_terminal_lifecycle_status_is_treated_as_finished(impl, status):
    assert impl.shard_is_terminal(status, None) is True, (
        f"a scan reporting {status!r} was not treated as finished, so its shard would "
        f"never be consolidated and its findings would be stranded")


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("status", ["cancelled", "failed"])
def test_case_is_not_significant(impl, status):
    """The scanner writes lowercase, but nothing guarantees that forever."""
    assert impl.shard_is_terminal(status.upper(), None) is True
    assert impl.shard_is_terminal(status.capitalize(), None) is True


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("status", ["running", "initiated", "", None])
def test_non_terminal_states_are_not_swept_up(impl, status):
    """The negative control. Without it, 'everything is terminal' also passes above."""
    assert impl.shard_is_terminal(status, None) is False, (
        f"{status!r} was treated as finished -- a scan still writing could have its shard "
        f"merged and deleted underneath it")


@pytest.mark.parametrize("impl", IMPLS)
def test_the_terminal_set_still_contains_all_three(impl):
    """Pins the set itself, so narrowing it fails here with a message that says why."""
    assert impl.TERMINAL_LIFECYCLE == {"completed", "cancelled", "failed"}, (
        f"TERMINAL_LIFECYCLE is {impl.TERMINAL_LIFECYCLE}. Removing 'cancelled' or "
        f"'failed' strands those scans' findings permanently: the shard is never terminal, "
        f"so it is never consolidated and never cleaned up.")


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("status", ["cancelled", "failed"])
def test_build_terminal_map_marks_partial_scans_terminal(impl, status):
    """End to end through the map the planner actually consumes."""
    rows_by_ds = {
        "yara_scanner_scans_v3_host1_abc123": [
            {"scan_id": "s1", "hostname": "host1", "status": "running",
             "event_timestamp_ms": 1000},
            {"scan_id": "s1", "hostname": "host1", "status": status,
             "event_timestamp_ms": 2000},
        ]
    }
    # Keyed by the host parsed out of the DATASET NAME, which carries the 6-hex shard
    # suffix -- not by the row's hostname field. Those differ, and keying on the wrong one
    # returns None rather than raising, so get it right here.
    tmap = impl.build_terminal_map(rows_by_ds)
    entry = tmap.get(("s1", "host1_abc123"))
    assert entry is not None, "the (scan_id, host) pair is absent from the terminal map"
    assert entry["terminal"] is True, (
        f"a scan whose newest lifecycle row says {status!r} was not marked terminal")
    assert entry["status"] == status


@pytest.mark.parametrize("impl", IMPLS)
def test_a_partial_scan_still_running_elsewhere_is_not_terminal(impl):
    """Two hosts, one cancelled and one still going: only the cancelled one is finished."""
    rows_by_ds = {
        "yara_scanner_scans_v3_host1_abc123": [
            {"scan_id": "s1", "hostname": "host1", "status": "cancelled",
             "event_timestamp_ms": 2000}],
        "yara_scanner_scans_v3_host2_def456": [
            {"scan_id": "s1", "hostname": "host2", "status": "running",
             "event_timestamp_ms": 2000}],
    }
    tmap = impl.build_terminal_map(rows_by_ds)
    assert tmap[("s1", "host1_abc123")]["terminal"] is True
    assert tmap[("s1", "host2_def456")]["terminal"] is False, (
        "a host still scanning was marked terminal because a SIBLING host had finished")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_later_running_row_does_not_revive_a_cancelled_scan(impl):
    """Ordering: the NEWEST row wins, so a stale 'running' arriving late cannot un-finish
    a cancelled scan. Rows are fed out of timestamp order deliberately."""
    rows_by_ds = {
        "yara_scanner_scans_v3_host1_abc123": [
            {"scan_id": "s1", "hostname": "host1", "status": "cancelled",
             "event_timestamp_ms": 5000},
            {"scan_id": "s1", "hostname": "host1", "status": "running",
             "event_timestamp_ms": 1000},
        ]
    }
    tmap = impl.build_terminal_map(rows_by_ds)
    assert tmap[("s1", "host1_abc123")]["terminal"] is True, (
        "an out-of-order 'running' row older than the cancellation revived the scan")
