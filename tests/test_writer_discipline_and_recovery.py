#!/usr/bin/env python3
"""Criteria D2.4 (single sequential writer), D3.3 (abandoned findings) and D4.4 (recovery).

The three remaining Round 4 criteria. Unlike the rest of the audit these were not gaps --
the behaviour was already right. What was missing was anything that would NOTICE if it
stopped being right, which for D2.4 in particular is the whole safety story.

D2.4 is the criterion the entire per-host sharding design exists to satisfy. `add_data` is
not concurrency-safe: measured live, 8 threads writing one dataset lost 87% of 1,601 rows.
Consolidation is safe only because it is the single sequential writer to its target. That is
currently true by construction -- the write path is a plain `for` loop over batches -- and
"true by construction" is exactly the kind of property a well-meant refactor deletes, since
parallelising a loop of slow network calls looks like an obvious win. `_delete_many` really
is threaded, which makes the write path look like an oversight rather than a decision.
"""
import threading

import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management  # noqa: F401
from test_consolidation import NOW, FakeClient, _m, _s, _seed

import YaraConsolidateCommon as pack_common
import xdr_consolidate as xc

IMPLS = [
    pytest.param(xc, id="xdr_consolidate"),
    pytest.param(pack_common, id="pack"),
]


class ThreadRecordingClient(FakeClient):
    """Records the thread each write happened on, plus the order of writes per dataset.

    Concurrency here would not fail visibly -- FakeClient's dict extend happens to be safe
    under the GIL -- so this asserts on the CALLS, not on the resulting data. A test that
    only checked the final row count would pass against a fully parallelised writer and miss
    the collision entirely, which is the same class of blindness D2.3 exposed.
    """

    def __init__(self):
        super().__init__()
        self.write_threads = {}   # dataset -> set of thread idents
        self.write_order = []     # (dataset, batch size) in call order

    def add_lookup_data(self, name, rows):
        self.write_threads.setdefault(name, set()).add(threading.get_ident())
        self.write_order.append((name, len(rows)))
        return super().add_lookup_data(name, rows)


@pytest.mark.parametrize("impl", IMPLS)
def test_a_target_is_written_by_exactly_one_thread(impl):
    """D2.4. Enough rows to force multiple batches, so a parallelised writer would show up
    as more than one thread ident against the same dataset."""
    fc = ThreadRecordingClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 700))
    _seed(fc, "yara_scanner_matches_v2_hostb_bb0002", _m("S1", "hostb", 700))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S1", "hostb", "completed"))

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is True

    target = "yara_scanner_matches_v2_scan_s1"
    assert len(fc.write_order) > 1, (
        "1,400 rows did not produce multiple batches, so this proves nothing about "
        "concurrent writing -- check _WRITE_BATCH")
    assert fc.write_threads[target] == {threading.main_thread().ident}, (
        f"the target was written from {len(fc.write_threads[target])} threads. add_data is "
        f"not concurrency-safe: 8 concurrent writers to one dataset lost 87% of rows when "
        f"measured live.")


@pytest.mark.parametrize("impl", IMPLS)
def test_no_two_datasets_are_written_interleaved(impl):
    """Sequential in the stronger sense the criterion means: a dataset's batches are not
    interleaved with another's. Interleaving would imply concurrent passes over the same
    target even if each individual call came from one thread."""
    fc = ThreadRecordingClient()
    for host, shard in (("hosta", "aa0001"), ("hostb", "bb0002")):
        _seed(fc, f"yara_scanner_matches_v2_{host}_{shard}", _m("S1", host, 700))
        _seed(fc, f"yara_scanner_scans_v2_{host}_{shard}", _s("S1", host, "completed"))
    impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                           log=lambda *a: None)

    seen, runs = set(), []
    for name, _ in fc.write_order:
        if not runs or runs[-1] != name:
            runs.append(name)
    for name in runs:
        assert name not in seen, (
            f"writes to {name} were interleaved with another dataset's: {runs}")
        seen.add(name)


@pytest.mark.parametrize("impl", IMPLS)
def test_an_abandoned_scans_partial_findings_are_preserved(impl):
    """D3.3. A scan that never reported a terminal row -- the console-Cancel hard-kill case,
    which orphans the lifecycle at 'running' forever. Past the 24h cutoff it stops blocking
    cleanup, and the criterion is that its findings are MERGED, not dropped: partial findings
    are real findings."""
    fc = FakeClient()
    stale = NOW - (25 * 3600 * 1000)
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 7, ts=stale))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "running", ts=stale))

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is True, (
        f"an abandoned scan was not consolidated ({plans[0]['reason']}), so its shard "
        f"remains forever -- the objective says no shard survives 24h past its scan start")
    assert len(fc.ds["yara_scanner_matches_v2_scan_s1"]) == 7, (
        "an abandoned scan's partial findings were not preserved into the target")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_live_scan_with_recent_rows_is_still_protected(impl):
    """The negative half of D3.3. Without it, 'consolidate every non-terminal scan' passes
    the test above and deletes shards out from under scans that are still running."""
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", _m("S1", "hosta", 7, ts=NOW - 60_000))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001",
          _s("S1", "hosta", "running", ts=NOW - 60_000))

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is not True, "a scan that reported a minute ago was consolidated"
    assert "yara_scanner_matches_v2_hosta_aa0001" in fc.ds, "a live scan's shard was deleted"


@pytest.mark.parametrize("impl", IMPLS)
def test_a_half_built_target_from_a_crashed_pass_keeps_every_source(impl):
    """D4.4. A pass that died mid-write leaves a target holding some of the rows. The next
    pass must not mistake it for a finished merge.

    Recovery here is the absence of an action: the count does not match, so nothing is
    deleted and the sources remain available for a later pass to redo the merge from. The
    orphaned-lock half of D4.4 is covered by tests/test_lock_takeover_reporting.py.
    """
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hostb_bb0002", _m("S2", "hostb", 10))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S2", "hostb", "completed"))
    _seed(fc, "yara_scanner_matches_v2_scan_s2", _m("S2", "hostb", 4))   # the crash residue

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is False
    assert plans[0]["reason"] == "count_mismatch"
    assert "yara_scanner_matches_v2_hostb_bb0002" in fc.ds, (
        "the source shard was deleted against a half-built target -- the 6 missing rows "
        "would be unrecoverable")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_complete_target_from_an_interrupted_pass_is_recognised(impl):
    """The other side of D4.4: a pass that wrote everything and died before deleting.

    Re-running must recognise the finished merge and complete the cleanup rather than
    re-merging (which would double the rows and then fail verification forever). This is
    what makes the operation resumable rather than merely safe to abandon.
    """
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hostb_bb0002", _m("S2", "hostb", 10))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S2", "hostb", "completed"))
    _seed(fc, "yara_scanner_matches_v2_scan_s2", _m("S2", "hostb", 10))   # already complete

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is True, (
        f"a complete target from an interrupted pass was not recognised "
        f"({plans[0]['reason']}), so the shard would never be cleaned up")
    assert len(fc.ds["yara_scanner_matches_v2_scan_s2"]) == 10, (
        "the target was re-merged, doubling its rows")
    assert "yara_scanner_matches_v2_hostb_bb0002" not in fc.ds, (
        "the source shard was not cleaned up on the resumed pass")
