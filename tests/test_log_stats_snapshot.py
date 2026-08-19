#!/usr/bin/env python3
"""LogManager.get_upload_statistics() must return a SNAPSHOT, not a half-live view.

Found on a live Round 1 scan, not by a test. Two completion records that are documented to
carry identical log_generation_stats disagreed, and one of them did not even agree with
itself:

    system     by_type sums to 67, total_logs 67   <- consistent
    statistics by_type sums to 69, total_logs 67   <- 2 more than its own total

Cause: `self.upload_stats.copy()` is SHALLOW. `total_logs` is an int and is snapshotted by
value; `by_type` is a dict and is handed back BY REFERENCE, so every `_log()` call after the
snapshot keeps mutating it. The gap is exactly the number of records written between taking
the snapshot and serialising it — here the two completion records themselves.

Why it matters beyond tidiness: an operator reconciling by_type against total_logs finds
they disagree and cannot tell which to trust, so "the counters are inconsistent" is
indistinguishable from "logging dropped records".

Both editions carry the identical LogManager; both were affected.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


def _manager(mod):
    """A LogManager shell carrying only the counters, no filesystem."""
    lm = object.__new__(mod.LogManager)
    lm.upload_stats = {"total_logs": 0,
                       "by_type": {t.value: 0 for t in mod.LogType}}
    return lm


@pytest.mark.parametrize("edition", EDITIONS)
def test_snapshot_does_not_move_afterwards(edition):
    m = importlib.import_module(edition)
    lm = _manager(m)
    kind = next(iter(lm.upload_stats["by_type"]))

    lm.upload_stats["total_logs"] += 1
    lm.upload_stats["by_type"][kind] += 1
    snap = lm.get_upload_statistics()

    # two more records land, exactly as the completion records did on the live run
    for _ in range(2):
        lm.upload_stats["total_logs"] += 1
        lm.upload_stats["by_type"][kind] += 1

    assert snap["by_type"][kind] == 1, (
        f"by_type moved from 1 to {snap['by_type'][kind]} after the snapshot was taken — "
        f"dict.copy() shared the nested dict by reference")
    assert sum(snap["by_type"].values()) == snap["total_logs"], (
        f"snapshot is internally inconsistent: by_type sums to "
        f"{sum(snap['by_type'].values())} but total_logs says {snap['total_logs']}")


@pytest.mark.parametrize("edition", EDITIONS)
def test_two_snapshots_of_the_same_moment_agree(edition):
    """The live symptom: two records that must carry identical stats did not."""
    m = importlib.import_module(edition)
    lm = _manager(m)
    kind = next(iter(lm.upload_stats["by_type"]))
    for _ in range(5):
        lm.upload_stats["total_logs"] += 1
        lm.upload_stats["by_type"][kind] += 1

    first = lm.get_upload_statistics()
    lm.upload_stats["total_logs"] += 1          # a record written between the two
    lm.upload_stats["by_type"][kind] += 1
    second = lm.get_upload_statistics()

    assert first["by_type"] != second["by_type"] or first["total_logs"] != second["total_logs"], \
        "sanity: the two snapshots should differ, a record was written between them"
    assert sum(first["by_type"].values()) == first["total_logs"]
    assert sum(second["by_type"].values()) == second["total_logs"]


@pytest.mark.parametrize("edition", EDITIONS)
def test_mutating_the_snapshot_cannot_corrupt_the_counters(edition):
    m = importlib.import_module(edition)
    lm = _manager(m)
    kind = next(iter(lm.upload_stats["by_type"]))
    snap = lm.get_upload_statistics()
    snap["by_type"][kind] = 9999
    assert lm.upload_stats["by_type"][kind] == 0, \
        "writing to the returned snapshot reached back into the live counters"
