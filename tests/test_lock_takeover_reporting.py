#!/usr/bin/env python3
"""A stolen consolidation lock must never be silent.

Round 4 criterion D4.2. `acquire_consolidation_lock` carries two safety parameters that
were implemented but never tested, so a regression dropping either would pass the whole
suite while changing behaviour on the one path that cannot be undone:

  on_takeover        fires when this run STEALS another run's lock, so the caller can
                     report "I proceeded while another run's marker was in place" rather
                     than presenting it as an ordinary uncontended pass.

  unreadable_is_held treats a marker whose row cannot be read as HELD rather than stale.
                     That state is not exotic -- it is exactly the add_data create-lag
                     window right after another run took the lock. YaraCleanup passes this
                     because its cost of a wrong takeover is irreversible: it DELETES
                     datasets, and an unconsolidated shard is a scan's only copy.

Both are about the same failure: two passes mutating the same shards while each believes
it holds the lock. The consolidation side merges twice (recoverable); the cleanup side
deletes concurrently (not).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import xdr_consolidate as xc  # noqa: E402

STALE = xc.DEFAULT_LOCK_STALE_SECS
NOW = 1_800_000_000_000


class _Client:
    """Minimal lock-dataset stand-in. `existing_ms` is the marker's age, or None for a
    marker whose row cannot be read."""

    def __init__(self, fresh, existing_ms=None):
        self._fresh = fresh
        self._existing_ms = existing_ms
        self.deleted = []
        self.added = []

    def create_lookup_dataset(self, name, schema):
        return {"dataset_name": name} if self._fresh else {"status": "exists"}

    def xql(self, q, limit=None):
        if self._existing_ms is None:
            return []
        return [{"started_ms": self._existing_ms}]

    def delete_dataset(self, name, force=False):
        self.deleted.append(name)
        self._fresh = True
        return {"status": "ok"}

    def add_lookup_data(self, name, rows):
        self.added.extend(rows)
        return {"rows added": len(rows)}


def test_a_fresh_lock_is_acquired_without_calling_back():
    seen = []
    c = _Client(fresh=True)
    assert xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                         on_takeover=seen.append) is True
    assert seen == [], "on_takeover fired on an uncontended acquisition"


def test_a_live_lock_is_not_taken_and_not_reported_as_a_takeover():
    seen = []
    c = _Client(fresh=False, existing_ms=NOW - 60_000)      # 60s old, well inside stale
    assert xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                         on_takeover=seen.append) is False
    assert seen == [], "a lock we did NOT take was reported as a takeover"
    assert c.deleted == [], "a live lock's dataset was deleted"


def test_stealing_a_stale_lock_fires_on_takeover():
    """The property: a steal is never silent."""
    seen = []
    c = _Client(fresh=False, existing_ms=NOW - (STALE + 60) * 1000)
    assert xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                         on_takeover=seen.append) is True
    assert len(seen) == 1, (
        "a stale lock was taken over without firing on_takeover — the run would report an "
        "ordinary pass while having mutated shards another run's marker covered")
    assert "taking over" in seen[0]


def test_takeover_replaces_the_marker_rather_than_appending():
    """Leaving stale rows lets a later read pick an arbitrary one, and the dataset grows
    by a row per steal forever."""
    c = _Client(fresh=False, existing_ms=NOW - (STALE + 60) * 1000)
    xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW)
    assert c.deleted, "the stale marker dataset was not deleted before re-creating it"
    assert len(c.added) == 1


def test_unreadable_marker_is_stale_by_default():
    """Consolidation's own posture: a merge repeated is recoverable."""
    seen = []
    c = _Client(fresh=False, existing_ms=None)
    got = xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                        on_takeover=seen.append)
    assert got is True
    assert len(seen) == 1 and "age unknown" in seen[0]


def test_unreadable_marker_is_HELD_for_the_destructive_caller():
    """The stricter posture. This is the add_data create-lag window right after another
    run took the lock; taking over there means deleting datasets concurrently with it."""
    seen = []
    c = _Client(fresh=False, existing_ms=None)
    got = xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                        unreadable_is_held=True, on_takeover=seen.append)
    assert got is False, (
        "an unreadable marker was taken over despite unreadable_is_held — the caller that "
        "passes this flag DELETES datasets, and an unconsolidated shard is a scan's only copy")
    assert seen == [], "stood down, but still reported a takeover"
    assert c.deleted == [], "stood down, but deleted the other run's marker anyway"


@pytest.mark.parametrize("flag", [False, True])
def test_the_flag_only_changes_the_unreadable_case(flag):
    """It must not make a genuinely stale lock un-takeable — that would deadlock cleanup
    behind any marker whose owner died."""
    c = _Client(fresh=False, existing_ms=NOW - (STALE + 60) * 1000)
    assert xc.acquire_consolidation_lock(c, log=lambda *_: None, now_ms=NOW,
                                         unreadable_is_held=flag) is True
