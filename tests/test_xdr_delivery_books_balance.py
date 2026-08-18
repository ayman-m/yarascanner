#!/usr/bin/env python3
"""XDR delivery books must balance: nothing may be both undelivered AND successful.

This is the SAME invariant tests/test_undelivered_books_balance.py pins for XSIAM, but it
is deliberately a separate file rather than a parametrised case, because the two uploaders
are not the same code and the XSIAM fix was explicitly flagged as unsafe to port blind:

    XSIAM              one item per send, `_upload_batch`, `_compute_drain_budget`
    XDR                accumulates into a `batch` list, `flush()` closure,
                       `_upload_alert_batch` returning a status STRING
                       ("ok" | "requeue" | "dropped"), plus ALERT_REQUEUE_ENABLED
                       and a rate-limited requeue path XSIAM has no equivalent of.

The shared shape is the defect: `stop_upload_thread` is consulted only in the
`except Empty:` branch, which a full queue never reaches.

Why the documented "deliberate window" does NOT make the fix unsafe
-------------------------------------------------------------------
stop() comments that `stop_upload_thread` stays False so rate-limited batches can still
requeue. That is true, and it is why a naive port would be wrong -- but the window closes
BEFORE the flag is set. Read in order, stop() does:

    1. queue the storm rollups
    2. drain, requeue-ENABLED, flag still False   <- the deliberate window
    3. self.stop_upload_thread = True             <- window is now closed
    4. put the None sentinel
    5. join(THREAD_CLEANUP_TIMEOUT)
    6. book whatever is still queued as `undelivered`

A stop-flag check at the TOP of the worker loop cannot shorten step 2, because during
step 2 the flag is still False and the check falls through. It only takes effect from
step 3, by which point requeue is already disabled anyway -- `_upload_alert_batch`'s
requeue condition itself reads `not self.stop_upload_thread`.

Nor does breaking early lose the accumulated batch: `_upload_worker` calls flush() once
more after the loop. Those items were already task_done()'d, so they are not in qsize()
and cannot also be booked undelivered. If that final flush is rate-limited it can no
longer requeue, so it falls through to `failed_uploads += n` -- counted, not leaked.

Why the hazard is real here and not merely theoretical
------------------------------------------------------
The sentinel lands at the BACK of the queue, so the worker must chew through the whole
backlog to reach it. At shipped values it delivers ALERT_BATCH_SIZE (60) per POST no
faster than ALERT_MIN_BATCH_INTERVAL (7 s), so a 60 s join covers only ~500 alerts. Any
larger backlog outlives the join, `is_alive()` is still True, stop() takes the
approximate branch -- `leftover = max(0, qsize() - 1)` -- and books those items
`undelivered` while the live thread goes on delivering them into `successful_uploads`.

That is the XSIAM symptom exactly: measured there at 12,146 booked undelivered while ok
climbed by 1,000 afterwards, one batch at a time.

The windows are shrunk here so the condition fits a unit test; the logic under test is
identical at 0.4 s.
"""
import importlib
import os
import sys
import threading
import time
from queue import Queue

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITION = "xdr_yara_scanner"
QUEUED = 20000


@pytest.fixture()
def mod():
    m = importlib.reload(importlib.import_module(EDITION))
    yield m
    importlib.reload(importlib.import_module(EDITION))


def _shrink_windows(mod, monkeypatch, drain=0.4, join=0.4):
    """Scale stop()'s two shutdown windows down. Both are read as module globals."""
    monkeypatch.setattr(mod, "ALERT_DRAIN_SECS", drain)
    monkeypatch.setattr(mod, "ALERT_DRAIN_MAX_SECS", drain)
    monkeypatch.setattr(mod, "THREAD_CLEANUP_TIMEOUT", join)


def _uploader(mod, sent, batch_secs=0.05):
    """A ResultsUploader with delivery stubbed, so only the loop logic is under test."""
    up = object.__new__(mod.ResultsUploader)
    up.upload_queue = Queue()
    up.stop_upload_thread = False
    up.upload_thread = None
    up.log_manager = None
    up._stop_done = False
    up._requeued_total = 0
    up._deliver_deadline = None
    up.upload_stats = {
        'total_matches': 0, 'findings': 0, 'alerts_queued': 0,
        'successful_uploads': 0, 'failed_uploads': 0,
        'suppressed': 0, 'rollups': 0, 'undelivered': 0,
    }
    # Rollups are a separate concern and would need the findings lock; not under test.
    up._queue_rollup_alerts = lambda: None

    def _batch(items):
        # Slow enough that the backlog cannot clear inside the stop window -- the
        # condition that produces the discrepancy. A queue that drains on its own would
        # leave through the Empty branch and prove nothing about the stop flag.
        time.sleep(batch_secs)
        sent.extend(items)
        up.upload_stats['successful_uploads'] += len(items)
        return "ok"

    up._upload_alert_batch = _batch
    return up


def _fill(up, n=QUEUED):
    for i in range(n):
        up.upload_queue.put({"n": i})


def test_worker_stops_attempting_once_told_to_stop(mod):
    """The loop must check the stop flag before taking work, not only on Empty.

    With a full queue the Empty branch is never reached, so a flag checked only there is
    a flag that never fires.
    """
    sent = []
    up = _uploader(mod, sent)
    _fill(up)

    t = threading.Thread(target=up._upload_worker, daemon=True)
    t.start()
    time.sleep(0.1)
    up.stop_upload_thread = True

    t.join(timeout=2.0)
    assert not t.is_alive(), (
        "the upload worker did not exit within 2 s of being told to stop -- it consults "
        "stop_upload_thread only when the queue is Empty, which a backlog never is, so "
        "it keeps sending past the shutdown window")

    delivered_at_exit = len(sent)
    time.sleep(0.2)
    assert len(sent) == delivered_at_exit, "the worker kept delivering after exiting"


def test_books_balance_after_a_stop_with_a_backlog(mod, monkeypatch):
    """ok + failed + undelivered must never exceed what was queued."""
    _shrink_windows(mod, monkeypatch)
    sent = []
    up = _uploader(mod, sent)
    _fill(up)

    up.upload_thread = threading.Thread(target=up._upload_worker, daemon=True)
    up.upload_thread.start()
    time.sleep(0.1)

    up.stop(wait=True)
    time.sleep(0.5)          # let any straggler batch land, as the live run did

    s = up.upload_stats
    total = s['successful_uploads'] + s['failed_uploads'] + s['undelivered']
    assert total <= QUEUED, (
        f"books over-count: ok={s['successful_uploads']} + failed={s['failed_uploads']} "
        f"+ undelivered={s['undelivered']} = {total}, but only {QUEUED} items were ever "
        f"queued. An item counted undelivered was afterwards delivered and counted again.")


def test_undelivered_is_not_contradicted_by_later_success(mod, monkeypatch):
    """Once the books are published, `undelivered` must not be silently invalidated."""
    _shrink_windows(mod, monkeypatch)
    sent = []
    up = _uploader(mod, sent)
    _fill(up)

    up.upload_thread = threading.Thread(target=up._upload_worker, daemon=True)
    up.upload_thread.start()
    time.sleep(0.1)

    up.stop(wait=True)
    ok_at_stop = up.upload_stats['successful_uploads']
    undelivered_at_stop = up.upload_stats['undelivered']

    time.sleep(0.5)
    assert up.upload_stats['successful_uploads'] == ok_at_stop, (
        f"successful_uploads moved from {ok_at_stop} to "
        f"{up.upload_stats['successful_uploads']} AFTER the final books were published, "
        f"while undelivered stayed at {undelivered_at_stop} -- the same drift measured "
        f"on the XSIAM side, one batch at a time")


def test_the_deliberate_requeue_window_is_preserved(mod, monkeypatch):
    """The fix must not shorten the requeue-enabled drain that stop() runs FIRST.

    This is the specific regression the porting note warned about: if the worker bailed
    out while the flag was still False, rate-limited batches would lose the later window
    they are supposed to get, and the fix would cause the loss it exists to prevent.
    """
    _shrink_windows(mod, monkeypatch, drain=0.6, join=0.4)
    sent = []
    up = _uploader(mod, sent, batch_secs=0.01)
    _fill(up, n=600)

    flag_while_draining = []
    real_sleep = time.sleep

    def watching_sleep(secs):
        # stop()'s drain loop is the only thing sleeping in 0.5 s steps.
        if secs == 0.5:
            flag_while_draining.append(up.stop_upload_thread)
        real_sleep(secs)

    up.upload_thread = threading.Thread(target=up._upload_worker, daemon=True)
    up.upload_thread.start()
    time.sleep(0.05)

    monkeypatch.setattr(time, "sleep", watching_sleep)
    up.stop(wait=True)
    monkeypatch.undo()

    assert flag_while_draining, "the drain window did not run at all"
    assert not any(flag_while_draining), (
        "stop_upload_thread was already True during the requeue-enabled drain; "
        "rate-limited batches would lose the later window stop() exists to give them")
