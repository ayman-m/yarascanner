#!/usr/bin/env python3
"""The delivery books must balance: nothing may be both undelivered AND successful.

Measured on a live endpoint. A whole-filesystem scan cancelled mid-walk booked 69,150
findings, and the SAME counter was read three times, 500 apart each time:

    [15:13:57] Match delivery final: matches=69150 ok=56504 failed=0 undelivered=12146
    result line                    :                ok=57004        undelivered=12146
    scan_summary_<run_id>.json     :                ok=57504        undelivered=12146

`undelivered` froze while `ok` kept climbing by exactly one batch (500) at a time. The
same log carries the cause, at the same timestamp as the "final" ledger:

    [15:13:57] Upload thread did not terminate within 60s timeout

The sequence: the drain window expires, `stop_upload_thread` is set, and a sentinel is
queued — but it lands BEHIND 12,146 items. `_upload_worker` only consults the stop flag
when the queue comes back Empty, which never happens against a full backlog, so it keeps
pulling batches. The 60 s join times out, `stop()` counts the still-queued items as
`undelivered`, and the thread — still alive — then delivers 1,000 of those very items into
`successful_uploads`.

So an item can be counted in both buckets. `ok + failed + undelivered` then exceeds the
number of items ever queued, and the shortfall on the operator's result line is computed
from a denominator that does not exist.

The contract the code states is that `undelivered` means "still queued when the drain
window expired — never attempted". Honouring that means the worker must stop attempting
once it has been told to stop, rather than overshooting the window and invalidating the
books. This asserts that property directly.
"""
import importlib
import os
import sys
import threading
import time
from queue import Queue

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITION = "xsiam_yara_scanner"


@pytest.fixture()
def mod():
    m = importlib.reload(importlib.import_module(EDITION))
    yield m
    importlib.reload(importlib.import_module(EDITION))


def _shrink_windows(mod, monkeypatch, drain=0.4, join=0.4):
    """Scale the shutdown windows down so the live condition fits in a unit test.

    The live discrepancy needed the drain budget to expire WITH a backlog and the 60 s
    join to then time out. Reproducing that at shipped values would take minutes; the
    logic under test is identical at 0.4 s.
    """
    monkeypatch.setattr(mod, "_compute_drain_budget", lambda n: drain)
    monkeypatch.setattr(mod, "THREAD_CLEANUP_TIMEOUT", join)


def _uploader(mod, sent, batch_secs=0.05):
    """A ResultsUploader with delivery stubbed out, so only the loop logic is under test."""
    up = object.__new__(mod.ResultsUploader)
    up.upload_queue = Queue()
    up.stop_upload_thread = False
    up.upload_thread = None
    up.log_manager = None
    up._stop_done = False
    up.upload_stats = {"total_matches": 0, "successful_uploads": 0,
                       "failed_uploads": 0, "undelivered": 0}

    def _batch(items):
        # Slow enough that a backlog cannot clear inside the stop window — the condition
        # that produced the live discrepancy. A queue that drains on its own would exit
        # the loop through the Empty branch and prove nothing about the stop flag.
        time.sleep(batch_secs)
        sent.extend(items)
        up.upload_stats["successful_uploads"] += len(items)

    up._upload_batch = _batch
    return up


def test_worker_stops_attempting_once_told_to_stop(mod, monkeypatch):
    """The loop must check the stop flag before pulling a batch, not only on Empty.

    With a full queue the Empty branch is never reached, so a flag checked only there is
    a flag that never fires.
    """
    sent = []
    up = _uploader(mod, sent)
    # 40 batches x 0.05 s = ~2 s of work, so the backlog cannot clear on its own.
    for i in range(20000):
        up.upload_queue.put({"n": i})

    t = threading.Thread(target=up._upload_worker, daemon=True)
    t.start()
    time.sleep(0.1)
    up.stop_upload_thread = True

    t.join(timeout=1.0)
    assert not t.is_alive(), (
        "the upload worker did not exit within 1 s of being told to stop — it only "
        "consults stop_upload_thread when the queue is Empty, which a backlog never is, "
        "so it keeps sending past the shutdown window")

    delivered_after_stop = len(sent)
    time.sleep(0.2)
    assert len(sent) == delivered_after_stop, "the worker kept delivering after exiting"


def test_books_balance_after_a_stop_with_a_backlog(mod, monkeypatch):
    """ok + failed + undelivered must never exceed what was queued."""
    _shrink_windows(mod, monkeypatch)
    sent = []
    up = _uploader(mod, sent)
    queued = 20000
    for i in range(queued):
        up.upload_queue.put({"n": i})

    up.upload_thread = threading.Thread(target=up._upload_worker, daemon=True)
    up.upload_thread.start()
    time.sleep(0.1)

    up.stop(wait=True)
    time.sleep(0.5)          # let any straggler batch land, as the live run did

    s = up.upload_stats
    total = s["successful_uploads"] + s["failed_uploads"] + s["undelivered"]
    assert total <= queued, (
        f"books over-count: ok={s['successful_uploads']} + failed={s['failed_uploads']} "
        f"+ undelivered={s['undelivered']} = {total}, but only {queued} items were ever "
        f"queued. An item counted undelivered was afterwards delivered and counted again.")


def test_undelivered_is_not_contradicted_by_later_success(mod, monkeypatch):
    """Once the books are read, `undelivered` must not be silently invalidated.

    This is the live symptom stated as an invariant: successful_uploads may not keep
    growing after stop() has published the final numbers.
    """
    _shrink_windows(mod, monkeypatch)
    sent = []
    up = _uploader(mod, sent)
    for i in range(20000):
        up.upload_queue.put({"n": i})

    up.upload_thread = threading.Thread(target=up._upload_worker, daemon=True)
    up.upload_thread.start()
    time.sleep(0.1)

    up.stop(wait=True)
    ok_at_stop = up.upload_stats["successful_uploads"]
    undelivered_at_stop = up.upload_stats["undelivered"]

    time.sleep(0.5)
    assert up.upload_stats["successful_uploads"] == ok_at_stop, (
        f"successful_uploads moved from {ok_at_stop} to "
        f"{up.upload_stats['successful_uploads']} AFTER the final books were published, "
        f"while undelivered stayed at {undelivered_at_stop} — the live 500-at-a-time drift")
