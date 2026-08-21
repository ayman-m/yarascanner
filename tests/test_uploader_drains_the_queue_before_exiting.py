#!/usr/bin/env python3
"""The lookup worker must not exit while rows are still queued.

Root cause of the xdragent stranding (2026-08-21): 19 of 1523 rows undelivered, worker
stopped 2.3s into a 150s drain budget with zero send failures. The sentinel is put on the
BACK of a FIFO queue, so "the drain timed out" cannot explain it — and it didn't.

The exit test in _worker's Empty branch reads:

    for target in ...:
        if batches[target] and ... >= self.flush_interval:
            flush_target(target)                       # blocks: jitter + POST + retries
    if self.stop_flag and not any(batches.values()):
        break

flush_target can block for seconds inside _send_batch. Anything the scan enqueues during
that window — trailing match rows, and the terminal lifecycle row — lands in the QUEUE,
while stop() concurrently sets stop_flag and adds the sentinel. flush_target then clears
`batches`, so the next line sees stop_flag set and no batches and breaks. The final drain
only flushes `batches`, which is empty, so every row queued during the flush is stranded:
never sent, never failed, counted as undelivered.

The exit condition has to see the queue, not just the in-memory batches.
"""
import os
import sys
import threading
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_yara_scanner as m  # noqa: E402

MATCHES = "yara_scanner_matches_v4_h_abc123"
SCANS = "yara_scanner_scans_v4_h_abc123"


def _uploader(on_send):
    u = m.LookupDatasetUploader.__new__(m.LookupDatasetUploader)
    u.queue = Queue()
    u.batch_size = 1000            # big, so only the flush_interval path flushes
    u.flush_interval = 0           # every Empty tick flushes what is pending
    u.stop_flag = False
    u.log_manager = None
    u.matches_dataset = MATCHES
    u.scans_dataset = SCANS
    u.upload_stats = {"queued": 0, "records_added": 0, "records_updated": 0,
                      "records_skipped": 0, "send_failures": 0, "batches_sent": 0}
    u._stats_lock = threading.Lock()
    u._send_batch = on_send
    return u


def test_rows_queued_during_a_blocking_flush_are_still_sent():
    """Reproduces the exact interleaving: the scan's last rows and the terminal lifecycle
    row are enqueued while the worker is inside a slow _send_batch, and stop() lands in the
    same window."""
    sent = []
    state = {"first": True}

    def on_send(target, batch):
        sent.append((target, list(batch)))
        if state["first"]:
            state["first"] = False
            # ---- everything below happens WHILE the worker is blocked in here ----
            for i in range(18):
                u.queue.put((MATCHES, {"file": "f%d" % i}))
            u.queue.put((SCANS, {"status": "completed"}))   # the terminal row, queued last
            u.stop_flag = True                              # stop() sets the flag...
            u.queue.put(None)                               # ...and adds the sentinel

    u = _uploader(on_send)
    u.queue.put((MATCHES, {"file": "first"}))               # seeds the first flush

    t = threading.Thread(target=u._worker, daemon=True)
    t.start()
    t.join(timeout=15)
    assert not t.is_alive(), "worker did not exit"

    delivered = [r for _, batch in sent for r in batch]
    assert len(delivered) == 20, (
        "worker exited with %d of 20 rows unsent — rows queued during the blocking flush "
        "were stranded (queue left with %d items)" % (len(delivered), u.queue.qsize()))
    assert {"status": "completed"} in delivered, "the terminal lifecycle row was stranded"


def test_the_queue_is_empty_when_the_worker_exits():
    """The accounting consequence: whatever is left in the queue is booked as undelivered,
    which is how a completed scan ends up reporting a delivery shortfall it never had."""
    def on_send(target, batch):
        if not getattr(on_send, "done", False):
            on_send.done = True
            for i in range(5):
                u.queue.put((MATCHES, {"file": "late%d" % i}))
            u.stop_flag = True
            u.queue.put(None)

    u = _uploader(on_send)
    u.queue.put((MATCHES, {"file": "seed"}))
    t = threading.Thread(target=u._worker, daemon=True)
    t.start()
    t.join(timeout=15)
    assert not t.is_alive()
    leftover = [u.queue.get_nowait() for _ in range(u.queue.qsize())]
    leftover = [x for x in leftover if x is not None]
    assert leftover == [], "%d row(s) left queued at exit" % len(leftover)


def test_a_clean_stop_with_nothing_queued_still_exits_promptly():
    """Guards the obvious over-correction: requiring an empty queue must not stop the worker
    from exiting when there is genuinely nothing left."""
    u = _uploader(lambda target, batch: None)
    u.stop_flag = True
    t = threading.Thread(target=u._worker, daemon=True)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "worker failed to exit on a clean stop"
