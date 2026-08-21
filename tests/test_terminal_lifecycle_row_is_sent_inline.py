#!/usr/bin/env python3
"""The terminal scan-lifecycle row must not ride the batch queue.

Consolidation decides a scan is finished by reading its terminal row. That row is emitted
LAST — after every match row has been queued — so on the shared FIFO upload queue it is
always the tail, and the tail is what a shortfall at drain time takes.

Measured on xdragent (2026-08-21, 636,743 files): the uploader logged
`Lookup drain: 19 rows pending (~1 batches), budget 150s` and then
`worker stopped (batches=35, added=1504, failures=0)` 2.3 seconds later — 19 rows stranded
inside a 150s budget with zero send failures. The scan's own summary recorded
outcome=completed, yet its dataset held only initiated + 2×running, so a finished scan read
as "running" and stayed unmergeable until the 24h abandoned-scan fallback.

Sending that one row inline takes it out of the queue, so it no longer depends on drain
behaviour. Heartbeats deliberately keep queueing: they are periodic, batching them is the
point, and losing one costs nothing.
"""
import ast
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_yara_scanner as m  # noqa: E402


class _Uploader:
    """A LookupUploader with the queue and the network both replaced by recorders."""

    def __init__(self):
        self.scans_dataset = "yara_scanner_scans_v4_h_abc123"
        self.matches_dataset = "yara_scanner_matches_v4_h_abc123"
        self.upload_stats = {"queued": 0, "send_failures": 0}
        self._stats_lock = threading.Lock()
        self.log_manager = None
        self.queued = []          # rows that went through the batch queue
        self.sent_inline = []     # (dataset, batch) sent straight out

    # real method under test, bound onto this stub
    send_scan_row_now = m.LookupDatasetUploader.send_scan_row_now

    def _send_batch(self, target, batch):
        self.sent_inline.append((target, list(batch)))

    def add_scan_row(self, record):
        self.queued.append(record)


class _ErrLog:
    valid_rules_count = 5
    failed_rules_count = 0


class _Cfg:
    hostname = "xdragent"
    os_info = "Windows 2022Server [AMD64]"
    ip_addresses = ["10.10.0.9"]
    scan_id = "xdragent_20260821_042451_058819_yara_b451b4336910"
    run_id = "20260821_042451_058819"
    tenant_id = "emea-cxdrp"
    scan_folder = "default"
    write_dataset = True
    cpu_guarantee = "headroom"
    posture = "alerts=on dataset=on"
    error_logger = _ErrLog()


class _Gov:
    slept_total = 0.0


def _scanner(uploader):
    s = m.YaraScanner.__new__(m.YaraScanner)
    s.lookup_uploader = uploader
    s.config = _Cfg()
    s.log_manager = None
    s._scan_started_at = 0.0
    s.files_scanned = 636743
    s.files_skipped = 50652
    s.total_detections = 2643
    s.cpu_governor = _Gov()
    s.lock_counts = threading.Lock()
    s.lock_throttle = threading.Lock()
    s._scans_row_lock = threading.Lock()
    return s


def test_the_terminal_row_bypasses_the_queue():
    up = _Uploader()
    _scanner(up)._emit_scan_row("completed", "scan completed", sync=True)
    assert up.queued == [], "terminal row was queued — it is the tail and gets stranded there"
    assert len(up.sent_inline) == 1
    target, batch = up.sent_inline[0]
    assert target == up.scans_dataset
    assert len(batch) == 1 and batch[0]["status"] == "completed"


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_every_terminal_status_takes_the_inline_path(status):
    """cancelled and failed matter as much as completed: consolidation treats all three as
    terminal, and an orphaned row blocks the merge whichever one it was."""
    up = _Uploader()
    _scanner(up)._emit_scan_row(status, "x", sync=True)
    assert up.queued == [] and len(up.sent_inline) == 1
    assert up.sent_inline[0][1][0]["status"] == status


def test_heartbeats_still_queue():
    """The regression this fix could easily cause: sending every row inline would put an
    add_data POST on the scan's own thread on every heartbeat."""
    up = _Uploader()
    _scanner(up)._emit_scan_row("running", "heartbeat")
    assert len(up.queued) == 1 and up.sent_inline == []


def test_the_inline_send_is_counted_as_queued():
    """queued must balance against added/updated/skipped/unconfirmed/undelivered. Bypassing
    _enqueue skips its counter, so send_scan_row_now has to pay it instead — otherwise the
    delivery books show one row more delivered than was ever queued."""
    up = _Uploader()
    _scanner(up)._emit_scan_row("completed", "scan completed", sync=True)
    assert up.upload_stats["queued"] == 1


def test_a_failing_inline_send_never_takes_the_scan_down():
    """This runs on the scan's own thread during cleanup, so an exception here would
    propagate into the epilogue and could flip a completed scan's reported outcome."""
    up = _Uploader()

    def boom(target, batch):
        raise RuntimeError("add_data exploded")

    up._send_batch = boom

    class _LM:
        def __init__(self):
            self.errors = []

        def log_error(self, msg):
            self.errors.append(msg)

    # send_scan_row_now logs through the UPLOADER's log manager, which is where a failure
    # of the direct send belongs — the scanner never sees the exception at all.
    up.log_manager = _LM()
    s = _scanner(up)
    s._emit_scan_row("completed", "scan completed", sync=True)     # must not raise
    assert up.upload_stats["send_failures"] == 1
    assert any("add_data exploded" in e for e in up.log_manager.errors)


def test_write_dataset_off_still_emits_nothing():
    """Unchanged behaviour: the sync path must respect the same opt-out as the queued one."""
    up = _Uploader()
    s = _scanner(up)
    s.config.write_dataset = False
    s._emit_scan_row("completed", "scan completed", sync=True)
    assert up.queued == [] and up.sent_inline == []


# --------------------------------------------------------- the call site itself
# The tests above drive _emit_scan_row(sync=True) directly, so they prove the MECHANISM and
# nothing about whether the terminal emission actually asks for it. Deleting `sync=True`
# from the call site left all of them green — the whole fix reverted, undetected. This gates
# the call site, which is the part that can silently regress.

def _terminal_emit_call():
    import ast
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "xdr", "xdr_yara_scanner.py")
    with open(src) as fh:
        tree = ast.parse(fh.read())
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "_emit_scan_row"):
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Name) and first.id == "_term_status":
            found.append(node)
    assert len(found) == 1, "expected exactly one terminal _emit_scan_row call, got %d" % len(found)
    return found[0]


def test_the_terminal_emission_call_site_asks_for_the_inline_path():
    kw = {k.arg: k.value for k in _terminal_emit_call().keywords}
    assert "sync" in kw, (
        "the terminal _emit_scan_row call dropped sync=True — the row is back on the batch "
        "queue as its tail, which is the exact stranding this file exists to prevent")
    assert isinstance(kw["sync"], ast.Constant) and kw["sync"].value is True


def test_the_heartbeat_call_site_does_not():
    """Guards the opposite regression: making heartbeats synchronous would put a blocking
    add_data POST on the scan thread every heartbeat interval."""
    import ast
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "xdr", "xdr_yara_scanner.py")
    with open(src) as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_emit_scan_row" and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in ("running", "initiated")):
            kw = {k.arg: k.value for k in node.keywords}
            assert not (isinstance(kw.get("sync"), ast.Constant) and kw["sync"].value is True), (
                "%r is emitted synchronously — only the terminal row should be"
                % node.args[0].value)
