#!/usr/bin/env python3
"""The diagnostics FileHandler must be closable, and setup_logging must never use stdout.

TWO DEFECTS, both found by auditing the capability catalogue against the source.

1. THE EIGHTH HANDLER. Windows refuses to delete a file that is still open, so every
   per-run log handler has to be closed before HostCleanup runs. main() is careful about
   this and says so at length -- it closes LogManager's six category handlers and
   ErrorLogger's seventh (yara_processing), and the comment records that this took two
   live rounds to get right:

       "Windows refuses to delete one - os.remove() fails with WinError 32 and
        HostCleanup silently records it as an error rather than crashing the scan.
        Verified live, in two rounds: closing only log_manager's handlers fixed six of
        the seven files; the seventh (yara_processing) needed error_logger.close() too"

   There are EIGHT. setup_logging() installs a FileHandler on the ROOT logger writing
   logs/diagnostics_<run_id>.log, and nothing ever closes it. Worse, the same comment
   explains that host cleanup's own messages cannot go through log_manager (already
   closed) and therefore use the plain `logging` module -- so cleanup logs its progress
   INTO the very file it is trying to delete, guaranteeing the handle is hot at the
   moment of the unlink.

   Consequence on Windows with host cleanup enabled: one diagnostics_<run_id>.log
   survives every run, the failure is recorded as an error rather than raised, and the
   endpoint accumulates a file per scan indefinitely. The scanner's whole host-footprint
   story is that it cleans up after itself.

2. STDOUT IS A CAPPED, SHARED RESOURCE. setup_logging's failure paths call bare print(),
   which writes to stdout -- the one resource Action Center truncates at 10,240
   characters, and whose budget the SCAN_RESULT line depends on. A logging failure is
   exactly the kind of thing that repeats. These belong on stderr, which is uncapped and
   which the scanner already uses for WARNING and above.

Both editions carry the same setup_logging, so both are covered.
"""
import importlib
import io
import logging
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


@pytest.fixture(params=EDITIONS)
def mod(request):
    m = importlib.reload(importlib.import_module(request.param))
    yield m
    for h in logging.root.handlers[:]:
        logging.root.removeHandler(h)
    importlib.reload(importlib.import_module(request.param))


class _Cfg:
    def __init__(self, logs_dir):
        self.logs_dir = logs_dir
        self.run_id = "testrun"


def _setup(mod, tmp_path):
    mod.setup_logging(_Cfg(str(tmp_path)))


def test_a_closer_exists(mod):
    assert hasattr(mod, "close_diagnostics_handler"), (
        "no way to close the root diagnostics FileHandler; on Windows it keeps "
        "diagnostics_<run_id>.log open and HostCleanup cannot delete it")


def test_the_handler_is_installed_then_closed(mod, tmp_path):
    _setup(mod, tmp_path)
    diag = [h for h in logging.root.handlers
            if isinstance(h, logging.FileHandler)
            and "diagnostics_" in getattr(h, "baseFilename", "")]
    assert len(diag) == 1, f"expected exactly one diagnostics FileHandler, got {len(diag)}"

    assert mod.close_diagnostics_handler() is True
    still = [h for h in logging.root.handlers
             if isinstance(h, logging.FileHandler)
             and "diagnostics_" in getattr(h, "baseFilename", "")]
    assert not still, "the diagnostics handler is still attached to the root logger"
    assert diag[0].stream is None or diag[0].stream.closed, (
        "the handler was detached but its file is still open — Windows still refuses "
        "the unlink")


def test_closing_is_idempotent(mod, tmp_path):
    """main()'s cleanup block runs inside a try/except that may be re-entered."""
    _setup(mod, tmp_path)
    assert mod.close_diagnostics_handler() is True
    assert mod.close_diagnostics_handler() is False      # nothing left to do, no raise


def test_closing_with_nothing_installed_is_safe(mod):
    assert mod.close_diagnostics_handler() is False


def test_the_stderr_warning_channel_survives(mod, tmp_path):
    """Cleanup's own warnings still need a home; stderr is not the capped resource."""
    _setup(mod, tmp_path)
    mod.close_diagnostics_handler()
    streams = [h for h in logging.root.handlers
               if isinstance(h, logging.StreamHandler)
               and not isinstance(h, logging.FileHandler)]
    assert streams, "closing diagnostics also removed the stderr channel"
    assert streams[0].level == logging.WARNING


def test_setup_logging_never_writes_to_stdout(mod, tmp_path):
    """stdout is capped at 10,240 chars and reserved for the result line."""
    out = io.StringIO()
    bad = os.path.join(str(tmp_path), "no", "such", "dir")
    with mock.patch.object(sys, "stdout", out):
        mod.setup_logging(_Cfg(bad))          # FileHandler creation must fail
    assert out.getvalue() == "", (
        f"setup_logging wrote {out.getvalue()!r} to stdout; that budget belongs to "
        f"SCAN_RESULT, and a logging failure is exactly the kind that repeats")
