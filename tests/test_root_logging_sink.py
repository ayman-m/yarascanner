#!/usr/bin/env python3
"""Root-level INFO records must land on disk, and must never reach stdout.

`setup_logging()` used to remove every root handler and pin the level to WARNING. That
kept stdout clean - which matters, because Action Center truncates a script's stdout at
10,240 characters and a chatty scan would push the SCAN_RESULT line out of the window -
but it also meant the ~40 (XSIAM) / ~44 (XDR) `logging.info` calls in each edition
reached NOTHING on any host.

That was not a cosmetic problem. For a large number of capabilities an info-level line is
the ONLY stated evidence that the behaviour ran, so those capabilities could not be
verified on a live scan at all: 46 such gaps were catalogued for XSIAM and 40 for XDR.
An unobservable capability cannot be a test success criterion, which made this the single
biggest blocker to writing acceptance criteria for the scan trials.

Four properties are pinned here, in both editions:

  1. INFO records reach logs/diagnostics_<run_id>.log.
  2. stdout stays clean - the regression this whole design exists to avoid.
  3. A categorized logger (propagate=False) is NOT duplicated into the diagnostics file.
  4. An unwritable logs_dir degrades to the old WARNING behaviour instead of killing the
     scan; losing the info trail is survivable, failing the run is not.
"""
import importlib
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


class _Cfg:
    """Minimal stand-in for ScanConfig: setup_logging only reads these two attributes."""

    def __init__(self, logs_dir, run_id="20260817_101112_131415"):
        self.logs_dir = logs_dir
        self.run_id = run_id


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """setup_logging mutates global state; put it back so tests stay independent."""
    saved = logging.root.handlers[:]
    saved_level = logging.root.level
    logging.root.handlers = []
    yield
    for h in logging.root.handlers[:]:
        try:
            h.close()
        except Exception:
            pass
        logging.root.removeHandler(h)
    logging.root.handlers = saved
    logging.root.setLevel(saved_level)


def _diag_path(cfg):
    return os.path.join(cfg.logs_dir, f"diagnostics_{cfg.run_id}.log")


@pytest.mark.parametrize("edition", EDITIONS)
def test_info_records_land_on_disk(edition, tmp_path):
    mod = importlib.import_module(edition)
    cfg = _Cfg(str(tmp_path))

    mod.setup_logging(cfg)
    logging.info("canary-info-record")
    for h in logging.root.handlers:
        h.flush()

    path = _diag_path(cfg)
    assert os.path.exists(path), f"{edition}: no diagnostics log was created"
    assert "canary-info-record" in open(path, encoding="utf-8").read(), (
        f"{edition}: logging.info did not reach the diagnostics log - the ~40 info calls "
        f"in this edition are still writing to nothing")


@pytest.mark.parametrize("edition", EDITIONS)
def test_info_never_reaches_stdout(edition, tmp_path, capsys):
    """The 10,240-char Action Center stdout budget is the reason this design exists."""
    mod = importlib.import_module(edition)
    mod.setup_logging(_Cfg(str(tmp_path)))

    logging.info("must-not-appear-on-stdout")
    logging.warning("warning-may-appear-on-stderr")
    captured = capsys.readouterr()

    assert "must-not-appear-on-stdout" not in captured.out, (
        f"{edition}: an INFO record reached stdout, which risks truncating SCAN_RESULT")
    assert "must-not-appear-on-stdout" not in captured.err, (
        f"{edition}: an INFO record reached stderr")


@pytest.mark.parametrize("edition", EDITIONS)
def test_categorized_loggers_are_not_duplicated(edition, tmp_path):
    """propagate=False loggers must not double-write now that root has a handler."""
    mod = importlib.import_module(edition)
    cfg = _Cfg(str(tmp_path))
    mod.setup_logging(cfg)

    private = logging.getLogger(f"{edition}_private_probe")
    private.propagate = False
    private.setLevel(logging.INFO)
    private.info("categorized-record")
    for h in logging.root.handlers:
        h.flush()

    body = open(_diag_path(cfg), encoding="utf-8").read()
    assert "categorized-record" not in body, (
        f"{edition}: a propagate=False logger was duplicated into the diagnostics log")


@pytest.mark.parametrize("edition", EDITIONS)
def test_unwritable_logs_dir_degrades_instead_of_raising(edition, tmp_path):
    """Losing the info trail is survivable. Killing the scan over it is not."""
    mod = importlib.import_module(edition)
    missing = tmp_path / "does" / "not" / "exist"

    mod.setup_logging(_Cfg(str(missing)))  # must not raise

    assert logging.root.level == logging.WARNING, (
        f"{edition}: expected a fall back to the old WARNING behaviour when the "
        f"diagnostics file cannot be opened")
