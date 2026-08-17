#!/usr/bin/env python3
"""The alert directory must have a ceiling — and counts must survive hitting it.

Per-finding caps bound each record and say nothing about the sum. F files x R rules is
unbounded, so a noisy ruleset on a small endpoint disk had no ceiling at all: the failure
this branch already hit once produced a 220 MB alert file on a single host.

The invariant that makes a ceiling safe is that it degrades DETAIL, never COUNTS. The
per-finding "Total string hits" line is what tenant-side totals reconcile against, so a
budget that dropped whole findings would turn a disk-space problem into a data-integrity
problem — the scanner would under-report matches and look like it had missed them.

So past the ceiling each finding still writes its count line plus a one-line explanation,
and only the per-offset dump is dropped. The scan summary reports alert_detail_suppressed
so a thin alert file is explainable rather than suspicious.

Note the ceiling triggers degradation rather than a hard stop: the compact records still
cost bytes, so the final size overshoots the limit by a bounded amount instead of stopping
dead mid-finding.
"""
import base64
import glob
import importlib
import json
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = [
    ("xsiam_yara_scanner", "ALERT_DIR_MAX_BYTES"),
    ("xdr_yara_scanner", "CONFIG_ALERT_DIR_MAX_BYTES"),
]
RULE = base64.b64encode(
    b'rule budget_probe { strings: $a = "MATCHME" condition: $a }').decode()


def _run(edition, max_mb, n_files=8, payload=400):
    """Run a real scan into a throwaway scanner dir; return (module, summary, alert text).

    The scan target lives OUTSIDE the scanner dir on purpose - a target inside it is
    correctly excluded by the self-skip predicate, which silently scans nothing.
    """
    work = tempfile.mkdtemp(prefix="scannerdir_")
    target = tempfile.mkdtemp(prefix="scantarget_")
    try:
        os.environ["YARA_SCANNER_DIR"] = work
        os.environ["YARA_ALERT_DIR_MAX_MB"] = str(max_mb)
        mod = importlib.reload(importlib.import_module(edition))
        # Credentials are placeholders in the committed file; without stubbing them the
        # run aborts before writing anything. Delivery stays off - this is a disk test.
        for attr, value in (("DEFAULT_API_KEY", "k" * 20),
                            ("DEFAULT_API_ENDPOINT", "https://example.invalid/logs/v1/event"),
                            ("DEFAULT_XDR_API_KEY", "k" * 20),
                            ("DEFAULT_XDR_API_ID", "1"),
                            ("DEFAULT_XDR_API_URL", "https://example.invalid")):
            if hasattr(mod, attr):
                setattr(mod, attr, value)
        for attr in ("UPLOAD_RESULTS", "CONFIG_CREATE_ALERTS", "CONFIG_WRITE_DATASET"):
            if hasattr(mod, attr):
                setattr(mod, attr, False)

        for i in range(n_files):
            with open(os.path.join(target, f"f{i}.txt"), "w") as fh:
                fh.write("MATCHME " * payload)

        mod.main(RULE, target, "low")

        body = "".join(open(a, errors="replace").read()
                       for a in glob.glob(os.path.join(work, "alert", "*")))
        summaries = sorted(glob.glob(os.path.join(work, "logs", "scan_summary_*.json")))
        summary = json.load(open(summaries[-1])) if summaries else {}
        return mod, summary, body
    finally:
        os.environ.pop("YARA_SCANNER_DIR", None)
        os.environ.pop("YARA_ALERT_DIR_MAX_MB", None)
        for d in (work, target):
            shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def _restore():
    yield
    for name, _ in EDITIONS:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


@pytest.mark.parametrize("edition,const", EDITIONS)
def test_counts_survive_the_ceiling(edition, const):
    """Every finding keeps its count line, however tight the budget."""
    _, summary, body = _run(edition, max_mb=0.002)

    assert summary.get("matches") == 8, (
        f"{edition}: the budget dropped findings ({summary.get('matches')} of 8). It must "
        f"degrade detail, never counts — under-reporting matches turns a disk problem into "
        f"a data-integrity problem.")
    assert body.count("Total string hits") == 8, (
        f"{edition}: only {body.count('Total string hits')} of 8 findings kept a count line")


@pytest.mark.parametrize("edition,const", EDITIONS)
def test_detail_is_actually_dropped(edition, const):
    _, summary, body = _run(edition, max_mb=0.002)

    assert summary.get("alert_detail_suppressed", 0) > 0, (
        f"{edition}: the ceiling never engaged, so nothing was bounded")
    assert "Offset detail omitted" in body
    assert body.count("Matched Strings") < 8, (
        f"{edition}: full offset dumps were still written for every finding")


@pytest.mark.parametrize("edition,const", EDITIONS)
def test_generous_budget_changes_nothing(edition, const):
    """The default path must be untouched — no degradation without pressure."""
    _, summary, body = _run(edition, max_mb=64)

    assert summary.get("alert_detail_suppressed", 0) == 0, (
        f"{edition}: detail was suppressed under a 64 MB budget for 8 tiny findings")
    assert "Offset detail omitted" not in body
    assert body.count("Matched Strings") == 8


@pytest.mark.parametrize("edition,const", EDITIONS)
def test_zero_disables_the_ceiling(edition, const):
    mod, summary, body = _run(edition, max_mb=0)

    assert getattr(mod, const) == 0
    assert summary.get("alert_detail_suppressed", 0) == 0, (
        f"{edition}: 0 must mean 'no ceiling', matching every other cap knob here")


@pytest.mark.parametrize("edition,const", EDITIONS)
def test_footprint_is_reported(edition, const):
    """A thin alert file must be explainable from the summary alone."""
    _, summary, _ = _run(edition, max_mb=0.002)
    for field in ("alert_bytes_written", "alert_detail_suppressed", "alert_dir_max_bytes"):
        assert field in summary, f"{edition}: {field} missing from scan_summary"
    assert summary["alert_bytes_written"] > 0
