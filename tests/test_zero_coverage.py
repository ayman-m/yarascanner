#!/usr/bin/env python3
"""A scan that covered nothing must not look like a scan that found nothing.

Both editions reported outcome="completed", files_scanned=0, files_skipped=0, exit 0
when the requested target was itself in the skip list. The operator's only signal was a
zero, which is indistinguishable from a genuinely empty directory - so an IR lead
scanning AppData\\Local\\Temp (covered by skip_path_fragments) got a clean success and
zero coverage.

Two separate defects, verified independently here:
  1. the excluded target was never reported at all
  2. files under a skipped directory were counted in NEITHER files_scanned nor
     files_skipped, so the summary could not be reconciled against what is on disk
"""
import base64
import glob
import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RULE = base64.b64encode(b'rule t { strings: $a = "MATCHME" condition: $a }').decode()
EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


@pytest.fixture
def tmp_path(tmp_path_factory, request):
    """A scratch dir OUTSIDE every platform skip list.

    Deliberately shadows pytest's built-in tmp_path. On macOS that resolves under
    /private/var/folders/, which is itself in mac_skip_directory - so a scan targeting it
    correctly skips everything and returns zero, and every assertion here silently tests
    nothing. (The same trap invalidated a manual repro earlier: /private/tmp is also on
    the list.) Anchoring under the home directory keeps the fixture outside all three
    editions' skip lists on every platform.
    """
    import re
    import shutil
    # Sanitise the node name: pytest parametrisation embeds "[edition]", and the glob used
    # to find the summary file would read those brackets as a character class and match
    # nothing, making every assertion here fail against an empty dict.
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", request.node.name)
    base = os.path.join(os.path.expanduser("~"), ".yara_scanner_tests", safe)
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    try:
        yield pathlib.Path(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _tree(tmp_path):
    """A target holding one scannable file and a skipped node_modules with two inside."""
    target = tmp_path / "target"
    (target / "node_modules").mkdir(parents=True)
    (target / "ok.txt").write_text("xx MATCHME xx")
    (target / "node_modules" / "a.txt").write_text("xx MATCHME xx")
    (target / "node_modules" / "b.txt").write_text("xx MATCHME xx")
    return target


def _scan(edition, scanner_dir, target):
    """Run a real scan with delivery off and return its summary dict."""
    import importlib
    os.environ["YARA_SCANNER_DIR"] = str(scanner_dir)
    try:
        mod = importlib.import_module(edition)
        importlib.reload(mod)
        if edition.startswith("xsiam"):
            mod.UPLOAD_RESULTS = False
            result = mod.main(RULE, str(target), "low")
        else:
            result = mod.run(RULE, str(target), "low",
                             create_alerts=False, write_dataset=False)
        files = sorted(glob.glob(os.path.join(str(scanner_dir), "logs", "scan_summary_*.json")))
        summary = json.load(open(files[-1], encoding="utf-8")) if files else {}
        return str(result), summary
    finally:
        os.environ.pop("YARA_SCANNER_DIR", None)


@pytest.mark.parametrize("edition", EDITIONS)
def test_skipped_subtree_is_counted_as_skipped(edition, tmp_path):
    """files_scanned + files_skipped must account for every file on disk.

    Regression: the directory-level skip did `continue` without incrementing anything,
    so the two files inside node_modules appeared nowhere. The per-FILE skip 20 lines
    below always incremented; only the directory-level one did not.
    """
    target = _tree(tmp_path)
    _, summary = _scan(edition, tmp_path / "sd", target)

    assert summary.get("files_scanned") == 1, "only ok.txt is scannable"
    assert summary.get("files_skipped", 0) >= 2, (
        f"the 2 files under node_modules must be counted as skipped, "
        f"got files_skipped={summary.get('files_skipped')}"
    )


@pytest.mark.parametrize("edition", EDITIONS)
def test_target_inside_skip_list_is_reported_not_silently_empty(edition, tmp_path):
    """Asking to scan an excluded path must say so, not return a clean zero."""
    target = _tree(tmp_path)
    result, summary = _scan(edition, tmp_path / "sd", target / "node_modules")

    assert summary.get("files_scanned") == 0, "precondition: nothing is scannable there"
    # Deliberately strict about WHERE the signal appears. The Action Center shows the
    # operator this returned string and little else, so a note buried in the summary JSON
    # on the endpoint does not reach them. Checking for "skip" alone is too weak - it now
    # matches the "Skipped directory" reason on any ordinary scan.
    assert "exclud" in result.lower(), (
        "a target dropped by the skip list must say so in the RESULT the operator sees; "
        f"got result={result!r}"
    )
    assert summary.get("excluded_targets"), (
        "the summary must record which requested targets were excluded, for reconciliation"
    )


@pytest.mark.parametrize("edition", EDITIONS)
def test_normal_scan_is_unaffected(edition, tmp_path):
    """The guard must not fire, or add noise, on an ordinary successful scan."""
    target = tmp_path / "plain"
    target.mkdir()
    (target / "hit.txt").write_text("xx MATCHME xx")

    result, summary = _scan(edition, tmp_path / "sd", target)
    assert summary.get("files_scanned") == 1
    assert summary.get("matches") == 1
    assert summary.get("outcome") == "completed"
    assert "exclud" not in result.lower()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
