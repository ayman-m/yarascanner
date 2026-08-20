#!/usr/bin/env python3
"""A scan's epilogue must not be able to change, or erase, the outcome already reported.

Two defects, one root cause: the block that gathers final statistics and uploads the closing
report was the only unguarded step in the shutdown sequence, sitting between two neighbours
that ARE guarded.

The symptom differs per edition because the ORDER differs, which is why this is asserted
structurally in both rather than ported as one behaviour:

  XDR    the terminal lifecycle row is emitted BEFORE this block, from scan_system's
         `finally`, with scan_failed still False -- so the row says "completed" and the
         tenant has already been told the scan finished. A raise here escaped to run()'s
         outer handler, which sets scan_failed = True, so scan_summary_<run_id>.json and the
         operator's result line said "failed" while the yara_scanner_scans row said
         "completed". Nothing reconciles them, and consolidation gates on the row -- so a
         scan that reported failure to a human would consolidate as an ordinary success.

  XSIAM  the terminal status upload happens AFTER this block. A raise here meant no terminal
         value was ever sent at all -- the exact failure this file documents having already
         fixed on the failure path ("It also sent no terminal event, so a dashboard just saw
         the scan stop").

A statistics call or a report upload failing does not un-scan the files. The scan genuinely
completed; only its epilogue did not.

Asserted with AST rather than a string search: `try:` appearing somewhere near the call
proves nothing about whether the call is INSIDE it, and that distinction is the entire fix.
"""
import ast
import os

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EDITIONS = [
    pytest.param(os.path.join(_ROOT, "xdr", "xdr_yara_scanner.py"), id="xdr"),
    pytest.param(os.path.join(_ROOT, "xsiam", "xsiam_yara_scanner.py"), id="xsiam"),
]


def _tree(path):
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _calls_named(tree, name):
    """Every Call node invoking a bare function of this name."""
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == name]


def _innermost_try(tree, lineno):
    """The tightest `try` whose BODY contains this line, or None.

    INNERMOST is the whole point, and the first version of this file got it wrong. Asking
    "is any try-with-a-handler wrapped around this line" answers YES for every line in
    run(), because run() has a function-wide `except Exception` -- and that handler is
    precisely the one that sets scan_failed and flips the outcome. Being inside it is the
    defect, not the fix. A mutation replacing the local `except` with a bare `finally`
    sailed past the earlier check for exactly this reason.

    Body specifically: a call sitting in a `finally` or inside an `except` is not protected
    by that statement, so matching the whole Try node would pass a file where the reporting
    had merely been moved into the handler.
    """
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for stmt in node.body:
            lo, hi = stmt.lineno, getattr(stmt, "end_lineno", stmt.lineno)
            if lo <= lineno <= hi:
                span = hi - lo
                if best is None or span < best[0]:
                    best = (span, node)
    return best[1] if best else None


def _is_guarded(tree, lineno):
    """Guarded means the TIGHTEST enclosing try has its own except handler."""
    t = _innermost_try(tree, lineno)
    return t is not None and bool(t.handlers)


@pytest.mark.parametrize("path", EDITIONS)
def test_the_final_report_upload_is_exception_guarded(path):
    """The specific call whose failure used to flip the outcome."""
    tree = _tree(path)
    calls = _calls_named(tree, "upload_final_comprehensive_report")
    assert calls, "upload_final_comprehensive_report is never called -- test is stale"
    for call in calls:
        assert _is_guarded(tree, call.lineno), (
            f"{os.path.basename(path)}:{call.lineno}: upload_final_comprehensive_report is "
            f"not inside a guarded try body. A failure here changes the reported outcome of "
            f"a scan that actually completed.")


@pytest.mark.parametrize("path", EDITIONS)
def test_the_closing_statistics_gathering_is_guarded(path):
    """The other half of the same block. get_current_stats_for_upload() reaches into live
    counters at shutdown and is exactly the kind of call that raises on a partially torn-down
    scanner -- which is when it runs."""
    tree = _tree(path)
    # Scoped to the EPILOGUE call -- the one feeding the closing report -- by its assignment
    # target. get_current_stats_for_upload is also called from _get_scanner_stats and from
    # the periodic progress path; those run mid-scan, have different callers and different
    # guards, and are not this defect. Asserting on all of them would make this test fail for
    # reasons unrelated to the outcome-flipping it exists to prevent.
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "get_current_stats_for_upload"):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "final_performance_stats" in names:
            hits.append(node)
    assert hits, ("no `final_performance_stats = ...get_current_stats_for_upload()` "
                  "assignment found -- test is stale")
    unguarded = [n.lineno for n in hits if not _is_guarded(tree, n.lineno)]
    assert not unguarded, (
        f"{os.path.basename(path)}: closing statistics gathered outside a guard at "
        f"line(s) {unguarded}")


@pytest.mark.parametrize("path", EDITIONS)
def test_the_guard_is_a_real_handler_not_a_bare_finally(path):
    """Negative control on the assertion itself. Wrapping the block in try/finally with no
    except would satisfy a naive "is there a Try ancestor" check while still letting the
    exception propagate and flip the outcome."""
    tree = _tree(path)
    call = _calls_named(tree, "upload_final_comprehensive_report")[0]
    inner = _innermost_try(tree, call.lineno)
    assert inner is not None, "no enclosing try at all"
    assert inner.handlers, (
        f"{os.path.basename(path)}: the tightest try around the final report upload has no "
        f"except handler -- so the exception propagates to run()'s function-wide handler, "
        f"which is the one that sets scan_failed and flips the outcome")


@pytest.mark.parametrize("path", EDITIONS)
def test_raw_yara_content_dump_is_run_scoped(path):
    """failed_rules/ is deliberately never pruned, so a fixed filename is not 'the latest
    copy' -- it is the only copy, silently replaced every run.

    This artefact holds the rule content that could not be split into rules at all, and the
    situation it exists for is precisely the one someone re-runs repeatedly while trying to
    fix it. Each attempt overwrote the evidence from the last.

    Its siblings (failed_rule_*, skipped_rule_*) were already run_id-scoped; this one was
    missed.
    """
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    assert '"raw_yara_content.yar"' not in src, (
        f"{os.path.basename(path)}: the raw-content dump uses a fixed filename, so each run "
        f"overwrites the previous run's copy in a directory that is never pruned")
    assert "raw_yara_content_" in src, "the raw-content dump is missing entirely"
    assert 'f"raw_yara_content_{self.config.run_id}.yar"' in src, (
        f"{os.path.basename(path)}: the raw-content dump is not scoped by run_id, unlike "
        f"every other artefact written into failed_rules/")


@pytest.mark.parametrize("path", EDITIONS)
def test_no_artefact_in_failed_rules_uses_a_fixed_name(path):
    """Generalises the case above: any literal filename joined onto failed_rules_dir is a
    silent-overwrite bug in a directory with no pruning."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    import re
    fixed = re.findall(r'failed_rules_dir,\s*"([^"]+)"', src)
    assert not fixed, (
        f"{os.path.basename(path)}: fixed-name artefact(s) written into the never-pruned "
        f"failed_rules/ directory: {fixed}")
