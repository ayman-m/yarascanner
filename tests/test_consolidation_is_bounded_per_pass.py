#!/usr/bin/env python3
"""A consolidation pass must fit inside the XSOAR task timeout, and say so when it doesn't.

Measured on the emea tenant (2026-08-21): with 85 scans eligible, YaraConsolidateApply ran
past its 900s task timeout and was killed. A hard kill runs no Python, so:

  * release_consolidation_lock() never ran -> the lock dataset survived, and because
    DEFAULT_LOCK_STALE_SECS was 2h while a run can only ever legitimately hold the lock for
    the 900s task timeout, consolidation was parked for ~105 minutes with nothing running.
  * record_consolidation_run() never ran -> the run left NO row in
    yara_scanner_consolidation_runs, so there was no queryable evidence it had ever started,
    let alone died. The `except -> record_consolidation_run("crashed")` path cannot help: a
    kill raises no exception.

Unbounded work made this permanent rather than transient — the next pass faces the same 85
scans and dies the same way. Bounding the pass is what turns it into progress.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import yaml  # noqa: E402
import xdr_consolidate as C  # noqa: E402
from test_consolidation import FakeClient, _seed, _m, _s, NOW  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _seed_scans(fc, n):
    """n independent, ready-to-consolidate scans."""
    for i in range(n):
        sid = "S%02d" % i
        _seed(fc, "yara_scanner_matches_v2_host%02d_aa00%02d" % (i, i), _m(sid, "host%02d" % i, 5))
        _seed(fc, "yara_scanner_scans_v2_host%02d_aa00%02d" % (i, i), _s(sid, "host%02d" % i, "completed"))


def test_a_pass_stops_at_max_scans():
    fc = FakeClient()
    _seed_scans(fc, 10)
    r = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                          now_ms=NOW, max_scans=4, log=lambda *a: None)
    assert r["consolidated_count"] == 4, r["consolidated_count"]
    assert r["stopped_early"] is True


def test_a_bounded_pass_says_it_left_work_behind():
    """Silent truncation would read as 'everything is consolidated' — the operator has to be
    able to tell a finished backlog from a capped pass."""
    fc = FakeClient()
    _seed_scans(fc, 10)
    r = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                          now_ms=NOW, max_scans=4, log=lambda *a: None)
    assert r["stopped_early"] is True
    r2 = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                           now_ms=NOW, max_scans=50, log=lambda *a: None)
    assert r2["stopped_early"] is False, "a pass that drained the backlog must not claim it stopped early"


def test_successive_passes_make_progress_and_converge():
    """The property that actually matters: capped passes must not re-pick the same scans and
    spin forever. Ten scans, four at a time, must finish."""
    fc = FakeClient()
    _seed_scans(fc, 10)
    done, passes = set(), 0
    while passes < 10:
        passes += 1
        r = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                              now_ms=NOW, max_scans=4, log=lambda *a: None)
        done |= set(r["consolidated_scan_ids"])
        if not r["stopped_early"]:
            break
    assert len(done) == 10, "converged to %d of 10 after %d passes" % (len(done), passes)
    assert passes <= 4, "took %d passes for 10 scans at 4/pass" % passes


def test_unbounded_is_still_the_default():
    """max_scans must be opt-in: the CLI and every existing caller keep draining the backlog."""
    fc = FakeClient()
    _seed_scans(fc, 6)
    r = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                          now_ms=NOW, log=lambda *a: None)
    assert r["consolidated_count"] == 6 and r["stopped_early"] is False


def test_the_stale_lock_window_is_not_wildly_longer_than_a_run_can_live():
    """A run cannot hold the lock longer than its task timeout — the platform kills it. A
    stale window far beyond that is dead time in which consolidation is parked and nothing
    is running. 2h against a 900s timeout was 8x, i.e. ~105 minutes of avoidable stall."""
    ymls = [os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts", n, n + ".yml")
            for n in ("YaraConsolidateApply", "YaraConsolidateStatus", "YaraConsolidateSummary")]
    timeouts = [yaml.safe_load(open(p)).get("timeout") for p in ymls]
    assert all(isinstance(t, int) and t > 0 for t in timeouts), timeouts
    worst = max(timeouts)
    assert C.DEFAULT_LOCK_STALE_SECS >= worst, (
        "stale window %ds is shorter than the %ds task timeout — a healthy long run would "
        "have its lock stolen mid-merge" % (C.DEFAULT_LOCK_STALE_SECS, worst))
    assert C.DEFAULT_LOCK_STALE_SECS <= 2 * worst, (
        "stale window %ds is more than 2x the %ds task timeout — that gap is time the "
        "pipeline is parked with nothing running" % (C.DEFAULT_LOCK_STALE_SECS, worst))


def test_the_bound_limits_WORK_not_just_the_REPORT():
    """The bug the first implementation shipped with, caught by the convergence test above.

    run_consolidation merges and deletes EAGERLY and only then yields per-scan results, so
    capping the result loop bounds the report and nothing else: every scan still gets
    consolidated, its sources still get deleted, and the ones past the cap simply come back
    unreported. That is worse than no bound at all — the run log and the playbook's
    failed/attention logic would both be reasoning about a fraction of what actually
    happened. The cap has to narrow only_scan_ids BEFORE the walk.

    Asserting on the datasets, not on the returned counts, is the whole point: the broken
    version returned exactly the same counts as the correct one.
    """
    fc = FakeClient()
    _seed_scans(fc, 10)
    r = C.consolidate_all(fc, kinds=("matches",), dry_run=False, quiet_secs=1,
                          now_ms=NOW, max_scans=4, log=lambda *a: None)
    targets = [d for d in fc.ds if d.startswith("yara_scanner_matches_v2_scan_")]
    sources = [d for d in fc.ds if d.startswith("yara_scanner_matches_v2_host")]
    assert len(targets) == 4, "%d scans were actually consolidated, not 4" % len(targets)
    assert len(sources) == 6, "%d source shards survived, expected 6 untouched" % len(sources)
    assert sorted(r["consolidated_scan_ids"]) == ["S00", "S01", "S02", "S03"]
    assert len(r["consolidated_scan_ids"]) == len(targets), (
        "reported %d consolidated but %d targets exist — the report does not match the work"
        % (len(r["consolidated_scan_ids"]), len(targets)))


def test_the_shipped_default_reflects_the_measured_per_scan_cost():
    """DEFAULT_MAX_SCANS_PER_PASS shipped as 20 with no measurement behind it. Live on emea
    (2026-08-21): 5 scans took 638s (71% of the 900s task timeout) - 20 would be killed
    around scan 7, reproducing the exact stuck-lock incident this whole file exists to
    prevent. A 4-scan pass was separately measured at 403s (45% of budget) and completed
    cleanly. Pin to that, with real margin instead of none.
    """
    assert C.DEFAULT_MAX_SCANS_PER_PASS <= 4, (
        "DEFAULT_MAX_SCANS_PER_PASS=%d has no margin against the measured cost "
        "(~105s fixed per-pass overhead + ~75-107s marginal per scan) and the 900s task "
        "timeout" % C.DEFAULT_MAX_SCANS_PER_PASS)


def test_the_playbook_apply_task_passes_execute_and_a_row_ceiling():
    """The playbook must send the arguments that make a full-consolidation pass do work AND
    stay bounded.

    Supersedes the old max_scans assertion. YaraConsolidateApply no longer walks scans in a
    bounded loop - it writes one dataset per ruleset group - so the per-pass bound is
    row_ceiling, not max_scans. And it is now DRY RUN BY DEFAULT, which is the sharper trap:
    a task that omits execute reports what it would write and writes nothing, silently, on
    every scheduled run for ever. That regression was introduced and caught by this file.
    """
    import yaml
    path = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Playbooks",
                        "playbook-YARA_Dataset_Consolidation.yml")
    pb = yaml.safe_load(open(path))
    apply_task = next(t for t in pb["tasks"].values()
                      if (t.get("task") or {}).get("script") == "YaraConsolidateApply")
    args = apply_task.get("scriptarguments") or {}
    assert "execute" in args, (
        "the playbook's Apply task does not pass execute - the full branch would dry-run "
        "for ever and never write")
    assert args["execute"] == {"simple": "${inputs.full_execute}"}, args["execute"]
    assert "row_ceiling" in args, "the playbook's Apply task does not pass row_ceiling"
    assert "max_scans" not in args, (
        "max_scans is not an argument of the full-consolidation Apply any more; passing it "
        "would be silently ignored and imply a bound that is not applied")


def test_the_playbook_declares_a_full_execute_input():
    """The counterpart of summary_execute. Without it the operator cannot preview a full
    pass, and task 6's ${inputs.full_execute} would resolve to nothing."""
    import yaml
    path = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Playbooks",
                        "playbook-YARA_Dataset_Consolidation.yml")
    pb = yaml.safe_load(open(path))
    inputs = {i.get("key"): i for i in (pb.get("inputs") or [])}
    assert "full_execute" in inputs, "playbook has no full_execute input"
    assert (inputs["full_execute"].get("value") or {}).get("simple") == "true", (
        "full_execute must default to true, or every scheduled full pass is a no-op")


def test_the_playbook_declares_no_max_scans_input():
    """The counterpart to test_the_playbook_apply_task_passes_execute_and_a_row_ceiling.

    That test asserts max_scans is never PASSED to the Apply task, because the v4 path has no
    such concept - consolidate_full writes a ruleset group as a unit and its per-pass bound is
    row_ceiling, rows being what runs the clock out. This asserts the other half: it must not
    be DECLARED either.

    Declaring it was worse than harmless. It put a knob in front of an operator, on a playbook
    whose whole job is a bounded pass, that was wired to nothing and silently did nothing when
    set. An input that cannot affect the run should not be offered.
    """
    import yaml
    path = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Playbooks",
                        "playbook-YARA_Dataset_Consolidation.yml")
    pb = yaml.safe_load(open(path))
    keys = [i.get("key") for i in (pb.get("inputs") or [])]
    assert "max_scans" not in keys, (
        "max_scans is declared but the v4 path has no such bound - it is row_ceiling")
    assert "row_ceiling" in keys, "the bound that DOES apply must stay overridable"
