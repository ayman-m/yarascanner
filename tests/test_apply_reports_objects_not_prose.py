#!/usr/bin/env python3
"""Apply's three result lists are CONTEXT, so they carry fields rather than sentences.

`written`, `skipped` and `failed` used to be lists of preformatted strings, and this
automation's are the ones with a live consumer: playbook-YARA_Dataset_Consolidation.yml tests
isNotEmpty on `Yara.ConsolidateApply.failed` and copies the whole list into an operator
attention flag. So a ceiling REFUSAL - nothing attempted, the operator has to choose a
different mode - and a transient HTTP 500 mid-write raised the identical flag and were
distinguishable only by reading English.

Two aggravations Summary did not have, both pinned below:

  * `skipped` mixes three entity kinds - a source dataset, a scan, a ruleset group - in one
    untyped list. `reason` is the discriminator that was missing.
  * the scan identity was TRUNCATED into the sentence with `str(sid)[:34]`, which is shorter
    than any real scan_id (hostname + _YYYYMMDD_HHMMSS_micros_yara_<hash>), so the run_id and
    the ruleset hash were always cut off and the scan could not be recovered from the record
    at all.

And one property that is not obvious: NOTHING in the three lists may be a string. The old
readable-output builder did `lines += ["  %s" % x for x in items]`, which formats a dict
without complaining - so a `%s`-formatted append slipped in beside the structured ones would
sail through the renderer and land in context as a lone string among objects. That is worse
than a crash, because it is silent.
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import yaml  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateApply as A, FakeTenant, _run_automation,
)

RULES = "1aca83d286ad"
TARGET = "yara_scanner_full_v4_rules_%s" % RULES
# Relative to the real clock, deliberately. main() stamps now_ms from time.time(), and the
# gate compares against it - so a fixture pinned to a fixed epoch puts every scan in the
# future, fails both the quiet and the aged test, and reports the whole fleet as still
# running.
NOW_MS = int(time.time() * 1000)
OLD_MS = NOW_MS - 40 * 3600 * 1000

_YML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                    "YaraConsolidateApply", "YaraConsolidateApply.yml")


class RowTenant(FakeTenant):
    """FakeTenant plus the RAW row read full consolidation needs.

    FakeTenant models a dataset as {scan_id: row_count} and answers aggregates out of it,
    which is all Summary ever asks for. Full consolidation copies every COLUMN of every row,
    so it issues a bare `dataset = X` read that the base fake answers with []. Rather than a
    second tenant fake with its own idea of the API, this answers exactly that one query and
    delegates everything else - the wildcard fan-in, the aggregates, the lock row, the
    dataset-not-found raise, the error_on injection - to the fixture the rest of the suite
    uses.
    """

    def __init__(self, *a, **kw):
        self.rows_by_ds = kw.pop("rows_by_ds", None) or {}
        super().__init__(*a, **kw)

    def xql(self, query, limit=1000):
        base = super().xql(query, limit=limit)
        if base:
            return base                       # aggregates, the lock row, an expanded fan-in
        m = re.match(r"^dataset = (\S+)$", query.strip())
        if not m or m.group(1).endswith("*"):
            return base
        return [dict(r) for r in self.rows_by_ds.get(m.group(1), ())]


def _fleet(n=4, quiet=(), running=(), rows=3, rules=RULES, now=OLD_MS):
    """A tenant of `n` hosts on one ruleset.

    Hosts named in `quiet` are stamped recently enough to be held back by the quiet window;
    hosts in `running` are stamped the same way AND have a non-terminal lifecycle row, which
    is the other half of the gate. Dataset names go through the REAL _shard_host_of
    derivation, so the `dataset` field on a skipped record has something true to resolve to.
    """
    names, scans, newest, rows_by_ds = [], {}, {}, {}
    for i in range(1, n + 1):
        hostname = "simhost%03d" % i
        seg = A._shard_host_of(hostname)
        m = "yara_scanner_matches_v4_%s" % seg
        sc = "yara_scanner_scans_v4_%s_202609" % seg
        sid = "%s_20260907_04%04d_123456_yara_%s" % (hostname, i, rules)
        ts = NOW_MS if (hostname in quiet or hostname in running) else now
        status = "in_progress" if hostname in running else "completed"
        names += [m, sc]
        scans[m] = {sid: rows}
        scans[sc] = {sid: 2}
        newest[m] = newest[sc] = ts
        rows_by_ds[m] = [{"tenant_id": "t", "scan_id": sid, "hostname": hostname,
                          "filename": "/tmp/f%d" % j, "file_size": 10 + j,
                          "file_sha256": "%064x" % j, "rules": '[{"rule": "R1"}]',
                          "rule_count": 1, "match_total": 1, "severity": "high",
                          "event_timestamp_ms": ts} for j in range(rows)]
        rows_by_ds[sc] = [{"tenant_id": "t", "scan_id": sid, "hostname": hostname,
                           "status": status, "event_timestamp_ms": ts} for _ in range(2)]
    return RowTenant(names=names, scans=scans, newest=newest, rows_by_ds=rows_by_ds)


def _run(t, **args):
    a = {"schema_version": "4", "retention_hours": "24", "quiet_secs": "900"}
    a.update(args)
    return _run_automation(A, a, t, pin_schema=False)


def _converged(n=4, taken=None):
    """A tenant whose target ALREADY holds every scan - the steady state a drain converges on.

    With `taken` set the pass is bounded, so the scans in the datasets it does not read are
    absent from `observed` and stale removal has to stand down rather than read that absence
    as supersession.
    """
    t = _fleet(n)
    t.names.append(TARGET)
    t.scans[TARGET] = {}
    for ds in sorted(t.scans):
        if ds.startswith("yara_scanner_matches_v4_"):
            for sid, cnt in t.scans[ds].items():
                t.scans[TARGET][sid] = cnt
    return t


# ------------------------------------------------------------------ the three lists

def test_every_entry_in_the_three_lists_is_an_object():
    """The whole point. One string among the objects is the silent failure mode."""
    scenarios = [_run(_fleet(5, quiet=["simhost005"])),
                 _run(_fleet(3), execute="true"),
                 _run(_fleet(3), row_ceiling="1"),
                 _run(_converged(4), execute="true", max_datasets="2")]
    for res in scenarios:
        for key in ("written", "skipped", "failed"):
            for entry in res.outputs[key]:
                assert isinstance(entry, dict), (
                    "%s holds a bare %s - a playbook filtering on a field would silently "
                    "match nothing: %r" % (key, type(entry).__name__, entry))


def test_a_skipped_entry_names_the_reason_and_keeps_the_whole_scan_id():
    res = _run(_fleet(4, quiet=["simhost004"]))
    skipped = res.outputs["skipped"]
    assert skipped, "the quiet host should have been skipped"
    for s in skipped:
        assert set(s) == {"name", "reason", "detail", "scan_id", "hostname", "dataset",
                          "ruleset"}, "skipped record shape drifted: %s" % sorted(s)
        assert s["reason"] and s["detail"]
    quiet = [s for s in skipped if s["reason"] == "quiet_period"]
    assert len(quiet) == 1, [s["reason"] for s in skipped]
    q = quiet[0]
    assert q["hostname"] == "simhost004"
    assert q["ruleset"] == RULES
    # The dataset is taken from the mapping recorded at the READ, so it is the real name and
    # costs no extra query.
    assert q["dataset"] == "yara_scanner_matches_v4_%s" % A._shard_host_of("simhost004")
    # The identity survives whole. str(sid)[:34] used to cut the run_id and the ruleset hash
    # off every real scan_id, so this is the assertion that pins the fix.
    assert q["scan_id"].startswith("simhost004_") and q["scan_id"].endswith(RULES)
    assert len(q["scan_id"]) > 34


def test_a_still_running_scan_is_told_apart_from_a_draining_one():
    """Two different situations that both mean "left alone", and the operator's next move is
    different for each: wait for the scanner, or wait for the uploader."""
    res = _run(_fleet(4, quiet=["simhost003"], running=["simhost004"]))
    by_reason = {s["reason"]: s for s in res.outputs["skipped"]}
    assert set(by_reason) == {"quiet_period", "scan_in_progress"}
    assert by_reason["scan_in_progress"]["hostname"] == "simhost004"
    assert by_reason["quiet_period"]["hostname"] == "simhost003"


def test_a_written_entry_says_whether_it_actually_wrote():
    """`action` is the field to branch on. A dry run must never look like a write."""
    dry = _run(_fleet(3))
    assert [w["action"] for w in dry.outputs["written"]] == ["would_write"]
    assert dry.outputs["status"] == "dry_run" and dry.outputs["dry_run"] is True
    # scans_new is NULL rather than 0 in a preview: the target is never read on that path, so
    # how many of these scans it already holds is unknown, and 0 would be a claim.
    assert dry.outputs["written"][0]["scans_new"] is None

    wrote = _run(_fleet(3), execute="true")
    assert [w["action"] for w in wrote.outputs["written"]] == ["wrote"]
    assert wrote.outputs["status"] == "success"
    assert wrote.outputs["written"][0]["scans_new"] == 3      # nothing held them yet


def test_a_written_entry_carries_the_numbers_not_a_sentence():
    res = _run(_fleet(5, rows=4))
    w = res.outputs["written"][0]
    assert set(w) == {"action", "ruleset", "target", "rows", "hosts", "scans", "scans_new",
                      "stale_rows_removed"}, "written record shape drifted: %s" % sorted(w)
    assert w["ruleset"] == RULES and w["target"] == TARGET
    assert w["rows"] == 20 and w["hosts"] == 5 and w["scans"] == 5
    assert isinstance(w["rows"], int) and isinstance(w["hosts"], int)


def test_a_ceiling_refusal_is_not_the_same_failure_as_a_broken_write():
    """The defect the playbook consumer makes real: `failed` raises one operator flag, and
    before this a REFUSAL an operator must act on and a retryable fault looked identical."""
    res = _run(_fleet(3), row_ceiling="1")
    assert [f["reason"] for f in res.outputs["failed"]] == ["row_ceiling_exceeded"]
    f = res.outputs["failed"][0]
    assert f["rows"] == 9 and f["row_ceiling"] == 1
    assert f["rows_added_before_failure"] is None      # nothing was attempted
    assert f["ruleset"] == RULES and f["target"] == TARGET
    assert res.outputs["written"] == [] and res.outputs["rows_written"] == 0


def test_a_failure_record_asserts_the_sources_were_not_touched():
    """The claim the troubleshooting docs make, carried on the record itself rather than left
    to prose an operator has to trust."""
    t = _fleet(3)
    t.names.append(TARGET)
    t.error_on = ("dataset = %s |" % TARGET,)         # the target read-back blows up
    res = _run(t, execute="true")
    assert res.outputs["failed"], "the unreadable target should have failed the ruleset"
    for f in res.outputs["failed"]:
        assert set(f) == {"reason", "detail", "ruleset", "target", "rows", "row_ceiling",
                          "rows_added_before_failure", "sources_untouched"}
        assert f["sources_untouched"] is True
    assert [f["reason"] for f in res.outputs["failed"]] == ["target_unreadable"]
    assert res.outputs["status"] == "partial_failure"
    # and it really did not touch them. The lock's own release is the only delete a failing
    # pass is allowed to make.
    assert [c for c in t.calls if c.startswith("delete_dataset:")] \
        == ["delete_dataset:%s" % A._LOCK_DATASET]


def test_an_unreadable_source_is_its_own_reason_and_names_the_dataset():
    bad = "yara_scanner_matches_v4_%s" % A._shard_host_of("simhost002")
    t = _fleet(4)
    t.error_on = ("dataset = %s" % bad,)
    res = _run(t)
    unreadable = [s for s in res.outputs["skipped"] if s["reason"] == "source_unreadable"]
    assert len(unreadable) == 1, [s["reason"] for s in res.outputs["skipped"]]
    assert unreadable[0]["dataset"] == bad
    assert unreadable[0]["scan_id"] is None and unreadable[0]["ruleset"] is None
    # the other three hosts still consolidate
    assert res.outputs["written"] and res.outputs["written"][0]["hosts"] == 3


def test_a_stood_down_stale_removal_says_which_of_the_two_reasons_it_was():
    """A pass that CHOSE to read part of the fleet is healthy; a pass that FAILED to read a
    source is not. Both disable stale removal, and reporting them as one reason sent an
    operator hunting a tenant fault that did not exist."""
    res = _run(_converged(4), execute="true", max_datasets="2")
    reasons = {s["reason"] for s in res.outputs["skipped"]}
    assert "stale_removal_disabled_bounded" in reasons
    assert "stale_removal_disabled_unreadable" not in reasons
    bounded = [s for s in res.outputs["skipped"]
               if s["reason"] == "stale_removal_disabled_bounded"][0]
    assert bounded["dataset"] == TARGET and bounded["ruleset"] == RULES
    assert res.outputs["datasets_taken"] == 2 and res.outputs["datasets_remaining"] == 2


def test_an_already_current_target_is_a_skip_with_its_own_reason():
    """The steady state. It used to be a sentence in the same untyped list as an unreadable
    dataset and a still-running scan."""
    res = _run(_converged(3), execute="true")
    current = [s for s in res.outputs["skipped"] if s["reason"] == "target_already_current"]
    assert len(current) == 1
    assert current[0]["dataset"] == TARGET and current[0]["ruleset"] == RULES
    assert res.outputs["written"] == [] and res.outputs["status"] == "success"


# ------------------------------------------------------- the vocabularies stay closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason code invented at a call site and never declared is exactly as unmatchable as
    the prose this replaced - it just looks like a contract."""
    bad = "yara_scanner_matches_v4_%s" % A._shard_host_of("simhost002")
    unreadable_src = _fleet(4)
    unreadable_src.error_on = ("dataset = %s" % bad,)
    unreadable_tgt = _fleet(3)
    unreadable_tgt.names.append(TARGET)
    unreadable_tgt.error_on = ("dataset = %s |" % TARGET,)
    for t, kw in ((_fleet(4, quiet=["simhost004"], running=["simhost003"]), {}),
                  (_fleet(3), {"execute": "true"}),
                  (_fleet(3), {"row_ceiling": "1"}),
                  (unreadable_src, {}),
                  (unreadable_tgt, {"execute": "true"}),
                  (_converged(4), {"execute": "true", "max_datasets": "2"})):
        res = _run(t, **kw)
        for s in res.outputs["skipped"]:
            assert s["reason"] in A.SKIP_REASONS, (
                "undeclared skip reason %r - add it to SKIP_REASONS or use an existing one"
                % s["reason"])
        for f in res.outputs["failed"]:
            assert f["reason"] in A.FAIL_REASONS, "undeclared failure reason %r" % f["reason"]
        for w in res.outputs["written"]:
            assert w["action"] in ("wrote", "would_write"), w["action"]


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    with open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    described = {o["contextPath"]: o["description"] for o in doc["outputs"]}
    for code in A.SKIP_REASONS:
        assert code in described["Yara.ConsolidateApply.skipped.reason"], (
            "skip reason %r is not in the yml's declared closed set" % code)
    for code in A.FAIL_REASONS:
        assert code in described["Yara.ConsolidateApply.failed.reason"], (
            "failure reason %r is not in the yml's declared closed set" % code)
    for verb in ("wrote", "would_write"):
        assert verb in described["Yara.ConsolidateApply.written.action"]


def test_the_two_stale_removal_phrases_still_separate_choice_from_fault():
    """Pinned by tests/test_full_retires_its_sources.py as source text; pinned here as the
    behaviour it describes, so a restructure that keeps the words but loses the distinction
    fails somewhere."""
    assert ("deliberately read only part of the fleet"
            in A.SKIP_REASONS["stale_removal_disabled_bounded"])
    assert ("could not be read this pass"
            in A.SKIP_REASONS["stale_removal_disabled_unreadable"])


# ------------------------------------------------------------- the numbers hold up

def test_the_totals_are_derived_from_the_lists_they_total():
    """A count beside its list is the house convention; a count computed from a SECOND
    expression is how a report comes to state a number the context does not hold."""
    res = _run(_fleet(5, rows=4, quiet=["simhost005"]))
    o = res.outputs
    assert o["rows_written"] == sum(w["rows"] for w in o["written"])
    assert o["targets_written"] == len(o["written"])
    assert o["skipped_count"] == len(o["skipped"])
    assert o["failed_count"] == len(o["failed"])


def test_hosts_is_a_fleet_count_and_survives_a_converged_pass():
    """The old key was a max over WRITTEN groups only, so a fully converged fleet - the steady
    state this automation exists to reach - reported 0 hosts on a complete success."""
    res = _run(_converged(4), execute="true")
    o = res.outputs
    assert o["written"] == [] and o["rows_written"] == 0        # nothing needed rewriting
    assert o["hosts"] == 4, "a converged pass reported %r hosts" % o["hosts"]
    assert o["groups"] == 1


def test_sources_retired_is_always_present_even_at_zero():
    """It used to be set only where retirement reached its tail - absent on every dry run, on
    a lock standdown and on an unreadable target - and a transformer filtering on a
    sometimes-absent key matches nothing and reports no error."""
    for res in (_run(_fleet(3)), _run(_fleet(3), execute="true"),
                _run(FakeTenant([]))):
        assert res.outputs["sources_retired"] == 0


def test_a_lock_standdown_reports_a_status_rather_than_an_empty_pass():
    t = _fleet(2)
    t.names.append(A._LOCK_DATASET)
    t.lock_rows = [{"holder": "another run", "started_ms": NOW_MS}]
    res = _run(t, execute="true")
    o = res.outputs
    assert o["lock_held_by_other_run"] is True and o["status"] == "skipped_locked"
    assert o["written"] == [] and o["skipped"] == [] and o["failed"] == []
    assert "STOOD DOWN" in res.readable_output


def test_an_empty_tenant_reports_zeroes_rather_than_nothing():
    o = _run_automation(A, {"schema_version": "4"}, FakeTenant([]), pin_schema=False).outputs
    assert o["written"] == [] and o["skipped"] == [] and o["failed"] == []
    assert o["rows_written"] == 0 and o["hosts"] == 0 and o["groups"] == 0
    assert o["datasets_total"] == 0 and o["datasets_remaining"] == 0
    assert o["status"] == "dry_run"


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    res = _run(_fleet(4, quiet=["simhost004"]))
    md = res.readable_output
    assert md.startswith("### YARA full consolidation - DRY RUN")
    assert "\n|---|" in md, "no markdown table in the output"
    for heading in ("#### Would write", "#### Skipped - nothing was touched"):
        assert heading in md, "missing section: %s" % heading
    # the plain-lines shape the tables replaced, which XSOAR reflowed into one paragraph
    assert "WRITTEN:" not in md and "SKIPPED:" not in md and "FAILED:" not in md
    assert "dataset(s): " not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    res = _run(_fleet(7, rows=5, quiet=["simhost007"]))
    o, md = res.outputs, res.readable_output
    assert "| **Rows** | %d would be written |" % o["rows_written"] in md
    assert "| **Targets** | %d would be written |" % o["targets_written"] in md
    assert "| **Skipped** | %d |" % o["skipped_count"] in md
    assert "| **Hosts covered** | %d |" % o["hosts"] in md
    assert "| **Ruleset groups** | %d |" % o["groups"] in md
    assert "| **Outcome** | `%s` |" % o["status"] in md


def test_the_two_status_lines_that_other_tests_pin_are_still_rendered():
    """_progress_line and _sources_line are asserted directly elsewhere; this is the check
    that they still reach the operator."""
    md = _run(_fleet(4)).readable_output
    assert "nothing is pending" in md
    assert "host matches datasets retired" in md
    assert "RE-RUN" in _run(_fleet(4), max_datasets="2").readable_output


def test_a_pipe_in_a_ruleset_name_cannot_shear_the_table():
    row = A._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    quiet = ["simhost%03d" % i for i in range(1, 61)]
    res = _run(_fleet(60, quiet=quiet, rows=1))
    assert len(res.outputs["skipped"]) == 60
    assert res.readable_output.count("`quiet_period`") == A._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.ConsolidateApply.skipped`" \
        in res.readable_output


def test_skips_are_grouped_by_reason_in_the_context():
    res = _run(_fleet(6, quiet=["simhost001"], running=["simhost006"]))
    reasons = [s["reason"] for s in res.outputs["skipped"]]
    assert reasons == sorted(reasons), "skipped is not grouped by reason"


# ------------------------------------------------------ the yml contract is not fiction

def _declared_outputs():
    with open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return [o["contextPath"][len("Yara.ConsolidateApply."):] for o in doc["outputs"]]


def _scenarios():
    """Union across runs rather than one pass: no single run populates written, skipped and
    failed at once, and requiring that would only prove something about a contrived tenant."""
    bad = "yara_scanner_matches_v4_%s" % A._shard_host_of("simhost002")
    unreadable_tgt = _fleet(3)
    unreadable_tgt.names.append(TARGET)
    unreadable_tgt.error_on = ("dataset = %s |" % TARGET,)
    out = [_run(_fleet(4, quiet=["simhost004"], running=["simhost003"])).outputs,
           _run(_fleet(3), execute="true").outputs,
           _run(_fleet(3), row_ceiling="1").outputs,
           _run(unreadable_tgt, execute="true").outputs,
           _run(_converged(4), execute="true", max_datasets="2").outputs]
    t = _fleet(4)
    t.error_on = ("dataset = %s" % bad,)
    out.append(_run(t).outputs)
    return out


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this covers YaraCleanup and YaraReport only, and it flattens a
    contextPath by stripping one prefix, so it cannot express `written.action`. Apply declares
    its object keys, which is the whole point of declaring them, so it needs a check that
    walks into the lists."""
    scenarios = _scenarios()
    missing = []
    for path in _declared_outputs():
        head, _, leaf = path.partition(".")
        if not leaf:
            if not any(head in o for o in scenarios):
                missing.append(path)
            continue
        # a declared object key: the list must be populated in SOME scenario, and every
        # element of it must carry the key - a key present on only some entries is a
        # transformer that matches some of the time, which is worse than one that never does
        seen = False
        for o in scenarios:
            for entry in o.get(head) or []:
                seen = True
                if leaf not in entry:
                    missing.append("%s (absent from a %s entry: %s)"
                                   % (path, head, sorted(entry)))
        if not seen:
            missing.append("%s (no scenario ever populated %s)" % (path, head))
    assert not missing, "declared but not produced:\n  " + "\n  ".join(sorted(set(missing)))


def test_nothing_is_produced_that_the_yml_does_not_declare():
    """The other direction. An undeclared key is invisible in the console's output picker, so
    a playbook author never learns it exists - which is how datasets_remaining, the key the
    code's own comment nominates as the one to branch on, sat there undocumented."""
    declared = set(_declared_outputs())
    for o in _scenarios():
        undeclared = sorted(set(o) - declared)
        assert not undeclared, (
            "produced but never declared in the yml: %s" % undeclared)


def test_the_identifier_lists_a_playbook_splices_are_not_in_this_automation():
    """Guard rail, stated once. ConsolidateStatus publishes eligible_scan_ids /
    pending_scan_ids as plain strings because the playbook copies them into this automation's
    scan_id argument and YaraConsolidateApply does set(only_scan_ids) on them. Nothing here
    may grow a same-named key of objects."""
    o = _run(_fleet(3)).outputs
    assert "eligible_scan_ids" not in o and "pending_scan_ids" not in o


# --------------------------------------------------- the report may not state a false thing
#
# Everything below drives one specific PATH on which the report used to assert something that
# was not true on it. Each is a sentence or a field an operator would have believed.

def _no_rule_hash_fleet(n=1, now=OLD_MS, rows=2):
    """A tenant whose scan_ids carry NO trailing `_yara_<hash>`.

    That is the exact input of the `no_rule_hash` skip, and also the exact input on which
    _host_of_scan_id's anchored tail match fails - so it is the one reason whose records could
    never carry a hostname, however well the rest of the pass knew which host it was talking
    about. The rows still carry the hostname column the scanner writes, which is what the fix
    reads.
    """
    names, scans, newest, rows_by_ds = [], {}, {}, {}
    for i in range(1, n + 1):
        hostname = "nrhost%03d" % i
        seg = A._shard_host_of(hostname)
        m = "yara_scanner_matches_v4_%s" % seg
        sc = "yara_scanner_scans_v4_%s_202609" % seg
        sid = "%s_20260907_04%04d_123456" % (hostname, i)      # no _yara_<hash> tail
        names += [m, sc]
        scans[m] = {sid: rows}
        scans[sc] = {sid: 2}
        newest[m] = newest[sc] = now
        rows_by_ds[m] = [{"tenant_id": "t", "scan_id": sid, "hostname": hostname,
                          "filename": "/tmp/f%d" % j, "file_size": 10 + j,
                          "file_sha256": "%064x" % j, "rules": '[{"rule": "R1"}]',
                          "rule_count": 1, "match_total": 1, "severity": "high",
                          "event_timestamp_ms": now} for j in range(rows)]
        rows_by_ds[sc] = [{"tenant_id": "t", "scan_id": sid, "hostname": hostname,
                           "status": "completed", "event_timestamp_ms": now} for _ in range(2)]
    return RowTenant(names=names, scans=scans, newest=newest, rows_by_ds=rows_by_ds)


def _locked(rows, n=2):
    """A tenant whose consolidation lock marker already exists. `rows` is what the lock row
    read returns: a row means another pass is genuinely running, none means the marker is
    there but unreadable - the add_data create-lag window."""
    t = _fleet(n)
    t.names.append(A._LOCK_DATASET)
    t.lock_rows = list(rows)
    return t


def test_a_no_rule_hash_skip_names_the_host_it_is_about():
    """`hostname` was null on EVERY no_rule_hash record, because it was derived by stripping a
    tail the scan_id does not have. The yml says null means "no single host is implicated",
    and one plainly is - the same record names that host's dataset."""
    res = _run(_no_rule_hash_fleet(2))
    nrh = [s for s in res.outputs["skipped"] if s["reason"] == "no_rule_hash"]
    assert len(nrh) == 2, [s["reason"] for s in res.outputs["skipped"]]
    for s in sorted(nrh, key=lambda r: r["name"]):
        assert s["hostname"], (
            "no_rule_hash record carries hostname=%r while its dataset %s names the host"
            % (s["hostname"], s["dataset"]))
        assert s["scan_id"].startswith(s["hostname"] + "_")
        # and it is the SAME host the dataset resolves to, not a slug or a guess
        assert s["dataset"] == "yara_scanner_matches_v4_%s" % A._shard_host_of(s["hostname"])
    assert {s["hostname"] for s in nrh} == {"nrhost001", "nrhost002"}
    # the readable output carries it too, rather than an empty column
    assert "nrhost001" in res.readable_output


def test_a_scan_level_skip_still_prefers_the_scan_id_derivation():
    """The fallback must not become the rule: a well-formed scan_id is still the source, so a
    row whose hostname column is missing or odd cannot rename a scan that names itself."""
    res = _run(_fleet(3, quiet=["simhost003"]))
    quiet = [s for s in res.outputs["skipped"] if s["reason"] == "quiet_period"][0]
    assert quiet["hostname"] == A._host_of_scan_id(quiet["scan_id"]) == "simhost003"


def test_a_dry_run_that_refused_a_group_does_not_report_a_clean_preview():
    """status is declared as "the single field a playbook should branch on ... it saves testing
    `failed` separately". On the dry-run path it was set once, up front, and never revised - so
    a ceiling REFUSAL, the only failure a dry run can produce and the one an operator has to
    act on, published status="dry_run" and the branch was silently empty. Dry run is also the
    DEFAULT mode, so this was the common case."""
    res = _run(_fleet(3), row_ceiling="1")
    o = res.outputs
    assert o["failed"] and o["failed_count"] == 1
    assert o["status"] == "partial_failure", (
        "a dry run holding %d failure(s) reported status=%r" % (o["failed_count"], o["status"]))
    # the MODE is still readable, and it is dry_run that carries it
    assert o["dry_run"] is True
    md = res.readable_output
    assert md.startswith("### YARA full consolidation - DRY RUN")
    assert "| **Outcome** | `partial_failure` |" in md
    # and the header must not promise that an executing re-run applies exactly this preview,
    # because for the refused group it would refuse identically
    assert "apply exactly this" not in md.split("\n")[1]
    assert "REFUSED" in md.split("\n")[1]


def test_a_clean_dry_run_still_says_dry_run():
    """The other half: partial_failure is driven by `failed`, not by the mode, so a preview
    with nothing wrong keeps the status a playbook already branches on."""
    o = _run(_fleet(3)).outputs
    assert o["failed"] == [] and o["status"] == "dry_run" and o["dry_run"] is True
    assert "apply exactly this" in _run(_fleet(3)).readable_output


def test_an_executed_pass_still_separates_success_from_partial_failure():
    assert _run(_fleet(3), execute="true").outputs["status"] == "success"
    t = _fleet(3)
    t.names.append(TARGET)
    t.error_on = ("dataset = %s |" % TARGET,)
    assert _run(t, execute="true").outputs["status"] == "partial_failure"


def test_a_lock_standdown_still_shows_the_lock_diagnostics():
    """main() collects lock_events and passes them in; the standdown returned before the
    section that renders them. So the ONE report whose whole content is "another run has the
    lock" was also the only one that withheld the lock lines - no age, no message, two lines
    total."""
    res = _run(_locked([{"holder": "another run", "started_ms": NOW_MS}]), execute="true")
    md = res.readable_output
    assert "#### Lock events" in md, "the lock diagnostics never reached the operator:\n%s" % md
    assert "consolidation lock held" in md and "another run appears to be in progress" in md


def test_the_two_lock_standdowns_are_not_the_same_report():
    """acquire_consolidation_lock refuses for two different reasons and returns the same
    False. The report asserted the first of them - "held by another concurrent run" - on both,
    so the add_data create-lag race, which clears itself in about a minute, was indistinguishable
    from a pass that really is running. The operator's next move differs for each."""
    held = _run(_locked([{"holder": "another run", "started_ms": NOW_MS}]), execute="true")
    lag = _run(_locked([]), execute="true")

    for res in (held, lag):
        o = res.outputs
        assert o["lock_held_by_other_run"] is True and o["status"] == "skipped_locked"
        assert o["written"] == [] and o["skipped"] == [] and o["failed"] == []
        assert "STOOD DOWN" in res.readable_output

    assert held.outputs["lock_standdown_reason"] == "held_by_running_pass"
    assert lag.outputs["lock_standdown_reason"] == "marker_unreadable"
    assert held.readable_output != lag.readable_output, (
        "both standdowns still render byte-identically, so a create-lag race and a real "
        "collision cannot be told apart")
    # the create-lag report must not assert contention, which is the false claim itself
    assert "held by another concurrent run" in held.readable_output
    assert "held by another concurrent run" not in lag.readable_output
    assert "create-lag" in lag.readable_output
    # each sentence is the declared one for its code, not prose invented at the call site
    for res in (held, lag):
        assert A.LOCK_STANDDOWN_REASONS[res.outputs["lock_standdown_reason"]] \
            in res.readable_output


def test_the_standdown_reason_is_null_on_every_pass_that_took_the_lock():
    """A sometimes-absent key matches nothing and reports no error, so it is always present -
    and null rather than a code wherever no standdown happened."""
    for res in (_run(_fleet(3)), _run(_fleet(3), execute="true")):
        assert res.outputs["lock_standdown_reason"] is None
    assert set(A.LOCK_STANDDOWN_REASONS) == {"held_by_running_pass", "marker_unreadable"}


# ------------------------------------------------- the shipped consumer declares what it reads

_PLAYBOOK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "xdr", "Packs", "YaraDatasetManagement", "Playbooks",
                         "playbook-YARA_Dataset_Consolidation.yml")


def test_the_playbook_no_longer_publishes_apply_outputs():
    """playbook-YARA_Dataset_Consolidation.yml was rebuilt to call only YaraConsolidateSummary
    - the full-detail path (this automation) is invoked directly elsewhere, not from this
    playbook. Its outputs block used to document Yara.ConsolidateApply.* alongside
    Yara.ConsolidateSummary.*; leaving stale Apply entries there would tell a content author
    reading the playbook to expect data a task in it never produces. This pins the absence so
    a copy-paste doesn't quietly bring them back.
    """
    with open(_PLAYBOOK, encoding="utf-8") as fh:
        pb = yaml.safe_load(fh)
    published = {o["contextPath"] for o in pb["outputs"]}
    apply_paths = {p for p in published if p.startswith("Yara.ConsolidateApply.")}
    assert not apply_paths, (
        "the playbook still publishes Apply outputs it can no longer produce: %s"
        % sorted(apply_paths))
    scripts = {t["task"]["script"] for t in pb["tasks"].values()
              if (t["task"].get("script") or "").startswith("Yara")}
    assert "YaraConsolidateApply" not in scripts, (
        "the playbook calls YaraConsolidateApply again - its outputs should be documented "
        "in the playbook's outputs block once more")


def _dry_result(failed):
    """The result dict shape render_run_markdown is contracted to, with `failed` injected.

    Rendered directly rather than through a tenant because the point is a claim the renderer
    makes about a combination the gate cannot produce TODAY - a dry run failing for something
    other than the ceiling. The sentence must stay true if it ever can.
    """
    return {"status": "partial_failure", "dry_run": True, "written": [], "skipped": [],
            "failed": list(failed), "targets_written": 0, "skipped_count": 0,
            "failed_count": len(failed), "rows_written": 0, "hosts": 0, "groups": 1,
            "lock_held_by_other_run": False, "lock_standdown_reason": None,
            "sources_retired": 0, "datasets_total": 1, "datasets_taken": 1,
            "datasets_remaining": 0, "rows_planned": 0}


def test_the_preview_header_only_promises_a_refusal_it_can_prove():
    """"An `execute=true` re-run refuses them again" is true of row_ceiling_exceeded and of
    nothing else, so it is decided by the reason code rather than by "this was a dry run, so
    it must have been the ceiling"."""
    ceiling = A.render_run_markdown(_dry_result(
        [A._failed_record("row_ceiling_exceeded", "too big", ruleset=RULES, target=TARGET,
                          rows=9, row_ceiling=1)]))
    assert "REFUSED outright" in ceiling and "refuses them again" in ceiling
    assert "apply exactly this" not in ceiling

    other = A.render_run_markdown(_dry_result(
        [A._failed_record("write_error", "boom", ruleset=RULES, target=TARGET, rows=9)]))
    assert "refuses them again" not in other, (
        "the header promises a repeat refusal for a failure that is retryable")
    assert "did not complete" in other and "apply exactly this" not in other


def test_a_standdown_with_no_recorded_reason_claims_neither():
    """The defensive default. A standdown this code cannot explain - an older result dict, a
    refusal path that logged nothing - must not be reported as one it can."""
    md = A.render_run_markdown({"lock_held_by_other_run": True, "status": "skipped_locked",
                                "lock_standdown_reason": None, "dry_run": False,
                                "written": [], "skipped": [], "failed": []})
    assert "STOOD DOWN" in md and "the consolidation lock could not be taken" in md
    for claim in A.LOCK_STANDDOWN_REASONS.values():
        assert claim not in md
