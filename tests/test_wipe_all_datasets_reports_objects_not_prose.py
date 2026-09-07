#!/usr/bin/env python3
"""The wipe's result lists are CONTEXT, so they carry fields rather than sentences.

This automation deletes every yara_scanner_* dataset on the tenant. What it reports is the
only record of what it did, and three things were wrong with that record:

  * `failed` was a bare list of names. The REASON a delete failed was formatted into a log
    line that main() collected and never read again - so it reached neither the context nor
    the readable output, even though the yml promised it was in the readable output. An
    operator holding a list of names had nothing to act on and no way to tell an expired API
    key from a throttled tenant.

  * `lock_taken_over` - "this wipe overrode another run's lock and may have deleted that
    run's source datasets underneath it", the single most consequential fact this script can
    report - was produced but NOT DECLARED in the yml, so no playbook could branch on it,
    and its explanation was a prose sentence carrying three facts at once.

  * There was no way to tell "not attempted" from "deleted" when a capped or partly-failed
    pass ended early. `to_delete` said 8 and `deleted` said 3, and which five datasets were
    still on the tenant was not recoverable from anything published. `not_attempted` closes
    that: to_delete partitions exactly into deleted + failed + not_attempted, always.

So the two lists that carry a per-entry reason are objects now, with `reason` drawn from a
CLOSED vocabulary and the sentence surviving as `detail`. These tests pin the shapes, pin
that the vocabularies stay closed and match the yml, and pin the partition.

Two properties are pinned here that are not obvious:

  * `to_delete`, `deleted` and `not_attempted` must stay lists of PLAIN STRINGS. They are
    identifiers, which is data rather than prose; wrapping them buys nothing and breaks
    every caller that splices the list. The inverse of the reference suite's rule, and it
    needs a test for exactly the same reason: nothing else would notice the drift.

  * The readable output is rendered from the result dict ALONE. The old builder formatted
    three of its numbers out of main() locals that were published nowhere - the pass count,
    the remainder, the preserved count - so the War Room could state a figure a playbook
    could not read anywhere. It also built its lists with `["  " + n for n in ...]`, which
    raises TypeError the moment one of those lists holds an object.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import yaml  # noqa: E402

from test_pack_data_management import _run_automation  # noqa: E402
from test_wipe_all_datasets import (  # noqa: E402
    W, FakeTenant, FULL_TENANT, AT_REST_TENANT, _YML,
)

# Relative to the real clock, deliberately: wipe_all stamps now_ms from time.time() when
# main() calls it, so a lock row pinned to a fixed epoch is either absurdly stale or in the
# future depending on the day the suite runs.
NOW_MS = int(time.time() * 1000)
STALE_MS = NOW_MS - (W.DEFAULT_LOCK_STALE_SECS + 3600) * 1000

CONFIRM = {"execute": "true", "confirm": W.CONFIRM_PHRASE}


class FailingTenant(FakeTenant):
    """A tenant whose delete_dataset raises for named datasets, with a chosen error text.

    The lock dataset is never made to fail: releasing the lock is not the behaviour under
    test here, and a failure there is swallowed by release_consolidation_lock anyway."""

    def __init__(self, names=(), fail_on=(), error="/v2/xql/delete_dataset/ HTTP 500: boom"):
        FakeTenant.__init__(self, names)
        self.fail_on = dict(fail_on) if isinstance(fail_on, dict) else {n: error for n in fail_on}

    def delete_dataset(self, dataset_name, force=False):
        if dataset_name in self.fail_on and dataset_name != W._LOCK_DATASET:
            self.calls.append("delete_dataset_FAILED:%s" % dataset_name)
            raise RuntimeError(self.fail_on[dataset_name])
        return FakeTenant.delete_dataset(self, dataset_name, force=force)


def _big_tenant(n=60):
    """More candidates than _MD_ROW_CAP, so truncation is exercised."""
    return ["yara_scanner_matches_v4_host%03d_abc123" % i for i in range(n)] + [
        "yara_scanner_consolidation_runs", "yara_scanner_cleanup_runs"]


def _run(client, **args):
    """main() end to end, so the readable output and the context come from one pass."""
    return _run_automation(W, dict(args), client, pin_schema=False)


# ------------------------------------------------------------------ the lists

def test_every_entry_in_the_object_lists_is_an_object():
    """The whole point. One string among the objects is the silent failure mode."""
    res = _run(FailingTenant(AT_REST_TENANT, fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
               **CONFIRM)
    for key in ("failed", "preserved"):
        for entry in res.outputs[key]:
            assert isinstance(entry, dict), (
                "%s holds a bare %s - a playbook filtering on a field would silently match "
                "nothing: %r" % (key, type(entry).__name__, entry))


def test_the_identifier_lists_stay_plain_dataset_names():
    """The inverse rule, and it matters just as much. to_delete / deleted / not_attempted
    carry one identifier per element and nothing else, so they stay strings: a caller that
    splices one of them into another automation's argument, or does set() over it, breaks
    the instant an element becomes a dict."""
    res = _run(FailingTenant(AT_REST_TENANT, fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
               max_deletes="4", **CONFIRM)
    for key in ("to_delete", "deleted", "not_attempted"):
        assert res.outputs[key], "%s was empty - the assertion below would prove nothing" % key
        for entry in res.outputs[key]:
            assert isinstance(entry, str), "%s holds a %r" % (key, entry)


def test_a_failed_entry_carries_the_dataset_the_reason_and_the_error():
    """Exactly the three fields, on every entry, always present. Before this the reason went
    to a log sink nothing read and the record was a bare name."""
    bad = "yara_scanner_matches_v4_hostA_abc123"
    res = _run(FailingTenant(AT_REST_TENANT, fail_on={bad: "delete HTTP 401: expired"}),
               **CONFIRM)
    failed = res.outputs["failed"]
    assert len(failed) == 1, failed
    assert set(failed[0]) == {"dataset", "reason", "detail"}, (
        "failed record shape drifted: %s" % sorted(failed[0]))
    assert failed[0]["dataset"] == bad
    assert failed[0]["reason"] == "auth_error"
    assert "expired" in failed[0]["detail"]
    # and the failure is visible in the verdict, not only in the list
    assert res.outputs["status"] == "partial_failure"
    assert res.outputs["failed_count"] == 1


def test_a_preserved_entry_says_why_it_was_never_a_candidate():
    """The WHY used to live only in a source comment and one sentence of the report."""
    res = _run(FakeTenant(FULL_TENANT))
    preserved = {p["dataset"]: p for p in res.outputs["preserved"]}
    assert preserved, "FULL_TENANT holds three preserved datasets"
    for p in preserved.values():
        assert set(p) == {"dataset", "reason", "detail"}, (
            "preserved record shape drifted: %s" % sorted(p))
        assert p["reason"] and p["detail"]
    assert preserved["yara_scanner_consolidation_lock"]["reason"] == "consolidation_lock"
    assert preserved["yara_scanner_cleanup_runs"]["reason"] == "run_log"
    # detail is per-name, not the vocabulary sentence restated on every row
    assert (preserved["yara_scanner_cleanup_runs"]["detail"]
            != preserved["yara_scanner_consolidation_runs"]["detail"])


def test_the_lock_takeover_is_fields_rather_than_a_sentence():
    """lock_takeover_reason was one prose string carrying three facts: which condition
    fired, how old the marker was, and the wording. A playbook could only substring-match
    it, and the yml declared neither it nor the boolean beside it."""
    client = FakeTenant(FULL_TENANT)
    client.lock_rows = [{"holder": "crashed-run", "started_ms": STALE_MS}]
    res = _run(client, **CONFIRM)
    o = res.outputs
    assert o["lock_taken_over"] is True
    assert set(o["lock_takeover"]) == {"reason", "age_secs", "detail"}
    assert o["lock_takeover"]["reason"] == "lock_stale"
    assert o["lock_takeover"]["age_secs"] > W.DEFAULT_LOCK_STALE_SECS
    assert "taking over" in o["lock_takeover"]["detail"]
    assert "lock_takeover_reason" not in o, "the prose key outlived its replacement"


def test_the_lock_takeover_object_is_present_even_when_no_lock_was_stolen():
    """A key that only sometimes exists is a filter that silently matches nothing. The
    uncontended case carries the same three keys, emptied."""
    o = _run(FakeTenant(AT_REST_TENANT), **CONFIRM).outputs
    assert o["lock_taken_over"] is False
    assert o["lock_takeover"] == {"reason": "", "age_secs": None, "detail": ""}


# ------------------------------------------------------- the vocabularies stay closed

@pytest.mark.parametrize("error,expected", [
    ("/v2/xql/delete_dataset/ HTTP 401: {}", "auth_error"),
    ("/v2/xql/delete_dataset/ HTTP 403: {}", "auth_error"),
    ("/v2/xql/delete_dataset/ HTTP 429: {}", "rate_limited"),
    ("/v2/xql/delete_dataset/ HTTP 500: {}", "server_error"),
    ("/v2/xql/delete_dataset/ HTTP 400: {}", "http_error"),
    ("HTTPSConnectionPool: Read timed out", "timeout"),
    ("Max retries exceeded: connection refused", "network_error"),
    ("something nobody predicted", "unknown"),
])
def test_every_delete_failure_classifies_into_the_closed_vocabulary(error, expected):
    reason = W._delete_failure_reason(RuntimeError(error))
    assert reason == expected
    assert reason in W.FAIL_REASONS


def test_no_reason_a_run_emits_is_outside_its_declared_vocabulary():
    """A code invented at a call site and never declared is exactly as unmatchable as the
    prose it replaced - it just looks like a contract."""
    scenarios = [
        _run(FailingTenant(AT_REST_TENANT,
                           fail_on={"yara_scanner_matches_v4_hostA_abc123": "HTTP 500: x",
                                    "yara_scanner_matches_v2_hostB_def456": "boom"}),
             **CONFIRM),
        _run(FakeTenant(FULL_TENANT)),
    ]
    for res in scenarios:
        for f in res.outputs["failed"]:
            assert f["reason"] in W.FAIL_REASONS, "undeclared failure reason %r" % f["reason"]
        for p in res.outputs["preserved"]:
            assert p["reason"] in W.PRESERVED_REASONS, "undeclared reason %r" % p["reason"]
        code = res.outputs["lock_takeover"]["reason"]
        assert code == "" or code in W.TAKEOVER_REASONS, "undeclared reason %r" % code
        assert res.outputs["status"] in ("dry_run", "skipped_locked", "executed",
                                         "partial_failure")


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    described = {o["contextPath"]: o["description"] for o in _yml()["outputs"]}
    for code in W.FAIL_REASONS:
        assert code in described["Yara.WipeAll.failed.reason"], (
            "failure reason %r is not in the yml's declared closed set" % code)
    for code in W.PRESERVED_REASONS:
        assert code in described["Yara.WipeAll.preserved.reason"], (
            "preserved reason %r is not in the yml's declared closed set" % code)
    for code in W.TAKEOVER_REASONS:
        assert code in described["Yara.WipeAll.lock_takeover.reason"], (
            "takeover reason %r is not in the yml's declared closed set" % code)
    for code in ("dry_run", "skipped_locked", "executed", "partial_failure"):
        assert code in described["Yara.WipeAll.status"], (
            "status %r is not in the yml's declared closed set" % code)


# ------------------------------------------------- the outcome lists partition the candidates

def _assert_partition(o):
    names = set(o["deleted"]) | {f["dataset"] for f in o["failed"]} | set(o["not_attempted"])
    assert names == set(o["to_delete"]), (
        "to_delete is not deleted + failed + not_attempted - a dataset is unaccounted for")
    assert (o["deleted_count"] + o["failed_count"] + o["not_attempted_count"]
            == o["to_delete_count"])


def test_the_three_outcome_lists_partition_the_candidate_set_in_every_mode():
    """The defect this closes: on a capped or partly-failed pass, to_delete said 8 and
    deleted said 3, and nothing published said which five were still there."""
    _assert_partition(_run(FakeTenant(FULL_TENANT)).outputs)                     # dry run
    _assert_partition(_run(FakeTenant(AT_REST_TENANT), **CONFIRM).outputs)       # executed
    _assert_partition(_run(FakeTenant(AT_REST_TENANT), max_deletes="3",
                           **CONFIRM).outputs)                                   # capped
    _assert_partition(_run(FailingTenant(
        AT_REST_TENANT, fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
        max_deletes="4", **CONFIRM).outputs)                                     # capped+failed
    locked = FakeTenant(FULL_TENANT)
    locked.lock_rows = [{"holder": "another-run", "started_ms": NOW_MS}]
    _assert_partition(_run(locked, **CONFIRM).outputs)                           # standdown


def test_a_capped_pass_names_what_it_did_not_attempt():
    o = _run(FakeTenant(AT_REST_TENANT), max_deletes="3", **CONFIRM).outputs
    assert o["stopped_early"] is True
    assert o["deleted_count"] == 3 and o["not_attempted_count"] == 5
    assert set(o["not_attempted"]) == set(o["to_delete"]) - set(o["deleted"])
    assert o["max_deletes"] == 3 and o["passes_expected"] == 3


def test_a_failed_delete_is_reported_as_still_there_and_not_as_deleted():
    bad = "yara_scanner_matches_v4_hostA_abc123"
    res = _run(FailingTenant(AT_REST_TENANT, fail_on=[bad]), **CONFIRM)
    o = res.outputs
    assert bad not in o["deleted"] and bad not in o["not_attempted"]
    assert [f["dataset"] for f in o["failed"]] == [bad]
    assert o["status"] == "partial_failure"


def test_a_standdown_reports_every_candidate_as_untouched():
    """Nothing was attempted, so the whole candidate set is owed to a later run - and the
    status says which of the two no-op modes this was."""
    client = FakeTenant(FULL_TENANT)
    client.lock_rows = [{"holder": "another-run", "started_ms": NOW_MS}]
    o = _run(client, **CONFIRM).outputs
    assert o["status"] == "skipped_locked" and o["lock_held_by_other_run"] is True
    assert o["deleted"] == [] and o["failed"] == []
    assert o["not_attempted"] == o["to_delete"]


def test_status_is_derived_once_and_the_audit_row_carries_the_same_value():
    """The run log and the context answering the same question differently is the failure
    this collapses: mode IS status now."""
    for client, args, expected in (
            (FakeTenant(FULL_TENANT), {}, "dry_run"),
            (FakeTenant(AT_REST_TENANT), CONFIRM, "executed"),
            (FailingTenant(AT_REST_TENANT, fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
             CONFIRM, "partial_failure")):
        res = _run(client, **args)
        assert res.outputs["status"] == expected
        assert client.wipe_run_rows[-1]["mode"] == expected


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    md = _run(FakeTenant(FULL_TENANT)).readable_output
    assert md.startswith("### YARA dataset wipe - DRY RUN")
    assert "\n|---|---|\n" in md, "no markdown table in the output"
    for heading in ("#### Would delete", "#### Preserved - never touched",
                    "#### Settings this run used"):
        assert heading in md, "missing section: %s" % heading
    # the prose the tables replaced
    assert "would delete:" not in md
    assert "preserved (never touched):" not in md


def test_the_readable_output_never_prints_a_raw_record():
    """The concat this replaced - `["  " + n for n in items]` - raises TypeError on a dict.
    Its lazier cousin, a `%s`-formatted append, would print `{'dataset': ...}` into the War
    Room instead, which is worse because it is silent."""
    md = _run(FailingTenant(AT_REST_TENANT,
                            fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
              **CONFIRM).readable_output
    assert "{'dataset'" not in md and '{"dataset"' not in md
    assert "#### Failed - still on the tenant" in md
    assert "`auth_error`" in md or "`server_error`" in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never
    reach the War Room from an expression the context did not also see - which is exactly
    what the old pass-count, remainder and preserved-count lines did."""
    res = _run(FakeTenant(AT_REST_TENANT), max_deletes="3", **CONFIRM)
    o, md = res.outputs, res.readable_output
    assert "| **Status** | `%s` |" % o["status"] in md
    assert "| **Deleted** | %d |" % o["deleted_count"] in md
    assert "%d of %d yara_scanner_* dataset(s)" % (o["to_delete_count"], o["total_found"]) in md
    # what "remains" is everything the pass left on the tenant - not_attempted AND failed.
    # This pass failed nothing, so the two definitions coincide here; the test below is the
    # one that separates them.
    assert "%d remain" % (o["not_attempted_count"] + o["failed_count"]) in md
    assert "bounded to %d of %d" % (o["max_deletes"], o["to_delete_count"]) in md


def test_a_capped_pass_that_also_failed_states_everything_still_on_the_tenant():
    """The remainder sentence must count the FAILED deletes too.

    This is the only scenario where "what is left" has two different definitions, and every
    other test of the bounded-pass sentence uses a zero-failure tenant, where they coincide.
    With failures they do not: the sentence formatted not_attempted alone, so a pass that
    both capped and failed said "4 remain" directly underneath a table whose own rows read
    "Failed | 1 - still on the tenant" and "Not attempted | 4 - still on the tenant" - and
    then told the operator to re-run "to continue draining the rest", which is 5 datasets,
    not 4. The report and the table it sits under cannot be allowed to disagree."""
    bad = "yara_scanner_matches_v4_hostA_abc123"
    res = _run(FailingTenant(AT_REST_TENANT,
                             fail_on={bad: "/v2/xql/delete_dataset/ HTTP 429: throttled"}),
               max_deletes="4", **CONFIRM)
    o, md = res.outputs, res.readable_output
    assert o["stopped_early"] is True and o["status"] == "partial_failure"
    assert (o["deleted_count"], o["failed_count"], o["not_attempted_count"]) == (3, 1, 4)

    still_there = o["failed_count"] + o["not_attempted_count"]
    assert "| **Failed** | %d - still on the tenant |" % o["failed_count"] in md
    assert ("| **Not attempted** | %d - still on the tenant, owed a further pass |"
            % o["not_attempted_count"]) in md
    assert "bounded to %d of %d candidate(s) - %d remain" % (
        o["max_deletes"], o["to_delete_count"], still_there) in md
    assert "%d never attempted, %d failed" % (
        o["not_attempted_count"], o["failed_count"]) in md
    assert "- %d remain" % o["not_attempted_count"] not in md, (
        "the sentence is back to counting only not_attempted, which undercounts what is "
        "still on the tenant by every failed delete")


def test_a_capped_pass_whose_every_attempt_failed_says_nothing_was_drained():
    """The extreme of the same path: the cap allowed 4, all 4 raised, so the pass deleted
    nothing at all and the whole candidate set is still there. The old sentence reported the
    4 never attempted, i.e. half of what a re-run has to get through."""
    attempted = sorted(n for n in AT_REST_TENANT
                       if n.startswith("yara_scanner") and n not in W.PRESERVED_DATASETS)[:4]
    res = _run(FailingTenant(AT_REST_TENANT,
                             fail_on={n: "/v2/xql/delete_dataset/ HTTP 500: boom"
                                      for n in attempted}),
               max_deletes="4", **CONFIRM)
    o, md = res.outputs, res.readable_output
    assert o["deleted_count"] == 0 and o["failed_count"] == 4
    assert "bounded to 4 of %d candidate(s) - %d remain" % (
        o["to_delete_count"], o["to_delete_count"]) in md
    assert "4 never attempted, 4 failed" in md


def test_neither_standdown_is_reported_as_a_fact_the_pass_never_established():
    """acquire_consolidation_lock refuses for TWO reasons and returns the same False for both.

    The report asserted the first of them on both paths - "the consolidation lock is held by
    another concurrent run", in the subtitle and again as "HELD by another run" in the facts
    table. On the second path (a marker whose row could not be read, which this automation
    treats as held BECAUSE it cannot tell) nothing established that any run holds it: that is
    the ordinary add_data create-lag window, and it is equally the signature of an orphaned
    marker left by a run that died. An operator told to wait for a concurrent pass waits for
    one that may not exist. Nothing in the result dict distinguishes the two, so the one thing
    the report may not do is pick one.

    YaraConsolidateApply publishes lock_standdown_reason for this and renders the two
    differently; this automation does not carry that key, so the sentence must cover both."""
    held = FakeTenant(FULL_TENANT)
    held.lock_rows = [{"holder": "another-run", "started_ms": NOW_MS}]
    unreadable = FakeTenant(FULL_TENANT)      # the lock dataset exists; its row does not
    unreadable.lock_rows = []

    for client in (held, unreadable):
        res = _run(client, **CONFIRM)
        o, md = res.outputs, res.readable_output
        assert o["status"] == "skipped_locked" and o["lock_held_by_other_run"] is True
        assert md.startswith("### YARA dataset wipe - STOOD DOWN")
        assert "could not be taken" in md, (
            "the report states a cause the pass never established:\n%s" % md.split("\n")[1])
        assert "could not be read" in md, "only one of the two refusals is named"
        assert "another run holds it" in md, "only one of the two refusals is named"
        assert "| **Lock** | NOT TAKEN - held by another run, or its marker could not be " \
               "read; this pass stood down and deleted nothing |" in md
        assert "HELD by another run - this pass stood down" not in md


def test_the_takeover_warning_is_impossible_to_miss():
    """The one fact that means a consolidation pass may have had its sources deleted from
    under it. It is a declared boolean now, and it leads the report."""
    client = FakeTenant(FULL_TENANT)
    client.lock_rows = [{"holder": "crashed-run", "started_ms": STALE_MS}]
    md = _run(client, **CONFIRM).readable_output
    assert "> **WARNING - this wipe took another run's consolidation lock over.**" in md
    assert "| **Lock** | TAKEN OVER" in md


def test_a_pipe_in_a_dataset_name_cannot_shear_the_table():
    """Dataset names reach the report from the tenant's own listing. One unescaped pipe and
    every row below it loses a column - silently, since markdown does not error."""
    row = W._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    """A 60-dataset wipe must not push the counts off the top of the War Room - and must
    not lose a name to do it."""
    res = _run(FakeTenant(_big_tenant(60)))
    assert len(res.outputs["to_delete"]) == 60
    assert res.readable_output.count("yara_scanner_matches_v4_host") == W._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.WipeAll.to_delete`" in res.readable_output


def test_the_dry_run_still_warns_that_one_execute_pass_is_not_enough():
    """Rendered from passes_expected and max_deletes, both published now - the old report
    computed both from main() locals that reached no context key at all."""
    res = _run(FakeTenant(_big_tenant(60)), max_deletes="25")
    assert res.outputs["passes_expected"] == 3
    assert "expect 3 execute run(s)" in res.readable_output
    assert "max_deletes=25" in res.readable_output


# ------------------------------------------------------ the yml contract is not fiction

def _yml():
    with open(_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _declared_outputs():
    return [o["contextPath"][len("Yara.WipeAll."):] for o in _yml()["outputs"]]


def _scenarios():
    """No single pass populates every list, and demanding one would only prove something
    about a contrived tenant. The union is the contract."""
    out = [_run(FakeTenant(FULL_TENANT)).outputs,
           _run(FakeTenant(AT_REST_TENANT), **CONFIRM).outputs,
           _run(FakeTenant(AT_REST_TENANT), max_deletes="3", **CONFIRM).outputs,
           _run(FailingTenant(AT_REST_TENANT,
                              fail_on=["yara_scanner_matches_v4_hostA_abc123"]),
                **CONFIRM).outputs]
    stolen = FakeTenant(FULL_TENANT)
    stolen.lock_rows = [{"holder": "crashed-run", "started_ms": STALE_MS}]
    out.append(_run(stolen, **CONFIRM).outputs)
    locked = FakeTenant(FULL_TENANT)
    locked.lock_rows = [{"holder": "another-run", "started_ms": NOW_MS}]
    out.append(_run(locked, **CONFIRM).outputs)
    return out


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this covers YaraCleanup and YaraReport only, and it flattens
    a contextPath by stripping one prefix, so it cannot express `failed.reason`. This
    automation declares its object keys, which is the whole point of declaring them, so it
    needs a check that walks into the lists and into lock_takeover."""
    scenarios = _scenarios()
    missing = []
    for path in _declared_outputs():
        head, _, leaf = path.partition(".")
        if not leaf:
            if not any(head in o for o in scenarios):
                missing.append(path)
            continue
        seen = False
        for o in scenarios:
            value = o.get(head)
            if isinstance(value, dict):        # lock_takeover: one object, not a list
                seen = True
                if leaf not in value:
                    missing.append("%s (absent from %s: %s)" % (path, head, sorted(value)))
                continue
            for entry in value or []:
                seen = True
                # a key present on only SOME entries is a transformer that matches some of
                # the time, which is worse than one that never matches
                if leaf not in entry:
                    missing.append("%s (absent from a %s entry: %s)"
                                   % (path, head, sorted(entry)))
        if not seen:
            missing.append("%s (no scenario ever populated %s)" % (path, head))
    assert not missing, "declared but not produced:\n  " + "\n  ".join(sorted(set(missing)))


def test_nothing_is_produced_that_the_yml_does_not_declare():
    """The other direction, and the one that actually bit: lock_taken_over and
    lock_takeover_reason were produced and undeclared, so a playbook author could not see
    the most consequential flag this automation has in the console's output picker."""
    declared = set(_declared_outputs())
    for o in _scenarios():
        undeclared = sorted(set(o) - declared)
        assert not undeclared, "produced but never declared in the yml: %s" % undeclared


def test_the_declared_object_keys_cover_every_field_the_records_carry():
    """Both directions again, one level down: a record field nobody declared is invisible,
    and a declared field nobody sets is a lie."""
    declared = set(_declared_outputs())
    for o in _scenarios():
        for head in ("failed", "preserved"):
            for entry in o.get(head) or []:
                for key in entry:
                    assert "%s.%s" % (head, key) in declared, (
                        "%s.%s is produced but not declared" % (head, key))
        for key in o["lock_takeover"]:
            assert "lock_takeover.%s" % key in declared
