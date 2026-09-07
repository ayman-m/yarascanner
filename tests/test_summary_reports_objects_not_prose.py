#!/usr/bin/env python3
"""Summary's three result lists are CONTEXT, so they carry fields rather than sentences.

`written`, `skipped` and `failed` used to be lists of preformatted strings. A playbook that
wanted to act on one of them - branch on why a scan was skipped, count the rows a pass would
write, tell a still-running scan from an unreadable source - had no option but to substring
match on prose that was written for a human. That is a contract nobody can change safely and
nobody can rely on: reword one message for clarity and every filter downstream silently stops
matching, with no error anywhere.

So each entry is an object now, and `reason` is a CLOSED vocabulary. These tests pin both -
the shapes, and the fact that the vocabularies are closed - because the value of a closed set
is entirely in it staying closed.

Two more properties are pinned here for reasons that are not obvious:

  * NOTHING in the three lists may be a string. The old readable-output builder did
    `out += ["  " + s for s in items]`, which raises TypeError the moment an element is a
    dict. That line is gone, but the inverse hazard now exists - a new `%s`-formatted append
    slipped in beside the structured ones would sail through the renderer and land in context
    as a lone string among objects, which is worse than a crash because it is silent.

  * The collapse ratio's two sides must cover the SAME population. `findings_collapsed` is
    summed over every scan the pass READ; if the denominator were `rows_written` - only what
    survived the gate - the ratio would move with how many scans happened to be mid-flight,
    which has nothing to do with how much detail collapsed.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateSummary as S, FakeTenant, _run_automation,
)

RULES = "1aca83d286ad"
# Relative to the real clock, deliberately. main() stamps now_ms from time.time(), and the
# gate compares against it - so a fixture pinned to a fixed epoch puts every scan in the
# future, fails both the quiet and the aged test, and reports the whole fleet as still
# running. Which is exactly what a first draft of this file did.
NOW_MS = int(time.time() * 1000)
OLD_MS = NOW_MS - 40 * 3600 * 1000


def _fleet(n=4, quiet=(), rules=RULES, now=OLD_MS):
    """A tenant of `n` hosts, with the hosts in `quiet` stamped recently enough to be held
    back by the quiet window. Dataset names go through the REAL _shard_host_of derivation, so
    the `dataset` field on a skipped record has something true to resolve to."""
    names, scans, newest = [], {}, {}
    for i in range(1, n + 1):
        hostname = "simhost%03d" % i
        seg = S._shard_host_of(hostname)
        m = "yara_scanner_matches_v4_%s" % seg
        sc = "yara_scanner_scans_v4_%s_202609" % seg
        sid = "%s_20260907_04%04d_123456_yara_%s" % (hostname, i, rules)
        names += [m, sc]
        scans[m] = {sid: 700 + i}
        scans[sc] = {sid: 2}
        newest[m] = newest[sc] = (NOW_MS if hostname in quiet else now)
    return FakeTenant(names=names, scans=scans, newest=newest)


def _run(t, **args):
    a = {"schema_version": "4", "retention_hours": "24", "quiet_secs": "900"}
    a.update(args)
    return _run_automation(S, a, t, pin_schema=False)


# ------------------------------------------------------------------ the three lists

def test_every_entry_in_the_three_lists_is_an_object():
    """The whole point. One string among the objects is the silent failure mode."""
    res = _run(_fleet(6, quiet=["simhost005", "simhost006"]))
    for key in ("written", "skipped", "failed"):
        for entry in res.outputs[key]:
            assert isinstance(entry, dict), (
                "%s holds a bare %s - a playbook filtering on a field would silently match "
                "nothing: %r" % (key, type(entry).__name__, entry))


def test_a_skipped_entry_names_the_dataset_and_the_reason():
    """Exactly the two fields an operator asked for, on every entry, always present."""
    res = _run(_fleet(4, quiet=["simhost004"]))
    skipped = res.outputs["skipped"]
    assert skipped, "the quiet host should have been skipped"
    for s in skipped:
        assert set(s) == {"name", "reason", "detail", "scan_id", "hostname", "dataset",
                          "ruleset"}, "skipped record shape drifted: %s" % sorted(s)
        assert s["reason"] and s["detail"]
    quiet = [s for s in skipped if s["reason"] == "quiet_period"]
    assert len(quiet) == 1, [s["reason"] for s in skipped]
    # The dataset is derived from the hostname inside the scan_id and checked against the
    # listing already in hand - so it is the real name, not a guess, and costs no query.
    assert quiet[0]["dataset"] == "yara_scanner_matches_v4_%s" % S._shard_host_of("simhost004")
    assert quiet[0]["hostname"] == "simhost004"
    assert quiet[0]["scan_id"].startswith("simhost004_")


def test_a_written_entry_says_whether_it_actually_wrote():
    """`action` is the field to branch on. A dry run must never look like a write."""
    dry = _run(_fleet(3))
    assert [w["action"] for w in dry.outputs["written"]] == ["would_write"]
    assert dry.outputs["status"] == "dry_run" and dry.outputs["dry_run"] is True
    # scans_refreshed is NULL rather than 0 in a preview: the target is never read, so how
    # many of these scans it already holds is unknown, and 0 would be a claim.
    assert dry.outputs["written"][0]["scans_refreshed"] is None

    wrote = _run(_fleet(3), execute="true")
    assert [w["action"] for w in wrote.outputs["written"]] == ["wrote"]
    assert wrote.outputs["status"] == "success"
    assert wrote.outputs["written"][0]["scans_refreshed"] == 0     # nothing held it yet


def test_a_written_entry_carries_the_numbers_not_a_sentence():
    res = _run(_fleet(5))
    w = res.outputs["written"][0]
    assert set(w) == {"action", "ruleset", "target", "rows", "hosts", "scans",
                      "scans_refreshed", "stale_rows_removed", "estimated_kb",
                      "eligibility"}, "written record shape drifted: %s" % sorted(w)
    assert w["ruleset"] == RULES
    assert w["target"] == "yara_scanner_summary_v4_rules_%s" % RULES
    assert w["hosts"] == 5 and w["scans"] == 5
    assert isinstance(w["rows"], int) and isinstance(w["estimated_kb"], float)


# ------------------------------------------------------- the vocabularies stay closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason code invented at a call site and never declared is exactly as unmatchable as
    the prose this replaced - it just looks like a contract."""
    for t, kw in ((_fleet(4, quiet=["simhost004"]), {}),
                  (_fleet(4, quiet=["simhost004"]), {"execute": "true"}),
                  (_fleet(3), {"max_datasets": "1"})):
        res = _run(t, **kw)
        for s in res.outputs["skipped"]:
            assert s["reason"] in S.SKIP_REASONS, (
                "undeclared skip reason %r - add it to SKIP_REASONS or use an existing one"
                % s["reason"])
        for f in res.outputs["failed"]:
            assert f["reason"] in S.FAIL_REASONS, "undeclared failure reason %r" % f["reason"]


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    import yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                        "YaraConsolidateSummary", "YaraConsolidateSummary.yml")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    described = {o["contextPath"]: o["description"] for o in doc["outputs"]}
    for code in S.SKIP_REASONS:
        assert code in described["Yara.ConsolidateSummary.skipped.reason"], (
            "skip reason %r is not in the yml's declared closed set" % code)
    for code in S.FAIL_REASONS:
        assert code in described["Yara.ConsolidateSummary.failed.reason"], (
            "failure reason %r is not in the yml's declared closed set" % code)


def test_a_failure_record_asserts_the_sources_were_not_touched():
    """The claim the troubleshooting docs make, carried on the record itself rather than left
    to prose an operator has to trust."""
    t = _fleet(3)
    t.error_on = ("| comp count() as n by scan_id",)     # target read-back fails
    t.names.append("yara_scanner_summary_v4_rules_%s" % RULES)
    res = _run(t, execute="true")
    assert res.outputs["failed"], "the unreadable target should have failed the ruleset"
    for f in res.outputs["failed"]:
        assert set(f) == {"reason", "detail", "ruleset", "target", "sources_untouched"}
        assert f["sources_untouched"] is True
    assert res.outputs["status"] == "partial_failure"


# ------------------------------------------------------------- the numbers hold up

def test_the_collapse_ratio_divides_two_figures_over_the_same_population():
    """findings_collapsed means nothing on its own - that was the complaint. Its denominator
    has to cover the same scans it does, INCLUDING the ones the gate held back, or the ratio
    reports the gate rather than the collapse."""
    res = _run(_fleet(6, quiet=["simhost005", "simhost006"]))
    o = res.outputs
    assert o["skipped_count"] == 2 and o["rows_written"] == 4
    # 6 scans read, one (host, rule) pair each -> the denominator is 6, not the 4 written
    assert o["summary_rows_observed"] == 6
    assert o["summary_rows_observed"] != o["rows_written"], (
        "the denominator collapsed onto rows_written - the ratio now moves with the gate")
    assert o["collapse_ratio"] == round(o["findings_collapsed"] / 6.0, 1)


def test_an_empty_tenant_reports_zeroes_rather_than_a_ratio():
    """No division by zero, and no invented 0.0 ratio that a dashboard would plot."""
    o = _run_automation(S, {"schema_version": "4"}, FakeTenant([]), pin_schema=False).outputs
    assert o["collapse_ratio"] is None
    assert o["findings_collapsed"] == 0 and o["summary_rows_observed"] == 0
    assert o["written"] == [] and o["skipped"] == [] and o["failed"] == []


def test_a_bounded_pass_says_so_and_says_stale_removal_is_off():
    """Both were previously visible only in a log line that never reached the output, which
    left the operator to infer the most consequential rail in the automation."""
    o = _run(_fleet(4), max_datasets="2").outputs
    assert o["bounded_pass"] is True
    assert o["sources_read"] == 2 and o["sources_total"] == 4
    assert o["stale_removal_enabled"] is False


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    res = _run(_fleet(4, quiet=["simhost004"]))
    md = res.readable_output
    assert md.startswith("### YARA summary consolidation - DRY RUN")
    assert "\n|---|" in md, "no markdown table in the output"
    for heading in ("#### Would write", "#### Skipped - nothing was touched",
                    "#### Settings this run used"):
        assert heading in md, "missing section: %s" % heading
    # the prose the tables replaced
    assert "file-level findings collapsed:" not in md
    assert "WRITTEN:" not in md and "SKIPPED:" not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    res = _run(_fleet(7, quiet=["simhost007"]))
    o, md = res.outputs, res.readable_output
    assert "| **Rows** | %d would be written |" % o["rows_written"] in md
    assert "| **Skipped** | %d |" % o["skipped_count"] in md
    assert "| **Hosts covered** | %d |" % o["hosts_covered"] in md
    assert "**%s** rows" % format(o["summary_rows_observed"], ",d") in md


def test_a_pipe_in_a_rule_name_cannot_shear_the_table():
    """Rule names come from a ruleset and hostnames from an endpoint. One unescaped pipe and
    every row below it loses a column - silently, since markdown does not error."""
    row = S._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    """A 200-host pass must not push the counts off the top of the War Room - and must not
    lose an entry to do it. Same trade YaraReport makes for the scan log."""
    quiet = ["simhost%03d" % i for i in range(1, 61)]
    res = _run(_fleet(60, quiet=quiet))
    assert len(res.outputs["skipped"]) == 60
    assert res.readable_output.count("`quiet_period`") == S._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.ConsolidateSummary.skipped`" \
        in res.readable_output


def test_skips_are_grouped_by_reason_in_both_the_table_and_the_context():
    """60 scans skipped for two different reasons read as noise in scan_id order."""
    res = _run(_fleet(6, quiet=["simhost001", "simhost006"]))
    reasons = [s["reason"] for s in res.outputs["skipped"]]
    assert reasons == sorted(reasons), "skipped is not grouped by reason"


# ------------------------------------------------------ the yml contract is not fiction

def _declared_outputs():
    import yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                        "YaraConsolidateSummary", "YaraConsolidateSummary.yml")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return [o["contextPath"][len("Yara.ConsolidateSummary."):] for o in doc["outputs"]]


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this - test_every_declared_output_is_actually_produced in
    test_pack_data_management.py - covers YaraCleanup and YaraReport only, and it flattens a
    contextPath by stripping one prefix, so it cannot express `written.action`. Summary
    declares its object keys, which is the whole point of declaring them, so it needs a
    check that walks into the lists.

    Union across scenarios rather than one pass: no single run populates written, skipped and
    failed at once, and requiring that would only prove something about a contrived tenant.
    """
    scenarios = []
    scenarios.append(_run(_fleet(4, quiet=["simhost004"])).outputs)              # written+skipped
    scenarios.append(_run(_fleet(3), execute="true").outputs)                    # wrote
    t = _fleet(3)
    t.error_on = ("| comp count() as n by scan_id",)
    t.names.append("yara_scanner_summary_v4_rules_%s" % RULES)
    scenarios.append(_run(t, execute="true").outputs)                            # failed
    scenarios.append(_run(_fleet(4), max_datasets="2").outputs)                  # bounded

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
    a playbook author never learns it exists - which is how findings_collapsed sat there as an
    unexplained six-figure number."""
    declared = set(_declared_outputs())
    res = _run(_fleet(4, quiet=["simhost004"]))
    undeclared = sorted(set(res.outputs) - declared)
    assert not undeclared, (
        "produced but never declared in the yml: %s" % undeclared)
