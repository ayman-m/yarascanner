#!/usr/bin/env python3
"""YaraConsolidateStatus's two result lists are CONTEXT, so they carry fields, not sentences.

Status had a purer form of the defect than Summary did. It did not publish prose - it
published bare scan_ids, and THREW THE REASON AWAY. The gate computed terminal / quiet / aged
per scan and then dropped all three on the floor, so the only surviving trace of why a scan
was held back was one hardcoded War Room sentence that called every pending scan "still in
progress" - including the ones that had already finished and were merely inside the settle
window, and the ones that carried no usable timestamp at all and could never age out. A
playbook wanting to tell those apart had nothing to read.

So the two lists now sit beside `eligible` and `pending`, one OBJECT per scan, each with a
`reason` from a CLOSED vocabulary. These tests pin the shapes, pin that the vocabularies are
closed and that the yml declares the same ones, and pin that the two vocabularies are
DISJOINT - because "reason alone tells you which list an entry came from" is a property
callers will rely on the moment they concatenate the lists.

Three more properties are pinned here for reasons that are not obvious:

  * eligible_scan_ids and pending_scan_ids MUST STAY LISTS OF PLAIN STRINGS.
    playbook-YARA_Dataset_Consolidation.yml splices them wholesale into another automation's
    scan_id argument and into GenericPolling's Ids, and YaraConsolidateApply does
    set(only_scan_ids), which raises `TypeError: unhashable type: 'dict'` on objects. A list
    of scan_ids is DATA, not prose; converting it would break a live playbook to fix nothing.

  * THE scan_id FILTER MUST NARROW THE GROUPS TOO. It used to be applied to the two returned
    lists only, so group_count and groups went on describing scans the filter had removed -
    and the report then printed the filtered eligible count and the unfiltered group count in
    one sentence. A report stating a number that is nowhere in the context is the exact
    failure this rework exists to remove.

  * THE MARKDOWN IS RENDERED FROM THE RESULT DICT AND FROM NOTHING ELSE. The old builder also
    did `", ".join(st["eligible_scan_ids"][:10])` in three places, which raises TypeError the
    moment an element is a dict - so the renderer had to be replaced in the same change that
    introduced the objects, not after it.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateStatus as S, FakeTenant, _run_automation,
)

RULES = "1aca83d286ad"
OTHER_RULES = "b451b4336910"

# Relative to the real clock, deliberately. main() stamps now_ms from time.time() inside
# check_readiness, and both time gates compare against it - so a fixture pinned to a fixed
# epoch puts every scan decades in the past, ages every one of them out, and reports the
# whole fleet as eligible whatever its lifecycle says.
NOW_MS = int(time.time() * 1000)

# One host per readiness state. `age_h` is the age of the newest MATCH row, which is the only
# thing either time gate measures; `status` is the lifecycle row, or None for a host with no
# scans shard at all.
CASES = {
    "terminal_and_quiet": {"status": "completed", "age_h": 2.0},    # finished and settled
    "aged_out":           {"status": "running",   "age_h": 40.0},   # never finished, silent
    "scan_in_progress":   {"status": "running",   "age_h": 0.02},   # genuinely running
    "quiet_period":       {"status": "completed", "age_h": 0.02},   # finished, still draining
    "no_lifecycle_row":   {"status": None,        "age_h": 1.0},    # no scans shard row
    "no_timestamp":       {"status": "completed", "age_h": None},   # unstamped match rows
    # A NEGATIVE age is a stamp in the future: the endpoint's clock runs ahead of the
    # platform's. check_readiness reads event_timestamp_ms raw, so it sees the future stamp
    # exactly as the endpoint wrote it - and every age test written for a positive number
    # reads it as "fresh".
    "clock_skew":         {"status": "completed", "age_h": -5.0},   # endpoint clock ahead
}
ELIGIBLE_CASES = ("terminal_and_quiet", "aged_out")
PENDING_CASES = ("scan_in_progress", "quiet_period", "no_lifecycle_row", "no_timestamp",
                 "clock_skew")
ALL_CASES = ELIGIBLE_CASES + PENDING_CASES


class Fleet(FakeTenant):
    """FakeTenant, plus whole-shard row reads.

    check_readiness reads shards with a bare `dataset = X` and no pipe - the one query shape
    FakeTenant answers with []. Everything else it needs (get_datasets, the mutable dataset
    list, the not-found raise) is inherited unchanged, so this stays the suite's tenant
    rather than a second implementation of one.
    """

    def __init__(self, rows=None, **kw):
        self.rows = dict(rows or {})
        kw.setdefault("names", list(self.rows))
        FakeTenant.__init__(self, **kw)

    def xql(self, query, limit=1000):
        if "|" not in query and query.startswith("dataset = "):
            self.calls.append("xql:%s" % query)
            name = query.split("dataset = ", 1)[1].strip()
            if name not in self.names:
                raise RuntimeError("dataset not found: %s" % name)
            return [dict(r) for r in self.rows.get(name, [])]
        return FakeTenant.xql(self, query, limit=limit)


def _fleet(*cases):
    """A tenant of one host per entry. Each entry is a case name, or (case, ruleset) - a
    ruleset of None makes a scan_id with no _yara_<hash> suffix at all.

    Dataset names go through the real shard grammar (a host segment ending `_<6 hex>`, the
    scans shard month-suffixed), so parse_shard and _matches_shard_for_read resolve them the
    way they resolve a tenant's.
    """
    rows = {}
    for i, case in enumerate(cases, 1):
        name, rules = case if isinstance(case, tuple) else (case, RULES)
        c = CASES[name]
        host = "simhost%03d" % i
        slug = "%s_%06x" % (host, i)
        sid = "%s_20260907_04%04d_123456" % (host, i)
        if rules:
            sid += "_yara_%s" % rules
        ts = None if c["age_h"] is None else int(NOW_MS - c["age_h"] * 3600 * 1000)
        rows["yara_scanner_matches_v4_" + slug] = [
            {"scan_id": sid, "hostname": host, "event_timestamp_ms": ts,
             "filename": "/f%d" % j} for j in range(3)]
        if c["status"]:
            rows["yara_scanner_scans_v4_%s_202609" % slug] = [
                {"scan_id": sid, "hostname": host, "status": c["status"],
                 "event_timestamp_ms": ts}]
    return Fleet(rows=rows)


def _run(t, **args):
    a = {"schema_version": "4", "retention_hours": "24", "quiet_secs": "900"}
    a.update(args)
    return _run_automation(S, a, t, pin_schema=False)


RECORD_KEYS = {"scan_id", "reason", "detail", "ruleset", "hostnames",
               "newest_ms", "age_hours"}


# ------------------------------------------------------------------ the two lists

def test_every_entry_in_eligible_and_pending_is_an_object():
    """The whole point. One bare string among the objects is the silent failure mode: a
    transformer filtering on a field matches nothing and reports no error."""
    res = _run(_fleet(*ALL_CASES))
    for key in ("eligible", "pending"):
        assert res.outputs[key], "%s was empty - the fixture proves nothing" % key
        for entry in res.outputs[key]:
            assert isinstance(entry, dict), (
                "%s holds a bare %s: %r" % (key, type(entry).__name__, entry))


def test_both_lists_share_one_record_shape():
    """One shape for both, so a transformer written against either works against the other -
    and every entry carries every key, including the ones that do not apply to it."""
    res = _run(_fleet(*ALL_CASES))
    for key in ("eligible", "pending"):
        for e in res.outputs[key]:
            assert set(e) == RECORD_KEYS, (
                "%s record shape drifted: %s" % (key, sorted(e)))
            assert e["reason"] and e["detail"]
            assert isinstance(e["hostnames"], list)


def test_each_readiness_state_gets_its_own_reason_code():
    """Six distinct states the old output collapsed into two bare id lists and one sentence
    that said "still in progress" about all four pending ones."""
    res = _run(_fleet(*ALL_CASES))
    got = {e["scan_id"].split("_")[0]: e["reason"]
           for e in res.outputs["eligible"] + res.outputs["pending"]}
    expected = {"simhost%03d" % (i + 1): case for i, case in enumerate(ALL_CASES)}
    assert got == expected


def test_a_finished_but_settling_scan_is_not_reported_as_running():
    """The sentence this replaced said "still in progress" about a scan that had already
    reported completed and was only waiting out the 900s drain window."""
    res = _run(_fleet("quiet_period"))
    p = res.outputs["pending"][0]
    assert p["reason"] == "quiet_period", p
    assert p["age_hours"] is not None and p["newest_ms"]
    assert "quiet window" in p["detail"]


def test_an_unstamped_scan_says_so_rather_than_pending_for_ever():
    """A scan whose match rows carry no usable event_timestamp_ms fails both time gates for
    ever. It used to be indistinguishable from a running one; it is the one pending reason
    that does NOT clear by waiting, so it has to be nameable."""
    p = _run(_fleet("no_timestamp")).outputs["pending"][0]
    assert p["reason"] == "no_timestamp"
    # None, not 0: 1970 and "no answer" are not the same claim.
    assert p["newest_ms"] is None and p["age_hours"] is None


# --------------------------------------------- a stamp in the FUTURE is not a fresh stamp

def test_a_future_stamped_scan_is_not_reported_as_a_row_that_just_landed():
    """The reproduced defect, end to end.

    An endpoint whose clock runs ahead stamps event_timestamp_ms in the future of the run's
    clock. check_readiness reads that stamp raw - unlike _newest_ms it has no _insert_time to
    correct it with - so age_hours comes out NEGATIVE, and the scan sits pending until real
    time catches up. The old report tested `mins < 1.0`, which is true of every negative
    value, and told the operator the scan had "finished, but its newest match row is only
    under a minute old ... rows may still be landing" - a row that has not been written yet
    described as one that just landed, and the opposite of the cause, on the one scan waiting
    for something other than the drain window.
    """
    p = _run(_fleet("clock_skew")).outputs["pending"][0]
    assert p["age_hours"] is not None and p["age_hours"] < 0, p
    assert p["reason"] == "clock_skew", p
    assert "under a minute" not in p["detail"], p["detail"]
    assert "rows may still be landing" not in p["detail"], p["detail"]
    assert "h in the FUTURE of this run's clock" in p["detail"], p["detail"]
    # the lifecycle fact the branches it takes precedence over would have carried
    assert "completed" in p["detail"], p["detail"]


def test_the_future_stamp_reaches_the_war_room_as_a_future_stamp():
    """The context and the table are two spellings of one fact, so the table must not undo
    the fix - it is the half an operator actually reads."""
    res = _run(_fleet("clock_skew"))
    md = res.readable_output
    assert "`clock_skew`" in md
    assert "under a minute" not in md, md
    assert res.outputs["pending"][0]["detail"] in md


def test_age_phrase_never_describes_a_future_stamp_as_fresh():
    """The unit underneath it. `mins < 1.0` matched every negative value, so this held for
    -0.01h and for -500h alike."""
    assert S._age_phrase(None) == "no stamp"
    assert S._age_phrase(0.0) == "under a minute old"
    assert S._age_phrase(0.7) == "42 min old"
    assert S._age_phrase(3.4) == "3.4h old"
    for future in (-0.01, -5.0, -500.0):
        phrase = S._age_phrase(future)
        assert "FUTURE" in phrase, (future, phrase)
        assert "old" not in phrase, (future, phrase)
    assert S._age_phrase(-5.0).startswith("5.0h in the FUTURE")


def test_a_clock_skewed_scan_is_told_apart_from_one_that_is_merely_settling():
    """Both are finished, both are pending, and only one of them clears by waiting out the
    quiet window. They used to carry the same code AND the same sentence."""
    o = _run(_fleet("quiet_period", "clock_skew")).outputs
    by_reason = {p["reason"]: p for p in o["pending"]}
    assert set(by_reason) == {"quiet_period", "clock_skew"}, o["pending"]
    assert by_reason["quiet_period"]["age_hours"] > 0
    assert by_reason["clock_skew"]["age_hours"] < 0


def test_a_small_skew_inside_the_tolerance_still_reads_as_a_future_stamp():
    """Under SKEW_TOLERANCE_MS the scan keeps its ordinary reason - the tolerance exists
    because that much drift is normal - but the age quoted in the sentence must still be the
    age it actually has."""
    t = _fleet("quiet_period")
    ds = "yara_scanner_matches_v4_simhost001_000001"
    ahead = int(time.time() * 1000) + 60 * 1000
    for r in t.rows[ds]:
        r["event_timestamp_ms"] = ahead
    p = _run(t).outputs["pending"][0]
    assert p["reason"] == "quiet_period", p
    assert p["age_hours"] < 0
    assert "in the FUTURE" in p["detail"], p["detail"]


def test_an_iso_timestamp_does_not_fail_the_whole_check():
    """int("2026-09-07T...") raises ValueError, and the read loop had no guard - one row in
    a shape the platform does return would have failed the entire readiness check rather
    than that row. _as_ms reads both shapes and never raises."""
    t = _fleet("terminal_and_quiet")
    ds = "yara_scanner_matches_v4_simhost001_000001"
    t.rows[ds][0]["event_timestamp_ms"] = "2026-09-07T00:00:00Z"
    res = _run(t)
    assert res.outputs["eligible_count"] + res.outputs["pending_count"] == 1


# ------------------------------------------------- CONSTRAINT: the id lists stay strings

def test_the_two_scan_id_lists_are_still_plain_strings():
    """playbook-YARA_Dataset_Consolidation.yml splices these into another automation's
    scan_id argument and into GenericPolling's Ids, and YaraConsolidateApply does
    set(only_scan_ids) - which raises `TypeError: unhashable type: 'dict'` on objects. A list
    of scan_ids is DATA, not prose. The structured detail lives beside it, not instead of
    it."""
    o = _run(_fleet(*ALL_CASES)).outputs
    for key in ("eligible_scan_ids", "pending_scan_ids"):
        assert o[key], key
        for sid in o[key]:
            assert isinstance(sid, str), "%s holds a %s: %r" % (key, type(sid).__name__, sid)


def test_the_id_lists_are_derived_from_the_records_so_they_cannot_diverge():
    """Same scans, same order. Two independently built lists of the same thing is precisely
    how a report and its context come to disagree."""
    o = _run(_fleet(*ALL_CASES)).outputs
    assert o["eligible_scan_ids"] == [e["scan_id"] for e in o["eligible"]]
    assert o["pending_scan_ids"] == [p["scan_id"] for p in o["pending"]]
    assert o["eligible_count"] == len(o["eligible"]) == len(o["eligible_scan_ids"])
    assert o["pending_count"] == len(o["pending"]) == len(o["pending_scan_ids"])


def test_pending_is_grouped_by_reason_in_the_context_and_the_table():
    """A 200-host fleet goes pending in runs of one reason; scan_id order scatters them."""
    o = _run(_fleet(*ALL_CASES)).outputs
    for key in ("eligible", "pending"):
        reasons = [e["reason"] for e in o[key]]
        assert reasons == sorted(reasons), "%s is not grouped by reason" % key


# ------------------------------------------------------- the vocabularies stay closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason invented at a call site and never declared is exactly as unmatchable as the
    prose this replaced - it just looks like a contract."""
    for t in (_fleet(*ALL_CASES), _fleet("no_timestamp"), _fleet(("aged_out", None))):
        o = _run(t).outputs
        for e in o["eligible"]:
            assert e["reason"] in S.ELIGIBLE_REASONS, (
                "undeclared eligibility reason %r" % e["reason"])
        for p in o["pending"]:
            assert p["reason"] in S.PENDING_REASONS, (
                "undeclared pending reason %r" % p["reason"])


def test_the_two_vocabularies_are_disjoint():
    """`reason` alone must say which list an entry came from, or a caller concatenating the
    two lists loses the distinction the codes exist to make."""
    assert not (set(S.ELIGIBLE_REASONS) & set(S.PENDING_REASONS))


def test_every_declared_reason_can_actually_happen():
    """The other direction on the vocabulary: a code nobody can produce is documentation of
    a branch that does not exist."""
    o = _run(_fleet(*ALL_CASES)).outputs
    emitted = {e["reason"] for e in o["eligible"] + o["pending"]}
    assert emitted == set(S.ELIGIBLE_REASONS) | set(S.PENDING_REASONS), (
        "never emitted: %s" % sorted(
            (set(S.ELIGIBLE_REASONS) | set(S.PENDING_REASONS)) - emitted))


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    described = {o["contextPath"]: o["description"] for o in _yml()["outputs"]}
    for code in S.ELIGIBLE_REASONS:
        assert code in described["Yara.ConsolidateStatus.eligible.reason"], (
            "eligibility reason %r is not in the yml's declared closed set" % code)
    for code in S.PENDING_REASONS:
        assert code in described["Yara.ConsolidateStatus.pending.reason"], (
            "pending reason %r is not in the yml's declared closed set" % code)


# ------------------------------------------- the scan_id filter narrows ONE population

def test_the_scan_id_filter_narrows_the_groups_and_their_count_too():
    """It was applied to the two returned lists only. group_count and groups went on
    describing scans the filter had removed, and the report printed the filtered eligible
    count beside the unfiltered group count in a single sentence."""
    t = _fleet(("terminal_and_quiet", RULES), ("terminal_and_quiet", OTHER_RULES))
    both = _run(t).outputs
    assert both["eligible_count"] == 2 and both["group_count"] == 2

    keep = [s for s in both["eligible_scan_ids"] if s.endswith(RULES)]
    one = _run(_fleet(("terminal_and_quiet", RULES), ("terminal_and_quiet", OTHER_RULES)),
               scan_id=",".join(keep))
    o = one.outputs
    assert o["eligible_count"] == 1
    assert o["group_count"] == 1 == len(o["groups"]), (
        "group_count %d still describes scans the filter removed" % o["group_count"])
    assert [g["rule_hash"] for g in o["groups"]] == [RULES]
    assert OTHER_RULES not in one.readable_output
    assert o["scan_id_filter"] == keep


def test_the_filter_narrows_pending_as_well():
    t = _fleet("scan_in_progress", "quiet_period")
    every = _run(t).outputs
    assert every["pending_count"] == 2
    one = _run(_fleet("scan_in_progress", "quiet_period"),
               scan_id=every["pending_scan_ids"][0]).outputs
    assert one["pending_count"] == 1 and one["eligible_count"] == 0


# ------------------------------------------------------------------- the groups roll-up

def test_a_group_names_the_datasets_a_run_would_write():
    """Derived from the naming convention rather than left for the caller to rebuild - a
    subtly wrong name is a plausible one that resolves to nothing."""
    g = _run(_fleet("terminal_and_quiet", "aged_out")).outputs["groups"][0]
    assert set(g) == {"rule_hash", "scans", "hosts", "summary_target", "full_target"}, sorted(g)
    assert g["rule_hash"] == RULES and g["scans"] == 2
    assert g["summary_target"] == "yara_scanner_summary_v4_rules_%s" % RULES
    assert g["full_target"] == "yara_scanner_full_v4_rules_%s" % RULES
    assert g["hosts"] == ["simhost001", "simhost002"]


def test_a_scan_with_no_ruleset_hash_gets_no_invented_target():
    """"rules_unknown" would name a dataset nothing will ever create."""
    o = _run(_fleet(("aged_out", None))).outputs
    assert o["eligible"][0]["ruleset"] is None
    g = o["groups"][0]
    assert g["rule_hash"] == "unknown"
    assert g["summary_target"] is None and g["full_target"] is None


def test_the_group_counts_sum_to_the_eligible_count():
    """groups is the ROLL-UP of eligible, so the two cannot disagree about how much work
    there is."""
    o = _run(_fleet(("terminal_and_quiet", RULES), ("aged_out", OTHER_RULES),
                    "scan_in_progress")).outputs
    assert sum(g["scans"] for g in o["groups"]) == o["eligible_count"] == 2
    assert o["group_count"] == len(o["groups"]) == 2


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    md = _run(_fleet(*ALL_CASES)).readable_output
    assert md.startswith("### YARA consolidation readiness - ")
    assert "\n|---|" in md, "no markdown table in the output"
    for heading in ("#### Ready to consolidate", "#### Ruleset groups a run would produce",
                    "#### Pending - not yet eligible", "#### Settings this run used"):
        assert heading in md, "missing section: %s" % heading
    # the prose the tables replaced
    assert "scan(s) ready to consolidate, in" not in md
    assert "still in progress - not yet eligible" not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see - which is
    exactly what the filtered/unfiltered count pair used to be."""
    res = _run(_fleet(*ALL_CASES))
    o, md = res.outputs, res.readable_output
    assert "| **Ready to consolidate** | %d |" % o["eligible_count"] in md
    assert "| **Still pending** | %d |" % o["pending_count"] in md
    assert "| **Ruleset groups** | %d - " % o["group_count"] in md
    for e in o["eligible"] + o["pending"]:
        assert "`%s`" % e["reason"] in md
        assert e["scan_id"] in md


def test_every_pending_reason_reaches_the_operator_with_its_detail():
    md = _run(_fleet(*PENDING_CASES)).readable_output
    for p in _run(_fleet(*PENDING_CASES)).outputs["pending"]:
        assert p["detail"] in md


def test_a_pipe_in_a_hostname_cannot_shear_the_table():
    """Hostnames reach the table from an endpoint. One unescaped `|` and every row below it
    loses a column - silently, since markdown does not error."""
    row = S._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_pending_footer_does_not_promise_a_stuck_scan_will_clear():
    """The footer used to read "Every reason above resolves on its own" whatever was in the
    table - including `no_timestamp`, whose own declared meaning is that the scan "can never
    age out on its own", and `clock_skew`, which waits on the endpoint's clock rather than on
    this pass. Telling an operator to keep polling those is the report contradicting the
    context printed directly above it."""
    for case in ("no_timestamp", "clock_skew"):
        md = _run(_fleet(case)).readable_output
        assert "resolves on its own" not in md, (case, md)
        assert "Waiting does NOT clear" in md, (case, md)
        assert "`%s`" % case in md
        assert S.PENDING_REASON_REMEDIES[case] in md, case


def test_the_pending_footer_still_says_so_when_every_reason_does_clear():
    """The other direction: polling really is the right answer for the three that settle, and
    the footer must keep saying so rather than hedging over all five."""
    md = _run(_fleet("quiet_period", "scan_in_progress", "no_lifecycle_row")).readable_output
    assert "A further poll clears" in md
    assert "Waiting does NOT clear" not in md, md


def test_the_footer_separates_the_two_kinds_when_both_are_pending():
    md = _run(_fleet(*PENDING_CASES)).readable_output
    assert "A further poll clears" in md and "Waiting does NOT clear" in md
    for code in ("no_timestamp", "clock_skew"):
        assert "`%s`" % code in md


def test_every_pending_reason_that_does_not_clear_by_waiting_carries_a_remedy():
    """The invariant the footer rests on. A code outside SELF_CLEARING_PENDING_REASONS with
    no remedy would be reported as stuck with nothing said about what to do, which is how a
    closed vocabulary turns back into prose."""
    stuck = set(S.PENDING_REASONS) - set(S.SELF_CLEARING_PENDING_REASONS)
    assert stuck == set(S.PENDING_REASON_REMEDIES), (
        "no remedy for %s" % sorted(stuck - set(S.PENDING_REASON_REMEDIES)))
    assert set(S.SELF_CLEARING_PENDING_REASONS) <= set(S.PENDING_REASONS)


def test_the_markdown_truncates_but_the_context_does_not():
    """A 200-host pass must not push the counts off the top of the War Room - and must not
    lose an entry to do it."""
    res = _run(_fleet(*(["quiet_period"] * (S._MD_ROW_CAP + 5))))
    assert len(res.outputs["pending"]) == S._MD_ROW_CAP + 5
    # The reason CELL, not the bare code: the footer under the table names the codes it is
    # talking about, so counting the code alone counts the footer too and this would report
    # one row more than the table holds.
    assert res.readable_output.count("| `quiet_period` |") == S._MD_ROW_CAP
    assert "and 5 more - the full list is in `Yara.ConsolidateStatus.pending`" \
        in res.readable_output


def test_an_empty_tenant_reports_zeroes_and_still_renders():
    """A fresh or freshly-wiped tenant is the documented normal case, not a failure."""
    res = _run(Fleet(rows={}))
    o = res.outputs
    assert o["eligible_count"] == o["pending_count"] == o["group_count"] == 0
    assert o["eligible"] == [] and o["pending"] == [] and o["groups"] == []
    assert o["eligible_scan_ids"] == [] and o["pending_scan_ids"] == []
    assert res.readable_output.startswith("### YARA consolidation readiness - 0 ready, "
                                          "0 pending")


def test_the_settings_travel_with_the_answer():
    """Without them, stored context cannot say which quiet_secs produced a given pending
    list - and a preview that disagrees with the run it previews is indistinguishable from a
    bug in the run."""
    o = _run(_fleet("quiet_period"), quiet_secs="60", retention_hours="8").outputs
    assert o["quiet_secs"] == 60.0 and o["retention_hours"] == 8.0
    assert o["schema_version"] == "4" and o["scan_id_filter"] == []


def test_the_context_is_cleared_before_it_is_written():
    """List-valued context is APPENDED to across repeated calls in one investigation, and
    this automation is polled in a loop."""
    from test_pack_data_management import demistomock
    _run(_fleet("quiet_period"))
    assert ("DeleteContext", {"key": "Yara.ConsolidateStatus"}) in demistomock.commands


# --------------------------------------------- a bad argument is this automation's error

def _run_expecting_error(args):
    """Drive main() the way _run_automation does, but expect return_error rather than a
    result - the stub raises SystemExit from return_error, exactly as the platform's does.

    Returns the message that reached return_error. An UNCAUGHT exception escapes this
    helper, which is the point: that is the failure being pinned."""
    from test_pack_data_management import CommonServerPython as csp, demistomock as dm
    dm.args_value = dict(args)
    dm.commands = []
    del csp.results[:]
    del csp.errors[:]
    real = S.CoreApiClient
    S.CoreApiClient = lambda *a, **k: Fleet(rows={})
    try:
        S.main()
    except SystemExit:
        pass
    finally:
        S.CoreApiClient = real
    assert csp.errors, "main() returned without reporting an error"
    assert not csp.results, "main() reported an error AND a result"
    return csp.errors[0]


@pytest.mark.parametrize("arg", ["quiet_secs", "retention_hours"])
def test_a_non_numeric_setting_is_this_automations_error_not_a_platform_traceback(arg):
    """Both coercions were hoisted ABOVE main()'s try, so float("abc") escaped the handler
    and the automation died with a raw traceback and an EMPTY errors list - no
    "YaraConsolidateStatus failed: ..." anywhere. The two arguments have to behave the same
    way: retention_hours had the same hole from the start.

    The message must also NAME the argument. `could not convert string to float: 'abc'` does
    not say which of the two numeric settings was mistyped, and both are on the same task.
    """
    msg = _run_expecting_error({"schema_version": "4", arg: "abc"})
    assert msg.startswith("YaraConsolidateStatus failed: "), msg
    assert arg in msg, msg
    assert "'abc'" in msg, msg


def test_the_numeric_settings_keep_their_defaults_when_omitted_or_blank():
    """The coercion moved; its semantics did not. An omitted argument, an empty string and a
    zero all fell back to the default before, and a preview that silently changed its gate
    would disagree with the run it previews."""
    for args in ({"schema_version": "4"},
                 {"schema_version": "4", "quiet_secs": "", "retention_hours": ""},
                 {"schema_version": "4", "quiet_secs": 0, "retention_hours": 0}):
        o = _run_automation(S, args, Fleet(rows={}), pin_schema=False).outputs
        assert o["quiet_secs"] == float(S.DEFAULT_QUIET_SECS), (args, o["quiet_secs"])
        assert o["retention_hours"] == 24.0, (args, o["retention_hours"])


# ------------------------------------------------------ the yml contract is not fiction

def _yml():
    import yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                        "YaraConsolidateStatus", "YaraConsolidateStatus.yml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _declared_outputs():
    return [o["contextPath"][len("Yara.ConsolidateStatus."):] for o in _yml()["outputs"]]


def _scenarios():
    """Union across scenarios rather than one pass: no single tenant populates every list and
    every reason, and requiring that would only prove something about a contrived one."""
    return [_run(_fleet(*ALL_CASES)).outputs,
            _run(_fleet(("aged_out", None))).outputs,
            _run(_fleet("quiet_period"), scan_id="nothing-matches-this").outputs,
            _run(Fleet(rows={})).outputs]


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this covers YaraCleanup and YaraReport only, and it flattens a
    contextPath by stripping one prefix, so it cannot express `pending.reason`. Status
    declares its object keys, which is the whole point of declaring them."""
    scenarios = _scenarios()
    missing = []
    for path in _declared_outputs():
        head, _, leaf = path.partition(".")
        if not leaf:
            if not any(head in o for o in scenarios):
                missing.append(path)
            continue
        # A declared object key: the list must be populated in SOME scenario, and every
        # element of it must carry the key - a key present on only some entries is a
        # transformer that matches some of the time, which is worse than one that never does.
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
    a playbook author never learns it exists."""
    declared = set(_declared_outputs())
    for o in _scenarios():
        undeclared = sorted(set(o) - declared)
        assert not undeclared, "produced but never declared in the yml: %s" % undeclared
        for head in ("eligible", "pending", "groups"):
            for entry in o.get(head) or []:
                extra = sorted("%s.%s" % (head, k) for k in entry
                               if "%s.%s" % (head, k) not in declared)
                assert not extra, "produced but never declared in the yml: %s" % extra


def test_the_docstrings_promise_no_bucket_the_code_does_not_emit():
    """The module docstring used to promise a `blocked` bucket - the row ceiling, the count
    mismatch - that only check_consolidation_status produces and main() never calls. A
    playbook written from that promise branched on a key nothing ever emitted, and took the
    silently-empty branch every time."""
    o = _run(_fleet(*ALL_CASES)).outputs
    for key in ("blocked", "blocked_count", "blocked_scan_ids", "blocked_reasons"):
        assert key not in o
    assert "blocked" not in " ".join(_declared_outputs())
    assert "no `blocked` bucket" in _yml()["comment"]
