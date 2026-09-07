#!/usr/bin/env python3
"""YaraCleanup's result lists are CONTEXT, so they carry fields rather than sentences.

`skipped` used to be a list of preformatted strings - nineteen sentence templates from five
producers - and `failed` was half-done: objects, but with free-text `str(e)` and no code. A
playbook that wanted to act on either (branch on rail 6 versus rail 7, tell a query that
errored from a shard still being written to, decide whether `force=true` would help) had no
option but to substring-match prose written for a human. That is a contract nobody can change
safely and nobody can rely on: reword one message for clarity and every filter downstream
silently stops matching, with no error anywhere.

So each entry is an object now and `reason` is a CLOSED vocabulary. These tests pin both - the
shapes, and the fact that the vocabularies stay closed - because the value of a closed set is
entirely in it staying closed.

Four properties are pinned here for reasons that are not obvious:

  * THE MAPPING IS TESTED AGAINST THE REAL PRODUCERS. Seventeen of the nineteen sentences are
    built inside select_rotated_for_deletion, filter_recently_written, filter_unconsolidated
    and select_legacy_for_deletion, which tests/test_pack_data_management.py compares
    byte-for-byte against xdr/xdr_data_management.py across all five shipping automations.
    They cannot be rewritten here, so prune_datasets converts at the BOUNDARY instead. That
    only holds while the mapping matches the sentences, so
    test_every_rail_sentence_the_selectors_produce_maps_to_a_reason CALLS those four functions
    and classifies whatever they return today - a reworded rail fails here rather than landing
    in context as `unclassified`.

  * PATH, NOT JUST REASON. Two sentences are IDENTICAL on the retention and the legacy path
    ("current month", "dated in the future"), and the two live rails run on both. No
    downstream matcher could ever separate those; the boundary knows which call it came from,
    so `path` records it.

  * NOTHING IN EITHER LIST MAY BE A STRING. The old readable-output builder did
    `lines += ["  skip  {}".format(s) for s in result["skipped"]]`, which does not raise on a
    dict - it prints its repr. A `%s`-formatted append slipping in beside the structured ones
    would sail through the renderer and land in context as a lone string among objects, which
    is worse than a crash because it is silent.

  * THE IDENTIFIER LISTS STAY PLAIN STRINGS. `selected`, `deleted` and `newer` hold dataset
    names. A name is data already; converting it to an object would break every caller that
    splices the list somewhere expecting scalars, and buys nothing.
"""
import datetime
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraCleanup as C, FakeTenant, _run_automation,
)

YML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "xdr", "Packs", "YaraDatasetManagement", "Scripts", "YaraCleanup",
                   "YaraCleanup.yml")

# Relative to the real clock, deliberately. main() has no now_ms/now_yyyymm seam - it stamps
# both from the real clock - so a fixture pinned to a fixed month puts every dataset either in
# the future (rail 2 keeps it) or far enough back that the wrong rail fires. Which is exactly
# what a first draft of this file did.
NOW = datetime.date.today()


def _month(delta):
    """YYYYMM `delta` whole months from this month. Negative is the past."""
    m = NOW.month - 1 + delta
    return "%04d%02d" % (NOW.year + m // 12, m % 12 + 1)


THIS_MONTH, NEXT_MONTH, LAST_MONTH, ANCIENT = _month(0), _month(1), _month(-1), _month(-60)


@pytest.fixture(autouse=True)
def _reset_schema_version():
    """set_schema_version mutates a module global AND os.environ, and one container serves
    many executions - so leaving "2" behind would change what a later module classifies."""
    yield
    C.set_schema_version(C.DEFAULT_SCHEMA_VERSION)


def _run(t, **args):
    a = {"schema_version": "2"}
    a.update(args)
    return _run_automation(C, a, t, pin_schema=False)


class LockStuck(FakeTenant):
    """A tenant whose lock dataset cannot be deleted, so the release at the end of the pass
    fails. That is the event that used to reach nobody: the next run is blocked until the
    marker ages out, and nothing in the context said so."""

    def delete_dataset(self, dataset_name, force=False):
        if dataset_name == C._LOCK_DATASET:
            raise RuntimeError("dataset is locked by another operation")
        return FakeTenant.delete_dataset(self, dataset_name, force=force)


class DeleteRefused(FakeTenant):
    def delete_dataset(self, dataset_name, force=False):
        if dataset_name.startswith("yara_scanner_matches_v2_bad"):
            raise RuntimeError("dataset has dependencies")
        return FakeTenant.delete_dataset(self, dataset_name, force=force)


# ------------------------------------------------------------------ the two lists

def test_every_entry_in_the_two_result_lists_is_an_object():
    """The whole point. One string among the objects is the silent failure mode."""
    t = DeleteRefused(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                       "yara_scanner_matches_v2_bad_%s" % ANCIENT,
                       "yara_scanner_matches_v2_ok_%s" % ANCIENT])
    res = _run(t, older_than_months="0", execute="true")
    assert res.outputs["skipped"] and res.outputs["failed"]
    for key in ("skipped", "failed", "warnings", "lock_events"):
        for entry in res.outputs[key]:
            assert isinstance(entry, dict), (
                "%s holds a bare %s - a playbook filtering on a field would silently match "
                "nothing: %r" % (key, type(entry).__name__, entry))


def test_a_skipped_entry_carries_every_key_on_every_entry():
    """A key present on only some entries is a transformer that matches some of the time,
    which is worse than one that never does, because it looks like it works."""
    t = FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                    "yara_scanner_matches_v2_h_%s" % NEXT_MONTH,
                    "yara_scanner_matches_v2_lonely",
                    "yara_scanner_matches_v1_old_%s" % ANCIENT])
    skipped = _run(t, older_than_months="0").outputs["skipped"]
    assert len(skipped) == 4
    for s in skipped:
        assert set(s) == {"name", "reason", "detail", "path", "rail", "age_months",
                          "window_months", "newest_age_hours", "stuck_scan_ids",
                          "newer_datasets", "error"}, (
            "skipped record shape drifted: %s" % sorted(s))
        assert s["reason"] in C.SKIP_REASONS and s["detail"]
        assert s["path"] in C.SKIP_PATHS
        assert s["name"] in s["detail"], "the record and its sentence disagree on the dataset"


def test_the_two_selection_paths_are_distinguishable_where_the_sentence_is_not():
    """select_rotated_for_deletion and select_legacy_for_deletion emit the SAME sentence for
    a current-month dataset, and both live rails run on both paths. Nothing downstream could
    ever tell those apart from the prose; the boundary can, because it knows which call it is
    converting."""
    current = "yara_scanner_matches_v2_h_%s" % THIS_MONTH
    legacy = "yara_scanner_matches_v1_h_%s" % THIS_MONTH
    res = _run(FakeTenant([current, legacy]), older_than_months="0", delete_legacy="true")
    by_name = {s["name"]: s for s in res.outputs["skipped"]}
    assert by_name[current]["reason"] == by_name[legacy]["reason"] == "current_month"
    assert by_name[current]["path"] == "retention"
    assert by_name[legacy]["path"] == "legacy"
    assert by_name[current]["detail"] == by_name[legacy]["detail"].replace("_v1_", "_v2_")


def test_a_failed_entry_carries_a_closed_reason_beside_what_the_api_said():
    """"dataset has dependencies" is a sentence to grep for; delete_refused_dependencies is a
    branch, and the one whose remedy (force=true) is documented."""
    t = DeleteRefused(["yara_scanner_matches_v2_bad_%s" % ANCIENT,
                       "yara_scanner_matches_v2_ok_%s" % ANCIENT])
    res = _run(t, older_than_months="0", execute="true")
    assert res.outputs["deleted"] == ["yara_scanner_matches_v2_ok_%s" % ANCIENT]
    failed = res.outputs["failed"]
    assert len(failed) == 1
    assert set(failed[0]) == {"dataset", "reason", "error", "path"}, (
        "failed record shape drifted: %s" % sorted(failed[0]))
    assert failed[0]["reason"] == "delete_refused_dependencies"
    assert failed[0]["path"] == "retention"
    assert "dependencies" in failed[0]["error"]
    assert res.outputs["status"] == "partial_failure"


# ----------------------------------------------------- the vocabularies stay closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason invented at a call site and never declared is exactly as unmatchable as the
    prose it replaced - it just looks like a contract."""
    scenarios = [
        (FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                     "yara_scanner_matches_v2_h_%s" % NEXT_MONTH,
                     "yara_scanner_matches_v9_h_%s" % ANCIENT,
                     "yara_scanner_summary_v2_rules_abc123",
                     "yara_scanner_matches_v2_lonely"]), {"older_than_months": "0"}),
        (FakeTenant(["yara_scanner_matches_v1_hostA",
                     "yara_scanner_matches_v1_scan_abc",
                     "yara_scanner_matches_v1_h_%s" % THIS_MONTH]),
         {"delete_legacy": "true"}),
        (FakeTenant(["yara_scanner_matches_v2_h_%s" % ANCIENT],
                    scans={"yara_scanner_matches_v2_h_%s" % ANCIENT: {"S1": 9}}),
         {"older_than_months": "0"}),
        (FakeTenant(["yara_scanner_matches_v2_h_%s" % ANCIENT],
                    error_on=("comp max(event_timestamp_ms)",)), {"older_than_months": "0"}),
    ]
    seen = set()
    for t, args in scenarios:
        for s in _run(t, **args).outputs["skipped"]:
            assert s["reason"] in C.SKIP_REASONS, (
                "undeclared skip reason %r - add it to SKIP_REASONS or use an existing one"
                % s["reason"])
            assert s["reason"] != "unclassified", (
                "a rail sentence stopped matching its template: %s" % s["detail"])
            seen.add(s["reason"])
    assert len(seen) >= 8, "the scenarios stopped covering the vocabulary: %s" % sorted(seen)


def test_every_rail_sentence_the_selectors_produce_maps_to_a_reason():
    """THE DRIFT GUARD for the boundary conversion.

    The four selectors are byte-compared against xdr/xdr_data_management.py across every
    shipping automation, so their sentences cannot be replaced with records - prune_datasets
    maps them instead. This calls the real functions and classifies whatever they return
    TODAY, so a reworded rail fails here loudly rather than landing in context as
    `unclassified`, which no other test would notice.
    """
    C.set_schema_version("2")
    rotated_names = [
        "yara_scanner_full_v2_rules_abc123",            # pack_output_full
        "yara_scanner_summary_v2_rules_abc123",         # pack_output_summary
        "yara_scanner_matches_v2_",                     # not_yara_name
        "yara_scanner_matches_v2_scan_abc",             # retired_scan_target
        "yara_scanner_matches_v4_hostA",                # overwrite_dataset
        "yara_scanner_matches_v2_frozen",               # unrotated_frozen (sibling below)
        "yara_scanner_matches_v2_frozen_%s" % ANCIENT,
        "yara_scanner_matches_v2_growing",              # unrotated_growing
        "yara_scanner_matches_v2_h_%s" % THIS_MONTH,    # current_month
        "yara_scanner_matches_v2_h_%s" % NEXT_MONTH,    # future_month
        "yara_scanner_matches_v2_h_%s" % LAST_MONTH,    # inside_window
    ]
    _, rotated = C.select_rotated_for_deletion(rotated_names, 6, THIS_MONTH)

    aged = "yara_scanner_matches_v2_g_%s" % ANCIENT
    now_ms = int(time.time() * 1000)
    _, quiet = C.filter_recently_written(
        FakeTenant([aged], newest={aged: now_ms - 1000}), [aged], 24 * 3600, now_ms)
    _, recency_err = C.filter_recently_written(
        FakeTenant([aged], error_on=("comp max(event_timestamp_ms)",)), [aged],
        24 * 3600, now_ms)
    _, stuck = C.filter_unconsolidated(FakeTenant([aged], scans={aged: {"S1": 9}}), [aged])
    _, consol_err = C.filter_unconsolidated(
        FakeTenant([aged], error_on=("by scan_id",)), [aged])

    _, refusal = C.select_legacy_for_deletion(["yara_scanner_matches_v1_h_%s" % ANCIENT],
                                              ["yara_scanner_matches_v9_h_%s" % ANCIENT])
    _, legacy = C.select_legacy_for_deletion(
        ["yara_scanner_matches_v1_scan_abc",            # retired_scan_target
         "yara_scanner_matches_v1_hostA",               # legacy_unsuffixed
         "yara_scanner_matches_v1_h_%s" % THIS_MONTH,   # current_month
         "yara_scanner_matches_v1_h_%s" % NEXT_MONTH],  # future_month
        (), THIS_MONTH)

    produced = {"retention": rotated + quiet + recency_err + stuck + consol_err,
                "legacy": refusal + legacy}
    got = set()
    for path, sentences in produced.items():
        for text in sentences:
            assert isinstance(text, str), "a selector stopped returning strings: %r" % text
            rec = C._classify_skip(text, path, rotated_names + [aged])
            assert rec["reason"] != "unclassified", (
                "no template matches this rail sentence any more, so it would reach context "
                "as `unclassified`:\n    %s" % text)
            got.add(rec["reason"])

    expected = set(C.SKIP_REASONS) - {"unclassified", "newer_schema", "legacy_not_requested"}
    assert got == expected, (
        "the selectors and the vocabulary have diverged - only these were produced: %s"
        % sorted(got))


def test_the_two_reasons_written_in_free_code_are_produced_too():
    """newer_schema and legacy_not_requested are built in prune_datasets rather than in a
    gated selector, so the test above cannot reach them."""
    t = FakeTenant(["yara_scanner_matches_v9_h_%s" % ANCIENT,
                    "yara_scanner_matches_v1_h_%s" % ANCIENT])
    o = _run(t, older_than_months="0").outputs
    assert {s["reason"] for s in o["skipped"]} == {"newer_schema", "legacy_not_requested"}
    assert [s["path"] for s in o["skipped"] if s["reason"] == "newer_schema"] == ["schema"]


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    import yaml
    with open(YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    described = {o["contextPath"]: o["description"] for o in doc["outputs"]}
    for vocab, path in ((C.SKIP_REASONS, "Yara.Cleanup.skipped.reason"),
                        (C.SKIP_PATHS, "Yara.Cleanup.skipped.path"),
                        (C.FAIL_REASONS, "Yara.Cleanup.failed.reason"),
                        (C.WARN_REASONS, "Yara.Cleanup.warnings.reason"),
                        (C.LOCK_EVENTS, "Yara.Cleanup.lock_events.event")):
        for code in vocab:
            assert code in described[path], (
                "%s is not in the closed set the yml declares at %s" % (code, path))


def test_every_reason_has_a_rail_and_the_rails_are_the_documented_seven():
    """`rail` is null where the guard is real but unnumbered, never missing - and it must not
    invent an eighth rail the docs have never heard of."""
    assert set(C.SKIP_RAILS) == set(C.SKIP_REASONS), (
        "SKIP_RAILS and SKIP_REASONS have drifted apart: %s"
        % sorted(set(C.SKIP_RAILS) ^ set(C.SKIP_REASONS)))
    assert set(C.SKIP_RAILS.values()) <= {None, 1, 2, 3, 4, 5, 6, 7}


# --------------------------------------- the numbers a sentence swallowed come back out

def test_the_numbers_folded_into_a_sentence_are_fields_again():
    ds = "yara_scanner_matches_v2_h_%s" % LAST_MONTH
    o = _run(FakeTenant([ds]), older_than_months="6").outputs
    inside = [s for s in o["skipped"] if s["reason"] == "inside_window"]
    assert len(inside) == 1
    assert inside[0]["age_months"] == 1 and inside[0]["window_months"] == 6
    # and everything that does not apply is present and null, not absent
    assert inside[0]["newest_age_hours"] is None and inside[0]["error"] == ""
    assert inside[0]["stuck_scan_ids"] == [] and inside[0]["newer_datasets"] == []


def test_the_quiet_rail_reports_the_age_it_measured():
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = FakeTenant([ds], newest={ds: int(time.time() * 1000) - 2 * 3600 * 1000})
    o = _run(t, older_than_months="0", min_quiet_hours="24").outputs
    quiet = [s for s in o["skipped"] if s["reason"] == "within_quiet_period"]
    assert len(quiet) == 1 and 1.9 <= quiet[0]["newest_age_hours"] <= 2.1


def test_the_stuck_scan_ids_and_the_failing_query_are_fields():
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    o = _run(FakeTenant([ds], scans={ds: {"S1": 9, "S2": 4}}),
             older_than_months="0").outputs
    stuck = [s for s in o["skipped"] if s["reason"] == "unconsolidated_scans"]
    assert stuck and stuck[0]["stuck_scan_ids"] == ["S1", "S2"]

    o = _run(FakeTenant([ds], error_on=("comp max(event_timestamp_ms)",)),
             older_than_months="0").outputs
    err = [s for s in o["skipped"] if s["reason"] == "recency_check_failed"]
    assert err and err[0]["error"] == "tenant hiccup"


def test_the_blanket_refusal_reports_every_newer_dataset_not_the_five_it_names():
    """The sentence caps its list at five with nothing saying more exist. The record carries
    the real list, which is the one an operator has to act on."""
    newer = ["yara_scanner_matches_v9_h%02d_%s" % (i, ANCIENT) for i in range(8)]
    o = _run(FakeTenant(newer + ["yara_scanner_matches_v1_h_%s" % ANCIENT]),
             delete_legacy="true").outputs
    refusal = [s for s in o["skipped"]
               if s["reason"] == "legacy_refused_newer_schema_present"]
    assert len(refusal) == 1
    assert refusal[0]["newer_datasets"] == sorted(newer)
    assert refusal[0]["name"] == "", "a whole-path refusal names no single dataset"
    assert o["deleted"] == [] and o["selected"] == []


# ------------------------------------------- facts that used to reach only the operator

def test_a_clamped_argument_reaches_a_playbook_and_not_only_the_war_room():
    """older_than_months=-3 was silently clamped to 0 and the run published 0, with nothing
    anywhere saying the value had been changed."""
    o = _run(FakeTenant([]), older_than_months="-3", min_quiet_hours="0").outputs
    assert o["older_than_months"] == 0 and o["min_quiet_hours"] == C.MIN_ALLOWED_QUIET_HOURS
    by_reason = {w["reason"]: w for w in o["warnings"]}
    assert set(by_reason) == {"older_than_months_clamped", "min_quiet_hours_floored"}
    for w in o["warnings"]:
        assert set(w) == {"reason", "detail", "argument", "requested", "applied"}
        assert w["reason"] in C.WARN_REASONS
    assert by_reason["older_than_months_clamped"]["requested"] == "-3"
    assert by_reason["older_than_months_clamped"]["applied"] == "0"


def test_a_lock_that_could_not_be_released_reaches_the_context():
    """It blocks the next run until it ages out, and it used to exist only as a log line
    scraped for the word "lock"."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    o = _run(LockStuck([ds]), older_than_months="0", execute="true").outputs
    assert [e["event"] for e in o["lock_events"]] == ["release_failed"]
    for e in o["lock_events"]:
        assert set(e) == {"event", "detail"} and e["event"] in C.LOCK_EVENTS
    assert o["deleted"] == [ds], "the failed release must not undo the pass's real outcome"


def test_status_folds_the_three_booleans_into_one_verdict():
    """A caller reconstructing the outcome from the booleans has to know the precedence, and
    the order is not obvious - a held lock outranks dry_run, which is set on both."""
    assert _run(FakeTenant([])).outputs["status"] == "nothing_requested"
    assert _run(FakeTenant([]), older_than_months="0").outputs["status"] == "dry_run"

    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    o = _run(FakeTenant([ds]), older_than_months="0", execute="true").outputs
    assert o["status"] == "success" and o["dry_run"] is False

    t = FakeTenant([ds, C._LOCK_DATASET])
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": int(time.time() * 1000) - 60_000}]
    o = _run(t, older_than_months="0", execute="true").outputs
    assert o["status"] == "lock_held" and o["lock_held_by_other_run"] is True
    # The SPECIFIC finding first, then the generic standdown. Two events rather than one
    # because acquire_consolidation_lock refuses for two different findings and returns the
    # same False for both: a lock whose row it READ and judged live, and a marker whose row
    # it could not read at all. Only the first identifies a holder. The pass's own summary
    # line therefore says nothing about who holds it, and `stood_down` is what that line
    # classifies as - so a playbook filtering for genuine contention matches
    # held_by_other_run and is not fooled by a create-lag marker.
    assert [e["event"] for e in o["lock_events"]] == ["held_by_other_run", "stood_down"]


def test_an_unreadable_lock_marker_is_never_reported_as_a_known_holder():
    """The same defect class as the "taken and released" claim, on the third standdown path.

    A marker dataset with no readable row is the add_data create-lag window right after
    another run took the lock - and equally the signature of a marker orphaned by a killed
    pass. The pass cannot tell which, and it does not have to: standing down is right either
    way. What it must not do is report a holder it never read, because `held_by_other_run` is
    the signal a playbook uses to decide it is racing a real run.
    """
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = FakeTenant([ds, C._LOCK_DATASET])
    t.lock_rows = []                                  # marker present, row unreadable
    res = _run(t, older_than_months="0", execute="true")
    o, md = res.outputs, res.readable_output

    assert o["status"] == "lock_held"
    events = [e["event"] for e in o["lock_events"]]
    assert events == ["unreadable_marker_stood_down", "stood_down"], events
    assert "held_by_other_run" not in events, (
        "an unread marker was reported as a known holder - a playbook filtering for real "
        "contention now gets a false positive from the ordinary create-lag window")

    assert "LOCK MARKER UNREADABLE" in md
    assert "could not be read" in md
    assert "held by another run" not in md, (
        "the summary row still claims a holder the pass never established: %s"
        % [l for l in md.splitlines() if "held by another run" in l])


def test_the_identifier_lists_stay_plain_strings():
    """A dataset name is data already. Converting it would break any caller splicing the list
    where scalars are expected, and would buy nothing."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    o = _run(FakeTenant([ds, "yara_scanner_matches_v9_x_%s" % ANCIENT]),
             older_than_months="0", execute="true").outputs
    for key in ("selected", "deleted", "newer"):
        assert o[key], "%s went empty - this test stopped proving anything" % key
        for entry in o[key]:
            assert isinstance(entry, str), "%s holds a %s" % (key, type(entry).__name__)


def test_newer_is_a_documented_view_over_skipped_and_they_cannot_disagree():
    """Both are published, so the yml has to say which is authoritative - and the code has to
    keep the derivation true."""
    o = _run(FakeTenant(["yara_scanner_matches_v9_a_%s" % ANCIENT,
                         "yara_scanner_matches_v9_b_%s" % ANCIENT]),
             older_than_months="0").outputs
    assert o["newer"] == sorted(s["name"] for s in o["skipped"]
                                if s["reason"] == "newer_schema")
    assert o["newer_count"] == len(o["newer"]) == 2


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    t = FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                    "yara_scanner_matches_v2_g_%s" % ANCIENT])
    md = _run(t, older_than_months="0").readable_output
    assert md.startswith("### YARA dataset cleanup - DRY RUN")
    assert "\n|---|" in md, "no markdown table in the output"
    for heading in ("#### Would delete", "#### Kept - nothing was deleted",
                    "#### Settings this run used"):
        assert heading in md, "missing section: %s" % heading
    # the prose the tables replaced
    assert "candidate(s) kept, with reason:" not in md
    assert "  skip  " not in md and "scope: schema v" not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    t = FakeTenant(["yara_scanner_matches_v2_h%02d_%s" % (i, THIS_MONTH) for i in range(4)]
                   + ["yara_scanner_matches_v2_g_%s" % ANCIENT])
    res = _run(t, older_than_months="0")
    o, md = res.outputs, res.readable_output
    assert "| **Status** | `%s` |" % o["status"] in md
    assert "| **Kept** | %d candidate(s)" % o["skipped_count"] in md
    assert "| **Selected** | %d dataset(s)" % o["selected_count"] in md
    assert "| **Failed** | %d |" % o["failed_count"] in md
    assert "| `schema_version` | v%s |" % o["schema_version"] in md


def test_no_section_of_the_report_comes_from_outside_the_result_dict():
    """Two sections used to: the argument NOTEs, and a lock log scraped for the word "lock".
    Both are keys now, so re-rendering the stored context reproduces the entry exactly."""
    o = _run(LockStuck(["yara_scanner_matches_v2_h_%s" % ANCIENT]),
             older_than_months="-1", min_quiet_hours="0", execute="true")
    assert C.render_run_markdown(o.outputs) == o.readable_output
    assert "#### Warnings" in o.readable_output and "#### Lock events" in o.readable_output


def test_a_dry_run_and_an_executed_run_never_read_as_each_other():
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    dry = _run(FakeTenant([ds]), older_than_months="0").readable_output
    assert "DRY RUN" in dry and "#### Would delete" in dry

    md = _run(FakeTenant([ds]), older_than_months="0", execute="true").readable_output
    assert "DRY RUN" not in md and "#### Deleted - irreversibly" in md
    # `selected` is exactly deleted + failed once a pass has run, so it does not get a third
    # table saying the same thing - the yml says the same about the three keys.
    assert "#### Would delete" not in md


def test_the_markdown_truncates_but_the_context_does_not():
    """A 60-candidate tenant must not push the counts off the top of the War Room - and must
    not lose an entry to do it."""
    t = FakeTenant(["yara_scanner_matches_v2_h%03d_%s" % (i, THIS_MONTH) for i in range(60)])
    res = _run(t, older_than_months="0")
    assert len(res.outputs["skipped"]) == 60
    assert res.readable_output.count("`current_month`") == C._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.Cleanup.skipped`" in res.readable_output


def test_skips_are_grouped_by_reason_in_both_the_table_and_the_context():
    """Sixty candidates kept for four different reasons read as noise in name order."""
    t = FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                    "yara_scanner_matches_v2_h_%s" % NEXT_MONTH,
                    "yara_scanner_matches_v2_lonely",
                    "yara_scanner_matches_v1_old_%s" % ANCIENT])
    reasons = [s["reason"] for s in _run(t, older_than_months="0").outputs["skipped"]]
    assert reasons == sorted(reasons), "skipped is not grouped by reason"


def test_a_pipe_in_a_dataset_name_cannot_shear_the_table():
    """Escaping is the shared helper's job, but the renderer has to be routing cells through
    it - one unescaped pipe and every row below loses a column, silently."""
    rec = C._skipped_record("unclassified", "we|ird: something", name="we|ird", path="legacy")
    md = C.render_run_markdown({"status": "dry_run", "dry_run": True, "selected": [],
                                "deleted": [], "failed": [], "skipped": [rec],
                                "selected_count": 0, "deleted_count": 0, "failed_count": 0,
                                "skipped_count": 1, "newer_count": 0, "schema_version": "2",
                                "older_than_months": 0, "delete_legacy": False,
                                "min_quiet_hours": 24.0, "warnings": [], "lock_events": []})
    assert "we\\|ird" in md


# ------------------------------------------------------ the yml contract is not fiction

def _declared_outputs():
    import yaml
    with open(YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return [o["contextPath"][len("Yara.Cleanup."):] for o in doc["outputs"]]


def _scenarios():
    """Union across runs rather than one pass: no single run populates skipped, failed,
    warnings and lock_events at once, and requiring that would only prove something about a
    contrived tenant."""
    out = []
    out.append(_run(FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                                "yara_scanner_matches_v9_n_%s" % ANCIENT]),
                    older_than_months="0").outputs)
    t = DeleteRefused(["yara_scanner_matches_v2_bad_%s" % ANCIENT,
                       "yara_scanner_matches_v2_ok_%s" % ANCIENT])
    out.append(_run(t, older_than_months="0", execute="true").outputs)
    out.append(_run(LockStuck(["yara_scanner_matches_v2_h_%s" % ANCIENT]),
                    older_than_months="-1", min_quiet_hours="0", execute="true").outputs)
    out.append(_run(FakeTenant([]), older_than_months="0").outputs)
    return out


def test_every_declared_output_is_actually_produced():
    """The pack's own gate flattens a contextPath by stripping one prefix and checks a single
    scenario, so it can assert `skipped` exists but proves nothing about a key that only some
    scenarios populate. This walks into the lists across every scenario."""
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
        assert not undeclared, (
            "produced but never declared in the yml: %s" % undeclared)
        for key in ("skipped", "failed", "warnings", "lock_events"):
            for entry in o.get(key) or []:
                extra = sorted("%s.%s" % (key, k) for k in entry)
                assert set(extra) <= declared, (
                    "produced but never declared in the yml: %s"
                    % sorted(set(extra) - declared))


# ------------------------------- the summary row is a FACT, never a proxy for "not dry"
#
# The report's job is that an operator can trust it. A confidently wrong line is worse than
# the prose it replaced, and the Consolidation-lock row was derived from `not dry` - a proxy -
# so it asserted "taken and released by this run" on two paths where it is false. Each test
# below drives one of those paths and pins the corrected sentence; the last two are the
# positive controls that stop the fix from being vacuous.


def test_a_nothing_requested_pass_never_claims_it_took_the_lock():
    """execute=true with no window returns from prune_datasets BEFORE
    acquire_consolidation_lock is reached - the tenant sees not one API call - and the row
    still read "taken and released by this run". That is the shape of a scheduled job whose
    older_than_months templated out empty against a hard-coded execute=true."""
    t = FakeTenant(["yara_scanner_matches_v2_h_%s" % ANCIENT])
    res = _run(t, execute="true")
    assert res.outputs["status"] == "nothing_requested"
    assert t.calls == [], "the pass reached the tenant, so this no longer tests the claim"

    md = res.readable_output
    assert "| **Consolidation lock** | never taken - nothing was requested, so the pass " \
           "returned before acquiring it |" in md
    assert "taken and released by this run" not in md
    assert "| `execute` | true - but nothing was requested, so nothing was deleted |" in md
    assert "deletes were applied" not in md


def test_a_pass_that_could_not_release_the_lock_does_not_say_it_released_it():
    """The two halves of one report contradicted each other: the summary row said "taken and
    released", the Lock events table directly below said `release_failed`, and the summary row
    is the one read first. A lock left behind blocks the next run until it ages out - the
    single failure lock_events was added to surface."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    res = _run(LockStuck([ds]), older_than_months="0", execute="true")
    assert [e["event"] for e in res.outputs["lock_events"]] == ["release_failed"]

    md = res.readable_output
    assert "| **Consolidation lock** | taken, and NOT RELEASED - see Lock events; the marker " \
           "is still on the tenant and blocks the next run until it ages out |" in md
    assert "taken and released by this run" not in md
    # ... and the pass's real outcome is still reported, not replaced by the failed release.
    assert res.outputs["deleted"] == [ds]
    assert "| `execute` | true - 1 dataset(s) deleted, irreversibly |" in md


def test_a_pass_that_stood_down_on_a_held_lock_never_says_deletes_were_applied():
    """Same class of falsehood on a third path: execute=true, status=lock_held, nothing
    deleted, and the Settings table said "true - deletes were applied"."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = FakeTenant([ds, C._LOCK_DATASET])
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": int(time.time() * 1000) - 60_000}]
    res = _run(t, older_than_months="0", execute="true")
    assert res.outputs["status"] == "lock_held" and res.outputs["deleted"] == []

    md = res.readable_output
    assert "| **Consolidation lock** | held by another run - stood down |" in md
    assert "| `execute` | true - but another run held the lock, so nothing was deleted |" in md
    assert "deletes were applied" not in md


def test_an_uncontended_executed_pass_still_reports_the_lock_taken_and_released():
    """The positive control. The sentence must still be printed where it is TRUE, or the fix
    above is just a deletion."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    res = _run(FakeTenant([ds]), older_than_months="0", execute="true")
    assert res.outputs["status"] == "success" and res.outputs["lock_events"] == []
    md = res.readable_output
    assert "| **Consolidation lock** | taken and released by this run |" in md
    assert "| `execute` | true - 1 dataset(s) deleted, irreversibly |" in md


def test_a_dry_run_still_says_the_lock_was_not_taken():
    """The other positive control, and the one path where "not taken" was already right."""
    md = _run(FakeTenant(["yara_scanner_matches_v2_h_%s" % ANCIENT]),
              older_than_months="0").readable_output
    assert "| **Consolidation lock** | not taken - a dry run never takes it |" in md
    assert "| `execute` | false - nothing was deleted |" in md


def test_a_stale_marker_taken_over_is_still_called_a_takeover():
    """Third positive control: the takeover branch sits between the two new ones and must not
    have been shadowed by either."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = FakeTenant([ds, C._LOCK_DATASET])
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": int(time.time() * 1000)
                    - (C.PRUNE_LOCK_STALE_SECS + 3600) * 1000}]
    md = _run(t, older_than_months="0", execute="true").readable_output
    assert "| **Consolidation lock** | TAKEN OVER as stale - see the warning below |" in md
    assert "TOOK IT OVER" in md


# ------------------- the two fail-closed rails, when the TENANT writes half of the sentence


class ErrorTextCollides(FakeTenant):
    """A tenant whose API error TEXT contains the words a generic rail marker matches.

    FakeTenant's own `error_on` raises RuntimeError("tenant hiccup") - a string that collides
    with nothing, which is exactly why the drift guard above could not see this. Rails 6 and 7
    interpolate the raw exception into their sentence, so it is the TENANT, not this pack,
    that decides what the classifier is handed.
    """

    def __init__(self, names, on, message):
        FakeTenant.__init__(self, names)
        self._on, self._message = on, message

    def xql(self, query, limit=1000):
        if self._on in query:
            self.calls.append("xql:%s" % query)
            raise RuntimeError(self._message)
        return FakeTenant.xql(self, query, limit=limit)


@pytest.mark.parametrize("error_text", [
    "HTTP 400: query over current month partition failed",   # collides with current_month
    "XQL error: dataset dated in the future",                 # collides with future_month
    "no data in the 3-month window",                          # collides with inside_window
    "HTTP 502\n<html><body>current month</body></html>",      # multi-line, collides too
])
def test_a_failed_recency_check_is_rail_6_whatever_the_tenant_put_in_the_message(error_text):
    """The silently-wrong branch, inverted. `current month` / `dated in the future` /
    `-month window` were tested BEFORE the two "could not check ..." markers and matched the
    tenant's own error text, so a skip caused by a query that FAILED was attributed to rail 1
    or 2 - name-only rails that issue no query - and `error` came back empty, because the
    extraction only runs on the matching branch. A playbook filtering on
    reason=='recency_check_failed' saw nothing at all."""
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = ErrorTextCollides([ds], "comp max(event_timestamp_ms)", error_text)
    o = _run(t, older_than_months="0", execute="true").outputs

    kept = [s for s in o["skipped"] if s["name"] == ds]
    assert len(kept) == 1
    assert kept[0]["reason"] == "recency_check_failed", (
        "a rail that failed CLOSED was reported as %r" % kept[0]["reason"])
    assert kept[0]["rail"] == 6
    assert kept[0]["error"] == error_text, "the API's own error text was dropped"
    assert ds in t.names and o["deleted"] == [], "rail 6 must still fail closed"


@pytest.mark.parametrize("error_text", [
    "HTTP 400: comp over the current month is not supported",
    "XQL error: shard dated in the future",
    "empty result for the 3-month window",
])
def test_a_failed_consolidation_check_is_rail_7_whatever_the_tenant_put_in_the_message(
        error_text):
    ds = "yara_scanner_matches_v2_h_%s" % ANCIENT
    t = ErrorTextCollides([ds], "by scan_id", error_text)
    o = _run(t, older_than_months="0", execute="true").outputs

    kept = [s for s in o["skipped"] if s["name"] == ds]
    assert len(kept) == 1
    assert kept[0]["reason"] == "consolidation_check_failed"
    assert kept[0]["rail"] == 7
    assert kept[0]["error"] == error_text
    assert ds in t.names and o["deleted"] == []


def test_the_classifier_reads_the_template_it_owns_not_the_error_it_was_handed():
    """The unit-level statement of the same thing, on the three sentences reproduced live."""
    cases = [
        ("ds1: could not check recency (HTTP 400: query over current month partition failed)"
         " - skipping to be safe", "recency_check_failed", 6,
         "HTTP 400: query over current month partition failed"),
        ("ds1: could not check consolidation state (XQL error: dataset dated in the future)"
         " - skipping to be safe", "consolidation_check_failed", 7,
         "XQL error: dataset dated in the future"),
        ("ds1: could not check recency (no data in the 3-month window) - skipping to be safe",
         "recency_check_failed", 6, "no data in the 3-month window"),
    ]
    for text, reason, rail, err in cases:
        rec = C._classify_skip(text, "retention", ["ds1"])
        assert (rec["reason"], rec["rail"], rec["error"]) == (reason, rail, err), (
            "%r classified as %s (rail %s, error %r)"
            % (text, rec["reason"], rec["rail"], rec["error"]))


def test_the_generic_month_markers_still_classify_the_rails_that_own_them():
    """The positive control for the reordering: moving two markers up must not have taken the
    three generic ones out of service."""
    t = FakeTenant(["yara_scanner_matches_v2_h_%s" % THIS_MONTH,
                    "yara_scanner_matches_v2_h_%s" % NEXT_MONTH,
                    "yara_scanner_matches_v2_h_%s" % LAST_MONTH])
    by_name = {s["name"]: s for s in _run(FakeTenant(t.names), older_than_months="6")
               .outputs["skipped"]}
    assert by_name["yara_scanner_matches_v2_h_%s" % THIS_MONTH]["reason"] == "current_month"
    assert by_name["yara_scanner_matches_v2_h_%s" % NEXT_MONTH]["reason"] == "future_month"
    assert by_name["yara_scanner_matches_v2_h_%s" % LAST_MONTH]["reason"] == "inside_window"


# ------------------------------------------------------- the docs cite a symbol, not a line

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_no_document_cites_this_automation_by_line_number():
    """`Scripts/YaraCleanup/YaraCleanup.py:1332` was already 109 lines stale before the report
    rework and ~450 after it, and nothing anywhere failed. A line number in prose is a
    reference that rots silently on every edit above it; the symbol is the stable handle, and
    the same page already says so."""
    import re as _re
    offenders = []
    for root, dirs, files in os.walk(_REPO):
        dirs[:] = [d for d in dirs
                   if d not in (".git", ".venv", "__pycache__", "dist", "node_modules")]
        for fn in files:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if _re.search(r"YaraCleanup\.py:\d+", line):
                        offenders.append("%s:%d" % (os.path.relpath(path, _REPO), i))
    assert not offenders, (
        "these cite YaraCleanup.py by line number, which nothing keeps true - name the "
        "symbol instead: %s" % offenders)

    doc = os.path.join(_REPO, "xdr", "docs", "topics", "Datasets_and_Maintenance.md")
    with open(doc, encoding="utf-8") as fh:
        text = fh.read()
    assert "`prune_datasets` — `Scripts/YaraCleanup/YaraCleanup.py`" in text
    assert callable(getattr(C, "prune_datasets", None)), (
        "the doc names prune_datasets as this automation's entry point and it is not there")
