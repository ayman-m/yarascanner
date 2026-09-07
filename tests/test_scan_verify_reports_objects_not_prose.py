#!/usr/bin/env python3
"""YaraScanVerify's per-host result is CONTEXT, so it carries fields rather than sentences.

The automation used to publish the SAME per-host facts twice: a flat `started` list of
hostnames beside a nested `states` dict built from the same `seen` map in the adjacent line.
Two keys, one truth, and no way for a reader to tell which was authoritative - made worse by
the two disagreeing on case, because `started` carried the caller's spelling and `states` was
keyed on the lowercased one. A playbook joining them silently matched nothing for every
mixed-case host, which is exactly the kind of failure that reports no error anywhere.

So there is one authoritative structure now - `hosts`, a list of objects - and `reason` is a
CLOSED vocabulary. These tests pin both: the shapes, and the fact that the vocabularies stay
closed, because the entire value of a closed set is in it staying closed.

Three more properties are pinned here for reasons that are not obvious:

  * ABSENCE IS NOT ZERO. `match_rows` was a dict that stayed empty both when every host was
    clean and when the evidence query had failed, and the report then printed "no match rows
    yet - evidence only, never a failure: a clean host has none" over a query nobody could
    read. `match_evidence` splits those two, and `match_rows` is null rather than 0 when
    nothing was measured.

  * UNKNOWN IS NOT FALSE. On the lifecycle-failure path `hosts[].started` is null, and
    `started`/`not_started` stay EMPTY rather than declaring the whole wave un-started. A
    playbook filtering hosts on `started == false` must not sweep up a wave nobody could read
    and conclude it was dead - the one error this gate exists not to make.

  * THE READABLE OUTPUT IS RENDERED FROM THE RESULT DICT AND NOTHING ELSE. The old report
    computed len(started) / len(dispatched) / len(not_started) inline, and those counts lived
    in no context key at all, so an operator could read a number a playbook had no way to
    reproduce. They are context keys now, and the report quotes them.
"""
import importlib.util
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    _install_xsoar_stubs, _run_automation,
)

_install_xsoar_stubs()

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PY = os.path.join(_ROOT, "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                   "YaraScanVerify", "YaraScanVerify.py")
_YML = os.path.join(_ROOT, "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                    "YaraScanVerify", "YaraScanVerify.yml")
spec = importlib.util.spec_from_file_location("YaraScanVerify", _PY)
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

# Relative to the real clock, deliberately. main() stamps nothing from time.time() itself, but
# the dispatch bound it enforces is an epoch-millisecond one, and a fixture pinned to a fixed
# epoch would put every lifecycle row far in the past the moment anyone compared the two.
NOW_MS = int(time.time() * 1000)
DISPATCH = NOW_MS - 5 * 60 * 1000


class FakeWave:
    """Answers the two comp queries the verifier makes, and nothing else.

    FakeTenant in test_pack_data_management.py models the lookup-dataset reads the five
    consolidation automations make - `by scan_id` groupings over named shards. This automation
    reads neither: it fans in over `yara_scanner_scans*` grouping `by hostname, status`, which
    FakeTenant answers with a `newest` row of the wrong shape. So the wave fixture is local,
    the way tests/test_scan_verify.py already keeps one; `_run_automation` is the shared piece
    that matters here, because it is what drives main() and hands back both halves of the
    contract - the context AND the readable output that has to agree with it.
    """

    def __init__(self, scans=(), matches=(), fail_lifecycle=False, fail_matches=False):
        self.scans = list(scans)      # (hostname, status, ts)
        self.matches = list(matches)  # (hostname, n)
        self.fail_lifecycle = fail_lifecycle
        self.fail_matches = fail_matches
        self.queries = []

    def xql(self, query, limit=1000):
        self.queries.append(query)
        if "yara_scanner_scans" in query:
            if self.fail_lifecycle:
                raise RuntimeError("tenant hiccup")
            return [{"hostname": h, "status": s, "ts": t} for h, s, t in self.scans]
        if self.fail_matches:
            raise RuntimeError("evidence read timed out")
        return [{"hostname": h, "n": n} for h, n in self.matches]


def _wave(started=(), quiet=(), matches=(), **kw):
    """A wave where `started` hosts have written a lifecycle row and `quiet` ones have not."""
    scans = [(h, "initiated", DISPATCH + 17000) for h in started]
    return FakeWave(scans=scans, matches=matches, **kw), list(started) + list(quiet)


def _run(client, hostnames, **args):
    a = {"hostnames": ",".join(hostnames), "dispatch_ms": str(DISPATCH)}
    a.update(args)
    return _run_automation(V, a, client, pin_schema=False)


HOST_KEYS = {"hostname", "started", "states", "match_rows", "match_evidence",
             "reason", "detail"}
ERROR_KEYS = {"reason", "detail", "stage", "exception", "fatal"}


# ------------------------------------------------------------------- the two lists

def test_every_entry_in_hosts_and_errors_is_an_object():
    """The whole point. One string among the objects is the silent failure mode - and the old
    renderer's `", ".join(result["started"])` would have raised TypeError on a dict the moment
    anyone structured one of these lists, which is why that line is gone."""
    c, names = _wave(started=["a", "b"], quiet=["c"], matches=[("a", 122)])
    res = _run(c, names)
    for key in ("hosts", "errors"):
        for entry in res.outputs[key]:
            assert isinstance(entry, dict), (
                "%s holds a bare %s - a playbook filtering on a field would silently match "
                "nothing: %r" % (key, type(entry).__name__, entry))


def test_a_host_entry_carries_every_key_on_every_path():
    """A key present on only some entries is a transformer that matches some of the time,
    which is worse than one that never does."""
    c, names = _wave(started=["a"], quiet=["b"], matches=[("a", 122)])
    hosts = _run(c, names).outputs["hosts"]
    assert len(hosts) == 2
    for h in hosts:
        assert set(h) == HOST_KEYS, "host record shape drifted: %s" % sorted(h)
        assert h["reason"] and h["detail"] and h["match_evidence"]

    by_name = {h["hostname"]: h for h in hosts}
    assert by_name["a"]["started"] is True
    assert by_name["a"]["states"] == ["initiated"]
    assert by_name["a"]["match_rows"] == 122
    assert by_name["a"]["match_evidence"] == "observed"
    assert by_name["a"]["reason"] == "started"
    assert by_name["b"]["started"] is False
    assert by_name["b"]["states"] == []
    assert by_name["b"]["match_rows"] == 0
    assert by_name["b"]["reason"] == "no_lifecycle_row"


def test_hosts_carries_the_callers_spelling_not_the_lifecycle_rows():
    """The case bug that made `started` and the old `states` dict unjoinable: one carried the
    caller's spelling and the other the lowercased key, and the yml said which nowhere."""
    c = FakeWave(scans=[("XDR-Agent", "initiated", DISPATCH + 17000)])
    res = _run(c, ["xdr-agent"])
    assert res.outputs["verdict"] == "ok"
    assert [h["hostname"] for h in res.outputs["hosts"]] == ["xdr-agent"]
    assert res.outputs["started"] == ["xdr-agent"]
    # and the two lists join with no lowercasing at all
    assert set(res.outputs["started"]) == {h["hostname"] for h in res.outputs["hosts"]
                                           if h["started"]}


def test_the_flat_lists_are_exactly_the_hosts_list_restated():
    """dispatched/started/not_started survive because they are the branch-friendly partition.
    They are KEPT, not authoritative - so they must never be able to disagree with `hosts`."""
    c, names = _wave(started=["a", "c"], quiet=["b", "d"])
    o = _run(c, names).outputs
    assert o["dispatched"] == sorted(h["hostname"] for h in o["hosts"])
    assert o["started"] == sorted(h["hostname"] for h in o["hosts"] if h["started"] is True)
    assert o["not_started"] == sorted(h["hostname"] for h in o["hosts"]
                                      if h["started"] is False)
    assert o["dispatched_count"] == len(o["dispatched"])
    assert o["started_count"] == len(o["started"])
    assert o["not_started_count"] == len(o["not_started"])


def test_started_and_not_started_partition_dispatched_exactly():
    """The invariant the yml now states and nothing previously asserted. A future filter
    change - counting a host with match rows but no lifecycle row, say - would break it
    silently, and a playbook branching on not_started would quietly act on the wrong set."""
    c, names = _wave(started=["a", "c"], quiet=["b", "d"])
    o = _run(c, names).outputs
    assert o["verdict"] == "partial"
    assert sorted(o["started"] + o["not_started"]) == o["dispatched"]
    assert not set(o["started"]) & set(o["not_started"])


def test_no_result_key_holds_the_same_per_host_facts_twice():
    """`states` and `match_rows` were the nested-and-flat restatements this rework removed.
    They live on the host record now, and nowhere else."""
    c, names = _wave(started=["a"], quiet=["b"], matches=[("a", 5)])
    o = _run(c, names).outputs
    assert "states" not in o, (
        "`states` is back - it restates hosts[].states, keyed on a different spelling")
    assert "match_rows" not in o, (
        "`match_rows` is back - it restates hosts[].match_rows")
    assert "error" not in o, "the scalar `error` is back - it restates errors[0].detail"


# ------------------------------------------------- unknown is not false, absence is not zero

def test_a_failed_lifecycle_query_reports_unknown_per_host_rather_than_not_started():
    """The one error this gate must not make. `wave_dead` on a query error would page an
    analyst about a healthy wave; `started == false` per host is the same claim wearing a
    different hat, and a transformer would happily act on it."""
    c, names = _wave(started=["a", "b"], fail_lifecycle=True)
    o = _run(c, names).outputs
    assert o["verdict"] == "unknown"
    assert o["hosts"] and len(o["hosts"]) == 2, "hosts must cover the wave on every path"
    for h in o["hosts"]:
        assert set(h) == HOST_KEYS
        assert h["started"] is None, "false here reads as evidence the host did not start"
        assert h["reason"] == "lifecycle_unreadable"
        assert h["states"] == [] and h["match_rows"] is None
    # and no host is placed in either half of a partition nobody could compute
    assert o["started"] == [] and o["not_started"] == []
    assert o["dispatched"] == ["a", "b"], "the dispatched list is still known"


def test_an_unreadable_match_query_is_unavailable_not_zero():
    """`match_rows` used to stay {} on this path, indistinguishable from a clean fleet, and
    the report then asserted a fact not in evidence."""
    c, names = _wave(started=["a"], fail_matches=True)
    o = _run(c, names).outputs
    assert o["verdict"] == "ok", "an evidence failure must never move the verdict"
    assert o["match_evidence"] == "unavailable"
    assert o["match_rows_total"] is None, "0 here is a measurement nobody made"
    assert o["hosts"][0]["match_rows"] is None
    assert o["hosts"][0]["match_evidence"] == "unavailable"
    assert [e["reason"] for e in o["errors"]] == ["match_query_failed"]
    assert o["errors"][0]["fatal"] is False


def test_a_clean_fleet_is_none_yet_and_says_so():
    c, names = _wave(started=["a", "b"], matches=[])
    o = _run(c, names).outputs
    assert o["match_evidence"] == "none_yet"
    assert o["match_rows_total"] == 0
    assert all(h["match_rows"] == 0 for h in o["hosts"])
    assert o["errors"] == [] and o["error_count"] == 0


def test_match_evidence_rolls_up_so_unavailable_dominates():
    """The computed verdict a caller would get wrong: one host with rows does not make a wave
    whose evidence query failed 'observed'."""
    c, names = _wave(started=["a", "b"], matches=[("a", 3)])
    assert _run(c, names).outputs["match_evidence"] == "observed"
    c2, names2 = _wave(started=["a", "b"], matches=[("a", 3)], fail_matches=True)
    assert _run(c2, names2).outputs["match_evidence"] == "unavailable"


def test_a_host_with_match_rows_but_no_lifecycle_row_says_what_that_means():
    """Reachable: match rows are keyed on the dispatched set, not on the started set. Left
    unexplained it reads as a contradiction between two tables."""
    c, names = _wave(started=["a"], quiet=["b"], matches=[("b", 9)])
    o = _run(c, names).outputs
    b = [h for h in o["hosts"] if h["hostname"] == "b"][0]
    assert b["started"] is False and b["match_rows"] == 9
    assert b["reason"] == "no_lifecycle_row"
    assert "not that the scan never started" in b["detail"]


# ------------------------------------------------------- the vocabularies stay closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason code invented at a call site and never declared is exactly as unmatchable as
    the prose this replaced - it just looks like a contract."""
    scenarios = [
        _wave(started=["a"], quiet=["b"], matches=[("a", 1)]),
        _wave(started=["a", "b"]),
        _wave(started=["a"], fail_matches=True),
        _wave(started=["a", "b"], fail_lifecycle=True),
        _wave(quiet=["a", "b"]),
    ]
    for c, names in scenarios:
        o = _run(c, names).outputs
        for h in o["hosts"]:
            assert h["reason"] in V.HOST_REASONS, (
                "undeclared host reason %r - add it to HOST_REASONS or use an existing one"
                % h["reason"])
            assert h["match_evidence"] in V.MATCH_EVIDENCE, (
                "undeclared match_evidence %r" % h["match_evidence"])
        for e in o["errors"]:
            assert e["reason"] in V.ERROR_REASONS, "undeclared error reason %r" % e["reason"]
        assert o["match_evidence"] in V.MATCH_EVIDENCE
        assert o["verdict"] in ("ok", "partial", "wave_dead", "unknown")


def test_the_vocabularies_are_the_ones_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    described = _described()
    for code in V.HOST_REASONS:
        assert code in described["Yara.ScanVerify.hosts.reason"], (
            "host reason %r is not in the yml's declared closed set" % code)
    for code in V.ERROR_REASONS:
        assert code in described["Yara.ScanVerify.errors.reason"], (
            "error reason %r is not in the yml's declared closed set" % code)
    for code in V.MATCH_EVIDENCE:
        assert code in described["Yara.ScanVerify.match_evidence"], (
            "match evidence %r is not in the yml's declared closed set" % code)
        assert code in described["Yara.ScanVerify.hosts.match_evidence"]


def test_an_error_record_says_whether_it_cost_us_the_verdict():
    """`fatal` folds in the rule a caller would get wrong - that a failed match query removes
    evidence and nothing else - so nobody has to know which stage is which."""
    c, names = _wave(started=["a"], fail_lifecycle=True)
    o = _run(c, names).outputs
    assert o["errors"], "the unreadable lifecycle should have been recorded"
    for e in o["errors"]:
        assert set(e) == ERROR_KEYS, "error record shape drifted: %s" % sorted(e)
        assert e["stage"] and e["exception"]
    assert o["errors"][0]["reason"] == "lifecycle_query_failed"
    assert o["errors"][0]["fatal"] is True and o["verdict"] == "unknown"
    assert all(e["fatal"] is (e["reason"] in V.FATAL_ERROR_REASONS) for e in o["errors"])


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    """XSOAR renders readable_output AS markdown, so the five plain sentences the old version
    joined with single newlines collapsed into one run-on paragraph."""
    c, names = _wave(started=["a"], quiet=["b"], matches=[("a", 122)])
    md = _run(c, names).readable_output
    assert md.startswith("### YARA wave verification - PARTIAL")
    assert "\n|---|" in md, "no markdown table in the output"
    for heading in ("#### Hosts",):
        assert heading in md, "missing section: %s" % heading
    # the prose the tables replaced
    assert "started: a" not in md and "no row yet: b" not in md
    assert "match rows already landed:" not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see - which is
    exactly what len(result["started"]) inline used to be."""
    c, names = _wave(started=["a", "c"], quiet=["b", "d"], matches=[("a", 7)])
    res = _run(c, names)
    o, md = res.outputs, res.readable_output
    assert "| **Dispatched** | %d |" % o["dispatched_count"] in md
    assert "| **Started** | %d |" % o["started_count"] in md
    assert "| **No lifecycle row yet** | %d |" % o["not_started_count"] in md
    assert "`%s`" % o["match_evidence"] in md
    assert "%d of %d host(s) started" % (o["started_count"], o["dispatched_count"]) in md


def test_the_unknown_report_claims_no_counts_it_does_not_have():
    """not_started_count is 0 on this path because not_started is empty, and printing a bare
    0 would read as 'every host started'."""
    c, names = _wave(started=["a", "b"], fail_lifecycle=True)
    res = _run(c, names)
    md = res.readable_output
    assert md.startswith("### YARA wave verification - UNKNOWN")
    assert "| **Started** | unknown - the lifecycle query failed |" in md
    assert "| **No lifecycle row yet** | unknown" in md
    assert "#### Errors" in md and "`lifecycle_query_failed`" in md


def test_a_pipe_in_a_hostname_cannot_shear_the_table():
    """Hostnames reach here from an endpoint. One unescaped pipe and every row below it loses
    a column - silently, since markdown does not error."""
    row = V._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    """The old renderer hard-capped its host lists at 20 names with NO overflow note, so on a
    200-host wave an operator saw 20 and no sign the other 180 existed."""
    names = ["simhost%03d" % i for i in range(1, 61)]
    c = FakeWave(scans=[])
    res = _run(c, names)
    assert len(res.outputs["hosts"]) == 60
    assert res.readable_output.count("`no_lifecycle_row`") == V._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.ScanVerify.hosts`" in res.readable_output


def test_hosts_are_grouped_by_reason_so_the_problems_come_first():
    """60 hosts in hostname order read as noise; the operator wants the ones that did not
    start adjacent to each other."""
    c, names = _wave(started=["a", "c", "e"], quiet=["b", "d", "f"])
    reasons = [h["reason"] for h in _run(c, names).outputs["hosts"]]
    assert reasons == sorted(reasons), "hosts is not grouped by reason"
    assert reasons[0] == "no_lifecycle_row", "the hosts needing attention are not first"


def test_the_context_is_cleared_before_it_is_written():
    """List-valued context is APPENDED to across calls in one investigation, so a second
    verification pass would otherwise merge both waves' host lists."""
    from test_pack_data_management import demistomock
    c, names = _wave(started=["a"])
    res = _run(c, names)
    assert ("DeleteContext", {"key": "Yara.ScanVerify"}) in demistomock.commands
    assert res.outputs_prefix == "Yara.ScanVerify"


# ------------------------------------------------------ the yml contract is not fiction

def _yml_outputs():
    import yaml
    with open(_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["outputs"]


def _described():
    return {o["contextPath"]: o["description"] for o in _yml_outputs()}


def _declared_outputs():
    return [o["contextPath"][len("Yara.ScanVerify."):] for o in _yml_outputs()]


def _scenarios():
    """No single run populates hosts, errors and both evidence states at once, and requiring
    that would only prove something about a contrived wave."""
    return [_run(c, names).outputs for c, names in (
        _wave(started=["a"], quiet=["b"], matches=[("a", 122)]),
        _wave(started=["a", "b"], fail_lifecycle=True),
        _wave(started=["a"], fail_matches=True),
        _wave(quiet=["a", "b"]),
    )]


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this covers YaraCleanup and YaraReport only, and it flattens a
    contextPath by stripping one prefix, so it cannot express `hosts.reason`. This automation
    declares its object keys, which is the whole point of declaring them."""
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


def test_the_yml_declares_every_key_of_both_object_lists():
    """A stable key set is only a contract if the contract is written down. Declaring six of
    seven keys is how a transformer comes to filter on a field nobody documented."""
    declared = set(_declared_outputs())
    assert {"hosts.%s" % k for k in HOST_KEYS} <= declared, (
        "undeclared host keys: %s" % sorted({"hosts.%s" % k for k in HOST_KEYS} - declared))
    assert {"errors.%s" % k for k in ERROR_KEYS} <= declared, (
        "undeclared error keys: %s" % sorted({"errors.%s" % k for k in ERROR_KEYS} - declared))


def test_the_yml_says_which_key_is_authoritative():
    """The actual defect being fixed was not that two keys held the same data - it was that a
    reader could not tell which one to trust."""
    described = _described()
    assert "AUTHORITATIVE" in described["Yara.ScanVerify.hosts"]
    for kept in ("dispatched", "started", "not_started"):
        assert "hosts" in described["Yara.ScanVerify.%s" % kept], (
            "%s does not say how it relates to hosts" % kept)
    assert "INVARIANT" in described["Yara.ScanVerify.started"]


# ------------------------- the report may only claim a failure that actually happened

def _drive(args):
    """main() with the stubs, for an ARGUMENT GUARD.

    `_run_automation` asserts that nothing errored, so it cannot exercise a refusal. The
    harness's return_error raises SystemExit, standing in for the way return_error aborts a
    script on a tenant. Returns the message it refused with.
    """
    from test_pack_data_management import CommonServerPython as csp, demistomock as dm
    dm.args_value = dict(args)
    dm.commands = []
    del csp.results[:]
    del csp.errors[:]
    with pytest.raises(SystemExit):
        V.main()
    assert len(csp.errors) == 1, csp.errors
    assert not csp.results, (
        "the run published a result as well as refusing - a playbook would branch on context "
        "written by a run that errored: %r" % csp.results)
    return csp.errors[0]


def test_a_lifecycle_failure_never_claims_a_match_query_that_was_never_issued():
    """THE defect: one vocabulary word doing double duty for two states, reintroduced at the
    roll-up. verify_wave returns on the lifecycle failure BEFORE the match query is issued, so
    nothing about the match query failed - but match_evidence was left at its initialiser
    `unavailable`, whose declared meaning is "the match query failed", and the renderer keyed
    both the facts row and the evidence sentence on `match_rows_total is None`. The report then
    stated a second failure that its own Errors table - one row, `lifecycle_query_failed` -
    did not list. An operator cannot audit a report that invents a failure."""
    c, names = _wave(started=["a", "b"], fail_lifecycle=True)
    res = _run(c, names)
    o, md = res.outputs, res.readable_output

    # the query really was never issued, so the fixture never saw it
    assert not any("yara_scanner_matches" in q for q in c.queries), (
        "the fixture answered a match query - this path no longer skips it, so the test is "
        "asserting against the wrong scenario")

    assert o["match_evidence"] == "not_attempted", (
        "`unavailable` here asserts a match-query failure on a path where the query was "
        "never issued")
    assert all(h["match_evidence"] == "not_attempted" for h in o["hosts"])
    assert o["match_rows_total"] is None and all(h["match_rows"] is None for h in o["hosts"])

    assert "the evidence query failed" not in md, (
        "the report claims the evidence query failed; it was never run:\n%s" % md)
    assert "the match query failed" not in md
    assert "the match query was never issued" in md
    assert "`not_attempted`" in md


def test_no_failure_named_in_the_report_is_absent_from_its_own_errors_table():
    """The general form of the defect, so the next renderer edit cannot reintroduce it under
    a different sentence: a failure code may appear in the body only if `errors` holds it."""
    for c, names in (_wave(started=["a", "b"], fail_lifecycle=True),
                     _wave(started=["a"], fail_matches=True),
                     _wave(started=["a"], quiet=["b"], matches=[("a", 3)])):
        res = _run(c, names)
        happened = {e["reason"] for e in res.outputs["errors"]}
        for reason in V.ERROR_REASONS:
            if reason not in happened:
                assert reason not in res.readable_output, (
                    "the report names `%s`, which is in no `errors` entry, so an operator "
                    "reading the Errors table cannot find the failure it describes:\n%s"
                    % (reason, res.readable_output))


def test_a_match_query_that_really_did_fail_is_still_reported_as_a_failure():
    """The other half of the split. Making the lifecycle path honest must not make the match
    path silent - `unavailable` still means the query ran and failed, and still says so."""
    c, names = _wave(started=["a"], fail_matches=True)
    res = _run(c, names)
    assert res.outputs["match_evidence"] == "unavailable"
    md = res.readable_output
    assert "| **Match rows since dispatch** | not known - the evidence query failed |" in md
    assert "the match query was never issued" not in md
    assert "`match_query_failed`" in md and "#### Errors" in md


def test_a_hostnames_argument_that_resolves_to_no_host_is_refused():
    """A comma-only string is what a transformer that resolved no endpoints hands over, and
    required:true in the yml blocks a MISSING argument, not an empty one. It used to produce
    verdict `ok` under "All 0 dispatched host(s) are scanning" - a wave dispatched to nobody
    reading as a passing gate."""
    msg = _drive({"hostnames": ", ,  ,", "dispatch_ms": str(DISPATCH)})
    assert "hostnames" in msg and "nobody" in msg
    msg = _drive({"hostnames": "   ", "dispatch_ms": str(DISPATCH)})
    assert "hostnames" in msg


def test_a_real_host_beside_empty_entries_still_runs():
    """The guard must reject an empty LIST, not punish a trailing comma."""
    c = FakeWave(scans=[("a", "initiated", DISPATCH + 17000)])
    o = _run(c, ["a", "", " "]).outputs
    assert o["verdict"] == "ok" and o["dispatched"] == ["a"]


# --------------------------------------------- the closed vocabularies are load-bearing

def test_an_undeclared_reason_cannot_be_recorded_at_all():
    """HOST_REASONS and ERROR_REASONS were declarative only - nothing in the implementation
    read either, so a reason invented at a call site shipped the moment someone added one
    without also editing this file. The constants close the set themselves now."""
    ok = dict(hostname="a", started=True, states=["initiated"], match_rows=0,
              match_evidence="none_yet", reason="started", detail="fine")
    assert V._host_record(**ok)["reason"] == "started"
    for bad in ({"reason": "host_is_sad"}, {"match_evidence": "probably_fine"}):
        kw = dict(ok, **bad)
        with pytest.raises(ValueError) as e:
            V._host_record(**kw)
        assert "CLOSED" in str(e.value)

    assert V._error_record("match_query_failed", "d", "match_evidence", "x")["fatal"] is False
    with pytest.raises(ValueError) as e:
        V._error_record("the_tenant_was_grumpy", "d", "match_evidence", "x")
    assert "CLOSED" in str(e.value)


def test_an_unexpected_match_evidence_degrades_the_sentence_rather_than_the_run():
    """MATCH_EVIDENCE was consumed by unchecked subscript, so a value outside the vocabulary
    raised KeyError inside the renderer - throwing away a completed verification, after both
    queries had already run, to save a caption."""
    c, names = _wave(started=["a"])
    result = V.verify_wave(c, names, DISPATCH)
    result["match_evidence"] = "something_new"
    md = V.render_run_markdown(result)
    assert "`something_new`" in md
    assert "not in the declared vocabulary" in md
