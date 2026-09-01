"""The consolidation playbook's two modes, checked against the automations they call.

A playbook task and the automation behind it are two files that agree only by convention:
XSOAR resolves `task.script` by NAME at run time and hands over whatever `scriptarguments`
the task carries. Nothing at author time rejects a task that calls a script which is not in
the pack, or that passes an argument the script never declares (YaraConsolidateSummary takes
no `row_ceiling`, which the full-detail branch passes to YaraConsolidateApply on the very
next line of the same file). Both mistakes surface as a failing scheduled Job, hours later.

The mode branch adds a second failure shape worth pinning: a mode value that matches neither
label must reach the dead-end task, NOT fall through to the branch that deletes per-host
shards. That is a routing property of the yml, so it is asserted on the yml.
"""
import os

import pytest
import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PACK = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement")
_PLAYBOOK = os.path.join(_PACK, "Playbooks", "playbook-YARA_Dataset_Consolidation.yml")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def pb():
    return _load(_PLAYBOOK)


def _script_tasks(pb):
    return {tid: t for tid, t in pb["tasks"].items()
            if (t["task"].get("script") or "").startswith("Yara")}


def test_every_task_calls_an_automation_this_pack_actually_ships(pb):
    for tid, t in _script_tasks(pb).items():
        name = t["task"]["script"]
        assert os.path.exists(os.path.join(_PACK, "Scripts", name, "%s.yml" % name)), \
            "task %s calls %s, which is not a content item in this pack" % (tid, name)


def test_no_task_passes_an_argument_its_automation_does_not_declare(pb):
    for tid, t in _script_tasks(pb).items():
        name = t["task"]["script"]
        declared = {a["name"] for a in _load(
            os.path.join(_PACK, "Scripts", name, "%s.yml" % name))["args"]}
        passed = set(t.get("scriptarguments") or {})
        assert passed <= declared, "task %s (%s) passes undeclared %s" % (
            tid, name, sorted(passed - declared))


def test_the_two_modes_route_to_the_two_different_automations(pb):
    gate = pb["tasks"]["11"]
    routes = {c["label"]: gate["nexttasks"][c["label"]][0] for c in gate["conditions"]}
    assert pb["tasks"][routes["full"]]["task"]["script"] == "YaraConsolidateApply"
    assert pb["tasks"][routes["summary"]]["task"]["script"] == "YaraConsolidateSummary"


def test_an_unrecognised_mode_reaches_neither_automation(pb):
    """The fail-safe. `#default#` must land on a task that runs no script at all — falling
    through to the full-detail branch would DELETE per-host shards on a typo."""
    dead_end = pb["tasks"]["11"]["nexttasks"]["#default#"][0]
    seen, stack = set(), [dead_end]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for nxt in (pb["tasks"][n].get("nexttasks") or {}).values():
            stack.extend(nxt or [])
    for n in seen:
        assert not (pb["tasks"][n]["task"].get("script") or "").startswith("Yara"), \
            "an unrecognised consolidation_mode can still reach %s via task %s" % (
                pb["tasks"][n]["task"]["script"], n)


def test_the_default_mode_is_the_pre_existing_behaviour(pb):
    """Anyone upgrading a scheduled Job that predates this input keeps the merge they had."""
    mode = {i["key"]: i for i in pb["inputs"]}["consolidation_mode"]
    assert mode["value"]["simple"] == "full"
    assert mode["required"] is False


def test_the_summary_branch_is_not_left_as_a_permanent_dry_run(pb):
    """YaraConsolidateSummary writes nothing unless execute=true. A scheduled Job in summary
    mode with this defaulted the other way would report forever and never write a row."""
    assert {i["key"]: i for i in pb["inputs"]}["summary_execute"]["value"]["simple"] == "true"
    assert pb["tasks"]["12"]["scriptarguments"]["execute"]["simple"] == "${inputs.summary_execute}"


def test_the_pre_existing_inputs_still_reach_the_tasks_that_read_them(pb):
    keys = {i["key"] for i in pb["inputs"]}
    assert {"scan_id", "poll_interval_minutes", "poll_timeout_minutes",
            "row_ceiling", "retention_hours"} <= keys
    # Renamed from abandoned_after_hours, which named a different concept from the argument it
    # was wired to: all three automation tasks pass it as retention_hours, and not one of them
    # accepts anything called abandoned_after_hours.
    assert "abandoned_after_hours" not in keys
    assert pb["tasks"]["6"]["scriptarguments"]["row_ceiling"]["simple"] == "${inputs.row_ceiling}"
    assert pb["tasks"]["1"]["scriptarguments"]["scan_id"]["simple"] == "${inputs.scan_id}"


def test_every_task_target_exists_and_nothing_is_orphaned(pb):
    tasks = pb["tasks"]
    seen, stack = set(), [pb["starttaskid"]]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for nxt in (tasks[n].get("nexttasks") or {}).values():
            for x in (nxt or []):
                assert x in tasks, "task %s points at missing task %s" % (n, x)
                stack.append(x)
    assert seen == set(tasks), "unreachable task(s): %s" % sorted(set(tasks) - seen, key=int)


def test_no_input_is_declared_without_being_used(pb):
    """Every declared input must be referenced by some task.

    Two phantoms had accumulated: `max_scans`, which belongs to the retired per-scan path and
    which no automation accepts, and `abandoned_after_hours`, which was wired to a differently
    named argument. Both put a control in front of an operator that did nothing when set, and
    neither failed anything - a playbook is happy to declare inputs nobody reads.

    Checking the property rather than the two names, so the next one is caught on arrival.
    """
    import re
    text = open(_PLAYBOOK).read()
    referenced = set(re.findall(r"inputs\.([A-Za-z_][A-Za-z0-9_]*)", text))
    declared = {i["key"] for i in pb["inputs"]}
    phantom = sorted(declared - referenced)
    assert not phantom, (
        "declared but referenced by no task: %s - wire them up or remove them" % phantom)


def test_every_input_a_task_reads_is_declared(pb):
    """The other direction: a task referencing an undeclared input resolves to empty at runtime
    and the failure is silent, because the playbook still runs."""
    import re
    text = open(_PLAYBOOK).read()
    referenced = set(re.findall(r"inputs\.([A-Za-z_][A-Za-z0-9_]*)", text))
    declared = {i["key"] for i in pb["inputs"]}
    undeclared = sorted(referenced - declared)
    assert not undeclared, "tasks read inputs that are not declared: %s" % undeclared
