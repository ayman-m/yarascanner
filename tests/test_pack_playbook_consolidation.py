"""The consolidation playbook, checked against the automation it calls.

A playbook task and the automation behind it are two files that agree only by convention:
XSOAR resolves `task.script` by NAME at run time and hands over whatever `scriptarguments`
the task carries. Nothing at author time rejects a task that calls a script which is not in
the pack, or that passes an argument the script never declares. Both mistakes surface as a
failing scheduled Job, hours later.

This playbook used to branch on a `consolidation_mode` input between full-detail
(YaraConsolidateApply) and summary (YaraConsolidateSummary) consolidation, with a separate
readiness-check/poll section (YaraConsolidateStatus, GenericPolling) gating both. All of that
was removed: YaraConsolidateSummary is dry-run-by-default and computes its own eligibility
internally, so the separate gate was pure overhead - and it was measured timing out at scale
on a live tenant, which is what triggered the rebuild. Full-detail consolidation is a separate
automation this playbook no longer calls at all; invoke it directly if full detail is ever
needed again. What's left is a straight line: clear context -> summarise -> flag failures.
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


def test_the_playbook_calls_only_the_summary_automation(pb):
    """The full-detail path (YaraConsolidateApply) and the readiness gate
    (YaraConsolidateStatus) were removed deliberately - pin that neither can silently creep
    back in via a copy-pasted task."""
    yara_scripts = {t["task"]["script"] for t in _script_tasks(pb).values()}
    assert yara_scripts == {"YaraConsolidateSummary"}, (
        "expected only YaraConsolidateSummary among Yara* tasks, found %s" % sorted(yara_scripts))


def test_the_summary_task_passes_execute(pb):
    """YaraConsolidateSummary is dry-run-by-default. A task that omits execute reports what
    it would write and writes nothing, silently, on every scheduled run for ever."""
    summary_task = next(t for t in pb["tasks"].values()
                        if (t.get("task") or {}).get("script") == "YaraConsolidateSummary")
    args = summary_task.get("scriptarguments") or {}
    assert "execute" in args, (
        "the playbook's summarise task does not pass execute - it would dry-run for ever "
        "and never write")
    assert args["execute"] == {"simple": "${inputs.execute}"}, args["execute"]


def test_the_playbook_declares_an_execute_input_defaulting_true(pb):
    inputs = {i["key"]: i for i in pb["inputs"]}
    assert "execute" in inputs, "playbook has no execute input"
    assert inputs["execute"]["value"]["simple"] == "true", (
        "execute must default to true, or every scheduled pass is a no-op")


def test_the_scan_id_input_reaches_the_summary_task(pb):
    """Restricting a manual run to specific scan_id(s) must actually reach the automation
    that reads it - this was declared but silently unwired to a status-check task's context
    output instead, until the playbook was rebuilt around a single automation call."""
    keys = {i["key"] for i in pb["inputs"]}
    assert {"scan_id", "retention_hours", "execute"} <= keys
    summary_task = next(t for t in pb["tasks"].values()
                        if (t.get("task") or {}).get("script") == "YaraConsolidateSummary")
    args = summary_task["scriptarguments"]
    assert args["scan_id"] == {"simple": "${inputs.scan_id}"}, args["scan_id"]
    assert args["retention_hours"] == {"simple": "${inputs.retention_hours}"}, \
        args["retention_hours"]


def test_no_stale_mode_input_remains(pb):
    """consolidation_mode / full_execute / row_ceiling / poll_interval_minutes /
    poll_timeout_minutes all belonged to the removed two-mode, gated design. Declaring one
    would put a control in front of an operator that is wired to nothing."""
    keys = {i["key"] for i in pb["inputs"]}
    stale = {"consolidation_mode", "full_execute", "row_ceiling",
             "poll_interval_minutes", "poll_timeout_minutes"}
    assert not (keys & stale), "stale mode-era input(s) still declared: %s" % sorted(keys & stale)


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

    Two phantoms had accumulated in the old two-mode design: `max_scans`, which belonged to
    a retired per-scan path and which no automation accepted, and `abandoned_after_hours`,
    which was wired to a differently named argument. Both put a control in front of an
    operator that did nothing when set, and neither failed anything - a playbook is happy to
    declare inputs nobody reads.

    Checking the property rather than specific names, so the next one is caught on arrival.
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


def test_emptiness_questions_use_isNotEmpty_not_isExists(pb):
    """isExists is TRUE for a declared-but-empty value, so it cannot ask "is there anything
    here". Proven live on this playbook in its earlier two-mode form: YaraConsolidateApply
    reported `failed: 0` and the failure-check task still branched 'yes', running the
    flag-failures task on a clean run. Every successful pass marked itself as needing
    attention.

    Checking the property, not one call site, so a second cannot arrive quietly - and so this
    still guards the current single failed-check task even though the paths that motivated it
    (ConsolidateStatus's eligible/pending lists, ConsolidateApply's failed list) no longer
    exist in this playbook.
    """
    EMPTINESS = {"Yara.ConsolidateStatus.eligible_scan_ids",
                 "Yara.ConsolidateStatus.pending_scan_ids",
                 "Yara.ConsolidateApply.failed",
                 "Yara.ConsolidateSummary.failed"}
    offenders = []
    for tid, t in pb["tasks"].items():
        for grp in (t.get("conditions") or []):
            for clause in grp["condition"]:
                for cond in clause:
                    path = (cond.get("left") or {}).get("value", {}).get("simple")
                    if path in EMPTINESS and cond.get("operator") == "isExists":
                        offenders.append("task %s / %s / %s" % (tid, grp["label"], path))
    assert not offenders, (
        "isExists cannot test emptiness - use isNotEmpty: %s" % offenders)
