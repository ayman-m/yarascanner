#!/usr/bin/env python3
"""YaraReport's inventory is CONTEXT before it is prose, and it says each fact exactly once.

Two defects are pinned here, because both were the kind that stays green while an operator
reads something the playbook cannot act on:

1. THE SAME FACT WAS PUBLISHED THREE WAYS. `legacy` and `newer` were flat name lists beside
   the identical lists nested in by_type[...]["by_state"]; `by_type_counts` was a pure
   projection of by_type[t]["count"]; `report` was the rendered inventory stored verbatim in
   context beside the identical text in the War Room; and a pack-output record carried
   "summary" in `kind` AND in `state` while `type` already said consolidated_summary. None of
   that is redundancy an operator can shrug at - two keys that answer the same question can
   DISAGREE, and nothing in the payload said which one to trust. There is now one record list
   (`datasets`), one grouped view of it (`by_type`), and counts.

2. THE STATE VOCABULARY WAS UNDECLARED. `state` is the field a playbook branches on, and its
   nine values existed nowhere but the body of report_datasets - not in a constant, not in
   the yml. A closed set is only worth anything while it stays closed and stays documented,
   so both directions are asserted below.

Two more properties are pinned for reasons that are not obvious:

  * EVERY record carries EVERY key, including the ones that do not apply to it. A transformer
    filtering on a sometimes-absent key matches nothing and reports no error - a silently
    empty branch, which is the worst kind to debug.

  * The markdown is rendered FROM the result dict and from nothing else. main() used to build
    its sentences with `", ".join(<a by_state list>)`, which raises TypeError the instant an
    element is an object rather than a string - the exact hazard converting these lists
    creates. That construction is gone, and the AST check below keeps it gone.

Ages are relative to the REAL clock: main() takes no now_yyyymm, so report_datasets stamps
today's month and every age is measured against it. A fixture pinned to a fixed month reports
ages that drift by one every 30 days.
"""
import ast
import datetime
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import yaml  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraReport as R, FakeTenant, _run_automation, TEST_SCHEMA_VERSION,
)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts", "YaraReport")
_YML = os.path.join(_SRC, "YaraReport.yml")
_PY = os.path.join(_SRC, "YaraReport.py")

RECORD_KEYS = {"name", "type", "kind", "host", "month", "age_months", "state", "detail",
               "remedy"}


@pytest.fixture(autouse=True)
def _leave_the_module_global_as_we_found_it():
    """set_schema_version writes a MODULE GLOBAL, and the script container is long-lived, so
    a test that runs at v4 and does not put it back changes what every later test classifies
    as legacy. main() sets it from args on every run, which is what makes that survivable in
    production and invisible here."""
    yield
    R.set_schema_version(TEST_SCHEMA_VERSION)


def _month(offset=0):
    """YYYYMM `offset` whole months before today - the real clock, per the module docstring."""
    d = datetime.date.today()
    m = d.year * 12 + (d.month - 1) - offset
    return "%04d%02d" % (m // 12, m % 12 + 1)


def _every_state_tenant():
    """One tenant holding a dataset in each of the nine states, at schema v4.

    v4 deliberately: `overwrite` only exists at v4+, and at v2 a v4 name classifies as
    `newer` instead - so a fixture at the suite's default version cannot reach that state at
    all. frozen/not_rotated use SCANS shards, because an unsuffixed v4 MATCHES dataset is the
    overwrite target rather than an un-rotated one.
    """
    return FakeTenant([
        "yara_scanner_matches_v4_hostA_abc123",                  # overwrite
        "yara_scanner_scans_v4_hostA_abc123_%s" % _month(6),     # rotated
        "yara_scanner_scans_v4_hostB_abc123",                    # frozen (sibling below)
        "yara_scanner_scans_v4_hostB_abc123_%s" % _month(6),
        "yara_scanner_scans_v4_hostC_abc123",                    # not_rotated
        "yara_scanner_matches_v4_scan_2026_07_01_a1b2",          # consolidated
        "yara_scanner_summary_v4_rules_abc123",                  # pack_output
        "yara_scanner_matches_v4_",                              # unrecognised
        "yara_scanner_matches_v1_hostZ",                         # legacy
        "yara_scanner_matches_v9_hostZ",                         # newer
    ])


def _run(tenant, schema_version="4"):
    return _run_automation(R, {"schema_version": schema_version}, tenant, pin_schema=False)


def _by_name(result):
    return {d["name"]: d for d in result["datasets"]}


# ------------------------------------------------------------------ the record list

def test_every_dataset_entry_is_an_object_with_the_same_keys():
    """The whole point. One bare string among the objects, or one key present on only some
    entries, is the silent failure mode a playbook never reports."""
    res = _run(_every_state_tenant())
    assert res.outputs["datasets"], "the fixture produced no records at all"
    for entry in res.outputs["datasets"]:
        assert isinstance(entry, dict), (
            "datasets holds a bare %s - a playbook filtering on a field would silently match "
            "nothing: %r" % (type(entry).__name__, entry))
        assert set(entry) == RECORD_KEYS, "record shape drifted: %s" % sorted(entry)


def test_a_record_carries_the_code_the_sentence_and_the_action_separately():
    """`state` is machine-readable and closed, `detail` is the sentence, `remedy` is the thing
    to DO. Previously the operator got the sentence and the playbook got nothing."""
    res = _run(_every_state_tenant())
    rec = _by_name(res.outputs)["yara_scanner_scans_v4_hostC_abc123"]
    assert rec["state"] == "not_rotated"
    assert "grows without bound" in rec["detail"]
    assert rec["remedy"] == 'set CONFIG_LOOKUP_ROTATION="monthly" in the scanner'
    # ...and the one that needs nothing done says so with an empty string, not by omitting
    # the key, so `remedy` is filterable on every record.
    frozen = _by_name(res.outputs)["yara_scanner_scans_v4_hostB_abc123"]
    assert frozen["state"] == "frozen" and frozen["remedy"] == ""
    assert "not growing" in frozen["detail"]


def test_a_record_never_spells_one_fact_three_times():
    """The pack-output case. `kind` used to be "summary", `state` used to be "summary" and
    `type` said consolidated_summary - one fact, three fields, and `kind` overloaded, since on
    every other record it carries the matches/scans vocabulary."""
    rec = _by_name(_run(_every_state_tenant()).outputs)["yara_scanner_summary_v4_rules_abc123"]
    assert rec["type"] == "consolidated_summary"     # the ONE place summary-vs-full is said
    assert rec["state"] == "pack_output"
    assert rec["kind"] == ""
    assert rec["state"] != rec["kind"]


def test_the_unparseable_and_the_pack_output_cases_are_told_apart():
    """Both fail NAME_RE. Only one of them is debris of unknown origin, and the operator needs
    to know which - the pack's own output being labelled "unrecognised" is what started this."""
    recs = _by_name(_run(_every_state_tenant()).outputs)
    assert recs["yara_scanner_matches_v4_"]["state"] == "unrecognised"
    assert recs["yara_scanner_summary_v4_rules_abc123"]["state"] == "pack_output"


def test_age_months_is_null_rather_than_zero_when_there_is_no_month():
    """"no rotation suffix" is not an age of zero. A dashboard averaging these would read
    every overwrite dataset as brand new."""
    recs = _by_name(_run(_every_state_tenant()).outputs)
    assert recs["yara_scanner_matches_v4_hostA_abc123"]["age_months"] is None
    assert recs["yara_scanner_matches_v4_hostA_abc123"]["month"] == ""
    rotated = recs["yara_scanner_scans_v4_hostA_abc123_%s" % _month(6)]
    assert rotated["month"] == _month(6) and rotated["age_months"] == 6


def test_records_are_grouped_by_state_in_both_the_context_and_the_table():
    """Ten datasets in name order read as noise; the operator wants like with like, and the
    table must not be ordered differently from the list it was rendered from."""
    md = _run(_every_state_tenant()).readable_output
    states = [d["state"] for d in _run(_every_state_tenant()).outputs["datasets"]]
    assert states == sorted(states), "datasets is not grouped by state"
    table = md.split("#### Every dataset")[1]
    seen = [ln.split("`")[3] for ln in table.splitlines() if ln.startswith("| `")]
    assert seen == states, "the table's order disagrees with the context's"


# ------------------------------------------------- the vocabulary is closed and declared

def test_every_state_emitted_is_in_the_declared_vocabulary():
    """A state invented at a call site and never declared is exactly as unmatchable as the
    prose this replaced - it just looks like a contract."""
    for tenant, ver in ((_every_state_tenant(), "4"),
                        (_every_state_tenant(), "2"),
                        (FakeTenant([]), "4")):
        for d in _run(tenant, schema_version=ver).outputs["datasets"]:
            assert d["state"] in R.DATASET_STATES, (
                "undeclared state %r - add it to DATASET_STATES or use an existing one"
                % d["state"])


def test_every_declared_state_is_actually_reachable():
    """The other half of a closed set: a vocabulary carrying a value nothing can ever emit
    documents a branch that never runs."""
    emitted = {d["state"] for d in _run(_every_state_tenant()).outputs["datasets"]}
    assert emitted == set(R.DATASET_STATES), (
        "declared but unreachable: %s / emitted but undeclared: %s"
        % (sorted(set(R.DATASET_STATES) - emitted), sorted(emitted - set(R.DATASET_STATES))))


def test_the_vocabulary_is_the_one_the_yml_documents():
    """The yml is the contract a playbook author reads in the console's output picker. If it
    and the code disagree, the author is the one who finds out."""
    with io.open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    described = {o["contextPath"]: o["description"] for o in doc["outputs"]}
    for code in R.DATASET_STATES:
        assert code in described["Yara.Report.datasets.state"], (
            "state %r is not in the yml's declared closed set" % code)


# ------------------------------------------------------ nothing says the same thing twice

def test_the_restated_keys_are_gone():
    """Each of these was a second spelling of something else in the same payload."""
    o = _run(_every_state_tenant()).outputs
    for key, was in (("report", "the rendered inventory, identical to the War Room output"),
                     ("by_type_counts", "a pure projection of by_type[t]['count']"),
                     ("legacy", "identical to the by_state['legacy'] lists"),
                     ("newer", "identical to the by_state['newer'] lists")):
        assert key not in o, "%s came back - it was %s" % (key, was)
    for bucket in o["by_type"].values():
        assert set(bucket) == {"count", "names"}, (
            "by_type bucket regained a sub-key: %s" % sorted(bucket))


def test_by_type_is_exactly_a_grouping_of_the_records_it_claims_to_view():
    """The yml calls by_type a grouped VIEW of `datasets` and names `datasets` authoritative.
    That claim is only safe while the two cover the same population - the old by_type covered
    current+legacy+newer while `datasets` covered current alone, so both looked like "the
    datasets" and quietly answered over different sets."""
    o = _run(_every_state_tenant()).outputs
    for t, bucket in o["by_type"].items():
        expected = sorted(d["name"] for d in o["datasets"] if d["type"] == t)
        assert bucket["names"] == expected, "by_type[%s] is not a view of datasets" % t
        assert bucket["count"] == len(expected)
    assert sum(b["count"] for b in o["by_type"].values()) == len(o["datasets"])
    assert set(o["by_type"]) == set(R.DATASET_TYPES), "a bucket went missing when empty"


def test_the_counts_agree_with_the_one_list_they_summarise():
    o = _run(_every_state_tenant()).outputs
    states = [d["state"] for d in o["datasets"]]
    assert o["legacy_count"] == states.count("legacy") == 1
    assert o["newer_count"] == states.count("newer") == 1
    assert o["current_count"] == len(states) - 2
    assert o["total_count"] == len(o["datasets"])
    assert o["total_count"] == o["current_count"] + o["legacy_count"] + o["newer_count"]


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    md = _run(_every_state_tenant()).readable_output
    assert md.startswith("### YARA lookup datasets - ")
    assert "\n|---|---|\n" in md, "no markdown table in the output"
    for heading in ("#### By type", "#### Needs attention", "#### Every dataset"):
        assert heading in md, "missing section: %s" % heading
    # the fixed-width block a code fence used to hold open, and the sentences it replaced
    assert "```" not in md
    assert "dataset(s):" not in md and "WARNING:" not in md


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    res = _run(_every_state_tenant())
    o, md = res.outputs, res.readable_output
    assert "| **Datasets** | %d |" % o["total_count"] in md
    assert "| **Current schema** | %d |" % o["current_count"] in md
    assert "| **Inventory month** | %s |" % o["now_yyyymm"] in md
    assert "| **Schema version assumed current** | v%s |" % o["schema_version"] in md
    for t, bucket in o["by_type"].items():
        assert "| %s | %d | " % (t, bucket["count"]) in md, (
            "the By type table disagrees with by_type[%s]" % t)


def test_the_needs_attention_section_is_exactly_the_records_carrying_a_remedy():
    res = _run(_every_state_tenant())
    needs = [d for d in res.outputs["datasets"] if d["remedy"]]
    assert sorted(d["state"] for d in needs) == ["newer", "not_rotated"]
    section = res.readable_output.split("#### Needs attention")[1].split("####")[0]
    for d in needs:
        assert d["name"] in section and d["remedy"] in section
    for d in res.outputs["datasets"]:
        if not d["remedy"]:
            assert d["name"] + "`" not in section


def test_an_empty_tenant_renders_a_table_and_not_an_error():
    """A report of zeros is a successful run: a listing that failed would have raised."""
    res = _run(FakeTenant([]))
    o = res.outputs
    assert o["datasets"] == [] and o["total_count"] == 0
    assert o["current_count"] == 0 and o["legacy_count"] == 0 and o["newer_count"] == 0
    assert o["now_yyyymm"] and o["schema_version"] == "4"
    assert set(o["by_type"]) == set(R.DATASET_TYPES)
    assert "none on this tenant" in res.readable_output
    assert "#### Every dataset" not in res.readable_output


def test_a_pipe_in_a_dataset_name_cannot_shear_the_table():
    """Dataset names arrive from the tenant's listing, which this automation does not police.
    One unescaped `|` and every row below it loses a column - silently, since markdown does
    not error."""
    row = R._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    """A 400-dataset tenant must not push the counts off the top of the War Room - and must
    not lose a record to do it."""
    names = ["yara_scanner_scans_v4_host%03d_abc123_%s" % (i, _month(6)) for i in range(60)]
    res = _run(FakeTenant(names))
    assert len(res.outputs["datasets"]) == 60
    assert res.readable_output.count("`rotated`") == R._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.Report.datasets`" in res.readable_output


# -------------------------------------------------- the string-concat hazard stays dead

def test_the_renderer_concatenates_no_strings_onto_list_elements():
    """`out += ["  " + s for s in items]` raises TypeError the moment an element is a dict,
    which is precisely what these lists now hold. The construction is gone from both the
    renderer and main(); this keeps a new one from creeping back in beside the structured
    formatting, where it would sail through and land in the War Room as a crash."""
    tree = ast.parse(io.open(_PY, encoding="utf-8").read())
    watched = {"render_inventory_markdown", "main", "report_datasets"}
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name in watched):
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add)
                    and any(isinstance(side, ast.Constant) and isinstance(side.value, str)
                            for side in (sub.left, sub.right))):
                raise AssertionError(
                    "%s builds output by adding a string literal to a value (line %d) - use "
                    "%%-formatting or _md_table; a dict on the other side is a TypeError"
                    % (node.name, sub.lineno))


# ------------------------------------------------------ the yml contract is not fiction

def _declared_outputs():
    with io.open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return [o["contextPath"][len("Yara.Report."):] for o in doc["outputs"]]


def test_every_declared_output_including_the_object_keys_is_produced():
    """The pack's own gate walks into lists now, but it runs one scenario per automation. This
    one runs the tenant that reaches every branch, so a key produced only for, say, a legacy
    record is still covered."""
    o = _run(_every_state_tenant()).outputs
    missing = []
    for path in _declared_outputs():
        head, _, leaf = path.partition(".")
        if head not in o:
            missing.append(path)
            continue
        if not leaf:
            continue
        entries = o[head] or []
        if not entries:
            missing.append("%s (nothing populated %s)" % (path, head))
        for entry in entries:
            if leaf not in entry:
                missing.append("%s (absent from a %s entry: %s)" % (path, head, sorted(entry)))
    assert not missing, "declared but not produced:\n  " + "\n  ".join(sorted(set(missing)))


def test_nothing_is_produced_that_the_yml_does_not_declare():
    """The other direction. An undeclared key is invisible in the console's output picker, so
    a playbook author never learns it exists - and an undeclared OBJECT key is worse, because
    the list is visible and the field inside it is not."""
    declared = set(_declared_outputs())
    o = _run(_every_state_tenant()).outputs
    assert not sorted(set(o) - {p.partition(".")[0] for p in declared}), (
        "produced but never declared in the yml: %s"
        % sorted(set(o) - {p.partition(".")[0] for p in declared}))
    record_paths = {p.partition(".")[2] for p in declared if p.startswith("datasets.")}
    for entry in o["datasets"]:
        assert not set(entry) - record_paths, (
            "datasets carries fields the yml never declares: %s"
            % sorted(set(entry) - record_paths))


# ------------------------------- the `internal` bucket describes what it actually collects

_PACK = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement")
_CHANGELOG = os.path.join(_PACK, "CHANGELOG.md")
_PACK_METADATA = os.path.join(_PACK, "pack_metadata.json")


def _pack_internal_datasets():
    """The three datasets the `internal` type USED to claim it holds, read from the module so
    a rename cannot quietly retire this test."""
    return [R._LOCK_DATASET, R._RUNS_DATASET, R._CLEANUP_RUNS_DATASET]


def _type_titles_carriers():
    """{file -> the _TYPE_TITLES tuple it defines}, DISCOVERED rather than listed - the same
    choice the markdown-helper gate makes, so a seventh copy is covered the day it is written.

    Read with ast, not imported: importing five automations to compare one constant costs
    five CommonServerPython stubs and buys nothing.
    """
    scripts = os.path.join(_PACK, "Scripts")
    paths = [os.path.join(_REPO, "xdr", "xdr_data_management.py")]
    paths += [os.path.join(scripts, d, d + ".py") for d in sorted(os.listdir(scripts))
              if os.path.isfile(os.path.join(scripts, d, d + ".py"))]
    out = {}
    for path in paths:
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "_TYPE_TITLES"):
                # Compared as a SEQUENCE, not a dict: the order is the order of the rows in
                # the By type table, and a reordered copy renders a different report.
                out[os.path.relpath(path, _REPO)] = list(ast.literal_eval(node.value))
    return out


def test_the_packs_lock_and_run_record_never_reach_this_inventory():
    """The fact the old wording contradicted. All three pack-internal datasets are
    yara_scanner_<word>_<word> names that fail YARA_OWNED_RE, so classify_yara_datasets drops
    them before a record is built. A tenant holding exactly those three is an EMPTY inventory
    - which is the correct answer, and the reason `internal` cannot mean what it said."""
    for name in _pack_internal_datasets():
        assert not R.YARA_OWNED_RE.match(name), (
            "%s is now yara-owned - it would classify as `legacy` and become a delete_legacy "
            "candidate, so widening the filter is not the way to make `internal` true" % name)
    res = _run(FakeTenant(_pack_internal_datasets()))
    assert res.outputs["total_count"] == 0
    assert res.outputs["by_type"]["internal"]["count"] == 0
    assert "none on this tenant" in res.readable_output


def test_the_internal_row_does_not_assert_a_provenance_the_record_denies():
    """THE DEFECT. `internal` is dataset_type's FALLBACK, so what lands in it is a yara-owned
    name the naming contract will not parse - `yara_scanner_summary_v4` with no
    `_rules_<hash>` tail reaches it. The By type row read "PACK INTERNAL - consolidation lock
    and run record" for that dataset while its own record two tables below said "its origin is
    unknown": one report, two contradictory claims about the same row, and the confident one
    was the wrong one."""
    res = _run(FakeTenant(["yara_scanner_summary_v4"]))
    rec, = res.outputs["datasets"]
    assert rec["type"] == "internal" and rec["state"] == "unrecognised"
    assert res.outputs["by_type"]["internal"]["count"] == 1

    md = res.readable_output
    row, = [ln for ln in md.splitlines() if ln.startswith("| internal | ")]
    assert "PACK INTERNAL" not in row and "consolidation lock and run record" not in row, (
        "the By type table still calls a name of unknown origin the pack's own bookkeeping: "
        + row)
    # ...and it says the true thing: the bucket is the fallback, and the lock and run-record
    # datasets are named only to be ruled OUT of it.
    assert "not yara-owned and never appear here" in row
    assert "origin is unknown" in rec["detail"]


def test_the_yml_documents_the_internal_bucket_as_the_fallback_it_is():
    """The operator reads the yml in the console's output picker, so the same claim has to be
    retired there too - it is the half a playbook author sees before ever running this."""
    with io.open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    desc, = [o["description"] for o in doc["outputs"]
             if o["contextPath"] == "Yara.Report.datasets.type"]
    assert "consolidation lock and run record" not in desc, (
        "the yml still promises `internal` holds the lock and run record")
    assert "FALLBACK" in desc and "never appear here" in desc


def test_every_copy_of_the_type_titles_says_the_same_thing():
    """_TYPE_TITLES is inlined into six files - five automations and the CLI - and no gate
    compares them, so a wording fix that lands in one leaves the other five telling the
    operator the retired story. The `internal` title is the one that has actually been wrong,
    so it is asserted by name as well as by agreement."""
    carriers = _type_titles_carriers()
    assert len(carriers) >= 6, "expected every carrier to be found, got %s" % sorted(carriers)
    baseline = carriers[os.path.relpath(_PY, _REPO)]
    for path, titles in sorted(carriers.items()):
        assert titles == baseline, (
            "_TYPE_TITLES has drifted in %s - the operator reads a different story, or reads "
            "it in a different order, depending on which automation rendered the table:\n"
            "  %s\n  %s" % (path, titles, baseline))
        internal, = [text for key, text in titles if key == "internal"]
        assert "consolidation lock and run record" not in internal, (
            "%s still describes `internal` as the pack's lock and run record" % path)


# ---------------------------------------- a removed output path is announced, not discovered

# Declared outputs of YaraReport in pack 1.5.0 that this change removes. On an upgraded
# tenant each is a DT expression that resolves to nothing and reports no error, which is the
# silently-empty branch this whole rework exists to eliminate - so the CHANGELOG has to name
# them. Hard-coded because the property is about what SHIPPED, which the working tree no
# longer knows.
_REMOVED_PATHS = ("Yara.Report.report", "Yara.Report.by_type_counts",
                  "Yara.Report.legacy", "Yara.Report.newer")


def test_the_removed_output_paths_are_really_gone():
    """Guards the test below: if one of these came back, its CHANGELOG line would be wrong and
    this pair would keep passing by asserting the wrong thing."""
    declared = {"Yara.Report." + p for p in _declared_outputs()}
    assert not declared & set(_REMOVED_PATHS)
    o = _run(_every_state_tenant()).outputs
    assert not {p[len("Yara.Report."):] for p in _REMOVED_PATHS} & set(o)
    for bucket in o["by_type"].values():
        assert "by_state" not in bucket, "by_type[t].by_state is back"


def test_the_changelog_names_every_removed_context_path():
    """A breaking output-contract change that ships unannounced fails on the tenant as
    silence: the playbook branch reads empty and nothing errors. Naming the paths is the only
    warning an upgrading operator gets."""
    text = io.open(_CHANGELOG, encoding="utf-8").read()
    # Backticked, so `Yara.Report.legacy` is not satisfied by a passing mention of
    # `Yara.Report.legacy_count` - which is the path that REPLACED it.
    missing = [p for p in _REMOVED_PATHS if "`%s`" % p not in text]
    assert not missing, (
        "removed from the yml but never announced in the CHANGELOG: %s" % missing)
    # The value changes are breaking in the same way - the path still resolves, to something
    # a branch matching the old value will never equal.
    assert "pack_output" in text, "the state rename for pack-output records is unannounced"


def test_the_changelog_top_entry_is_the_version_the_pack_declares():
    """currentVersion is what a tenant installs; the top CHANGELOG heading is what an operator
    reads to find out what changed. While they disagree, the newest shipped version is
    documented by an entry describing a different one."""
    version = json.load(io.open(_PACK_METADATA, encoding="utf-8"))["currentVersion"]
    head = io.open(_CHANGELOG, encoding="utf-8").read().splitlines()[0]
    assert head.startswith("## [%s]" % version), (
        "pack_metadata says currentVersion %s but the CHANGELOG's top entry is %r"
        % (version, head))
