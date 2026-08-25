"""Unit tests for YaraWipeAllDatasets — the pack's unconditional, unscoped delete-everything
tool. Referenced from test_pack_data_management.py's OTHER_AUTOMATIONS registry, which is
this file's contract with that suite's completeness gate: every automation the pack ships
must be accounted for by SOME suite, and this is the one for this script.

Four jobs, given what this script actually is:

1. Prove it finds EVERYTHING yara_scanner_*-owned — matches and scans, old schema and new,
   per-scan consolidated targets, summary datasets, and unrecognised future kinds alike —
   unlike the other five automations' narrower matches/scans-only pattern.

2. Prove PRESERVED_DATASETS is the only thing that survives an executed pass, and that
   nothing else does, regardless of how many datasets or what kind are on the tenant.

3. Prove the confirm-phrase gate is real: execute=true alone must never delete anything,
   only execute=true AND an exact, case-sensitive confirm match may.

4. Prove the platform contract: the .yml's declared defaults match the .py's fallbacks,
   and — the one requirement unique to this automation — that no playbook in the pack
   references it. It must only ever be run by hand.

No tenant access: FakeTenant below is an in-memory stand-in, reused from
test_pack_data_management.py's shape but self-contained here, matching the script's own
"imports nothing" convention.
"""
import glob
import importlib.util
import os
import re
import sys

import pytest
import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DIR = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts", "YaraWipeAllDatasets")
_PY = os.path.join(_DIR, "YaraWipeAllDatasets.py")
_YML = os.path.join(_DIR, "YaraWipeAllDatasets.yml")
_PLAYBOOKS_GLOB = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Playbooks", "*.yml")

sys.path.insert(0, _REPO)

from test_pack_data_management import _install_xsoar_stubs  # noqa: E402

_install_xsoar_stubs()
import demistomock as demisto  # noqa: E402
import CommonServerPython as csp  # noqa: E402


def _load_module():
    spec = importlib.util.spec_from_file_location("YaraWipeAllDatasets", _PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.DEFAULT_XDR_API_URL = "https://api-test.xdr.eu.paloaltonetworks.com"
    m.DEFAULT_XDR_API_KEY = "k"
    m.DEFAULT_XDR_API_ID = "1"
    return m


W = _load_module()


class FakeTenant:
    """In-memory stand-in for CoreApiClient. `names` is the tenant's live LOOKUP dataset
    list, mutated by delete_dataset — assertions check the tenant's actual state, not just
    a returned count."""

    def __init__(self, names=()):
        self.names = list(names)
        self.calls = []
        self.lock_rows = []
        self.wipe_run_rows = []

    def get_datasets(self):
        self.calls.append("get_datasets")
        return [{"Dataset Name": n, "Type": "LOOKUP"} for n in self.names]

    def xql(self, query, limit=1000):
        self.calls.append("xql:%s" % query)
        m = re.match(r"dataset = (\S+)", query)
        name = m.group(1) if m else ""
        if name == W._LOCK_DATASET:
            return list(self.lock_rows)
        return []

    def create_lookup_dataset(self, dataset_name, schema):
        self.calls.append("create_lookup_dataset:%s" % dataset_name)
        if dataset_name in self.names:
            return {"status": "exists"}
        self.names.append(dataset_name)
        return {"dataset_name": dataset_name}

    def add_lookup_data(self, dataset_name, rows):
        self.calls.append("add_lookup_data:%s" % dataset_name)
        if dataset_name == W._LOCK_DATASET:
            self.lock_rows.extend(rows)
        if dataset_name == W._WIPE_RUNS_DATASET:
            self.wipe_run_rows.extend(rows)
        return {"records_added": len(rows)}

    def delete_dataset(self, dataset_name, force=False):
        self.calls.append("delete_dataset:%s" % dataset_name)
        if dataset_name in self.names:
            self.names.remove(dataset_name)
        if dataset_name == W._LOCK_DATASET:
            self.lock_rows = []
        return {"status": "ok"}

    def deleted(self):
        return [c.split(":", 1)[1] for c in self.calls if c.startswith("delete_dataset:")]


# A representative tenant: live matches (old and new schema), rotated scans (old and new,
# current and past month), per-scan consolidated targets of every kind, summary datasets,
# an unrecognised-but-prefixed name, this pack's three OTHER run-logs, and a dataset outside
# the yara_scanner_ prefix entirely (must never be touched).
FULL_TENANT = [
    "yara_scanner_matches_v4_hostA_abc123",                       # live v4 matches
    "yara_scanner_matches_v2_hostB_def456",                       # live-shaped v2 matches
    "yara_scanner_scans_v4_hostA_abc123_202608",                  # current-month scans
    "yara_scanner_scans_v2_hostB_def456_202601",                  # old-month, old-schema
    "yara_scanner_matches_v4_scan_hostA_20260820_1154_yara_ab12", # consolidated target
    "yara_scanner_scans_v4_scan_hostA_20260820_1154_yara_ab12",   # consolidated target
    "yara_scanner_summary_v4_scan_hostA_20260820_1154_yara_ab12", # summary dataset
    "yara_scanner_something_unrecognised_v9",                     # future/unknown kind
    "yara_scanner_consolidation_lock",                            # preserved
    "yara_scanner_consolidation_runs",                            # preserved
    "yara_scanner_cleanup_runs",                                  # preserved
    "not_yara_owned_at_all",                                      # never touched, ignored
]


@pytest.fixture(autouse=True)
def _reset_stubs():
    demisto.args_value = {}
    demisto.commands = []
    csp.results = []
    csp.errors = []
    yield


# --------------------------------------------------------------------- discovery
def test_finds_every_yara_scanner_prefixed_lookup_dataset_regardless_of_kind():
    """The one behaviour that genuinely differs from every sibling automation's
    matches/scans-only pattern: this must also see summary datasets and any future,
    unrecognised kind — anything starting with the bare prefix."""
    client = FakeTenant(FULL_TENANT)
    found = W.list_all_yara_datasets(client)
    assert set(found) == set(FULL_TENANT) - {"not_yara_owned_at_all"}


def test_ignores_non_lookup_type_datasets():
    class Client(FakeTenant):
        def get_datasets(self):
            return [{"Dataset Name": "yara_scanner_matches_v4_hostA_abc", "Type": "LOOKUP"},
                    {"Dataset Name": "yara_scanner_matches_v4_hostB_def", "Type": "TIMESERIES"}]
    found = W.list_all_yara_datasets(Client())
    assert found == ["yara_scanner_matches_v4_hostA_abc"]


def test_ignores_datasets_outside_the_prefix():
    client = FakeTenant(["not_yara_owned", "also_unrelated"])
    assert W.list_all_yara_datasets(client) == []


# --------------------------------------------------------------------- preservation
def test_preserved_datasets_is_exactly_the_four_bookkeeping_names():
    assert W.PRESERVED_DATASETS == frozenset({
        "yara_scanner_consolidation_lock",
        "yara_scanner_consolidation_runs",
        "yara_scanner_cleanup_runs",
        "yara_scanner_wipe_runs",
    })


def test_dry_run_never_deletes_anything():
    client = FakeTenant(FULL_TENANT)
    before = set(client.names)
    result = W.wipe_all(client, execute=False, log=lambda *a: None)
    assert result["dry_run"] is True
    # every pre-existing dataset survives untouched; the only change is this pass's own
    # audit row landing in yara_scanner_wipe_runs (a write, not a delete — see the
    # dedicated test for that behaviour)
    assert before <= set(client.names)
    assert not any(c.startswith("delete_dataset:") for c in client.calls)


def test_dry_run_takes_no_lock():
    client = FakeTenant(FULL_TENANT)
    W.wipe_all(client, execute=False, log=lambda *a: None)
    assert "create_lookup_dataset:yara_scanner_consolidation_lock" not in client.calls


def test_dry_run_reports_the_correct_split_and_records_itself():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=False, log=lambda *a: None)
    assert result["total_found"] == len(FULL_TENANT) - 1   # minus the non-yara dataset
    assert set(result["to_delete"]) == set(FULL_TENANT) - {
        "not_yara_owned_at_all", "yara_scanner_consolidation_lock",
        "yara_scanner_consolidation_runs", "yara_scanner_cleanup_runs",
    }
    assert set(result["preserved"]) == {
        "yara_scanner_consolidation_lock", "yara_scanner_consolidation_runs",
        "yara_scanner_cleanup_runs",
    }
    # a dry run still leaves an audit trail of itself
    assert len(client.wipe_run_rows) == 1
    assert client.wipe_run_rows[0]["mode"] == "dry_run"


def test_dry_run_warns_up_front_that_more_than_one_execute_pass_will_be_needed():
    """The gap a real run exposed: an operator following the documented "dry run first"
    advice must learn about the cap BEFORE ever setting execute=true, not discover it only
    after a capped pass. FULL_TENANT has 8 candidates; max_deletes=3 needs ceil(8/3)=3 runs."""
    demisto.args_value = {"max_deletes": "3"}
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    assert client.deleted() == []   # still just a dry run
    out = csp.results[-1].readable_output
    assert "3 execute run(s)" in out
    assert "max_deletes=3" in out


def test_dry_run_says_nothing_about_passes_when_everything_fits_in_one():
    demisto.args_value = {"max_deletes": "100"}
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    out = csp.results[-1].readable_output
    assert "execute run(s)" not in out


def test_executed_capped_pass_states_exactly_how_many_remain():
    demisto.args_value = {"execute": "true", "confirm": "DELETE ALL YARA DATASETS",
                          "max_deletes": "3"}
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    out = csp.results[-1].readable_output
    assert "3 of 8 candidate(s) - 5 remain" in out
    assert "Run this exact command again" in out


def test_executed_pass_deletes_everything_except_preserved():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=True, log=lambda *a: None)
    assert result["dry_run"] is False
    remaining = set(client.names)
    # The lock dataset itself is deleted as the mechanism of releasing it (not merely
    # cleared) — see release_consolidation_lock — so it does not persist between runs,
    # even though it is in PRESERVED_DATASETS (this pass never treats it as a delete
    # candidate; it is simply gone by the time the next acquire recreates it). The other
    # two pre-existing preserved names, plus the wipe-run log this pass itself created,
    # do persist.
    assert remaining == {
        "yara_scanner_consolidation_runs", "yara_scanner_cleanup_runs", "yara_scanner_wipe_runs",
        "not_yara_owned_at_all",   # outside the prefix entirely; never a candidate at all
    }
    # and nothing NOT preserved survives — old schema, new schema, live matches, rotated
    # scans, consolidated targets, summary datasets, unrecognised kinds: all gone
    for n in FULL_TENANT:
        if n in W.PRESERVED_DATASETS or n == "not_yara_owned_at_all":
            continue
        assert n not in remaining, "%s should have been deleted" % n
    assert result["deleted_count"] == len(FULL_TENANT) - 1 - 3  # minus non-yara, minus 3 preexisting preserved
    # the lock's own deletion (via release, not via the wipe pass) is never counted here
    assert "yara_scanner_consolidation_lock" not in result["deleted"]


def test_executed_pass_records_itself_with_deleted_and_failed_lists():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=True, log=lambda *a: None)
    assert len(client.wipe_run_rows) == 1
    row = client.wipe_run_rows[0]
    assert row["mode"] == "executed"
    assert row["deleted_count"] == result["deleted_count"]


# --------------------------------------------------------------------- max_deletes cap
# The bug this whole block exists to catch: a real pass against ~240 accumulated datasets
# ran 12-wide with delete_dataset's measured ~60s server-side cost, exceeded the platform's
# ~900s automation task timeout, and got killed mid-batch — surfacing to the operator as a
# bare "Internal Server Error" after silently deleting most of its candidates first.

def test_default_max_deletes_matches_the_documented_constant():
    assert W.DEFAULT_MAX_DELETES_PER_PASS == 100


def test_execute_bounds_a_pass_to_max_deletes():
    client = FakeTenant(FULL_TENANT)   # 8 real candidates
    result = W.wipe_all(client, execute=True, max_deletes=3, log=lambda *a: None)
    assert result["stopped_early"] is True
    assert result["deleted_count"] == 3
    # the report still shows the TRUE total scope, not just what this pass touched
    assert result["to_delete_count"] == 8


def test_a_pass_within_the_cap_is_not_marked_stopped_early():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=True, max_deletes=100, log=lambda *a: None)
    assert result["stopped_early"] is False
    assert result["deleted_count"] == result["to_delete_count"]


def test_dry_run_ignores_max_deletes_and_reports_the_full_list():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=False, max_deletes=1, log=lambda *a: None)
    assert result["stopped_early"] is False
    assert len(result["to_delete"]) == result["to_delete_count"] == 8


def test_zero_max_deletes_disables_the_cap():
    client = FakeTenant(FULL_TENANT)
    result = W.wipe_all(client, execute=True, max_deletes=0, log=lambda *a: None)
    assert result["stopped_early"] is False
    assert result["deleted_count"] == 8


def test_stopped_early_is_recorded_in_the_audit_row():
    client = FakeTenant(FULL_TENANT)
    W.wipe_all(client, execute=True, max_deletes=2, log=lambda *a: None)
    assert client.wipe_run_rows[0]["stopped_early"] == "True"


def test_main_rejects_a_non_numeric_max_deletes():
    demisto.args_value = {"execute": "true", "confirm": "DELETE ALL YARA DATASETS",
                          "max_deletes": "not-a-number"}
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    assert client.deleted() == []
    assert csp.errors and "max_deletes" in csp.errors[-1]


def test_main_wires_max_deletes_through_to_the_pass():
    demisto.args_value = {"execute": "true", "confirm": "DELETE ALL YARA DATASETS",
                          "max_deletes": "3"}
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    # client.deleted() also counts the lock's own acquire/release housekeeping (FULL_TENANT
    # already has the lock dataset present, so taking it over deletes-then-recreates it) -
    # the wipe-run audit row is what reports candidates actually wiped, cleanly.
    assert csp.results and csp.results[-1].outputs["deleted_count"] == 3
    assert csp.results[-1].outputs["stopped_early"] is True


def test_executed_pass_takes_and_releases_the_lock():
    client = FakeTenant(FULL_TENANT)
    W.wipe_all(client, execute=True, log=lambda *a: None)
    assert "create_lookup_dataset:yara_scanner_consolidation_lock" in client.calls
    # released: the lock dataset survives (it's preserved) but holds no row afterward
    assert client.lock_rows == []


def test_a_held_lock_blocks_the_wipe_and_deletes_nothing():
    client = FakeTenant(FULL_TENANT)
    # FULL_TENANT already contains the lock dataset, so create_lookup_dataset will report
    # "already exists" and acquire falls through to reading its row below.
    client.lock_rows = [{"holder": "someone-else", "started_ms": 99999999999999}]
    before = set(client.names)
    result = W.wipe_all(client, execute=True, log=lambda *a: None, now_ms=99999999999999 + 1000)
    assert result["lock_held_by_other_run"] is True
    assert set(client.names) == before
    assert result["deleted_count"] == 0


# --------------------------------------------------------------------- confirm-phrase gate
def _run_main(execute=None, confirm=None):
    """Run main() against a client built BEFORE main() is called, so the returned client
    is inspectable even when the confirm-phrase gate rejects the call before ever
    constructing one — the whole point of several tests below is proving that path never
    reaches CoreApiClient() at all."""
    args = {}
    if execute is not None:
        args["execute"] = execute
    if confirm is not None:
        args["confirm"] = confirm
    demisto.args_value = args
    client = FakeTenant(FULL_TENANT)
    W.CoreApiClient = lambda: client
    try:
        W.main()
    except SystemExit:
        pass
    return client


def test_execute_true_without_confirm_deletes_nothing():
    client = _run_main(execute="true")
    assert client.deleted() == []
    assert csp.errors and "confirm" in csp.errors[0]


def test_execute_true_with_wrong_confirm_deletes_nothing():
    client = _run_main(execute="true", confirm="delete all yara datasets")  # wrong case
    assert client.deleted() == []
    assert csp.errors


@pytest.mark.parametrize("near_miss", [
    "DELETE ALL YARA DATASET",       # missing S
    " DELETE ALL YARA DATASETS",     # leading space
    "DELETE ALL YARA DATASETS ",     # trailing space
    "delete all yara datasets",      # wrong case
    "DELETE-ALL-YARA-DATASETS",      # wrong punctuation
])
def test_execute_true_rejects_every_near_miss_confirm_phrase(near_miss):
    client = _run_main(execute="true", confirm=near_miss)
    assert client.deleted() == []


def test_execute_true_with_exact_confirm_deletes():
    client = _run_main(execute="true", confirm="DELETE ALL YARA DATASETS")
    assert set(client.deleted()) >= {
        "yara_scanner_matches_v4_hostA_abc123", "yara_scanner_matches_v2_hostB_def456",
    }
    assert not csp.errors


def test_confirm_alone_without_execute_is_a_dry_run():
    """A correct confirm phrase with execute omitted/false must still be a no-op — confirm
    only matters when paired with execute=true."""
    client = _run_main(confirm="DELETE ALL YARA DATASETS")
    assert client.deleted() == []


# --------------------------------------------------------------------- platform contract
def _yml():
    with open(_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_execute_defaults_to_false_in_the_yml():
    doc = _yml()
    arg = next(a for a in doc["args"] if a["name"] == "execute")
    assert arg["defaultValue"] == "false"


def test_confirm_has_no_default_value():
    doc = _yml()
    arg = next(a for a in doc["args"] if a["name"] == "confirm")
    assert not arg.get("defaultValue")


def test_the_yml_declares_exactly_the_arguments_the_py_reads():
    doc = _yml()
    names = {a["name"] for a in doc["args"]}
    assert names == {"execute", "confirm", "max_deletes"}


def test_py_compiles():
    import py_compile
    py_compile.compile(_PY, doraise=True)


# --------------------------------------------------------------------- must stay unwired
def test_no_playbook_in_the_pack_references_this_script():
    """The one requirement unique to this automation: it must only ever be run by hand,
    from the Playground or War Room. If any playbook task ever names it, that guarantee is
    gone — this is the trip wire."""
    for pb_path in glob.glob(_PLAYBOOKS_GLOB):
        with open(pb_path, encoding="utf-8") as fh:
            text = fh.read()
        assert "YaraWipeAllDatasets" not in text, (
            "%s references YaraWipeAllDatasets — this script must never be reachable from "
            "a playbook" % pb_path)
