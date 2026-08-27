"""Unit tests for the XSOAR pack's data-management port (YaraReport / YaraCleanup).

Three jobs here:

1. Prove the PORT agrees with the canonical CLI — in EVERY file that ships. The six
   automations under Scripts/ are standalone: the tenant does not resolve cross-script
   imports, so each one hand-carries a verbatim copy of `xdr_data_management.py`'s
   selection logic. That is six independent chances for a fix to land in the CLI and not on
   the tenant, so the gate below (and its sibling in test_consolidation.py) compares the CLI
   against all six, one parametrised case each — a fix that misses even one automation names
   that automation when it fails.

2. Prove the DELETION path is safe. YaraCleanup deletes whole datasets, so every one of the
   seven safety rails is exercised independently on BOTH selection paths (retention window
   and delete_legacy), against an in-memory fake tenant whose dataset list is asserted
   UNCHANGED afterwards — not merely a returned flag.

3. Prove the platform CONTRACT holds. An automation's behaviour is decided jointly by its
   Python and its .yml: XSOAR delivers a declared `defaultValue` in demisto.args() when the
   caller omits an argument, so `execute`'s dry-run default is half a YAML fact. The .yml
   files are parsed and asserted here too.

No tenant access: the pack's client interface (get_datasets / xql / create_lookup_dataset /
add_lookup_data / delete_dataset) is driven by FakeTenant below.
"""
import ast
import os
import re
import sys
import time
import types

import pytest
import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts")
_CLI = os.path.join(_REPO, "xdr", "xdr_data_management.py")

# ------------------------------------------------------- the files that SHIP
# The six automations the tenant actually runs. Each is STANDALONE: it inlines the whole
# shared library, imports no other automation and neither demistomock nor
# CommonServerPython, because the tenant does not resolve cross-script imports and injects
# `demisto` / `return_error` / `CommandResults` implicitly.
#
# This tuple is the single definition of "what ships" for the whole tests/ tree —
# test_consolidation.py's drift gate and the six behavioural files import it from here.
# Adding a seventh automation is a one-line change that widens every one of them at once,
# and test_no_automation_escapes_the_gate below fails if someone adds one without doing so.
SHIPPING = ("YaraReport", "YaraConsolidateStatus", "YaraConsolidateApply", "YaraConsolidateSummary", "YaraCleanup")
SHIPPING_PATHS = {n: os.path.join(_SCRIPTS, n, "%s.py" % n) for n in SHIPPING}

sys.path.insert(0, _REPO)


# --------------------------------------------------------------- XSOAR stubs
# The pack's scripts run inside an XSOAR docker image where `demistomock` and
# `CommonServerPython` are provided by the platform. Neither is pip-installable here, so
# stand in for exactly the surface these three scripts use.
class _CommandResults:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None,
                 raw_response=None):
        self.readable_output = readable_output
        self.outputs_prefix = outputs_prefix
        self.outputs = outputs
        self.raw_response = raw_response


def _install_xsoar_stubs():
    if "demistomock" in sys.modules:
        return sys.modules["demistomock"], sys.modules["CommonServerPython"]

    dm = types.ModuleType("demistomock")
    dm.args_value = {}
    dm.commands = []
    dm.args = lambda: dict(dm.args_value)
    dm.executeCommand = lambda cmd, cmd_args=None: dm.commands.append((cmd, cmd_args))
    dm.results = lambda r: None
    dm.debug = lambda *a, **k: None
    dm.error = lambda *a, **k: None
    dm.info = lambda *a, **k: None

    csp = types.ModuleType("CommonServerPython")
    csp.results = []
    csp.errors = []
    csp.CommandResults = _CommandResults

    # The real CommonServerPython does `from datetime import datetime, timedelta` and
    # declares no __all__, so on a tenant those names arrive in an automation's global scope
    # ALREADY BOUND — the bare name `datetime` is the datetime CLASS, not the module — which
    # is why each automation re-imports `datetime` for itself rather than trusting what is
    # in scope. Stubbed here so the harness reproduces that hazard instead of hiding it:
    # without these, a copy that dropped its own `import datetime` would break the tenant
    # with every unit test still green.
    import datetime as _datetime_module
    import json as _json_module
    csp.datetime = _datetime_module.datetime
    csp.timedelta = _datetime_module.timedelta
    csp.os = os
    csp.re = re
    csp.sys = sys
    csp.time = time
    csp.json = _json_module

    def argToList(value, separator=","):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return []
            return [v.strip() for v in value.split(separator) if v.strip()]
        return [value]

    def argToBoolean(value):
        """The PERMISSIVE reading of CommonServerPython's boolean vocabulary.

        Which exact vocabulary the platform ships has varied by version (a narrow
        true/yes/false/no reading, and a wider strtobool-style one). This stub deliberately
        takes the WIDER true-set, so no test here can claim `execute="1"` is inert when a
        real tenant might read it as true. The property the deletion tests actually assert
        is vocabulary-independent: anything that is not an explicit affirmative must either
        return False or raise, and in both cases nothing is deleted.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.strip().lower() in ("y", "yes", "t", "true", "on", "1"):
                return True
            if value.strip().lower() in ("n", "no", "f", "false", "off", "0"):
                return False
        raise ValueError("Argument does not contain a valid boolean-like value: %r" % (value,))

    def return_results(r):
        csp.results.append(r)

    def return_error(message, error=None, outputs=None):
        csp.errors.append(message)
        raise SystemExit(message)

    csp.argToList = argToList
    csp.argToBoolean = argToBoolean
    csp.return_results = return_results
    csp.return_error = return_error
    csp.demisto = dm

    sys.modules["demistomock"] = dm
    sys.modules["CommonServerPython"] = csp

    # Inject the platform-provided names as BUILTINS, because that is what the tenant does.
    #
    # The six automations are now standalone: they carry all their logic inline and import
    # neither demistomock nor CommonServerPython, because on a Cortex tenant both are already
    # in scope -- an automation just uses `demisto`, `return_error`, `CommandResults` and so
    # on without importing anything. That is correct for the tenant and it is what the pack
    # owner requires.
    #
    # It also means that importing one of those files as an ordinary Python module -- which is
    # exactly what these tests do -- leaves every one of those names unbound, and the first
    # call fails with `NameError: name 'demisto' is not defined`. Registering the stub modules
    # in sys.modules above does nothing for them, because nothing imports those modules any more.
    #
    # So the harness has to stand in for the platform's injection, not for its import system.
    # builtins is the honest place for it: it makes the names resolve from any module's global
    # scope without that module importing them, which is precisely the runtime contract the
    # scripts are written against.
    import builtins
    builtins.demisto = dm
    builtins.CommandResults = _CommandResults
    builtins.argToList = argToList
    builtins.argToBoolean = argToBoolean
    builtins.return_results = return_results
    builtins.return_error = return_error

    return dm, csp


demistomock, CommonServerPython = _install_xsoar_stubs()

for _d in SHIPPING:
    _p = os.path.join(_SCRIPTS, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# All six imported at module scope, before any test can call set_schema_version() — that
# function writes YARA_LOOKUP_SCHEMA_VER into os.environ, and every one of these files (like
# xdr_action_center) resolves its own YARA_SCHEMA_VERSION from that variable at IMPORT time,
# so a later import would pick up whichever version ran last.
import YaraReport               # noqa: E402
import YaraConsolidateStatus    # noqa: E402
import YaraConsolidateApply     # noqa: E402
import YaraConsolidateSummary   # noqa: E402
import YaraCleanup              # noqa: E402
import xdr_action_center as AC  # noqa: E402

SHIPPING_MODULES = {
    "YaraReport": YaraReport,
    "YaraConsolidateStatus": YaraConsolidateStatus,
    "YaraConsolidateApply": YaraConsolidateApply,
    "YaraConsolidateSummary": YaraConsolidateSummary,
    "YaraCleanup": YaraCleanup,
}
assert tuple(SHIPPING_MODULES) == SHIPPING

# The parametrisation the six cross-copy behavioural files reuse. Defined once, here, so
# that widening SHIPPING widens all of them together.
SHIPPING_IMPLS = [pytest.param(_m, id=_n) for _n, _m in SHIPPING_MODULES.items()]


def impls(*canonical):
    """`[canonical modules...] + all six shipping automations`, as pytest params.

    The canonical module (xdr_consolidate.py) is the one with the readable history and the
    one a developer edits; the six are what the tenant executes. A behaviour proven only in
    the canonical copy is not a guarantee, which is why every one of these files runs its
    assertions against all seven.
    """
    return ([pytest.param(m, id=m.__name__) for m in canonical] + list(SHIPPING_IMPLS))


# The library surface these tests drive directly, bound to the automation that actually
# ships the behaviour: retention/pruning and the lock are YaraCleanup's job, the read-only
# inventory is YaraReport's. (Both files carry the identical inlined library — the gates
# below are what prove that — but a test should name the automation whose behaviour it is
# describing, so a failure points at the thing an operator runs.)
K = YaraCleanup
R = YaraReport


# --------------------------------------------------------------- fake tenant
NOW_MS = 10_000_000_000
NOW_YYYYMM = "202607"


class FakeTenant:
    """In-memory stand-in for the pack's client interface.

    `names` is the tenant's live LOOKUP dataset list and is mutated by delete_dataset —
    so a test can assert a rail kept a dataset by looking at the tenant, not at a flag.

    Querying a dataset that does not exist RAISES, as the real tenant does. That is what
    drives filter_unconsolidated's `tcount = -1` branch (the "target was never created"
    case), which a lenient fake answering 0 rows would leave dead.
    """

    def __init__(self, names=(), newest=None, scans=None, counts=None, error_on=()):
        self.counts = dict(counts or {})    # per-scan target -> row count
        # A dataset with a row count exists by definition.
        self.names = list(names) + [n for n in self.counts if n not in names]
        self.newest = dict(newest or {})    # dataset -> newest event_timestamp_ms
        self.scans = dict(scans or {})      # shard -> {scan_id: row count}
        self.error_on = tuple(error_on)     # query substrings that blow up
        self.calls = []
        self.lock_rows = []

    # -- reads --
    def get_datasets(self):
        self.calls.append("get_datasets")
        return [{"Dataset Name": n, "Type": "LOOKUP"} for n in self.names]

    def xql(self, query, limit=1000):
        self.calls.append("xql:%s" % query)
        for frag in self.error_on:
            if frag in query:
                raise RuntimeError("tenant hiccup")
        m = re.match(r"dataset = (\S+)", query)
        name = m.group(1) if m else ""
        if name and name not in self.names:
            raise RuntimeError("dataset not found: %s" % name)
        if name == K._LOCK_DATASET and "|" not in query:
            return list(self.lock_rows)
        if "comp max(event_timestamp_ms)" in query:
            v = self.newest.get(name)
            return [{"newest": v}] if v is not None else []
        if "by scan_id" in query:
            return [{"scan_id": s, "n": n} for s, n in sorted(self.scans.get(name, {}).items())]
        if "comp count() as n" in query:
            return [{"n": self.counts.get(name, 0)}]
        return []

    # -- writes --
    def create_lookup_dataset(self, dataset_name, schema):
        self.calls.append("create_lookup_dataset:%s" % dataset_name)
        if dataset_name in self.names:
            return {"status": "exists"}
        self.names.append(dataset_name)
        return {"dataset_name": dataset_name}

    def add_lookup_data(self, dataset_name, rows):
        self.calls.append("add_lookup_data:%s" % dataset_name)
        if dataset_name == K._LOCK_DATASET:
            self.lock_rows.extend(rows)
        return {"records_added": len(rows)}

    def remove_lookup_data(self, dataset_name, filters):
        """Drop rows whose scan_id matches any filter block. Mirrors the real endpoint's
        EXACT-value, OR-across-blocks semantics closely enough to reconcile a summary
        target: the fake models a dataset as {scan_id: row_count}, so removing a scan_id
        removes its rows."""
        self.calls.append("remove_lookup_data:%s" % dataset_name)
        wanted = set()
        for block in (filters or []):
            for cond in (block if isinstance(block, list) else [block]):
                if isinstance(cond, dict) and cond.get("field") == "scan_id":
                    v = cond.get("value")
                    wanted.update(v if isinstance(v, list) else [v])
        held = self.scans.get(dataset_name, {})
        removed = sum(n for sid, n in held.items() if sid in wanted)
        self.scans[dataset_name] = {s: n for s, n in held.items() if s not in wanted}
        if dataset_name in self.counts:
            self.counts[dataset_name] = max(0, self.counts[dataset_name] - removed)
        return {"deleted": removed}

    def delete_dataset(self, dataset_name, force=False):
        self.calls.append("delete_dataset:%s" % dataset_name)
        self.force_flags = getattr(self, "force_flags", [])
        self.force_flags.append((dataset_name, force))
        if dataset_name in self.names:
            self.names.remove(dataset_name)
        if dataset_name == K._LOCK_DATASET:
            self.lock_rows = []
        return {"status": "ok"}

    # -- helpers --
    def deleted(self):
        return [c.split(":", 1)[1] for c in self.calls if c.startswith("delete_dataset:")]

    def mutating_calls(self):
        return [c for c in self.calls
                if c.split(":", 1)[0] in ("delete_dataset", "create_lookup_dataset",
                                          "add_lookup_data", "remove_lookup_data")]


def _prune(client, **kw):
    kw.setdefault("now_ms", NOW_MS)
    kw.setdefault("now_yyyymm", NOW_YYYYMM)
    kw.setdefault("log", lambda *a: None)
    return K.prune_datasets(client, **kw)


# The version this suite's `_v2_` dataset fixtures are written against. Deliberately NOT
# DEFAULT_SCHEMA_VERSION: pinning the suite to whatever the automations happen to ship makes
# every classification test silently change meaning the day that default is bumped. What the
# shipped default should BE is asserted once, in
# test_the_shipped_default_tracks_the_scanners_schema_version.
TEST_SCHEMA_VERSION = "2"


@pytest.fixture(autouse=True)
def _reset_schema_version():
    """set_schema_version writes a module global AND os.environ, both of which outlive the
    call — the same property that makes it leak between automation executions inside one
    long-running XSOAR container. The automations reset it explicitly on every run; a test
    calling the library directly does not, so pin it here rather than let test order decide
    which schema version a report is rendered against.
    """
    # Every automation carries its OWN YARA_SCHEMA_VERSION global — resetting one module's
    # copy leaves the other four holding whatever the previous test set, which is how these
    # tests silently became order-dependent. Reset all of them.
    for _m in SHIPPING_MODULES.values():
        _m.set_schema_version(TEST_SCHEMA_VERSION)
    yield
    for _m in SHIPPING_MODULES.values():
        _m.set_schema_version(TEST_SCHEMA_VERSION)


# ------------------------------------------------------------- port fidelity
_PORTED_FUNCS = ("parse_dataset_name", "months_between", "has_rotated_sibling",
                 "select_rotated_for_deletion", "filter_recently_written",
                 "filter_unconsolidated", "select_legacy_for_deletion", "render_report")
_PORTED_CONSTS = ("NAME_RE", "MONTH_RE", "DEFAULT_MIN_QUIET_HOURS")


def _logic_index(path):
    """{name: normalised source} for the ported functions/constants in a file, with
    docstrings and comments stripped so only executable logic is compared.

    One normalisation, and only one: the CLI's filter_unconsolidated does
    `import xdr_consolidate as C` and calls `C.target_name(...)`. An XSOAR script cannot
    import a repo module at runtime, and each automation already carries target_name itself
    (it is part of the xdr_consolidate port above it), so that import is dropped and the
    `C.` qualifier removed. Everything else must match character for character.
    """
    with open(path) as fh:
        tree = ast.parse(fh.read())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _PORTED_FUNCS:
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]          # drop the docstring; wording may differ
            stmts = []
            for s in body:
                if isinstance(s, ast.Import) and any(a.name == "xdr_consolidate" for a in s.names):
                    continue
                stmts.append(ast.unparse(s).replace("C.target_name(", "target_name("))
            out[node.name] = "def %s(%s):\n%s" % (node.name, ast.unparse(node.args),
                                                  "\n".join(stmts))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in _PORTED_CONSTS):
            out[node.targets[0].id] = ast.unparse(node)
    return out


@pytest.mark.parametrize("automation", SHIPPING)
def test_pack_data_management_logic_matches_the_cli(automation):
    """THE DRIFT GATE, one case per shipping automation.

    Previously this compared the CLI against a single library file that no tenant ever
    executes, which meant a fix could land in xdr_data_management.py, be faithfully copied
    into that library, and still miss every automation that actually runs. Six cases now: a
    fix that misses even one names it in the failure.
    """
    mine = _logic_index(_CLI)
    pack = _logic_index(SHIPPING_PATHS[automation])
    missing = sorted(set(_PORTED_FUNCS + _PORTED_CONSTS) - set(mine))
    assert not missing, "test is stale — not found in xdr_data_management.py: %s" % missing
    for name in sorted(mine):
        assert name in pack, (
            "%s is missing from %s — the tenant runs THAT file, so a fix that lands only in "
            "xdr_data_management.py does nothing on the tenant"
            % (name, SHIPPING_PATHS[automation]))
        assert pack[name] == mine[name], (
            "%s has drifted between xdr_data_management.py and %s:\n"
            "--- xdr_data_management\n%s\n--- %s\n%s"
            % (name, automation, mine[name], automation, pack[name]))


def _pack_script_dirs():
    """Every script directory in the pack that is a real content item.

    A directory counts iff it ships BOTH `<name>.py` and `<name>.yml`: the yml is what makes
    it a content item (see test_every_script_directory_ships_a_yml) and a bare .py is
    delivered by no upload path at all.
    """
    found = set()
    for d in sorted(os.listdir(_SCRIPTS)):
        script_dir = os.path.join(_SCRIPTS, d)
        if not os.path.isdir(script_dir) or d.startswith("__"):
            continue
        if (os.path.exists(os.path.join(script_dir, "%s.yml" % d))
                and os.path.exists(os.path.join(script_dir, "%s.py" % d))):
            found.add(d)
    return found


# There are no exemptions from the gate for a script that ships untested, and that is still
# the point. This pack used to carry one library script, YaraConsolidateCommon — a seventh
# content item that no automation imported and no playbook task reached, exempted from the
# gate because a file that never runs cannot usefully be gated. It was deleted once the gate
# was widened from that dead copy to the five that shared xdr_data_management.py's
# classify/select contract (schema_version, older_than_months, delete_legacy — the thing this
# whole file and test_consolidation.py's sibling gate compare against the CLI).
#
# YaraWipeAllDatasets is not that contract. It has no selection rules, no schema_version, no
# retention window — it is an unconditional wipe with exactly two arguments (execute,
# confirm), so parametrising it into SHIPPING would either fail every schema/retention/
# delete_legacy test here for a script that was never meant to have those arguments, or
# require bolting on unused rule logic just to satisfy a comparison it has no business being
# compared against. So it is covered by its OWN dedicated, equally-rigorous suite instead:
# tests/test_wipe_all_datasets.py. OTHER_AUTOMATIONS below is that pointer, not an escape
# hatch — every name in it must resolve to a real test file, checked in
# test_every_other_automation_has_dedicated_coverage.
_DELETED_LIBRARY = "YaraConsolidateCommon"
_DELETED_AUTOMATIONS = ("YaraConsolidateCommon",)
OTHER_AUTOMATIONS = {"YaraWipeAllDatasets": "test_wipe_all_datasets.py",
                     "YaraRulesFromFile": "test_rules_from_file.py",
                     "YaraScanVerify": "test_scan_verify.py"}


def test_no_automation_escapes_the_gate():
    """SHIPPING (this file's classify/select contract) plus OTHER_AUTOMATIONS (anything
    with its own dedicated suite) must account for every script directory in the pack. A
    new automation added to neither would ship untested by anything — invisibly, because
    every existing case would still pass. So discover the pack from the filesystem and
    require the three to agree."""
    found = _pack_script_dirs()
    accounted_for = set(SHIPPING) | set(OTHER_AUTOMATIONS)
    ungated = sorted(found - accounted_for)
    assert not ungated, (
        "these automations ship but are covered by nothing: %s — add them to SHIPPING if "
        "they share xdr_data_management.py's contract, or to OTHER_AUTOMATIONS with a "
        "dedicated test file otherwise, in %s" % (ungated, os.path.abspath(__file__)))
    vanished = sorted(accounted_for - found)
    assert not vanished, (
        "SHIPPING/OTHER_AUTOMATIONS names automations no longer in the pack: %s" % vanished)


def test_every_other_automation_has_dedicated_coverage():
    """The other half of the gate OTHER_AUTOMATIONS widens: every file it points at must
    actually exist, so pointing at a typo'd or deleted filename cannot silently stand in
    for real coverage."""
    for name, test_file in OTHER_AUTOMATIONS.items():
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), test_file)
        assert os.path.isfile(path), (
            "OTHER_AUTOMATIONS[%r] points at %s, which does not exist" % (name, path))


def test_the_deleted_library_stays_deleted():
    """The dead library is gone; this keeps it gone, rather than passing vacuously.

    Re-adding it would not be caught by anything else: it would arrive as an ungated seventh
    content item (test_no_automation_escapes_the_gate would fail, but the obvious way to
    quieten that is to re-add an exemption), and shipping it in `unified/` would put a file
    a customer imports back among the six that are actually required. So assert the two
    artifacts are absent, and assert the two things that would make it live again — an
    automation importing it, or a playbook task naming it — still are not true.
    """
    dead = _DELETED_LIBRARY
    assert not os.path.isdir(os.path.join(_SCRIPTS, dead)), (
        "%s is back in Scripts/. Nothing imports it and the tenant resolves no cross-script "
        "import, so it can only ship as a content item that never runs." % dead)
    unified = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "unified",
                           "%s.yml" % dead)
    assert not os.path.exists(unified), (
        "%s is back in unified/, which is the set a customer imports — its presence there "
        "implies the tenant needs it, and the tenant cannot even resolve it." % unified)

    for automation in SHIPPING:
        with open(SHIPPING_PATHS[automation]) as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name != dead for a in node.names), (
                    "%s imports %s — the tenant cannot resolve that import, and no drift "
                    "gate covers %s" % (automation, dead, dead))
            elif isinstance(node, ast.ImportFrom):
                assert node.module != dead, (
                    "%s does `from %s import ...` — the tenant cannot resolve that import, "
                    "and no drift gate covers %s" % (automation, dead, dead))

    playbook = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Playbooks",
                            "playbook-YARA_Dataset_Consolidation.yml")
    assert os.path.exists(playbook), playbook
    with open(playbook) as fh:
        assert dead not in fh.read(), (
            "%s names %s, so it is reachable on the tenant after all" % (playbook, dead))


@pytest.mark.parametrize("impl", SHIPPING_IMPLS)
def test_pack_name_regexes_compile_to_the_same_patterns_as_the_cli(impl):
    # NAME_RE is built from PREFIX, which each automation aliases to its own _PREFIX — the
    # source comparison above cannot see that the two literals still agree.
    # YARA_OWNED_RE/CURRENT_RE come from xdr_action_center.py instead, and were previously
    # covered only behaviourally by one seven-name fixture.
    import xdr_data_management as CLI
    impl.set_schema_version(impl.DEFAULT_SCHEMA_VERSION)
    assert impl.PREFIX == CLI.PREFIX
    assert impl.NAME_RE.pattern == CLI.NAME_RE.pattern
    assert impl.MONTH_RE.pattern == CLI.MONTH_RE.pattern
    assert impl.DEFAULT_MIN_QUIET_HOURS == CLI.DEFAULT_MIN_QUIET_HOURS
    assert impl.YARA_OWNED_RE.pattern == AC.YARA_OWNED_RE.pattern
    assert impl.CURRENT_RE.pattern == AC.CURRENT_RE.pattern


@pytest.mark.parametrize("impl", SHIPPING_IMPLS)
def test_pack_classify_yara_datasets_matches_xdr_action_center(impl):
    """classify_yara_datasets is ported from a METHOD (XDRActionCenter), so it cannot be
    diffed statement-by-statement. Prove it behaviourally instead, on one dataset list."""
    names = ["yara_scanner_matches_v2_h_202607", "yara_scanner_scans_v2_h_202607",
             "yara_scanner_matches_v1_h", "yara_matches_old", "yara_scanner_matches_v9_h",
             "yara_scanner_consolidation_runs", "some_other_dataset"]
    raw = [{"Dataset Name": n, "Type": "LOOKUP"} for n in names]

    ac = AC.XDRActionCenter.__new__(AC.XDRActionCenter)     # no creds, no network
    ac.get_datasets = lambda: raw
    impl.set_schema_version(impl.DEFAULT_SCHEMA_VERSION)
    assert impl.classify_yara_datasets(FakeTenant(names)) == ac.classify_yara_datasets()


def _scanner_schema_default():
    """The scanner's LOOKUP_SCHEMA_VERSION fallback, read from source. Importing the scanner
    would drag in yara/psutil, which this suite deliberately does not require."""
    src = open(os.path.join(_REPO, "xdr", "xdr_yara_scanner.py")).read()
    m = re.search(r'^LOOKUP_SCHEMA_VERSION\s*=\s*os\.environ\.get\(\s*"YARA_LOOKUP_SCHEMA_VER"\s*,\s*"(\d+)"',
                  src, re.M)
    assert m, "could not find LOOKUP_SCHEMA_VERSION in xdr_yara_scanner.py"
    return m.group(1)


@pytest.mark.parametrize("automation", SHIPPING)
def test_the_shipped_default_tracks_the_scanners_schema_version(automation):
    """The scanner NAMES datasets `..._v<LOOKUP_SCHEMA_VERSION>_...`; these automations decide
    which of those names count as current from their own default. When the two disagree every
    live dataset classifies as "newer", and the tooling's correct response to "newer" is to
    touch nothing — so a run reports 0 candidates and exits 0. It looks like a clean no-op,
    not a misconfiguration, which is exactly why this needs a gate rather than a reader.
    """
    want = _scanner_schema_default()
    got = SHIPPING_MODULES[automation].DEFAULT_LOOKUP_SCHEMA_VERSION
    assert got == want, (
        "%s ships DEFAULT_LOOKUP_SCHEMA_VERSION=%r but the scanner writes v%s datasets — "
        "every live dataset would classify as 'newer' and be silently skipped"
        % (automation, got, want))


def test_the_cli_default_tracks_the_scanners_schema_version():
    """Same gate for the operator CLI, which classifies from its own module-level copy."""
    assert AC.YARA_SCHEMA_VERSION == _scanner_schema_default()


@pytest.mark.parametrize("impl", SHIPPING_IMPLS)
def test_set_schema_version_moves_newer_datasets_into_current(impl):
    """XSOAR containers have no YARA_LOOKUP_SCHEMA_VER env var, so the version the CLI
    reads from the environment has to be passable as an argument instead."""
    names = ["yara_scanner_matches_v3_h_202601"]
    try:
        # Set explicitly. The autouse fixture resets the CLI library's global, not each
        # automation's own copy, so without this the baseline is whatever the previous
        # parametrised case left behind.
        impl.set_schema_version("2")
        cur, legacy, newer = impl.classify_yara_datasets(FakeTenant(names))
        assert (cur, newer) == ([], names)            # v3 > assumed v2 -> never pruned
        impl.set_schema_version("3")
        cur, legacy, newer = impl.classify_yara_datasets(FakeTenant(names))
        assert (cur, newer) == (names, [])
    finally:
        impl.set_schema_version("2")


@pytest.mark.parametrize("impl", SHIPPING_IMPLS)
def test_set_schema_version_refuses_a_non_numeric_version(impl):
    """The single highest-blast-radius argument in the pack. "v3"/"abc" makes CURRENT_RE
    match nothing AND cur_ver None, so rail 4's `v > cur_ver` guard can never fire and every
    live dataset on the tenant falls into `legacy`. Refusing here is the only point at which
    that is still distinguishable from a genuine legacy tenant."""
    for bad in ("v3", "abc", "", "  ", "3.0", "-1"):
        with pytest.raises(ValueError):
            impl.set_schema_version(bad)
    assert impl.YARA_SCHEMA_VERSION == "2"            # unchanged by the rejected calls


# --------------------------------------------------------------------- rails
def test_rail1_never_deletes_the_current_month():
    """delete_dataset on a dataset a scan is WRITING to does not error the scan — it keeps
    POSTing rows to a name that no longer exists and gets HTTP 400 per batch."""
    ds = "yara_scanner_matches_v2_h_202607"           # == NOW_YYYYMM
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "current month" in s for s in r["skipped"])


def test_rail1_still_holds_when_the_age_window_does_not_cover_it():
    """At older_than_months=0 the generic `age <= window` check already skips a current-month
    dataset (age 0), so that test alone passes with rail 1 deleted. A NEGATIVE window is
    where rail 1 is the only thing left, and the argument accepts one."""
    ds = "yara_scanner_matches_v2_h_202607"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=-1, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "current month" in s for s in r["skipped"])


def test_rail2_never_deletes_a_future_month():
    ds = "yara_scanner_matches_v2_h_202612"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "future" in s for s in r["skipped"])


def test_rail2_still_holds_when_the_age_window_does_not_cover_it():
    """Same argument as rail 1: at window 0 the negative age is caught by `age <= window`
    anyway. At window -1 only the explicit future check stands between clock skew and a
    delete."""
    ds = "yara_scanner_matches_v2_h_202612"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=-1, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "future" in s for s in r["skipped"])


def test_rail3_never_deletes_an_unsuffixed_dataset():
    """An unsuffixed dataset holds ALL pre-rotation history for that host — same API call,
    categorically bigger blast radius than dropping one month."""
    ds = "yara_scanner_matches_v2_h"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "not rotated" in s for s in r["skipped"])


# ------------------------------------------- the v4 overwrite matches dataset
# Since the scanner started overwriting the per-host matches dataset at the start of every
# scan, `yara_scanner_matches_v4_<host>` carries no month BY DESIGN. The pre-v4 classifier
# read "no month" as "rotation is off, this grows without bound" and told the operator to
# set CONFIG_LOOKUP_ROTATION="monthly" — advice that is both wrong (the dataset is bounded
# by the overwrite) and unactionable (that setting governs the SCANS datasets only).

def _classify_at_v4(impl, names):
    impl.set_schema_version("4")
    try:
        return impl.report_datasets(FakeTenant(names), now_yyyymm=NOW_YYYYMM)
    finally:
        impl.set_schema_version(TEST_SCHEMA_VERSION)


def test_the_v4_matches_dataset_is_not_reported_as_unrotated():
    ds = "yara_scanner_matches_v4_hostA_abc123"
    r = _classify_at_v4(R, [ds])
    assert r["overwrite"] == [ds], r["overwrite"]
    assert r["not_rotated"] == [] and r["frozen"] == []
    assert [d["state"] for d in r["datasets"]] == ["overwrite"]


def test_the_overwrite_dataset_is_never_a_deletion_candidate():
    """It was already protected — an unsuffixed name has never been selectable. What changed
    is the REASON, which previously told the operator to enable a setting that does not apply
    to this dataset and would not have changed its name if it did."""
    ds = "yara_scanner_matches_v4_hostA_abc123"
    R.set_schema_version("4")
    try:
        cands, skipped = R.select_rotated_for_deletion([ds], older_than_months=0,
                                                       now_yyyymm=NOW_YYYYMM)
    finally:
        R.set_schema_version(TEST_SCHEMA_VERSION)
    assert cands == []
    reason = next(s for s in skipped if ds in s)
    assert "REPLACES it" in reason
    assert "CONFIG_LOOKUP_ROTATION" not in reason or "does not apply" in reason


def test_a_dated_v4_matches_dataset_is_still_ordinary_debris():
    """The pre-overwrite naming left dated matches datasets behind. Those are NOT the live
    dataset and must stay deletable once they age out, or the leftovers are unreachable."""
    ds = "yara_scanner_matches_v4_hostA_abc123_202601"
    R.set_schema_version("4")
    try:
        cands, _ = R.select_rotated_for_deletion([ds], older_than_months=0,
                                                 now_yyyymm=NOW_YYYYMM)
    finally:
        R.set_schema_version(TEST_SCHEMA_VERSION)
    assert cands == [ds]


def test_only_matches_and_only_from_v4_count_as_overwrite():
    """Both boundaries. SCANS still rotates monthly at v4, so an unsuffixed scans dataset is
    genuinely unrotated; and on v2/v3 matches rotated too, so the old warning is still right
    for a tenant pinned there. Both models' datasets coexist during a rollout."""
    scans_v4 = "yara_scanner_scans_v4_hostA_abc123"
    R.set_schema_version("4")
    try:
        r = R.report_datasets(FakeTenant([scans_v4]), now_yyyymm=NOW_YYYYMM)
    finally:
        R.set_schema_version(TEST_SCHEMA_VERSION)
    assert r["overwrite"] == [] and r["not_rotated"] == [scans_v4]

    matches_v3 = "yara_scanner_matches_v3_hostA_abc123"
    R.set_schema_version("3")
    try:
        r = R.report_datasets(FakeTenant([matches_v3]), now_yyyymm=NOW_YYYYMM)
    finally:
        R.set_schema_version(TEST_SCHEMA_VERSION)
    assert r["overwrite"] == [] and r["not_rotated"] == [matches_v3]


@pytest.mark.parametrize("impl", SHIPPING_IMPLS)
def test_every_automation_classifies_the_overwrite_dataset_alike(impl):
    """parse_dataset_name is carried in all five; a fix that reaches only one is the exact
    failure mode the drift gate exists for."""
    info = impl.parse_dataset_name("yara_scanner_matches_v4_hostA_abc123")
    assert info["overwrite"] is True
    assert impl.parse_dataset_name("yara_scanner_scans_v4_hostA_abc123")["overwrite"] is False
    assert impl.parse_dataset_name("yara_scanner_matches_v2_hostA")["overwrite"] is False


def test_rail4_never_deletes_a_newer_schema_version():
    """A host running a stale YARA_LOOKUP_SCHEMA_VER must never delete a future schema's
    data — classification, not selection, is what keeps it out of reach."""
    ds = "yara_scanner_matches_v9_h_202601"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, delete_legacy=True, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert ds not in r["selected"]


def test_rail4_reports_the_newer_bucket_it_vetoed():
    """Requirement (d) for the one bucket that used to be discarded silently: "0 selected,
    0 skipped" must never be the report for "rail 4 vetoed the entire tenant"."""
    ds = "yara_scanner_matches_v9_h_202601"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["newer"] == [ds] and r["newer_count"] == 1
    assert any(ds in s and "NEWER schema" in s and "schema_version" in s for s in r["skipped"])


def test_rail5_never_deletes_a_dataset_that_reaches_the_selector_unparsed():
    """The real rail-5 guard is `parse_dataset_name(...) is None` INSIDE the selector, and a
    foreign name never gets that far (classify_yara_datasets drops it first). This name does:
    a trailing underscore satisfies YARA_OWNED_RE and CURRENT_RE, so it lands in `current`,
    but NAME_RE rejects it."""
    ds = "yara_scanner_matches_v2_"
    t = FakeTenant([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "not a YARA dataset name" in s for s in r["skipped"])


def test_a_foreign_dataset_never_reaches_the_selector_at_all():
    """The ownership filter, one layer above rail 5."""
    foreign = "some_other_dataset_202601"
    t = FakeTenant([foreign])
    r = _prune(t, older_than_months=0, delete_legacy=True, execute=True)
    assert r["deleted"] == [] and foreign in t.names


def test_rail6_never_deletes_a_shard_still_being_written_to():
    """The month label says old; the rows say a scan is still writing (a scan running late
    across a month boundary, or endpoint clock skew)."""
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds], newest={ds: NOW_MS - 60_000})     # 1 minute ago
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "may still be writing" in s for s in r["skipped"])


def test_rail6_cannot_be_switched_off_from_the_console():
    """min_quiet_hours=0 does not relax rail 6, it DISABLES it: filter_recently_written's
    `(now - newest) < 0 * 1000` is false for a row written one second ago. The automation
    floors the value rather than passing a rail-off switch through."""
    import YaraCleanup
    ds = "yara_scanner_matches_v2_h_202606"
    t = FakeTenant([ds], newest={ds: int(time.time() * 1000) - 1000})   # 1 second old
    out = _run_automation(YaraCleanup, {"older_than_months": "0", "min_quiet_hours": "0",
                                        "execute": "true"}, t)
    assert ds in t.names and ds not in t.deleted()
    assert out.outputs["min_quiet_hours"] == K.MIN_ALLOWED_QUIET_HOURS
    assert "floor" in out.readable_output

    t = FakeTenant([ds], newest={ds: int(time.time() * 1000) - 1000})
    out = _run_automation(YaraCleanup, {"older_than_months": "0", "min_quiet_hours": "-99999",
                                        "execute": "true"}, t)
    assert ds in t.names and ds not in t.deleted()


def test_rail6_skips_to_be_safe_when_the_recency_query_errors():
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds], error_on=("comp max(event_timestamp_ms)",))
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any("could not check recency" in s for s in r["skipped"])


def test_rail7_never_deletes_a_shard_holding_an_unconsolidated_scan():
    """A permanently-stuck scan (row_ceiling_exceeded) blocks xdr_consolidate's own delete
    pass forever; this prune knows nothing about that and would drop the only copy. The
    per-scan target does not exist here at all, so the tenant raises and tcount is -1."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 463}})
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any(ds in s and "S1" in s and "would lose data" in s for s in r["skipped"])


def test_rail7_skips_to_be_safe_when_the_consolidation_query_errors():
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], error_on=("by scan_id",))
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [] and ds in t.names
    assert any("could not check consolidation state" in s for s in r["skipped"])


def test_a_consolidated_per_scan_target_is_never_a_deletion_candidate():
    """Consolidation's own OUTPUT. It is unsuffixed by design, and once the source shards
    were deleted it is the ONLY copy of that scan. A slug ending in month-shaped digits must
    not make it look like an ancient rotated dataset — and rail 7 cannot save it, because a
    target verifies against ITSELF (count == count reads as "already consolidated")."""
    target = "yara_scanner_matches_v2_scan_winserver01_20260812_110501"
    t = FakeTenant([target], counts={target: 500}, scans={target: {"S1": 500}})
    r = _prune(t, older_than_months=6, execute=True)
    assert r["deleted"] == [] and target in t.names
    assert any(target in s and "per-scan consolidated target" in s for s in r["skipped"])


def test_a_timestamp_shaped_slug_does_not_crash_either_automation():
    """"143025" is not a month; under a bare \\d{6} it raised ValueError out of
    months_between, aborting the mutating prune AND the read-only report."""
    target = "yara_scanner_matches_v2_scan_winserver01_20260812_143025"
    t = FakeTenant([target])
    r = _prune(t, older_than_months=6, execute=True)
    assert r["deleted"] == [] and target in t.names
    rep = R.report_datasets(FakeTenant([target]), now_yyyymm=NOW_YYYYMM)
    assert rep["consolidated"] == [target]


def test_a_fully_verified_quiet_old_shard_is_deleted():
    """The rails must not be vacuous: a shard that passes all seven really is deleted."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], newest={ds: NOW_MS - 30 * 86_400_000},
                   scans={ds: {"S1": 463}},
                   counts={"yara_scanner_matches_v2_scan_s1": 463})
    r = _prune(t, older_than_months=3, execute=True)
    assert r["deleted"] == [ds] and ds not in t.names
    assert r["failed_count"] == 0


# ------------------------------------------------------------- dry run first
def test_dry_run_by_default_deletes_nothing():
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    r = _prune(t, older_than_months=3)                 # no execute= at all
    assert r["dry_run"] is True
    assert r["selected"] == [ds]                       # it WOULD have gone
    assert r["deleted"] == [] and r["deleted_count"] == 0
    assert ds in t.names                               # still on the tenant
    assert t.deleted() == []


def test_dry_run_makes_no_mutating_call_of_any_kind():
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    _prune(t, older_than_months=3, delete_legacy=True)
    assert t.mutating_calls() == []


def test_the_automation_defaults_to_dry_run_when_execute_is_not_given():
    """Requirement (a): an operator who runs YaraCleanup with a window but no opt-in must
    never lose data — asserted on the tenant's dataset list, not on a returned flag."""
    import YaraCleanup
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    out = _run_automation(YaraCleanup, {"older_than_months": "3"}, t)
    assert ds in t.names and t.deleted() == []
    assert out.outputs["dry_run"] is True
    assert "DRY RUN" in out.readable_output


def test_the_automation_deletes_only_with_an_explicit_opt_in():
    import YaraCleanup
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    out = _run_automation(YaraCleanup, {"older_than_months": "3", "execute": "true"}, t)
    assert ds not in t.names
    assert out.outputs["deleted"] == [ds]
    assert "DRY RUN" not in out.readable_output


@pytest.mark.parametrize("value", [None, "", "false", "False", "no", "0", "off", "n", "f",
                                   "maybe", "TRUE!", " "])
def test_only_an_explicit_affirmative_can_delete(value):
    """Vocabulary-independent statement of requirement (a): whatever the platform's
    argToBoolean happens to accept, a value that is not an explicit affirmative either reads
    as False or raises — and NEITHER outcome deletes anything."""
    import YaraCleanup
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    args = {"older_than_months": "3"}
    if value is not None:
        args["execute"] = value
    try:
        _run_automation(YaraCleanup, args, t)
    except SystemExit:
        pass                                   # return_error path — also deletes nothing
    assert ds in t.names and t.deleted() == []


@pytest.mark.parametrize("value", ["true", "True", "yes"])
def test_the_ordinary_affirmatives_do_delete(value):
    import YaraCleanup
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    _run_automation(YaraCleanup, {"older_than_months": "3", "execute": value}, t)
    assert ds not in t.names


# ------------------------------------------------------------ argument wiring
def test_delete_legacy_is_wired_through_the_automations_arguments():
    """Every argument's path from demisto.args() to behaviour needs its own assertion — a
    typo'd arg name makes a documented flag a permanent silent no-op."""
    import YaraCleanup
    legacy = "yara_scanner_matches_v1_h_202601"
    t = FakeTenant([legacy])
    out = _run_automation(YaraCleanup, {"delete_legacy": "true", "execute": "true"}, t)
    assert legacy not in t.names and out.outputs["deleted"] == [legacy]
    assert out.outputs["delete_legacy"] is True


def test_min_quiet_hours_is_wired_through_and_is_really_hours():
    """48h old passes the 24h default but not a 72h override — this pins both the wiring and
    the unit. An operator widening the window to protect a long fleet-wide scan must not
    silently get 24 back."""
    import YaraCleanup
    ds = "yara_scanner_matches_v2_h_202601"
    now = int(time.time() * 1000)
    t = FakeTenant([ds], newest={ds: now - 48 * 3_600_000})
    _run_automation(YaraCleanup, {"older_than_months": "0", "min_quiet_hours": "72",
                                  "execute": "true"}, t)
    assert ds in t.names                       # 48h < 72h -> kept

    t = FakeTenant([ds], newest={ds: now - 48 * 3_600_000})
    _run_automation(YaraCleanup, {"older_than_months": "0", "execute": "true"}, t)
    assert ds not in t.names                   # 48h > the 24h default -> deleted


def test_force_is_wired_through_to_delete_dataset():
    import YaraCleanup
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds])
    _run_automation(YaraCleanup, {"older_than_months": "0", "force": "true",
                                  "execute": "true"}, t)
    assert (ds, True) in t.force_flags


def test_schema_version_is_wired_through_both_automations():
    """The pack's entire substitute for the YARA_LOOKUP_SCHEMA_VER env var an XSOAR
    container does not have. Without it a v3 tenant classifies everything as `newer`,
    YaraCleanup prunes nothing forever and YaraReport reports the wrong current schema."""
    import YaraCleanup
    import YaraReport
    ds = "yara_scanner_matches_v3_h_202601"
    out = _run_automation(YaraReport, {"schema_version": "3"}, FakeTenant([ds]))
    assert out.outputs["current_count"] == 1 and out.outputs["newer"] == []

    t = FakeTenant([ds])
    out = _run_automation(YaraCleanup, {"older_than_months": "0", "schema_version": "3"}, t)
    assert out.outputs["schema_version"] == "3" and out.outputs["newer"] == []


def test_the_schema_version_does_not_leak_into_the_next_run():
    """set_schema_version mutates a module global AND os.environ, and one XSOAR docker
    container serves many executions. A run that passes schema_version must not decide the
    scope of the next run that passes none."""
    import YaraReport
    ds = "yara_scanner_matches_v3_h_202601"
    _run_automation(YaraReport, {"schema_version": "3"}, FakeTenant([ds]), pin_schema=False)
    out = _run_automation(YaraReport, {}, FakeTenant([ds]), pin_schema=False)
    # Asserted against the SHIPPED default rather than a literal: the point of this test is
    # that run 2 falls back, not that the fallback happens to be any particular version.
    assert out.outputs["schema_version"] == YaraReport.DEFAULT_LOOKUP_SCHEMA_VERSION
    assert out.outputs["schema_version"] != "3"


def test_a_malformed_argument_fails_with_this_scripts_own_message():
    """All coercion happens inside a try, so a mistyped argument produces "nothing was
    deleted" rather than a bare traceback — on the one automation whose whole UX premise is
    that a typo is obviously and legibly harmless."""
    import YaraCleanup
    for args in ({"older_than_months": "3.5"}, {"older_than_months": "six"},
                 {"min_quiet_hours": "abc", "older_than_months": "3"},
                 {"execute": "maybe", "older_than_months": "3"},
                 {"schema_version": "v3", "older_than_months": "3"}):
        ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
        t = FakeTenant([ds])
        demistomock.args_value = dict(args)
        demistomock.commands = []
        del CommonServerPython.results[:]
        del CommonServerPython.errors[:]
        real = YaraCleanup.CoreApiClient
        YaraCleanup.CoreApiClient = lambda *a, **k: t
        try:
            with pytest.raises(SystemExit):
                YaraCleanup.main()
        finally:
            YaraCleanup.CoreApiClient = real
        assert CommonServerPython.errors, "no return_error for %s" % args
        assert "YaraCleanup" in CommonServerPython.errors[0]
        assert ds in t.names and t.deleted() == []
        # Stale context from a previous successful run must not survive a failed one.
        assert ("DeleteContext", {"key": "Yara.Cleanup"}) in demistomock.commands


# ------------------------------------------------------------------ the lock
def test_a_real_deletion_pass_takes_and_releases_the_lock():
    """Pruning and consolidation mutate the same shards, and rails 6/7 are point-in-time
    checks — so the lock must be held across the checks AND the deletes, not just around
    the deletes."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds], scans={ds: {"S1": 5}}, counts={"yara_scanner_matches_v2_scan_s1": 5})
    _prune(t, older_than_months=3, execute=True)
    acquired = t.calls.index("create_lookup_dataset:%s" % K._LOCK_DATASET)
    deleted = t.calls.index("delete_dataset:%s" % ds)
    released = t.calls.index("delete_dataset:%s" % K._LOCK_DATASET)
    first_rail_query = next(i for i, c in enumerate(t.calls) if "comp max(event_timestamp_ms)" in c)
    assert acquired < first_rail_query < deleted < released
    assert K._LOCK_DATASET not in t.names


def test_the_lock_is_released_even_when_the_pass_blows_up():
    """The release belongs in a `finally`, not on the happy path. get_datasets() is inside
    the try and is a realistic raiser (HTTP 401 after a key rotation, an XQL timeout, a
    tenant 5xx). A leaked marker parks the twice-daily merge Job for hours — the precise
    interference the lock exists to prevent, caused by the lock itself."""
    class Exploding(FakeTenant):
        def get_datasets(self):
            raise RuntimeError("HTTP 401")

    t = Exploding(["yara_scanner_matches_v2_hostx_ab1234_202601"])
    with pytest.raises(RuntimeError):
        _prune(t, older_than_months=3, execute=True)
    assert "delete_dataset:%s" % K._LOCK_DATASET in t.calls
    assert K._LOCK_DATASET not in t.names


def test_a_dry_run_never_takes_the_lock():
    """A dry run mutates nothing and must stay safe to run concurrently with anything,
    including a consolidation pass."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds])
    _prune(t, older_than_months=3)
    assert not any(c.startswith("create_lookup_dataset") for c in t.calls)
    assert not any(K._LOCK_DATASET in c for c in t.calls)


def test_a_held_lock_blocks_deletion_and_is_reported():
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds, K._LOCK_DATASET], scans={ds: {"S1": 5}},
                   counts={"yara_scanner_matches_v2_scan_s1": 5})
    t.lock_rows = [{"holder": "YaraConsolidateApply", "started_ms": NOW_MS - 60_000}]
    r = _prune(t, older_than_months=3, execute=True)
    assert r["lock_held_by_other_run"] is True
    assert r["deleted"] == [] and ds in t.names
    assert t.lock_rows                                  # the other run's lock is untouched


def test_an_unreadable_lock_row_is_treated_as_held_by_the_delete_path():
    """The marker dataset exists but has no readable row — precisely the window right after
    another run created it, since add_lookup_data tolerates ~60s of create-lag. Consolidation
    may take that over (it costs a redundant merge); a prune may not (it costs datasets)."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds, K._LOCK_DATASET], scans={ds: {"S1": 5}},
                   counts={"yara_scanner_matches_v2_scan_s1": 5})
    t.lock_rows = []                                    # created, row not landed yet
    r = _prune(t, older_than_months=3, execute=True)
    assert r["lock_held_by_other_run"] is True
    assert r["deleted"] == [] and ds in t.names
    assert "delete_dataset:%s" % K._LOCK_DATASET not in t.calls   # not stolen


def test_a_long_running_consolidation_lock_is_not_stolen_by_a_prune():
    """Consolidation's own 20-minute staleness window would treat a 3h-old lock as abandoned.
    For a prune the cost of being wrong is deleted datasets, so it judges on a much longer
    window (PRUNE_LOCK_STALE_SECS, 6h)."""
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds, K._LOCK_DATASET], scans={ds: {"S1": 5}},
                   counts={"yara_scanner_matches_v2_scan_s1": 5})
    t.lock_rows = [{"holder": "YaraConsolidateApply", "started_ms": NOW_MS - 3 * 3_600_000}]
    assert 3 * 3600 > K.DEFAULT_LOCK_STALE_SECS         # consolidation would have taken it
    r = _prune(t, older_than_months=3, execute=True)
    assert r["lock_held_by_other_run"] is True and ds in t.names


def test_a_genuinely_stale_lock_is_taken_over_but_never_silently():
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds, K._LOCK_DATASET])
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": NOW_MS - (K.PRUNE_LOCK_STALE_SECS + 3600) * 1000}]
    r = _prune(t, older_than_months=0, execute=True)
    assert r["lock_taken_over"] is True and "taking over" in r["lock_takeover_reason"]
    assert r["deleted"] == [ds]


def test_the_automation_reports_a_held_lock():
    import YaraCleanup
    ds = "yara_scanner_matches_v2_hostx_ab1234_202601"
    t = FakeTenant([ds, K._LOCK_DATASET])
    # main() has no now_ms seam — it runs on the real clock, so the held lock has to look
    # fresh against that, not against this module's frozen NOW_MS (which would read as stale
    # and be taken over).
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": int(time.time() * 1000) - 60_000}]
    out = _run_automation(YaraCleanup, {"older_than_months": "3", "execute": "true"}, t)
    assert out.outputs["lock_held_by_other_run"] is True
    assert "lock" in out.readable_output.lower()
    assert ds in t.names


def test_the_automation_surfaces_a_lock_takeover_to_the_operator():
    """"I deleted while another run's marker was in place" must never be indistinguishable
    from an ordinary pass — the takeover message exists only in the library's log stream."""
    import YaraCleanup
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds, K._LOCK_DATASET])
    t.lock_rows = [{"holder": "YaraConsolidateApply",
                    "started_ms": int(time.time() * 1000)
                    - (K.PRUNE_LOCK_STALE_SECS + 3600) * 1000}]
    out = _run_automation(YaraCleanup, {"older_than_months": "0", "execute": "true"}, t)
    assert out.outputs["lock_taken_over"] is True
    assert "TOOK IT OVER" in out.readable_output
    assert "lock events:" in out.readable_output


# ------------------------------------------------ nothing asked for, nothing done
def test_no_threshold_and_no_legacy_flag_does_nothing_at_all():
    """Requirement (c): --older-than-months has no default in the CLI on purpose. A bare
    invocation must not fall back to some assumed window."""
    ds = "yara_scanner_matches_v2_h_202001"             # ancient, would go under any window
    t = FakeTenant([ds])
    r = _prune(t, execute=True)
    assert r["nothing_requested"] is True
    assert r["deleted"] == [] and r["selected"] == [] and ds in t.names
    assert t.calls == []                                # not even a listing call


def test_the_automation_with_no_arguments_does_nothing_and_says_so():
    import YaraCleanup
    ds = "yara_scanner_matches_v2_h_202001"
    t = FakeTenant([ds])
    out = _run_automation(YaraCleanup, {}, t)
    assert out.outputs["nothing_requested"] is True
    assert ds in t.names and t.calls == []
    assert "nothing" in out.readable_output.lower()


# -------------------------------------------------------------- skip reasons
def test_every_skipped_candidate_reports_its_own_reason():
    """Requirement (d): a dataset silently not deleted is indistinguishable from a bug."""
    current_month = "yara_scanner_matches_v2_a_202607"
    future = "yara_scanner_matches_v2_b_202612"
    unrotated = "yara_scanner_matches_v2_c"
    busy = "yara_scanner_matches_v2_d_202601"
    stuck = "yara_scanner_matches_v2_e_ab1234_202601"
    t = FakeTenant([current_month, future, unrotated, busy, stuck],
                   newest={busy: NOW_MS - 60_000},
                   scans={stuck: {"S9": 12}})
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == []
    joined = "\n".join(r["skipped"])
    for name in (current_month, future, unrotated, busy, stuck):
        assert name in joined, "no skip reason surfaced for %s" % name
    assert r["skipped_count"] == len(r["skipped"]) == 5


def test_legacy_datasets_left_out_of_scope_are_reported_too():
    """Without this, a tenant full of legacy shards and a run without delete_legacy reports
    "0 selected, 0 skipped" and the operator cannot tell it from "nothing has aged out"."""
    legacy = "yara_scanner_matches_v1_h_202601"
    t = FakeTenant([legacy])
    r = _prune(t, older_than_months=0, execute=True)
    assert any(legacy in s and "delete_legacy was not set" in s for s in r["skipped"])


def test_the_automation_surfaces_every_skip_reason_to_the_operator():
    import YaraCleanup
    # A rail that does not depend on the clock — main() has no now_ms/now_yyyymm seam.
    unrotated = "yara_scanner_matches_v2_hostB"
    t = FakeTenant([unrotated])
    out = _run_automation(YaraCleanup, {"older_than_months": "0"}, t)
    assert any(unrotated in s and "not rotated" in s for s in out.outputs["skipped"])
    assert unrotated in out.readable_output
    assert "kept, with reason" in out.readable_output


def test_the_automation_records_the_scope_it_ran_with():
    import YaraCleanup
    t = FakeTenant(["yara_scanner_matches_v2_hostB"])
    out = _run_automation(YaraCleanup, {"older_than_months": "0"}, t)
    assert "schema v2" in out.readable_output and "min_quiet_hours" in out.readable_output


# ---------------------------------------------------------------- legacy path
def test_delete_legacy_applies_the_same_rails_as_the_age_path():
    """The scenario that motivated this: a fleet mid-rollout, half the endpoints still on the
    previous scanner version and scanning RIGHT NOW. Their shards classify as legacy. Only
    the live rails can tell that apart from genuinely-dead old-schema leftovers."""
    writing = "yara_scanner_matches_v1_hostA_ab1234_202606"      # newest row 1s old
    history = "yara_scanner_matches_v1_hostA"                    # ALL pre-rotation history
    unconsolidated = "yara_scanner_matches_v1_hostB_cd5678_202606"
    dead = "yara_scanner_matches_v1_hostC_ef9012_202601"         # quiet, empty -> really goes
    t = FakeTenant([writing, history, unconsolidated, dead],
                   newest={writing: NOW_MS - 1000},
                   scans={unconsolidated: {"S1": 900}})
    r = _prune(t, delete_legacy=True, execute=True)
    assert r["deleted"] == [dead]
    for kept in (writing, history, unconsolidated):
        assert kept in t.names
        assert any(kept in s for s in r["skipped"]), "no reason given for keeping %s" % kept
    assert any(writing in s and "may still be writing" in s for s in r["skipped"])
    assert any(history in s and "ALL pre-rotation history" in s for s in r["skipped"])
    assert any(unconsolidated in s and "would lose data" in s for s in r["skipped"])


def test_delete_legacy_is_refused_outright_while_a_newer_schema_exists():
    """A newer-schema dataset proves schema_version is stale, which means the legacy bucket
    may be full of live data. Same keep-guard xdr_action_center.py's prune-datasets carries."""
    legacy = "yara_scanner_matches_v1_h_202601"
    newer = "yara_scanner_matches_v9_h_202601"
    t = FakeTenant([legacy, newer])
    r = _prune(t, delete_legacy=True, execute=True)
    assert r["deleted"] == [] and legacy in t.names and newer in t.names
    assert any("NEWER schema" in s and "cannot be trusted" in s for s in r["skipped"])


def test_a_too_high_schema_version_cannot_delete_the_live_tenant():
    """The blocker this suite exists for. schema_version="3" on a v2 tenant is undetectable
    from the version alone (2 > 3 is simply False, so every live dataset classifies as
    legacy) — the rails on the legacy path are what stop it."""
    import YaraCleanup
    now = int(time.time() * 1000)
    live = "yara_scanner_matches_v2_hostA_ab1234_202607"
    history = "yara_scanner_matches_v2_hostA"
    target = "yara_scanner_matches_v2_scan_abc123def456"
    stuck = "yara_scanner_matches_v2_hostB_cd5678_202601"
    t = FakeTenant([live, history, target, stuck],
                   newest={live: now - 1000},
                   scans={stuck: {"S1": 900}},
                   counts={target: 500})
    out = _run_automation(YaraCleanup, {"schema_version": "3", "delete_legacy": "true",
                                        "execute": "true"}, t)
    assert out.outputs["deleted"] == []
    for name in (live, history, target, stuck):
        assert name in t.names, "%s was deleted" % name
    assert out.outputs["skipped_count"] == 4


def test_a_delete_failure_does_not_strand_the_rest_of_the_cleanup():
    a = "yara_scanner_matches_v1_a_202601"
    b = "yara_scanner_matches_v1_b_202601"

    class Flaky(FakeTenant):
        def delete_dataset(self, dataset_name, force=False):
            if dataset_name == a:
                raise RuntimeError("dataset has dependencies")
            return FakeTenant.delete_dataset(self, dataset_name, force=force)

    t = Flaky([a, b])
    r = _prune(t, delete_legacy=True, execute=True)
    assert r["deleted"] == [b] and r["failed_count"] == 1
    assert r["failed"][0]["dataset"] == a and "dependencies" in r["failed"][0]["error"]


# ------------------------------------------------------------- the audit trail
def test_an_executed_pass_leaves_a_durable_record():
    """The only automation here whose action cannot be undone, and War Room entries plus
    investigation context are per-run and not queryable across runs."""
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds])
    _prune(t, older_than_months=0, execute=True)
    assert "add_lookup_data:%s" % K._CLEANUP_RUNS_DATASET in t.calls
    assert K._CLEANUP_RUNS_DATASET != K._RUNS_DATASET     # never the consolidation run-log


def test_a_dry_run_leaves_no_record_because_it_did_nothing():
    ds = "yara_scanner_matches_v2_h_202601"
    t = FakeTenant([ds])
    _prune(t, older_than_months=0)
    assert not any(K._CLEANUP_RUNS_DATASET in c for c in t.calls)


def test_a_failure_to_record_never_masks_the_runs_real_outcome():
    ds = "yara_scanner_matches_v2_h_202601"

    class NoRecord(FakeTenant):
        def add_lookup_data(self, dataset_name, rows):
            if dataset_name == K._CLEANUP_RUNS_DATASET:
                raise RuntimeError("dataset quota exceeded")
            return FakeTenant.add_lookup_data(self, dataset_name, rows)

    t = NoRecord([ds])
    r = _prune(t, older_than_months=0, execute=True)
    assert r["deleted"] == [ds] and r["failed_count"] == 0


# -------------------------------------------------------------------- report
def test_the_report_is_genuinely_read_only():
    t = FakeTenant(["yara_scanner_matches_v2_h_202601", "yara_scanner_matches_v1_h"])
    R.report_datasets(t, now_yyyymm=NOW_YYYYMM)
    assert t.mutating_calls() == []
    assert t.calls == ["get_datasets"]                  # not even a row-count query


def test_the_report_flags_frozen_separately_from_not_rotated():
    """Opposite advice: 'frozen' is a pre-rotation leftover (rotation IS on, writes moved
    to the dated names); 'not rotated' means rotation is genuinely off and it will grow."""
    frozen = "yara_scanner_matches_v2_hostA"
    sibling = "yara_scanner_matches_v2_hostA_202601"
    lonely = "yara_scanner_matches_v2_hostB"
    r = R.report_datasets(FakeTenant([frozen, sibling, lonely]), now_yyyymm=NOW_YYYYMM)
    assert r["frozen"] == [frozen] and r["not_rotated"] == [lonely]
    assert r["frozen_count"] == 1 and r["not_rotated_count"] == 1
    states = {d["name"]: d["state"] for d in r["datasets"]}
    assert states == {frozen: "frozen", sibling: "rotated", lonely: "not_rotated"}
    assert "abandoned pre-rotation" not in r["report"]   # that wording is a SKIP reason
    assert "predate rotation" in r["report"] and "NOT rotated" in r["report"]


def test_consolidated_targets_are_not_reported_as_unrotated():
    """This pack's OWN output. Filing it under not_rotated tells the operator to change a
    scanner setting that is already correct, and on a tenant with hundreds of consolidated
    scans it buries the one genuinely-unrotated dataset the bucket exists to surface."""
    shard = "yara_scanner_matches_v2_hostA_202601"
    t1 = R.target_name("matches", "2", "scan_2026_07_01_a1b2")
    t2 = R.target_name("scans", "2", "scan_2026_07_01_a1b2")
    r = R.report_datasets(FakeTenant([shard, t1, t2]), now_yyyymm=NOW_YYYYMM)
    assert r["not_rotated_count"] == 0 and r["not_rotated"] == []
    assert r["frozen_count"] == 0
    assert sorted(r["consolidated"]) == sorted([t1, t2])
    assert "CONFIG_LOOKUP_ROTATION" not in r["report"]
    assert "CONSOLIDATED TARGETS" in r["report"]


def test_the_report_carries_age_kind_host_and_the_other_schema_buckets():
    rotated = "yara_scanner_scans_v2_hostA_202601"
    legacy = "yara_scanner_matches_v1_hostA"
    newer = "yara_scanner_matches_v9_hostA"
    r = R.report_datasets(FakeTenant([rotated, legacy, newer]), now_yyyymm=NOW_YYYYMM)
    row = [d for d in r["datasets"] if d["name"] == rotated][0]
    assert row["kind"] == "scans" and row["host"] == "hostA"
    assert row["month"] == "202601" and row["age_months"] == 6
    assert r["legacy"] == [legacy] and r["newer"] == [newer]
    assert r["current_count"] == 1 and r["now_yyyymm"] == NOW_YYYYMM


def test_the_report_automation_writes_nothing_and_returns_the_rendered_table():
    import YaraReport
    t = FakeTenant(["yara_scanner_matches_v2_hostA_202601"])
    out = _run_automation(YaraReport, {}, t)
    assert t.mutating_calls() == []
    assert out.outputs_prefix == "Yara.Report"
    assert "yara_scanner_matches_v2_hostA_202601" in out.readable_output
    assert out.outputs["current_count"] == 1


def test_the_report_automation_gives_the_two_conditions_opposite_advice():
    """The requirement YaraReport exists to satisfy, asserted on what the operator actually
    reads — not just on the library's buckets."""
    import YaraReport
    frozen = "yara_scanner_matches_v2_hostA"
    sibling = "yara_scanner_matches_v2_hostA_202601"
    lonely = "yara_scanner_matches_v2_hostB"
    out = _run_automation(YaraReport, {}, FakeTenant([frozen, sibling, lonely]))
    headline = out.readable_output.split("```")[0]
    frozen_line = [ln for ln in headline.splitlines() if "frozen" in ln]
    unrot_line = [ln for ln in headline.splitlines() if "NOT rotated" in ln]
    assert len(frozen_line) == 1 and len(unrot_line) == 1
    assert frozen_line[0] != unrot_line[0]              # two buckets, not one collapsed count
    assert frozen in frozen_line[0] and lonely in unrot_line[0]
    assert "CONFIG_LOOKUP_ROTATION" in unrot_line[0]
    assert "CONFIG_LOOKUP_ROTATION" not in frozen_line[0]


# --------------------------------------------------- the .yml half of the contract
_PACK = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement")


def _yml(name):
    with open(os.path.join(_SCRIPTS, name, "%s.yml" % name)) as fh:
        return yaml.safe_load(fh)


def _yml_args(doc):
    return {a["name"]: a for a in (doc.get("args") or [])}


def _args_read_by(module_name):
    """Every argument name the automation's source actually reads — via args.get("X") or
    the _flag(args, "X") helper."""
    path = os.path.join(_SCRIPTS, module_name, "%s.py" % module_name)
    with open(path) as fh:
        tree = ast.parse(fh.read())
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if (isinstance(f, ast.Attribute) and f.attr == "get"
                and isinstance(f.value, ast.Name) and f.value.id == "args"
                and node.args and isinstance(node.args[0], ast.Constant)):
            found.add(node.args[0].value)
        if (isinstance(f, ast.Name) and f.id == "_flag" and len(node.args) == 2
                and isinstance(node.args[1], ast.Constant)):
            found.add(node.args[1].value)
    return found


def test_every_script_directory_ships_a_yml():
    """An XSOAR automation IS its yml: demisto-sdk detects content items by yml, and a pack
    install enumerates yml-backed items. A directory holding a bare .py is delivered by no
    upload path, so it does not exist on the tenant at all — which is also why every
    automation here is standalone rather than importing a shared library script."""
    for d in sorted(os.listdir(_SCRIPTS)):
        script_dir = os.path.join(_SCRIPTS, d)
        if not os.path.isdir(script_dir) or d.startswith("__"):
            continue
        ymlpath = os.path.join(script_dir, "%s.yml" % d)
        assert os.path.exists(ymlpath), (
            "%s has no %s.yml, so it is not a content item and no upload path creates it — "
            "every automation importing it then fails with 'No module named %s'" % (d, d, d))
        doc = yaml.safe_load(open(ymlpath))
        assert doc["name"] == d and doc["commonfields"]["id"] == d


def test_the_yml_declares_the_dry_run_default():
    """Requirement (a) is decided jointly by Python AND yaml: XSOAR delivers a declared
    defaultValue in demisto.args() when the caller omits the argument, so flipping this one
    line to 'true' would make a bare invocation delete whole datasets with every Python test
    still green."""
    execute = _yml_args(_yml("YaraCleanup"))["execute"]
    assert execute["defaultValue"] == "false"
    assert execute["required"] is False
    assert set(execute["predefined"]) == {"true", "false"}


def test_the_yml_gives_the_retention_window_no_default():
    """Requirement (c): adding a defaultValue here would silently give a bare invocation a
    retention window."""
    older = _yml_args(_yml("YaraCleanup"))["older_than_months"]
    assert "defaultValue" not in older, (
        "older_than_months must declare NO defaultValue — the CLI gives --older-than-months "
        "none on purpose so that a bare invocation cannot select anything")


def test_declared_arguments_and_read_arguments_agree_in_both_directions():
    """Catches a renamed argument silently becoming a no-op: declared-but-unread means the
    operator sets something with no effect, read-but-undeclared means the console offers no
    way to set it."""
    for module_name in ("YaraCleanup", "YaraReport"):
        declared = set(_yml_args(_yml(module_name)))
        read = _args_read_by(module_name)
        assert declared == read, "%s: declared=%s read=%s" % (
            module_name, sorted(declared), sorted(read))


def test_the_cleanup_yml_allows_for_its_unbounded_query_fan_out():
    """This automation issues one XQL per candidate plus one per scan_id inside it, each with
    its own polling loop, and it holds the consolidation lock across all of it. A platform
    timeout kill skips the finally that releases the lock."""
    assert _yml("YaraCleanup")["timeout"] > _yml("YaraReport")["timeout"]


def test_every_declared_output_is_actually_produced():
    for module_name, result in (
            ("YaraCleanup", _prune(FakeTenant(["yara_scanner_matches_v2_h_202601"]),
                                   older_than_months=0, delete_legacy=True, execute=True)),
            ("YaraReport", R.report_datasets(FakeTenant(["yara_scanner_matches_v2_h_202601"]),
                                             now_yyyymm=NOW_YYYYMM))):
        doc = _yml(module_name)
        prefix = doc["outputs"][0]["contextPath"].rsplit(".", 1)[0]
        for out in doc["outputs"]:
            key = out["contextPath"][len(prefix) + 1:]
            assert key in result, "%s declares %s but never produces it" % (module_name, key)


def test_the_context_prefix_follows_the_packs_own_convention():
    """automation name minus the Yara prefix — a playbook author extrapolating from the
    other items would otherwise read an empty DT path and silently take the wrong branch."""
    for module_name, prefix in (("YaraCleanup", "Yara.Cleanup"),
                                ("YaraReport", "Yara.Report")):
        doc = _yml(module_name)
        for out in doc["outputs"]:
            assert out["contextPath"].startswith(prefix + "."), out["contextPath"]


# --------------------------------------------------------- automation harness
def _run_automation(module, args, client, pin_schema=True):
    """Drive an automation's main() with stubbed platform globals, and hand back the single
    CommandResults it returned.

    schema_version defaults to TEST_SCHEMA_VERSION, not to the automation's shipped
    DEFAULT_LOOKUP_SCHEMA_VERSION: this suite's dataset fixtures are `_v2_` names, and
    inheriting the shipped default would silently reclassify every one of them as legacy
    the day that default is bumped. Tests that pass schema_version explicitly still win.
    """
    args = dict(args)
    if pin_schema:
        args.setdefault("schema_version", TEST_SCHEMA_VERSION)
    demistomock.args_value = dict(args)
    demistomock.commands = []
    del CommonServerPython.results[:]
    del CommonServerPython.errors[:]
    real_client = module.CoreApiClient
    module.CoreApiClient = lambda *a, **k: client
    try:
        module.main()
    finally:
        module.CoreApiClient = real_client
    assert not CommonServerPython.errors, CommonServerPython.errors
    assert len(CommonServerPython.results) == 1
    return CommonServerPython.results[0]


def test_both_automations_clear_their_context_path_before_writing():
    """Measured live on the consolidation automations: XSOAR APPENDS to list-valued context
    across repeated calls in one investigation, so a stale union would poison the next
    reader. Same hazard applies to these two."""
    import YaraCleanup
    import YaraReport
    out = _run_automation(YaraReport, {}, FakeTenant([]))
    assert ("DeleteContext", {"key": "Yara.Report"}) in demistomock.commands
    assert out.outputs_prefix == "Yara.Report"
    out = _run_automation(YaraCleanup, {}, FakeTenant([]))
    assert ("DeleteContext", {"key": "Yara.Cleanup"}) in demistomock.commands
    assert out.outputs_prefix == "Yara.Cleanup"
