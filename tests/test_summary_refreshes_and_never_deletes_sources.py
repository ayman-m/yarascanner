#!/usr/bin/env python3
"""Summary consolidation: never touch host datasets, and rewrite on a re-run.

Two properties an operator relies on, neither of which the code guaranteed.

FIRST - summary must never delete a host dataset. It reads them and nothing else; the host
matches dataset is permanent, overwritten in place by that host's next scan, and it is the
deep-dive source a full consolidation or an investigation goes back to. Only FULL mode
retires sources, and only after reading its own write back. The retired inlined-library
function _delete_many still sits in this file, unreachable from main(), which is exactly the
kind of thing a later refactor wires up by accident - so the property is pinned here rather
than left to reading.

SECOND - a re-run is a REFRESH. The old code compared scan_id SETS and skipped the write
when they matched, reporting "target already current - verified, not rewritten". That treats
scan_id equality as proof of content equality, which it is not: a target left short by a
failed batch, a partial write, or an edit stayed wrong permanently, because every later pass
saw matching scan_ids and declined to look further. Now the rows read from the host datasets
replace whatever the target holds for those scans.

The two interact through a third property. Refreshing means clearing the rows for the scans
about to be rewritten, and clearing is a deletion - so it must be scoped to this automation's
OWN target and to scans it actually observed, never to a host dataset and never to a scan
whose source it could not see. That last case is real rather than theoretical: full mode
retires host datasets, summary reads the same ones, and a summary pass after a full pass
would otherwise read every retired host as superseded and drop its rows. Nine such hosts were
sitting on the lab tenant when this was written.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    YaraConsolidateSummary as S, FakeTenant, _run_automation,
)

HOSTS = ["hosta_aa0001", "hostb_bb0002", "hostc_cc0003"]
MATCHES = ["yara_scanner_matches_v4_%s" % h for h in HOSTS]
SCANS = ["yara_scanner_scans_v4_%s_202609" % h for h in HOSTS]
RULE = "90149530ddc2"
TARGET = "yara_scanner_summary_v4_rules_%s" % RULE


def _sid(host):
    """A scan_id of the real shape. The ruleset hash at the end is what groups a scan into a
    target - an invented id like "scan01" is silently ungroupable and the pass does nothing."""
    return "%s_20260901_120000_00000%d_yara_%s" % (host, HOSTS.index(host) + 1, RULE)


def _tenant(extra=()):
    rows = {}
    for i, host in enumerate(HOSTS):
        rows["yara_scanner_matches_v4_%s" % host] = {_sid(host): 3}
        rows["yara_scanner_scans_v4_%s_202609" % host] = {_sid(host): 2}
    return FakeTenant(names=MATCHES + SCANS + list(extra), scans=rows)


class Log:
    def __init__(self):
        self.lines = []

    def __call__(self, *a):
        self.lines.append(" ".join(str(x) for x in a))


# ------------------------------------------- summary never deletes a source

def test_a_summary_run_never_deletes_any_dataset():
    """The property in one assertion. Summary reads host datasets; it does not own them."""
    t = _tenant()
    _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    # the consolidation LOCK is this automation's own coordination marker, created and
    # dropped by every executed pass - it is not anybody's data
    deletes = [c for c in t.calls if c.startswith("delete_dataset")
               and "consolidation_lock" not in c]
    assert not deletes, "summary deleted a dataset: %r" % deletes


def test_a_summary_run_never_removes_rows_from_a_host_dataset():
    """Row-level deletion is as damaging as dropping the dataset, and reaches the same data.
    Only the automation's own target may be written to by remove_lookup_data."""
    t = _tenant()
    _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    for call in t.calls:
        if call.startswith("remove_lookup_data"):
            name = call.split(":", 1)[1] if ":" in call else ""
            assert "_matches_v4_" not in name and "_scans_v4_" not in name, (
                "summary removed rows from a SOURCE dataset: %s" % call)


def test_the_only_delete_helper_is_unreachable_from_main():
    """_delete_many is retired inlined-library code. It must stay unreachable - this is the
    tripwire for a refactor that quietly reconnects it."""
    import ast
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                        "YaraConsolidateSummary", "YaraConsolidateSummary.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    reached, todo = set(), ["main"]
    while todo:
        name = todo.pop()
        if name in reached or name not in funcs:
            continue
        reached.add(name)
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                todo.append(node.func.id)
    assert "_delete_many" not in reached, "_delete_many is now reachable from main()"


# ------------------------------------------------- a re-run refreshes rows

def test_a_second_run_rewrites_rather_than_skipping():
    """The behaviour change. Previously the second pass reported "already current - not
    rewritten" and wrote nothing, so a target that was wrong stayed wrong."""
    t = _tenant(extra=[TARGET])
    t.scans[TARGET] = {_sid(h): 4 for h in HOSTS}     # a target already holding every scan
    res = _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    # counted against the TARGET specifically: the run record and the lock are also writes
    writes = [c for c in t.calls if c.startswith("add_lookup_data") and TARGET in c]
    text = str(getattr(res, "readable_output", ""))
    assert writes, (
        "the pass wrote nothing to a target it already held - it skipped instead of "
        "refreshing: %s" % text[:300])
    assert "not rewritten" not in text


def test_a_refresh_clears_before_writing_so_rows_do_not_double():
    """Rewriting without clearing appends a second copy of every (host, rule) pair.

    The target is seeded holding exactly the scans the sources hold - the state after any
    successful earlier pass - because the fake does not make written rows queryable, so
    running twice would leave `held` empty and never exercise the refresh at all.
    """
    t = _tenant(extra=[TARGET])
    t.scans[TARGET] = {_sid(h): 4 for h in HOSTS}
    _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    removes = [c for c in t.calls if c.startswith("remove_lookup_data") and TARGET in c]
    adds = [c for c in t.calls if c.startswith("add_lookup_data") and TARGET in c]
    assert removes, "refresh wrote rows without clearing the previous copies: %r" % t.calls
    assert adds, "refresh cleared the rows but wrote nothing back: %r" % t.calls


def test_nothing_observed_leaves_the_target_untouched():
    """A refresh rewrites what this pass READ. With nothing read for a ruleset, there is
    nothing to refresh, and the target must not be cleared on the strength of an empty pass."""
    t = FakeTenant(names=MATCHES + SCANS + [TARGET], scans={TARGET: {"old_scan": 4}})
    _run_automation(S, {"execute": "true", "schema_version": "4"}, t)
    removes = [c for c in t.calls if c.startswith("remove_lookup_data") and TARGET in c]
    assert not removes, "an empty pass cleared the target: %r" % removes


# ------------------------------- an absent source is not proof of supersession

def test_a_scan_whose_host_dataset_still_exists_is_superseded():
    """The original meaning of stale has to keep working: the host rescanned, the scanner
    overwrote its dataset, the old scan_id is gone from a dataset that is still present."""
    old = "hosta_20260901_120000_000001_yara_%s" % RULE
    existing = {"yara_scanner_matches_v4_%s" % S._shard_host_of("hosta")}
    assert S._supersedable({old}, TARGET, existing, "4", Log()) == {old}


def test_a_scan_whose_host_dataset_was_retired_is_kept():
    """The cross-mode bug. Full consolidation retires host datasets once their rows are
    verified; summary reads the same datasets. Without this, the next summary pass deletes
    the summary rows of every host full mode retired."""
    lg = Log()
    old = "hosta_20260901_120000_000001_yara_%s" % RULE
    assert S._supersedable({old}, TARGET, set(), "4", lg) == set()
    assert any("no source dataset at all" in l for l in lg.lines)


def test_both_cases_are_separated_within_one_pass():
    a = "hosta_20260901_120000_000001_yara_%s" % RULE
    b = "hostb_20260901_120000_000002_yara_%s" % RULE
    existing = {"yara_scanner_matches_v4_%s" % S._shard_host_of("hosta")}
    assert S._supersedable({a, b}, TARGET, existing, "4", Log()) == {a}


def test_an_unparseable_scan_id_is_never_removed():
    assert S._supersedable({"garbage"}, TARGET, set(), "4", Log()) == set()


@pytest.mark.parametrize("host", ["xdr-agent", "simhost001", "web_srv_01", "WIN-SRV-01"])
def test_the_derived_name_matches_the_scanner(host):
    """Compared against the scanner itself rather than pinned constants - this name decides
    which dataset counts as "still present", so a wrong one misjudges supersession."""
    import importlib.util
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "scanner_naming_chk", os.path.join(repo, "xdr", "xdr_yara_scanner.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert S._shard_host_of(host) == m._dataset_shard_suffix(host)
