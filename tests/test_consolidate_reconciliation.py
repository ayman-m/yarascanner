#!/usr/bin/env python3
"""Reconciliation must delete a scan's rows only when that scan was genuinely superseded.

`stale = held - desired` conflates two different facts: "this scan was replaced by a newer
one" and "I did not process this scan on this pass". Only the first justifies deleting rows
from the consolidated target. `desired` is the GATED, FILTERED set, so anything that narrows
it - the scan_id filter, an in-progress gate, an unreadable source - silently becomes a
deletion instruction.

Measured against a fake seeded with the live tenant (161 + 425 + 426 = 1012 rows across one
ruleset): `!YaraConsolidateApply scan_id=<one host> execute=true` deleted 586 rows belonging
to the two hosts the operator did not name, on an argument documented as "Restrict the
consolidation to these scan_id(s)". The shipped playbook reaches the same code path, wiring
Yara.ConsolidateStatus.eligible_scan_ids into that argument (task 6).

The correct question is not "did I process this scan?" but "is this scan still backed by a
source?". A scan_id in the target that no longer appears in any per-host matches dataset was
superseded - the scanner overwrites that dataset on the next scan. That, and only that, is
stale.
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import _install_xsoar_stubs  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_S = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts")

RULE = "90149530ddc2"
TARGET = "yara_scanner_full_v4_rules_" + RULE
SUM_TARGET = "yara_scanner_summary_v4_rules_" + RULE
SCAN_MS = 1787654400000
HOSTS = [("xdr-agent", "xdr_agent_cd7e9b", "xdr-agent_20260825_103650_036642_yara_" + RULE, 161),
         ("xdragent2", "xdragent2_2fd370", "xdragent2_20260825_103653_463411_yara_" + RULE, 425),
         ("xdragent",  "xdragent_68494d",  "xdragent_20260825_103654_176781_yara_" + RULE, 426)]


def _load(name):
    _install_xsoar_stubs()
    path = os.path.join(_S, name, name + ".py")
    spec = importlib.util.spec_from_file_location("recon_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def A():
    return _load("YaraConsolidateApply")


@pytest.fixture(scope="module")
def S():
    return _load("YaraConsolidateSummary")


class Client:
    """Mirrors the REAL lookup API's filter format, which the older FakeClient predates:
    remove_lookup_data takes a list of AND-groups, OR'd together, each entry
    {field, operator, value}. Getting this wrong makes a deletion test silently pass."""

    def __init__(self, unreadable=()):
        self.ds = {}
        self.unreadable = set(unreadable)

    def get_datasets(self):
        return [{"Dataset Name": n, "Type": "LOOKUP"} for n in self.ds]

    def create_lookup_dataset(self, n, schema):
        if n in self.ds:
            return {"status": "exists"}
        self.ds[n] = []
        return {"dataset_name": n}

    def add_lookup_data(self, n, rows):
        self.ds.setdefault(n, []).extend(rows)
        return {"rows added": len(rows)}

    def delete_dataset(self, n, force=False):
        self.ds.pop(n, None)
        return {"status": "deleted"}

    def remove_lookup_data(self, n, filters):
        """The REAL endpoint's contract, probed live against the tenant:

            [{"scan_id": "S1"}, {"scan_id": "S2"}]   -> HTTP 200 {"deleted": N}
            [[{"field": "scan_id", "operator": "eq", "value": "S1"}]]
                -> HTTP 500  "'list' object has no attribute 'items'"
            [{"field": "scan_id", "operator": "eq", "value": "S1"}]
                -> HTTP 400  "Filter's key field field not found"

        A list of COLUMN -> VALUE dicts, OR'd across the list. The earlier fake accepted the
        field/operator/value shape because it was written to match the code rather than the
        API, so consolidate_full's reconciliation passed every test while 500ing on every
        real call. Rejecting the wrong shapes here is the whole point of this method."""
        for f in (filters or []):
            if isinstance(f, list):
                raise RuntimeError("HTTP 500: 'list' object has no attribute 'items'")
            if not isinstance(f, dict):
                raise RuntimeError("HTTP 400: filter must be an object")
            for key in f:
                if key in ("field", "operator", "value"):
                    raise RuntimeError("HTTP 400: Filter's key field %s not found" % key)
        if n not in self.ds:
            return {"deleted": 0}

        def m(row):
            return any(all(row.get(k) == v for k, v in f.items()) for f in filters)

        before = len(self.ds[n])
        self.ds[n] = [r for r in self.ds[n] if not m(r)]
        return {"deleted": before - len(self.ds[n])}

    def xql(self, q, limit=1000):
        import re
        m = re.match(r"dataset = (\S+)", q)
        if not m:
            return []
        name = m.group(1)
        if name in self.unreadable:
            raise RuntimeError("HTTP 500: transient backend error")
        rows = self.ds.get(name, [])
        if "comp count() as n by scan_id" in q:
            agg = {}
            for r in rows:
                agg[r.get("scan_id")] = agg.get(r.get("scan_id"), 0) + 1
            return [{"scan_id": k, "n": v} for k, v in agg.items()]
        return list(rows)


def seed(status="completed", scan_ms=SCAN_MS, unreadable=()):
    c = Client(unreadable=unreadable)
    for host, slug, sid, n in HOSTS:
        c.ds["yara_scanner_matches_v4_" + slug] = [
            {"scan_id": sid, "hostname": host, "event_timestamp_ms": scan_ms,
             "file_path": "/f%d" % i, "rule": "R%d" % (i % 8), "offset": i} for i in range(n)]
        c.ds["yara_scanner_scans_v4_%s_202608" % slug] = [
            {"scan_id": sid, "hostname": host, "status": status,
             "event_timestamp_ms": scan_ms}]
    return c


AGED = SCAN_MS + 48 * 3600 * 1000      # every scan is well past retention_hours
DRAINING = SCAN_MS + 2 * 60 * 1000     # 2 min after the last match row - drain may be live
FRESH = SCAN_MS + 40 * 60 * 1000       # past the 15-min quiet period, far inside retention


# --- defect 1: the scan_id filter must not delete what it was not asked to touch ---------

def test_the_scan_id_filter_does_not_delete_the_other_hosts_rows(A):
    """Reproduced live-shaped: 1012 -> 426, i.e. 586 rows of two untouched hosts deleted by a
    run whose argument is documented as "Restrict the consolidation to these scan_id(s)"."""
    c = seed()
    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED, log=lambda *a: None)
    assert len(c.ds[TARGET]) == 1012, "baseline pass did not build the expected target"

    A.consolidate_full(c, ver="4", only_scan_ids=[HOSTS[2][2]], execute=True,
                       now_ms=AGED, log=lambda *a: None)
    assert len(c.ds[TARGET]) == 1012, (
        "restricting to one scan deleted %d row(s) belonging to hosts the operator never "
        "named" % (1012 - len(c.ds[TARGET])))
    assert len({r["scan_id"] for r in c.ds[TARGET]}) == 3


def test_the_summary_scan_id_filter_has_the_same_protection(S, monkeypatch):
    """Summary keeps its consolidation inline in main() rather than in an extractable
    function, so this drives main() the way the rest of the suite does. summarise_shard and
    _lifecycle_state are stubbed: the XQL summary query and the lifecycle read are each
    their own concern, and faking them here would test the fake rather than the
    reconciliation this file is about."""
    from test_pack_data_management import _run_automation

    def fake_summarise(client, dataset, ver, qcount, log, findings=None):
        rows = client.ds.get(dataset, [])
        out, seen = [], set()
        for r in rows:
            key = (r["scan_id"], r["hostname"], r["rule"])
            if key not in seen:
                seen.add(key)
                out.append((r["scan_id"], r["hostname"], r["rule"],
                            r["event_timestamp_ms"]))
        return out, "primary"

    monkeypatch.setattr(S, "summarise_shard", fake_summarise)
    monkeypatch.setattr(S, "_lifecycle_state", lambda *a, **k: dict(
        (sid, {"terminal": True, "newest_ms": SCAN_MS}) for _h, _s, sid, _n in HOSTS))

    c = seed()
    _run_automation(S, {"schema_version": "4", "execute": "true"}, c, pin_schema=False)
    baseline = len(c.ds.get(SUM_TARGET, []))
    assert baseline > 0, "summary target was never built"
    held = {r["scan_id"] for r in c.ds[SUM_TARGET]}
    assert len(held) == 3, "expected all three scans in the summary target, got %s" % held

    _run_automation(S, {"schema_version": "4", "execute": "true",
                        "scan_id": HOSTS[2][2]}, c, pin_schema=False)
    assert len(c.ds.get(SUM_TARGET, [])) == baseline, (
        "summary lost %d row(s) to a restricted run"
        % (baseline - len(c.ds.get(SUM_TARGET, []))))


# --- defect 2: a scan that no longer has a source IS stale and must still be removed -----

def test_a_genuinely_superseded_scan_is_still_removed(A):
    """The fix must not turn reconciliation off. When a host is re-scanned the scanner
    OVERWRITES its matches dataset, so the old scan_id vanishes from the source - that is
    exactly the signal that means superseded."""
    c = seed()
    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED, log=lambda *a: None)
    assert len(c.ds[TARGET]) == 1012

    host, slug, old_sid, n = HOSTS[2]
    new_sid = "xdragent_20260827_090000_111111_yara_" + RULE
    c.ds["yara_scanner_matches_v4_" + slug] = [
        {"scan_id": new_sid, "hostname": host, "event_timestamp_ms": AGED,
         "file_path": "/g%d" % i, "rule": "R1", "offset": i} for i in range(10)]
    c.ds["yara_scanner_scans_v4_%s_202608" % slug].append(
        {"scan_id": new_sid, "hostname": host, "status": "completed",
         "event_timestamp_ms": AGED})

    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED + 48 * 3600 * 1000,
                       log=lambda *a: None)
    sids = {r["scan_id"] for r in c.ds[TARGET]}
    assert old_sid not in sids, "the superseded scan_id was left behind - reconciliation broke"
    assert new_sid in sids, "the replacement scan was never written"
    assert len(c.ds[TARGET]) == 161 + 425 + 10


# --- defect 3: an unreadable source is not evidence that a scan was superseded -----------

def test_a_transient_read_failure_does_not_delete_that_hosts_rows(A):
    """One 500 on a source read must not delete that host's intact consolidated rows. The
    run previously reported success while dropping them, which is the worst shape a data
    loss can take."""
    c = seed()
    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED, log=lambda *a: None)
    assert len(c.ds[TARGET]) == 1012

    c.unreadable = {"yara_scanner_matches_v4_" + HOSTS[2][1]}
    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED, log=lambda *a: None)
    assert len(c.ds[TARGET]) == 1012, (
        "a transient read failure deleted %d row(s) that were never superseded"
        % (1012 - len(c.ds[TARGET])))


# --- defect 4: the terminal gate is dead code -------------------------------------------

def test_a_completed_scan_is_eligible_before_the_retention_window_expires(A):
    """build_terminal_map keys on the 2-tuple (scan_id, host); the full path looked it up
    with a bare scan_id string, which can never match. terminal was therefore permanently
    False and eligibility rested entirely on the 24h age check - so a scan that finished
    ten minutes ago logged as "scan still in progress"."""
    c = seed(status="completed")
    A.consolidate_full(c, ver="4", execute=True, now_ms=FRESH, retention_hours=24.0,
                       log=lambda *a: None)
    assert TARGET in c.ds and len(c.ds[TARGET]) == 1012, (
        "a cleanly completed scan was not consolidated inside the retention window")


def test_a_terminal_scan_is_NOT_consolidated_while_its_rows_may_still_be_draining(A):
    """The trap in re-enabling the terminal gate.

    xdr_yara_scanner.py:7270 emits the terminal lifecycle row with sync=True BEFORE stopping
    and draining the uploaders - deliberately, because queued behind the drain it was the tail
    of the queue and got stranded there. So `status == completed` does NOT mean the match rows
    have landed; the lookup drain can still be running, and drain time can exceed scan time.

    Consolidating in that window copies a PARTIAL row set, and the damage is permanent: the
    scan_id is then in `held`, so `fresh = desired - held` is empty on every later pass and
    the missing rows are never written. The 24h age check used to mask this by accident. The
    quiet period is what replaces that accident with an actual guarantee.
    """
    c = seed(status="completed")
    A.consolidate_full(c, ver="4", execute=True, now_ms=DRAINING, retention_hours=24.0,
                       log=lambda *a: None)
    assert not c.ds.get(TARGET), (
        "a scan was consolidated %d seconds after its newest match row - inside the quiet "
        "period, while the lookup uploader may still be draining"
        % ((DRAINING - SCAN_MS) // 1000))


def test_summary_also_refuses_a_scan_whose_rows_may_still_be_draining(S, monkeypatch):
    """Summary's terminal lookup was never broken - _lifecycle_state keys on sid alone - so
    unlike Apply, this race was live rather than latent. A partial summary loses whole
    (host, rule) pairs, and permanently: the scan_id lands in `held`, so no later pass ever
    writes the rules that were still in flight."""
    from test_pack_data_management import _run_automation

    def fake_summarise(client, dataset, ver, qcount, log, findings=None):
        out, seen = [], set()
        for r in client.ds.get(dataset, []):
            key = (r["scan_id"], r["hostname"], r["rule"])
            if key not in seen:
                seen.add(key)
                out.append((r["scan_id"], r["hostname"], r["rule"], r["event_timestamp_ms"]))
        return out, "primary"

    monkeypatch.setattr(S, "summarise_shard", fake_summarise)
    monkeypatch.setattr(S, "_lifecycle_state", lambda *a, **k: dict(
        (sid, {"terminal": True, "newest_ms": SCAN_MS}) for _h, _s, sid, _n in HOSTS))

    c = seed(status="completed")
    import time as _t
    real = _t.time
    _t.time = lambda: DRAINING / 1000.0
    try:
        _run_automation(S, {"schema_version": "4", "execute": "true"}, c, pin_schema=False)
    finally:
        _t.time = real
    assert not c.ds.get(SUM_TARGET), (
        "summary consolidated a scan %d seconds after its newest row, inside the quiet period"
        % ((DRAINING - SCAN_MS) // 1000))


def test_a_still_running_scan_is_NOT_treated_as_terminal(A):
    """The naive fix - correcting only the key - makes any scan with a lifecycle row
    terminal, including one still running. The ["terminal"] deref is load-bearing."""
    c = seed(status="running")
    A.consolidate_full(c, ver="4", execute=True, now_ms=FRESH, retention_hours=24.0,
                       log=lambda *a: None)
    assert TARGET not in c.ds or not c.ds.get(TARGET), (
        "a running scan was consolidated - the terminal check is not reading the status")


def test_a_running_scan_still_consolidates_once_it_ages_out(A):
    """The age backstop must survive the fix: an abandoned scan that never reached a
    terminal status is still consolidated rather than stranded for ever."""
    c = seed(status="running")
    A.consolidate_full(c, ver="4", execute=True, now_ms=AGED, retention_hours=24.0,
                       log=lambda *a: None)
    assert len(c.ds.get(TARGET, [])) == 1012


def test_an_operator_can_lower_the_quiet_period_when_a_wave_has_drained(A):
    """The escape hatch has to actually work, or the 900s default becomes a hard wait an
    operator cannot get past when they know the wave finished."""
    c = seed(status="completed")
    A.consolidate_full(c, ver="4", execute=True, now_ms=DRAINING, retention_hours=24.0,
                       quiet_secs=0, log=lambda *a: None)
    assert len(c.ds.get(TARGET, [])) == 1012, (
        "quiet_secs=0 did not let a known-drained wave consolidate")


def test_the_declared_default_matches_the_code(A):
    """A yml defaultValue that drifts from the code is worse than none: the argument panel
    tells the operator one number and the run uses another."""
    import yaml
    d = yaml.safe_load(open(os.path.join(_S, "YaraConsolidateApply",
                                         "YaraConsolidateApply.yml")))
    arg = next(a for a in d["args"] if a["name"] == "quiet_secs")
    assert int(arg["defaultValue"]) == int(A.DEFAULT_QUIET_SECS), (
        "yml says %s, code says %s" % (arg["defaultValue"], A.DEFAULT_QUIET_SECS))


# --- Status is Apply's PREVIEW: if their gates differ, the preview lies -------------------

@pytest.fixture(scope="module")
def ST():
    return _load("YaraConsolidateStatus")


def test_status_and_apply_agree_that_a_fresh_completed_scan_is_not_yet_eligible(ST, A):
    """YaraConsolidateStatus exists to tell an operator what Apply WILL do, and the playbook
    feeds its eligible_scan_ids straight into Apply. So the two gates have to be the same
    gate. Status carried the same dead terminal lookup Apply did - fixed there and missed
    here - and once Apply gained the quiet period the two answers diverged: Status would
    call a scan ready that Apply then declines to touch.
    """
    c = seed(status="completed")
    r = ST.check_readiness(c, ver="4", retention_hours=24.0, now_ms=DRAINING,
                           log=lambda *a: None)
    assert r["eligible_count"] == 0, (
        "Status called %d scan(s) ready inside the quiet period; Apply consolidates none"
        % r["eligible_count"])

    A.consolidate_full(c, ver="4", execute=True, now_ms=DRAINING, log=lambda *a: None)
    assert not c.ds.get(TARGET), "Apply wrote inside the quiet period"


def test_status_and_apply_agree_once_the_quiet_period_has_passed(ST, A):
    """The other half: Status must not under-report either, or an operator waits 24h for
    something that is ready now."""
    c = seed(status="completed")
    r = ST.check_readiness(c, ver="4", retention_hours=24.0, now_ms=FRESH,
                           log=lambda *a: None)
    assert r["eligible_count"] == 3, (
        "Status called only %d of 3 completed scans ready past the quiet period"
        % r["eligible_count"])

    A.consolidate_full(c, ver="4", execute=True, now_ms=FRESH, log=lambda *a: None)
    assert len(c.ds.get(TARGET, [])) == 1012, "Apply did not consolidate what Status promised"


def test_status_does_not_call_a_running_scan_ready(ST):
    c = seed(status="running")
    r = ST.check_readiness(c, ver="4", retention_hours=24.0, now_ms=FRESH,
                           log=lambda *a: None)
    assert r["eligible_count"] == 0, "a running scan was reported ready"
