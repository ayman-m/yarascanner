#!/usr/bin/env python3
"""Full consolidation retires the per-host sources it has verified - and only those.

Full mode copies every column of every row into the ruleset dataset, so once that write is
verified the per-host source holds nothing the target does not. Retiring it frees the storage
and, more usefully, shrinks the dataset census that the read phase is priced by: a fleet that
retires its sources gets cheaper to consolidate each pass instead of steadily dearer.

That is only true if "verified" means verified, and if reconciliation survives the deletion.
The second part is the one that bites. `stale = held - observed` treats a scan's absence from
the sources as proof the scanner overwrote it, which stops being true the moment retirement is
what removed them: the next pass reads every retired scan as superseded and deletes the rows
retirement existed to protect. Caught here rather than on a tenant -
test_a_genuinely_superseded_scan_is_still_removed took the target from 596 rows to 10.

The separator is that a host's matches dataset name is STABLE - permanent, overwritten in
place, never rotated - so it comes back on the host's next scan. Present-but-missing-the-scan
means superseded; absent entirely means retired and not yet rescanned. Retirement therefore
delays a host's reconciliation until its next scan and never skips it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
from test_pack_data_management import YaraConsolidateApply as A  # noqa: E402

RULE = "90149530ddc2"
HOSTS = [("hosta", "hosta_0f2a1c"), ("hostb", "hostb_9b31ee")]


def sid_for(host, stamp="20260901_120000_000001"):
    return "%s_%s_yara_%s" % (host, stamp, RULE)


# ------------------------------------------------------- scan_id -> hostname

def test_a_hostname_containing_underscores_survives_the_parse():
    """Splitting a scan_id on "_" would take the hostname apart. The tail has a fixed shape,
    so it is the tail that gets matched and removed."""
    assert A._host_of_scan_id(sid_for("web_srv_01")) == "web_srv_01"
    assert A._host_of_scan_id(sid_for("a")) == "a"


def test_a_real_scan_id_from_the_tenant_parses():
    """Shape taken from a live run rather than invented."""
    assert A._host_of_scan_id(
        "xdr-agent_20260901_135138_522150_yara_4ecc80858255") == "xdr-agent"


def test_an_unparseable_scan_id_is_unknown_not_guessed():
    """None makes the caller keep the scan. Guessing a hostname here would delete rows."""
    for bad in ("", None, "nothing_like_a_scan_id", "_20260901_120000_1_yara_abc"):
        assert A._host_of_scan_id(bad) is None


@pytest.mark.parametrize("host", [
    "xdr-agent", "xdragent2", "simhost001", "WIN-SRV-01", "9leading",
    "web_srv_01", "a" * 60, "h\u00f4st-\u00fcn\u00efcode", "IT-DL-DSK-162",
])
def test_the_derived_dataset_name_matches_the_scanner(host):
    """Compared against the scanner's own function rather than against hashes typed into this
    file. Retirement deletes whatever name this produces, so a wrong one deletes a different
    host's findings - and a pinned constant only proves the constant was copied correctly."""
    import importlib.util
    _repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "scanner_for_naming", os.path.join(_repo, "xdr", "xdr_yara_scanner.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert A._shard_host_of(host) == m._dataset_shard_suffix(host)


def test_an_empty_hostname_yields_no_name_rather_than_a_wrong_one():
    """A blank hostname must not resolve to some default dataset that then gets deleted."""
    assert A._shard_host_of("") is None
    assert A._shard_host_of(None) is None


# ------------------------------------------------------------ _supersedable

class Log:
    def __init__(self):
        self.lines = []

    def __call__(self, *a):
        self.lines.append(" ".join(str(x) for x in a))


def test_a_scan_whose_host_dataset_still_exists_is_superseded():
    """The original meaning of stale, and it must keep working: the host rescanned, the
    scanner overwrote its dataset, the old scan_id is gone from a dataset that is still there."""
    old = sid_for("hosta")
    existing = {"yara_scanner_matches_v4_%s" % A._shard_host_of("hosta")}
    assert A._supersedable({old}, "t", None, existing, "4", Log()) == {old}


def test_a_scan_whose_host_dataset_was_retired_is_kept():
    """The regression this function exists for. No dataset at all means retired, which says
    nothing about whether the scan is current - and deleting on that basis is data loss."""
    lg = Log()
    old = sid_for("hosta")
    assert A._supersedable({old}, "t", None, set(), "4", lg) == set()
    assert any("no source dataset at all" in l for l in lg.lines)


def test_the_two_cases_are_separated_within_one_pass():
    """A fleet mid-migration has both: one host rescanned, another only retired."""
    a, b = sid_for("hosta"), sid_for("hostb")
    existing = {"yara_scanner_matches_v4_%s" % A._shard_host_of("hosta")}
    assert A._supersedable({a, b}, "t", None, existing, "4", Log()) == {a}


def test_an_unparseable_scan_id_is_never_removed():
    """Unknown host, so the dataset cannot be checked. Keeping costs a stale row; removing
    costs data."""
    assert A._supersedable({"garbage"}, "t", None, set(), "4", Log()) == set()


def test_nothing_missing_means_nothing_to_do():
    assert A._supersedable(set(), "t", None, set(), "4", Log()) == set()


# ------------------------------------------------- retirement's verification gate

class RetireClient:
    def __init__(self, held, fail=()):
        self.held = held          # scan_id -> rows the target reports holding
        self.deleted = []
        self.fail = set(fail)

    def xql(self, q, limit=None):
        return [{"scan_id": s, "n": n} for s, n in sorted(self.held.items())]

    def delete_dataset(self, name, force=False):
        if name in self.fail:
            raise RuntimeError("delete refused")
        self.deleted.append(name)
        return {"ok": True}


def _retire(client, fresh, by_scan, src_of, complete=True):
    res = {}
    A._retire_consolidated_sources(client, "tgt", fresh, by_scan, src_of, {"tgt"},
                                   complete, Log(), res)
    return res


def test_a_verified_scan_retires_its_source():
    c = RetireClient({"s1": 10})
    res = _retire(c, ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}})
    assert c.deleted == ["ds1"] and res["sources_retired"] == 1


def test_a_short_target_blocks_retirement():
    """The whole point of reading back rather than trusting the write: the target holds fewer
    rows than were sourced, so the write did not fully land and the source is the only copy."""
    c = RetireClient({"s1": 4})
    _retire(c, ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}})
    assert c.deleted == []


def test_a_scan_absent_from_the_target_blocks_retirement():
    c = RetireClient({})
    _retire(c, ["s1"], {"s1": [0] * 3}, {"s1": {"ds1"}})
    assert c.deleted == []


def test_a_dataset_holding_one_unverified_scan_is_kept_whole():
    """Per-dataset, not per-scan: a shard carrying any scan this pass could not verify stays,
    even though its other scan verified fine."""
    c = RetireClient({"s1": 5})
    _retire(c, ["s1", "s2"], {"s1": [0] * 5, "s2": [0] * 5},
            {"s1": {"shared"}, "s2": {"shared"}})
    assert c.deleted == []


def test_an_incomplete_read_disables_retirement_entirely():
    """Same rule as stale removal: if a source could not be read, a scan missing from this
    pass is not evidence of anything."""
    c = RetireClient({"s1": 10})
    _retire(c, ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}}, complete=False)
    assert c.deleted == []


def test_an_unreadable_target_blocks_retirement():
    class Blind(RetireClient):
        def xql(self, q, limit=None):
            raise RuntimeError("target unreadable")
    c = Blind({"s1": 10})
    _retire(c, ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}})
    assert c.deleted == []


def test_a_failed_delete_is_survivable():
    """The rows are already in the target, so a source that will not delete costs storage and
    a query - never data - and must not fail the run."""
    c = RetireClient({"s1": 5, "s2": 5}, fail={"ds1"})
    res = _retire(c, ["s1", "s2"], {"s1": [0] * 5, "s2": [0] * 5},
                  {"s1": {"ds1"}, "s2": {"ds2"}})
    assert c.deleted == ["ds2"] and res["sources_retired"] == 1


# ---------------------------------------------------------------- the switch

def test_retirement_is_one_constant_and_it_is_reported():
    """Whichever way it is set, the run says what it did rather than restating a policy - the
    old output hardcoded 'deleted: 0 - source data is never deleted', which stopped being true
    the moment this became a setting."""
    assert isinstance(A.CONFIG_RETIRE_SOURCES_AFTER_FULL, bool)
    assert "retired" in A._sources_line({"sources_retired": 3, "dry_run": False})
    assert "0" in A._sources_line({"dry_run": True})


def test_a_dry_run_never_retires():
    assert "dry run" in A._sources_line({"dry_run": True}).lower()


# ------------------------------- retirement vs pass completeness (the deadlock)

def test_a_partial_pass_still_retires_what_it_verified():
    """The bug that deadlocked the drain loop.

    Retirement was originally gated on `sources_complete`, which a bounded pass sets False by
    design. The result on a 205-dataset fleet: pass 1 wrote 6 scans and retired nothing, so the
    fleet never shrank, so passes 2, 3 and 4 selected the same 8 datasets, found the target
    already current, and wrote nothing. Four passes, 2,436 seconds, no progress.

    The two flags answer different questions. `sources_complete` is "did this pass look
    everywhere", which is what stale REMOVAL needs before calling anything superseded.
    Retirement asks "are THIS scan's rows in the target", which is answered by reading them
    back and is just as true on a pass that deliberately read eight datasets of two hundred.
    """
    c = RetireClient({"s1": 10})
    res = {}
    A._retire_consolidated_sources(c, "tgt", ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}},
                                   {"tgt"}, True, Log(), res)
    assert c.deleted == ["ds1"], "a partial pass refused to retire a verified source"
    assert res["sources_retired"] == 1


def test_an_unreadable_source_still_blocks_retirement():
    """The distinction must not become "retire regardless". A source that failed to READ may
    have yielded a short row list, so the count the scan was written with is itself short and
    the target matching it proves nothing."""
    c = RetireClient({"s1": 10})
    res = {}
    A._retire_consolidated_sources(c, "tgt", ["s1"], {"s1": [0] * 10}, {"s1": {"ds1"}},
                                   {"tgt"}, False, Log(), res)
    assert c.deleted == []


def test_retirement_is_what_lets_a_bounded_drain_converge():
    """Stale removal stays off until a pass covers the whole fleet, so the two features are
    load-bearing on each other: retirement shrinks the remainder until a pass CAN cover
    everything, at which point reconciliation resumes. Without retirement a fleet permanently
    larger than one pass would never reconcile again."""
    remaining, pass_size = 205, 8
    passes = 0
    while remaining > 0 and passes < 100:
        remaining -= min(pass_size, remaining)     # retirement removes what was consolidated
        passes += 1
    assert remaining == 0 and passes == 26


def test_a_source_already_consolidated_by_an_earlier_pass_is_still_retired():
    """The second standstill, distinct from the sources_complete one.

    Retirement originally ran only inside the write branch, so a scan an EARLIER pass had
    already consolidated left its source in place forever. On a bounded drain those datasets
    are the oldest, so every pass re-selected the same ones, found the target already current,
    wrote nothing and retired nothing. Three passes, 1,163 seconds, remaining stuck at 200.

    "Already current" is the strongest verification available - the target holds the scans and
    the pass has just confirmed it - so it must retire exactly as a fresh write does.
    """
    c = RetireClient({"s1": 10, "s2": 4})
    res = {}
    A._retire_consolidated_sources(c, "tgt", ["s1", "s2"],
                                   {"s1": [0] * 10, "s2": [0] * 4},
                                   {"s1": {"ds1"}, "s2": {"ds2"}},
                                   {"tgt"}, True, Log(), res)
    assert sorted(c.deleted) == ["ds1", "ds2"] and res["sources_retired"] == 2


def test_the_skip_message_distinguishes_bounded_from_broken():
    """A pass that chose to read part of the fleet and a pass that failed to read a source both
    disable stale removal, and reporting both as "could not be read" sent me looking for a
    tenant fault that did not exist. The words have to separate them."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                            "YaraConsolidateApply", "YaraConsolidateApply.py"),
               encoding="utf-8").read()
    assert "deliberately read only part of the fleet" in src
    assert "a source dataset could not be read this pass" in src
