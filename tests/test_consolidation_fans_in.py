#!/usr/bin/env python3
"""Summary reads the whole fleet in one query, not one query per dataset.

The read phase costs one XQL round trip per dataset, and a tenant's dataset census is
hosts x (1 + retained months): one permanent matches dataset per host, plus one scans shard
per host per rotation month, which nothing prunes. So the cost of a pass is set by the
tenant's dataset count, never by how many scans it consolidates.

Measured on emea, and the numbers are not marginal. Per-call latency is flat - 6.9s, 7.1s,
6.8s across the three query shapes, two polls each at the 3s poll interval - because every
query is pinned to one dataset by literal name and a host's dataset stays ~337 rows however
large the fleet gets. It is more calls, not slower calls. At 200 hosts and one month that is
401 calls against a 900s task timeout: the run is killed roughly one-sixteenth of the way
through the lifecycle loop, having read no matches data and written nothing. Worse, a
platform kill runs no Python, so the `finally` that releases the consolidation lock never
fires and the marker strands for DEFAULT_LOCK_STALE_SECS.

The fan-in works because the merge was already being done twice. `_lifecycle_state` takes
max() of newest and OR of terminal across shards; `summary_query` groups by (scan_id,
hostname, rule). Every one of those keys is shard-independent, so a wildcard hands the engine
exactly the merge the Python loop was performing. Verified against emea rather than assumed:
17 lifecycle scan_ids and 16 (scan_id, hostname, rule) tuples, identical both ways, at 5.4x
and 4.0x on a five-shard lab - and the saving grows with the fleet, since the fan-in is one
query at any size.

What makes it safe is the guard, not the speed. A wildcard reads whatever the tenant holds;
the loop reads a list this module curated, and `_matches_shard_for_read` deliberately drops
retired per-scan copies. `_fanin_source` therefore returns a wildcard only when those two
sets are provably equal, and every failure path falls back to reading shard by shard.
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
RETIRED = "yara_scanner_matches_v4_scan_s1"


# ------------------------------------------------------------------ _fanin_source

def test_a_uniform_tenant_collapses_to_one_wildcard():
    """The whole point: N datasets, one query."""
    got = S._fanin_source(MATCHES + SCANS, "matches", "4", MATCHES)
    assert got == "yara_scanner_matches_v4_*"


def test_an_uncurated_dataset_on_the_tenant_disables_the_fanin():
    """The rail. `_matches_shard_for_read` drops retired per-scan copies, and a wildcard
    cannot express that exclusion - so when the tenant holds one, the whole optimisation is
    withdrawn rather than silently widening what gets read."""
    assert S._fanin_source(MATCHES + [RETIRED], "matches", "4", MATCHES) is None


def test_a_shard_the_pass_curated_but_the_tenant_lost_disables_it_too():
    """Set equality, not subset, in both directions."""
    assert S._fanin_source(MATCHES[:2], "matches", "4", MATCHES) is None


def test_one_shard_stays_on_the_per_shard_path():
    """A wildcard would cost the same one query and give up per-shard error isolation."""
    assert S._fanin_source(MATCHES[:1], "matches", "4", MATCHES[:1]) is None


def test_an_older_schema_dataset_does_not_disable_the_fanin():
    """v2 and v4 rows have different columns, so a wildcard spanning both would mis-project -
    which is exactly why the version is baked into the prefix rather than checked separately.
    A v2 leftover is outside `yara_scanner_matches_v4_` and cannot be read by it, so it costs
    the v4 pass nothing. Left as a test because the cheap version of this guard - matching on
    kind alone - would silently span schemas."""
    mixed = MATCHES + ["yara_scanner_matches_v2_hostd_dd0004"]
    assert S._fanin_source(mixed, "matches", "4", MATCHES) == "yara_scanner_matches_v4_*"


def test_no_shards_means_no_query():
    assert S._fanin_source([], "matches", "4", []) is None


# -------------------------------------------------------------- the guarded interpolation

def test_only_the_exact_wildcard_is_accepted_as_a_non_shard_name():
    """summarise_shard interpolates its argument into XQL. Widening that guard to admit the
    fan-in must not admit anything else - the host segment of a real shard name originates as
    a HOSTNAME, so a name that merely resembles the wildcard must still be refused."""
    for bad in ("yara_scanner_matches_v4_*x", "yara_scanner_matches_*",
                "yara_scanner_scans_v4_*", "*", "yara_scanner_matches_v3_*"):
        with pytest.raises(ValueError, match="refusing non-matches dataset"):
            S.summarise_shard(object(), bad, "4", [0], lambda *a: None)


def test_the_accepted_wildcard_is_the_one_fanin_source_mints():
    """Guard and producer must agree, or the fan-in is dead code that always falls back."""
    minted = S._fanin_source(MATCHES, "matches", "4", MATCHES)
    calls = []

    class C:
        def xql(self, q, limit=None):
            calls.append(q)
            return []

    S.summarise_shard(C(), minted, "4", [0], lambda *a: None)
    assert calls and minted in calls[0]


# ------------------------------------------------------------------ lifecycle fan-in

def _life_rows(sid, status, newest):
    return {"scan_id": sid, "status": status, "n": 1, "newest": newest}


class LifeClient:
    """Returns lifecycle rows per shard, and unions them for a wildcard - the tenant's own
    behaviour, confirmed live."""

    def __init__(self, per_shard, fail_on_wildcard=False):
        self.per_shard = per_shard
        self.fail_on_wildcard = fail_on_wildcard
        self.queries = []

    def xql(self, query, limit=None):
        self.queries.append(query)
        name = query.split("dataset = ", 1)[1].split(" ", 1)[0]
        if name.endswith("*"):
            if self.fail_on_wildcard:
                raise RuntimeError("comp over wildcard rejected")
            out = []
            for rows in self.per_shard.values():
                out.extend(rows)
            return out
        return self.per_shard.get(name, [])


def test_the_fanin_gives_the_same_state_as_the_loop():
    """Equivalence is the whole claim. max() of newest and OR of terminal are associative
    across shards, so the engine's merge and the loop's merge cannot disagree."""
    per = {SCANS[0]: [_life_rows("s1", "running", 100), _life_rows("s2", "completed", 300)],
           SCANS[1]: [_life_rows("s1", "completed", 500)],
           SCANS[2]: [_life_rows("s3", "failed", 200)]}
    loop = S._lifecycle_state(LifeClient(per), SCANS, lambda *a: None, [0])
    fan = S._lifecycle_state(LifeClient(per), SCANS, lambda *a: None, [0],
                             fanin="yara_scanner_scans_v4_*")
    assert loop == fan
    # and the merge actually did something across shards
    assert fan["s1"] == {"terminal": True, "newest_ms": 500}


def test_the_fanin_is_one_query_not_one_per_shard():
    per = {s: [_life_rows("s%d" % i, "completed", 100)] for i, s in enumerate(SCANS)}
    q = [0]
    S._lifecycle_state(LifeClient(per), SCANS, lambda *a: None, q,
                       fanin="yara_scanner_scans_v4_*")
    assert q[0] == 1, "fan-in still cost one query per shard"


def test_a_rejected_fanin_falls_back_to_the_loop_and_loses_nothing():
    """A tenant that will not run comp over a wildcard must degrade to the old behaviour, not
    to a half-read lifecycle - state that reports live scans as non-terminal decides what is
    eligible to consolidate."""
    per = {SCANS[0]: [_life_rows("s1", "completed", 100)],
           SCANS[1]: [_life_rows("s2", "running", 200)],
           SCANS[2]: [_life_rows("s3", "completed", 300)]}
    c = LifeClient(per, fail_on_wildcard=True)
    state = S._lifecycle_state(c, SCANS, lambda *a: None, [0],
                               fanin="yara_scanner_scans_v4_*")
    assert state == S._lifecycle_state(LifeClient(per), SCANS, lambda *a: None, [0])
    assert len(c.queries) == 1 + len(SCANS), "did not fall back to every shard"


def test_a_partial_fanin_read_is_discarded_not_merged():
    """The failure mode that would be worst: absorbing whatever the wildcard returned before
    it failed, then topping it up from the loop, would double-count nothing but WOULD leave a
    scan marked terminal on the strength of a truncated read."""
    per = {s: [_life_rows("s1", "completed", 100)] for s in SCANS}

    class Half(LifeClient):
        def xql(self, query, limit=None):
            if "*" in query:
                raise RuntimeError("died after streaming some rows")
            return super().xql(query, limit)

    state = Half(per).xql and S._lifecycle_state(Half(per), SCANS, lambda *a: None, [0],
                                                 fanin="yara_scanner_scans_v4_*")
    assert state == {"s1": {"terminal": True, "newest_ms": 100}}


# ------------------------------------------------------- end to end through the automation

def _tenant():
    t = FakeTenant(names=MATCHES + SCANS)
    t.ds = getattr(t, "ds", {})
    return t


def _seeded(extra=()):
    """A tenant whose shards actually hold rows.

    Seeding matters: an EMPTY fleet-wide read is now treated as a failed fan-in and falls back
    to per-shard, because a wildcard resolving to nothing would otherwise consolidate nothing
    while reporting success. A fixture with no rows therefore exercises the fallback, not the
    fan-in - which is the opposite of what these two tests are for."""
    rows = {ds: {"scan%02d" % i: 3} for i, ds in enumerate(MATCHES + SCANS)}
    return FakeTenant(names=MATCHES + SCANS + list(extra), scans=rows)


def test_a_summary_run_reads_the_fleet_in_one_query_per_kind():
    """The observable that matters to an operator: the reported XQL call count stops tracking
    the host count. Two reads (lifecycle + matches) plus at most one target census."""
    t = _seeded()
    res = _run_automation(S, {"execute": "false", "schema_version": "4"}, t)
    reads = [c for c in t.calls if c.startswith("xql:")]
    wildcards = [c for c in reads if "_*" in c]
    assert len(wildcards) == 2, "expected one lifecycle + one matches fan-in, got %r" % reads
    assert not [c for c in reads if any(m in c for m in MATCHES)], (
        "still reading individual matches shards: %r" % reads)
    assert res is not None


def test_an_uncurated_tenant_still_reads_every_shard():
    """End-to-end proof the rail survives the wiring: drop a retired per-scan copy on the
    tenant and the pass must go back to one query per shard rather than widening its read."""
    t = _seeded(extra=[RETIRED])
    _run_automation(S, {"execute": "false", "schema_version": "4"}, t)
    reads = [c for c in t.calls if c.startswith("xql:")]
    assert not [c for c in reads if "_matches_v4_*" in c], (
        "fanned in despite an uncurated dataset: %r" % reads)
    assert [c for c in reads if MATCHES[0] in c], "did not fall back to per-shard reads"
