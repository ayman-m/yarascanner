#!/usr/bin/env python3
"""Verification must be positive evidence that rows arrived, not merely the absence of
disagreement. Criteria D2.1 and D2.6.

Found by mutation audit. Two edits to the one comparison in `plan_consolidation` left the
whole suite green:

    target_count == source_total  ->  target_count >= source_total
    source_total > 0              ->  source_total >= 0

Neither is a typo anyone would notice in review, and each one converts "I counted the rows
into the target and they are all there" into something much weaker.

`plan_consolidation` is the last gate before deletion. Everything upstream can be
conservative, but if this returns ok=True the sources are deleted, and a lookup dataset
that has been deleted is gone. So its two guards are load-bearing in opposite directions:

    ==  not >=   a target holding MORE rows than its sources is not a success, it is a
                 double-merge. Accepting it makes a re-run's duplicates look correct and
                 breaks the idempotency D2.6 requires.
    > 0 not >= 0 0 == 0 is not evidence of anything. run_consolidation passes
                 target_count=0 when the target does not exist, so with `>= 0` a scan whose
                 sources also count 0 -- because they are genuinely empty, or because a
                 count query failed -- reads as "verified" and its shards are deleted on the
                 strength of two zeroes agreeing.
"""
import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management

import xdr_consolidate as xc

# xdr_consolidate.py plus ALL SIX automations that ship (test_pack_data_management.SHIPPING).
# Each of the six inlines this logic verbatim -- the tenant does not resolve cross-script
# imports, so an automation has to be self-contained -- and it is those six copies, not
# xdr_consolidate.py, that execute. A behaviour proven only in the CLI is not a guarantee, and
# a behaviour proven in five of six is not one either.
IMPLS = test_pack_data_management.impls(xc)


@pytest.mark.parametrize("impl", IMPLS)
def test_an_exact_count_match_verifies(impl):
    """Positive control. Without it, 'nothing ever verifies' passes every case below and
    the tool silently stops consolidating while looking perfectly safe."""
    plan = impl.plan_consolidation("s1", {"ds_a": 3, "ds_b": 2}, target_count=5)
    assert plan["ok"] is True
    assert plan["reason"] == "verified"
    assert plan["deletable"] == ["ds_a", "ds_b"]


@pytest.mark.parametrize("impl", IMPLS)
def test_a_target_holding_more_rows_than_its_sources_does_not_verify(impl):
    """D2.1 / D2.6. The double-merge case: a re-run that merged the same sources twice.

    `>=` would call this verified and delete the sources, leaving a target with duplicated
    findings and no way left to detect it -- the sources that would have proved the
    duplication are the very things deleted.
    """
    plan = impl.plan_consolidation("s1", {"ds_a": 3, "ds_b": 2}, target_count=10)
    assert plan["ok"] is False, (
        "a target with 10 rows for 5 source rows was accepted as verified -- that is a "
        "double-merge, not a success")
    assert plan["reason"] == "count_mismatch"
    assert plan["deletable"] == [], "sources marked deletable despite duplicate rows"


@pytest.mark.parametrize("impl", IMPLS)
def test_one_row_over_is_still_a_mismatch(impl):
    """The boundary. A test using 10-vs-5 alone would also pass under a `>=` that had been
    written as `> source_total + 5`, so pin the tightest failing case."""
    plan = impl.plan_consolidation("s1", {"ds_a": 5}, target_count=6)
    assert plan["ok"] is False
    assert plan["deletable"] == []


@pytest.mark.parametrize("impl", IMPLS)
def test_two_zeroes_agreeing_is_not_verification(impl):
    """D2.6. run_consolidation passes target_count=0 when the target does not exist, so
    this is reachable whenever a scan's sources also count 0 -- genuinely empty, or a failed
    count query. `>= 0` would delete the shards on the strength of 0 == 0."""
    plan = impl.plan_consolidation("s1", {"ds_a": 0}, target_count=0)
    assert plan["ok"] is False, (
        "0 source rows and 0 target rows was accepted as verified, so the shard would be "
        "deleted without any evidence that a merge happened")
    assert plan["deletable"] == [], "an unmerged shard was marked deletable"


@pytest.mark.parametrize("impl", IMPLS)
def test_a_shortfall_keeps_every_source(impl):
    """The direction the criteria state outright: any shortfall keeps everything."""
    plan = impl.plan_consolidation("s1", {"ds_a": 3, "ds_b": 6}, target_count=4)
    assert plan["ok"] is False
    assert plan["reason"] == "count_mismatch"
    assert plan["deletable"] == []
    assert plan["source_total"] == 9, "the report must state what it expected"
    assert plan["target_count"] == 4, "and what it actually found"


@pytest.mark.parametrize("impl", IMPLS)
def test_the_ceiling_is_judged_on_sources_so_refusal_precedes_writing(impl):
    """D2.5. Checked against the SOURCE total, so an oversize job is refused before a
    partial target exists. Judging it on the target would only refuse after writing."""
    ceiling = 100
    plan = impl.plan_consolidation("s1", {"ds_a": 150}, target_count=0, row_ceiling=ceiling)
    assert plan["ok"] is False
    assert plan["reason"] == "row_ceiling_exceeded", (
        "an oversize merge was not refused on its source count, so it would only be caught "
        "after the target had been written")
    assert plan["deletable"] == []


@pytest.mark.parametrize("impl", IMPLS)
def test_the_ceiling_refusal_outranks_a_count_match(impl):
    """An oversize job that happens to have merged correctly is still refused. Ordering
    matters: if the count check ran first, a large successful merge would be waved through
    and the ceiling would only ever fire on jobs that had already failed."""
    plan = impl.plan_consolidation("s1", {"ds_a": 150}, target_count=150, row_ceiling=100)
    assert plan["reason"] == "row_ceiling_exceeded"
    assert plan["ok"] is False
