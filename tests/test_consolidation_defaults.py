#!/usr/bin/env python3
"""The default gate values are what the tenant actually runs on. Pin them.

Found by mutation audit. Every one of these constants can be overridden per call, and the
existing suite always passes explicit values -- so the LOGIC is well covered while the
DEFAULTS were never exercised once. Mutating all three in both copies at once left the
whole suite green:

    DEFAULT_QUIET_SECS     900     -> 0            suite still green
    DEFAULT_ABANDONED_SECS 24h     -> 10 years     suite still green
    DEFAULT_ROW_CEILING    2e6     -> 1e15         suite still green

Nobody passes quiet_secs on a real run. The tenant gets the defaults, so an edit to any of
these three ships straight to production behaviour with no test standing in the way.

Two of these are not arbitrary numbers -- they are relationships to facts outside this
module, stated in the source comments but enforced nowhere. Where that is the case these
tests assert the RELATIONSHIP, not the literal, so raising the scanner's drain budget
without raising the quiet period fails here instead of silently truncating uploads on the
tenant.
"""
import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management  # noqa: F401

import YaraConsolidateCommon as pack_common
import xdr_consolidate as xc
import xdr_yara_scanner as scanner

IMPLS = [
    pytest.param(xc, id="xdr_consolidate"),
    pytest.param(pack_common, id="pack"),
]

# The Action Center caps a script run at 6 hours. This is a platform fact with no constant
# to import -- it is named here so the abandoned-cutoff test states what it depends on.
ACTION_CENTER_MAX_SCRIPT_SECS = 6 * 3600


@pytest.mark.parametrize("impl", IMPLS)
def test_quiet_period_outlasts_the_scanners_upload_drain(impl):
    """The invariant the source comment states: quiet >= the scanner's max drain budget.

    A scan reports `completed` and THEN keeps draining queued lookup batches. Merge inside
    that window and the shard is consolidated while rows are still arriving, so the late
    rows land on a dataset that has already been counted, verified and deleted.

    Asserted against the scanner's own constant rather than against 600, so raising the
    drain budget without raising the quiet period fails here. (LOOKUP_DRAIN_MAX_SECS is
    env-resolved at import; unset in tests, so this reads the shipped default.)
    """
    drain = scanner.LOOKUP_DRAIN_MAX_SECS
    assert impl.DEFAULT_QUIET_SECS >= drain, (
        f"quiet period {impl.DEFAULT_QUIET_SECS}s is shorter than the scanner's max upload "
        f"drain of {drain}s -- a shard can be merged and deleted while its scanner is still "
        f"writing rows into it")


@pytest.mark.parametrize("impl", IMPLS)
def test_quiet_period_keeps_a_real_margin_over_the_drain(impl):
    """`>=` alone is satisfied by exactly equal, which leaves no room for scheduling jitter.

    Separate from the test above on purpose: that one is the hard safety floor, this one is
    the design intent ("+ margin"). They fail with different messages because they mean
    different things.
    """
    drain = scanner.LOOKUP_DRAIN_MAX_SECS
    assert impl.DEFAULT_QUIET_SECS >= drain * 1.25, (
        f"quiet period {impl.DEFAULT_QUIET_SECS}s leaves under 25% margin over the {drain}s "
        f"drain budget; the comment specifies drain + margin, not drain exactly")


@pytest.mark.parametrize("impl", IMPLS)
def test_abandoned_cutoff_is_the_one_day_objective(impl):
    """The stated objective, encoded: no per-host shard survives a day past its scan start.

    This constant IS the requirement, not an implementation detail. Raising it strands a
    crashed host's findings for however long it is raised to; the 10-year mutation that
    passed the whole suite would have stranded them permanently.
    """
    assert impl.DEFAULT_ABANDONED_SECS == 24 * 3600, (
        f"abandoned cutoff is {impl.DEFAULT_ABANDONED_SECS}s, not 24h. The objective is that "
        f"no individual per-host shard remains once its scan is complete or a day has passed "
        f"since it started.")


@pytest.mark.parametrize("impl", IMPLS)
def test_abandoned_cutoff_cannot_catch_a_scan_that_is_merely_slow(impl):
    """The lower bound the comment argues: 24h comfortably exceeds the 6h script cap.

    The failure this prevents is the opposite of stranding -- declaring a scan abandoned
    while it is still legitimately running, then merging and deleting a shard underneath a
    live writer. The 60-second mutation was caught by an existing test; this states WHY the
    floor sits where it does rather than leaving it to a fixture's chosen numbers.
    """
    assert impl.DEFAULT_ABANDONED_SECS > ACTION_CENTER_MAX_SCRIPT_SECS, (
        f"abandoned cutoff {impl.DEFAULT_ABANDONED_SECS}s is not clear of the Action Center's "
        f"{ACTION_CENTER_MAX_SCRIPT_SECS}s script cap -- a scan still legitimately running "
        f"could be treated as abandoned")


@pytest.mark.parametrize("impl", IMPLS)
def test_row_ceiling_is_a_real_ceiling(impl):
    """A ceiling that cannot be reached is not a ceiling.

    It exists to refuse an implausibly large merge rather than attempt it -- the runaway
    case, where a bad plan would otherwise push millions of rows through add_data. The 1e15
    mutation kept the parameter and the comparison while removing every effect they have.
    """
    assert impl.DEFAULT_ROW_CEILING == 2_000_000, (
        f"row ceiling is {impl.DEFAULT_ROW_CEILING}, not 2,000,000")
    # Guards the mutation directly: any plausible fleet must sit under it, any absurd
    # total must sit over it. A ceiling outside that band is decorative.
    assert impl.DEFAULT_ROW_CEILING < 10 ** 9, (
        f"row ceiling {impl.DEFAULT_ROW_CEILING} is too large to ever refuse anything")
    assert impl.DEFAULT_ROW_CEILING > 100_000, (
        f"row ceiling {impl.DEFAULT_ROW_CEILING} is low enough to refuse a legitimate "
        f"fleet-wide merge")


def test_both_copies_agree_on_all_three_defaults():
    """Belt and braces: the parity test compares source text, this compares live values."""
    for name in ("DEFAULT_QUIET_SECS", "DEFAULT_ABANDONED_SECS", "DEFAULT_ROW_CEILING"):
        assert getattr(xc, name) == getattr(pack_common, name), (
            f"{name} differs between xdr_consolidate ({getattr(xc, name)}) and the pack copy "
            f"({getattr(pack_common, name)}) -- the pack copy is what runs on the tenant")
