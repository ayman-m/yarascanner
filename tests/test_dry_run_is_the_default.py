#!/usr/bin/env python3
"""Omitting `dry_run` must not mutate the tenant. Criterion D6.2.

Found by mutation audit. Flipping `run_consolidation`'s default from `dry_run=True` to
`dry_run=False` in both copies left the whole suite green -- because every existing test
passes the flag explicitly, so the default itself was never once exercised.

The default IS the protection. A caller that passes `dry_run=False` has decided to write;
a caller that passes nothing has not decided anything, and the only safe reading of "not
decided" is "do not touch the tenant". Flipped, that caller silently deletes datasets. A
dry run that writes is worse than having no dry run at all, because it is the mode people
reach for precisely when they are unsure.

`test_orchestration_happy_path_matches` uses this exact fixture with `dry_run=False` and
consolidates 65 rows, so the positive control below is not decoration -- it is what stops
this file passing vacuously against a fixture that would never have consolidated anyway.
"""
import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management  # noqa: F401
from test_consolidation import NOW, FakeClient, SpyClient, _m, _s, _seed

import YaraConsolidateCommon as pack_common
import xdr_consolidate as xc

IMPLS = [
    pytest.param(xc, id="xdr_consolidate"),
    pytest.param(pack_common, id="pack"),
]

MATCHES_A = "yara_scanner_matches_v2_hosta_aa0001"
MATCHES_B = "yara_scanner_matches_v2_hostb_bb0002"
TARGET = "yara_scanner_matches_v2_scan_s1"


def _consolidatable(client_cls=FakeClient):
    """Two finished hosts with 65 matches between them -- genuinely consolidatable."""
    fc = client_cls()
    _seed(fc, MATCHES_A, _m("S1", "hosta", 40))
    _seed(fc, MATCHES_B, _m("S1", "hostb", 25))
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    _seed(fc, "yara_scanner_scans_v2_hostb_bb0002", _s("S1", "hostb", "completed"))
    return fc


@pytest.mark.parametrize("impl", IMPLS)
def test_the_fixture_really_would_consolidate(impl):
    """POSITIVE CONTROL. Without this, every assertion below passes on a fixture that does
    nothing, and the file would still be green with dry-run completely broken."""
    fc = _consolidatable()
    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is True
    assert len(fc.ds[TARGET]) == 65
    assert MATCHES_A not in fc.ds, "the fixture must actually delete shards when writing"


@pytest.mark.parametrize("impl", IMPLS)
def test_omitting_dry_run_writes_nothing_and_deletes_nothing(impl):
    """The criterion. Same fixture, flag omitted -- the tenant must be untouched."""
    fc = _consolidatable(SpyClient)
    before = {name: list(rows) for name, rows in fc.ds.items()}

    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, now_ms=NOW,
                                   log=lambda *a: None)

    assert fc.calls == [], (
        f"omitting dry_run performed mutating calls: {fc.calls}")
    assert fc.ds == before, "the dataset contents changed on a run with dry_run omitted"
    assert TARGET not in fc.ds, "a consolidation target was created with dry_run omitted"
    assert MATCHES_A in fc.ds and MATCHES_B in fc.ds, "source shards were deleted"
    assert plans, "the pass reported nothing at all, so 'no writes' proves nothing"
    assert all(p.get("reason") == "dry_run" for p in plans), (
        f"a run with dry_run omitted did not report itself as a dry run: "
        f"{[p.get('reason') for p in plans]}")


@pytest.mark.parametrize("impl", IMPLS)
def test_the_signature_default_is_still_true(impl):
    """Pins the default directly, so the failure names the cause rather than a symptom
    three layers down in an orchestration assertion."""
    import inspect
    default = inspect.signature(impl.run_consolidation).parameters["dry_run"].default
    assert default is True, (
        f"run_consolidation's dry_run default is {default!r}. A caller that passes nothing "
        f"has not decided to write, and would now mutate the tenant.")


@pytest.mark.parametrize("impl", IMPLS)
def test_status_check_never_mutates_whatever_it_is_asked(impl):
    """check_consolidation_status exists to look without touching. It forces dry_run
    internally, so no argument a caller supplies should be able to make it write."""
    fc = _consolidatable(SpyClient)
    before = {name: list(rows) for name, rows in fc.ds.items()}
    impl.check_consolidation_status(fc, quiet_secs=1, now_ms=NOW, log=lambda *a: None)
    assert fc.calls == [], f"the status check mutated the tenant: {fc.calls}"
    assert fc.ds == before
    assert TARGET not in fc.ds
