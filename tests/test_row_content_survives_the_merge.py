#!/usr/bin/env python3
"""What the rows SAY must survive the merge, not just how many there are. Criterion D2.3.

The largest gap the mutation audit found. Three separate corruptions of `_coerce_row`, each
leaving the row count exactly right, all survived the entire suite:

    every text value -> ""      rule names, file paths, hostnames all emptied
    every number     -> 0       offsets, file sizes, match counts all zeroed
    non-str text     -> None    a text field that read back as a number is lost

Counts still balance under all three, so `plan_consolidation` still reports verified, and
the source shards are still deleted. The findings that survive are blank, and the only
copies that said anything have been deleted as "successfully merged".

This is why D2.3 is worded "not just the count". Row-count arithmetic is necessary and it
was thoroughly covered; it is simply blind to this, because a corrupted row is still a row.

`_coerce_row` is where the risk concentrates: it exists to rewrite values (XQL read-back
does not round-trip types, so 'number' fields come back as '0' or 9.0 and add_data drops
rows whose types mismatch). Its whole job is changing values, which makes "changed the value
correctly" and "destroyed the value" adjacent edits.
"""
import pytest

# Installs the XSOAR stubs and puts the pack scripts on sys.path.
import test_pack_data_management
from test_consolidation import NOW, FakeClient, _s, _seed

import xdr_consolidate as xc

# xdr_consolidate.py plus ALL SIX automations that ship (test_pack_data_management.SHIPPING).
# Each of the six inlines this logic verbatim -- the tenant does not resolve cross-script
# imports, so an automation has to be self-contained -- and it is those six copies, not
# xdr_consolidate.py, that execute. A behaviour proven only in the CLI is not a guarantee, and
# a behaviour proven in five of six is not one either.
IMPLS = test_pack_data_management.impls(xc)

TARGET = "yara_scanner_matches_v2_scan_s1"

# Deliberately distinctive: a blanking or zeroing mutation cannot coincidentally reproduce
# any of these, and each field exercises a different branch of _coerce_row.
FINDINGS = [
    {"scan_id": "S1", "hostname": "hosta", "rule": "Evil_Ransomware_A",
     "filename": "/home/user/.cache/dropper.elf", "file_size": 448512,
     "file_sha256": "a9f1" + "0" * 60, "offset": 4096, "severity": "high",
     "event_timestamp_ms": 1000},
    {"scan_id": "S1", "hostname": "hosta", "rule": "Cobalt_Strike_Beacon",
     "filename": "/opt/app/lib/libssl.so.1.1", "file_size": 1,
     "file_sha256": "beef" + "1" * 60, "offset": 0, "severity": "critical",
     "event_timestamp_ms": 1001},
]


def _seeded():
    fc = FakeClient()
    _seed(fc, "yara_scanner_matches_v2_hosta_aa0001", [dict(r) for r in FINDINGS])
    _seed(fc, "yara_scanner_scans_v2_hosta_aa0001", _s("S1", "hosta", "completed"))
    return fc


def _key(r):
    return (r.get("scan_id"), r.get("rule"), r.get("filename"))


@pytest.mark.parametrize("impl", IMPLS)
def test_every_field_of_every_finding_survives(impl):
    """The criterion's own evidence line: sample rows by (scan_id, rule, file_path) in
    source and target. Compared field by field, because the count already balances under
    every corruption this is guarding against."""
    fc = _seeded()
    plans = impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                                   log=lambda *a: None)
    assert plans[0]["ok"] is True, "the fixture did not consolidate, so nothing is proven"

    merged = {_key(r): r for r in fc.ds[TARGET]}
    assert len(merged) == len(FINDINGS), "rows collapsed or duplicated on the merge"

    for original in FINDINGS:
        got = merged.get(_key(original))
        assert got is not None, (
            f"no merged row for rule={original['rule']} file={original['filename']} -- the "
            f"identifying fields did not survive")
        for field, expected in original.items():
            assert got.get(field) == expected, (
                f"{field} was corrupted by the merge: expected {expected!r}, got "
                f"{got.get(field)!r} (rule={original['rule']})")


@pytest.mark.parametrize("impl", IMPLS)
def test_findings_are_not_blanked(impl):
    """Names the blanking mutation directly, so the failure says what happened rather than
    surfacing as a confusing field-by-field mismatch."""
    fc = _seeded()
    impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                           log=lambda *a: None)
    for r in fc.ds[TARGET]:
        assert r.get("rule"), f"a merged finding has no rule name: {r}"
        assert r.get("filename"), f"a merged finding has no file path: {r}"
        assert r.get("hostname"), f"a merged finding has no hostname: {r}"


@pytest.mark.parametrize("impl", IMPLS)
def test_numeric_fields_are_not_zeroed(impl):
    """A zeroing mutation is invisible to any assertion that only checks a field EXISTS.
    file_size=1 and offset=0 are in the fixture on purpose: 1 is the smallest value that
    still distinguishes from a zeroed field, and offset=0 proves this checks the actual
    value rather than truthiness."""
    fc = _seeded()
    impl.run_consolidation(fc, "matches", quiet_secs=1, dry_run=False, now_ms=NOW,
                           log=lambda *a: None)
    sizes = sorted(r["file_size"] for r in fc.ds[TARGET])
    assert sizes == [1, 448512], f"file sizes were not preserved: {sizes}"
    offsets = sorted(r["offset"] for r in fc.ds[TARGET])
    assert offsets == [0, 4096], f"offsets were not preserved: {offsets}"


@pytest.mark.parametrize("impl", IMPLS)
def test_coerce_row_changes_the_type_without_changing_the_value(impl):
    """`_coerce_row` at the unit level. Its job is rewriting values, so 'rewrote it
    correctly' and 'destroyed it' are adjacent edits -- these pin the difference."""
    schema = {"rule": "text", "filename": "text", "offset": "number",
              "file_size": "number", "truncated": "bool"}
    out = impl._coerce_row(
        {"rule": "Evil_A", "filename": "/tmp/x.exe", "offset": "4096",
         "file_size": 9.0, "truncated": "true", "_insert_time": "sys"}, schema)

    assert out["rule"] == "Evil_A"
    assert out["filename"] == "/tmp/x.exe"
    assert out["offset"] == 4096 and isinstance(out["offset"], int), (
        "the string '4096' must become the NUMBER 4096, not 0 and not '4096'")
    assert out["file_size"] == 9 and isinstance(out["file_size"], int)
    assert out["truncated"] is True
    assert "_insert_time" not in out, "system columns must be projected away"


@pytest.mark.parametrize("impl", IMPLS)
def test_a_text_field_returned_as_a_number_keeps_its_value(impl):
    """The third mutation: dropping to None instead of stringifying. XQL read-back is what
    makes this reachable -- it stringifies and floats numeric columns unpredictably, so a
    text field arriving as a number is a real read-back shape, not a hypothetical."""
    out = impl._coerce_row({"rule": 12345}, {"rule": "text"})
    assert out["rule"] == "12345", (
        f"a text field that read back as a number became {out.get('rule')!r} instead of "
        f"its stringified value")
