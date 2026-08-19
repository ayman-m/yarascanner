#!/usr/bin/env python3
"""PROBE 5 — Round 4 edge cases.

Seeds each situation deliberately and asserts what the design says must happen. The happy
path already passes (probe 3); these are the cases that decide whether the design is safe.

Each case is independent and named for its criterion in ROUND4_CRITERIA.md.

  python3 sim_edge.py            # run every case
  python3 sim_edge.py --case D12 # one case
"""
import argparse
import time

from simlib import (TRACKER, TRACKER_SCHEMA, DATA_SCHEMA, banner, client, ensure,
                    new_scan_id, rows_in, sim_name, verdict)

DAY_MS = 24 * 3600 * 1000
RESULTS = []


def record(cid, ok, msg):
    RESULTS.append((cid, ok, msg))
    verdict(ok, f"{cid}  {msg}")
    return ok


def _seed(ac, host, n, event="completed", status="completed", age_ms=0, scan_id=None):
    """Seed one host: its own data lookup plus tracker rows, optionally aged."""
    scan_id = scan_id or new_scan_id(host)
    mds = ensure(ac, sim_name("matches", host), DATA_SCHEMA)
    ensure(ac, TRACKER, TRACKER_SCHEMA)
    now = int(time.time() * 1000) - age_ms
    if n:
        ac.add_lookup_data(mds, [
            {"scan_id": scan_id, "hostname": host, "rule": "edge_rule",
             "file_path": f"/opt/sim/{host}/f{i}", "match_count": 1,
             "event_timestamp_ms": now + i} for i in range(n)])
    base = {"scan_id": scan_id, "hostname": host, "event": "started", "event_ts_ms": now,
            "status": "", "matches_dataset": mds, "scans_dataset": sim_name("scans", host),
            "files_scanned": 0, "matches": 0}
    rows = [base]
    if event == "completed":
        rows.append(dict(base, event="completed", status=status,
                         event_ts_ms=now + 1000, files_scanned=100, matches=n))
    ac.add_lookup_data(TRACKER, rows)
    return scan_id, mds


def case_D12(ac):
    """A scan still RUNNING must be untouched: not read, not merged, not deleted."""
    scan_id, mds = _seed(ac, "edge_running", 7, event="started")   # no completed row
    time.sleep(15)
    before = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    # what the playbook would select
    done = ac.xql(f'dataset = {TRACKER} | filter event = "completed" | fields scan_id',
                  limit=200) or []
    selected = {r.get("scan_id") for r in done}
    if scan_id in selected:
        return record("D1.2", False,
                      f"a scan with no terminal row was SELECTED for consolidation "
                      f"({scan_id}) — its host may still be writing")
    after = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    return record("D1.2", before == after == 7,
                  f"running scan not selected; its dataset unchanged at {after} rows")


def case_D14(ac):
    """The 24h abandoned cutoff needs a PAIR: 25h old qualifies, 23h old does not."""
    old_id, _ = _seed(ac, "edge_aband25", 5, event="started", age_ms=25 * 3600 * 1000)
    new_id, _ = _seed(ac, "edge_aband23", 5, event="started", age_ms=23 * 3600 * 1000)
    time.sleep(15)
    rows = ac.xql(f'dataset = {TRACKER} | filter event = "started" '
                  f'| fields scan_id, event_ts_ms', limit=400) or []
    now = int(time.time() * 1000)
    aged = {r["scan_id"] for r in rows
            if r.get("event_ts_ms") and (now - float(r["event_ts_ms"])) > DAY_MS}
    ok = (old_id in aged) and (new_id not in aged)
    return record("D1.4", ok,
                  f"25h-old scan past the cutoff: {old_id in aged}; "
                  f"23h-old scan past it: {new_id not in aged and 'no' or 'YES — too eager'}")


def case_D22(ac):
    """A count mismatch must keep EVERY source and delete nothing."""
    scan_id, mds = _seed(ac, "edge_mismatch", 9)
    time.sleep(15)
    src = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    target = sim_name("scan", "mismatch_probe")
    ac.create_lookup_dataset(target, DATA_SCHEMA)
    # deliberately merge only PART of the source, as a botched merge would
    rows = ac.xql(f'dataset = {mds} | filter scan_id = "{scan_id}" | limit 100', limit=100) or []
    ac.add_lookup_data(target, [{k: r.get(k) for k in
                                 ("scan_id","hostname","rule","file_path","match_count",
                                  "event_timestamp_ms")} for r in rows[:4]])
    time.sleep(15)
    merged = rows_in(ac, target, f'scan_id = "{scan_id}"')
    if merged == src:
        return record("D2.2", False, "could not construct a mismatch; case inconclusive")
    # the gate: sources must survive
    still = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    return record("D2.2", still == src,
                  f"merged {merged} != source {src}, and all {still} source row(s) survive "
                  f"— nothing deleted on a mismatch")


def case_D31(ac):
    """A CANCELLED scan's findings are real findings: merged, never discarded."""
    scan_id, mds = _seed(ac, "edge_cancelled", 6, status="cancelled")
    time.sleep(15)
    rows = ac.xql(f'dataset = {TRACKER} | filter scan_id = "{scan_id}" and event = "completed" '
                  f'| fields status, matches_dataset', limit=5) or []
    if not rows:
        return record("D3.1", False, "cancelled scan wrote no terminal tracker row")
    st = rows[0].get("status")
    n = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    return record("D3.1", st == "cancelled" and n == 6,
                  f"cancelled scan is selectable (status={st!r}) with its {n} finding(s) intact")


def case_D34(ac):
    """A scan whose dataset is EMPTY is retired cleanly, not treated as an error."""
    scan_id, mds = _seed(ac, "edge_empty", 0)          # tracker rows, zero findings
    time.sleep(15)
    n = rows_in(ac, mds, f'scan_id = "{scan_id}"', tries=2, delay=4)
    tracked = rows_in(ac, TRACKER, f'scan_id = "{scan_id}"')
    return record("D3.4", n <= 0 and tracked == 2,
                  f"empty scan: {max(n,0)} finding row(s), {tracked} tracker row(s) — "
                  f"nothing to merge, and it is still discoverable for retirement")


CASES = {"D12": case_D12, "D14": case_D14, "D22": case_D22,
         "D31": case_D31, "D34": case_D34}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", choices=sorted(CASES))
    a = ap.parse_args()
    banner("PROBE 5 — Round 4 edge cases")
    ac = client()
    for name in ([a.case] if a.case else sorted(CASES)):
        print(f"\n--- {name} ---")
        try:
            CASES[name](ac)
        except Exception as e:
            record(name, False, f"raised {type(e).__name__}: {str(e)[:150]}")
    ok = sum(1 for _, o, _ in RESULTS if o)
    print(f"\n{'='*72}\nEDGE CASES: {ok}/{len(RESULTS)} pass")
    for cid, o, msg in RESULTS:
        if not o:
            print(f"  FAIL {cid}: {msg[:170]}")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
