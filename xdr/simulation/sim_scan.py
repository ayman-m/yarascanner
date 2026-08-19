#!/usr/bin/env python3
"""PROBE 1 — one simulated host runs one scan.

Assumption under test: a host can create its own per-host data lookups, write findings and
lifecycle rows to them, and register itself in the shared tracker with a started row and a
completed row.

This is the write path the whole design depends on. If it does not hold for ONE host, there
is no point measuring what happens with five hundred.

  python3 sim_scan.py --host simhost1 --matches 25
"""
import argparse
import time

from simlib import (TRACKER, TRACKER_SCHEMA, DATA_SCHEMA, banner, client, ensure,
                    new_scan_id, rows_in, sim_name, verdict)


def run_one(ac, host, n_matches, verify=True):
    scan_id = new_scan_id(host)
    matches_ds = ensure(ac, sim_name("matches", host), DATA_SCHEMA)
    scans_ds = ensure(ac, sim_name("scans", host), DATA_SCHEMA)
    ensure(ac, TRACKER, TRACKER_SCHEMA)

    now = int(time.time() * 1000)

    # 1. REGISTER FIRST. The started row is written before any finding, so a scan that dies
    #    mid-run has still declared that its dataset exists. Registering afterwards would
    #    leave exactly the invisible-orphan window the tracker is meant to close.
    started = {"scan_id": scan_id, "hostname": host, "event": "started",
               "event_ts_ms": now, "status": "", "matches_dataset": matches_ds,
               "scans_dataset": scans_ds, "files_scanned": 0, "matches": 0}
    ac.add_lookup_data(TRACKER, [started])

    # 2. write findings to this host's OWN dataset (never shared -> never collides)
    rows = [{"scan_id": scan_id, "hostname": host, "rule": f"sim_rule_{i % 3}",
             "file_path": f"/opt/sim/{host}/f{i}", "match_count": 1 + (i % 7),
             "event_timestamp_ms": now + i} for i in range(n_matches)]
    if rows:
        ac.add_lookup_data(matches_ds, rows)
    ac.add_lookup_data(scans_ds, [{"scan_id": scan_id, "hostname": host, "rule": "",
                                   "file_path": "", "match_count": n_matches,
                                   "event_timestamp_ms": now}])

    # 3. terminal tracker row -- the trigger the correlation rule watches
    completed = dict(started, event="completed", status="completed",
                     event_ts_ms=int(time.time() * 1000),
                     files_scanned=100 + n_matches, matches=n_matches)
    ac.add_lookup_data(TRACKER, [completed])
    return scan_id, matches_ds, scans_ds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="simhost1")
    ap.add_argument("--matches", type=int, default=25)
    a = ap.parse_args()

    banner(f"PROBE 1 — one host, one scan  (host={a.host}, matches={a.matches})")
    ac = client()
    scan_id, mds, sds = run_one(ac, a.host, a.matches)
    print(f"scan_id        {scan_id}")
    print(f"matches ds     {mds}")
    print(f"tracker        {TRACKER}")
    print("waiting for ingest…")

    ok = True
    n_match = rows_in(ac, mds, f'scan_id = "{scan_id}"')
    ok &= verdict(n_match == a.matches,
                  f"per-host matches dataset holds {n_match} row(s), expected {a.matches}")
    n_track = rows_in(ac, TRACKER, f'scan_id = "{scan_id}"')
    ok &= verdict(n_track == 2,
                  f"tracker holds {n_track} row(s) for this scan, expected 2 (started+completed)")
    try:
        r = ac.xql(f'dataset = {TRACKER} | filter scan_id = "{scan_id}" '
                   f'| fields event, matches_dataset, status', limit=10)
        names = {x.get("matches_dataset") for x in r}
        ok &= verdict(names == {mds},
                      f"tracker rows carry the LITERAL dataset name {names} — no derivation needed")
    except Exception as e:
        ok &= verdict(False, f"could not read tracker rows back: {e}")

    print()
    print("PROBE 1 RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
