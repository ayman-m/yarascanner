#!/usr/bin/env python3
"""PROBE 2 — THE CRITICAL ONE. Concurrent tracker writes.

Assumption under test: many hosts can write their two tracker rows to ONE shared lookup
dataset without losing rows.

This is the assumption the whole trigger design rests on, and the one most likely to be
false. Measured previously on this tenant: 8 threads writing 1,601 rows to a single lookup
dataset landed 201 of them -- 87% silently lost, with no error raised to 7 of the 8
writers. The tracker writes far less (2 rows per scan, not hundreds), but "less" is not
"safe", and the difference has to be measured rather than argued.

Three modes, so the result says WHICH mitigation is needed rather than just pass/fail:

  --mode naive     all hosts write at once, no jitter, no verify   (the worst case)
  --mode jitter    starts spread over --jitter seconds             (what jitter alone buys)
  --mode verify    jitter + read-back-and-retry                    (the proposed design)

  python3 sim_fleet.py --hosts 24 --mode naive
  python3 sim_fleet.py --hosts 24 --mode verify --jitter 60
"""
import argparse
import random
import threading
import time

from simlib import (TRACKER, TRACKER_SCHEMA, banner, client, ensure, new_scan_id,
                    rows_in, verdict)

_lock = threading.Lock()
_stats = {"attempted": 0, "write_errors": 0, "retries": 0, "verify_failures": 0}


def bump(k, n=1):
    with _lock:
        _stats[k] += n


def one_host(ac, host, mode, jitter, verify_tries=4):
    if mode in ("jitter", "verify") and jitter:
        time.sleep(random.uniform(0, jitter))
    scan_id = new_scan_id(host)
    base = {"scan_id": scan_id, "hostname": host, "event": "started",
            "event_ts_ms": int(time.time() * 1000), "status": "",
            "matches_dataset": f"sim_matches_{host}", "scans_dataset": f"sim_scans_{host}",
            "files_scanned": 0, "matches": 0}
    for ev in ("started", "completed"):
        row = dict(base, event=ev, event_ts_ms=int(time.time() * 1000))
        bump("attempted")
        try:
            ac.add_lookup_data(TRACKER, [row])
        except Exception:
            bump("write_errors")
            continue
        if mode != "verify":
            continue
        # WRITE-THEN-VERIFY: read the row back; retry if the platform silently dropped it.
        landed = False
        for attempt in range(verify_tries):
            time.sleep(3 + attempt * 3)
            try:
                r = ac.xql(f'dataset = {TRACKER} | filter scan_id = "{scan_id}" '
                           f'and event = "{ev}" | comp count() as n', limit=3)
                if r and int(float(r[0].get("n") or 0)) >= 1:
                    landed = True
                    break
            except Exception:
                pass
            bump("retries")
            try:
                ac.add_lookup_data(TRACKER, [row])
            except Exception:
                bump("write_errors")
        if not landed:
            bump("verify_failures")
    return scan_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=16)
    ap.add_argument("--mode", choices=("naive", "jitter", "verify"), default="naive")
    ap.add_argument("--jitter", type=float, default=60.0)
    a = ap.parse_args()

    banner(f"PROBE 2 — concurrent tracker writes  "
           f"(hosts={a.hosts}, mode={a.mode}, jitter={a.jitter if a.mode!='naive' else 0}s)")
    ac = client()
    ensure(ac, TRACKER, TRACKER_SCHEMA)
    before = max(0, rows_in(ac, TRACKER))
    print(f"tracker rows before: {before}")

    expected = a.hosts * 2
    t0 = time.time()
    threads, ids = [], []
    for i in range(a.hosts):
        h = f"simfleet{i:03d}"
        t = threading.Thread(target=lambda hh=h: ids.append(one_host(ac, hh, a.mode, a.jitter)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    print(f"{a.hosts} hosts x 2 rows = {expected} attempted in {elapsed:.0f}s")
    print(f"write errors {_stats['write_errors']}  retries {_stats['retries']}  "
          f"verify failures {_stats['verify_failures']}")

    print("waiting for ingest to settle…")
    time.sleep(25)
    after = rows_in(ac, TRACKER)
    landed = after - before
    loss = expected - landed
    pct = (100.0 * loss / expected) if expected else 0

    print(f"tracker rows after: {after}   landed: {landed}/{expected}   lost: {loss} ({pct:.1f}%)")
    ok = verdict(loss <= 0, f"no rows lost writing {expected} rows from {a.hosts} concurrent hosts")
    if loss > 0:
        print(f"      -> at this concurrency the shared tracker loses rows. A lost `started`")
        print(f"         row means a real dataset is never registered and never cleaned up.")
        if a.mode != "verify":
            print(f"      -> re-run with --mode verify to see whether read-back-and-retry closes it.")
    print()
    print("PROBE 2 RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
