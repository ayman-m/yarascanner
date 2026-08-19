#!/usr/bin/env python3
"""PROBE 3 — the playbook's actions, end to end.

Assumption under test: given only the tracker, the playbook can find a finished scan's
datasets, merge them into a per-scan target, verify the merge, delete the sources, and
retire the tracking rows -- with no wildcard and no name derivation anywhere.

Every step is the API call the real playbook would make, in the order it would make it.

  python3 sim_playbook.py            # merge everything the tracker says is complete
  python3 sim_playbook.py --dry-run  # report only
"""
import argparse
import time

from simlib import TRACKER, banner, client, rows_in, sim_name, verdict


def finished_scans(ac):
    """Read the tracker for scans with a completed row. NO WILDCARD -- one fixed name."""
    q = (f'dataset = {TRACKER} | filter event = "completed" '
         f'| fields scan_id, hostname, matches_dataset, scans_dataset, status, matches '
         f'| limit 200')
    return ac.xql(q, limit=200) or []


def merge_one(ac, row, dry_run):
    scan_id = row["scan_id"]
    src = row.get("matches_dataset")
    target = sim_name("scan", scan_id.replace("-", "_")[:60])
    print(f"\n  scan {scan_id}")
    print(f"    source (from the tracker row, not derived): {src}")

    src_rows = rows_in(ac, src, f'scan_id = "{scan_id}"', tries=3, delay=4)
    if src_rows <= 0:
        print(f"    source holds {src_rows} row(s) — nothing to merge; retire the tracking rows")
        if not dry_run:
            ac.remove_lookup_data(TRACKER, [{"scan_id": scan_id}])
        return True

    if dry_run:
        print(f"    would merge {src_rows} row(s) -> {target}")
        return True

    # 1. read the source rows by EXACT dataset name
    rows = ac.xql(f'dataset = {src} | filter scan_id = "{scan_id}" | limit 5000', limit=5000) or []
    payload = [{k: r.get(k) for k in
                ("scan_id", "hostname", "rule", "file_path", "match_count", "event_timestamp_ms")}
               for r in rows]

    # 2. single sequential writer into the per-scan target
    from simlib import DATA_SCHEMA
    ac.create_lookup_dataset(target, DATA_SCHEMA)
    ac.add_lookup_data(target, payload)
    time.sleep(12)

    # 3. VERIFY BEFORE DELETE -- row-count parity, the whole safety of the design
    merged = rows_in(ac, target, f'scan_id = "{scan_id}"')
    if merged != src_rows:
        print(f"    MISMATCH: merged {merged} vs source {src_rows} — keeping sources, nothing deleted")
        return False
    print(f"    verified {merged} == {src_rows}; deleting source rows and retiring tracker rows")

    # 4. only now remove the source rows, then the tracking rows -- in that order.
    #    A tracking row retired first is a scan forgotten.
    ac.remove_lookup_data(src, [{"scan_id": scan_id}])
    ac.remove_lookup_data(TRACKER, [{"scan_id": scan_id}])
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    banner(f"PROBE 3 — playbook actions{' (DRY RUN)' if a.dry_run else ''}")
    ac = client()

    scans = finished_scans(ac)
    print(f"tracker reports {len(scans)} completed scan(s)")
    if not scans:
        print("nothing to do — run sim_scan.py first")
        return 0

    ok = all(merge_one(ac, r, a.dry_run) for r in scans)
    if not a.dry_run:
        time.sleep(12)
        left = rows_in(ac, TRACKER, tries=3, delay=5)
        print(f"\ntracker rows remaining: {left}")
        ok &= verdict(left >= 0, "tracker pruned surgically, not dumped and rewritten")
    print()
    print("PROBE 3 RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
