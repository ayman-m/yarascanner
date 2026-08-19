#!/usr/bin/env python3
"""PROBE 4 — can a correlation rule watch the tracker at all?

Three assumptions, in the order that matters:

  A. the trigger QUERY runs against a fixed dataset name, with no wildcard
  B. a correlation rule can be CREATED over that query (via API, or by hand in the console)
  C. writing a completed row makes the rule FIRE and raise an issue

A is testable from here. B and C may not be: every correlation-rule API path probed so far
returns HTTP 500, which is why this script also prints the exact query to paste into the
console if the API route is closed.

Nothing else in the design matters if A fails, so A is checked first and separately.

  python3 sim_correlation.py
"""
import json

from simlib import TRACKER, banner, client, verdict

# The trigger. One fixed dataset name. No wildcard anywhere.
TRIGGER_QUERY = f'''dataset = {TRACKER}
| filter event = "completed"
| fields scan_id, hostname, status, matches_dataset, scans_dataset, matches, event_ts_ms'''

# The abandoned arm: started with no completed. Correlation rules are much weaker at
# absence than at presence, which is why this may have to live in the sweep instead.
ABANDONED_QUERY = f'''dataset = {TRACKER}
| comp count() as events, values(event) as evs by scan_id, hostname, matches_dataset
| filter events = 1'''

RULE_PATHS = [
    "/public_api/v1/correlations/get_correlation_rules/",
    "/public_api/v1/correlations/insert_correlation_rule/",
    "/public_api/v1/correlation_rules/get/",
    "/public_api/v1/correlation_rules/insert/",
]


def main():
    banner("PROBE 4 — correlation rule over the tracker")
    ac = client()
    ok = True

    print("A. does the trigger query run against a FIXED dataset name?\n")
    print("   " + TRIGGER_QUERY.replace("\n", "\n   "))
    try:
        rows = ac.xql(TRIGGER_QUERY + " | limit 20", limit=20)
        n = len(rows) if rows else 0
        ok &= verdict(True, f"trigger query runs: {n} completed scan(s) visible")
        for r in (rows or [])[:3]:
            print(f"        {r.get('scan_id')}  {r.get('status')}  -> {r.get('matches_dataset')}")
    except Exception as e:
        ok &= verdict(False, f"trigger query FAILED: {str(e)[:200]}")

    print("\n   abandoned arm (started with no completed):")
    try:
        rows = ac.xql(ABANDONED_QUERY + " | limit 20", limit=20)
        n = len(rows) if rows else 0
        verdict(True, f"abandoned query runs: {n} scan(s) with only one event row")
    except Exception as e:
        verdict(False, f"abandoned query FAILED: {str(e)[:160]} "
                       f"— this arm may have to live in the reconciliation sweep")

    print("\nB. is there an API to create the rule?")
    reachable = False
    for p in RULE_PATHS:
        try:
            st, data = ac.call(p, {}, timeout=45) if hasattr(ac, "call") else (None, None)
        except Exception as e:
            print(f"   ERR  {p}: {str(e)[:90]}")
            continue
        note = str(data)[:90] if data else ""
        print(f"   {st}  {p}  {note}")
        if st and st < 500:
            reachable = True
    verdict(reachable, "a correlation-rule API path responded below 500"
            if reachable else
            "no correlation-rule API path is usable — the rule must be created BY HAND "
            "in the console using the query printed above")

    print("\nC. does the rule fire when a completed row lands?")
    print("   Not testable from here without B. To check by hand:")
    print("     1. create a correlation rule in the console with the query above")
    print("     2. run:  python3 sim_scan.py --host simfire --matches 3")
    print("     3. confirm an issue is raised carrying scan_id")
    print("\n   THE QUESTION THIS ANSWERS, and the one the whole design turns on:")
    print("   does a correlation rule accept a LOOKUP dataset as its source at all?")
    print("   Correlation rules are built for streaming/event data; lookups are state.")
    print("   If lookups cannot be a rule source, the tracker must instead be written to")
    print("   an INGESTED dataset rather than a lookup, and the design changes again.")

    print()
    print("PROBE 4 RESULT (part A only):", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
