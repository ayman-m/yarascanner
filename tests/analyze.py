#!/usr/bin/env python3
"""Analyze the matrix results + cross-check against XDR datasets, and compute performance.

Reads tests/results/matrix.jsonl (per-action ground truth), then queries XDR to confirm
match/scan data landed, and derives performance metrics (compile-time curve vs rule count,
throughput on big folders). Flags anomalies for the bug-fix pass.

Usage: python3 tests/analyze.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xdr_action_center import XDRActionCenter  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSONL = os.path.join(REPO, "tests", "results", "matrix.jsonl")

# expected matches per rule file against the seeded corpus (for anomaly detection).
# None = don't assert an exact count (platform-dependent / module rules).
RULE_COUNTS = {
    "01_single.yar": 1, "16_pack_100.yar": 100, "17_pack_250.yar": 250, "15_big_500.yar": 500,
    "19_many_strings.yar": 1, "20_no_match.yar": 2, "18_dup_names.yar": 3,
}


def load():
    rows = []
    with open(JSONL) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    rows = load()
    print(f"=== matrix results: {len(rows)} actions ===\n")
    by_outcome = {}
    anomalies = []
    for r in rows:
        by_outcome[r["outcome"]] = by_outcome.get(r["outcome"], 0) + 1
    print("outcomes:", by_outcome, "\n")

    # per-action table
    print(f"{'host':10} {'label':24} {'outcome':11} {'files':>6} {'match':>6} {'fail':>5} {'wall':>7} {'paused':>7}")
    for r in sorted(rows, key=lambda x: (x["host"], x["label"])):
        print(f"{r['host']:10} {r['label']:24} {r['outcome']:11} "
              f"{str(r.get('files')):>6} {str(r.get('matches')):>6} {str(r.get('failed_rules')):>5} "
              f"{str(r.get('wall_secs')):>7} {str(r.get('paused')):>7}")
        # anomaly checks
        if r["outcome"] in ("error", "snippet_error", "failed"):
            anomalies.append(f"{r['host']}/{r['label']}: outcome={r['outcome']} :: {r.get('raw','')[:200]}")
        if r["outcome"] == "completed" and r.get("matches") == 0 and r["label"].startswith("rules:") \
           and r["rules"] in ("01_single.yar", "18_dup_names.yar", "19_many_strings.yar"):
            anomalies.append(f"{r['host']}/{r['label']}: expected matches but got 0")

    # performance: compile-time curve (rule count -> wall) on the small corpus
    print("\n=== compile/scale perf (rule-count vs wall, corpus scans) ===")
    for host in sorted({r["host"] for r in rows}):
        pts = []
        for rf, n in [("01_single.yar", 1), ("16_pack_100.yar", 100),
                      ("17_pack_250.yar", 250), ("15_big_500.yar", 500)]:
            for r in rows:
                if r["host"] == host and r["label"] == f"rules:{rf}" and r.get("wall_secs"):
                    pts.append((n, r["wall_secs"]))
        print(f"  {host}: " + ", ".join(f"{n}rules={w}s" for n, w in sorted(pts)))

    # throughput on the big folder
    print("\n=== throughput (big-folder scans) ===")
    for r in rows:
        if r["label"] == "throughput:bigdir" and r.get("files") and r.get("wall_secs"):
            fps = round(r["files"] / r["wall_secs"], 1)
            print(f"  {r['host']}: {r['files']} files in {r['wall_secs']}s (~{fps} files/s wall incl. overhead), paused={r.get('paused')}s")

    # XDR cross-check
    print("\n=== XDR dataset cross-check ===")
    try:
        c = XDRActionCenter()
        for host in sorted({r["host"] for r in rows}):
            h = host.replace('"', '')
            mrows = c.xql(f'dataset = yara_scanner_matches | filter hostname = "{h}" | comp count() as n')
            srows = c.xql(f'dataset = yara_scanner_scans | filter hostname = "{h}" '
                          f'| comp count() as n by status')
            print(f"  {host}: match rows total={mrows[0].get('n') if mrows else 0}; "
                  f"scan rows by status={{" + ", ".join(f"{x.get('status')}:{x.get('n')}" for x in srows) + "}}")
        # top rules that fired across the fleet
        top = c.xql('dataset = yara_scanner_matches | comp count() as hits by rule | sort desc hits | limit 12')
        print("  top rules:", ", ".join(f"{x.get('rule')}={x.get('hits')}" for x in top))
    except Exception as e:
        print("  XDR cross-check error:", str(e)[:200])

    print("\n=== ANOMALIES ===")
    if anomalies:
        for a in anomalies:
            print("  ! " + a)
    else:
        print("  none")


if __name__ == "__main__":
    main()
