#!/usr/bin/env python3
"""Verify scan data landed in the lookup datasets via XQL.

  python3 verify.py --hostname WINSERVER01
Shows recent matches and the scan lifecycle rows for the host, confirming tenant_id
is populated (the thing that silently failed under the old Standard-auth scanner).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xdr_lib import XDRClient  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostname", default="WINSERVER01")
    ap.add_argument("--limit", type=int, default=15)
    args = ap.parse_args()
    c = XDRClient()
    h = args.hostname.replace('"', '')

    print(f"=== yara_scanner_matches (host={h}) ===")
    rows = c.xql(
        f'dataset = yara_scanner_matches | filter hostname = "{h}" '
        f'| sort desc event_timestamp_ms '
        f'| fields tenant_id, rule, filename, string, severity, scan_id '
        f'| limit {args.limit}'
    )
    print(f"rows: {len(rows)}")
    for r in rows:
        print(f"  [{r.get('tenant_id')}] {r.get('rule'):32} {r.get('filename')}  ~ {r.get('string')}")

    print(f"\n=== yara_scanner_scans (host={h}) ===")
    rows = c.xql(
        f'dataset = yara_scanner_scans | filter hostname = "{h}" '
        f'| fields tenant_id, status, files_scanned, detections, elapsed_secs, '
        f'total_paused_secs, throttle_mode, posture, message, event_timestamp_ms '
        f'| sort desc event_timestamp_ms | limit {args.limit}'
    )
    print(f"rows: {len(rows)}")
    for r in rows:
        print(f"  [{r.get('tenant_id')}] {str(r.get('status')):10} files={r.get('files_scanned')} "
              f"det={r.get('detections')} paused={r.get('total_paused_secs')} "
              f"throttle={r.get('throttle_mode')} :: {r.get('message')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
