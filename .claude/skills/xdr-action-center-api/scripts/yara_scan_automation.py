#!/usr/bin/env python3
"""End-to-end YARA scan automation over the Cortex XDR PUBLIC API.

One runnable example of the full lifecycle, suitable for cron/CI/SOAR:

    resolve endpoint -> deliver scan -> poll action -> print result
    -> read the endpoint's scan_summary JSON -> verify dataset rows via XQL
    (optionally: cancel mid-scan to demonstrate cooperative cancellation)

Public APIs used (see ../references/public-api-map.md for the map):
    endpoints/get_endpoint, scripts/run_snippet_code_script,
    actions/get_action_status, scripts/get_script_execution_results, XQL query.

Auth via env: XDR_API_URL / XDR_API_ID / XDR_API_KEY (Advanced or Standard key —
auto-detected). Optional: XDR_CA_BUNDLE for TLS-intercepting proxies.

Usage:
    python3 yara_scan_automation.py --hostname HOST01 --rules rules.yar \
        --scan-folder /tmp/target [--severity low] [--cancel-after 30]
"""
import argparse
import base64
import json
import os
import sys
import time

# The toolkit lives at the repo root (two levels up from this script).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
sys.path.insert(0, REPO_ROOT)
from xdr_action_center import XDRActionCenter  # noqa: E402

SUMMARY_PROBE = r"""
import os, glob, json, re
LOGDIRS = [r"C:\yara_scanner\logs", "/opt/yara_scanner/logs", "/usr/local/yara_scanner/logs"]
logs = next((d for d in LOGDIRS if os.path.isdir(d)), None)
if not logs:
    print("NO_LOGS_DIR"); raise SystemExit
rids = set()
for fn in os.listdir(logs):
    m = re.search(r"(\d{8}_\d{6}_\d{6})", fn)
    if m: rids.add(m.group(1))
summ = os.path.join(logs, "scan_summary_%s.json" % sorted(rids)[-1]) if rids else ""
print(json.dumps(json.load(open(summ)), indent=1) if summ and os.path.exists(summ)
      else "NO_SUMMARY_YET")
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hostname", required=True, help="target endpoint hostname (must be connected)")
    ap.add_argument("--rules", required=True, help="path to a .yar rules file")
    ap.add_argument("--scan-folder", default="default", help="path to scan, or 'default'")
    ap.add_argument("--severity", default="low", choices=("low", "medium", "high"))
    ap.add_argument("--scanner", default=os.path.join(REPO_ROOT, "xdr_yara_scanner.py"))
    ap.add_argument("--cancel-after", type=int, default=0,
                    help="seconds after which to deliver the cancel entry point (0 = don't)")
    ap.add_argument("--timeout", type=int, default=1800, help="max seconds to wait for the scan")
    args = ap.parse_args()

    c = XDRActionCenter()

    # 1) Resolve the endpoint (public API: endpoints/get_endpoint)
    eid = c.endpoint_id(args.hostname)
    print(f"[1/4] endpoint {args.hostname} -> {eid}")

    # 2) Deliver the scan (public API: scripts/run_snippet_code_script).
    #    run_scanner() embeds the scanner + base64 rules into a snippet, starts it, and
    #    polls actions/get_action_status -> get_script_execution_results to completion.
    rules_b64 = base64.b64encode(open(args.rules, "rb").read()).decode()
    print(f"[2/4] scan started (folder={args.scan_folder}, severity={args.severity})")

    if args.cancel_after > 0:
        # Demonstrate cooperative cancellation: start the scan without waiting, then
        # deliver the scanner's `cancel` entry point after the delay.
        import threading

        result_box = {}

        def _run():
            out, aid = c.run_scanner(eid, args.scanner, rules_b64, args.scan_folder,
                                     args.severity, "scan", "", timeout_secs=args.timeout,
                                     poll_secs=10, max_polls=max(6, args.timeout // 10))
            result_box["out"] = out

        th = threading.Thread(target=_run, daemon=True)
        th.start()
        time.sleep(args.cancel_after)
        print(f"      delivering cancel after {args.cancel_after}s...")
        c.run_scanner(eid, args.scanner, rules_b64, args.scan_folder,
                      args.severity, "cancel", "", timeout_secs=300, poll_secs=5, max_polls=60)
        th.join(timeout=args.timeout)
        out = result_box.get("out", {})
    else:
        out, _aid = c.run_scanner(eid, args.scanner, rules_b64, args.scan_folder,
                                  args.severity, "scan", "", timeout_secs=args.timeout,
                                  poll_secs=10, max_polls=max(6, args.timeout // 10))

    for _eid, text in (out or {}).items():
        tail = (text or "").strip().splitlines()
        print(f"      result: {tail[-1][:140] if tail else '(no output)'}")

    # 3) Pull the machine-readable scan summary from the endpoint (delivery accounting).
    res = c.run_snippet_wait(SUMMARY_PROBE, [eid], timeout_secs=120, poll_secs=5, max_polls=24)
    summary_text = next(iter(res[0].values()), "") if res and res[0] else ""
    print("[3/4] scan_summary (alert/dataset delivery books):")
    try:
        j = json.loads(summary_text)
        for k in ("outcome", "files_scanned", "matches", "alert_delivery",
                  "dataset_delivery", "matches_dataset"):
            if k in j:
                print(f"      {k} = {j[k]}")
    except Exception:
        print("      " + summary_text.strip()[:400])

    # 4) Verify rows landed, via XQL over the wildcard dataset (public API: XQL query).
    rows = c.xql(f'dataset = yara_scanner_scans* | filter hostname = "{args.hostname}" '
                 f'| sort desc event_timestamp_ms | limit 3')
    print(f"[4/4] latest lifecycle rows for {args.hostname}:")
    for r in rows or []:
        print(f"      {r.get('status', '?'):10s} run={r.get('run_id', '?')} "
              f"files={r.get('files_scanned', '?')}")


if __name__ == "__main__":
    main()
