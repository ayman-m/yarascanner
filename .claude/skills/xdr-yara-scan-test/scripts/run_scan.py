#!/usr/bin/env python3
"""Build the scanner snippet, run it on an endpoint via run_snippet_code_script,
poll to completion, and print the scan summary. End-to-end scan test.

Examples:
  # quick deterministic match test (seeds a small folder on the endpoint):
  python3 run_scan.py --hostname WINSERVER01 --seed-files 0
  # scan a real path with alerts disabled:
  python3 run_scan.py --hostname WINSERVER01 --scan-folder 'C:\\Users' --options create_alerts=false
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_snippet as bs          # noqa: E402
from xdr_lib import XDRClient, load_env, find_env_file  # noqa: E402


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", "..", "..", ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostname", default="WINSERVER01")
    ap.add_argument("--scan-folder", default="default")
    ap.add_argument("--severity", default="low")
    ap.add_argument("--options", default=None)
    ap.add_argument("--seed-files", type=int, default=0,
                    help="seed a temp folder with N benign files + guaranteed-match content")
    ap.add_argument("--rules", default=os.path.join(repo, "test_rules.yar"))
    ap.add_argument("--scanner", default=os.path.join(repo, "xdr_yara_scanner.py"))
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--poll-secs", type=int, default=6)
    ap.add_argument("--max-polls", type=int, default=60)
    ap.add_argument("--out", default=os.path.join(repo, "local_test", "scan_snippet.py"))
    args = ap.parse_args()

    env_path = find_env_file()
    env = load_env(env_path)
    import base64
    rules_b64 = base64.b64encode(open(args.rules, "rb").read()).decode("ascii")
    snippet = bs.build(args.scanner, env, rules_b64, args.scan_folder, args.severity,
                       "scan", args.options, args.seed_files)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(snippet)
    print(f"snippet: {args.out} ({len(snippet)} bytes)")

    c = XDRClient()
    eid = c.endpoint_id(args.hostname)
    print(f"target {args.hostname} -> {eid}")
    reply = c.run_snippet(snippet, [eid], timeout_secs=args.timeout)
    if not isinstance(reply, dict) or "action_id" not in reply:
        sys.exit(f"launch rejected: {reply}")
    action_id = reply["action_id"]
    gid = reply.get("group_action_id") or action_id
    print(f"action_id={action_id} endpoints={reply.get('endpoints_count')}")

    def _on_poll(i, statuses):
        print(f"  poll {i+1}: {statuses}")
    c.wait_action(gid, poll_secs=args.poll_secs, max_polls=args.max_polls, on_poll=_on_poll)

    print("\n=== endpoint output ===")
    for eid_, out in c.endpoint_stdout(action_id).items():
        for line in str(out).splitlines():
            print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
