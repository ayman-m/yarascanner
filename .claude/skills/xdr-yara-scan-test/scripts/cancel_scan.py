#!/usr/bin/env python3
"""Deliver a cooperative cancel to a running scan on an endpoint (mode=cancel).

Runs the scanner with mode=cancel on the target endpoint, which drops
<scanner_dir>/control/cancel.flag; the running scan's watcher picks it up and shuts
down gracefully (terminal 'cancelled' lifecycle row). Prints whether a scan looked
to be running at cancel time.

  python3 cancel_scan.py --hostname WINSERVER01
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
    ap.add_argument("--scanner", default=os.path.join(repo, "xdr_yara_scanner.py"))
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", default=os.path.join(repo, "local_test", "cancel_snippet.py"))
    args = ap.parse_args()

    env = load_env(find_env_file())
    snippet = bs.build(args.scanner, env, "", None, "low", "cancel", None, None)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(snippet)

    c = XDRClient()
    eid = c.endpoint_id(args.hostname)
    print(f"delivering cancel to {args.hostname} -> {eid}")
    reply = c.run_snippet(snippet, [eid], timeout_secs=args.timeout)
    if not isinstance(reply, dict) or "action_id" not in reply:
        sys.exit(f"cancel launch rejected: {reply}")
    action_id = reply["action_id"]
    gid = reply.get("group_action_id") or action_id
    c.wait_action(gid, poll_secs=4, max_polls=30)
    for _eid, out in c.endpoint_stdout(action_id).items():
        for line in str(out).splitlines():
            print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
