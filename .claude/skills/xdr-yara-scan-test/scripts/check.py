#!/usr/bin/env python3
"""Preflight: confirm creds/auth work and the target endpoint is reachable.

  python3 check.py --hostname WINSERVER01
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xdr_lib import XDRClient  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hostname", default="WINSERVER01")
    args = ap.parse_args()

    for auth in ("advanced", "standard"):
        try:
            c = XDRClient(auth=auth)
            c.get_scripts()  # cheap authenticated call; raises on 401
            print(f"AUTH OK ({auth})  tenant host: {c.base.split('//')[-1]}")
            break
        except Exception as e:
            print(f"auth {auth} failed: {str(e)[:120]}")
    else:
        return 2

    eps = c.find_endpoint(args.hostname)
    if not eps:
        print(f"endpoint '{args.hostname}' NOT FOUND")
        return 3
    ep = eps[0]
    print(f"endpoint {args.hostname}: id={ep.get('endpoint_id')} status={ep.get('endpoint_status')} "
          f"os={ep.get('operating_system') or ep.get('os_type')} agent={ep.get('endpoint_version')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
