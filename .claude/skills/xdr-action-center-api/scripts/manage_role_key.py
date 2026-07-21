#!/usr/bin/env python3
"""Create/delete a least-privilege custom role + API key for the YARA scanner, via the
Cortex XDR IAM Platform APIs. Every call here was verified live.

Requires an admin (Access-Management-privileged) key in the env — creating roles/keys is a
one-time setup action, NOT something the scanner does at runtime. The KEY SECRET is printed
ONCE at creation and never retrievable again; store it safely (never commit it).

Examples:
    # least-priv delivery role + a 90-day Advanced key (default components)
    python3 manage_role_key.py create --name yara-scanner-delivery --days 90

    # custom component set (machine keys from `list-perms`)
    python3 manage_role_key.py create --name my-role \
        --components external_alerts_action data_management_action --days 30

    python3 manage_role_key.py list-perms | grep -i "data management"
    python3 manage_role_key.py delete --name yara-scanner-delivery --key-id 42
"""
import argparse
import json
import os
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
sys.path.insert(0, REPO_ROOT)
import requests  # noqa: E402
from xdr_action_center import XDRActionCenter  # noqa: E402

# The verified least-privilege delivery components (see references/api-permissions.md).
DEFAULT_DELIVERY_COMPONENTS = ["external_alerts_action", "data_management_action"]


def _perm_index(c):
    """{machine_key: permission_entry} from the tenant's live permission catalog."""
    cfg = requests.get(c.base + "/platform/iam/v1/role/permission-config",
                       headers=c._headers(), timeout=30, verify=c.verify).json()["data"]
    idx = {}
    for cat in cfg.get("rbac_permissions", []):
        for sub in cat.get("sub_categories", []):
            for p in sub.get("permissions", []):
                p["_category"] = cat.get("category_name")
                for k in (p.get("view_name"), p.get("action_name")):
                    if k:
                        idx[k] = p
    return idx


def _closure(idx, keys):
    """Expand a component set to include every dependency the catalog requires."""
    resolved, frontier = set(), set(keys)
    while frontier:
        k = frontier.pop()
        if k in resolved:
            continue
        resolved.add(k)
        p = idx.get(k)
        if not p:
            continue
        level = "action" if k == p.get("action_name") else "view"
        for d in (p.get("permission_dependencies", {}) or {}).get(level, {}).get("dependencies", []):
            if d.get("name") and d["name"] not in resolved:
                frontier.add(d["name"])
    return sorted(resolved)


def cmd_list_perms(c, _args):
    idx = _perm_index(c)
    seen = set()
    for key, p in sorted(idx.items(), key=lambda kv: (kv[1].get("_category") or "", kv[1].get("name") or "")):
        name = p.get("name")
        if name in seen:
            continue
        seen.add(name)
        print(f"{p.get('_category',''):28s} | {name:34s} | view={p.get('view_name') or '-'} "
              f"action={p.get('action_name') or '-'}")


def cmd_create(c, args):
    idx = _perm_index(c)
    comps = _closure(idx, args.components)
    added = sorted(set(comps) - set(args.components))
    print(f"components: {args.components}" + (f"  (+dependencies {added})" if added else ""))

    r = requests.post(c.base + "/platform/iam/v1/role", headers=c._headers(), verify=c.verify, timeout=30,
                      json={"request_data": {"pretty_name": args.name,
                                             "description": args.description,
                                             "component_permissions": comps}})
    if r.status_code not in (200, 201):
        print(f"role create failed: HTTP {r.status_code}: {r.text[:300]}")
        sys.exit(1)
    print(f"role '{args.name}' created")

    expiration = int(time.time() * 1000) + args.days * 24 * 3600 * 1000  # epoch MILLIS (0 is rejected)
    rk = requests.post(c.base + "/public_api/v1/api_keys/generate", headers=c._headers(), verify=c.verify,
                       timeout=30, json={"request_data": {"roles": [args.name],  # pretty_name, NOT role_id
                                                          "security_level": args.security_level,
                                                          "expiration": expiration,
                                                          "comment": args.comment}})
    if r.status_code not in (200, 201) or "reply" not in rk.json():
        print(f"key generate failed: HTTP {rk.status_code}: {rk.text[:300]}")
        sys.exit(1)
    reply = rk.json()["reply"]
    print("\n=== API KEY CREATED (secret shown ONCE — store securely, do not commit) ===")
    print(f"  key id (x-xdr-auth-id): {reply.get('id')}")
    print(f"  api key secret        : {reply.get('key')}")
    print(f"  security level        : {args.security_level}")
    print(f"  expires               : {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(expiration/1000))}")
    print("\nSet these in the scanner's DEFAULT_XDR_API_KEY / _API_ID / _API_URL and upload.")


def cmd_delete(c, args):
    if args.key_id is not None:
        r = requests.post(c.base + "/public_api/v1/api_keys/delete", headers=c._headers(), verify=c.verify,
                          timeout=30, json={"request_data": {"filters": [
                              {"field": "id", "operator": "in", "value": [int(args.key_id)]}]}})
        print(f"delete key {args.key_id}: HTTP {r.status_code}")
    if args.name:
        roles = requests.get(c.base + "/platform/iam/v1/role", headers=c._headers(),
                             verify=c.verify, timeout=30).json()["data"]
        rid = next((x["role_id"] for x in roles if x.get("pretty_name") == args.name), None)
        if rid:
            r = requests.delete(c.base + f"/platform/iam/v1/role/{rid}", headers=c._headers(),
                                verify=c.verify, timeout=30)
            print(f"delete role {args.name} ({rid}): HTTP {r.status_code}")
        else:
            print(f"role {args.name} not found")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create", help="create a custom role + Advanced API key")
    p.add_argument("--name", required=True, help="role pretty name")
    p.add_argument("--components", nargs="+", default=DEFAULT_DELIVERY_COMPONENTS,
                   help="permission machine keys (default = verified delivery set)")
    p.add_argument("--description", default="Least-privilege YARA scanner role")
    p.add_argument("--comment", default="YARA scanner key")
    p.add_argument("--days", type=int, default=90, help="key lifetime in days")
    p.add_argument("--security-level", default="advanced", choices=("advanced", "standard"))

    p = sub.add_parser("delete", help="delete a key and/or role")
    p.add_argument("--name", help="role pretty name to delete")
    p.add_argument("--key-id", type=int, help="API key id to delete")

    sub.add_parser("list-perms", help="list the tenant's permission components + machine keys")

    args = ap.parse_args()
    c = XDRActionCenter()
    {"create": cmd_create, "delete": cmd_delete, "list-perms": cmd_list_perms}[args.cmd](c, args)


if __name__ == "__main__":
    main()
