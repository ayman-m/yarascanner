#!/usr/bin/env python3
"""
xdr_action_center.py — one-file Cortex XDR Action Center automation toolkit.

A self-contained client (only `requests` required) for automating everything the
Cortex XDR public API exposes around Action Center + XQL, plus high-level helpers for
the YARA scanner in this repo. Usable as a CLI or imported as a library.

Authentication is auto-detected (Advanced HMAC or Standard). Credentials are read from
a .env file (XDR_API_ID / XDR_API_URL / XDR_API_KEY) or the process environment.
For corporate-proxy TLS, set XDR_CA_BUNDLE / REQUESTS_CA_BUNDLE / SSL_CERT_FILE to a
CA bundle (or XDR_INSECURE=1 to disable verification — diagnostics only).

CLI examples
------------
  python3 xdr_action_center.py endpoints [--hostname WINHOST01]
  python3 xdr_action_center.py scripts
  python3 xdr_action_center.py run-snippet  --hostname H --code-file probe.py
  python3 xdr_action_center.py run-scanner  --hostname H --rules rules.yar \
          --scan-folder default --severity low --options create_alerts=false
  python3 xdr_action_center.py cancel       --hostname H
  python3 xdr_action_center.py read-file    --hostname H --path /opt/yara_scanner/logs
  python3 xdr_action_center.py list-dir     --hostname H --path C:\\yara_scanner\\logs
  python3 xdr_action_center.py xql          --query 'dataset = yara_scanner_scans* | limit 5'
  python3 xdr_action_center.py verify       --hostname H
  python3 xdr_action_center.py prune-datasets [--delete-legacy] [--older-than 30] [--yes]
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import time

import requests

# YARA lookup-dataset naming (mirrors the scanner so the keep-set matches what it writes):
#   current  -> yara_scanner_(matches|scans)_v<VER>[_<shard>]
#   legacy   -> the shared yara_scanner_matches/_scans, old yara_matches_*, and any v1 shards
YARA_SCHEMA_VERSION = (os.environ.get("YARA_LOOKUP_SCHEMA_VER", "2").strip() or "2")
YARA_OWNED_RE = re.compile(r"^(yara_scanner_(matches|scans)(_.*)?|yara_(matches|scans)_.*)$")
CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans)_v%s(_.*)?$" % re.escape(YARA_SCHEMA_VERSION))

# ---------------------------------------------------------------------------
# Config / auth
# ---------------------------------------------------------------------------

def find_env_file(explicit=None):
    for cand in (explicit, os.environ.get("XDR_ENV_FILE"), os.path.join(os.getcwd(), ".env")):
        if cand and os.path.exists(cand):
            return cand
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        cand = os.path.join(here, ".env")
        if os.path.exists(cand):
            return cand
        here = os.path.dirname(here)
    return None


def load_env(path=None):
    env = {}
    path = find_env_file(path)
    if path:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("XDR_API_ID", "XDR_API_URL", "XDR_API_KEY"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def _base_url(raw):
    raw = (raw or "").strip().rstrip("/")
    if "/public_api" in raw:
        raw = raw[: raw.index("/public_api")]
    return raw


def _verify_target():
    for var in ("XDR_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        p = os.environ.get(var)
        if p and os.path.exists(p):
            return p
    if os.environ.get("XDR_INSECURE") == "1":
        requests.packages.urllib3.disable_warnings()  # type: ignore
        return False
    return True


TERMINAL_STATES = {"COMPLETED_SUCCESSFULLY", "FAILED", "TIMEOUT", "CANCELED", "EXPIRED",
                   "COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"}


class XDRActionCenter:
    """Cortex XDR public-API client with Action Center + XQL + scanner helpers."""

    def __init__(self, env=None, auth="auto", verbose=False):
        self.env = env or load_env()
        self.base = _base_url(self.env.get("XDR_API_URL"))
        self.api_key = self.env.get("XDR_API_KEY", "")
        self.api_id = self.env.get("XDR_API_ID", "")
        self.verify = _verify_target()
        self.verbose = verbose
        self._auth = auth              # 'auto' | 'advanced' | 'standard'
        self._resolved_auth = None if auth == "auto" else auth
        if not (self.base and self.api_key and self.api_id):
            raise RuntimeError("Missing XDR creds — provide .env with XDR_API_ID/URL/KEY.")

    # ---- auth ----
    def _advanced_headers(self):
        nonce = os.urandom(32).hex()
        ts = str(int(time.time() * 1000))
        sig = hashlib.sha256((self.api_key + nonce + ts).encode()).hexdigest()
        return {"x-xdr-timestamp": ts, "x-xdr-nonce": nonce, "x-xdr-auth-id": str(self.api_id),
                "Authorization": sig, "Content-Type": "application/json"}

    def _standard_headers(self):
        return {"Authorization": self.api_key, "x-xdr-auth-id": str(self.api_id),
                "Content-Type": "application/json"}

    def _headers(self):
        atype = self._resolved_auth or self._detect_auth()
        return self._advanced_headers() if atype == "advanced" else self._standard_headers()

    def _detect_auth(self):
        if self._resolved_auth:
            return self._resolved_auth
        url = self.base + "/public_api/v1/xql/get_datasets/"
        for atype in ("advanced", "standard"):
            hdr = self._advanced_headers() if atype == "advanced" else self._standard_headers()
            try:
                r = requests.post(url, headers=hdr, json={"request": {}}, timeout=30, verify=self.verify)
                if 200 <= r.status_code < 300:
                    self._resolved_auth = atype
                    if self.verbose:
                        print(f"[auth] detected: {atype}", file=sys.stderr)
                    return atype
            except Exception:
                pass
        self._resolved_auth = "advanced"
        return self._resolved_auth

    # ---- raw call ----
    def call(self, path, request_data=None, timeout=60, wrap="request_data"):
        body = {wrap: request_data if request_data is not None else {}}
        r = requests.post(self.base + path, headers=self._headers(), json=body,
                          timeout=timeout, verify=self.verify)
        try:
            data = r.json()
        except Exception:
            data = {"_raw": r.text}
        return r.status_code, data

    def reply(self, path, request_data=None, timeout=60, wrap="request_data"):
        st, data = self.call(path, request_data, timeout, wrap)
        if st != 200:
            raise RuntimeError(f"{path} HTTP {st}: {json.dumps(data)[:600]}")
        return data.get("reply", data) if isinstance(data, dict) else data

    # ---- endpoints ----
    def get_endpoints(self, filters=None):
        return self.reply("/public_api/v1/endpoints/get_endpoint/", {"filters": filters or []})

    def find_endpoint(self, hostname):
        r = self.get_endpoints([{"field": "hostname", "operator": "in", "value": [hostname]}])
        return r.get("endpoints", []) if isinstance(r, dict) else []

    def endpoint_id(self, hostname):
        eps = self.find_endpoint(hostname)
        if not eps:
            raise RuntimeError(f"endpoint '{hostname}' not found")
        return eps[0]["endpoint_id"]

    # ---- scripts library ----
    def get_scripts(self):
        return self.reply("/public_api/v1/scripts/get_scripts/", {"filters": []})

    def get_script_metadata(self, uid):
        return self.reply("/public_api/v1/scripts/get_script_metadata/", {"script_uid": uid})

    def get_script_code(self, uid):
        return self.reply("/public_api/v1/scripts/get_script_code/", {"script_uid": uid})

    # ---- run code / scripts ----
    def run_snippet(self, snippet_code, endpoint_ids, timeout_secs=600):
        return self.reply("/public_api/v1/scripts/run_snippet_code_script/", {
            "snippet_code": snippet_code,
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": list(endpoint_ids)}],
            "timeout": timeout_secs})

    def run_script(self, script_uid, parameters_values, endpoint_ids, timeout_secs=600):
        return self.reply("/public_api/v1/scripts/run_script/", {
            "script_uid": script_uid, "parameters_values": parameters_values,
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": list(endpoint_ids)}],
            "timeout": timeout_secs})

    # ---- action status / results ----
    def action_status(self, group_action_id):
        return self.reply("/public_api/v1/actions/get_action_status/",
                          {"group_action_id": int(group_action_id)})

    def script_exec_results(self, action_id):
        return self.reply("/public_api/v1/scripts/get_script_execution_results/",
                          {"action_id": int(action_id)})

    def wait_action(self, group_action_id, poll_secs=5, max_polls=120, on_poll=None):
        statuses = {}
        for i in range(max_polls):
            st = self.action_status(group_action_id)
            statuses = st.get("data", st) if isinstance(st, dict) else st
            if on_poll:
                on_poll(i, statuses)
            vals = list(statuses.values()) if isinstance(statuses, dict) else []
            if vals and all(str(v).upper() in TERMINAL_STATES for v in vals):
                break
            time.sleep(poll_secs)
        return statuses

    def endpoint_stdout(self, action_id):
        res = self.script_exec_results(action_id)
        results = res.get("results", res) if isinstance(res, dict) else res
        out = {}
        if isinstance(results, list):
            for r in results:
                out[r.get("endpoint_id")] = (r.get("standard_output")
                                             or r.get("command_output")
                                             or r.get("_return_value") or "")
        return out

    def run_snippet_wait(self, code, endpoint_ids, timeout_secs=600, poll_secs=5, max_polls=120,
                         on_poll=None):
        """Launch a snippet, wait for completion, return {endpoint_id: stdout} and action_id."""
        reply = self.run_snippet(code, endpoint_ids, timeout_secs)
        if not isinstance(reply, dict) or "action_id" not in reply:
            raise RuntimeError(f"snippet launch rejected: {reply}")
        aid = reply["action_id"]
        gid = reply.get("group_action_id") or aid
        self.wait_action(gid, poll_secs=poll_secs, max_polls=max_polls, on_poll=on_poll)
        return self.endpoint_stdout(aid), aid

    # ---- endpoint file operations (via snippet; agent Python runs as SYSTEM/root) ----
    def read_file(self, endpoint_id, path, max_bytes=2_000_000):
        code = (
            "import base64\n"
            f"p = r'''{path}'''\n"
            "try:\n"
            f"    d = open(p,'rb').read({max_bytes})\n"
            "    print('FILE_B64:' + base64.b64encode(d).decode())\n"
            "except Exception as e:\n"
            "    print('FILE_ERR:' + str(e))\n")
        out, _ = self.run_snippet_wait(code, [endpoint_id], timeout_secs=120)
        s = out.get(endpoint_id, "")
        for line in s.splitlines():
            if line.startswith("FILE_B64:"):
                return base64.b64decode(line[9:])
            if line.startswith("FILE_ERR:"):
                raise RuntimeError("read_file: " + line[9:])
        return b""

    def list_dir(self, endpoint_id, path, walk=False):
        code = (
            "import os, json\n"
            f"p = r'''{path}'''\n"
            "out = []\n"
            "try:\n"
            + ("    for root, dirs, files in os.walk(p):\n"
               "        for f in files:\n"
               "            fp = os.path.join(root, f)\n"
               "            try: out.append([fp, os.path.getsize(fp)])\n"
               "            except Exception: out.append([fp, -1])\n" if walk else
               "    for name in sorted(os.listdir(p)):\n"
               "        fp = os.path.join(p, name)\n"
               "        try: out.append([name, os.path.getsize(fp) if os.path.isfile(fp) else 'DIR'])\n"
               "        except Exception: out.append([name, '?'])\n")
            + "    print('DIR_JSON:' + json.dumps(out))\n"
            "except Exception as e:\n"
            "    print('DIR_ERR:' + str(e))\n")
        out, _ = self.run_snippet_wait(code, [endpoint_id], timeout_secs=120)
        s = out.get(endpoint_id, "")
        for line in s.splitlines():
            if line.startswith("DIR_JSON:"):
                return json.loads(line[9:])
            if line.startswith("DIR_ERR:"):
                raise RuntimeError("list_dir: " + line[8:])
        return []

    def write_file(self, endpoint_id, path, data):
        if isinstance(data, str):
            data = data.encode()
        b64 = base64.b64encode(data).decode()
        code = (
            "import base64, os\n"
            f"p = r'''{path}'''\n"
            f"b = base64.b64decode('''{b64}''')\n"
            "try:\n"
            "    d = os.path.dirname(p)\n"
            "    if d: os.makedirs(d, exist_ok=True)\n"
            "    open(p,'wb').write(b)\n"
            "    print('WRITE_OK:' + str(len(b)))\n"
            "except Exception as e:\n"
            "    print('WRITE_ERR:' + str(e))\n")
        out, _ = self.run_snippet_wait(code, [endpoint_id], timeout_secs=120)
        return out.get(endpoint_id, "")

    # ---- XQL ----
    def xql(self, query, poll_secs=3, max_polls=40, limit=1000):
        qid = self.reply("/public_api/v1/xql/start_xql_query/", {"query": query})
        if isinstance(qid, dict):
            qid = qid.get("query_id") or qid.get("reply") or qid
        for _ in range(max_polls):
            st, data = self.call("/public_api/v1/xql/get_query_results/",
                                 {"query_id": qid, "pending_flag": True, "limit": limit, "format": "json"})
            reply = data.get("reply", data) if isinstance(data, dict) else data
            status = reply.get("status") if isinstance(reply, dict) else None
            if status and status != "PENDING":
                if status != "SUCCESS":
                    raise RuntimeError(f"XQL {status}: {json.dumps(reply)[:400]}")
                results = reply.get("results", {})
                rows = results.get("data", results) if isinstance(results, dict) else results
                return rows if isinstance(rows, list) else []
            time.sleep(poll_secs)
        raise RuntimeError("XQL timed out")

    # ---- datasets ----
    def get_datasets(self):
        return self.reply("/public_api/v1/xql/get_datasets/", {}, wrap="request")

    def delete_dataset(self, dataset_name, force=False):
        """Delete an entire dataset (schema + all rows). NOTE the v2 path. force=True is only
        needed to delete a dataset that has dependencies (correlation rules / scheduled queries)."""
        return self.reply("/public_api/v2/xql/delete_dataset/",
                          {"dataset_name": dataset_name, "force": bool(force)}, wrap="request")

    def remove_lookup_data(self, dataset_name, filters):
        """Remove rows matching filter blocks (OR across blocks, AND within a block; EXACT values
        only). NOT concurrency-safe — the caller must serialize. Returns {'deleted': N}."""
        return self.reply("/public_api/v1/xql/lookups/remove_data/",
                          {"dataset_name": dataset_name, "filters": filters}, wrap="request", timeout=200)

    def dataset_scan_dates(self, dataset_name):
        if not YARA_OWNED_RE.match(dataset_name):  # guard the XQL interpolation
            raise ValueError(f"refusing non-yara dataset in XQL: {dataset_name}")
        rows = self.xql(f"dataset = {dataset_name} | fields scan_date | "
                        f"comp count() as n by scan_date | sort asc scan_date", limit=1000)
        return [(r.get("scan_date"), r.get("n")) for r in rows if r.get("scan_date")]

    def classify_yara_datasets(self):
        """Split the tenant's yara-owned LOOKUP datasets into (current, legacy, newer) by schema
        version. legacy = older/unversioned (safe to prune); newer = a HIGHER _vN than we assume,
        which signals this host's YARA_LOOKUP_SCHEMA_VER is stale — so it must NOT be pruned."""
        cur_ver = int(YARA_SCHEMA_VERSION) if YARA_SCHEMA_VERSION.isdigit() else None
        ver_re = re.compile(r"_v(\d+)(?:_|$)")
        current, legacy, newer = [], [], []
        datasets = self.get_datasets()
        if isinstance(datasets, dict):  # get_datasets can return {"data":[...]} / {"datasets":[...]}
            datasets = datasets.get("data") or datasets.get("datasets") or []
        for d in (datasets or []):
            if not isinstance(d, dict):
                continue
            name = d.get("Dataset Name") or d.get("dataset_name") or ""
            dtype = (d.get("Type") or d.get("dataset_type") or "").upper()
            if dtype != "LOOKUP" or not YARA_OWNED_RE.match(name):
                continue
            if CURRENT_RE.match(name):
                current.append(name)
                continue
            m = ver_re.search(name)
            v = int(m.group(1)) if m else None
            if cur_ver is not None and v is not None and v > cur_ver:
                newer.append(name)  # a version we don't recognize as old — refuse to prune
            else:
                legacy.append(name)
        return sorted(current), sorted(legacy), sorted(newer)

    # ---- YARA scanner helpers ----
    def build_scanner_snippet(self, scanner_path, rules_b64, scan_folder="default",
                              severity="low", mode="scan", options=None, prelude=""):
        """Wrap xdr_yara_scanner.py into a runnable snippet (creds injected from env)."""
        src = open(scanner_path, "r", encoding="utf-8").read()
        src = src.replace('DEFAULT_XDR_API_KEY = "replace_with_xdr_standard_api_key"',
                          f'DEFAULT_XDR_API_KEY = {self.api_key!r}')
        src = src.replace('DEFAULT_XDR_API_ID = "replace_with_xdr_standard_api_id"',
                          f'DEFAULT_XDR_API_ID = {str(self.api_id)!r}')
        src = src.replace('DEFAULT_XDR_API_URL = "replace_with_xdr_standard_api_url"',
                          f'DEFAULT_XDR_API_URL = {self.base!r}')
        src = src.replace('if __name__ == "__main__":', 'if False:  # snippet-neutralized')
        opts = repr(options) if options else "None"
        rules = repr(rules_b64 or "")
        footer = (
            "\n\n# ---- snippet footer ----\n"
            "import traceback as _tb\n"
            f"{prelude}\n"
            "try:\n"
            f"    print('SCAN_RESULT: ' + str(run({rules}, {scan_folder!r}, {severity!r}, "
            f"mode={mode!r}, options={opts})))\n"
            "except Exception:\n"
            "    print('SNIPPET_ERROR:\\n' + _tb.format_exc())\n")
        return src + footer

    def run_scanner(self, endpoint_id, scanner_path, rules_b64, scan_folder="default",
                    severity="low", mode="scan", options=None, prelude="",
                    timeout_secs=1800, poll_secs=6, max_polls=200, on_poll=None):
        code = self.build_scanner_snippet(scanner_path, rules_b64, scan_folder, severity,
                                          mode, options, prelude)
        return self.run_snippet_wait(code, [endpoint_id], timeout_secs=timeout_secs,
                                     poll_secs=poll_secs, max_polls=max_polls, on_poll=on_poll)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _repo_root():
    return os.path.dirname(os.path.abspath(__file__))


def _print(obj):
    print(json.dumps(obj, indent=2, default=str) if not isinstance(obj, str) else obj)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cortex XDR Action Center automation toolkit")
    ap.add_argument("--auth", default="auto", choices=["auto", "advanced", "standard"])
    ap.add_argument("--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("endpoints", help="list/find endpoints")
    p.add_argument("--hostname")

    sub.add_parser("scripts", help="list library scripts")

    p = sub.add_parser("run-snippet", help="run inline Python on an endpoint")
    p.add_argument("--hostname", required=True)
    p.add_argument("--code"); p.add_argument("--code-file")
    p.add_argument("--timeout", type=int, default=600)

    p = sub.add_parser("run-scanner", help="run the YARA scanner on an endpoint")
    p.add_argument("--hostname", required=True)
    p.add_argument("--rules", help=".yar file (base64-encoded automatically)")
    p.add_argument("--scan-folder", default="default")
    p.add_argument("--severity", default="low")
    p.add_argument("--mode", default="scan")
    p.add_argument("--options")
    p.add_argument("--scanner", default=os.path.join(_repo_root(), "xdr_yara_scanner.py"))
    p.add_argument("--timeout", type=int, default=1800)

    p = sub.add_parser("cancel", help="deliver mode=cancel to an endpoint")
    p.add_argument("--hostname", required=True)
    p.add_argument("--scanner", default=os.path.join(_repo_root(), "xdr_yara_scanner.py"))

    p = sub.add_parser("read-file", help="read a file from an endpoint")
    p.add_argument("--hostname", required=True); p.add_argument("--path", required=True)

    p = sub.add_parser("list-dir", help="list a directory on an endpoint")
    p.add_argument("--hostname", required=True); p.add_argument("--path", required=True)
    p.add_argument("--walk", action="store_true")

    p = sub.add_parser("write-file", help="write a file to an endpoint")
    p.add_argument("--hostname", required=True); p.add_argument("--path", required=True)
    p.add_argument("--content"); p.add_argument("--content-file")

    p = sub.add_parser("xql", help="run an XQL query")
    p.add_argument("--query", required=True); p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("verify", help="show matches + scan rows for a host")
    p.add_argument("--hostname", required=True); p.add_argument("--limit", type=int, default=15)

    sub.add_parser("datasets", help="list datasets")

    p = sub.add_parser("prune-datasets", help="report/clean up legacy or old YARA lookup datasets")
    p.add_argument("--delete-legacy", action="store_true",
                   help="delete every legacy (non-v%s) yara lookup dataset" % YARA_SCHEMA_VERSION)
    p.add_argument("--older-than", type=int, help="prune rows older than N days from CURRENT datasets")
    p.add_argument("--name", action="append", default=[], help="explicit dataset to delete (repeatable)")
    p.add_argument("--force", action="store_true", help="delete_dataset force=true (datasets with dependencies)")
    p.add_argument("--counts", action="store_true", help="include XQL row counts in the report")
    p.add_argument("--sleep", type=float, default=11.0, help="seconds between remove_data calls")
    p.add_argument("--yes", action="store_true", help="actually mutate (otherwise dry-run)")

    args = ap.parse_args(argv)
    c = XDRActionCenter(auth=args.auth, verbose=args.verbose)

    if args.cmd == "endpoints":
        eps = c.find_endpoint(args.hostname) if args.hostname else c.get_endpoints().get("endpoints", [])
        for e in eps:
            print(f"{e.get('endpoint_name'):20} {e.get('endpoint_id')} {e.get('endpoint_status'):10} "
                  f"{e.get('os_type')} {e.get('operating_system') or e.get('os_version')}")
        return 0

    if args.cmd == "scripts":
        for s in c.get_scripts().get("scripts", []):
            print(f"{s.get('script_id'):>4} {s.get('name'):40} {s.get('script_uid')}")
        return 0

    if args.cmd == "run-snippet":
        code = args.code or open(args.code_file).read()
        eid = c.endpoint_id(args.hostname)
        out, aid = c.run_snippet_wait(code, [eid], timeout_secs=args.timeout,
                                      on_poll=lambda i, s: print(f"  poll {i+1}: {s}", file=sys.stderr))
        print(f"action_id={aid}")
        for _e, o in out.items():
            print(o)
        return 0

    if args.cmd == "run-scanner":
        rules_b64 = ""
        if args.rules:
            rules_b64 = base64.b64encode(open(args.rules, "rb").read()).decode()
        eid = c.endpoint_id(args.hostname)
        out, aid = c.run_scanner(eid, args.scanner, rules_b64, args.scan_folder, args.severity,
                                 args.mode, args.options, timeout_secs=args.timeout,
                                 on_poll=lambda i, s: print(f"  poll {i+1}: {s}", file=sys.stderr))
        print(f"action_id={aid}")
        for _e, o in out.items():
            print(o)
        return 0

    if args.cmd == "cancel":
        eid = c.endpoint_id(args.hostname)
        out, aid = c.run_scanner(eid, args.scanner, "", "default", "low", "cancel", None,
                                 timeout_secs=180)
        for _e, o in out.items():
            print(o)
        return 0

    if args.cmd == "read-file":
        data = c.read_file(c.endpoint_id(args.hostname), args.path)
        sys.stdout.buffer.write(data)
        return 0

    if args.cmd == "list-dir":
        for row in c.list_dir(c.endpoint_id(args.hostname), args.path, walk=args.walk):
            print(f"{row[1]:>12}  {row[0]}")
        return 0

    if args.cmd == "write-file":
        content = args.content if args.content is not None else open(args.content_file, "rb").read()
        print(c.write_file(c.endpoint_id(args.hostname), args.path, content))
        return 0

    if args.cmd == "xql":
        rows = c.xql(args.query, limit=args.limit)
        print(f"rows: {len(rows)}")
        for r in rows[: args.limit]:
            print("  " + json.dumps(r, default=str))
        return 0

    if args.cmd == "verify":
        h = args.hostname.replace('"', '')
        m = c.xql(f'dataset = yara_scanner_matches* | filter hostname = "{h}" '
                  f'| sort desc event_timestamp_ms '
                  f'| fields tenant_id, rule, filename, string, severity | limit {args.limit}')
        print(f"=== matches ({len(m)}) ===")
        for r in m:
            print(f"  [{r.get('tenant_id')}] {r.get('rule'):28} {r.get('filename')} ~ {r.get('string')}")
        s = c.xql(f'dataset = yara_scanner_scans* | filter hostname = "{h}" '
                  f'| fields status, files_scanned, detections, elapsed_secs, total_paused_secs, '
                  f'throttle_mode, message, event_timestamp_ms | sort desc event_timestamp_ms | limit {args.limit}')
        print(f"=== scans ({len(s)}) ===")
        for r in s:
            print(f"  {str(r.get('status')):10} files={r.get('files_scanned')} det={r.get('detections')} "
                  f"elapsed={r.get('elapsed_secs')}s paused={r.get('total_paused_secs')}s "
                  f"throttle={r.get('throttle_mode')} :: {r.get('message')}")
        return 0

    if args.cmd == "datasets":
        _print(c.get_datasets())
        return 0

    if args.cmd == "prune-datasets":
        current, legacy, newer = c.classify_yara_datasets()

        def _rows(n):
            if not args.counts:
                return ""
            try:
                r = c.xql(f"dataset = {n} | comp count() as n", limit=1)
                return f"  rows={r[0].get('n', 0) if r else 0}"
            except Exception:
                return "  rows=?"

        print(f"CURRENT (keep, v{YARA_SCHEMA_VERSION}): {len(current)}")
        for n in current:
            print(f"  KEEP    {n}{_rows(n)}")
        if newer:
            print(f"NEWER (keep — higher schema version than v{YARA_SCHEMA_VERSION}; your "
                  f"YARA_LOOKUP_SCHEMA_VER may be stale): {len(newer)}")
            for n in newer:
                print(f"  NEWER   {n}{_rows(n)}")
        print(f"LEGACY (prune candidates): {len(legacy)}")
        for n in legacy:
            print(f"  LEGACY  {n}{_rows(n)}")

        if not (args.delete_legacy or args.older_than or args.name):
            return 0  # pure report

        # keep-guard: never delete a CURRENT or NEWER dataset unless it was explicitly named.
        if args.name:
            bad = [n for n in args.name if not YARA_OWNED_RE.match(n)]
            if bad:
                print(f"refusing non-yara dataset(s): {bad}", file=sys.stderr)
                return 2
            delete_targets = list(args.name)
        elif args.delete_legacy:
            # Refuse blanket legacy deletion when NEWER-version datasets exist — that is a reliable
            # signal this host's YARA_LOOKUP_SCHEMA_VER is out of date and "legacy" is untrustworthy.
            if newer:
                print(f"REFUSING --delete-legacy: found {len(newer)} dataset(s) at a NEWER schema "
                      f"version than v{YARA_SCHEMA_VERSION}. Set YARA_LOOKUP_SCHEMA_VER to match the "
                      f"scanner, or delete specific datasets with --name.", file=sys.stderr)
                return 2
            delete_targets = list(legacy)
        else:
            delete_targets = []
        _protected = set(current) | set(newer)
        delete_targets = [n for n in delete_targets if n not in _protected or n in args.name]

        if not args.yes:
            print(f"\nDRY RUN — would delete {len(delete_targets)} dataset(s): {delete_targets}")
            if args.older_than:
                print(f"DRY RUN — would prune rows older than {args.older_than}d from {len(current)} current dataset(s)")
            print("Re-run with --yes to execute.")
            return 0

        deleted, failed, pruned_rows = [], [], 0
        for n in delete_targets:
            try:
                c.delete_dataset(n, force=args.force)
                deleted.append(n)
                print(f"deleted {n}")
            except Exception as e:
                failed.append((n, str(e)[:200]))
                print(f"FAILED  {n}: {e}", file=sys.stderr)

        if args.older_than:
            cutoff = (datetime.date.today() - datetime.timedelta(days=args.older_than)).strftime("%Y%m%d")
            for n in current:
                for sd, _cnt in c.dataset_scan_dates(n):
                    if sd < cutoff:  # YYYYMMDD sorts lexicographically
                        res = c.remove_lookup_data(n, [{"scan_date": sd}])  # one block per call (all-or-nothing gotcha)
                        got = res.get("deleted", 0) if isinstance(res, dict) else 0
                        pruned_rows += got
                        print(f"pruned {n} scan_date={sd}: deleted={got}")
                        time.sleep(args.sleep)  # endpoint is not concurrency-safe

        print(f"\nSUMMARY: deleted={len(deleted)} failed={len(failed)} pruned_rows={pruned_rows}")
        for n, e in failed:
            print(f"  FAIL {n}: {e}")
        return 1 if failed else 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
