#!/usr/bin/env python3
"""Cortex XDR public-API client core for the YARA-scanner test skill.

Reads credentials from a .env file (XDR_API_ID, XDR_API_URL, XDR_API_KEY) or the
process environment. Defaults to Advanced (HMAC) auth — the modern Cortex key type —
and falls back to Standard if configured. Corporate-proxy TLS is handled by pointing
XDR_CA_BUNDLE / REQUESTS_CA_BUNDLE / SSL_CERT_FILE at a CA bundle (see make_ca_bundle.sh).

This module is import-safe and has no side effects.
"""
import hashlib
import json
import os
import time

import requests


def find_env_file(explicit=None):
    """Locate a .env file: explicit arg, $XDR_ENV_FILE, cwd, or repo root above skill."""
    for cand in (explicit, os.environ.get("XDR_ENV_FILE"),
                 os.path.join(os.getcwd(), ".env")):
        if cand and os.path.exists(cand):
            return cand
    # Walk up from this file looking for a .env (repo root).
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


def _verify():
    for var in ("XDR_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        p = os.environ.get(var)
        if p and os.path.exists(p):
            return p
    if os.environ.get("XDR_INSECURE") == "1":
        requests.packages.urllib3.disable_warnings()  # type: ignore
        return False
    return True


class XDRClient:
    def __init__(self, env=None, auth="advanced"):
        self.env = env or load_env()
        self.base = _base_url(self.env.get("XDR_API_URL"))
        self.api_key = self.env.get("XDR_API_KEY", "")
        self.api_id = self.env.get("XDR_API_ID", "")
        self.auth = auth
        self.verify = _verify()
        if not (self.base and self.api_key and self.api_id):
            raise RuntimeError("Missing XDR creds. Provide .env with XDR_API_ID/URL/KEY.")

    def _headers(self):
        if self.auth == "standard":
            return {"Authorization": self.api_key, "x-xdr-auth-id": str(self.api_id),
                    "Content-Type": "application/json"}
        nonce = os.urandom(32).hex()
        ts = str(int(time.time()) * 1000)
        sig = hashlib.sha256((self.api_key + nonce + ts).encode("utf-8")).hexdigest()
        return {"x-xdr-timestamp": ts, "x-xdr-nonce": nonce, "x-xdr-auth-id": str(self.api_id),
                "Authorization": sig, "Content-Type": "application/json"}

    def call(self, path, request_data=None, timeout=60):
        body = {"request_data": request_data if request_data is not None else {}}
        r = requests.post(self.base + path, headers=self._headers(), json=body,
                          timeout=timeout, verify=self.verify)
        try:
            data = r.json()
        except Exception:
            data = {"_raw": r.text}
        return r.status_code, data

    def reply(self, path, request_data=None, timeout=60):
        st, data = self.call(path, request_data, timeout)
        if st != 200:
            raise RuntimeError(f"{path} HTTP {st}: {json.dumps(data)[:500]}")
        return data.get("reply", data) if isinstance(data, dict) else data

    # ---- endpoints ----
    def find_endpoint(self, hostname):
        reply = self.reply("/public_api/v1/endpoints/get_endpoint/",
                           {"filters": [{"field": "hostname", "operator": "in", "value": [hostname]}]})
        return reply.get("endpoints", []) if isinstance(reply, dict) else []

    def endpoint_id(self, hostname):
        eps = self.find_endpoint(hostname)
        if not eps:
            raise RuntimeError(f"Endpoint '{hostname}' not found on tenant")
        return eps[0]["endpoint_id"]

    # ---- run code on endpoints ----
    def run_snippet(self, snippet_code, endpoint_ids, timeout_secs=600):
        return self.reply("/public_api/v1/scripts/run_snippet_code_script/", {
            "snippet_code": snippet_code,
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": list(endpoint_ids)}],
            "timeout": timeout_secs,
        })

    def run_script(self, script_uid, parameters_values, endpoint_ids, timeout_secs=600):
        return self.reply("/public_api/v1/scripts/run_script/", {
            "script_uid": script_uid,
            "parameters_values": parameters_values,
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": list(endpoint_ids)}],
            "timeout": timeout_secs,
        })

    def get_scripts(self):
        return self.reply("/public_api/v1/scripts/get_scripts/", {"filters": []})

    # ---- action status / results ----
    def action_status(self, group_action_id):
        return self.reply("/public_api/v1/actions/get_action_status/",
                          {"group_action_id": int(group_action_id)})

    def script_results(self, action_id):
        return self.reply("/public_api/v1/scripts/get_script_execution_results/",
                          {"action_id": int(action_id)})

    def wait_action(self, group_action_id, poll_secs=5, max_polls=60, on_poll=None):
        """Poll until every endpoint reaches a terminal state; return the status map."""
        terminal = {"COMPLETED_SUCCESSFULLY", "FAILED", "TIMEOUT", "CANCELED", "EXPIRED",
                    "COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"}
        statuses = {}
        for i in range(max_polls):
            st = self.action_status(group_action_id)
            statuses = st.get("data", st) if isinstance(st, dict) else st
            if on_poll:
                on_poll(i, statuses)
            vals = list(statuses.values()) if isinstance(statuses, dict) else []
            if vals and all(str(v).upper() in terminal for v in vals):
                break
            time.sleep(poll_secs)
        return statuses

    def endpoint_stdout(self, action_id):
        """Return {endpoint_id: standard_output} for a completed script action."""
        res = self.script_results(action_id)
        results = res.get("results", res) if isinstance(res, dict) else res
        out = {}
        if isinstance(results, list):
            for r in results:
                out[r.get("endpoint_id")] = (
                    r.get("standard_output") or r.get("command_output") or r.get("_return_value") or ""
                )
        return out

    # ---- XQL (dataset verification) ----
    def xql(self, query, poll_secs=3, max_polls=30, limit=100):
        """Run an XQL query, poll to completion, return the list of result rows."""
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
