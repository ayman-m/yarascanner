"""YaraScanVerify - did the wave we just dispatched actually start?

Bounded confirmation, NOT a wait for completion. A full scan runs 24-29 minutes plus upload
drain; this answers a much cheaper question in a few minutes: are the scanners running?

MEASURED, and it decides the design (launch 10:36:44 UTC, three hosts):
    initiated row      +17s / +19s / +20s     <- the signal
    match rows landing ~+136s                 <- soft evidence only
    first running row  +619s / +620s          <- 10.3 minutes

The heartbeat CANNOT be the health signal. SCANS_HEARTBEAT_SECS is 600, so the first one
lands at roughly double a five-minute budget; a gate waiting for it either false-alarms on
every wave or is no longer short. `initiated` is fast and reliable, so it is the signal.

Match rows are POSITIVE EVIDENCE ONLY. Presence proves the whole path - scanner started,
rules compiled, uploader delivered, dataset writable. Absence proves nothing: a clean host
legitimately has none. Never fail a host for having no matches.

Every query is bounded on event_timestamp_ms > dispatch_ms. Without that bound a host scanned
yesterday reads as healthy today and the wave reports ok having started nothing.

A query that FAILS returns verdict "unknown", never "wave_dead" - XQL hiccuping is not
evidence a scan failed, and paging an analyst about a healthy wave trains them to ignore it.
"""

# ############################################################################
# #  CONFIGURATION - the only values in this file you need to edit.          #
# ############################################################################
# Cortex XDR API credentials, security level ADVANCED
# (Settings > Configurations > API Keys). Fill all three in before uploading this
# script; until the URL is replaced every run fails immediately and does nothing.
DEFAULT_XDR_API_KEY = "replace_with_xdr_advanced_api_key"   # the API key secret
DEFAULT_XDR_API_ID = "replace_with_xdr_advanced_api_id"     # that key's numeric ID
# Tenant API base URL, https://api-<tenant>.xdr.<region>.paloaltonetworks.com
DEFAULT_XDR_API_URL = "replace_with_xdr_api_url"

# Merge gates. Each is also overridable per run from the matching script argument.
DEFAULT_QUIET_SECS = 900            # a finished scan's newest row must be older than this
DEFAULT_ROW_CEILING = 2_000_000     # a scan bigger than this is reported, never half-merged
DEFAULT_ABANDONED_SECS = 24 * 3600  # a non-terminal scan silent this long counts as finished

# Lookup schema version assumed when the schema_version argument is left empty.
# Must match the scanner's YARA_LOOKUP_SCHEMA_VER on the endpoints.
DEFAULT_LOOKUP_SCHEMA_VERSION = "4"
# ############################################################################

# ============================================================================
# INLINED LIBRARY - carried in-file so this automation imports nothing.
# Configure it from the CONFIGURATION block above, not from in here.
# ============================================================================
import json
import re
import time

DEFAULT_LOOKUP_SCHEMA_VERSION = "4"


class CoreApiClient:
    """XQL queries and lookup-dataset writes against this tenant's public API."""

    def __init__(self, poll_secs=3, max_polls=60):
        self.poll_secs = poll_secs
        self.max_polls = max_polls
        self.base = DEFAULT_XDR_API_URL.rstrip("/")
        if "/public_api" in self.base:
            self.base = self.base[:self.base.index("/public_api")]
        if self.base.startswith("replace_with"):
            raise RuntimeError("XDR API credentials are not set - fill in the "
                               "CONFIGURATION block at the top of this script and re-upload.")

    def _headers(self):
        import hashlib
        import os
        nonce = os.urandom(32).hex()
        ts = str(int(time.time() * 1000))
        sig = hashlib.sha256((DEFAULT_XDR_API_KEY + nonce + ts).encode()).hexdigest()
        return {"x-xdr-timestamp": ts, "x-xdr-nonce": nonce,
                "x-xdr-auth-id": str(DEFAULT_XDR_API_ID), "Authorization": sig,
                "Content-Type": "application/json"}

    def _post(self, uri, body, timeout=90):
        import requests
        r = requests.post(self.base + uri, headers=self._headers(), json=body, timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = {"_raw": r.text}
        if r.status_code != 200:
            raise RuntimeError("%s HTTP %d: %s" % (uri, r.status_code, json.dumps(data)[:400]))
        return data

    def xql(self, query, limit=1000):
        started = self._post("/public_api/v1/xql/start_xql_query/", {"request_data": {"query": query}})
        qid = started.get("reply", started) if isinstance(started, dict) else started
        if isinstance(qid, dict):
            qid = qid.get("query_id") or qid.get("reply") or qid
        for _ in range(self.max_polls):
            data = self._post("/public_api/v1/xql/get_query_results/",
                              {"request_data": {"query_id": qid, "pending_flag": True,
                                                "limit": limit, "format": "json"}})
            reply = data.get("reply", data) if isinstance(data, dict) else data
            status = reply.get("status") if isinstance(reply, dict) else None
            if status and status != "PENDING":
                if status != "SUCCESS":
                    raise RuntimeError("XQL %s: %s" % (status, json.dumps(reply)[:400]))
                results = reply.get("results", {})
                if isinstance(results, dict) and "data" in results:
                    rows = results["data"]
                    return rows if isinstance(rows, list) else []
                if isinstance(results, dict) and results.get("stream_id"):
                    return self._xql_stream(qid, results["stream_id"])
                return results if isinstance(results, list) else []
            time.sleep(self.poll_secs)
        raise RuntimeError("XQL timed out")

    def _xql_stream(self, query_id, stream_id):
        data = self._post("/public_api/v1/xql/get_query_results_stream/",
                          {"request_data": {"query_id": query_id, "stream_id": stream_id,
                                            "is_gzip_compressed": False}})
        raw = data.get("_raw") if isinstance(data, dict) else None
        if raw is None:
            return data if isinstance(data, list) else []
        rows = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def get_datasets(self):
        data = self._post("/public_api/v1/xql/get_datasets/", {"request": {}})
        return data.get("reply", data) if isinstance(data, dict) else data

    def create_lookup_dataset(self, dataset_name, schema):
        try:
            data = self._post("/public_api/v1/xql/add_dataset/",
                              {"request": {"dataset_name": dataset_name, "dataset_type": "lookup",
                                          "dataset_schema": schema}})
            return data.get("reply", data) if isinstance(data, dict) else data
        except RuntimeError as e:
            if "already exists" in str(e).lower():
                return {"status": "exists"}
            raise

    def add_lookup_data(self, dataset_name, rows, create_lag_retries=6):
        last = None
        for attempt in range(create_lag_retries):
            try:
                data = self._post("/public_api/v1/xql/lookups/add_data/",
                                  {"request": {"dataset_name": dataset_name, "data": list(rows)}})
                return data.get("reply", data) if isinstance(data, dict) else data
            except RuntimeError as e:
                msg = str(e)
                if "HTTP 401" in msg:
                    # A rotated, expired or revoked key will not fix itself between retries.
                    raise
                msg = msg.lower()
                # A new dataset is briefly unreadable after add_dataset returns; retry that
                # window rather than losing the batch.
                if ("no schema" in msg or "not found" in msg) and attempt < create_lag_retries - 1:
                    last = e
                    time.sleep(3 * (attempt + 1))
                    continue
                raise
        raise last

    def remove_lookup_data(self, dataset_name, filters):
        """Remove rows matching filter blocks (OR across blocks, AND within a block; EXACT
        values only). NOT concurrency-safe - the caller must serialize. Returns {'deleted': N}."""
        data = self._post("/public_api/v1/xql/lookups/remove_data/",
                          {"request": {"dataset_name": dataset_name, "filters": filters}}, timeout=200)
        return data.get("reply", data) if isinstance(data, dict) else data

    def delete_dataset(self, dataset_name, force=False, retries=3):
        last = None
        for attempt in range(retries):
            try:
                data = self._post("/public_api/v2/xql/delete_dataset/",
                                  {"request": {"dataset_name": dataset_name, "force": bool(force)}})
                return data.get("reply", data) if isinstance(data, dict) else data
            except Exception as e:
                last = e
                if "HTTP 401" in str(e):
                    # A dead key will not recover across retries.
                    raise
                msg = str(e).lower()
                # delete_dataset can exceed the read timeout while still committing, so a
                # "not found" on the retry means the first call succeeded.
                if "not found" in msg or "nonetype" in msg:
                    return {"status": "already_deleted"}
                time.sleep(5 * (attempt + 1))
        raise last


def _norm(h):
    return str(h or "").strip().lower()


# A row in ANY of these states proves the scanner started. A short scan can reach a terminal
# state inside the window - measured, a Linux host completed at +253s - so treating only
# `initiated` as proof would report that host as never-started.
STARTED_STATES = ("initiated", "running", "completed", "cancelled", "failed")


def verify_wave(client, hostnames, dispatch_ms, ver="4", log=lambda *a: None):
    """Which of the dispatched hosts have started scanning since dispatch_ms."""
    want = {}
    for h in (hostnames or []):
        if _norm(h):
            want[_norm(h)] = h
    out = {"verdict": "unknown", "dispatched": sorted(want.values()),
           "started": [], "not_started": [], "match_rows": {}, "states": {},
           "error": ""}
    if not want:
        out["verdict"] = "ok"
        return out

    try:
        rows = client.xql(
            "dataset = yara_scanner_scans* "
            "| filter event_timestamp_ms > %d "
            "| comp max(event_timestamp_ms) as ts by hostname, status" % int(dispatch_ms),
            limit=10000) or []
    except Exception as e:
        # UNKNOWN, never wave_dead: a query failing is not evidence a scan failed.
        out["error"] = "scan lifecycle query failed: %s" % str(e)[:160]
        return out

    seen = {}
    for r in rows:
        h = _norm(r.get("hostname"))
        st = str(r.get("status") or "").lower()
        if h not in want or st not in STARTED_STATES:
            continue
        # Re-check the time bound here even though the query carries it. The whole verdict
        # rests on "since dispatch", and a row from a previous scan counted as this wave
        # starting would report a dead wave as healthy - the one error this gate must not
        # make. Cheap: the row already carries its timestamp.
        try:
            if int(r.get("ts") or 0) <= int(dispatch_ms):
                continue
        except (TypeError, ValueError):
            continue
        seen.setdefault(h, set()).add(st)

    out["started"] = sorted(want[h] for h in seen)
    out["not_started"] = sorted(v for k, v in want.items() if k not in seen)
    out["states"] = dict((k, sorted(v)) for k, v in seen.items())

    # Soft evidence, queried AFTER the verdict inputs are settled so a failure here can never
    # change the verdict.
    try:
        for r in (client.xql(
                "dataset = yara_scanner_matches* "
                "| filter event_timestamp_ms > %d "
                "| comp count() as n by hostname" % int(dispatch_ms), limit=10000) or []):
            h = _norm(r.get("hostname"))
            if h in want:
                out["match_rows"][want[h]] = int(r.get("n") or 0)
    except Exception as e:
        log("match evidence unavailable (not a failure): %s" % str(e)[:120])

    if not out["started"]:
        out["verdict"] = "wave_dead"
    elif out["not_started"]:
        out["verdict"] = "partial"
    else:
        out["verdict"] = "ok"
    return out


def main():
    args = demisto.args()
    hosts = argToList(args.get("hostnames"))
    ver = str(args.get("schema_version") or DEFAULT_LOOKUP_SCHEMA_VERSION).strip()
    try:
        dispatch_ms = int(float(args.get("dispatch_ms") or 0))
    except (TypeError, ValueError):
        return_error("YaraScanVerify: dispatch_ms must be epoch milliseconds (%r given)."
                     % args.get("dispatch_ms"))
        return
    if not dispatch_ms:
        return_error("YaraScanVerify: dispatch_ms is required - without it a scan from "
                     "yesterday would count as this wave starting.")
        return

    log_lines = []
    try:
        result = verify_wave(CoreApiClient(), hosts, dispatch_ms, ver=ver,
                             log=lambda m: log_lines.append(m))
    except Exception as ex:
        return_error("YaraScanVerify failed: {}".format(ex))
        return

    v = result["verdict"]
    if v == "ok":
        head = "All %d dispatched host(s) are scanning." % len(result["started"])
    elif v == "partial":
        head = ("%d of %d host(s) started; %d have written no lifecycle row yet."
                % (len(result["started"]), len(result["dispatched"]),
                   len(result["not_started"])))
    elif v == "wave_dead":
        head = ("NO host started. The whole wave appears dead - check the ruleset, the script "
                "UID and the delivery action before re-dispatching.")
    else:
        head = ("Could not determine - the lifecycle query failed. Treat as UNKNOWN, not "
                "failed: a query error is not evidence a scan failed.")

    lines = [head]
    if result["started"]:
        lines.append("started: %s" % ", ".join(result["started"][:20]))
    if result["not_started"]:
        lines.append("no row yet: %s" % ", ".join(result["not_started"][:20]))
    if result["match_rows"]:
        lines.append("match rows already landed: %s"
                     % ", ".join("%s=%d" % (k, n)
                                 for k, n in sorted(result["match_rows"].items())))
    else:
        lines.append("no match rows yet - evidence only, never a failure: a clean host has "
                     "none.")
    if result["error"]:
        lines.append("error: %s" % result["error"])

    # List-valued context is APPENDED to across calls in one investigation, so a second
    # verification pass would otherwise merge both waves' host lists.
    demisto.executeCommand("DeleteContext", {"key": "Yara.ScanVerify"})
    return_results(CommandResults(readable_output="\n".join(lines),
                                  outputs_prefix="Yara.ScanVerify",
                                  outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
