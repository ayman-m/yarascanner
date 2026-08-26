"""YaraConsolidateApply - perform the YARA per-scan dataset merge.

Creates a per-scan target dataset for every eligible scan, writes its rows, and deletes a
source shard only once every scan that shard holds has been verified into its target. A scan
that turns out to be active again between the readiness check and this call is deferred, not
failed - log deferred_scan_ids and alarm only on failed_count.

MUTATING: it writes datasets and it deletes source shards. It is idempotent per scan (an
already-complete target is verified, not rewritten), but every call re-reads tenant-wide
state, so run it once per pass rather than speculatively. If another run holds the
consolidation lock, this pass stands down and reports lock_held_by_other_run.

ARGUMENTS
  scan_id                Restrict the merge to these scan_id(s), comma-separated - normally
                         YaraConsolidateStatus's eligible_scan_ids. Omit to re-derive
                         eligibility here and merge everything that qualifies.
  quiet_secs             Override DEFAULT_QUIET_SECS for this run.
  row_ceiling            Override DEFAULT_ROW_CEILING for this run.
  abandoned_after_hours  Override DEFAULT_ABANDONED_SECS for this run, given in hours.
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

# Write and delete behaviour. Lower the batch size if the tenant gateway returns 502s.
_WRITE_BATCH = 500                  # rows per lookups/add_data call
DELETE_CONCURRENCY = 12             # source shards deleted in parallel
DEFAULT_LOCK_STALE_SECS = 20 * 60   # a run cannot outlive the 900s task timeout
# One pass consolidates at most this many scans, so it finishes inside that 900s
# timeout instead of being killed mid-merge still holding the lock.
# 20 shipped with no measurement behind it. Live on emea (2026-08-21): 5 scans took 638s -
# 71% of the 900s task timeout - and 20 would be killed around scan 7, reproducing the exact
# stuck-lock incident this bound exists to prevent. A 4-scan pass measured at 403s (45%)
# completed cleanly; keep real margin, not none.
DEFAULT_MAX_SCANS_PER_PASS = 4

# Lookup schema version assumed when the schema_version argument is left empty.
# Must match the scanner's YARA_LOOKUP_SCHEMA_VER on the endpoints.
DEFAULT_LOOKUP_SCHEMA_VERSION = "4"
# ############################################################################

# ============================================================================
# INLINED LIBRARY - carried in-file so this automation imports nothing.
# Configure it from the CONFIGURATION block above, not from in here.
# ============================================================================
import json
import time

# ---- consolidation core: naming, schemas, locking, merge gates -------------
import collections
import re

_PREFIX = "yara_scanner"
_SHARD_RE = re.compile(
    r"^yara_scanner_(?P<kind>matches|scans)_v(?P<ver>\d+)_(?P<host>.+?_[0-9a-f]{6})(?:_(?P<month>\d{6}))?$"
)
TERMINAL_LIFECYCLE = {"completed", "cancelled", "failed"}
# Every Action Center state meaning the script is no longer running. Both spellings of
# CANCEL(L)ED are required - the platform returns either.
TERMINAL_ACTION = {"COMPLETED_SUCCESSFULLY", "FAILED", "ABORTED", "EXPIRED",
                   "TIMEOUT", "CANCELED", "CANCELLED",
                   "COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"}
# Endpoint clocks can run ahead of ingest, so both time gates compare against the later of
# the endpoint stamp and the platform's _insert_time, within this tolerance.
SKEW_TOLERANCE_MS = 5 * 60 * 1000
DEFAULT_SKEW_BACKSTOP_SECS = 7 * 24 * 3600

# Every matches-dataset shape a tenant can still be holding. All are kept: a fleet
# mid-rollout writes two shapes at once, and an un-consolidated shard is its scan's only copy.
#   v2: one row per matched string OFFSET.
#   v3: one row per (rule, file) FINDING.
#   v4: one row per matched FILE, every rule that hit it folded into `rules`.
MATCHES_SCHEMA = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "rule": "text", "filename": "text", "file_size": "number", "file_sha256": "text",
    "file_creation_time": "text", "scan_folder": "text", "match": "text", "offset": "number",
    "matched_length": "number", "string": "text", "severity": "text",
    "event_timestamp_ms": "number", "date_of_scan": "text",
}
MATCHES_SCHEMA_V3 = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "rule": "text", "filename": "text", "file_size": "number", "file_sha256": "text",
    "file_creation_time": "text", "scan_folder": "text",
    "match_count": "number", "offsets": "text", "strings": "text", "string_ids": "text",
    "truncated": "bool", "severity": "text",
    "event_timestamp_ms": "number", "date_of_scan": "text",
}
MATCHES_SCHEMA_V4 = {
    "tenant_id": "text", "scan_id": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "filename": "text", "file_size": "number", "file_sha256": "text",
    "file_creation_time": "text",
    "rules": "text",            # JSON array of {rule,match_count,offsets,strings,string_ids,truncated,severity}
    "rule_count": "number", "match_total": "number",
    "severity": "text",         # highest across the file's rules
    "truncated": "bool",        # true when ANY rule's embedded sample was capped
    "event_timestamp_ms": "number",
}
_MATCHES_SCHEMAS_BY_VER = {"2": MATCHES_SCHEMA, "3": MATCHES_SCHEMA_V3, "4": MATCHES_SCHEMA_V4}
KNOWN_MATCHES_SCHEMA_VERSIONS = tuple(sorted(_MATCHES_SCHEMAS_BY_VER))


def matches_schema_for(ver):
    return _MATCHES_SCHEMAS_BY_VER.get(str(ver), MATCHES_SCHEMA_V4)


SCANS_SCHEMA = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "status": "text", "scan_folder": "text", "files_scanned": "number",
    "files_skipped": "number", "detections": "number", "valid_rules": "number",
    "failed_rules": "number", "scan_rate_fps": "number", "elapsed_secs": "number",
    "total_paused_secs": "number", "throttle_mode": "text", "posture": "text",
    "event_timestamp_ms": "number", "message": "text",
}

# ---- overlap guard: one lock dataset, so two runs cannot collide on one target ----
_LOCK_DATASET = "yara_scanner_consolidation_lock"
_LOCK_SCHEMA = {"holder": "text", "started_ms": "number"}


def _read_lock(client):
    rows = client.xql("dataset = %s" % _LOCK_DATASET, limit=5) or []
    if not rows:
        return None
    ts = rows[0].get("started_ms")
    try:
        return int(ts) if ts is not None else None
    except (TypeError, ValueError):
        return None


def acquire_consolidation_lock(client, log=print, now_ms=None,
                               stale_after_secs=DEFAULT_LOCK_STALE_SECS, holder="unknown",
                               unreadable_is_held=False, on_takeover=None):
    """Take the consolidation lock. Returns False if another run holds it.

    unreadable_is_held treats a lock dataset with no readable row as HELD - that is the
    create-lag window right after another run took it. on_takeover reports a steal, so a
    caller whose action is irreversible can never report an uncontended pass."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    resp = client.create_lookup_dataset(_LOCK_DATASET, _LOCK_SCHEMA)
    fresh = isinstance(resp, dict) and "dataset_name" in resp
    if not fresh:
        held_ms = _read_lock(client)
        if held_ms is not None and (now_ms - held_ms) < stale_after_secs * 1000:
            log("consolidation lock held (age %.0fs) - another run appears to be in "
                "progress; skipping this pass" % ((now_ms - held_ms) / 1000.0))
            return False
        if held_ms is None and unreadable_is_held:
            log("consolidation lock marker exists but its row is unreadable - another run "
                "most likely just created it (add_data create-lag); standing down rather "
                "than taking over")
            return False
        msg = ("consolidation lock is stale or unreadable (%s) - taking over"
               % ("age unknown" if held_ms is None
                  else "age %.0fs" % ((now_ms - held_ms) / 1000.0)))
        log(msg)
        if on_takeover:
            on_takeover(msg)
        client.delete_dataset(_LOCK_DATASET, force=True)
        client.create_lookup_dataset(_LOCK_DATASET, _LOCK_SCHEMA)
    client.add_lookup_data(_LOCK_DATASET, [{"holder": str(holder), "started_ms": now_ms}])
    return True


def release_consolidation_lock(client, log=print):
    try:
        client.delete_dataset(_LOCK_DATASET, force=True)
    except Exception as e:
        log("could not release consolidation lock: %s" % e)


# ---- consolidation run-log --------------------------------------------------
# One row per YaraConsolidateApply pass, so the Consolidation Run Health widget can query
# whether the merge is running at all. Investigation context is per-run and not queryable.
_RUNS_DATASET = "yara_scanner_consolidation_runs"
_RUNS_SCHEMA = {
    "run_ts_ms": "number", "status": "text", "consolidated_count": "number",
    "failed_count": "number", "failed_scan_ids": "text", "failed_reasons": "text",
    "error_message": "text",
}


def record_consolidation_run(client, status, result=None, error_message="", now_ms=None, log=print):
    """Best-effort: write ONE row recording this pass's outcome.

    status is "success", "partial_failure", or "crashed" (the merge raised before returning,
    and error_message carries the exception text). Every exception here is caught and only
    logged: failing to write this row must never replace the run's real outcome."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    result = result or {}
    row = {
        "run_ts_ms": now_ms,
        "status": status,
        "consolidated_count": int(result.get("consolidated_count", 0) or 0),
        "failed_count": int(result.get("failed_count", 0) or 0),
        "failed_scan_ids": json.dumps(result.get("failed_scan_ids", [])),
        "failed_reasons": json.dumps(result.get("failed_reasons", {})),
        "error_message": str(error_message or "")[:500],
    }
    try:
        client.create_lookup_dataset(_RUNS_DATASET, _RUNS_SCHEMA)
        client.add_lookup_data(_RUNS_DATASET, [row])
    except Exception as e:
        log("could not record consolidation run outcome: %s" % e)


def target_name(kind, ver, scan_id):
    slug = re.sub(r"[^a-z0-9]+", "_", str(scan_id).lower()).strip("_") or "unknown"
    return "%s_%s_v%s_scan_%s" % (_PREFIX, kind, ver, slug)


def parse_shard(name):
    if name is None:
        return None
    m = _SHARD_RE.match(name)
    if not m:
        return None
    host = m.group("host")
    if host.startswith("scan_") or host == "scan":
        return None
    # v4 is where matches stopped rotating and became overwrite-per-scan, so an UNSUFFIXED
    # matches dataset at v4+ is the scanner's permanent write target, not a rotation shard.
    # Consolidating it would delete the host dataset and leave one per-scan dataset behind
    # for every scan - precisely the unbounded growth the overwrite model removed - and the
    # scanner would recreate the host dataset for the next pass to eat again. A DATED v4
    # matches dataset predates that model and stays ordinary, consolidatable debris; scans
    # still rotates monthly at v4 and is untouched by this.
    if m.group("kind") == "matches" and int(m.group("ver")) >= 4 and not m.group("month"):
        return None
    return {"kind": m.group("kind"), "ver": m.group("ver"), "host": host, "month": m.group("month")}


def shard_is_terminal(latest_status, action_state):
    if latest_status and str(latest_status).lower() in TERMINAL_LIFECYCLE:
        return True
    if action_state and str(action_state).upper() in TERMINAL_ACTION:
        return True
    return False


def _as_ms(v):
    """Epoch-ms int from whatever XQL hands back (int, float, numeric string, ISO
    timestamp), or None. Never raises."""
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        pass
    try:
        return int(float(v))
    except (TypeError, ValueError):
        pass
    try:
        from datetime import datetime, timezone
        s = str(v).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def _newest_ms(endpoint_ms, server_ms, now_ms=None):
    """The freshness signal both time gates measure against: the LATER of the endpoint's own
    event_timestamp_ms and the platform's _insert_time, with implausible values discarded
    first. Must only ever be fed SOURCE SHARDS, never a per-scan target."""
    ep, srv = _as_ms(endpoint_ms), _as_ms(server_ms)
    if ep is not None and srv is not None and now_ms is not None \
            and srv > now_ms + SKEW_TOLERANCE_MS:
        srv = None                       # guard 2: implausible server stamp (unit mismatch)
    if ep is not None and srv is not None and ep > srv + SKEW_TOLERANCE_MS:
        ep = None                        # guard 1: endpoint clock ahead of ingest
    vals = [v for v in (ep, srv) if v is not None]
    return max(vals) if vals else None


def _max_ms(a, b):
    """max() over two optional epoch-ms values, ignoring Nones."""
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


_ScanStat = collections.namedtuple("_ScanStat", "count newest ep_newest")


def build_terminal_map(scans_rows_by_ds, action_state_for=None):
    out = {}
    for ds, rows in scans_rows_by_ds.items():
        p = parse_shard(ds)
        if not p or p["kind"] != "scans":
            continue
        host = p["host"]
        per = {}
        for r in rows:
            sid = r.get("scan_id")
            if sid:
                per.setdefault(sid, []).append(r)
        for sid, rs in per.items():
            rs_sorted = sorted(rs, key=lambda r: _as_ms(r.get("event_timestamp_ms")) or 0)
            latest_status = rs_sorted[-1].get("status")
            newest = None
            for r in rs:
                newest = _max_ms(newest, _newest_ms(r.get("event_timestamp_ms"),
                                                    r.get("_insert_time")))
            astate = action_state_for(host) if action_state_for else None
            out[(sid, host)] = {"terminal": shard_is_terminal(latest_status, astate),
                                "newest_ms": newest, "status": latest_status}
    return out


def newest_row_age_ok(newest_ms, now_ms, quiet_secs):
    if newest_ms is None:
        return True
    return (now_ms - int(newest_ms)) >= quiet_secs * 1000


def plan_consolidation(scan_id, source_counts, target_count, row_ceiling=DEFAULT_ROW_CEILING):
    source_total = sum(int(v) for v in source_counts.values())
    if source_total > row_ceiling:
        return {"scan_id": scan_id, "ok": False, "reason": "row_ceiling_exceeded",
                "source_total": source_total, "target_count": target_count, "deletable": []}
    if target_count == source_total and source_total > 0:
        return {"scan_id": scan_id, "ok": True, "reason": "verified",
                "source_total": source_total, "target_count": target_count,
                "deletable": sorted(source_counts)}
    return {"scan_id": scan_id, "ok": False, "reason": "count_mismatch",
            "source_total": source_total, "target_count": target_count, "deletable": []}


def _added(reply):
    r = reply or {}
    return int(r.get("records_added", r.get("rows added", 0)) or 0)


def _rows_of(dataset, client, limit=50000):
    return client.xql("dataset = %s" % dataset, limit=limit) or []


def _rows_for_scan(client, dataset, scan_id, limit=50000):
    safe = str(scan_id).replace('"', "")
    return client.xql('dataset = %s | filter scan_id = "%s"' % (dataset, safe), limit=limit) or []


def _is_live_overwrite_dataset(name):
    """True for the scanner's permanent per-host matches dataset (v4+, no month) - the
    dataset an unsuffixed name RESOLVES TO, independent of whatever list a caller believes
    it collected. parse_shard's exclusion at enumeration time is the only thing that keeps
    this name out of a shard/deletion list in the first place; this is a SECOND, independent
    check at the point of the two destructive calls (_cleanup_verified_scan_rows,
    _delete_many), so a bug in enumeration - stale state, a future refactor, a caller that
    builds its own shard list - cannot reach delete_dataset() or remove_lookup_data() against
    this name. Belt-and-braces: under correct enumeration this never fires.

    Deliberately does NOT call parse_shard - depending on the function this is meant to
    backstop would make the two guards fail together the moment parse_shard itself is what
    broke. This re-derives the answer from _SHARD_RE directly."""
    m = _SHARD_RE.match(name or "")
    return bool(m and m.group("kind") == "matches" and int(m.group("ver")) >= 4
               and not m.group("month") and not (m.group("host") or "").startswith("scan_")
               and (m.group("host") or "") != "scan")


def _cleanup_verified_scan_rows(client, srcs, scan_id, log):
    """Once a scan's per-scan target is verified, strip that scan's rows out of every source
    shard, so a dashboard querying the wildcard stops double-counting it.

    Sequential: remove_lookup_data is NOT concurrency-safe. Best effort - a failure here
    never blocks the eventual whole-shard delete. Callers must only invoke this for
    kind=="matches": a "scans" shard's rows are the lifecycle signal for the sibling scans
    still sharing it."""
    for ds in srcs:
        if _is_live_overwrite_dataset(ds):
            log("  scan %s: refusing to strip rows from %s - permanent overwrite dataset, "
               "never a cleanup source regardless of how it reached this list" % (scan_id, ds))
            continue
        try:
            client.remove_lookup_data(ds, [{"scan_id": scan_id}])
        except Exception as e:
            log("  scan %s: row-level cleanup of %s FAILED (leaving rows for eventual "
                "whole-shard delete instead): %s" % (scan_id, ds, str(e)[:120]))


def _scan_stats(client, dataset, now_ms=None, log=None):
    """{scan_id: _ScanStat(count, newest, ep_newest)} via aggregation - no row pull. `newest`
    is skew-proofed per _newest_ms. dataset MUST be a source shard, never a per-scan target."""
    rows = client.xql("dataset = %s | comp count() as n, max(event_timestamp_ms) as newest, "
                      "max(_insert_time) as srv_newest by scan_id" % dataset, limit=10000) or []
    out, srv_seen = {}, False
    for r in rows:
        sid = r.get("scan_id")
        if not sid:
            continue
        ep, srv = _as_ms(r.get("newest")), _as_ms(r.get("srv_newest"))
        srv_seen = srv_seen or srv is not None
        out[sid] = _ScanStat(int(r.get("n") or 0), _newest_ms(ep, srv, now_ms), ep)
    _warn_if_no_server_stamp(dataset, bool(out), srv_seen, log)
    return out


def _warn_if_no_server_stamp(dataset, had_rows, srv_seen, log):
    """Log when the platform returns no _insert_time, so the clock-skew protection cannot go
    inactive unnoticed."""
    if had_rows and not srv_seen and log:
        log("  note: %s returned no usable _insert_time — endpoint-clock-skew protection is "
            "INACTIVE for this shard; gates fall back to event_timestamp_ms alone" % dataset)


def _coerce_row(row, schema):
    out = {}
    for k in schema:
        if k not in row:
            continue
        v, t = row[k], schema[k]
        if v is None:
            out[k] = v
        elif t == "number":
            try:
                f = float(v)
                out[k] = int(f) if f == int(f) else f
            except (TypeError, ValueError):
                out[k] = v
        elif t == "bool":
            out[k] = v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes")
        elif t == "text":
            out[k] = v if isinstance(v, str) else str(v)
        else:
            out[k] = v
    return out


def _stats_from_rows(rows, now_ms=None, log=None, dataset=""):
    """Same shape as _scan_stats but from already-read rows (used for the small scans
    shards). Rows MUST come from a source shard, never a per-scan target."""
    out, srv_seen = {}, False
    for r in rows:
        sid = r.get("scan_id")
        if not sid:
            continue
        prev = out.get(sid) or _ScanStat(0, None, None)
        ep, srv = _as_ms(r.get("event_timestamp_ms")), _as_ms(r.get("_insert_time"))
        srv_seen = srv_seen or srv is not None
        out[sid] = _ScanStat(prev.count + 1,
                             _max_ms(prev.newest, _newest_ms(ep, srv, now_ms)),
                             _max_ms(prev.ep_newest, ep))
    _warn_if_no_server_stamp(dataset, bool(out), srv_seen, log)
    return out


def _gate_scan(scan_id, srcs, newest_by, ep_newest_by, tmap, now_ms, quiet_secs,
               abandoned_after_secs, log, skew_backstop_secs=DEFAULT_SKEW_BACKSTOP_SECS):
    """Defer-reason string if any source host is not safe to merge yet, else ''. Both age
    checks measure the skew-proof `newest`, except the `settled` backstop, which uses the
    endpoint stamp alone - the one value nothing but the endpoint itself can re-arm."""
    for ds in srcs:
        host = (parse_shard(ds) or {}).get("host", "")
        entry = tmap.get((scan_id, host))
        is_terminal = bool(entry and entry["terminal"])
        newest = newest_by.get((scan_id, ds))
        ep_newest = (ep_newest_by or {}).get((scan_id, ds))
        ep_age_ms = (now_ms - ep_newest) if ep_newest is not None else None
        settled = ep_age_ms is not None and ep_age_ms >= skew_backstop_secs * 1000
        if newest is not None and newest > now_ms + SKEW_TOLERANCE_MS:
            log("  scan %s: shard %s newest stamp is %.1fh in the FUTURE of this run's clock "
                "(endpoint clock ahead, no usable _insert_time to correct with) — this scan "
                "will keep deferring until real time catches up"
                % (scan_id, ds, (newest - now_ms) / 3_600_000.0))
        if not is_terminal:
            age_ms = (now_ms - newest) if newest is not None else None
            abandoned = age_ms is not None and age_ms >= abandoned_after_secs * 1000
            if abandoned or settled:
                log("  scan %s: host %s non-terminal (%s) but %s — treating as ABANDONED, "
                    "consolidating to preserve its findings"
                    % (scan_id, host, (entry.get("status") if entry else "no lifecycle row"),
                       ("newest row is %.1fh old" % (age_ms / 3_600_000.0)) if abandoned else
                       ("the endpoint has written nothing for %.1f days (server-stamp "
                        "backstop)" % (ep_age_ms / 86_400_000.0))))
            else:
                log("  scan %s: host %s not terminal (%s) — deferring"
                    % (scan_id, host, "no lifecycle row" if not entry else entry.get("status")))
                return "host_not_terminal"
        if not newest_row_age_ok(newest, now_ms, quiet_secs) and not settled:
            log("  scan %s: host shard %s within quiet period — deferring" % (scan_id, ds))
            return "within_quiet_period"
    return ""


def _list_yara_datasets(client):
    raw = client.get_datasets()
    if isinstance(raw, dict):
        items = raw.get("data") or raw.get("datasets") or raw.get("reply") or []
    else:
        items = raw or []
    names = []
    for d in items:
        if isinstance(d, str):
            n, dtype = d, "LOOKUP"
        elif isinstance(d, dict):
            n = d.get("Dataset Name") or d.get("dataset_name") or d.get("name")
            dtype = str(d.get("Type") or d.get("dataset_type") or "LOOKUP").upper()
        else:
            continue
        if n and dtype == "LOOKUP" and str(n).startswith(_PREFIX):
            names.append(str(n))
    return names


def _count(client, dataset):
    r = client.xql("dataset = %s | comp count() as n" % dataset, limit=5)
    return int(r[0].get("n", 0)) if r else 0


def _delete_many(client, names, log, concurrency=None):
    blocked = [n for n in names if _is_live_overwrite_dataset(n)]
    for n in blocked:
        log("  refusing to delete %s - permanent overwrite dataset, never a deletion "
           "candidate regardless of how it reached this list" % n)
    names = [n for n in names if n not in blocked]
    import threading
    concurrency = concurrency or DELETE_CONCURRENCY
    lock = threading.Lock()
    done = {"n": 0}

    def worker(ds):
        try:
            client.delete_dataset(ds, force=True)
            with lock:
                done["n"] += 1
        except Exception as e:
            log("    delete FAILED %s: %s" % (ds, str(e)[:60]))

    for i in range(0, len(names), concurrency):
        batch = names[i:i + concurrency]
        threads = [threading.Thread(target=worker, args=(ds,)) for ds in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log("    deleted %d/%d shards" % (done["n"], len(names)))


def run_consolidation(client, kind, ver="2", quiet_secs=DEFAULT_QUIET_SECS,
                      row_ceiling=DEFAULT_ROW_CEILING, dry_run=True, log=print,
                      now_ms=None, action_state_for=None, only_scan_ids=None,
                      abandoned_after_secs=DEFAULT_ABANDONED_SECS):
    # ONE schema version per call: a v2 and a v3 shard for the same scan have different
    # columns, so merging them under one schema would mis-project every row. The two callers
    # below fan out across every known version.
    ver = str(ver)
    schema = matches_schema_for(ver) if kind == "matches" else SCANS_SCHEMA
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

    all_ds = _list_yara_datasets(client)
    shards = [d for d in all_ds
              if (parse_shard(d) or {}).get("kind") == kind and (parse_shard(d) or {}).get("ver") == ver]
    if not shards:
        log("no %s shards found" % kind)
        return []

    scans_ds = [d for d in all_ds if (parse_shard(d) or {}).get("kind") == "scans"]
    scans_rows = {d: _rows_of(d, client) for d in scans_ds}
    tmap = build_terminal_map(scans_rows, action_state_for)

    all_groups, newest_by, ep_newest_by = {}, {}, {}
    for ds in shards:
        stats = (_stats_from_rows(scans_rows[ds], now_ms=now_ms, log=log, dataset=ds)
                 if kind == "scans" else _scan_stats(client, ds, now_ms=now_ms, log=log))
        for sid, st in stats.items():
            all_groups.setdefault(sid, {})[ds] = st.count
            newest_by[(sid, ds)] = st.newest
            ep_newest_by[(sid, ds)] = st.ep_newest

    shard_scans = {}
    for sid, counts in all_groups.items():
        for ds in counts:
            shard_scans.setdefault(ds, set()).add(sid)

    groups = all_groups
    if only_scan_ids is not None:
        want = set(only_scan_ids)
        groups = {s: c for s, c in all_groups.items() if s in want}
    log("found %d %s shard(s) across %d scan(s)" % (len(shards), kind, len(groups)))
    existing = set(all_ds)

    verified = set()
    plans = []
    for scan_id, counts in sorted(groups.items()):
        srcs = sorted(counts)
        deferred = _gate_scan(scan_id, srcs, newest_by, ep_newest_by, tmap, now_ms, quiet_secs,
                              abandoned_after_secs, log)
        if deferred:
            plans.append({"scan_id": scan_id, "ok": False, "reason": deferred, "deletable": []})
            continue

        target = target_name(kind, ver, scan_id)
        src_total = sum(counts.values())
        if src_total > row_ceiling:
            log("  scan %s: %d rows exceeds ceiling %d — skipped" % (scan_id, src_total, row_ceiling))
            plans.append(plan_consolidation(scan_id, counts, 0, row_ceiling))
            continue

        if dry_run:
            log("  scan %s: WOULD consolidate %d rows from %d shard(s) -> %s"
                % (scan_id, src_total, len(srcs), target))
            plans.append({"scan_id": scan_id, "ok": None, "reason": "dry_run",
                          "source_total": src_total, "target": target, "deletable": []})
            continue

        pre = _count(client, target) if target in existing else 0
        if pre == src_total and src_total > 0:
            log("  scan %s: target already complete (%d rows) — verified, not rewritten"
                % (scan_id, pre))
            verified.add(scan_id)
            # Target was written and verified by an earlier run; retry the row-level cleanup
            # in case it did not fully land that time.
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue                                          # <-- PATH A: idempotent re-verify
        if pre > src_total > 0:
            # Target holds MORE rows than the live sources sum to: row-level cleanup has
            # partially landed on a multi-shard scan. Still verified - retry the rest.
            log("  scan %s: target has %d rows, sources currently sum to only %d "
                "(cleanup already landed on some sources) — still verified, retrying cleanup "
                "on the rest" % (scan_id, pre, src_total))
            verified.add(scan_id)
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
            plans.append({"scan_id": scan_id, "ok": True, "reason": "verified",
                          "source_total": src_total, "target_count": pre,
                          "deletable": sorted(srcs)})
            continue                                          # <-- PATH A2: partial-cleanup re-verify
        if pre not in (0, src_total):
            log("  scan %s: target exists with %d rows, expected %d — NOT touching, reports mismatch"
                % (scan_id, pre, src_total))
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue

        client.create_lookup_dataset(target, schema)
        written = 0
        for ds in srcs:
            rows = _rows_for_scan(client, ds, scan_id)
            rows = [_coerce_row(r, schema) for r in rows]
            for i in range(0, len(rows), _WRITE_BATCH):
                written += _added(client.add_lookup_data(target, rows[i:i + _WRITE_BATCH]))
        time.sleep(min(30, 2 + src_total // 500))
        tcount = _count(client, target)
        plan = plan_consolidation(scan_id, counts, tcount, row_ceiling)
        log("  scan %s: wrote %d, target now %d, sources %d -> %s"
            % (scan_id, written, tcount, src_total, "VERIFIED" if plan["ok"] else plan["reason"]))
        if plan["ok"]:
            verified.add(scan_id)                             # <-- PATH B: fresh write verified
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
        plans.append(plan)

    if not dry_run:
        to_delete = [ds for ds, sids in shard_scans.items() if sids and sids <= verified]
        for ds, sids in sorted(shard_scans.items()):
            if sids & verified and not (sids <= verified):
                log("  kept shard %s — %d of %d scan(s) still pending consolidation"
                    % (ds, len(sids - verified), len(sids)))
        if to_delete:
            log("  deleting %d fully-consolidated shard(s), %d at a time" % (len(to_delete), DELETE_CONCURRENCY))
            _delete_many(client, to_delete, log)
    return plans


def check_consolidation_status(client, kinds=("matches", "scans"), vers=KNOWN_MATCHES_SCHEMA_VERSIONS,
                               quiet_secs=DEFAULT_QUIET_SECS, row_ceiling=DEFAULT_ROW_CEILING,
                               abandoned_after_secs=DEFAULT_ABANDONED_SECS,
                               only_scan_ids=None, now_ms=None, action_state_for=None,
                               log=lambda *a: None):
    # Every known schema version by default: a tenant mid-rollout has both old- and
    # new-schema shards live at once, and both need consolidating.
    eligible, deferred, blocked = set(), set(), set()
    blocked_reasons = {}
    for ver in vers:
        for kind in kinds:
            for p in run_consolidation(client, kind, ver=ver, quiet_secs=quiet_secs,
                                       row_ceiling=row_ceiling, dry_run=True, log=log,
                                       now_ms=now_ms, action_state_for=action_state_for,
                                       only_scan_ids=only_scan_ids,
                                       abandoned_after_secs=abandoned_after_secs):
                sid = p["scan_id"]
                if p.get("ok") is None and p.get("reason") == "dry_run":
                    eligible.add(sid)
                elif p.get("reason") in ("host_not_terminal", "within_quiet_period"):
                    deferred.add(sid)
                else:
                    blocked.add(sid)
                    blocked_reasons[sid] = p.get("reason")
    eligible -= deferred | blocked
    return {"any_in_progress": bool(deferred), "eligible_count": len(eligible),
            "eligible_scan_ids": sorted(eligible), "pending_scan_ids": sorted(deferred),
            "blocked_count": len(blocked), "blocked_scan_ids": sorted(blocked),
            "blocked_reasons": blocked_reasons}


def _matches_shard_for_read(name, ver):
    """{kind, ver, host, month} for a dataset safe to READ as a matches source of schema
    `ver`, or None. Unlike parse_shard, this INCLUDES the live overwrite dataset (matches
    v4+, unsuffixed) - parse_shard excludes it so Apply/Fast can never select it for
    deletion, but Summary never deletes anything, and the live dataset is the ONLY place a
    v4-scanned host's current findings live once matches stopped rotating. Excluding it here
    left Summary silently producing zero rows for every host on the shipped default: `main`
    built match_ds from parse_shard's list alone, and the live host dataset was the only
    thing in it for a host running the current scanner. Read-for-summary and
    safe-to-delete are different questions; this answers the first one, independent of
    parse_shard's answer to the second."""
    p = parse_shard(name)
    if p:
        return p if p["kind"] == "matches" and str(p["ver"]) == str(ver) else None
    m = _SHARD_RE.match(name or "")
    if not (m and m.group("kind") == "matches" and str(m.group("ver")) == str(ver)):
        return None
    host = m.group("host")
    if host.startswith("scan_") or host == "scan":
        return None
    return {"kind": "matches", "ver": m.group("ver"), "host": host, "month": m.group("month")}


_RULE_HASH_RE = re.compile(r"_yara_([0-9a-f]{6,})$")


def rule_hash_of(scan_id):
    """The ruleset hash trailing a scan_id, or None.

    The scanner builds scan_id as "{hostname}_{run_id}_yara_{sha256(rules)[:12]}" and keeps
    that suffix deliberately "so the ruleset stays identifiable from the scan_id alone".
    hostname and run_id are per-host; the hash is the ONLY component every host in one
    Action Center scan shares, which makes it the grouping key. No API call, no scanner
    change, and it works on data already on the tenant."""
    m = _RULE_HASH_RE.search(str(scan_id or ""))
    return m.group(1) if m else None


def full_target_for_rules(ver, rule_hash):
    """yara_scanner_full_v<VER>_rules_<hash>. ONE dataset per ruleset holding EVERY column
    of every matched-file row, for every host scanned with that ruleset.

    A distinct `full` kind on purpose. Naming it matches_v<N>_rules_<hash> would put a
    consolidated target inside the pattern _SHARD_RE reads, and a six-character rule hash
    would then be indistinguishable from a host suffix - the consolidated output could be
    mistaken for somebody's live per-host dataset. `full` cannot collide with anything."""
    slug = re.sub(r"[^a-z0-9]+", "_", str(rule_hash or "unknown").lower()).strip("_") or "unknown"
    return "%s_full_v%s_rules_%s" % (_PREFIX, ver, slug)


def consolidate_all(client, kinds=("matches", "scans"), vers=KNOWN_MATCHES_SCHEMA_VERSIONS, dry_run=False,
                    only_scan_ids=None, quiet_secs=DEFAULT_QUIET_SECS,
                    row_ceiling=DEFAULT_ROW_CEILING, abandoned_after_secs=DEFAULT_ABANDONED_SECS,
                    now_ms=None, action_state_for=None, max_scans=None, log=print):
    if not dry_run and not acquire_consolidation_lock(client, log=log, now_ms=now_ms):
        return {"consolidated_count": 0, "consolidated_scan_ids": [],
                "deferred_count": 0, "deferred_scan_ids": [],
                "failed_count": 0, "failed_scan_ids": [], "failed_reasons": {},
                "would_count": 0, "would_scan_ids": [],
                "stopped_early": False,
                "lock_held_by_other_run": True}
    try:
        stopped_early = False
        if max_scans:
            if only_scan_ids is None:
                _ready = check_consolidation_status(
                    client, kinds=kinds, vers=vers, quiet_secs=quiet_secs,
                    row_ceiling=row_ceiling, abandoned_after_secs=abandoned_after_secs,
                    now_ms=now_ms, action_state_for=action_state_for, log=log)
                _candidates = sorted(_ready.get("eligible_scan_ids") or [])
            else:
                _candidates = sorted(only_scan_ids)
            stopped_early = len(_candidates) > max_scans
            only_scan_ids = _candidates[:max_scans]
            if stopped_early:
                log("pass bounded to %d of %d eligible scan(s) so it finishes inside its "
                    "task timeout; the rest are owed a further pass"
                    % (max_scans, len(_candidates)))
        consolidated, deferred, failed, would = set(), set(), set(), set()
        failed_reasons = {}
        for ver in vers:
            for kind in kinds:
                for p in run_consolidation(client, kind, ver=ver, quiet_secs=quiet_secs,
                                           row_ceiling=row_ceiling, dry_run=dry_run, log=log,
                                           now_ms=now_ms, action_state_for=action_state_for,
                                           only_scan_ids=only_scan_ids,
                                           abandoned_after_secs=abandoned_after_secs):
                    sid = p["scan_id"]
                    if p.get("ok"):
                        consolidated.add(sid)
                    elif p.get("reason") == "dry_run":
                        # A PREVIEW, NOT AN OUTCOME. A dry-run plan carries ok=None because
                        # nothing ran. Without this branch it fell through to `failed`, so a
                        # healthy dry run reported every previewed scan as a failure - and the
                        # operator docs say to alarm only on failed_count. Measured live: a
                        # three-scan preview reported failed_count=3.
                        would.add(sid)
                    elif p.get("reason") in ("host_not_terminal", "within_quiet_period"):
                        deferred.add(sid)
                    else:
                        failed.add(sid)
                        failed_reasons[sid] = p.get("reason")
    finally:
        if not dry_run:
            release_consolidation_lock(client, log=log)
    return {"consolidated_count": len(consolidated), "consolidated_scan_ids": sorted(consolidated),
            "deferred_count": len(deferred), "deferred_scan_ids": sorted(deferred),
            "lock_held_by_other_run": False,
            "stopped_early": stopped_early,
            "failed_count": len(failed), "failed_scan_ids": sorted(failed),
            "failed_reasons": failed_reasons,
            "would_count": len(would), "would_scan_ids": sorted(would)}


# ---- dataset classification, retention selection, and its safety rails -----
# These two imports MUST stay below the platform's implicit `from CommonServerPython import
# *`: that star-import binds the bare name `datetime` to the datetime CLASS, and the month
# arithmetic below needs the MODULE. Moved into an import block at the top of the file, every
# month calculation fails on the tenant with AttributeError.
import datetime
import os

PREFIX = _PREFIX

NAME_RE = re.compile(
    r"^%s_(?P<kind>matches|scans)_v(?P<version>\d+)(?:_(?P<rest>.+))?$" % re.escape(PREFIX)
)
# A trailing group that is a PLAUSIBLE YYYYMM (20xx, month 01-12) is the rotation month; a
# host segment of that exact shape is read as a month, because declining to delete is the
# safe misreading. The year/month RANGE is load-bearing: a bare \d{6} reads "110501" as year
# 1105 - older than every retention window - and crashes on a HHMMSS tail like "143025".
MONTH_RE = re.compile(r"^(?:(?P<host>.*?)_)?(?P<month>20\d{2}(?:0[1-9]|1[0-2]))$")

DEFAULT_MIN_QUIET_HOURS = 24.0         # rail 6: newest row must be at least this old
MIN_ALLOWED_QUIET_HOURS = 1.0          # floor; 0 would DISABLE rail 6, not relax it
PRUNE_LOCK_STALE_SECS = 6 * 3600       # a prune judges another run's lock far more slowly

# Dataset-name classification. The tenant's script container has no YARA_LOOKUP_SCHEMA_VER,
# so main() always sets the version explicitly through set_schema_version().
YARA_SCHEMA_VERSION = (os.environ.get("YARA_LOOKUP_SCHEMA_VER",
                                      DEFAULT_LOOKUP_SCHEMA_VERSION).strip()
                       or DEFAULT_LOOKUP_SCHEMA_VERSION)
YARA_OWNED_RE = re.compile(r"^(yara_scanner_(matches|scans|summary)(_.*)?|yara_(matches|scans)_.*)$")
CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans|summary)_v%s(_.*)?$" % re.escape(YARA_SCHEMA_VERSION))

# The value at import, before any set_schema_version() call. The script container is
# long-lived and serves many executions from one process, so main() resets to this rather
# than inheriting whatever version the previous run set.
DEFAULT_SCHEMA_VERSION = YARA_SCHEMA_VERSION


def set_schema_version(ver):
    """Point the classification at a different current schema version.

    os.environ is set too, so render_report's header agrees with the classification.

    NON-NUMERIC INPUT IS REFUSED. A bad value fails in the DANGEROUS direction: "v3" makes
    CURRENT_RE match nothing and stops rail 4 firing, so every live dataset on the tenant
    classifies as legacy and delete_legacy would be pointed at all of it. A too-HIGH whole
    number has the same effect and cannot be detected here; the deletion rails catch that one.

    Set below the version the fleet actually writes, YaraCleanup prunes nothing: everything
    higher lands in the `newer` bucket, which is never deleted.
    """
    global YARA_SCHEMA_VERSION, CURRENT_RE
    clean = str(ver).strip()
    if not clean.isdigit():
        raise ValueError(
            "schema_version must be a whole number — the scanner's YARA_LOOKUP_SCHEMA_VER, "
            'e.g. "2" or "3" — but got %r. Refusing to continue: a non-numeric version '
            "silently reclassifies every live dataset on the tenant as legacy." % (ver,))
    YARA_SCHEMA_VERSION = clean
    CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans|summary)_v%s(_.*)?$"
                            % re.escape(YARA_SCHEMA_VERSION))
    os.environ["YARA_LOOKUP_SCHEMA_VER"] = YARA_SCHEMA_VERSION


def classify_yara_datasets(client):
    """Split the tenant's yara-owned LOOKUP datasets into (current, legacy, newer) by schema
    version. legacy = older/unversioned (safe to prune); newer = a HIGHER _vN than we assume,
    which signals this host's YARA_LOOKUP_SCHEMA_VER is stale — so it must NOT be pruned.

    This is safety rail 4: `newer` is never handed to any selection function."""
    cur_ver = int(YARA_SCHEMA_VERSION) if YARA_SCHEMA_VERSION.isdigit() else None
    ver_re = re.compile(r"_v(\d+)(?:_|$)")
    current, legacy, newer = [], [], []
    datasets = client.get_datasets()
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


_SUMMARY_DS_RE = re.compile(r"^yara_scanner_summary_v\d+_.+$")


def is_summary_dataset(name):
    """True for this pack's OWN summary output, yara_scanner_summary_v<N>_rules_<hash>.

    LABELLING ONLY. It never grants deletion candidacy and is never consulted by any
    selection rail. NAME_RE deliberately refuses to parse a summary dataset - that refusal
    IS safety rail 5, and loosening it would make the pack's own consolidated output an
    ordinary retention candidate. This exists so the inventory stops describing a dataset
    this pack created as "unrecognised", which read as debris of unknown origin.
    """
    return bool(_SUMMARY_DS_RE.match(name or ""))


def parse_dataset_name(name):
    """Parse a dataset name into its parts, or None if it is not YARA-owned.

    Returning None is safety rail 5: anything outside the naming contract can never be a
    deletion candidate. `scan_target` marks a CONSOLIDATED per-scan target
    (yara_scanner_<kind>_v<N>_scan_<slug>) - no month by design, immutable once verified, and
    once consolidation deleted the sources it is the ONLY copy of that scan.
    """
    m = NAME_RE.match(name or "")
    if not m:
        return None
    rest = m.group("rest")
    host, month, scan_target = None, None, False
    if rest:
        if rest == "scan" or rest.startswith("scan_"):
            host, scan_target = rest, True
        else:
            mm = MONTH_RE.match(rest)
            if mm:
                host = mm.group("host") or None
                month = mm.group("month")
            else:
                host = rest
    return {"name": name, "kind": m.group("kind"),
            "version": int(m.group("version")), "host": host, "month": month,
            "scan_target": scan_target,
            # v4 is where matches stopped rotating and became overwrite-per-scan. On v2/v3 an
            # unsuffixed matches dataset really was unrotated and really did grow, so the old
            # warning is still the correct advice for a tenant pinned to those versions.
            "overwrite": (m.group("kind") == "matches" and int(m.group("version")) >= 4
                          and not month and not scan_target)}


def months_between(older_yyyymm, newer_yyyymm):
    """Whole months from older to newer. NEGATIVE if `older` is actually in the future,
    which is how clock skew is detected and refused."""
    o = datetime.date(int(older_yyyymm[:4]), int(older_yyyymm[4:6]), 1)
    n = datetime.date(int(newer_yyyymm[:4]), int(newer_yyyymm[4:6]), 1)
    return (n.year - o.year) * 12 + (n.month - o.month)


def has_rotated_sibling(name, all_names):
    """Does an unsuffixed dataset have rotated siblings for the same kind+host?

    Yes = a pre-rotation leftover: frozen, not growing. No = CONFIG_LOOKUP_ROTATION is
    genuinely "none" and the dataset will grow without bound. The two need opposite advice.
    """
    prefix = name + "_"
    return any(n != name and n.startswith(prefix) and n[len(prefix):].isdigit()
               and len(n) - len(prefix) == 6 for n in (all_names or []))


def select_rotated_for_deletion(current_names, older_than_months, now_yyyymm):
    """Pick rotated datasets older than the window. Returns (candidates, skip_reasons).

    Every safety rail that governs WHAT gets deleted from name alone lives here:
      * the CURRENT month is never a candidate - a scan may be writing to it, and
        delete_dataset mid-scan does not error the scan, it just makes every subsequent
        add_data batch fail with HTTP 400 against a name that no longer exists
      * a FUTURE month is never a candidate - clock skew must not destroy data
      * an UNROTATED dataset is never a candidate - deleting it destroys ALL history for
        that host, not one month: same API call, categorically different blast radius
      * anything outside the naming contract is never a candidate
    """
    candidates, skipped = [], []
    for name in current_names or []:
        info = parse_dataset_name(name)
        if info is None:
            skipped.append("%s: %s" % (name,
                "summary consolidation OUTPUT - this pack's own cross-host rollup, not a "
                "rotation shard and never a retention candidate"
                if is_summary_dataset(name) else "not a YARA dataset name"))
            continue
        if info["scan_target"]:
            skipped.append("%s: per-scan consolidated target - consolidation OUTPUT, not a "
                           "rotation shard, and after the source shards were deleted it is "
                           "the only copy of that scan" % name)
            continue
        if info["overwrite"]:
            skipped.append("%s: permanent per-host matches dataset - the scanner REPLACES it "
                           "wholesale at the start of every scan, so it is bounded by that "
                           "overwrite rather than by rotation, and CONFIG_LOOKUP_ROTATION "
                           "does not apply to it" % name)
            continue
        if not info["month"]:
            if has_rotated_sibling(name, current_names):
                skipped.append(
                    "%s: abandoned pre-rotation dataset (rotated siblings exist) - "
                    "frozen, not growing" % name)
            else:
                skipped.append(
                    '%s: not rotated (no YYYYMM) - set CONFIG_LOOKUP_ROTATION="monthly" '
                    "in the scanner so this dataset stops growing" % name)
            continue
        if info["month"] == now_yyyymm:
            skipped.append("%s: current month - a scan may be writing to it" % name)
            continue
        age = months_between(info["month"], now_yyyymm)
        if age < 0:
            skipped.append("%s: dated in the future (clock skew?)" % name)
            continue
        if age <= older_than_months:
            skipped.append("%s: %d month(s) old, inside the %d-month window"
                           % (name, age, older_than_months))
            continue
        candidates.append(name)
    return candidates, skipped


def filter_recently_written(client, candidates, min_quiet_secs, now_ms, log=print):
    """Safety rail 6. Drop any candidate whose newest row is younger than min_quiet_secs.
    Returns (survivors, skip_reasons).

    A month label says nothing about liveness: the instant the calendar rolls over, every
    prior month's shard looks arbitrarily old, including one a scan is still writing to. This
    rail asks the question that matters instead. A query error SKIPS (keeps) the dataset."""
    survivors, skipped = [], []
    for name in candidates:
        try:
            rows = client.xql("dataset = %s | comp max(event_timestamp_ms) as newest" % name, limit=5) or []
            newest = rows[0].get("newest") if rows else None
            newest = int(newest) if newest is not None else None
        except Exception as e:
            skipped.append("%s: could not check recency (%s) - skipping to be safe" % (name, e))
            continue
        if newest is not None and (now_ms - newest) < min_quiet_secs * 1000:
            skipped.append("%s: newest row is only %.1fh old - a scan may still be writing "
                           "to it, skipping despite month age" % (name, (now_ms - newest) / 3_600_000.0))
            continue
        survivors.append(name)
    return survivors, skipped


def filter_unconsolidated(client, candidates, log=print):
    """Safety rail 7. Drop any candidate still holding a scan_id that consolidation has not
    verified into a per-scan target. Returns (survivors, skip_reasons).

    A permanently stuck scan (row ceiling exceeded, or a merge never run) blocks
    consolidation's own deletion pass forever. This prune is a separate path and would
    otherwise delete that shard on month age alone - the scan's only copy. A query error
    SKIPS (keeps) the dataset."""
    survivors, skipped = [], []
    for name in candidates:
        info = parse_dataset_name(name)
        if info is None:
            survivors.append(name)  # not a YARA dataset name; not this function's job to gate
            continue
        try:
            rows = client.xql("dataset = %s | comp count() as n by scan_id" % name, limit=10000) or []
        except Exception as e:
            skipped.append("%s: could not check consolidation state (%s) - skipping to be safe" % (name, e))
            continue
        stuck = []
        for r in rows:
            sid, n = r.get("scan_id"), int(r.get("n") or 0)
            if not sid or n <= 0:
                continue
            target = target_name(info["kind"], str(info["version"]), sid)
            try:
                tcount_rows = client.xql("dataset = %s | comp count() as n" % target, limit=5) or []
                tcount = int(tcount_rows[0].get("n", 0)) if tcount_rows else 0
            except Exception:
                tcount = -1  # target doesn't exist or errored - definitely not verified
            if tcount != n:
                stuck.append(sid)
        if stuck:
            skipped.append("%s: still holds unconsolidated scan(s) %s (row_ceiling_exceeded, "
                           "count_mismatch, or simply never run) - skipping, would lose data"
                           % (name, ", ".join(stuck[:5])))
            continue
        survivors.append(name)
    return survivors, skipped


def select_legacy_for_deletion(legacy_names, newer_names=(), now_yyyymm=None):
    """Legacy = older/unversioned schema. Returns (candidates, skip_reasons), the same shape
    as select_rotated_for_deletion, because the same name-derived rails apply.

    The `newer` bucket is deliberately NOT accepted: a host on a stale schema version must
    never delete a future schema's data. "Legacy" is only as trustworthy as the
    schema_version argument - set one version too high and every live dataset reclassifies as
    legacy - so callers must still run the survivors through filter_recently_written and
    filter_unconsolidated, the only two rails that can see an endpoint still writing.
    """
    if newer_names:
        return [], ["refusing blanket legacy deletion: %d dataset(s) are on a NEWER schema "
                    "version (%s) - the assumed current version is stale, so this 'legacy' "
                    "classification cannot be trusted"
                    % (len(newer_names), ", ".join(sorted(newer_names)[:5]))]
    candidates, skipped = [], []
    for name in legacy_names or []:
        info = parse_dataset_name(name)
        # The rails below must NOT be conditional on `info` parsing. The oldest legacy names
        # predate the _vN segment entirely ("yara_scanner_scans_hostA") and hold a host's
        # whole pre-rotation history. Derive the two facts the rails need - per-scan target,
        # and month suffix - from the name itself when the full contract will not parse.
        if info is not None:
            is_scan_target, month = info["scan_target"], info["month"]
        elif str(name).startswith(PREFIX + "_"):
            # Inside the yara_scanner_* contract but missing the _vN segment: still a shard
            # whose shape we can read, so the rails apply.
            is_scan_target = "_scan_" in name
            m = MONTH_RE.match(name.rsplit("_", 1)[-1]) if "_" in name else None
            month = m.group("month") if m else None
        else:
            # Pre-contract naming (no yara_scanner_ prefix at all): the shape cannot be read,
            # so no unsuffixed-ness is inferred - that would make delete_legacy vacuous for the
            # oldest data it exists to remove. Rails 6 and 7 run after this and are the last
            # line of defence for these.
            candidates.append(name)
            continue

        if is_scan_target:
            skipped.append("%s: per-scan consolidated target - consolidation OUTPUT, not a "
                           "legacy leftover" % name)
            continue
        if not month:
            skipped.append("%s: unsuffixed - holds ALL pre-rotation history for that host, "
                           "so it is never a blanket candidate; delete it by name if you "
                           "really want the space" % name)
            continue
        if now_yyyymm:
            if month == now_yyyymm:
                skipped.append("%s: current month - a scan may be writing to it" % name)
                continue
            if months_between(month, now_yyyymm) < 0:
                skipped.append("%s: dated in the future (clock skew?)" % name)
                continue
        candidates.append(name)
    return candidates, skipped


def render_report(current, legacy, newer, now_yyyymm):
    """Human-readable inventory. Ages are whole months."""
    schema = os.environ.get("YARA_LOOKUP_SCHEMA_VER", "4")
    lines = ["YARA lookup datasets (schema v%s current, now %s)" % (schema, now_yyyymm), ""]
    lines.append("%-52s %-8s %-14s %6s" % ("dataset", "kind", "host", "age"))
    lines.append("-" * 84)
    unrotated, abandoned, consolidated, overwritten = [], [], [], []
    for name in current:
        info = parse_dataset_name(name)
        if info is None:
            label = ("(summary - this pack's own rollup, never a candidate)"
                     if is_summary_dataset(name) else "(unrecognised - never a candidate)")
            lines.append("%-52s %s" % (name[:52], label))
            continue
        if info["scan_target"]:
            age = "scan"
            consolidated.append(name)
        elif info["overwrite"]:
            age = "live"
            overwritten.append(name)
        elif info["month"]:
            age = "%dmo" % months_between(info["month"], now_yyyymm)
        else:
            age = "frozen" if has_rotated_sibling(name, current) else "n/a"
            (abandoned if age == "frozen" else unrotated).append(name)
        lines.append("%-52s %-8s %-14s %6s"
                     % (name[:52], info["kind"], (info["host"] or "-")[:14], age))
    if not current:
        lines.append("(none)")
    if legacy:
        lines += ["", "legacy schema (deletable with --delete-legacy):"]
        lines += ["  " + n for n in legacy]
    if newer:
        lines += ["", "NEWER schema - never deleted by this tool. Your "
                      "YARA_LOOKUP_SCHEMA_VER may be stale:"]
        lines += ["  " + n for n in newer]
    if consolidated:
        lines += [
            "",
            "%d dataset(s) are per-scan CONSOLIDATED TARGETS (…_scan_<id>). They are"
            % len(consolidated),
            "      consolidation OUTPUT: unrotated by design, finished, not growing, and",
            "      often a scan's only surviving copy. Never a cleanup candidate.",
        ]
    if overwritten:
        lines += [
            "",
            "%d dataset(s) are PERMANENT per-host matches datasets. The scanner replaces"
            % len(overwritten),
            "      each one wholesale at the start of every scan, so they hold exactly one",
            "      scan and are bounded by that overwrite, not by rotation. An unsuffixed",
            "      name is their correct steady state - CONFIG_LOOKUP_ROTATION governs the",
            "      SCANS datasets only and cannot change these. Never a cleanup candidate.",
            "      A matches dataset that DOES carry a month predates this model and is",
            "      ordinary deletable debris once it ages out of the window.",
        ]
    if abandoned:
        lines += [
            "",
            "NOTE: %d dataset(s) predate rotation (rotated siblings exist for the same"
            % len(abandoned),
            "      host). They are frozen, not growing - writes moved to the dated names.",
            "      This tool will not delete them: an unsuffixed dataset holds ALL",
            "      pre-rotation history for that host, so removing one is a bigger",
            "      decision than dropping a month. Delete manually if you want the space.",
        ]
    if unrotated:
        lines += [
            "",
            "WARNING: %d dataset(s) are NOT rotated and will grow without bound."
            % len(unrotated),
            "         add_data merge time scales with dataset SIZE, so these eventually",
            "         exceed any client timeout and go write-dead. Set",
            '         CONFIG_LOOKUP_ROTATION="monthly" in the scanner.',
            "         This tool deletes whole datasets only and will not touch them.",
        ]
    return "\n".join(lines)


# ---- cleanup run-log --------------------------------------------------------
# YaraCleanup's own record, deliberately NOT yara_scanner_consolidation_runs: a row there
# would satisfy the Consolidation Run Health widget's liveness check and mask a dead merge.
# War Room entries are per-run and not queryable, and this is the one automation in the pack
# whose action cannot be undone.
_CLEANUP_RUNS_DATASET = "yara_scanner_cleanup_runs"
_CLEANUP_RUNS_SCHEMA = {
    "run_ts_ms": "number", "mode": "text", "schema_version": "text",
    "older_than_months": "number", "delete_legacy": "text", "min_quiet_hours": "number",
    "selected_count": "number", "deleted_count": "number", "failed_count": "number",
    "skipped_count": "number", "deleted": "text", "skipped_reasons": "text",
    "lock_taken_over": "text",
}


def record_cleanup_run(client, result, now_ms=None, log=print):
    """Best-effort: write ONE row per prune pass. Every exception is caught and only logged -
    failing to write this row must never replace the run's real outcome."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    otm = result.get("older_than_months")
    row = {
        "run_ts_ms": now_ms,
        "mode": "dry_run" if result.get("dry_run") else "executed",
        "schema_version": str(result.get("schema_version", "")),
        # -1, not null: "no retention window was given" is a distinct, meaningful state and a
        # numeric column cannot carry None on this API.
        "older_than_months": int(otm) if otm is not None else -1,
        "delete_legacy": str(bool(result.get("delete_legacy"))),
        "min_quiet_hours": float(result.get("min_quiet_hours") or 0),
        "selected_count": int(result.get("selected_count", 0) or 0),
        "deleted_count": int(result.get("deleted_count", 0) or 0),
        "failed_count": int(result.get("failed_count", 0) or 0),
        "skipped_count": int(result.get("skipped_count", 0) or 0),
        "deleted": json.dumps(result.get("deleted", []))[:4000],
        "skipped_reasons": json.dumps(result.get("skipped", []))[:8000],
        "lock_taken_over": str(bool(result.get("lock_taken_over"))),
    }
    try:
        client.create_lookup_dataset(_CLEANUP_RUNS_DATASET, _CLEANUP_RUNS_SCHEMA)
        client.add_lookup_data(_CLEANUP_RUNS_DATASET, [row])
    except Exception as e:
        log("could not record cleanup run outcome: %s" % e)


# ---- orchestration ----------------------------------------------------------

def report_datasets(client, now_yyyymm=None):
    """READ-ONLY inventory of every yara_scanner_* lookup dataset. Issues exactly one API
    call (the dataset listing) and never writes or deletes.

    Returns the rendered text under "report", plus the same information structured for
    context in three states that need different advice:
      overwrite     a permanent per-host matches dataset - replaced wholesale at the start
                    of every scan, so unsuffixed is its correct steady state
      frozen        unsuffixed, but rotated siblings exist - a pre-rotation leftover
      not_rotated   unsuffixed with no rotated siblings - rotation is off and it will grow
      consolidated  a per-scan target (…_v<N>_scan_<slug>) - finished and immutable by design
    """
    now_yyyymm = now_yyyymm or datetime.date.today().strftime("%Y%m")
    current, legacy, newer = classify_yara_datasets(client)
    datasets, frozen, not_rotated, consolidated, overwrite = [], [], [], [], []
    for name in current:
        info = parse_dataset_name(name)
        if info is None:
            datasets.append({"name": name, "kind": "", "host": "", "month": "",
                             "age_months": None, "state": "unrecognised"})
            continue
        if info["scan_target"]:
            state, age = "consolidated", None
            consolidated.append(name)
        elif info["overwrite"]:
            state, age = "overwrite", None
            overwrite.append(name)
        elif info["month"]:
            state, age = "rotated", months_between(info["month"], now_yyyymm)
        else:
            age = None
            if has_rotated_sibling(name, current):
                state = "frozen"
                frozen.append(name)
            else:
                state = "not_rotated"
                not_rotated.append(name)
        datasets.append({"name": name, "kind": info["kind"], "host": info["host"] or "",
                         "month": info["month"] or "", "age_months": age, "state": state})
    return {
        "now_yyyymm": now_yyyymm,
        "schema_version": YARA_SCHEMA_VERSION,
        "report": render_report(current, legacy, newer, now_yyyymm),
        "datasets": datasets,
        "current_count": len(current),
        "frozen": frozen, "frozen_count": len(frozen),
        "not_rotated": not_rotated, "not_rotated_count": len(not_rotated),
        "consolidated": consolidated, "consolidated_count": len(consolidated),
        "overwrite": overwrite, "overwrite_count": len(overwrite),
        "legacy": legacy, "legacy_count": len(legacy),
        "newer": newer, "newer_count": len(newer),
    }


def _live_rails(client, names, min_quiet_hours, now_ms, log):
    """Rails 6 and 7 - the only two that query the tenant, and so the only two that can see
    an endpoint still WRITING to a dataset whose name says it is ancient. Both fail closed (a
    query error keeps the dataset), and both apply to the rotated and the legacy lists
    alike: a name-derived classification is never on its own enough to delete."""
    names, s1 = filter_recently_written(client, names, min_quiet_hours * 3600, now_ms, log=log)
    names, s2 = filter_unconsolidated(client, names, log=log)
    return names, s1 + s2


def prune_datasets(client, older_than_months=None, delete_legacy=False,
                   min_quiet_hours=DEFAULT_MIN_QUIET_HOURS, force=False, execute=False,
                   now_ms=None, now_yyyymm=None, log=print, holder="YaraCleanup"):
    """Retention pruning: DELETES WHOLE DATASETS when execute is True.

    Four properties it is required to have:

    * No retention window and no legacy flag -> nothing happens, and it says so, before any
      API call is made. A bare invocation must never delete.
    * A real deletion pass takes the consolidation lock BEFORE evaluating the rails and
      releases it in a finally: rails 6 and 7 are point-in-time checks, and a consolidation
      pass starting between the checks and the deletes would race them. A DRY RUN never takes
      the lock. Because a wrong takeover here is irreversible, this caller treats an
      unreadable lock row as HELD and judges staleness on a much longer window.
    * EVERY candidate passes the same rails, on the age path and the legacy path alike.
      `legacy` is derived from the schema_version argument, and only the live rails can tell
      real old-schema leftovers from "my assumed version is one too high, so the whole live
      tenant now looks legacy".
    * Every skipped candidate's reason is returned, including the buckets that were never
      candidates (`newer` always, `legacy` when delete_legacy is false). A dataset silently
      not deleted is indistinguishable from a bug.
    """
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    now_yyyymm = now_yyyymm or datetime.date.today().strftime("%Y%m")
    result = {
        "dry_run": not execute,
        "nothing_requested": False,
        "lock_held_by_other_run": False,
        "lock_taken_over": False,
        "lock_takeover_reason": "",
        "older_than_months": older_than_months,
        "delete_legacy": bool(delete_legacy),
        "min_quiet_hours": float(min_quiet_hours),
        "schema_version": YARA_SCHEMA_VERSION,
        "selected": [], "selected_count": 0,
        "deleted": [], "deleted_count": 0,
        "failed": [], "failed_count": 0,
        "skipped": [], "skipped_count": 0,
        "newer": [], "newer_count": 0,
    }

    if older_than_months is None and not delete_legacy:
        result["nothing_requested"] = True
        log("no retention window (older_than_months) and delete_legacy is false — nothing "
            "selected, nothing deleted")
        return result

    takeovers = []
    if execute and not acquire_consolidation_lock(
            client, log=log, now_ms=now_ms, holder=holder,
            stale_after_secs=PRUNE_LOCK_STALE_SECS, unreadable_is_held=True,
            on_takeover=takeovers.append):
        result["lock_held_by_other_run"] = True
        log("consolidation lock is held by another run — deleting nothing this pass")
        return result
    if takeovers:
        # Reported, never silent: this pass proceeded while another run's lock marker was in
        # place, and the operator must be able to tell it apart from an uncontended pass.
        result["lock_taken_over"] = True
        result["lock_takeover_reason"] = takeovers[0]

    try:
        current, legacy, newer = classify_yara_datasets(client)   # rail 4 lives here
        targets, skipped = [], []
        result["newer"], result["newer_count"] = newer, len(newer)
        for n in newer:
            skipped.append("%s: NEWER schema version than this code understands - never "
                           "pruned (rail 4); if that is unexpected, the schema_version "
                           "argument (currently v%s) is stale" % (n, YARA_SCHEMA_VERSION))
        if older_than_months is not None:
            t, s = select_rotated_for_deletion(current, older_than_months, now_yyyymm)
            skipped += s
            t, s2 = _live_rails(client, t, min_quiet_hours, now_ms, log)
            skipped += s2
            targets += t
        if delete_legacy:
            t, s = select_legacy_for_deletion(legacy, newer, now_yyyymm)
            skipped += s
            t, s2 = _live_rails(client, t, min_quiet_hours, now_ms, log)
            skipped += s2
            targets += t
        else:
            for n in legacy:
                skipped.append("%s: legacy schema, but delete_legacy was not set" % n)

        result["selected"] = targets
        result["selected_count"] = len(targets)
        result["skipped"] = skipped
        result["skipped_count"] = len(skipped)
        for s in skipped:
            log("  skip  %s" % s)

        if not execute:
            log("DRY RUN — %d dataset(s) would be deleted, nothing touched" % len(targets))
            return result

        for name in targets:
            try:
                client.delete_dataset(name, force=force)
                result["deleted"].append(name)
                log("  deleted %s" % name)
            except Exception as e:
                # Continue: one dataset with dependencies must not strand the whole cleanup.
                result["failed"].append({"dataset": name, "error": str(e)[:200]})
                log("  FAILED  %s: %s" % (name, e))
        result["deleted_count"] = len(result["deleted"])
        result["failed_count"] = len(result["failed"])
        record_cleanup_run(client, result, now_ms=now_ms, log=log)
        return result
    finally:
        if execute:
            release_consolidation_lock(client, log=log)


# ---- API client -------------------------------------------------------------
# Calls this tenant's own public API over HTTPS, signed with the Advanced (HMAC) credentials
# from the CONFIGURATION block at the top of this file. No generic REST bridge command
# (demisto-api-post / core-api-post) is registered on this tenant, so the automation carries
# its own credentials rather than borrowing an integration instance's.


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


# ---- entry point ------------------------------------------------------------

# ---------------------------------------------------------------- full consolidation ----
# The mode this automation now performs. Its sibling YaraConsolidateSummary keeps four
# columns per (host, rule); this keeps EVERY column of every matched-file row. Same sources,
# same grouping key, same reconciliation - the only difference is fidelity, which is exactly
# the choice being offered to the operator.
DEFAULT_FULL_ROW_CEILING = 60000   # below the ~70k rows where lookup writes were seen to die


def consolidate_full(client, ver="4", only_scan_ids=None, retention_hours=24.0,
                     row_ceiling=DEFAULT_FULL_ROW_CEILING, execute=False,
                     now_ms=None, log=print):
    """Group every host's full matched-file rows for one ruleset into ONE dataset.

    Reads the live per-host matches datasets and NEVER deletes them - they are permanent,
    overwritten by the next scan on that host, and remain the deep-dive source. Grouping is
    by the ruleset hash carried at the end of every scan_id. Re-running reconciles on
    scan_id sets: unchanged hosts are left alone, a re-scanned host's old rows are dropped
    and its new ones written, and a run with nothing changed is a verified no-op.
    """
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    cutoff_ms = float(retention_hours) * 3600 * 1000
    only = set(only_scan_ids or []) or None
    written, skipped, failed = [], [], []
    result = {"dry_run": not execute, "written": written, "skipped": skipped,
              "failed": failed, "rows_written": 0, "hosts": 0, "groups": 0,
              "lock_held_by_other_run": False}

    if execute and not acquire_consolidation_lock(
            client, log=log, now_ms=now_ms, holder="YaraConsolidateApply",
            unreadable_is_held=True):
        result["lock_held_by_other_run"] = True
        return result
    try:
        names = _list_yara_datasets(client)
        existing = set(names)
        match_ds = [n for n in names if _matches_shard_for_read(n, ver)]
        scans_ds = [n for n in names
                    if (parse_shard(n) or {}).get("kind") == "scans"
                    and str((parse_shard(n) or {}).get("ver")) == str(ver)]
        log("schema v%s: %d matches shard(s), %d scans shard(s)" % (ver, len(match_ds), len(scans_ds)))

        tmap = build_terminal_map({d: _rows_of(d, client) for d in scans_ds}, None)

        # 1. every full row, bucketed by the scan that produced it
        by_scan, newest = {}, {}
        for ds in match_ds:
            try:
                rows = _rows_of(ds, client)
            except Exception as e:
                skipped.append("%s: unreadable (%s)" % (ds, str(e)[:110]))
                continue
            for r in rows:
                sid = r.get("scan_id")
                if not sid:
                    continue
                by_scan.setdefault(sid, []).append(r)
                ts = int(r.get("event_timestamp_ms") or 0)
                newest[sid] = max(newest.get(sid, 0), ts)

        # 2. gate per scan, then bucket the survivors by ruleset
        groups = {}
        for sid in sorted(by_scan):
            if only and sid not in only:
                continue
            terminal = bool(tmap.get(sid))
            aged = bool(newest.get(sid)) and (now_ms - newest[sid]) >= cutoff_ms
            if not terminal and not aged:
                skipped.append("%s: scan still in progress - left alone" % str(sid)[:34])
                continue
            rh = rule_hash_of(sid)
            if not rh:
                skipped.append("%s: no ruleset hash in scan_id - cannot be grouped" % str(sid)[:34])
                continue
            g = groups.setdefault(rh, {"rows": [], "sids": set(), "hosts": set()})
            g["rows"].extend(by_scan[sid])
            g["sids"].add(sid)
            g["hosts"].update(r.get("hostname") for r in by_scan[sid])

        # 3. one dataset per ruleset, reconciled on scan_id sets
        schema = matches_schema_for(ver)
        for rh in sorted(groups):
            g = groups[rh]
            target = full_target_for_rules(ver, rh)
            rows = [_coerce_row(r, schema) for r in g["rows"]]
            desired = set(g["sids"])
            label = "rules %s" % rh

            if row_ceiling and len(rows) > row_ceiling:
                failed.append("%s: %d row(s) exceeds the full-consolidation ceiling of %d - "
                              "REFUSED rather than half-filling %s. Use "
                              "YaraConsolidateSummary for a fleet this size, or raise "
                              "row_ceiling deliberately."
                              % (label, len(rows), row_ceiling, target))
                continue

            if not execute:
                written.append("%s: WOULD write %d full row(s) from %d host(s) / %d scan(s) "
                               "-> %s" % (label, len(rows), len(g["hosts"]), len(desired), target))
                result["rows_written"] += len(rows)
                result["hosts"] = max(result["hosts"], len(g["hosts"]))
                continue

            held = set()
            if target in existing:
                try:
                    for r in (client.xql("dataset = %s | comp count() as n by scan_id" % target,
                                         limit=10000) or []):
                        if r.get("scan_id"):
                            held.add(str(r.get("scan_id")))
                except Exception as e:
                    failed.append("%s: could not read existing target %s (%s) - NOT written"
                                  % (label, target, str(e)[:100]))
                    continue
            stale = sorted(held - desired)
            fresh = sorted(desired - held)
            if held and not stale and not fresh:
                skipped.append("%s: target already current for %d scan(s) across %d host(s) "
                               "- verified, not rewritten" % (label, len(desired), len(g["hosts"])))
                continue
            try:
                client.create_lookup_dataset(target, schema)
                removed = 0
                if stale:
                    # Against this automation's OWN consolidated output only. Source host
                    # datasets are never touched - they are the deep-dive source.
                    reply = client.remove_lookup_data(
                        target, [[{"field": "scan_id", "operator": "eq", "value": x}]
                                 for x in stale])
                    removed = int((reply or {}).get("deleted") or 0)
                add_rows = [r for r in rows if str(r.get("scan_id")) in set(fresh)]
                added, ok = 0, True
                for i in range(0, len(add_rows), _WRITE_BATCH):
                    got = _added(client.add_lookup_data(target, add_rows[i:i + _WRITE_BATCH]))
                    if got <= 0:
                        ok = False
                        break
                    added += got
                if ok:
                    written.append("%s: wrote %d full row(s) for %d new scan(s), dropped %d "
                                   "stale row(s) -> %s (%d host(s) total)"
                                   % (label, added, len(fresh), removed, target, len(g["hosts"])))
                    result["rows_written"] += added
                    result["hosts"] = max(result["hosts"], len(g["hosts"]))
                else:
                    failed.append("%s: write to %s returned 0 rows added after %d - re-run to "
                                  "retry (host datasets untouched)" % (label, target, added))
            except Exception as e:
                failed.append("%s: %s - host datasets untouched" % (label, str(e)[:140]))
        result["groups"] = len(groups)
    finally:
        if execute:
            try:
                release_consolidation_lock(client, log=log)
            except Exception as e:
                log("lock release failed: %s" % e)
    return result



def main():
    args = demisto.args()
    scan_ids = argToList(args.get("scan_id")) or None
    ver = str(args.get("schema_version") or DEFAULT_LOOKUP_SCHEMA_VERSION).strip()
    retention_hours = float(args.get("retention_hours") or 24.0)
    rc = args.get("row_ceiling")
    row_ceiling = int(rc) if rc not in (None, "") else DEFAULT_FULL_ROW_CEILING
    execute = bool(argToBoolean(args.get("execute"))) if args.get("execute") not in (None, "") else False

    log_lines = []
    client = None
    try:
        client = CoreApiClient()
        # Recorded BEFORE the merge. The platform kills a task that overruns its timeout and
        # a kill runs no Python, so the terminal row below is unreachable in exactly the case
        # worth diagnosing. A "started" row with no terminal row is that state, made queryable.
        if execute:
            record_consolidation_run(client, "started", log=lambda *a: None)
        result = consolidate_full(client, ver=ver, only_scan_ids=scan_ids,
                                  retention_hours=retention_hours, row_ceiling=row_ceiling,
                                  execute=execute, log=lambda m: log_lines.append(m))
    except Exception as ex:
        if client is not None:
            record_consolidation_run(client, "crashed", error_message=str(ex), log=lambda *a: None)
        return_error("YaraConsolidateApply failed: {}".format(ex))
        return

    if execute:
        record_consolidation_run(
            client, "partial_failure" if result["failed"] else "success",
            result={"consolidated_count": len(result["written"]),
                    "failed_count": len(result["failed"]),
                    "failed_scan_ids": [], "failed_reasons": {}},
            log=lambda *a: None)

    if result.get("lock_held_by_other_run"):
        lines = ["Skipped this pass - the consolidation lock is held by another concurrent run."]
    else:
        head = "DRY RUN - nothing was created or written." if result["dry_run"] else "EXECUTED."
        lines = ["%s  FULL consolidation: every column of every matched-file row." % head,
                 "dataset(s): %d | rows: %d | skipped: %d | failed: %d"
                 % (len(result["written"]), result["rows_written"],
                    len(result["skipped"]), len(result["failed"])),
                 "host matches datasets deleted: 0 (source data is never deleted - they are "
                 "permanent and are the deep-dive source; only this automation's own "
                 "consolidated rows are reconciled)"]
        for label, items in (("WRITTEN", result["written"]), ("SKIPPED", result["skipped"]),
                             ("FAILED", result["failed"])):
            if items:
                lines += ["", "%s:" % label] + ["  %s" % x for x in items]

    if log_lines:
        lines += ["", "lock events:"] + ["  %s" % m for m in log_lines
                                         if "lock" in m.lower()]
    return_results(CommandResults(readable_output="\n".join(lines),
                                  outputs_prefix="Yara.ConsolidateApply",
                                  outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
