"""YaraCleanup - retention pruning for YARA lookup datasets. DELETES WHOLE DATASETS.

DRY RUN BY DEFAULT: without execute=true it reports what it would delete and deletes nothing,
so a bare invocation can never lose data. The readable output always states which mode ran.

Seven safety rails apply to every candidate on BOTH selection paths - the retention window
and delete_legacy - and none of them is optional: never the current month, never a future
month, never an unsuffixed dataset, never a newer schema version, never a name outside the
yara_scanner_* contract, never a dataset written to within min_quiet_hours, and never a
dataset still holding a scan consolidation has not verified. An executed pass takes the same
lock YaraConsolidateApply uses, before the rails are evaluated, and records itself in
yara_scanner_cleanup_runs; a dry run takes no lock and records nothing.

ARGUMENTS
  older_than_months  Delete rotated datasets older than N whole months. No default, on
                     purpose: omit it and delete_legacy, and nothing is selected at all.
  delete_legacy      Also delete datasets on an older or unversioned schema. Every rail
                     applies to these too, because "legacy" is derived from schema_version.
  execute            THE DELETION OPT-IN. Leave false for a dry run. true really deletes -
                     whole datasets, with no undo.
  min_quiet_hours    Never delete a dataset whose newest row is younger than this, whatever
                     its month label says. Defaults to DEFAULT_MIN_QUIET_HOURS and is floored
                     at MIN_ALLOWED_QUIET_HOURS: 0 disables the rail rather than relaxing it.
  force              Pass force=true through to delete_dataset, for datasets with
                     dependencies.
  schema_version     The scanner's current lookup schema version. Must be a whole number. It
                     decides what counts as current, legacy and newer. Defaults to
                     DEFAULT_LOOKUP_SCHEMA_VERSION.
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

# Lookup schema version assumed when the schema_version argument is left empty. Set it to the
# version the fleet actually writes: too low and nothing is ever pruned, too high and live
# datasets are classified as legacy.
DEFAULT_LOOKUP_SCHEMA_VERSION = "4"

# Safety rail 6, the recency floor. min_quiet_hours=0 would DISABLE the rail rather than
# relax it, so the argument is floored at MIN_ALLOWED_QUIET_HOURS.
DEFAULT_MIN_QUIET_HOURS = 24.0
MIN_ALLOWED_QUIET_HOURS = 1.0

# A prune judges another run's lock far more conservatively than consolidation does, because
# deleting while a merge is mid-copy cannot be undone.
PRUNE_LOCK_STALE_SECS = 6 * 3600
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
DEFAULT_QUIET_SECS = 900               # settle window a finished scan must clear
DEFAULT_ROW_CEILING = 2_000_000        # per-scan row cap; above it a scan is refused
DEFAULT_ABANDONED_SECS = 24 * 3600     # silence after which a non-terminal scan is merged
DELETE_CONCURRENCY = 12                # parallel delete_dataset calls
_WRITE_BATCH = 500                     # rows per add_data call
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
DEFAULT_LOCK_STALE_SECS = 20 * 60   # a run cannot outlive the 900s task timeout
# One pass consolidates at most this many scans, so it finishes inside that 900s
# timeout instead of being killed mid-merge still holding the lock.
# 20 shipped with no measurement behind it. Live on emea (2026-08-21): 5 scans took 638s -
# 71% of the 900s task timeout - and 20 would be killed around scan 7, reproducing the exact
# stuck-lock incident this bound exists to prevent. A 4-scan pass measured at 403s (45%)
# completed cleanly; keep real margin, not none.
DEFAULT_MAX_SCANS_PER_PASS = 4


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


# Dataset-name classification. The tenant's script container has no YARA_LOOKUP_SCHEMA_VER,
# so main() always sets the version explicitly through set_schema_version().
YARA_SCHEMA_VERSION = (os.environ.get("YARA_LOOKUP_SCHEMA_VER",
                                      DEFAULT_LOOKUP_SCHEMA_VERSION).strip()
                       or DEFAULT_LOOKUP_SCHEMA_VERSION)
YARA_OWNED_RE = re.compile(r"^(yara_scanner_(matches|scans|summary|full)(_.*)?|yara_(matches|scans)_.*)$")
CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans|summary|full)_v%s(_.*)?$" % re.escape(YARA_SCHEMA_VERSION))

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
    CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans|summary|full)_v%s(_.*)?$"
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


_PACK_OUTPUT_DS_RE = re.compile(r"^yara_scanner_(?:summary|full)_v\d+_.+$")


def is_pack_output_dataset(name):
    """True for this pack's OWN consolidated output - summary_v<N>_rules_<hash> (compact) or
    full_v<N>_rules_<hash> (every column).

    LABELLING ONLY. It never grants deletion candidacy and is never consulted by any
    selection rail. NAME_RE deliberately refuses to parse a summary dataset - that refusal
    IS safety rail 5, and loosening it would make the pack's own consolidated output an
    ordinary retention candidate. This exists so the inventory stops describing a dataset
    this pack created as "unrecognised", which read as debris of unknown origin.
    """
    return bool(_PACK_OUTPUT_DS_RE.match(name or ""))


def parse_dataset_name(name):
    """Parse a dataset name into its parts, or None if it is not YARA-owned.

    Returning None is safety rail 5: anything outside the naming contract can never be a
    deletion candidate. `scan_target` marks a per-scan target
    (yara_scanner_<kind>_v<N>_scan_<slug>) left behind by the RETIRED per-scan merge - no
    month by design, immutable once verified, and no longer produced by anything: full and
    summary consolidation write one dataset per RULESET instead. Never a candidate all the
    same, because on a tenant that ran the old merge it can be that scan's only copy.
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
                "%s consolidation OUTPUT - this pack's own cross-host rollup, not a "
                "rotation shard and never a retention candidate"
                % ("full" if "_full_v" in name else "summary")
                if is_pack_output_dataset(name) else "not a YARA dataset name"))
            continue
        if info["scan_target"]:
            skipped.append("%s: per-scan consolidated target from the retired per-scan "
                           "merge - consolidation OUTPUT, not a rotation shard, and on a "
                           "tenant that ran that merge it can be the only copy of that "
                           "scan" % name)
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
    """Safety rail 7. Drop any candidate still holding a scan_id that the retired per-scan
    merge never verified into a per-scan target. Returns (survivors, skip_reasons).

    Consolidation has no deletion pass of its own any more, so this rail is the only thing
    standing between an aged month-suffixed shard and YaraCleanup, which really does delete.
    A permanently stuck scan (row ceiling exceeded, or the merge never run) would otherwise
    be dropped on month age alone - the scan's only copy. A query error SKIPS (keeps) the
    dataset."""
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


DATASET_TYPES = ("host_matches", "host_scans", "consolidated_full", "consolidated_summary",
                 "retired_scan_target", "internal")

_TYPE_TITLES = (
    ("host_matches",         "PER-HOST FINDINGS  - latest scan per host, replaced wholesale "
                             "by the next scan"),
    # Deliberately does NOT name the rotation setting. That string appears only in the
    # not_rotated advice below, where it is actionable; printing it on every run tells an
    # operator whose rotation is already correct to go and change it.
    ("host_scans",           "PER-HOST SCAN LOG  - lifecycle rows, append-only, one dataset "
                             "per host per retained month"),
    ("consolidated_summary", "CONSOLIDATED (SUMMARY) - one row per (host, rule) per ruleset, "
                             "fleet-wide"),
    ("consolidated_full",    "CONSOLIDATED (FULL)    - every column of every matched-file row "
                             "per ruleset, fleet-wide"),
    ("retired_scan_target",  "RETIRED PER-SCAN TARGETS - from the withdrawn per-scan merge; "
                             "nothing produces these now"),
    # NOT the pack's own lock or run record. yara_scanner_consolidation_lock,
    # yara_scanner_consolidation_runs and yara_scanner_cleanup_runs all fail YARA_OWNED_RE,
    # so no inventory ever lists them and this bucket has never held one. It is
    # dataset_type's FALLBACK - a yara-owned name none of the rows above matched - and
    # calling it "the consolidation lock and run record" had the By type table asserting a
    # provenance for a dataset whose own record says its origin is unknown.
    ("internal",             "UNPARSED NAME - a yara_scanner_* name none of the rows above "
                             "matched; the pack's lock and run-record datasets are not "
                             "yara-owned and never appear here"),
)

_COUNT_ONLY_TYPES = ("host_scans",)

def dataset_type(name):
    """Which of DATASET_TYPES this dataset is, from the name alone. Never queries."""
    n = str(name or "")
    if re.search(r"_full_v\d+_rules_", n):
        return "consolidated_full"
    if re.search(r"_summary_v\d+_rules_", n):
        return "consolidated_summary"
    # BOTH kinds have per-scan targets: target_name() builds
    # yara_scanner_<kind>_v<N>_scan_<slug>, so matching only the matches spelling filed every
    # scans-kind target under host_scans and inflated the per-host count.
    if re.search(r"_(?:matches|scans)_v\d+_scan(?:_|$)", n):
        return "retired_scan_target"
    if re.search(r"_matches_v\d+_", n):
        return "host_matches"
    if re.search(r"_scans_v\d+_", n):
        return "host_scans"
    return "internal"

def group_by_type(names):
    """{type: {"count": n, "names": [...]}} - the dataset list grouped by what each dataset
    IS, decided from the name alone.

    A GROUPED VIEW of report_datasets' `datasets` list, never a second copy of the facts on
    it: the only thing this adds is the grouping. `datasets` is the authoritative record, and
    by_type[t]["names"] is exactly sorted(d["name"] for d in datasets if d["type"] == t) over
    the same population - so the two can never answer the same question differently.

    State used to be nested here as well, under "by_state", which published the
    (name -> state) map twice - once here and once as datasets[].state - and left a reader
    with no way to tell which spelling to trust. State is carried on the record only.

    Every type bucket is present even when empty, so a caller can index it without testing.
    """
    buckets = {t: [] for t in DATASET_TYPES}
    for n in names or ():
        buckets[dataset_type(n)].append(n)
    return {t: {"count": len(ns), "names": sorted(ns)} for t, ns in buckets.items()}

def render_by_type(current, legacy, newer, now_yyyymm):
    """One table per KIND OF DATASET, so the inventory can be read without knowing the
    naming scheme. The single flat table below answers "what state is each dataset in";
    this answers "what do I actually have", which is the question asked first."""
    everything = list(current) + list(legacy) + list(newer)
    grouped = group_by_type(everything)
    out = []
    for key, title in _TYPE_TITLES:
        names = (grouped.get(key) or {}).get("names") or []
        out.append("%s  [%d]" % (title, len(names)))
        if not names:
            out.append("    (none)")
            out.append("")
            continue
        if key in _COUNT_ONLY_TYPES:
            months = sorted({(parse_dataset_name(n) or {}).get("month") or "-" for n in names})
            hosts = len({(parse_dataset_name(n) or {}).get("host") or n for n in names})
            out.append("    %d dataset(s) across %d host(s), month(s): %s"
                       % (len(names), hosts, ", ".join(m for m in months if m != "-") or "none"))
            out.append("    (not listed by name - see by_type.host_scans.names in the context)")
            out.append("")
            continue
        out.append("    %-56s %-14s %8s" % ("dataset", "host", "age"))
        out.append("    " + "-" * 80)
        for n in names:
            info = parse_dataset_name(n)
            host = (info or {}).get("host") or "-"
            if info and info.get("month"):
                age = "%dmo" % months_between(info["month"], now_yyyymm)
            elif info and info.get("overwrite"):
                age = "live"
            elif info and info.get("scan_target"):
                age = "scan"
            else:
                age = "-"
            out.append("    %-56s %-14s %8s" % (n[:56], str(host)[:14], age))
        out.append("")
    return out

def render_report(current, legacy, newer, now_yyyymm):
    """Human-readable inventory. Ages are whole months."""
    schema = os.environ.get("YARA_LOOKUP_SCHEMA_VER", "4")
    lines = ["YARA lookup datasets (schema v%s current, now %s)" % (schema, now_yyyymm), ""]
    # One table per type, and only one. The flat by-state table that used to follow listed
    # every name a second time - the same duplication the context had - and the state each
    # dataset is in is already the `age` column here (live / frozen / n/a / <n>mo).
    lines += render_by_type(current, legacy, newer, now_yyyymm)
    _sink = []
    unrotated, abandoned, consolidated, overwritten = [], [], [], []
    for name in current:
        info = parse_dataset_name(name)
        if info is None:
            label = (("(%s - this pack's own consolidated output, never a candidate)"
                      % ("full" if "_full_v" in name else "summary"))
                     if is_pack_output_dataset(name) else "(unrecognised - never a candidate)")
            _sink.append("%-52s %s" % (name[:52], label))
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
        _sink.append("%-52s %-8s %-14s %6s"
                     % (name[:52], info["kind"], (info["host"] or "-")[:14], age))
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
            "%d dataset(s) are per-scan CONSOLIDATED TARGETS (…_scan_<id>) from the"
            % len(consolidated),
            "      retired per-scan merge: consolidation OUTPUT, unrotated by design,",
            "      finished, not growing, and no longer produced by anything - on a tenant",
            "      that ran that merge, often a scan's only surviving copy. Never a",
            "      cleanup candidate.",
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
    failing to write this row must never replace the run's real outcome.

    skipped_reasons carries (name, reason) only, not the whole record. The column is capped at
    8000 characters and a full record runs to several hundred bytes, so dumping them whole
    would have truncated the audit row at roughly a third of the candidates it holds today -
    a regression introduced by making `skipped` structured, paid for here instead. The name
    and the closed reason code are what a query over this dataset can actually use; the
    sentence is in the War Room entry for the run."""
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
        "skipped_reasons": json.dumps(
            [{"name": s.get("name", ""), "reason": s.get("reason", "")}
             for s in (result.get("skipped") or []) if isinstance(s, dict)])[:8000],
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

    Returns ONE RECORD PER DATASET under "datasets" - the authoritative row, carrying name,
    type, kind, host, month and age_months alongside a `state` drawn from the closed
    DATASET_STATES vocabulary, the `detail` sentence that state means for THIS dataset, and
    the `remedy` an operator would act on (empty for every state that needs no action).
    Every record carries every key even where one does not apply: a transformer filtering on
    a sometimes-absent key matches nothing and reports no error, which is a silently empty
    branch rather than a failure anyone sees.

    The record covers CURRENT, LEGACY and NEWER schema datasets alike - the schema buckets
    are STATES ("legacy", "newer") rather than separate name lists, so no two keys in this
    dict answer the same question over different populations. Records are ordered by
    (state, name), so like sits with like in the context and in the rendered table.

    "by_type" is a grouped VIEW of that same list and nothing more; `datasets` is what to
    trust. The rendered fixed-width inventory is NOT returned: it is a second spelling of
    everything here, and the automation renders the War Room's markdown from this dict
    instead. render_report survives for the CLI, which prints it to a terminal.
    """
    now_yyyymm = now_yyyymm or datetime.date.today().strftime("%Y%m")
    current, legacy, newer = classify_yara_datasets(client)
    datasets = []

    def _age(info):
        month = (info or {}).get("month")
        return months_between(month, now_yyyymm) if month else None

    def _record(name, state, detail, remedy="", info=None):
        return {"name": name, "type": dataset_type(name),
                "kind": (info or {}).get("kind") or "",
                "host": (info or {}).get("host") or "",
                "month": (info or {}).get("month") or "",
                "age_months": _age(info),
                "state": state, "detail": detail, "remedy": remedy}

    for name in current:
        info = parse_dataset_name(name)
        if info is None:
            # NAME_RE deliberately refuses to parse this pack's own consolidated output -
            # that refusal IS safety rail 5. `type` already says which of the two it is
            # (consolidated_summary / consolidated_full), so neither `state` nor `kind`
            # spells that same fact a second time.
            pack = is_pack_output_dataset(name)
            datasets.append(_record(
                name, "pack_output" if pack else "unrecognised",
                "this pack's own consolidated output - a cross-host rollup for one ruleset, "
                "not a rotation shard, and never a retention candidate" if pack else
                "matches the current-schema name filter but not the yara_scanner naming "
                "contract - never a retention candidate, and its origin is unknown"))
            continue
        if info["scan_target"]:
            datasets.append(_record(
                name, "consolidated",
                "per-scan target from the retired per-scan merge - consolidation output, "
                "unrotated by design, finished and not growing; on a tenant that ran that "
                "merge it can be the only surviving copy of that scan", info=info))
        elif info["overwrite"]:
            datasets.append(_record(
                name, "overwrite",
                "permanent per-host matches dataset - the scanner replaces it wholesale at "
                "the start of every scan, so it is bounded by that overwrite rather than by "
                "rotation and an unsuffixed name is correct here", info=info))
        elif info["month"]:
            datasets.append(_record(
                name, "rotated",
                "rotation shard for %s, %d month(s) old"
                % (info["month"], months_between(info["month"], now_yyyymm)), info=info))
        elif has_rotated_sibling(name, current):
            datasets.append(_record(
                name, "frozen",
                "unsuffixed, but rotated siblings exist for this host - a pre-rotation "
                "leftover; writes moved to the dated names, so it is frozen and not growing",
                info=info))
        else:
            datasets.append(_record(
                name, "not_rotated",
                "unsuffixed with no rotated sibling - rotation is off for that deployment, "
                "so this dataset grows without bound until add_data merge time exceeds the "
                "client timeout and it goes write-dead",
                remedy='set CONFIG_LOOKUP_ROTATION="monthly" in the scanner',
                info=info))
    for name in legacy:
        datasets.append(_record(
            name, "legacy",
            "on an older or unversioned schema - prunable by YaraCleanup with "
            "delete_legacy, subject to its own rails", info=parse_dataset_name(name)))
    for name in newer:
        datasets.append(_record(
            name, "newer",
            "on a HIGHER schema version than the %s this run assumes - never pruned, "
            "because a host reading a stale version must not delete a future schema's data"
            % YARA_SCHEMA_VERSION,
            remedy="raise schema_version to the version the fleet actually writes",
            info=parse_dataset_name(name)))
    datasets.sort(key=lambda d: (d["state"], d["name"]))
    return {
        "now_yyyymm": now_yyyymm,
        "schema_version": YARA_SCHEMA_VERSION,
        # THE per-dataset record, and the only place any fact about a dataset is carried.
        "datasets": datasets,
        # A grouped VIEW of `datasets` - count and names per type bucket, so a caller can
        # branch on "how many host_scans" without walking every record. Same population,
        # same names; `datasets` is authoritative if the two could ever disagree.
        "by_type": group_by_type([d["name"] for d in datasets]),
        # The schema-bucket verdict. Counts rather than lists, because the names are already
        # on the records: a caller wanting them filters `datasets` on state legacy / newer.
        "current_count": len(current),
        "legacy_count": len(legacy),
        "newer_count": len(newer),
        "total_count": len(datasets),
    }


# ---------------------------------------------------------------------------------------
# RUN RECORDS AND THE WAR ROOM REPORT
#
# `selected`, `deleted` and `newer` are lists of DATASET NAMES - identifiers, which are data
# already - and stay plain strings. `skipped` and `failed` carried sentences written for a
# human, so a playbook that wanted to act on one of them - tell a still-writing shard from an
# unreadable query, tell rail 6 from rail 7 - had to substring-match prose. That is a contract
# nobody can change and nobody can rely on: reword a message for clarity and every filter
# downstream stops matching, silently, with no error anywhere.
#
# So each entry is an OBJECT with a stable key set and a `reason` from a CLOSED vocabulary,
# and the sentence survives as `detail` rather than BEING the record. Every entry carries
# every key even where one does not apply, because a transformer filtering on a key that is
# only sometimes present matches nothing and reports no error - a silently empty branch,
# which is the worst kind to debug.
#
# WHY THE SENTENCES ARE PARSED RATHER THAN REPLACED. Seventeen of the nineteen skip sentences
# are built inside select_rotated_for_deletion, filter_recently_written, filter_unconsolidated
# and select_legacy_for_deletion, and those four are compared byte-for-byte against
# xdr/xdr_data_management.py across all five shipping automations by
# tests/test_pack_data_management.py's drift gate. Rewriting them here would turn that gate
# red for every automation at once. So the conversion happens at the BOUNDARY: the rails keep
# returning their strings, and prune_datasets maps each one to a record - knowing which rail
# produced it and which selection path it was on. That is also how the two sentences that are
# IDENTICAL on both paths ("current month", "dated in the future") become distinguishable,
# which no amount of substring matching downstream could ever do.
#
# _classify_skip is pinned template-by-template by
# tests/test_cleanup_reports_objects_not_prose.py, so a reworded rail fails a test here rather
# than quietly landing in context as `unclassified`.
#
# The markdown report is rendered FROM the result dict and from nothing else, so the table an
# operator reads and the context a playbook branches on cannot disagree.
# ---------------------------------------------------------------------------------------

SKIP_REASONS = {
    "pack_output_full":
        "this pack's own FULL cross-host rollup (yara_scanner_full_v<N>_rules_<hash>) - "
        "consolidation output, never a rotation shard and never a retention candidate",
    "pack_output_summary":
        "this pack's own SUMMARY cross-host rollup (yara_scanner_summary_v<N>_rules_<hash>) - "
        "consolidation output, never a rotation shard and never a retention candidate",
    "not_yara_name":
        "the name is outside the yara_scanner_<kind>_v<N> naming contract, so nothing about "
        "it can be derived safely and it can never be a candidate",
    "retired_scan_target":
        "a per-scan consolidated target from the retired per-scan merge - consolidation "
        "output, and on a tenant that ran that merge it can be that scan's only copy",
    "overwrite_dataset":
        "the scanner's permanent per-host matches dataset - replaced wholesale at the start "
        "of every scan, so it is bounded by that overwrite rather than by rotation",
    "unrotated_frozen":
        "unsuffixed, but rotated siblings exist - an abandoned pre-rotation leftover, frozen "
        "rather than growing",
    "unrotated_growing":
        "unsuffixed with no rotated siblings - rotation is off and it will grow without "
        "bound; deleting it would destroy ALL history for that host, not one month",
    "current_month":
        "dated in the CURRENT month - a scan may be writing to it right now",
    "future_month":
        "dated in the future, which means clock skew - never a candidate",
    "inside_window":
        "older than the current month, but still inside the older_than_months window",
    "recency_check_failed":
        "the recency query errored, so rail 6 could not be evaluated - kept, because rail 6 "
        "fails closed",
    "within_quiet_period":
        "its newest row is younger than min_quiet_hours, so a scan may still be writing to "
        "it whatever its month label says",
    "consolidation_check_failed":
        "the consolidation-state query errored, so rail 7 could not be evaluated - kept, "
        "because rail 7 fails closed",
    "unconsolidated_scans":
        "it still holds scan_id(s) that no per-scan target has verified, so deleting it "
        "would lose that scan's only copy",
    "legacy_refused_newer_schema_present":
        "a WHOLE-PATH refusal rather than a per-dataset skip, so `name` is empty: at least "
        "one NEWER-schema dataset exists, which proves schema_version is stale, so the whole "
        "legacy classification is untrustworthy and delete_legacy selected nothing",
    "legacy_unsuffixed":
        "an unsuffixed legacy dataset holds ALL pre-rotation history for that host, so it is "
        "never a blanket candidate; delete it by name if you want the space",
    "newer_schema":
        "on a HIGHER schema version than this run assumes - never pruned; if that is "
        "unexpected, the schema_version argument is stale",
    "legacy_not_requested":
        "a legacy-schema dataset that was never a candidate this run, because delete_legacy "
        "was not set",
    "unclassified":
        "the rail's sentence matched no template this automation knows - the mapping in "
        "_classify_skip is stale relative to the selector that produced it. `detail` still "
        "carries the sentence verbatim; this is a bug here, not a condition on the tenant",
}

# Which of the seven numbered safety rails kept the candidate, or None where the guard is real
# but unnumbered - the pack's own consolidation output, a retired per-scan target, the
# retention window itself, and the legacy bucket nobody asked for.
SKIP_RAILS = {
    "pack_output_full": 5, "pack_output_summary": 5, "not_yara_name": 5,
    "retired_scan_target": None, "overwrite_dataset": None,
    "unrotated_frozen": 3, "unrotated_growing": 3, "legacy_unsuffixed": 3,
    "current_month": 1, "future_month": 2, "inside_window": None,
    "recency_check_failed": 6, "within_quiet_period": 6,
    "consolidation_check_failed": 7, "unconsolidated_scans": 7,
    "legacy_refused_newer_schema_present": 4, "newer_schema": 4,
    "legacy_not_requested": None, "unclassified": None,
}

# Which selection path the candidate was on when it was kept. The same rail fires on both
# paths and produces the SAME sentence on each, so this is the only thing that separates them.
SKIP_PATHS = {
    "retention": "the older_than_months path, over datasets on the current schema version",
    "legacy": "the delete_legacy path, over datasets on an older/unversioned schema",
    "schema": "neither path - rail 4 vetoed the dataset before either could see it",
}

# Each rail sentence mapped to its code by the one fragment of it that no other template
# shares. Checked in order, first match wins. Substring-matching prose is exactly what this
# change exists to spare a playbook author - it is done ONCE, here, next to the vocabulary,
# under a test that feeds every literal template through it.
#
# ORDER IS MOST-SPECIFIC-FIRST, and the two "could not check ..." markers lead deliberately.
# Rails 6 and 7 interpolate the TENANT'S RAW EXCEPTION TEXT into their sentence, so an
# arbitrary API error string is scanned against this whole table. Three markers below are
# generic enough for real error text to collide with - "current month", "dated in the future",
# "-month window" - and while they were tested first, an error like
#     "ds: could not check recency (HTTP 400: query over current month partition failed) ..."
# classified as `current_month`, rail 1: a name-only rail that issues no query, on a skip that
# happened precisely BECAUSE a query failed. The `error` field came back empty with it,
# because the extraction below only runs on the matching branch. A playbook watching for a
# rail that FAILED CLOSED - the case an operator most needs - matched nothing.
_SKIP_MARKERS = (
    ("could not check recency", "recency_check_failed"),
    ("could not check consolidation state", "consolidation_check_failed"),
    ("full consolidation OUTPUT", "pack_output_full"),
    ("summary consolidation OUTPUT", "pack_output_summary"),
    ("not a YARA dataset name", "not_yara_name"),
    ("per-scan consolidated target", "retired_scan_target"),
    ("permanent per-host matches dataset", "overwrite_dataset"),
    ("abandoned pre-rotation dataset", "unrotated_frozen"),
    ("not rotated (no YYYYMM)", "unrotated_growing"),
    ("holds ALL pre-rotation history", "legacy_unsuffixed"),
    ("current month", "current_month"),
    ("dated in the future", "future_month"),
    ("-month window", "inside_window"),
    ("a scan may still be writing", "within_quiet_period"),
    ("still holds unconsolidated scan(s)", "unconsolidated_scans"),
    ("refusing blanket legacy deletion", "legacy_refused_newer_schema_present"),
    ("NEWER schema version than this code understands", "newer_schema"),
    ("legacy schema, but delete_legacy was not set", "legacy_not_requested"),
)

# The numbers and identifiers the sentences fold in. Pulled back out so a caller never has to.
_RE_SKIP_WINDOW = re.compile(r"(\d+) month\(s\) old, inside the (\d+)-month window")
_RE_SKIP_QUIET = re.compile(r"newest row is only ([0-9.]+)h old")
_RE_SKIP_RECENCY_ERR = re.compile(
    r"could not check recency \((.*)\) - skipping to be safe", re.S)
_RE_SKIP_CONSOL_ERR = re.compile(
    r"could not check consolidation state \((.*)\) - skipping to be safe", re.S)
_RE_SKIP_STUCK = re.compile(r"still holds unconsolidated scan\(s\) (.+?) \(row_ceiling_exceeded")

# The two fail-closed rails, recognised STRUCTURALLY - by the same expression that extracts
# the tenant's error - before any substring in _SKIP_MARKERS is looked at. Substring order
# alone is not enough here: the sentence embeds text this automation did not write, and the
# only part of it that is ours is the template around it. re.S so a multi-line exception
# body (an HTML error page, a traceback) still matches the shape rather than falling through
# to a marker that happens to appear inside the body.
_SKIP_STRUCTURAL = (
    (_RE_SKIP_RECENCY_ERR, "recency_check_failed"),
    (_RE_SKIP_CONSOL_ERR, "consolidation_check_failed"),
)


def _skipped_record(reason, detail, name="", path="", age_months=None, window_months=None,
                    newest_age_hours=None, stuck_scan_ids=None, newer_datasets=None,
                    error=""):
    """One `skipped` entry. EVERY key is present on EVERY entry, null where it does not apply.

    `name` is the dataset the rail kept, and is "" only for the one whole-path refusal
    (legacy_refused_newer_schema_present), which is about the run rather than a dataset.
    `detail` is the rail's own sentence, verbatim - the record's provenance, not its contract.
    """
    return {"name": name, "reason": reason, "detail": detail, "path": path,
            "rail": SKIP_RAILS.get(reason),
            "age_months": age_months, "window_months": window_months,
            "newest_age_hours": newest_age_hours,
            "stuck_scan_ids": list(stuck_scan_ids or []),
            "newer_datasets": list(newer_datasets or []),
            "error": error}


def _classify_skip(text, path, candidates=(), newer_names=()):
    """Map one rail sentence to a `skipped` record. See the boundary note above for why this
    parses rather than replaces.

    `candidates` is the list the rail was given, so the dataset name is RECOGNISED rather than
    guessed at by splitting on a colon - a name that ever contained one would otherwise be
    silently truncated. `newer_names` fills newer_datasets on the whole-path refusal from the
    real list, recovering what the sentence had already capped at five.
    """
    s = str(text)
    name = ""
    for n in sorted(candidates or (), key=len, reverse=True):
        if s.startswith("%s: " % n):
            name = n
            break
    if not name and ": " in s:
        head = s.split(": ", 1)[0]
        if head and " " not in head:      # a whole-path refusal opens with a sentence, not a name
            name = head

    reason = ""
    for rx, code in _SKIP_STRUCTURAL:
        if rx.search(s):
            reason = code
            break
    if not reason:
        reason = "unclassified"
        for marker, code in _SKIP_MARKERS:
            if marker in s:
                reason = code
                break

    age = window = quiet_h = None
    stuck, newer, err = [], [], ""
    if reason == "inside_window":
        m = _RE_SKIP_WINDOW.search(s)
        if m:
            age, window = int(m.group(1)), int(m.group(2))
    elif reason == "within_quiet_period":
        m = _RE_SKIP_QUIET.search(s)
        if m:
            quiet_h = float(m.group(1))
    elif reason == "recency_check_failed":
        m = _RE_SKIP_RECENCY_ERR.search(s)
        err = m.group(1) if m else ""
    elif reason == "consolidation_check_failed":
        m = _RE_SKIP_CONSOL_ERR.search(s)
        err = m.group(1) if m else ""
    elif reason == "unconsolidated_scans":
        m = _RE_SKIP_STUCK.search(s)
        if m:
            # The rail prints only the first five, and nothing in the sentence says whether
            # there were more. Reported as what it is: the first five it named.
            stuck = [p.strip() for p in m.group(1).split(",") if p.strip()]
    elif reason == "legacy_refused_newer_schema_present":
        newer = list(newer_names or [])

    return _skipped_record(reason, s, name=name, path=path, age_months=age,
                           window_months=window, newest_age_hours=quiet_h,
                           stuck_scan_ids=stuck, newer_datasets=newer, error=err)


FAIL_REASONS = {
    "delete_refused_dependencies":
        "delete_dataset refused the dataset because something still depends on it - re-run "
        "with force=true if you mean to drop it anyway. Read off the API's own error text, "
        "which is the only signal the platform gives",
    "delete_failed":
        "delete_dataset raised for some other reason - `error` carries the API's text",
}


def _failed_record(dataset, error, path=""):
    """One `failed` entry. `error` is the API's own text, truncated - it is this list's
    `detail`, and there is deliberately no second key restating it. A record here means the
    dataset was NOT deleted and the rest of the pass continued."""
    text = str(error)[:200]
    reason = ("delete_refused_dependencies" if "depend" in text.lower() else "delete_failed")
    return {"dataset": dataset, "reason": reason, "error": text, "path": path}


WARN_REASONS = {
    "older_than_months_clamped":
        "older_than_months was negative and was clamped to 0. A negative window means "
        "nothing beyond 0 and would leave rails 1 and 2 as the only thing between the prune "
        "and a live shard",
    "min_quiet_hours_floored":
        "min_quiet_hours was below the floor and was raised to it. Below 1h the value does "
        "not relax rail 6, it DISABLES it",
}


def _warning_record(reason, detail, argument, requested, applied):
    """One `warnings` entry: an argument this run did not use as given. Without it a clamped
    run publishes the CLAMPED value with nothing anywhere saying it was changed."""
    return {"reason": reason, "detail": detail, "argument": argument,
            "requested": "" if requested is None else str(requested),
            "applied": str(applied)}


LOCK_EVENTS = {
    "held_by_other_run":
        "another run's lock was live, so this pass stood down and deleted nothing",
    "unreadable_marker_stood_down":
        "the lock marker existed but its row was unreadable - most likely another run had "
        "just created it, so this pass stood down rather than take it over",
    "stale_marker_taken_over":
        "a lock marker was present but judged stale, and this pass took it over and "
        "proceeded",
    "release_failed":
        "the lock could not be released at the end of the pass - it will block the next run "
        "until it ages out",
    "stood_down":
        "the pass stood down on the lock and deleted nothing. It says only THAT, never who "
        "holds it - the event beside this one carries the specific finding, which is either "
        "held_by_other_run or unreadable_marker_stood_down",
    "other":
        "a lock line this automation does not have a code for; `detail` carries it verbatim",
}

_LOCK_MARKERS = (
    ("stood down on the consolidation lock", "stood_down"),
    ("could not release consolidation lock", "release_failed"),
    ("marker exists but its row is unreadable", "unreadable_marker_stood_down"),
    ("is stale or unreadable", "stale_marker_taken_over"),
    ("held by another run", "held_by_other_run"),
    ("consolidation lock held (age", "held_by_other_run"),
)


def _lock_event(line):
    """A lock log line as a record, or None if the line is not about the lock.

    Lock events reached the operator by scraping the log for the word "lock" and reached a
    playbook not at all, so a lock this pass failed to RELEASE - which blocks the next run
    until it ages out - was invisible to anything automated."""
    s = str(line)
    if "lock" not in s.lower():
        return None
    for marker, event in _LOCK_MARKERS:
        if marker in s:
            return {"event": event, "detail": s}
    return {"event": "other", "detail": s}


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

    # Every lock line this pass emits, structured, in order and at most one per event. The
    # SAME list object goes into the result dict below, so the release attempt in the finally
    # - which runs after `return result` has evaluated - still lands in what the caller gets.
    lock_events = []

    def lock_log(m):
        ev = _lock_event(m)
        if ev and not any(e["event"] == ev["event"] for e in lock_events):
            lock_events.append(ev)
        log(m)

    result = {
        # ONE key to branch on, folding in the precedence a caller would otherwise have to
        # rebuild from the four booleans below and would get wrong: nothing_requested beats a
        # held lock beats dry_run, and an executed pass is "partial_failure" the moment any
        # delete raised. The booleans stay because each is independently meaningful.
        "status": "",
        "dry_run": not execute,
        "nothing_requested": False,
        "lock_held_by_other_run": False,
        "lock_taken_over": False,
        "lock_takeover_reason": "",
        "lock_events": lock_events,
        "older_than_months": older_than_months,
        "delete_legacy": bool(delete_legacy),
        "min_quiet_hours": float(min_quiet_hours),
        "schema_version": YARA_SCHEMA_VERSION,
        # Argument coercion happens in main(), so this is empty when prune_datasets is driven
        # as a library. Declared here all the same: a key that only sometimes exists is the
        # same silently-empty branch the object conversion exists to remove.
        "warnings": [],
        "selected": [], "selected_count": 0,
        "deleted": [], "deleted_count": 0,
        "failed": [], "failed_count": 0,
        "skipped": [], "skipped_count": 0,
        "newer": [], "newer_count": 0,
    }

    if older_than_months is None and not delete_legacy:
        result["nothing_requested"] = True
        result["status"] = "nothing_requested"
        log("no retention window (older_than_months) and delete_legacy is false — nothing "
            "selected, nothing deleted")
        return result

    takeovers = []
    if execute and not acquire_consolidation_lock(
            client, log=lock_log, now_ms=now_ms, holder=holder,
            stale_after_secs=PRUNE_LOCK_STALE_SECS, unreadable_is_held=True,
            on_takeover=takeovers.append):
        result["lock_held_by_other_run"] = True
        result["status"] = "lock_held"
        # Worded from what acquire_consolidation_lock actually established. It returns the
        # same False whether it READ a live lock or merely found a marker whose row it could
        # not read, and this line used to assert the first in both cases - which the
        # classifier then turned into a `held_by_other_run` lock_event. That is worse than a
        # misleading sentence: a playbook filtering lock_events for a genuine contention got
        # a false positive out of a pass that never identified a holder. The specific finding
        # is already recorded by acquire_consolidation_lock's own line, so say only what is
        # true of BOTH paths here and let that line carry the distinction.
        lock_log("stood down on the consolidation lock — deleting nothing this pass")
        return result
    if takeovers:
        # Reported, never silent: this pass proceeded while another run's lock marker was in
        # place, and the operator must be able to tell it apart from an uncontended pass.
        result["lock_taken_over"] = True
        result["lock_takeover_reason"] = takeovers[0]

    try:
        current, legacy, newer = classify_yara_datasets(client)   # rail 4 lives here
        targets, skipped, path_of = [], [], {}
        result["newer"], result["newer_count"] = newer, len(newer)
        for n in newer:
            # Built as a record directly rather than through _classify_skip: this sentence is
            # written HERE, in free code, so there is no gated producer to stay faithful to.
            skipped.append(_skipped_record(
                "newer_schema",
                "%s: NEWER schema version than this code understands - never pruned "
                "(rail 4); if that is unexpected, the schema_version argument (currently v%s) "
                "is stale" % (n, YARA_SCHEMA_VERSION), name=n, path="schema"))
        if older_than_months is not None:
            t, s = select_rotated_for_deletion(current, older_than_months, now_yyyymm)
            skipped += [_classify_skip(x, "retention", current) for x in s]
            t, s2 = _live_rails(client, t, min_quiet_hours, now_ms, log)
            skipped += [_classify_skip(x, "retention", current) for x in s2]
            path_of.update((n, "retention") for n in t)
            targets += t
        if delete_legacy:
            t, s = select_legacy_for_deletion(legacy, newer, now_yyyymm)
            skipped += [_classify_skip(x, "legacy", legacy, newer) for x in s]
            t, s2 = _live_rails(client, t, min_quiet_hours, now_ms, log)
            skipped += [_classify_skip(x, "legacy", legacy) for x in s2]
            path_of.update((n, "legacy") for n in t)
            targets += t
        else:
            for n in legacy:
                skipped.append(_skipped_record(
                    "legacy_not_requested",
                    "%s: legacy schema, but delete_legacy was not set" % n,
                    name=n, path="legacy"))

        # Sorted so like sits with like: a tenant with 200 kept candidates keeps them in runs
        # of one reason, and an operator reading the table wants the three held by a DIFFERENT
        # rail adjacent rather than scattered through the dataset-name ordering.
        skipped.sort(key=lambda r: (r["reason"], r["name"]))

        result["selected"] = targets
        result["selected_count"] = len(targets)
        result["skipped"] = skipped
        result["skipped_count"] = len(skipped)
        for r in skipped:
            log("  skip  [%s] %s" % (r["reason"], r["detail"]))

        if not execute:
            result["status"] = "dry_run"
            log("DRY RUN — %d dataset(s) would be deleted, nothing touched" % len(targets))
            return result

        for name in targets:
            try:
                client.delete_dataset(name, force=force)
                result["deleted"].append(name)
                log("  deleted %s" % name)
            except Exception as e:
                # Continue: one dataset with dependencies must not strand the whole cleanup.
                result["failed"].append(_failed_record(name, e, path_of.get(name, "")))
                log("  FAILED  %s: %s" % (name, e))
        result["deleted_count"] = len(result["deleted"])
        result["failed_count"] = len(result["failed"])
        result["status"] = "partial_failure" if result["failed"] else "success"
        record_cleanup_run(client, result, now_ms=now_ms, log=log)
        return result
    finally:
        if execute:
            release_consolidation_lock(client, log=lock_log)


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
def _flag(args, name):
    """A boolean argument the platform may deliver as an absent key, an empty string, or a
    string. Absent or empty is False - that is what makes `execute` a dry run by default.
    Anything else goes through argToBoolean, so an unrecognised value RAISES rather than
    being read as either truth value; main() turns that into a return_error."""
    value = args.get(name)
    if value is None or value == "":
        return False
    return argToBoolean(value)


_MD_ROW_CAP = 50


def _n(v):
    """Thousands-separated. The numbers this reports run to six figures.

    Integral values print as integers, floats included: the settings arrive as
    float(args.get(...)), and "900.0" in a table reads as a typo rather than a default.

    A NON-integral float keeps its fraction. The previous version went through int(), which
    silently truncated - a quiet_secs of 900.5 printed as 900 while the context carried 900.5,
    so the report and the context stated different numbers. That is the one disagreement this
    renderer exists to make impossible, and it was being introduced by the formatter itself.
    """
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return format(int(f), ",d") if f.is_integer() else format(f, ",g")


def _md_table(headers, rows):
    """A markdown table, or "" when there is nothing to put in it. Cells are escaped: rule
    names and hostnames reach here from a ruleset and from an endpoint, and a single pipe in
    either would silently shear a column off every row below it."""
    if not rows:
        return ""

    def cell(v):
        return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")

    out = ["| " + " | ".join(cell(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(cell(v) for v in r) + " |")
    return "\n".join(out)


def _md_capped(headers, rows, context_key):
    """_md_table, truncated. The context keeps every entry, so a 200-host pass cannot push the
    counts off the top of the War Room - the same trade YaraReport makes for the scan log."""
    body = _md_table(headers, rows[:_MD_ROW_CAP])
    if len(rows) > _MD_ROW_CAP:
        body += ("\n\n_... and %s more - the full list is in `%s`._"
                 % (_n(len(rows) - _MD_ROW_CAP), context_key))
    return body


_HEADLINES = {
    "nothing_requested": ("NOTHING REQUESTED",
                          "No retention window was given (`older_than_months`) and "
                          "`delete_legacy` is false, so nothing was selected and no API call "
                          "was made. This automation has no default window on purpose - a "
                          "bare invocation must never delete."),
    "lock_held": ("STOOD DOWN - LOCK HELD",
                  "The consolidation lock is held by another run (YaraConsolidateApply, or "
                  "another scheduled execution). Nothing was deleted. Pruning and "
                  "consolidation mutate the same shards, so this pass stands down rather "
                  "than race it."),
    "lock_unreadable": ("STOOD DOWN - LOCK MARKER UNREADABLE",
                        "A lock marker exists but its row could not be read, so this pass "
                        "stood down without establishing WHO holds it. Almost always another "
                        "run created it moments ago and the row has not landed yet; the same "
                        "signature also fits a marker orphaned by a killed pass, which clears "
                        "itself once it ages out. Nothing was deleted either way - standing "
                        "down is the safe direction when the holder is unknown."),
    "dry_run": ("DRY RUN",
                "Nothing was deleted. Re-run with `execute=true` to apply exactly this."),
    "success": ("EXECUTED", "Datasets were deleted. This cannot be undone."),
    "partial_failure": ("EXECUTED WITH FAILURES",
                        "Datasets were deleted and at least one delete raised. The failures "
                        "are listed below; every other candidate went through."),
}


def _lock_cell(result):
    """What this pass actually did with the consolidation lock, in one sentence.

    Every branch here is a FACT the pass recorded. It used to be derived from `not dry`,
    which is a proxy, and the proxy is wrong on two reachable paths:

      * `nothing_requested` returns from prune_datasets BEFORE acquire_consolidation_lock is
        reached, so an `execute=true` pass with no window took no lock at all - and the
        summary row said "taken and released by this run" over a pass that made zero API
        calls of any kind. That is the shape of a scheduled job whose older_than_months
        templated out empty.
      * A pass whose RELEASE raised still holds the marker. The Lock events table right below
        said `release_failed`, the summary row said "taken and released", and the summary row
        is the one read first. A lock left behind blocks the next run until it ages out,
        which is the single failure `lock_events` was added to surface.
    """
    if result.get("lock_held_by_other_run"):
        # acquire_consolidation_lock returns the same False for two different findings, and
        # only ONE of them establishes a holder. An unreadable marker row means the pass
        # never read who owns it - saying "held by another run" there states a fact it did
        # not establish, and the lock_events row directly below says so in as many words.
        # Same shape as the two paths above, found in the same place: the summary row talking
        # over the structured signal that contradicts it.
        if any((e or {}).get("event") == "unreadable_marker_stood_down"
               for e in (result.get("lock_events") or [])):
            return ("a marker is present but its row could not be read - stood down without "
                    "establishing who holds it")
        return "held by another run - stood down"
    if (result.get("status") or "") == "nothing_requested":
        return ("never taken - nothing was requested, so the pass returned before "
                "acquiring it")
    if result.get("dry_run"):
        return "not taken - a dry run never takes it"
    if any((e or {}).get("event") == "release_failed"
           for e in (result.get("lock_events") or [])):
        return ("taken%s, and NOT RELEASED - see Lock events; the marker is still on the "
                "tenant and blocks the next run until it ages out"
                % (" OVER as stale" if result.get("lock_taken_over") else ""))
    if result.get("lock_taken_over"):
        return "TAKEN OVER as stale - see the warning below"
    return "taken and released by this run"


def _execute_cell(result):
    """What `execute` MEANT for this pass, not what it was set to.

    "true - deletes were applied" was printed whenever the run was not a dry run, including
    the two paths that return before a single delete is attempted (nothing_requested, and
    standing down on a held lock). The count is the fact; read it instead.
    """
    if result.get("dry_run"):
        return "false - nothing was deleted"
    status = result.get("status") or ""
    if status == "nothing_requested":
        return "true - but nothing was requested, so nothing was deleted"
    if status == "lock_held":
        return "true - but another run held the lock, so nothing was deleted"
    return "true - %s dataset(s) deleted, irreversibly" % _n(result.get("deleted_count") or 0)


def render_run_markdown(result):
    """The War Room report for one pass, rendered from the result dict ALONE.

    Nothing here reads a log line, an argument or a local: every number in this report is a
    number in the context, so the table an operator reads and the branch a playbook takes
    cannot disagree. The previous version built its lines with
    `lines += ["  skip  {}".format(s) for s in result["skipped"]]`, which prints a dict's repr
    the moment an entry stops being a string - silent garbage rather than a loud TypeError.
    Tables replace it.

    `newer` is deliberately NOT given a section of its own: every dataset in it is already in
    the Kept table under `newer_schema`, and printing it twice is how a reader ends up unsure
    which listing is authoritative.
    """
    status = result.get("status") or ("dry_run" if result.get("dry_run") else "success")
    # `lock_held` covers both standdowns; only the readable one identified a holder.
    if status == "lock_held" and any(
            (e or {}).get("event") == "unreadable_marker_stood_down"
            for e in (result.get("lock_events") or [])):
        status_key = "lock_unreadable"
    else:
        status_key = status
    headline, blurb = _HEADLINES.get(status_key, (status.upper(), ""))
    dry = bool(result.get("dry_run"))
    out = ["### YARA dataset cleanup - %s" % headline, "_%s_" % blurb, ""]

    window = result.get("older_than_months")
    lock = _lock_cell(result)
    out.append(_md_table(["", ""], [("**%s**" % k, v) for k, v in [
        ("Status", "`%s`" % status),
        ("Selected", "%s dataset(s)%s" % (_n(result["selected_count"]),
                                          " that WOULD be deleted" if dry else "")),
        ("Deleted", "%s%s" % (_n(result["deleted_count"]),
                              " - nothing was touched" if dry else "")),
        ("Failed", _n(result["failed_count"])),
        ("Kept", "%s candidate(s), each with the rail that kept it" % _n(result["skipped_count"])),
        ("Vetoed by rail 4", "%s dataset(s) on a newer schema - listed under Kept, reason "
                             "`newer_schema`, and repeated in `Yara.Cleanup.newer`"
                             % _n(result["newer_count"])),
        ("Retention window", "none" if window is None else "older than %s whole month(s)"
                             % _n(window)),
        ("Legacy schema", "in scope" if result["delete_legacy"] else "NOT in scope"),
        ("Consolidation lock", lock),
    ]]))

    if result.get("lock_taken_over"):
        out += ["", "> **WARNING:** another run's consolidation lock marker was present and "
                    "this pass **TOOK IT OVER** as stale (%s). If a consolidation pass was in "
                    "fact still running, its shards were pruned concurrently."
                    % (result.get("lock_takeover_reason") or "no reason recorded")]

    # `selected` gets a table of its own on a DRY RUN only. On an executed pass it is exactly
    # deleted + the failed datasets, both tabled below, and printing it a third time would
    # leave a reader working out which of three listings to trust.
    if dry and result["selected"]:
        out += ["", "#### Would delete",
                _md_capped(["Dataset"], [("`%s`" % n,) for n in result["selected"]],
                           "Yara.Cleanup.selected")]

    if result["deleted"]:
        out += ["", "#### Deleted - irreversibly",
                _md_capped(["Dataset"], [("`%s`" % n,) for n in result["deleted"]],
                           "Yara.Cleanup.deleted")]

    if result["failed"]:
        out += ["", "#### Failed to delete - still on the tenant",
                _md_capped(["Dataset", "Path", "Reason", "What the API said"],
                           [("`%s`" % f["dataset"], f["path"] or "-", "`%s`" % f["reason"],
                             f["error"]) for f in result["failed"]],
                           "Yara.Cleanup.failed")]

    # Uncapped in the CONTEXT, capped in this table: a dataset silently not deleted is
    # indistinguishable from a bug, so every reason is kept - but a 200-candidate tenant must
    # not push the counts off the top of the War Room to say so.
    if result["skipped"]:
        out += ["", "#### Kept - nothing was deleted",
                _md_capped(["Dataset", "Path", "Rail", "Reason", "Detail"],
                           [(("`%s`" % s["name"]) if s["name"] else "_(whole path)_",
                             s["path"] or "-",
                             s["rail"] if s["rail"] is not None else "-",
                             "`%s`" % s["reason"], s["detail"])
                            for s in result["skipped"]],
                           "Yara.Cleanup.skipped")]

    if result.get("warnings"):
        out += ["", "#### Warnings - an argument was not used as given",
                _md_table(["Argument", "Requested", "Applied", "Why"],
                          [("`%s`" % w["argument"], w["requested"], w["applied"], w["detail"])
                           for w in result["warnings"]])]

    out += ["", "#### Settings this run used",
            _md_table(["Argument", "Value", "What it controls"], [
                ("`schema_version`", "v%s" % result["schema_version"],
                 "which datasets count as current, legacy or newer - and so whether this run "
                 "had any scope at all"),
                ("`older_than_months`", "none" if window is None else _n(window),
                 "the retention window over CURRENT-schema rotated datasets; none means that "
                 "path selected nothing"),
                ("`delete_legacy`", "true" if result["delete_legacy"] else "false",
                 "whether older/unversioned-schema datasets were in scope; the same rails "
                 "apply to them either way"),
                ("`min_quiet_hours`", "%sh" % result["min_quiet_hours"],
                 "rail 6's threshold: a dataset written to more recently than this is kept, "
                 "whatever its month label says"),
                ("`execute`", _execute_cell(result),
                 "false previews, true deletes whole datasets irreversibly"),
            ])]

    if result.get("lock_events"):
        out += ["", "#### Lock events",
                _md_table(["Event", "Detail"],
                          [("`%s`" % e["event"], e["detail"])
                           for e in result["lock_events"]])]

    return "\n".join(out)


def main():
    args = demisto.args()
    notes = []

    # All argument coercion lives inside a try: on a destructive automation a mistyped
    # argument must produce this script's own "nothing was deleted" message, not a traceback.
    try:
        # Always explicit, even when the caller passed none: set_schema_version mutates a
        # module global and os.environ, and one container serves many executions.
        set_schema_version(args.get("schema_version") or DEFAULT_SCHEMA_VERSION)

        older_than_months = args.get("older_than_months")
        older_than_months = int(older_than_months) if older_than_months not in (None, "") else None
        if older_than_months is not None and older_than_months < 0:
            notes.append(_warning_record(
                "older_than_months_clamped",
                "A negative window means nothing beyond 0 (\"every month before the current "
                "one\") and would leave rails 1 and 2 as the only thing standing between the "
                "prune and a live shard.",
                "older_than_months", args.get("older_than_months"), 0))
            older_than_months = 0

        min_quiet_hours = args.get("min_quiet_hours")
        min_quiet_hours = (float(min_quiet_hours) if min_quiet_hours not in (None, "")
                           else DEFAULT_MIN_QUIET_HOURS)
        if min_quiet_hours < MIN_ALLOWED_QUIET_HOURS:
            # 0 or a negative switches rail 6 off entirely rather than relaxing it: the
            # comparison `(now - newest) < 0` is false even for a row written a second ago.
            notes.append(_warning_record(
                "min_quiet_hours_floored",
                "Below the {}h floor, which would DISABLE the recency rail rather than relax "
                "it: `(now - newest) < 0` is false even for a row written a second ago. "
                "Raised to the floor for this run.".format(MIN_ALLOWED_QUIET_HOURS),
                "min_quiet_hours", args.get("min_quiet_hours"), MIN_ALLOWED_QUIET_HOURS))
            min_quiet_hours = MIN_ALLOWED_QUIET_HOURS

        kwargs = {
            "older_than_months": older_than_months,
            "delete_legacy": _flag(args, "delete_legacy"),
            "min_quiet_hours": min_quiet_hours,
            "force": _flag(args, "force"),
            # The opt-in. Absent -> False -> dry run: nothing is deleted.
            "execute": _flag(args, "execute"),
        }
    except Exception as ex:
        # Cleared on the failure path too: a crashed destructive run must not leave a previous
        # run's deleted list in context for a downstream task to read as this run's outcome.
        demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})
        return_error("YaraCleanup: invalid argument ({}). Nothing was deleted.".format(ex))
        return

    # A sink, not a source. The run's narration is kept out of the War Room entirely - the
    # report below is rendered from the result dict and from nothing else, and the one part of
    # the log an operator needed (the lock) is now a structured `lock_events` list instead of
    # a substring scrape over these lines.
    log_lines = []
    try:
        result = prune_datasets(CoreApiClient(), log=lambda m: log_lines.append(m), **kwargs)
    except Exception as ex:
        demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})
        return_error("YaraCleanup failed: {}".format(ex))
        return

    # Argument clamping used to reach the operator as a NOTE line and reach a playbook not at
    # all: a run that silently clamped older_than_months=-3 to 0 published older_than_months=0
    # with nothing anywhere saying it had been changed, so a caller could not tell the window
    # it asked for from the window that ran.
    result["warnings"] = notes

    # List-valued context is APPENDED to across repeated calls in one investigation; clear
    # it first so selected/deleted/skipped never carry a prior call's entries.
    demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})

    return_results(CommandResults(
        readable_output=render_run_markdown(result),
        outputs_prefix="Yara.Cleanup",
        outputs=result,
        raw_response=result,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
