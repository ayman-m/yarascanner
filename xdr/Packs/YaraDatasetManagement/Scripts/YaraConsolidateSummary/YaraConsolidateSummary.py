"""YaraConsolidateSummary - summary-only consolidation: which rules fired on which host.

Writes ONE ROW PER (host, rule) into yara_scanner_summary_v<VER>_scan_<slug>, with four
columns - scan_id, hostname, rule, event_timestamp_ms. No filenames, no offsets, no per-rule
counts: the per-host matches dataset stays the deep-dive source for those. The rule list
comes from one XQL per host shard, expanded and grouped inside the engine, so the read cost
does not scale with the number of matches.

THIS AUTOMATION NEVER DELETES ANYTHING - not a host shard, not a scans shard, not a row. That
is the difference from YaraConsolidateApply. DRY RUN BY DEFAULT: without execute=true it
reports what it would write, and its XQL cost, and writes nothing. A scan is summarised only
once its lifecycle is terminal or has been silent past retention_hours, and a target that
already holds a different row count is reported and left alone rather than appended to.

ARGUMENTS
  scan_id          Restrict which scans are WRITTEN, comma-separated. It does not reduce the
                   read cost: only a query can say which shard holds which scan, so every
                   host shard is still read once.
  schema_version   The scanner's YARA_LOOKUP_SCHEMA_VER. Selects which shards are in scope
                   AND which query shape is used - v4 expands the `rules` JSON array, v2/v3
                   carry a scalar `rule` column. Defaults to DEFAULT_LOOKUP_SCHEMA_VERSION.
  retention_hours  A scan with no terminal lifecycle row is treated as finished past this
                   age. Defaults to DEFAULT_RETENTION_HOURS. It is only that threshold - this
                   automation has no deletion window because it deletes nothing.
  execute          true to create the per-scan targets and write to them. Anything else,
                   including absent, is a dry run.
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

# Lookup schema version assumed when the schema_version argument is left empty. It also
# selects the query shape: v4 expands the `rules` JSON array, v2 and v3 do not.
DEFAULT_LOOKUP_SCHEMA_VERSION = "4"

DEFAULT_RETENTION_HOURS = 24        # a scan with no terminal lifecycle row is finished past this
_WRITE_BATCH = 500                  # rows per lookups/add_data call
DEFAULT_LOCK_STALE_SECS = 20 * 60   # a run cannot outlive the 900s task timeout
# One pass consolidates at most this many scans, so it finishes inside that 900s
# timeout instead of being killed mid-merge still holding the lock.
DEFAULT_MAX_SCANS_PER_PASS = 20
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


def _cleanup_verified_scan_rows(client, srcs, scan_id, log):
    """Once a scan's per-scan target is verified, strip that scan's rows out of every source
    shard, so a dashboard querying the wildcard stops double-counting it.

    Sequential: remove_lookup_data is NOT concurrency-safe. Best effort - a failure here
    never blocks the eventual whole-shard delete. Callers must only invoke this for
    kind=="matches": a "scans" shard's rows are the lifecycle signal for the sibling scans
    still sharing it."""
    for ds in srcs:
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
        consolidated, deferred, failed = set(), set(), set()
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
            "failed_reasons": failed_reasons}


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
YARA_OWNED_RE = re.compile(r"^(yara_scanner_(matches|scans)(_.*)?|yara_(matches|scans)_.*)$")
CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans)_v%s(_.*)?$" % re.escape(YARA_SCHEMA_VERSION))

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
    CURRENT_RE = re.compile(r"^yara_scanner_(matches|scans)_v%s(_.*)?$"
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
            skipped.append("%s: not a YARA dataset name" % name)
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
            lines.append("%-52s %s" % (name[:52], "(unrecognised - never a candidate)"))
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

# The summary row, and the schema its per-scan target is CREATED with. FOUR COLUMNS. A
# dataset created from a NARROWER schema silently drops every extra field, with no error, so
# this dict is a contract rather than a suggestion. Filenames, hashes and offsets are absent
# by design (the host matches dataset keeps them) and so are per-rule counts, which would
# turn every dashboard query here into an aggregation instead of a distinct-set lookup.
SUMMARY_SCHEMA = {
    "scan_id": "text",
    "hostname": "text",
    "rule": "text",
    "event_timestamp_ms": "number",
}

# Approximate row size, used to report the size of a write. A lookup dataset caps at 50 MB,
# so one per-scan summary target holds roughly 321,000 (host, rule) pairs - the limit is
# rules matched per host times hosts in the scan, never host count on its own.
_SUMMARY_ROW_BYTES = 163

# Target-name kind: "summary", NOT "matches_summary", and the choice is load-bearing.
# "matches_summary" would match YARA_OWNED_RE but not CURRENT_RE, so classify_yara_datasets
# would file every summary target under LEGACY and a YaraCleanup run with delete_legacy=true
# would delete them all. "summary" matches neither regex, nor _SHARD_RE, so a summary target
# can never become a deletion candidate and no consolidation pass can mistake it for a source
# shard. The consequence, stated rather than hidden: YaraCleanup never prunes these either.
_SUMMARY_KIND = "summary"

# Read cap per shard. One host shard yields at most (rules matched on that host) rows, so
# this sits far above anything a shard can produce - but a read that comes back at exactly
# the limit is reported rather than trusted.
_SUMMARY_LIMIT = 10000


def summary_target_name(ver, scan_id):
    """yara_scanner_summary_v<VER>_scan_<slug>. Same slugifier as every other per-scan
    target, so the summary and full-detail targets for one scan share a slug."""
    return target_name(_SUMMARY_KIND, ver, scan_id)


def summary_query(dataset, ver):
    """The ONE query this automation is built around: one row per (scan_id, hostname, rule),
    computed entirely in the engine.

    v4 folds every rule that hit a file into the `rules` JSON array, so the array is expanded
    first; v2 and v3 carry a scalar `rule` column per row and need no expansion.
    """
    if str(ver) == "4":
        return ('dataset = %s | alter r = json_extract_array(rules, "$") | arrayexpand r '
                '| alter rule = json_extract_scalar(r, "$.rule") '
                '| comp count() as n, max(event_timestamp_ms) as ts '
                'by scan_id, hostname, rule' % dataset)
    return ('dataset = %s | comp count() as n, max(event_timestamp_ms) as ts '
            'by scan_id, hostname, rule' % dataset)


def summary_query_fallback(dataset, scan_id):
    """Fallback shape, scoped to one scan, for a tenant that rejects summary_query()'s
    extended `comp` stage. Costs one query per scan instead of one per shard, and returns no
    `ts` - the caller then stamps the row from lifecycle recency instead."""
    safe = str(scan_id).replace('"', "")
    return ('dataset = %s | filter scan_id = "%s" '
            '| alter r = json_extract_array(rules, "$") | arrayexpand r '
            '| alter rule = json_extract_scalar(r, "$.rule") '
            '| comp count() as n by hostname, rule' % (dataset, safe))


def _shard_scan_ids(client, dataset):
    """Distinct scan_ids in a shard. Only the fallback path needs it."""
    rows = client.xql("dataset = %s | fields scan_id | comp count() as n by scan_id"
                      % dataset, limit=10000) or []
    out = []
    for r in rows:
        sid = r.get("scan_id") if isinstance(r, dict) else None
        if sid and sid not in out:
            out.append(str(sid))
    return out


def summarise_shard(client, dataset, ver, qcount, log, findings=None):
    """[(scan_id, hostname, rule, ts_ms_or_None)] for ONE host shard.

    Primary path is a single XQL; it falls back to one query per scan only if that query is
    rejected. `findings` accumulates the discarded count() aggregate so the run can report how
    many file-level findings collapsed into the summary; it never reaches a row.
    """
    p = parse_shard(dataset)
    if not p or p["kind"] != "matches":
        # Guards the XQL interpolation. Names reaching here are already anchored by
        # parse_shard's regex, but the host segment originates as a HOSTNAME, so the check is
        # made explicitly rather than assumed.
        raise ValueError("refusing non-matches dataset in XQL: %s" % dataset)

    try:
        # Counted BEFORE the call, here and everywhere below: a failed query still cost the
        # tenant a query, and the reported figure is the run's real cost.
        qcount[0] += 1
        rows = client.xql(summary_query(dataset, ver), limit=_SUMMARY_LIMIT) or []
        if len(rows) >= _SUMMARY_LIMIT:
            # Never silent truncation. Nothing is deleted on the strength of this read, so a
            # short read costs coverage, never data.
            log("  ! %s returned %d rows - at the %d-row read cap; its summary may be "
                "incomplete" % (dataset, len(rows), _SUMMARY_LIMIT))
        out = []
        for r in rows:
            sid, host, rule = r.get("scan_id"), r.get("hostname"), r.get("rule")
            if not sid or not rule:
                continue
            if findings is not None:
                try:
                    findings[0] += int(r.get("n") or 0)
                except (TypeError, ValueError):
                    pass
            out.append((str(sid), str(host or ""), str(rule), _as_ms(r.get("ts"))))
        return out, "single-query"
    except Exception as e:
        if str(ver) != "4":
            raise
        log("  ! per-shard summary query failed on %s (%s) - retrying with the unmodified "
            "per-scan form" % (dataset, str(e)[:140]))

    out = []
    qcount[0] += 1
    sids = _shard_scan_ids(client, dataset)
    for sid in sids:
        qcount[0] += 1
        rows = client.xql(summary_query_fallback(dataset, sid), limit=_SUMMARY_LIMIT) or []
        for r in rows:
            rule = r.get("rule")
            if not rule:
                continue
            if findings is not None:
                try:
                    findings[0] += int(r.get("n") or 0)
                except (TypeError, ValueError):
                    pass
            out.append((str(sid), str(r.get("hostname") or ""), str(rule), None))
    return out, "per-scan fallback"


def _lifecycle_state(client, scans_shards, log, qcount):
    """scan_id -> {"terminal": bool, "newest_ms": int} from ONE aggregate per shard.

    Reading every lifecycle row to learn a status field would be a full-table read per
    dataset; a comp stage answers the same question in one row per (scan_id, status).
    """
    state = {}
    for ds in scans_shards:
        try:
            qcount[0] += 1
            rows = client.xql("dataset = %s | comp count() as n, "
                              "max(event_timestamp_ms) as newest by scan_id, status" % ds,
                              limit=10000) or []
        except Exception as e:
            # An unreadable lifecycle means UNKNOWN, never "finished". Skipping the shard is
            # the safe direction - it survives to the next run.
            log("  ! lifecycle unreadable for %s (%s) - its scans stay untouched" % (ds, e))
            continue
        for r in rows:
            sid = r.get("scan_id")
            if not sid:
                continue
            newest = _as_ms(r.get("newest")) or 0
            cur = state.setdefault(sid, {"terminal": False, "newest_ms": 0})
            cur["newest_ms"] = max(cur["newest_ms"], newest)
            st = str(r.get("status") or "").lower()
            if st in TERMINAL_LIFECYCLE:
                cur["terminal"] = True
    return state


def main():
    args = demisto.args()
    only = argToList(args.get("scan_id")) or None
    retention_hours = float(args.get("retention_hours") or DEFAULT_RETENTION_HOURS)
    execute = argToBoolean(args.get("execute") or "false")
    dry = not execute
    log_lines = []

    def log(m):
        log_lines.append(str(m))

    try:
        set_schema_version(args.get("schema_version") or DEFAULT_SCHEMA_VERSION)
    except Exception as ex:
        return_error("YaraConsolidateSummary: invalid argument (%s)." % ex)
        return

    ver = str(YARA_SCHEMA_VERSION)
    cutoff_ms = retention_hours * 3600 * 1000
    now_ms = int(time.time() * 1000)
    qcount = [0]          # XQL queries ISSUED, succeeded or not; the dataset listing is not
                          # an XQL and is reported separately rather than folded in here
    findings = [0]        # the discarded count() aggregate, summed for the report line
    written, skipped, failed, modes = [], [], [], set()

    client = CoreApiClient()

    # A writing run takes the same lock YaraConsolidateApply takes: two passes creating and
    # filling the same per-scan target is the collision it exists for. A dry run never takes
    # it, because it mutates nothing.
    if execute and not acquire_consolidation_lock(client, log=log,
                                                  holder="YaraConsolidateSummary"):
        return_results(CommandResults(
            readable_output="Another consolidation run holds the lock - nothing was touched.",
            outputs_prefix="Yara.ConsolidateSummary",
            outputs={"status": "lock_held_by_other_run"}))
        return

    try:
        names = _list_yara_datasets(client)
        shards = {}
        for n in names:
            p = parse_shard(n)
            if p and str(p.get("ver")) == ver:
                shards[n] = p
        scans_ds = [n for n, p in shards.items() if p["kind"] == "scans"]
        match_ds = [n for n, p in shards.items() if p["kind"] == "matches"]
        existing = set(names)
        log("schema v%s: %d matches shard(s), %d scans shard(s)"
            % (ver, len(match_ds), len(scans_ds)))

        # ---- 1. lifecycle, so a still-running scan can be told from a finished one ------
        state = _lifecycle_state(client, scans_ds, log, qcount)
        log("lifecycle: %d scan(s) known" % len(state))

        # ---- 2. ONE query per host shard -> (scan_id, hostname, rule) -------------------
        # Every shard is read BEFORE any scan is written: a scan can span hosts, and its
        # summary must carry every host's rules, not the first shard's.
        by_scan = {}
        for ds in sorted(match_ds):
            try:
                tuples, mode = summarise_shard(client, ds, ver, qcount, log, findings)
                modes.add(mode)
            except Exception as e:
                skipped.append("%s: unreadable (%s)" % (ds, str(e)[:120]))
                continue
            for sid, host, rule, ts in tuples:
                # Dedupe on the full key: a host with a leftover month-suffixed matches
                # dataset alongside its permanent one is two shards for one host. Keep the
                # newest ts.
                slot = by_scan.setdefault(sid, {})
                prev = slot.get((host, rule))
                slot[(host, rule)] = _max_ms(prev, ts) if prev is not None else ts

        log("collected %d scan(s) across %d matches shard(s); %d file-level finding(s) "
            "collapsed" % (len(by_scan), len(match_ds), findings[0]))

        # ---- 3. gate, then write ONE ROW PER (host, rule) -------------------------------
        for sid in sorted(by_scan):
            if only and sid not in only:
                continue
            pairs = by_scan[sid]
            st = state.get(sid) or {}
            terminal = bool(st.get("terminal"))
            # Recency comes from the lifecycle stamp, or - when the scan has no lifecycle row
            # at all, because its scans shard was pruned or rotated away - from the newest
            # matches stamp this run already read. Without that second source such a scan
            # could never be summarised.
            newest = int(st.get("newest_ms") or 0)
            for ts in pairs.values():
                newest = max(newest, int(ts or 0))
            aged = bool(newest) and (now_ms - newest) >= cutoff_ms
            if not terminal and not aged:
                skipped.append("%s: scan still in progress - left alone" % sid[:34])
                continue
            why = "completed" if terminal else "no lifecycle activity for %gh" % retention_hours

            rows = [{"scan_id": sid, "hostname": host, "rule": rule,
                     "event_timestamp_ms": int(ts) if ts else (newest or now_ms)}
                    for (host, rule), ts in sorted(pairs.items())]
            rows = [_coerce_row(r, SUMMARY_SCHEMA) for r in rows]
            hosts = len({h for h, _ in pairs})
            target = summary_target_name(ver, sid)

            if dry:
                written.append("%s: WOULD write %d (host, rule) row(s) from %d host(s) -> %s "
                               "(%s, ~%.1f KB)"
                               % (sid[:34], len(rows), hosts, target, why,
                                  len(rows) * _SUMMARY_ROW_BYTES / 1024.0))
                continue

            # Idempotency. target_name() slugifies the scan_id down to [a-z0-9_], so
            # interpolating the target name into XQL here is safe.
            pre = 0
            if target in existing:
                try:
                    qcount[0] += 1
                    pre = _count(client, target)
                except Exception as e:
                    failed.append("%s: could not count existing target %s (%s) - NOT written"
                                  % (sid[:34], target, str(e)[:100]))
                    continue
            if pre and pre == len(rows):
                skipped.append("%s: target already holds %d row(s) - verified, not rewritten"
                               % (sid[:34], pre))
                continue
            if pre:
                # Appending would duplicate (host, rule) pairs and this automation has no
                # delete path to undo that. The host dataset still holds everything, so
                # nothing is lost by declining.
                failed.append("%s: target %s holds %d row(s), this run computed %d - NOT "
                              "written (appending would duplicate (host, rule) pairs)"
                              % (sid[:34], target, pre, len(rows)))
                continue

            try:
                client.create_lookup_dataset(target, SUMMARY_SCHEMA)
                added, ok = 0, True
                for i in range(0, len(rows), _WRITE_BATCH):
                    reply = client.add_lookup_data(target, rows[i:i + _WRITE_BATCH])
                    got = _added(reply)
                    if got <= 0:
                        # A batch that added nothing is a failed write. Nothing is ever
                        # deleted here, so it is reported rather than guarded against -
                        # re-running simply retries.
                        ok = False
                        break
                    added += got
                if ok:
                    written.append("%s: wrote %d (host, rule) row(s) from %d host(s) -> %s (%s)"
                                   % (sid[:34], added, hosts, target, why))
                else:
                    failed.append("%s: write to %s returned 0 rows added after %d - re-run to "
                                  "retry (host shards are untouched)" % (sid[:34], target, added))
            except Exception as e:
                failed.append("%s: %s - host shards untouched" % (sid[:34], str(e)[:140]))

        # ---- 4. there is no step 4. NOTHING IS DELETED ---------------------------------
        # No delete_dataset, no remove_lookup_data, no _delete_many anywhere in this file.
        # The host matches dataset is permanent and is overwritten by the NEXT scan on that
        # host; the scans shard is the lifecycle record every future pass gates on.

    finally:
        if execute:
            try:
                release_consolidation_lock(client, log=log)
            except Exception as e:
                log("lock release failed: %s" % e)

    head = "DRY RUN - nothing was created or written." if dry else "EXECUTED."
    out = ["%s  XQL calls: %d (+1 dataset listing)%s"
           % (head, qcount[0],
              ("  [%s]" % ", ".join(sorted(modes))) if modes else ""),
           "written: %d | skipped: %d | failed: %d | file-level findings collapsed: %d"
           % (len(written), len(skipped), len(failed), findings[0]),
           "host shards deleted: 0 (this automation never deletes - the host dataset is the "
           "deep-dive source)"]
    for label, items in (("WRITTEN", written), ("SKIPPED", skipped), ("FAILED", failed)):
        if items:
            out.append("")
            out.append("%s:" % label)
            out += ["  " + s for s in items[:60]]
            if len(items) > 60:
                out.append("  ... and %d more" % (len(items) - 60))
    lock_log = [m for m in log_lines if "lock" in m.lower()]
    if lock_log:
        out.append("")
        out.append("lock events:")
        out += ["  " + m for m in lock_log]

    # List-valued context is APPENDED to across repeated calls in one investigation; clear
    # it first so written/skipped/failed never carry a prior call's entries.
    demisto.executeCommand("DeleteContext", {"key": "Yara.ConsolidateSummary"})
    result = {"dry_run": dry, "xql_calls": qcount[0], "written": written,
              "skipped": skipped, "failed": failed, "schema_version": ver,
              "retention_hours": retention_hours, "shards_deleted": 0,
              "findings_collapsed": findings[0], "query_modes": sorted(modes)}
    return_results(CommandResults(readable_output="\n".join(out),
                                  outputs_prefix="Yara.ConsolidateSummary", outputs=result,
                                  raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
