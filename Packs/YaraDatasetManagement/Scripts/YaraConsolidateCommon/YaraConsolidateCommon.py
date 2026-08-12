"""Shared library automation for the YARA dataset-management playbook.

Not invoked directly by the playbook — the four thin automations
(YaraConsolidateStatus, YaraConsolidateApply, YaraReport, YaraCleanup) import from this
module. It embeds xdr_consolidate.py's client-agnostic core logic unchanged (that module
takes a duck-typed `client`: get_datasets/xql/create_lookup_dataset/add_lookup_data/
delete_dataset) plus a client implementation that reaches the tenant's own public API
through the already-configured Cortex Core - IR integration's generic REST bridge
(core-api-post), rather than embedding separate signed credentials in the script.

Endpoint paths and request-wrapping ("request" vs "request_data" as the top-level JSON
key, the v2 delete path) are ported from xdr_action_center.py's XDRActionCenter class,
which is the already-live-verified reference for this tenant's API.
"""
import json
import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


# ============================================================================
# xdr_consolidate.py core logic — verbatim port. That module is the one unit-tested with no
# network in tests/test_consolidation.py against a FakeClient; the copy below is held to it by
# test_pack_copy_gate_logic_matches_xdr_consolidate, which compares the two files' gate
# helpers statement-by-statement so this copy cannot silently drift out of sync again. See
# xdr_consolidate.py for full comments.
# ============================================================================
import collections
import re

_PREFIX = "yara_scanner"
_SHARD_RE = re.compile(
    r"^yara_scanner_(?P<kind>matches|scans)_v(?P<ver>\d+)_(?P<host>.+?_[0-9a-f]{6})(?:_(?P<month>\d{6}))?$"
)
TERMINAL_LIFECYCLE = {"completed", "cancelled", "failed"}
# Kept in sync with xdr_consolidate.py's TERMINAL_ACTION — see that module for the
# provenance comment (union of every Action Center state this repo's tooling has observed
# as terminal from live polling, plus ABORTED/CANCELLED for Gate B).
TERMINAL_ACTION = {"COMPLETED_SUCCESSFULLY", "FAILED", "ABORTED", "EXPIRED",
                   "TIMEOUT", "CANCELED", "CANCELLED",
                   "COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"}
DEFAULT_QUIET_SECS = 900
DEFAULT_ROW_CEILING = 2_000_000
DEFAULT_ABANDONED_SECS = 24 * 3600
DELETE_CONCURRENCY = 12
_WRITE_BATCH = 500
# Endpoint-clock-skew tolerances (edge case #6) — kept in sync with xdr_consolidate.py, see
# that module for the reasoning and the live measurements behind both numbers.
SKEW_TOLERANCE_MS = 5 * 60 * 1000
DEFAULT_SKEW_BACKSTOP_SECS = 7 * 24 * 3600

# v2: one row per matched string offset (pre-3.0.0 scanner). v3: one row per (rule, file)
# finding — see xdr_yara_scanner.py's add_match docstring for why. Both stay consolidatable
# so a tenant mid-rollout of scanner v3.0.0 can still process leftover v2 shards.
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
_MATCHES_SCHEMAS_BY_VER = {"2": MATCHES_SCHEMA, "3": MATCHES_SCHEMA_V3}
KNOWN_MATCHES_SCHEMA_VERSIONS = tuple(sorted(_MATCHES_SCHEMAS_BY_VER))


def matches_schema_for(ver):
    return _MATCHES_SCHEMAS_BY_VER.get(str(ver), MATCHES_SCHEMA_V3)


SCANS_SCHEMA = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "status": "text", "scan_folder": "text", "files_scanned": "number",
    "files_skipped": "number", "detections": "number", "valid_rules": "number",
    "failed_rules": "number", "scan_rate_fps": "number", "elapsed_secs": "number",
    "total_paused_secs": "number", "throttle_mode": "text", "posture": "text",
    "event_timestamp_ms": "number", "message": "text",
}

# ---- overlap guard (defense in depth against a misconfigured/broken Job queue-handling
# setting letting two consolidate_all runs collide on the same per-scan target) ----
_LOCK_DATASET = "yara_scanner_consolidation_lock"
_LOCK_SCHEMA = {"holder": "text", "started_ms": "number"}
DEFAULT_LOCK_STALE_SECS = 2 * 3600


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
                               stale_after_secs=DEFAULT_LOCK_STALE_SECS, holder="unknown"):
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    resp = client.create_lookup_dataset(_LOCK_DATASET, _LOCK_SCHEMA)
    fresh = isinstance(resp, dict) and "dataset_name" in resp
    if not fresh:
        held_ms = _read_lock(client)
        if held_ms is not None and (now_ms - held_ms) < stale_after_secs * 1000:
            log("consolidation lock held (age %.0fs) - another run appears to be in "
                "progress; skipping this pass" % ((now_ms - held_ms) / 1000.0))
            return False
        log("consolidation lock is stale or unreadable (%s) - taking over"
            % ("age unknown" if held_ms is None else "age %.0fs" % ((now_ms - held_ms) / 1000.0)))
        client.delete_dataset(_LOCK_DATASET, force=True)
        client.create_lookup_dataset(_LOCK_DATASET, _LOCK_SCHEMA)
    client.add_lookup_data(_LOCK_DATASET, [{"holder": str(holder), "started_ms": now_ms}])
    return True


def release_consolidation_lock(client, log=print):
    try:
        client.delete_dataset(_LOCK_DATASET, force=True)
    except Exception as e:
        log("could not release consolidation lock: %s" % e)


# ---- consolidation run-log (edge case #36/#53) ------------------------------
# A persistent, tenant-queryable record of each YaraConsolidateApply pass's outcome — the
# only dashboard-visible signal for whether the twice-daily consolidation pipeline itself is
# healthy. Task 8 ("Flag failures for attention") only writes to that one run's OWN ephemeral
# XSOAR investigation context, which nothing else reads and which a total execution crash
# (return_error on task 1/4/6, halting the playbook before task 8 is ever reached) bypasses
# entirely — this dataset is what a widget can actually query, for every outcome including
# a crash. See widgets/xdr/Consolidation Run Health.xql.
_RUNS_DATASET = "yara_scanner_consolidation_runs"
_RUNS_SCHEMA = {
    "run_ts_ms": "number", "status": "text", "consolidated_count": "number",
    "failed_count": "number", "failed_scan_ids": "text", "failed_reasons": "text",
    "error_message": "text",
}


def record_consolidation_run(client, status, result=None, error_message="", now_ms=None, log=print):
    """Best-effort: write ONE row per YaraConsolidateApply invocation recording its outcome.

    status is "success" (result["failed_count"] == 0), "partial_failure"
    (result["failed_count"] > 0), or "crashed" (consolidate_all raised before returning —
    result is then None/absent and error_message carries the exception text).

    A failure to WRITE this row must never mask or replace the run's real outcome — the
    caller still return_error()s / returns its normal CommandResults exactly as before
    regardless of whether this call succeeds; that is why every exception here is caught and
    only logged, never re-raised."""
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
    """Epoch-ms int from whatever XQL hands back (int, float, numeric/exponent string, ISO
    timestamp), or None. Never raises - see xdr_consolidate.py for why each shape is accepted."""
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
    event_timestamp_ms and the platform's server-side _insert_time, with implausible values
    discarded first (endpoint stamp ahead of ingest = a clock running ahead; server stamp far
    in the future of now_ms = a unit mismatch). Edge case #6 - see xdr_consolidate.py's copy
    for the full reasoning, including why this must never be reduced to _insert_time alone and
    why both callers may only ever be fed SOURCE SHARDS, never a per-scan target."""
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
    """Once scan_id's per-scan target is verified, strip just its rows out of every source
    shard right away - narrowing the window where a dashboard querying the wildcard
    double-counts it (once from the shard, once from the already-complete target), rather
    than waiting for the whole shard to become deletable (every OTHER scan it holds also
    finished). Sequential - remove_lookup_data is documented NOT concurrency-safe. Best
    effort: a failure here must not affect the scan's (already-verified) plan, and must not
    block the eventual whole-shard delete_dataset() once every scan sharing that shard is
    also done - that cleanup is separate and unconditional on this succeeding.

    Callers must only invoke this for kind=="matches" - see xdr_consolidate.py's identical
    helper for why "scans" shards must never be stripped this way (their rows are the sole
    source of build_terminal_map's lifecycle signal for sibling scans still sharing that
    shard)."""
    for ds in srcs:
        try:
            client.remove_lookup_data(ds, [{"scan_id": scan_id}])
        except Exception as e:
            log("  scan %s: row-level cleanup of %s FAILED (leaving rows for eventual "
                "whole-shard delete instead): %s" % (scan_id, ds, str(e)[:120]))


def _scan_stats(client, dataset, now_ms=None, log=None):
    """{scan_id: _ScanStat(count, newest, ep_newest)} via aggregation - no row pull. newest is
    skew-proofed per _newest_ms: max(_insert_time) rides along in the same comp stage (verified
    working on the live tenant). dataset MUST be a source shard, never a per-scan target."""
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
    """A silently-inactive skew protection (platform stopped returning _insert_time) must be
    visible in the Job's log rather than degrade unnoticed to pre-fix behaviour."""
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
    """Same shape as _scan_stats but from already-read rows (used for tiny scans shards); here
    _insert_time arrives as a system column on each read-back row rather than from the
    aggregation. Rows MUST come from a source shard, never a per-scan target."""
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
    """Defer-reason string if any source host is not safe yet, else ''. Both age checks measure
    the skew-proof `newest` EXCEPT the `settled` backstop, which uses the endpoint stamp alone -
    the one value nothing but the endpoint itself can re-arm. See xdr_consolidate.py."""
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
    # ver selects ONE schema version's shards - a v2 shard and a v3 shard for the same scan
    # have different columns, so mixing them under one schema would mis-project every row.
    # check_consolidation_status/consolidate_all fan out across every known version; this
    # function only ever handles one per call.
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
            # A retry of a previously-failed cleanup naturally lands here: this scan's target
            # was already written+verified by an earlier run, but the row-level cleanup below
            # may not have (fully) succeeded that time. Retry it now.
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue                                          # <-- PATH A: idempotent re-verify
        if pre > src_total > 0:
            # Target holds MORE rows than the currently-live sources sum to - expected once
            # row-level cleanup has partially landed on a multi-shard scan (src_total is
            # recomputed fresh every run from whatever source shards are still live, so it
            # shrinks as cleanup succeeds on some sources while pre stays fixed at the
            # original, correct total). Stay verified and retry cleanup on what's left.
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
    # Covers every known schema version by default - a tenant mid-rollout of a new scanner
    # version has both old- and new-schema shards live at once, and both need consolidating.
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
                    now_ms=None, action_state_for=None, log=print):
    if not dry_run and not acquire_consolidation_lock(client, log=log, now_ms=now_ms):
        return {"consolidated_count": 0, "consolidated_scan_ids": [],
                "deferred_count": 0, "deferred_scan_ids": [],
                "failed_count": 0, "failed_scan_ids": [], "failed_reasons": {},
                "lock_held_by_other_run": True}
    try:
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
            "failed_count": len(failed), "failed_scan_ids": sorted(failed),
            "failed_reasons": failed_reasons}


# ============================================================================
# In-platform client: reaches this tenant's own public API directly over HTTPS with
# signed Advanced (HMAC) credentials.
#
# The original design called the tenant's own API through the Cortex Core - IR
# integration's generic REST bridge (demisto-api-post / core-api-post), avoiding a
# separate embedded credential. Measured live against this tenant, 2026-08-10: NEITHER
# command is registered here at all (automation/search for *api*/*core* returns zero
# results) - a real platform gap on this specific Cortex XDR tenant, not a wording or
# fallback bug. There is no generic REST bridge available to call through.
#
# Falls back to the SAME pattern xdr_yara_scanner.py already uses for the same problem
# (a script needing tenant credentials without a bridge available): placeholder
# constants substituted with real values before upload, never committed filled-in.
# Auth logic (HMAC signing) ported verbatim from xdr_action_center.py's
# XDRActionCenter._advanced_headers - the already-live-verified reference for this
# tenant, used throughout this whole repo's live validation.
# ============================================================================
DEFAULT_XDR_API_KEY = "replace_with_xdr_advanced_api_key"
DEFAULT_XDR_API_ID = "replace_with_xdr_advanced_api_id"
DEFAULT_XDR_API_URL = "replace_with_xdr_api_url"


class CoreApiClient:
    """xdr_consolidate's duck-typed client interface, backed by a direct, signed HTTPS
    call to this tenant's own public API (see module-level note above for why - no
    generic REST bridge command is registered on this tenant)."""

    def __init__(self, poll_secs=3, max_polls=60):
        self.poll_secs = poll_secs
        self.max_polls = max_polls
        self.base = DEFAULT_XDR_API_URL.rstrip("/")
        if "/public_api" in self.base:
            self.base = self.base[:self.base.index("/public_api")]
        if self.base.startswith("replace_with"):
            raise RuntimeError("XDR API credentials are not set - edit the three "
                               "DEFAULT_XDR_* constants and re-upload.")

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
                    # A rotated/expired/revoked key will not fix itself between retries —
                    # fail fast instead of burning 3 pointless 3/6/9s sleeps first (#47).
                    raise
                msg = msg.lower()
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
                    # Same reasoning as add_lookup_data (#47): a dead key won't recover
                    # across retries, so fail on the first call instead of 3x 5/10/15s sleeps.
                    raise
                msg = str(e).lower()
                if "not found" in msg or "nonetype" in msg:
                    return {"status": "already_deleted"}
                time.sleep(5 * (attempt + 1))
        raise last
