#!/usr/bin/env python3
"""Consolidate per-host YARA lookup datasets into one dataset per scan, then delete
the per-host sources — safely, at fleet scale.

WHY THIS EXISTS
    The scanner writes one dataset per host, because XDR's lookups/add_data is not
    concurrency-safe: two endpoints writing the SAME dataset collide server-side and lose
    rows silently. That is correct for writing, but a 7,000-host scan then leaves 7,000
    dataset pairs. This tool folds each scan's shards back into a single per-scan dataset
        yara_scanner_matches_v2_scan_<scan_id>
        yara_scanner_scans_v2_scan_<scan_id>
    and removes the shards, so the tenant's dataset count is bounded by scans, not hosts.

WHY PER-SCAN AND NOT ONE-DATASET-FOREVER
    add_data merge time scales with the TARGET dataset's size, so a single forever-growing
    dataset eventually goes write-dead — the exact failure monthly rotation exists to
    prevent. One dataset per scan keeps each target bounded to a single scan's output.

SAFETY (this tool DELETES datasets)
    1. Consolidation is a SINGLE sequential writer to its target — never concurrent, so it
       is not exposed to the collision it is cleaning up after.
    2. A host's shard is processed only when that host's scan is genuinely finished:
       terminal lifecycle row, OR terminal Action Center state (rescues console-cancelled
       hosts whose lifecycle is stuck at "running"), AND the newest row older than a quiet
       period so the uploader has finished draining.
    3. VERIFY BEFORE DELETE: a shard is deleted only after the target row count equals the
       sum of source counts. A mismatch keeps every source and reports it.
    4. A row ceiling refuses to start a consolidation too large to finish, rather than
       half-building a target and stranding it.

The pure decision logic (parsing, grouping, gates, plan) is below and unit-tested with no
network. The live orchestration (run_consolidation) uses an injected client so it can be
driven against the real API or a fake.
"""
import re
import sys
import time

__version__ = "2.1.0"

# ---- naming -----------------------------------------------------------------
# per-host shard:  yara_scanner_<kind>_v<ver>_<host>_<6hex>[_<YYYYMM>]
# per-scan target: yara_scanner_<kind>_v<ver>_scan_<scan_id>
_PREFIX = "yara_scanner"
_SHARD_RE = re.compile(
    r"^yara_scanner_(?P<kind>matches|scans)_v(?P<ver>\d+)_(?P<host>.+?_[0-9a-f]{6})(?:_(?P<month>\d{6}))?$"
)

TERMINAL_LIFECYCLE = {"completed", "cancelled", "failed"}
TERMINAL_ACTION = {"COMPLETED_SUCCESSFULLY", "FAILED", "ABORTED", "EXPIRED",
                   "TIMEOUT", "CANCELED", "CANCELLED"}

DEFAULT_QUIET_SECS = 900       # >= the scanner's max lookup drain budget (600s) + margin
DEFAULT_ROW_CEILING = 2_000_000
# A non-terminal scan whose newest row is older than this is treated as ABANDONED: the
# scanner never wrote a terminal row (typically a console-Cancel hard-kill, which orphans
# the lifecycle at "running"/"initiated" forever). Past this age it stops blocking its
# shard's cleanup. 24h comfortably exceeds the 6h Action Center script timeout, so a scan
# still legitimately running cannot be mistaken for abandoned. Its partial matches are REAL
# findings, so an abandoned scan is still consolidated (preserved), not dropped.
DEFAULT_ABANDONED_SECS = 24 * 3600
DELETE_CONCURRENCY = 12        # a single dataset delete is ~60s server-side; different-dataset
                               # deletes don't race, so delete in bounded-concurrent batches


def target_name(kind, ver, scan_id):
    """Per-scan consolidated dataset name. scan_id is slugified to XDR's [a-z0-9_] rule."""
    slug = re.sub(r"[^a-z0-9]+", "_", str(scan_id).lower()).strip("_") or "unknown"
    return "%s_%s_v%s_scan_%s" % (_PREFIX, kind, ver, slug)


def parse_shard(name):
    """Return {kind, ver, host, month} for a per-host shard, or None.

    Deliberately returns None for a per-scan target (…_scan_<id>): a consolidated dataset
    must never be re-consumed as a source. The host group requires a 6-hex suffix, which
    _dataset_shard_suffix always appends and the literal 'scan' marker never has."""
    if name is None:
        return None
    m = _SHARD_RE.match(name)
    if not m:
        return None
    host = m.group("host")
    if host.startswith("scan_") or host == "scan":
        return None
    return {"kind": m.group("kind"), "ver": m.group("ver"),
            "host": host, "month": m.group("month")}


def group_shards_by_scan(rows_by_dataset, kind):
    """Given {dataset_name: [rows...]} for shards of one kind, return
    {scan_id: {dataset_name: row_count}}. A dataset may hold rows from more than one scan
    (a host re-scanned in the same month), so grouping is by the scan_id ON THE ROWS."""
    groups = {}
    for ds, rows in rows_by_dataset.items():
        p = parse_shard(ds)
        if not p or p["kind"] != kind:
            continue
        per_scan = {}
        for r in rows:
            sid = r.get("scan_id")
            if sid:
                per_scan[sid] = per_scan.get(sid, 0) + 1
        for sid, n in per_scan.items():
            groups.setdefault(sid, {})[ds] = n
    return groups


def shard_is_terminal(latest_status, action_state):
    """A host's scan is finished if EITHER signal says so.

    latest_status : newest lifecycle row status for this host (scanner's own report)
    action_state  : Action Center state for the host's action (platform's report)

    Both are needed: lifecycle is reliable when the scanner finished cleanly but stuck at
    'running' forever when console-Cancel hard-killed it; the action state is authoritative
    about execution ending but silent about whether rows finished uploading."""
    if latest_status and str(latest_status).lower() in TERMINAL_LIFECYCLE:
        return True
    if action_state and str(action_state).upper() in TERMINAL_ACTION:
        return True
    return False


def build_terminal_map(scans_rows_by_ds, action_state_for=None):
    """Derive terminality per (scan_id, host) from the SCANS shards.

    The lifecycle status lives only in the scans datasets — matches rows carry no status —
    so consolidating EITHER kind must consult this map to know whether a host's scan has
    finished. Returns {(scan_id, host): {terminal, newest_ms, status}}.

    A (scan_id, host) that is absent here has no terminal lifecycle row yet, which the
    caller must treat as NOT safe: matches can stream before the terminal row is written."""
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
            rs_sorted = sorted(rs, key=lambda r: int(r.get("event_timestamp_ms") or 0))
            latest_status = rs_sorted[-1].get("status")
            newest = max((int(r.get("event_timestamp_ms") or 0) for r in rs), default=None)
            astate = action_state_for(host) if action_state_for else None
            out[(sid, host)] = {
                "terminal": shard_is_terminal(latest_status, astate),
                "newest_ms": newest,
                "status": latest_status,
            }
    return out


def newest_row_age_ok(newest_ms, now_ms, quiet_secs):
    """True if the newest row is old enough that the uploader has surely finished draining.
    No rows (newest_ms None) is not a blocker — nothing to wait for."""
    if newest_ms is None:
        return True
    return (now_ms - int(newest_ms)) >= quiet_secs * 1000


def plan_consolidation(scan_id, source_counts, target_count, row_ceiling=DEFAULT_ROW_CEILING):
    """Decide whether this scan's shards may be deleted, given the counts.

    ok=True and deletable=all sources  ONLY when target_count == sum(source_counts) and the
    total is within the ceiling. Any shortfall keeps every source. The ceiling is checked
    against the SOURCE total so an oversize job is refused before writing, not after."""
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


# ---- live orchestration -----------------------------------------------------
MATCHES_SCHEMA = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "rule": "text", "filename": "text", "file_size": "number", "file_sha256": "text",
    "file_creation_time": "text", "scan_folder": "text", "match": "text", "offset": "number",
    "matched_length": "number", "string": "text", "severity": "text",
    "event_timestamp_ms": "number", "date_of_scan": "text",
}
SCANS_SCHEMA = {
    "tenant_id": "text", "scan_id": "text", "run_id": "text", "scan_date": "text",
    "hostname": "text", "os_info": "text", "os_type": "text", "ip_address": "text",
    "status": "text", "scan_folder": "text", "files_scanned": "number",
    "files_skipped": "number", "detections": "number", "valid_rules": "number",
    "failed_rules": "number", "scan_rate_fps": "number", "elapsed_secs": "number",
    "total_paused_secs": "number", "throttle_mode": "text", "posture": "text",
    "event_timestamp_ms": "number", "message": "text",
}
_WRITE_BATCH = 500


def _added(reply):
    """add_data reply carries counts under either 'records_added' or 'rows added'."""
    r = reply or {}
    return int(r.get("records_added", r.get("rows added", 0)) or 0)


def _rows_of(dataset, client, limit=50000):
    return client.xql("dataset = %s" % dataset, limit=limit) or []


def _rows_for_scan(client, dataset, scan_id, limit=50000):
    """Only one scan's rows from a shard — a server-side filter, not a full pull."""
    safe = str(scan_id).replace('"', "")
    return client.xql('dataset = %s | filter scan_id = "%s"' % (dataset, safe), limit=limit) or []


def _scan_stats(client, dataset):
    """{scan_id: (count, newest_ms)} via aggregation — no row pull. This is what lets the
    tool scale: a matches shard with millions of rows is summarised in one query."""
    rows = client.xql("dataset = %s | comp count() as n, max(event_timestamp_ms) as newest "
                      "by scan_id" % dataset, limit=10000) or []
    out = {}
    for r in rows:
        sid = r.get("scan_id")
        if sid:
            newest = r.get("newest")
            out[sid] = (int(r.get("n") or 0), int(newest) if newest is not None else None)
    return out


def _coerce_row(row, schema):
    """Project a read-back row to the schema's fields AND coerce values to the schema's
    types. XQL read-back does not round-trip types: a 'number' field can come back as the
    string '0' or the float 9.0, and add_data SKIPS a whole row whose value type does not
    match the field type (verified live: real match rows had offset='0' as text and were all
    skipped, records_added=0). Coercing number->int/float, text->str, bool->bool makes the
    rows land. System columns (_insert_time, ...) are dropped by the projection."""
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


def _stats_from_rows(rows):
    """Same shape as _scan_stats but from already-read rows (used for tiny scans shards)."""
    out = {}
    for r in rows:
        sid = r.get("scan_id")
        if not sid:
            continue
        n, newest = out.get(sid, (0, None))
        ts = r.get("event_timestamp_ms")
        ts = int(ts) if ts is not None else None
        newest = ts if newest is None else (max(newest, ts) if ts is not None else newest)
        out[sid] = (n + 1, newest)
    return out


def run_consolidation(client, kind, ver="2", quiet_secs=DEFAULT_QUIET_SECS,
                      row_ceiling=DEFAULT_ROW_CEILING, dry_run=True, log=print,
                      now_ms=None, action_state_for=None, only_scan_ids=None,
                      abandoned_after_secs=DEFAULT_ABANDONED_SECS):
    """Consolidate every finished scan's shards of one kind. Returns a list of per-scan
    plans. Deletes sources only when dry_run is False AND a scan's plan verifies.

    client must provide: get_datasets(), xql(q, limit), create_lookup_dataset(name, schema),
    add_lookup_data(name, rows), delete_dataset(name, force). action_state_for(host)->state
    is optional (Gate B); without it only the lifecycle gate applies.
    """
    schema = MATCHES_SCHEMA if kind == "matches" else SCANS_SCHEMA
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

    all_ds = _list_yara_datasets(client)
    shards = [d for d in all_ds if (parse_shard(d) or {}).get("kind") == kind]
    if not shards:
        log("no %s shards found" % kind)
        return []

    # Terminality lives in the SCANS shards (matches rows carry no status), so always load
    # them for the per-(scan_id, host) terminal map — even when consolidating matches. Scans
    # shards are tiny (a few rows per scan), so a full read is cheap.
    scans_ds = [d for d in all_ds if (parse_shard(d) or {}).get("kind") == "scans"]
    scans_rows = {d: _rows_of(d, client) for d in scans_ds}
    tmap = build_terminal_map(scans_rows, action_state_for)

    # Group + count + newest-timestamp per (scan_id, shard) WITHOUT pulling every row. A
    # matches shard can hold millions of rows; pulling them all just to group by scan_id does
    # not scale and (measured) makes the read phase outlast the run. Use an XQL aggregation
    # (comp count(), max(ts) by scan_id) instead; full rows are pulled ONLY for the one scan
    # being written, later. Scans shards reuse the rows already read above.
    all_groups, newest_by = {}, {}
    for ds in shards:
        stats = (_stats_from_rows(scans_rows[ds]) if kind == "scans"
                 else _scan_stats(client, ds))
        for sid, (n, newest) in stats.items():
            all_groups.setdefault(sid, {})[ds] = n
            newest_by[(sid, ds)] = newest

    # A shard can hold rows for MORE THAN ONE scan (a host re-scanned in the same month
    # shares its dataset). Deleting a shard after consolidating ONE of its scans would
    # destroy the others' rows. Track each shard's FULL scan membership (from the UNFILTERED
    # grouping, so scan-scoping below cannot make a shard look single-scan) and delete a
    # shard only once EVERY scan in it has been consolidated and verified.
    shard_scans = {}
    for sid, counts in all_groups.items():
        for ds in counts:
            shard_scans.setdefault(ds, set()).add(sid)

    groups = all_groups
    if only_scan_ids is not None:
        want = set(only_scan_ids)
        groups = {s: c for s, c in all_groups.items() if s in want}
    log("found %d %s shard(s) across %d scan(s)" % (len(shards), kind, len(groups)))
    existing = set(all_ds)   # per-scan targets that existed BEFORE this run (idempotency)

    verified = set()
    plans = []
    for scan_id, counts in sorted(groups.items()):
        srcs = sorted(counts)
        deferred = _gate_scan(scan_id, srcs, newest_by, tmap, now_ms, quiet_secs,
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

        # Idempotency: if the per-scan target already holds exactly this scan's rows (a prior
        # run consolidated it but could not yet delete every shared shard), do NOT rewrite —
        # that would duplicate rows. Treat it as verified and move to the deletion pass.
        pre = _count(client, target) if target in existing else 0
        if pre == src_total and src_total > 0:
            log("  scan %s: target already complete (%d rows) — verified, not rewritten"
                % (scan_id, pre))
            verified.add(scan_id)
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue
        if pre not in (0, src_total):
            log("  scan %s: target exists with %d rows, expected %d — NOT touching, reports mismatch"
                % (scan_id, pre, src_total))
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue

        # write: single sequential writer into the per-scan target. Pull ONLY this scan's
        # rows from each source shard (server-side filter), never the whole shard.
        client.create_lookup_dataset(target, schema)
        written = 0
        for ds in srcs:
            rows = _rows_for_scan(client, ds, scan_id)
            # Project to the schema's fields AND coerce to the schema's types. XQL read-back
            # both adds system columns (_insert_time, ...) that add_data rejects, and returns
            # numbers as strings/floats that a 'number' field also rejects — either skips the
            # whole row silently. _coerce_row fixes both. (Caught live twice: synthetic data
            # only hit the field problem; real match rows also hit the type problem.)
            rows = [_coerce_row(r, schema) for r in rows]
            for i in range(0, len(rows), _WRITE_BATCH):
                written += _added(client.add_lookup_data(target, rows[i:i + _WRITE_BATCH]))
        time.sleep(min(30, 2 + src_total // 500))  # let merges settle before counting
        tcount = _count(client, target)
        plan = plan_consolidation(scan_id, counts, tcount, row_ceiling)
        log("  scan %s: wrote %d, target now %d, sources %d -> %s"
            % (scan_id, written, tcount, src_total, "VERIFIED" if plan["ok"] else plan["reason"]))
        if plan["ok"]:
            verified.add(scan_id)
        plans.append(plan)

    # Deletion pass: a shard is safe to delete only when EVERY scan it contains is verified.
    # Deletes run CONCURRENTLY: a single dataset delete takes ~60s server-side, but deletes
    # of DIFFERENT datasets do not race (only add_data to the SAME dataset does), verified
    # live at 4-wide. Serial deletion of a fleet's shards would take days; bounded-concurrent
    # deletion makes it hours. Writes above stay sequential — this parallelism is deletes only.
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


def _delete_many(client, names, log, concurrency=None):
    """Delete datasets concurrently in bounded batches. Different-dataset deletes are safe to
    parallelise (verified live); this turns a fleet's serial ~60s-per-delete into hours."""
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


def _gate_scan(scan_id, srcs, newest_by, tmap, now_ms, quiet_secs, abandoned_after_secs, log):
    """Return a defer-reason string if any source host is not safe yet, else ''.

    A source is eligible when its scan is FINISHED — terminal lifecycle/action state, OR
    ABANDONED (non-terminal but its newest row is older than abandoned_after_secs, so the
    scanner will never write a terminal row; typically a console-Cancel orphan). An
    abandoned scan is still consolidated so its partial matches, which are real findings,
    are preserved rather than dropped. A non-terminal scan younger than the cutoff may still
    be running, so it defers."""
    for ds in srcs:
        host = (parse_shard(ds) or {}).get("host", "")
        entry = tmap.get((scan_id, host))
        is_terminal = bool(entry and entry["terminal"])
        newest = newest_by.get((scan_id, ds))
        if not is_terminal:
            age_ms = (now_ms - newest) if newest is not None else None
            if age_ms is not None and age_ms >= abandoned_after_secs * 1000:
                log("  scan %s: host %s non-terminal (%s) but newest row is %.1fh old — "
                    "treating as ABANDONED, consolidating to preserve its findings"
                    % (scan_id, host, (entry.get("status") if entry else "no lifecycle row"),
                       age_ms / 3_600_000.0))
            else:
                log("  scan %s: host %s not terminal (%s) — deferring"
                    % (scan_id, host, "no lifecycle row" if not entry else entry.get("status")))
                return "host_not_terminal"
        if not newest_row_age_ok(newest, now_ms, quiet_secs):
            log("  scan %s: host shard %s within quiet period — deferring" % (scan_id, ds))
            return "within_quiet_period"
    return ""


def _list_yara_datasets(client):
    """Names of the tenant's yara-owned LOOKUP datasets.

    get_datasets() returns a LIST whose entries key the name under 'Dataset Name' (note the
    capital and space) and the type under 'Type' == 'LOOKUP' — NOT dataset_name/reply, which
    is what a naive read assumes and which silently returns nothing (verified live: a wrong
    key made the whole tool a no-op against real data). A dict form {"data"/"datasets": [...]}
    is also tolerated for forward-compat."""
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


if __name__ == "__main__":
    print("xdr_consolidate %s — import and call run_consolidation(client, kind).\n"
          "This module is the logic; the CLI wrapper lives in xdr_data_management.py."
          % __version__)
    sys.exit(0)
