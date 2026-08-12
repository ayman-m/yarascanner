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

__version__ = "2.6.0"

# ---- naming -----------------------------------------------------------------
# per-host shard:  yara_scanner_<kind>_v<ver>_<host>_<6hex>[_<YYYYMM>]
# per-scan target: yara_scanner_<kind>_v<ver>_scan_<scan_id>
_PREFIX = "yara_scanner"
_SHARD_RE = re.compile(
    r"^yara_scanner_(?P<kind>matches|scans)_v(?P<ver>\d+)_(?P<host>.+?_[0-9a-f]{6})(?:_(?P<month>\d{6}))?$"
)

TERMINAL_LIFECYCLE = {"completed", "cancelled", "failed"}
# Union of every Action Center state this repo's tooling has observed as terminal from live
# polling (xdr_action_center.py's TERMINAL_STATES / xdr-yara-scan-test's xdr_lib.wait_action)
# plus ABORTED/CANCELLED, which those two don't carry but this module needs (Gate B rescues a
# console-Cancel-killed host via exactly that state). COMPLETED_WITH_ERRORS/COMPLETED_PARTIAL
# were missing here even though both live-verified-terminal sets already include them.
TERMINAL_ACTION = {"COMPLETED_SUCCESSFULLY", "FAILED", "ABORTED", "EXPIRED",
                   "TIMEOUT", "CANCELED", "CANCELLED",
                   "COMPLETED_WITH_ERRORS", "COMPLETED_PARTIAL"}

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

# ---- overlap guard --------------------------------------------------------
# Two consolidate_all runs writing to the SAME per-scan target concurrently is exactly the
# collision per-host sharding exists to prevent (measured elsewhere in this project: 87% row
# loss at 8 concurrent writers to one dataset). The intended safeguard is the XSOAR Job's own
# "don't trigger a new instance" queue-handling setting - but that is a deployment-time console
# setting this code cannot verify, so this is defense in depth for when it is missing or fails.
_LOCK_DATASET = "yara_scanner_consolidation_lock"
_LOCK_SCHEMA = {"holder": "text", "started_ms": "number"}
DEFAULT_LOCK_STALE_SECS = 2 * 3600  # generous: real runs take minutes, not hours


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
    """Best-effort mutual exclusion, NOT a true distributed lock. Relies on
    create_lookup_dataset distinguishing a fresh create ({"dataset_name": ...}) from an
    already-exists response ({"status": "exists"}) - verified live against the real API.
    Good enough to catch the common case (a stuck/misconfigured scheduler), not to guarantee
    correctness under a genuine simultaneous race (there is an inherent check-then-act window
    between the create call and any concurrent caller's own create call).

    Returns True if the lock was acquired (caller MUST release it via
    release_consolidation_lock), False if another run appears to already hold it."""
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
        # Delete-then-recreate rather than just appending a fresh row: leaving the stale
        # row(s) in place would let a future _read_lock pick up an arbitrary (not
        # necessarily newest) row, and the dataset would accumulate one row per steal
        # forever.
        client.delete_dataset(_LOCK_DATASET, force=True)
        client.create_lookup_dataset(_LOCK_DATASET, _LOCK_SCHEMA)
    client.add_lookup_data(_LOCK_DATASET, [{"holder": str(holder), "started_ms": now_ms}])
    return True


def release_consolidation_lock(client, log=print):
    """Best-effort - a failed release just means the next run waits out stale_after_secs
    rather than anything being corrupted."""
    try:
        client.delete_dataset(_LOCK_DATASET, force=True)
    except Exception as e:
        log("could not release consolidation lock: %s" % e)


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
# v2: one row per matched string offset. Superseded by v3 (scanner v3.0.0) — one row per
# (rule, file) finding, offsets/strings/string_ids folded into the row — but v2 shards may
# still exist on a tenant from before the upgrade, so both stay consolidatable.
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
# Versions run_consolidation/check_consolidation_status/consolidate_all cover by default when
# no explicit version is requested — every schema version this tool knows how to read.
KNOWN_MATCHES_SCHEMA_VERSIONS = tuple(sorted(_MATCHES_SCHEMAS_BY_VER))


def matches_schema_for(ver):
    """The matches-dataset schema for a given version tag. Unknown versions fall back to the
    latest known schema rather than raising — a consolidation run should degrade to 'best
    effort against an unrecognised newer shard', not hard-fail the whole pass."""
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


def _cleanup_verified_scan_rows(client, srcs, scan_id, log):
    """Once scan_id's per-scan target is verified, strip just its rows out of every source
    shard right away — narrowing the window where a dashboard querying the wildcard
    double-counts it (once from the shard, once from the already-complete target), rather
    than waiting for the whole shard to become deletable (every OTHER scan it holds also
    finished). Sequential — remove_lookup_data is documented NOT concurrency-safe. Best
    effort: a failure here must not affect the scan's (already-verified) plan, and must not
    block the eventual whole-shard delete_dataset() once every scan sharing that shard is
    also done — that cleanup is separate and unconditional on this succeeding.

    Callers must only invoke this for kind=="matches". A "scans" shard's rows are also the
    sole source of build_terminal_map's per-(scan_id, host) lifecycle signal, which a LATER,
    separate run_consolidation call (any kind, rebuilt fresh from current scans shards each
    time) needs for every OTHER scan still sharing that shard — stripping a verified scan's
    status row out from under them would make that sibling's lifecycle silently vanish
    (build_terminal_map: absent == not-terminal), misclassifying a cleanly-finished scan as
    stuck until the 24h abandoned-scan cutoff bails it out. "matches" shards carry no
    lifecycle data, so they have no such consumer and are always safe to strip."""
    for ds in srcs:
        try:
            client.remove_lookup_data(ds, [{"scan_id": scan_id}])
        except Exception as e:
            log("  scan %s: row-level cleanup of %s FAILED (leaving rows for eventual "
                "whole-shard delete instead): %s" % (scan_id, ds, str(e)[:120]))


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
    add_lookup_data(name, rows), remove_lookup_data(name, filters), delete_dataset(name, force).
    action_state_for(host)->state is optional (Gate B); without it only the lifecycle gate
    applies.

    ver selects ONE schema version's shards, not every version present on the tenant — a v2
    shard and a v3 shard for the same scan have different columns, so mixing them into one
    target under one schema would silently mis-project every row. Call once per version (see
    check_consolidation_status/consolidate_all, which already do this) to cover a tenant that
    has both, e.g. mid-rollout of a new scanner version.
    """
    ver = str(ver)
    schema = matches_schema_for(ver) if kind == "matches" else SCANS_SCHEMA
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

    all_ds = _list_yara_datasets(client)
    shards = [d for d in all_ds
              if (parse_shard(d) or {}).get("kind") == kind and (parse_shard(d) or {}).get("ver") == ver]
    if not shards:
        log("no %s shards found" % kind)
        return []

    # Terminality lives in the SCANS shards (matches rows carry no status), so always load
    # them for the per-(scan_id, host) terminal map — even when consolidating matches. Scans
    # shards are tiny (a few rows per scan), so a full read is cheap. Deliberately NOT
    # filtered by ver like `shards` above: the scans row shape hasn't changed across schema
    # versions (only the matches row shape has), scan_id is globally unique so there is no
    # cross-version key collision, and reading every version's scans shards only makes the
    # terminal map MORE complete — never wrong — regardless of which matches version this
    # particular call is consolidating.
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
            # A retry of a previously-failed cleanup naturally lands here: this scan's target
            # was already written+verified by an earlier run, but the row-level cleanup below
            # may not have (fully) succeeded that time. Retry it now.
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
            plans.append(plan_consolidation(scan_id, counts, pre, row_ceiling))
            continue                                          # <-- PATH A: idempotent re-verify
        if pre > src_total > 0:
            # The target holds MORE rows than the sources currently visible sum to. This is
            # NOT corruption — it is the expected shape once row-level cleanup has partially
            # landed: `src_total` is recomputed EVERY run from whatever source shards are
            # still live, so it shrinks as cleanup (row removal and/or eventual whole-shard
            # delete) succeeds on some sources, while `pre` — the target's actual row count —
            # stays fixed at the original, correct total written when every source still had
            # its rows. A transient failure on just ONE of a multi-shard scan's sources (a
            # sibling shard's cleanup/delete having already succeeded this run or an earlier
            # one) would otherwise permanently misdiagnose this as count_mismatch below,
            # never retry the failed cleanup again, and leave the still-dirty shard
            # undeletable forever (edge case #51a follow-up). Stay verified and retry cleanup
            # on whatever sources are still visible.
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
            verified.add(scan_id)                             # <-- PATH B: fresh write verified
            if kind == "matches":
                _cleanup_verified_scan_rows(client, srcs, scan_id, log)
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


def check_consolidation_status(client, kinds=("matches", "scans"), vers=KNOWN_MATCHES_SCHEMA_VERSIONS,
                               quiet_secs=DEFAULT_QUIET_SECS, row_ceiling=DEFAULT_ROW_CEILING,
                               abandoned_after_secs=DEFAULT_ABANDONED_SECS,
                               only_scan_ids=None, now_ms=None, action_state_for=None,
                               log=lambda *a: None):
    """Read-only readiness check: never writes or deletes (drives run_consolidation with
    dry_run=True for every kind/version, whose write/delete passes never execute in that
    mode). Safe to call repeatedly, including from inside a wait/retry poll loop.

    Covers every known schema VERSION by default (not just the latest) — a tenant mid-rollout
    of a new scanner version has both old- and new-schema shards live at once, and both need
    consolidating; run_consolidation itself only ever looks at one version per call (see its
    docstring), so this is the layer that fans out across versions.

    A scan counts as ELIGIBLE only if every kind's shards agree it's ready — a scan whose
    scans-lifecycle shard is done but whose matches shard is still draining is still
    in-progress, not eligible, since each kind computes its own gate independently.

    blocked_reasons maps each blocked scan_id to plan_consolidation's own reason string
    (e.g. "row_ceiling_exceeded" vs "count_mismatch") — collapsing every non-deferred failure
    into one opaque "blocked" bucket makes a permanently-stuck oversized scan
    indistinguishable from a genuine data-integrity concern; this is the one place that
    distinction survives to be surfaced by a caller (see YaraConsolidateStatus.py)."""
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
    """Drive run_consolidation across kinds AND schema versions, returning a structured
    summary instead of printing and discarding it — the same call
    xdr_data_management._run_consolidate already makes, extracted so both the CLI and an
    XSOAR automation can share it. See check_consolidation_status for why every known version
    is covered by default, not just the latest.

    Unlike check_consolidation_status, this does NOT cross-kind-dedupe: a scan_id can
    legitimately appear in both consolidated_scan_ids (its scans-lifecycle shard, tiny,
    finished first) and deferred_scan_ids (its matches shard, still draining) in the same
    call — each kind's target dataset is independent, so partial-by-kind completion is a
    real, safe state, not an error to hide.

    Write passes (dry_run=False) take a best-effort overlap guard first (see
    acquire_consolidation_lock) — if another run appears to already hold it, this returns
    immediately with lock_held_by_other_run=True and nothing touched. Dry runs never write or
    delete, so they skip the lock entirely and can run concurrently with anything."""
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
