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
import collections
import re
import sys
import time

__version__ = "2.7.0"

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

# ---- clock-skew tolerances (edge case #6) ----------------------------------
# How far apart the endpoint's own event_timestamp_ms and the platform's _insert_time may
# legitimately be in the "endpoint newer" direction. A row cannot be AUTHORED after the
# platform INGESTED it, so any excess is the endpoint's clock running ahead. Measured live on
# real shards, the honest gap (upload latency, ingest first) was 3.2s / 3.7s / 5.2s / 5.4s /
# 66.8s; 5 minutes is generous headroom over that without tolerating a genuinely wrong clock.
SKEW_TOLERANCE_MS = 5 * 60 * 1000
# Backstop that keeps the abandoned cutoff from being deferrable without limit. The cutoff now
# measures age from max(event_timestamp_ms, _insert_time) (see _newest_ms), and _insert_time is
# only guaranteed to mean "when this row was ingested" as long as nothing REWRITES the shard.
# This tool itself rewrites: _cleanup_verified_scan_rows removes one scan's rows from a shard
# that may still hold OTHER scans' rows. If the platform implements that removal as a
# rewrite/compaction rather than an in-place tombstone (unverified — a live check needs a
# destructive remove against a real shard), the surviving siblings get a fresh _insert_time on
# every cleanup pass, and a host scanned daily could reset an orphan's age before the 24h
# cutoff ever elapses — its shard would then never be deletable. Past this backstop, the
# ENDPOINT stamp alone is enough to call a non-terminal scan abandoned and to satisfy the quiet
# period. The trade is explicit: it gives back skew protection only for a clock wrong by more
# than a week (far rarer than one wrong by hours), and only that far past any plausible scan.
DEFAULT_SKEW_BACKSTOP_SECS = 7 * 24 * 3600

# ---- overlap guard --------------------------------------------------------
# Two consolidate_all runs writing to the SAME per-scan target concurrently is exactly the
# collision per-host sharding exists to prevent (measured elsewhere in this project: 87% row
# loss at 8 concurrent writers to one dataset). The intended safeguard is the XSOAR Job's own
# "don't trigger a new instance" queue-handling setting - but that is a deployment-time console
# setting this code cannot verify, so this is defense in depth for when it is missing or fails.
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
    """Best-effort mutual exclusion, NOT a true distributed lock. Relies on
    create_lookup_dataset distinguishing a fresh create ({"dataset_name": ...}) from an
    already-exists response ({"status": "exists"}) - verified live against the real API.
    Good enough to catch the common case (a stuck/misconfigured scheduler), not to guarantee
    correctness under a genuine simultaneous race (there is an inherent check-then-act window
    between the create call and any concurrent caller's own create call).

    Two knobs exist for callers whose cost of a WRONG takeover is irreversible (dataset
    deletion) rather than a retry (consolidation):

    * unreadable_is_held - treat an existing lock dataset whose row cannot be read as HELD
      instead of stale. That state is not exotic: it is exactly the window right after another
      run created the marker, because add_lookup_data tolerates up to ~60s of create-lag with
      its retries, so the dataset exists before its row does.
    * on_takeover - called with the takeover message when this call DOES steal a lock, so the
      caller can surface "I proceeded while another run's marker was in place" instead of
      reporting an ordinary, uncontended pass.

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
    # v4 is where matches stopped rotating and became overwrite-per-scan, so an UNSUFFIXED
    # matches dataset at v4+ is the scanner's permanent write target, not a rotation shard.
    # Consolidating it would delete the host dataset and leave one per-scan dataset behind
    # for every scan - precisely the unbounded growth the overwrite model removed - and the
    # scanner would recreate the host dataset for the next pass to eat again. A DATED v4
    # matches dataset predates that model and stays ordinary, consolidatable debris; scans
    # still rotates monthly at v4 and is untouched by this.
    if m.group("kind") == "matches" and int(m.group("ver")) >= 4 and not m.group("month"):
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


def _as_ms(v):
    """Epoch-ms int from whatever XQL hands back, or None. Never raises: a stamp this can't
    read must degrade to 'no signal', not kill a run.

    Accepts int, float, and the string forms XQL is known to return numbers as — this repo has
    live evidence (see _coerce_row) that read-back stringifies numeric columns ('0') and floats
    them (9.0), so '1799999995000', '1799999995000.0' and '1.8e12' must all parse. An
    ISO-8601 form is also accepted, because whether _insert_time comes back as epoch ms or as a
    formatted timestamp on a RAW row pull (as opposed to the max(_insert_time) aggregation,
    which was measured live and does return a number) is not verified on this tenant — parsing
    it costs nothing and silently losing the skew signal costs the whole protection."""
    if v is None:
        return None
    if isinstance(v, bool):          # bools are ints in Python; a bool stamp is nonsense
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
    discarded first. Either may be None.

    WHY max() OF THE TWO, and not just one of them (edge case #6):

    event_timestamp_ms is stamped ON THE ENDPOINT, so it carries that endpoint's clock error.
    At fleet scale a wrong endpoint clock is routine, and one direction is dangerous: a clock
    running BEHIND makes a live scan's rows look hours or days old, so the abandoned cutoff
    sweeps it and the quiet period waves it through — and this tool then consolidates and
    DELETES the shard of a scan that is still writing to it. _insert_time is stamped by the
    platform at ingest, so while a scan is actively uploading it stays ~"now" no matter what
    the endpoint's clock says, and taking the max makes that dangerous direction impossible.

    WHY THE TWO GUARDS, and not a bare max():

    1. endpoint AHEAD of ingest (ep > srv + SKEW_TOLERANCE_MS) — impossible in reality (a row
       cannot be authored after the platform received it), so the endpoint stamp is discarded
       rather than maxed in. A bare max() would keep it, and a future stamp makes
       `now_ms - newest` NEGATIVE FOREVER: the quiet period can never be satisfied AND the
       abandoned cutoff can never fire, so the scan is permanently un-consolidatable and its
       shard permanently un-deletable — the exact stuck-forever failure the cutoff exists to
       prevent, not the "harmless delay" it looks like at a glance.
    2. server stamp implausibly in the future of now_ms — the tell for a unit mismatch (epoch
       microseconds reads ~1000x now_ms). Dropped in favour of the endpoint stamp, so a
       platform returning _insert_time in unexpected units degrades to pre-fix behaviour
       instead of stalling every scan on the tenant. Only applied when the endpoint stamp
       survives to take over: returning None would mean "no signal at all", which the quiet
       gate reads as "nothing to wait for" — the delete-happy direction.

    Absent/unreadable _insert_time falls back to event_timestamp_ms alone, i.e. exactly the
    pre-fix behaviour — never worse. Residual, deliberately not closed here: an endpoint clock
    running ahead on a platform that returns NO usable _insert_time still stalls, because there
    is then no trustworthy stamp to fall back to (and clamping to now_ms would reset the age to
    zero on every pass, which livelocks the same way). _gate_scan logs that case distinctly.

    DO NOT "simplify" this to _insert_time alone. That stamp is only a freshness signal on a
    SOURCE SHARD. Consolidation READS a shard's rows and RE-WRITES them into the per-scan
    target, which resets _insert_time to the consolidation time while event_timestamp_ms
    keeps the original scan time — measured on a real target: _insert_time was ~31 DAYS newer
    than the scan it describes. Both callers below are invoked only on source shards (see
    run_consolidation, which draws them from `shards`/`scans_ds`, and parse_shard, which
    returns None for a per-scan target); that restriction is what keeps this valid."""
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


# count      : rows for this scan_id in this shard
# newest     : skew-proof freshness signal both gates measure against (see _newest_ms)
# ep_newest  : the ENDPOINT stamp alone — only used by _gate_scan's backstop, which must not
#              be re-armable by a server-side re-stamp (see DEFAULT_SKEW_BACKSTOP_SECS)
_ScanStat = collections.namedtuple("_ScanStat", "count newest ep_newest")


def build_terminal_map(scans_rows_by_ds, action_state_for=None):
    """Derive terminality per (scan_id, host) from the SCANS shards.

    The lifecycle status lives only in the scans datasets — matches rows carry no status —
    so consolidating EITHER kind must consult this map to know whether a host's scan has
    finished. Returns {(scan_id, host): {terminal, newest_ms, status}}.

    A (scan_id, host) that is absent here has no terminal lifecycle row yet, which the
    caller must treat as NOT safe: matches can stream before the terminal row is written.

    newest_ms here is informational (the gates read their own per-(scan_id, shard) value from
    newest_by, not this) but is computed through the same skew-proof _newest_ms, so a future
    caller reaching for the value sitting next to `terminal` cannot silently reintroduce edge
    case #6. Every stamp goes through _as_ms, so a non-numeric timestamp degrades to "no
    signal" instead of raising ValueError and aborting the whole consolidation pass."""
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
            out[(sid, host)] = {
                "terminal": shard_is_terminal(latest_status, astate),
                "newest_ms": newest,
                "status": latest_status,
            }
    return out


def newest_row_age_ok(newest_ms, now_ms, quiet_secs):
    """True if the newest row is old enough that the uploader has surely finished draining.
    No rows (newest_ms None) is not a blocker — nothing to wait for.

    newest_ms must be the skew-proof value from _newest_ms, not a bare event_timestamp_ms:
    now_ms is server-side while event_timestamp_ms is endpoint-side, so subtracting one from
    the other measures the endpoint's clock error as well as the row's age.

    None is deliberately "not blocked" and not "defer": it means neither stamp on any of the
    shard's rows was readable at all, and deferring on that would make such a shard
    permanently undeletable with no path out. _scan_stats/_stats_from_rows log when a shard's
    server stamp is missing, so the degraded case is visible in the run log rather than
    silent."""
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
# Every matches-dataset shape a tenant can still be holding. None of these are removed when a
# newer one lands: a fleet mid-rollout writes two shapes at once, and an un-consolidated shard is
# its scan's only copy, so a shape this module cannot resolve is a shard it cannot merge.
#   v2: one row per matched string OFFSET.
#   v3 (scanner v3.0.0): one row per (rule, file) FINDING — offsets/strings/string_ids folded in.
#   v4 (current): one row per matched FILE — every rule that hit it folded into `rules`, and
#       run_id/scan_date/scan_folder/date_of_scan dropped as derivable or scan-constant. See
#       xdr_yara_scanner.MATCHES_SCHEMA_V4, which this must stay in step with.
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
# Versions run_consolidation/check_consolidation_status/consolidate_all cover by default when
# no explicit version is requested — every schema version this tool knows how to read.
KNOWN_MATCHES_SCHEMA_VERSIONS = tuple(sorted(_MATCHES_SCHEMAS_BY_VER))


def matches_schema_for(ver):
    """The matches-dataset schema for a given version tag. Unknown versions fall back to the
    latest known schema rather than raising — a consolidation run should degrade to 'best
    effort against an unrecognised newer shard', not hard-fail the whole pass."""
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
    """{scan_id: _ScanStat(count, newest, ep_newest)} via aggregation — no row pull. This is
    what lets the tool scale: a matches shard with millions of rows is summarised in one query.

    newest is skew-proofed per _newest_ms: max(_insert_time) rides along in the same comp stage
    (verified working on the live tenant) so one endpoint's wrong clock cannot make a running
    scan look finished. dataset MUST be a source shard, never a per-scan target."""
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
    """The skew protection is only active while the platform actually returns _insert_time.
    If it ever stops (column dropped, renamed alias, an aggregation form a future platform
    version rejects), every gate silently reverts to the pre-fix, skew-vulnerable behaviour
    with green tests and no symptom. Say so in the run log instead."""
    if had_rows and not srv_seen and log:
        log("  note: %s returned no usable _insert_time — endpoint-clock-skew protection is "
            "INACTIVE for this shard; gates fall back to event_timestamp_ms alone" % dataset)


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


def _stats_from_rows(rows, now_ms=None, log=None, dataset=""):
    """Same shape as _scan_stats but from already-read rows (used for tiny scans shards).

    Same skew-proof newest (see _newest_ms) — here _insert_time comes along as a system column
    on each read-back row rather than from an aggregation, so it is read through _as_ms, which
    also accepts the string/ISO forms XQL read-back is known to hand numbers back in. Rows MUST
    come from a source shard, never a per-scan target."""
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
    # (comp count(), max(ts), max(_insert_time) by scan_id) instead; full rows are pulled ONLY
    # for the one scan being written, later. Scans shards reuse the rows already read above.
    # Both stats helpers are fed SOURCE SHARDS ONLY (`shards` and `scans_ds` are both filtered
    # through parse_shard, which returns None for a per-scan target) — required, because the
    # _insert_time half of their freshness signal is meaningless on a target: consolidation
    # re-writes rows there, resetting it. See _newest_ms.
    all_groups, newest_by, ep_newest_by = {}, {}, {}
    for ds in shards:
        stats = (_stats_from_rows(scans_rows[ds], now_ms=now_ms, log=log, dataset=ds)
                 if kind == "scans" else _scan_stats(client, ds, now_ms=now_ms, log=log))
        for sid, st in stats.items():
            all_groups.setdefault(sid, {})[ds] = st.count
            newest_by[(sid, ds)] = st.newest
            ep_newest_by[(sid, ds)] = st.ep_newest

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
                    now_ms=None, action_state_for=None, max_scans=None, log=print):
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
    delete, so they skip the lock entirely and can run concurrently with anything.

    A dry run reports its plans in would_count/would_scan_ids, never in failed_*: a preview is
    not an outcome, and failed_count is the field callers alarm on."""
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


def _delete_many(client, names, log, concurrency=None):
    """Delete datasets concurrently in bounded batches. Different-dataset deletes are safe to
    parallelise (verified live); this turns a fleet's serial ~60s-per-delete into hours."""
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


def _gate_scan(scan_id, srcs, newest_by, ep_newest_by, tmap, now_ms, quiet_secs,
               abandoned_after_secs, log, skew_backstop_secs=DEFAULT_SKEW_BACKSTOP_SECS):
    """Return a defer-reason string if any source host is not safe yet, else ''.

    A source is eligible when its scan is FINISHED — terminal lifecycle/action state, OR
    ABANDONED (non-terminal but its newest row is older than abandoned_after_secs, so the
    scanner will never write a terminal row; typically a console-Cancel orphan). An
    abandoned scan is still consolidated so its partial matches, which are real findings,
    are preserved rather than dropped. A non-terminal scan younger than the cutoff may still
    be running, so it defers.

    Both age checks measure against the skew-proof `newest` (see _newest_ms), EXCEPT for the
    `settled` backstop, which measures the ENDPOINT stamp alone. The backstop exists because
    `newest` can in principle be re-armed server-side — this tool's own row-level cleanup of a
    sibling scan may re-stamp _insert_time on a shard's surviving rows — and an age that can be
    reset by someone else's cleanup is an age that can be deferred forever, which is exactly
    what the abandoned cutoff exists to prevent (see DEFAULT_SKEW_BACKSTOP_SECS). Nothing can
    re-arm the endpoint stamp except the endpoint itself writing a new row."""
    for ds in srcs:
        host = (parse_shard(ds) or {}).get("host", "")
        entry = tmap.get((scan_id, host))
        is_terminal = bool(entry and entry["terminal"])
        newest = newest_by.get((scan_id, ds))
        ep_newest = (ep_newest_by or {}).get((scan_id, ds))
        ep_age_ms = (now_ms - ep_newest) if ep_newest is not None else None
        settled = ep_age_ms is not None and ep_age_ms >= skew_backstop_secs * 1000
        if newest is not None and newest > now_ms + SKEW_TOLERANCE_MS:
            # Only reachable when there is no usable server stamp to correct against (with one,
            # _newest_ms discards an endpoint stamp that is ahead of ingest). Nothing can be
            # done about it here — clamping to now_ms would reset the age to zero every pass —
            # but a permanently-deferring scan must at least be diagnosable.
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
