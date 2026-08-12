#!/usr/bin/env python3
"""Bound YARA lookup dataset growth by deleting whole old datasets.

The scanner writes into per-host, monthly-rotated lookup datasets:

    yara_scanner_{matches,scans}_v<SCHEMA>[_<host>][_<YYYYMM>]

Rotation bounds each dataset's SIZE, which is what keeps add_data fast - merge time scales
with dataset size, not payload (measured ~13s at 15k rows, ~31s at 77k), so an unrotated
dataset eventually exceeds any client timeout and goes write-dead. But rotation never
deletes anything: old months accumulate on the tenant forever. This script deletes them.

DELIBERATELY NOT A PREREQUISITE FOR ANYTHING. The scanner creates its own datasets and
writes to them self-sufficiently. If this script never runs, datasets get large and
eventually slow, but every scan still succeeds. Creation is not optional; cleanup is - and
coupling them would mean a scan could fail because a different script had not run, which
on a fleet is a silent, per-endpoint failure.

Usage:
    python3 xdr_data_management.py --report
    python3 xdr_data_management.py --older-than-months 6 --yes
    python3 xdr_data_management.py --delete-legacy --yes
"""

__version__ = "2.1.1"   # see repo CHANGELOG.md for what changed since 2.1.0
import argparse
import datetime
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xdr_action_center import XDRActionCenter  # noqa: E402

PREFIX = "yara_scanner"

NAME_RE = re.compile(
    r"^%s_(?P<kind>matches|scans)_v(?P<version>\d+)(?:_(?P<rest>.+))?$" % re.escape(PREFIX)
)
# A trailing 6-digit group is the rotation month. A host segment that is ITSELF exactly six
# digits is indistinguishable from a month - we resolve it as a month, because the worst
# outcome of that reading is declining to delete something that looks recent, whereas
# reading it as a host could delete a whole host's history in one call.
MONTH_RE = re.compile(r"^(?:(?P<host>.*?)_)?(?P<month>\d{6})$")


def parse_dataset_name(name):
    """Parse a dataset name into its parts, or None if it is not YARA-owned.

    Returning None is safety rail 3: anything outside the naming contract can never be a
    deletion candidate, so a bug here cannot reach unrelated tenant data.
    """
    m = NAME_RE.match(name or "")
    if not m:
        return None
    rest = m.group("rest")
    host, month = None, None
    if rest:
        mm = MONTH_RE.match(rest)
        if mm:
            host = mm.group("host") or None
            month = mm.group("month")
        else:
            host = rest
    return {"name": name, "kind": m.group("kind"),
            "version": int(m.group("version")), "host": host, "month": month}


def months_between(older_yyyymm, newer_yyyymm):
    """Whole months from older to newer. NEGATIVE if `older` is actually in the future,
    which is how clock skew is detected and refused."""
    o = datetime.date(int(older_yyyymm[:4]), int(older_yyyymm[4:6]), 1)
    n = datetime.date(int(newer_yyyymm[:4]), int(newer_yyyymm[4:6]), 1)
    return (n.year - o.year) * 12 + (n.month - o.month)


def has_rotated_sibling(name, all_names):
    """Does an unsuffixed dataset have rotated siblings for the same kind+host?

    If yes it is an ABANDONED pre-rotation dataset - rotation was enabled later and
    writes moved to the dated names, so this one is frozen, not growing. If no, the
    deployment is genuinely running CONFIG_LOOKUP_ROTATION="none" and the dataset really
    will grow without bound. The two need opposite advice, and telling someone to enable
    a setting that is already enabled sends them looking in the wrong place.
    """
    prefix = name + "_"
    return any(n != name and n.startswith(prefix) and n[len(prefix):].isdigit()
               and len(n) - len(prefix) == 6 for n in (all_names or []))


def select_rotated_for_deletion(current_names, older_than_months, now_yyyymm):
    """Pick rotated datasets older than the window. Returns (candidates, skip_reasons).

    Every safety rail that governs WHAT gets deleted lives here:
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
    """Drop any candidate whose newest row is younger than min_quiet_secs. Returns
    (survivors, skip_reasons).

    select_rotated_for_deletion's month-label age check has a real gap: the instant the
    calendar rolls to a new month, EVERY prior month's shard looks arbitrarily old regardless
    of actual elapsed wall-clock time since its last write - a scan running late on the last
    day of a month, or pure clock/timezone skew between the scanning endpoint and the machine
    running this prune, can make a shard a scan is STILL WRITING TO look like fair game. This
    asks the question that actually matters - has this shard stopped receiving writes
    recently - instead of inferring liveness from a calendar label. min_quiet_secs defaults
    generously (24h) since the goal is proving no active writer at all, not just outlasting
    the scanner's own upload-drain window."""
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
    """Drop any candidate that still holds a scan_id xdr_consolidate.py has not yet fully
    verified into a per-scan target. Returns (survivors, skip_reasons).

    A row_ceiling_exceeded (or otherwise permanently stuck) scan blocks xdr_consolidate.py's
    OWN deletion pass forever (a shard is only deleted once every scan_id it holds is
    verified) - but this prune tool is a completely separate code path with no knowledge of
    that. Left unchecked, it would eventually delete that shard by month age alone, destroying
    the one and only copy of a scan's data that was never successfully consolidated."""
    import xdr_consolidate as C
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
            target = C.target_name(info["kind"], str(info["version"]), sid)
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


def select_legacy_for_deletion(legacy_names):
    """Legacy = older/unversioned schema, already classified by the toolkit.

    The toolkit's 'newer' bucket is deliberately NOT accepted by this function: a host
    running a stale YARA_LOOKUP_SCHEMA_VER must never delete a future schema's data.
    """
    return list(legacy_names or [])


def render_report(current, legacy, newer, now_yyyymm):
    """Human-readable inventory. Ages are whole months."""
    schema = os.environ.get("YARA_LOOKUP_SCHEMA_VER", "2")
    lines = ["YARA lookup datasets (schema v%s current, now %s)" % (schema, now_yyyymm), ""]
    lines.append("%-52s %-8s %-14s %6s" % ("dataset", "kind", "host", "age"))
    lines.append("-" * 84)
    unrotated, abandoned = [], []
    for name in current:
        info = parse_dataset_name(name)
        if info is None:
            lines.append("%-52s %s" % (name[:52], "(unrecognised - never a candidate)"))
            continue
        if info["month"]:
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


def _run_consolidate(client, args):
    """Drive xdr_consolidate.run_consolidation for both kinds, across every known schema
    version. Verify-before-delete and the finished-scan gate live in that module; this just
    wires the CLI flags to it. Every version is covered by default (not just the latest) so a
    tenant mid-rollout of a new scanner version — old- and new-schema shards both live — gets
    both consolidated in one pass; run_consolidation itself only handles one version per call."""
    import xdr_consolidate as C
    kwargs = {"dry_run": not args.yes}
    if args.quiet_secs is not None:
        kwargs["quiet_secs"] = args.quiet_secs
    if args.row_ceiling is not None:
        kwargs["row_ceiling"] = args.row_ceiling
    if args.abandoned_after_hours is not None:
        kwargs["abandoned_after_secs"] = int(args.abandoned_after_hours * 3600)
    if args.scan_id:
        kwargs["only_scan_ids"] = args.scan_id

    # Write passes take the same overlap guard consolidate_all uses, in case a scheduled Job
    # is running concurrently (its queue-handling setting is the primary safeguard; this is
    # defense in depth for when that's missing or fails — see acquire_consolidation_lock).
    if args.yes and not C.acquire_consolidation_lock(client, log=print):
        print("\nAnother consolidation run appears to already be in progress — skipping "
              "this pass entirely rather than risk a concurrent write collision.")
        return 1

    total_ok = total_would = total_deferred = total_fail = 0
    try:
        for ver in C.KNOWN_MATCHES_SCHEMA_VERSIONS:
            for kind in ("matches", "scans"):
                print("\n=== consolidate %s (schema v%s) ===" % (kind, ver))
                try:
                    plans = C.run_consolidation(client, kind, ver=ver, **kwargs)
                except Exception as e:
                    print("  error: %s" % e, file=sys.stderr)
                    total_fail += 1
                    continue
                for p in plans:
                    if p.get("ok"):
                        total_ok += 1
                    elif p.get("ok") is None:
                        total_would += 1   # dry-run: this scan WOULD consolidate
                    elif p.get("reason") in ("host_not_terminal", "within_quiet_period"):
                        total_deferred += 1
                    else:
                        total_fail += 1
    finally:
        if args.yes:
            C.release_consolidation_lock(client, log=print)
    if args.yes:
        print("\nconsolidation summary: %d consolidated, %d deferred (scan still active), %d failed"
              % (total_ok, total_deferred, total_fail))
    else:
        print("\nconsolidation summary (dry run): %d would consolidate, %d deferred "
              "(scan still active), %d failed" % (total_would, total_deferred, total_fail))
        print("DRY RUN — nothing written or deleted. Re-run with --yes to apply.")
    return 1 if total_fail else 0


def main():
    ap = argparse.ArgumentParser(
        description="Bound YARA lookup dataset growth: delete old datasets, or consolidate "
                    "per-host shards into one dataset per scan.")
    ap.add_argument("--report", action="store_true",
                    help="inventory of YARA datasets (default action)")
    ap.add_argument("--older-than-months", type=int,
                    help="delete rotated datasets older than N months (no default)")
    ap.add_argument("--delete-legacy", action="store_true",
                    help="delete datasets on an older/unversioned schema")
    ap.add_argument("--min-quiet-hours", type=float, default=24.0,
                    help="older-than-months: never delete a shard whose newest row is younger "
                         "than this many hours, regardless of its month label - protects "
                         "against a scan still writing near a month boundary, or clock/"
                         "timezone skew between the scanning endpoint and this machine "
                         "(default 24)")
    ap.add_argument("--force", action="store_true",
                    help="delete_dataset force=true, for datasets with dependencies")
    ap.add_argument("--yes", action="store_true",
                    help="actually delete; without this everything is a dry run")
    ap.add_argument("--consolidate", action="store_true",
                    help="fold per-host shards into one dataset per scan, then delete the "
                         "shards (only for scans whose hosts have finished). Dry run unless --yes")
    ap.add_argument("--quiet-secs", type=int, default=None,
                    help="consolidate: a host shard is processed only when its newest row is "
                         "older than this (default 900, >= the scanner's drain budget)")
    ap.add_argument("--row-ceiling", type=int, default=None,
                    help="consolidate: refuse a per-scan consolidation larger than this "
                         "many rows rather than half-building it (default 2,000,000)")
    ap.add_argument("--abandoned-after-hours", type=float, default=None,
                    help="consolidate: a non-terminal scan whose newest row is older than "
                         "this is treated as abandoned (console-Cancel orphan) so it stops "
                         "blocking its shard's cleanup; its partial findings are still "
                         "preserved (default 24)")
    ap.add_argument("--scan-id", action="append", default=None,
                    help="consolidate: restrict to these scan_id(s) (repeatable). Omit for "
                         "all finished scans")
    args = ap.parse_args()

    client = XDRActionCenter()

    if args.consolidate:
        return _run_consolidate(client, args)

    try:
        current, legacy, newer = client.classify_yara_datasets()
    except Exception as e:
        print("Could not list datasets: %s" % e, file=sys.stderr)
        return 2
    now_yyyymm = datetime.date.today().strftime("%Y%m")

    # No window and no legacy flag means there is nothing to select, so report instead.
    # This is also why a bare --yes is harmless.
    if args.report or (args.older_than_months is None and not args.delete_legacy):
        print(render_report(current, legacy, newer, now_yyyymm))
        return 0

    targets, skipped = [], []
    if args.older_than_months is not None:
        t, s = select_rotated_for_deletion(current, args.older_than_months, now_yyyymm)
        skipped += s
        # Two more safety rails, both requiring live calls so they run only against
        # candidates that already survived the (free) month-label check above:
        # - a shard may look old by calendar label but still be receiving writes (a scan
        #   running late across a month boundary, or clock/timezone skew) - see
        #   filter_recently_written's docstring;
        # - a shard may be old AND quiet but still hold a scan xdr_consolidate.py has never
        #   been able to fully verify (e.g. row_ceiling_exceeded) - deleting it here would be
        #   the only copy of that scan's data, permanently. See filter_unconsolidated.
        t, s2 = filter_recently_written(client, t, args.min_quiet_hours * 3600, int(time.time() * 1000))
        skipped += s2
        t, s3 = filter_unconsolidated(client, t)
        skipped += s3
        targets += t
    if args.delete_legacy:
        targets += select_legacy_for_deletion(legacy)

    for s in skipped:
        print("  skip  %s" % s)
    if not targets:
        print("Nothing to delete.")
        return 0

    print("\n%d dataset(s) selected for deletion:" % len(targets))
    for name in targets:
        print("  %s" % name)
    if not args.yes:
        print("\nDRY RUN - nothing deleted. Re-run with --yes to apply.")
        return 0

    failures = 0
    for name in targets:
        try:
            client.delete_dataset(name, force=args.force)
            print("  deleted %s" % name)
        except Exception as e:
            # Continue: one dataset with dependencies must not strand the whole cleanup.
            failures += 1
            print("  FAILED  %s: %s" % (name, e))
    print("\n%d deleted, %d failed." % (len(targets) - failures, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
