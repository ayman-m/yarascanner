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

__version__ = "2.0.0"   # released with xdr_yara_scanner 2.0.0; see repo releases
import argparse
import datetime
import os
import re
import sys

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


def main():
    ap = argparse.ArgumentParser(
        description="Bound YARA lookup dataset growth by deleting whole old datasets.")
    ap.add_argument("--report", action="store_true",
                    help="inventory of YARA datasets (default action)")
    ap.add_argument("--older-than-months", type=int,
                    help="delete rotated datasets older than N months (no default)")
    ap.add_argument("--delete-legacy", action="store_true",
                    help="delete datasets on an older/unversioned schema")
    ap.add_argument("--force", action="store_true",
                    help="delete_dataset force=true, for datasets with dependencies")
    ap.add_argument("--yes", action="store_true",
                    help="actually delete; without this everything is a dry run")
    args = ap.parse_args()

    client = XDRActionCenter()
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
        targets += t
        skipped += s
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
