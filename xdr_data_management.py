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
            skipped.append(
                '%s: not rotated (no YYYYMM) - set CONFIG_LOOKUP_ROTATION="monthly" in '
                "the scanner so this dataset stops growing" % name)
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
