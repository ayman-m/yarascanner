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
