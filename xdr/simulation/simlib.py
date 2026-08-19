#!/usr/bin/env python3
"""Shared helpers for the dataset-management simulation probes.

These scripts exist to prove -- against the live tenant, not by reasoning -- the API
assumptions the dataset-management design rests on. Each probe tests ONE assumption and
prints PASS or FAIL with the numbers behind it.

Nothing here touches the real scanner datasets. Every object is named with the SIM_PREFIX
below so a stray run can never collide with production data, and `cleanup.py` removes
anything carrying that prefix.
"""
import os
import sys
import time
import uuid

SIM_PREFIX = "yara_sim_"

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_REPO, "xdr"))

from xdr_action_center import XDRActionCenter  # noqa: E402


def _load_env():
    """Find .env and export it, so a probe works from any cwd and any checkout.

    The toolkit discovers .env by walking up from the working directory. That fails in a
    git worktree, where .env is gitignored and lives only in the primary checkout -- and
    it fails silently enough to look like a credentials problem rather than a path one.
    Searched in order: $YARA_ENV, the repo root, then the known primary checkout.
    """
    import pathlib
    cands = []
    if os.environ.get("YARA_ENV"):
        cands.append(pathlib.Path(os.environ["YARA_ENV"]))
    cands.append(pathlib.Path(_REPO) / ".env")
    cands.append(pathlib.Path.home() / "Documents" / "Coding" / "Yara" / ".env")
    for c in cands:
        if not c.is_file():
            continue
        for line in c.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        return str(c)
    return None


def client():
    src = _load_env()
    if not os.environ.get("XDR_API_KEY"):
        raise SystemExit("no XDR credentials found; set YARA_ENV=/path/to/.env")
    if not os.environ.get("XDR_CA_BUNDLE"):
        bundle = os.path.join(pathlib_home_bundle())
        if bundle and os.path.isfile(bundle):
            os.environ["XDR_CA_BUNDLE"] = bundle
    return XDRActionCenter()


def pathlib_home_bundle():
    return os.path.join(os.path.expanduser("~"), "Documents", "Coding", "Yara",
                        ".claude", "skills", "xdr-yara-scan-test", "scripts",
                        "xdr_ca_bundle.pem")


def sim_name(*parts):
    """Every simulated dataset name is prefixed, so cleanup is total and unambiguous."""
    return SIM_PREFIX + "_".join(str(p) for p in parts)


TRACKER = sim_name("tracker")

DATA_SCHEMA = {
    "scan_id": "text", "hostname": "text", "rule": "text",
    "file_path": "text", "match_count": "number", "event_timestamp_ms": "number",
}

TRACKER_SCHEMA = {
    "scan_id": "text",           # the join key
    "hostname": "text",
    "event": "text",             # started | completed
    "event_ts_ms": "number",
    "status": "text",            # terminal status on the completed row
    "matches_dataset": "text",   # the LITERAL dataset name, so no derivation is needed
    "scans_dataset": "text",
    "files_scanned": "number",
    "matches": "number",
}


def ensure(ac, name, schema):
    ac.create_lookup_dataset(name, schema)
    return name


def rows_in(ac, dataset, where="", tries=8, delay=6):
    """Count rows, tolerating ingest lag. Returns -1 if the dataset never became queryable."""
    q = f"dataset = {dataset}" + (f" | filter {where}" if where else "") + " | comp count() as n"
    for _ in range(tries):
        try:
            r = ac.xql(q, limit=5)
            if r:
                return int(float(r[0].get("n") or 0))
        except Exception:
            pass
        time.sleep(delay)
    return -1


def banner(title):
    print("=" * 72)
    print(title)
    print("=" * 72)


def verdict(ok, msg):
    print(("PASS  " if ok else "FAIL  ") + msg)
    return ok


def new_scan_id(host):
    return f"{host}_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
