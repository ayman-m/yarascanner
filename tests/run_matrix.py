#!/usr/bin/env python3
"""Comprehensive YARA-scanner test matrix across both endpoints.

Runs each rule file (and flag/throttle/throughput variants) as a SEPARATE XDR action on
both machines, with bounded concurrency, recording results incrementally to
tests/results/matrix.jsonl and a summary to stdout. Cross-reference each row with XDR via
its action_id / scan_id, and with the datasets via verify.

Usage: python3 tests/run_matrix.py
"""
import base64
import concurrent.futures as cf
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xdr_action_center import XDRActionCenter  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "tests", "yara_rules")
SCANNER = os.path.join(REPO, "xdr_yara_scanner.py")
RESULTS_DIR = os.path.join(REPO, "tests", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
JSONL = os.path.join(RESULTS_DIR, "matrix.jsonl")

# Target endpoints for the matrix. Override with YARA_TEST_HOSTS as
#   "WINHOST=C:\\yara_corpus:C:\\Windows\\System32,LINUXHOST=/opt/yara_corpus:/usr/bin"
# so the harness carries no environment-specific hostnames.
def _load_machines():
    spec = os.environ.get("YARA_TEST_HOSTS", "").strip()
    if not spec:
        return {
            "WINHOST01": {"corpus": "C:\\yara_corpus", "bigdir": "C:\\Windows\\System32"},
            "LINUXHOST01": {"corpus": "/opt/yara_corpus", "bigdir": "/usr/bin"},
        }
    machines = {}
    for entry in spec.split(","):
        host, _, paths = entry.strip().partition("=")
        corpus, _, bigdir = paths.partition(":")
        machines[host.strip()] = {"corpus": corpus.strip(), "bigdir": bigdir.strip()}
    return machines


MACHINES = _load_machines()

CONCURRENCY = 4
_print_lock = threading.Lock()
_file_lock = threading.Lock()


def rules_b64(fname):
    return base64.b64encode(open(os.path.join(RULES_DIR, fname), "rb").read()).decode()


def parse_summary(stdout):
    """Pull structured fields out of the scanner's SCAN_RESULT line."""
    r = {"outcome": "unknown", "files": None, "failed_rules": None, "matches": None,
         "paused": None, "posture": None, "raw": ""}
    for line in stdout.splitlines():
        if line.startswith("SCAN_RESULT:"):
            r["raw"] = line
            if "cancelled by operator" in line:
                r["outcome"] = "cancelled"
            elif line.lower().startswith("scan_result: scan failed") or "Scan failed" in line:
                r["outcome"] = "failed"
            else:
                r["outcome"] = "completed"
            m = re.search(r"(\d+) files scanned", line);        r["files"] = int(m.group(1)) if m else None
            m = re.search(r"(\d+) rules failed", line);         r["failed_rules"] = int(m.group(1)) if m else None
            m = re.search(r"(\d+) matches found", line);        r["matches"] = int(m.group(1)) if m else None
            m = re.search(r"paused ([\d.]+)s", line);           r["paused"] = float(m.group(1)) if m else None
            m = re.search(r"(alerts=.*)$", line);               r["posture"] = m.group(1) if m else None
        elif line.startswith("SNIPPET_ERROR"):
            r["outcome"] = "snippet_error"; r["raw"] = stdout[-500:]
    return r


def build_matrix():
    rule_files = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".yar"))
    tasks = []
    for host, cfg in MACHINES.items():
        # 1) every rule file against the corpus (default flags)
        for rf in rule_files:
            tasks.append({"host": host, "label": f"rules:{rf}", "rules": rf,
                          "folder": cfg["corpus"], "options": None, "mode": "scan"})
        # 2) output-flag variants (realistic pack)
        tasks.append({"host": host, "label": "flag:no_alerts", "rules": "14_realistic_pack.yar",
                      "folder": cfg["corpus"], "options": "create_alerts=false", "mode": "scan"})
        tasks.append({"host": host, "label": "flag:no_dataset", "rules": "14_realistic_pack.yar",
                      "folder": cfg["corpus"], "options": f"write_dataset=false,tenant_id=matrix_nods_{host}", "mode": "scan"})
        tasks.append({"host": host, "label": "flag:collect_files", "rules": "14_realistic_pack.yar",
                      "folder": cfg["corpus"], "options": "collect_files=true", "mode": "scan"})
        # 3) throttle modes (500-rule compile)
        tasks.append({"host": host, "label": "throttle:os", "rules": "15_big_500.yar",
                      "folder": cfg["corpus"], "options": "throttle_mode=os", "mode": "scan"})
        tasks.append({"host": host, "label": "throttle:off", "rules": "15_big_500.yar",
                      "folder": cfg["corpus"], "options": "throttle_mode=off", "mode": "scan"})
        # 4) throughput at scale (big real folder)
        tasks.append({"host": host, "label": "throughput:bigdir", "rules": "14_realistic_pack.yar",
                      "folder": cfg["bigdir"], "options": "create_alerts=false", "mode": "scan"})
    # interleave hosts so concurrent actions spread across both endpoints
    tasks.sort(key=lambda t: (t["label"],))
    return tasks


def run_one(client, ids, t):
    rec = dict(t); rec["ts_start"] = int(time.time())
    t0 = time.time()
    try:
        rb64 = rules_b64(t["rules"]) if t["rules"] else ""
        out, aid = client.run_scanner(ids[t["host"]], SCANNER, rb64, t["folder"], "low",
                                      t["mode"], t["options"], timeout_secs=1800,
                                      poll_secs=6, max_polls=300)
        stdout = next(iter(out.values()), "")
        rec.update(parse_summary(stdout))
        rec["action_id"] = aid
    except Exception as e:
        rec["outcome"] = "error"; rec["raw"] = f"{type(e).__name__}: {e}"[:400]
    rec["wall_secs"] = round(time.time() - t0, 1)
    with _file_lock:
        with open(JSONL, "a") as f:
            f.write(json.dumps(rec) + "\n")
    with _print_lock:
        print(f"[{rec['host']:10}] {rec['label']:22} -> {rec['outcome']:11} "
              f"files={rec.get('files')} matches={rec.get('matches')} "
              f"failed={rec.get('failed_rules')} wall={rec['wall_secs']}s aid={rec.get('action_id')}",
              flush=True)
    return rec


def main():
    open(JSONL, "w").close()  # reset
    c = XDRActionCenter()
    ids = {h: c.endpoint_id(h) for h in MACHINES}
    print("endpoints:", ids, flush=True)
    tasks = build_matrix()
    print(f"matrix: {len(tasks)} actions, concurrency={CONCURRENCY}", flush=True)
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futs = [ex.submit(run_one, c, ids, t) for t in tasks]
        for _ in cf.as_completed(futs):
            pass
    print(f"\nMATRIX DONE in {round(time.time()-t0)}s -> {JSONL}", flush=True)


if __name__ == "__main__":
    main()
