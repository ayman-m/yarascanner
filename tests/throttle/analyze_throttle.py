#!/usr/bin/env python3
"""Analyse a throttle head-to-head run: script vs os vs off.

Consumes the directory produced by throttle_matrix.sh:
  scan_<tag>.txt    SCAN_RESULT line
  wall_<tag>.txt    scan wall-clock seconds
  events_<tag>.jsonl THROTTLE_EVENT lines from the scanner's performance log
  config_<tag>.txt  THROTTLE_CONFIG header
  load_<tag>.json   load generator output

Two derived numbers carry the argument:
  slowdown    = scan wall-clock under load / scan wall-clock alone   (lower is better)
  degradation = competing work rate during scan / baseline rate      (higher is better)

Usage: python3 analyze_throttle.py <results_dir>
"""
import json
import os
import sys

MODES = ["script", "os", "off"]
SETTLE_SECS = 15.0        # matches throttle_matrix.sh; scan starts this far into the load run


def _read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return default


def _json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _events(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                i = line.find("THROTTLE_EVENT ")
                if i >= 0:
                    try:
                        out.append(json.loads(line[i + len("THROTTLE_EVENT "):]))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


def work_rate(samples, t0, t1):
    """Work units per second strictly inside [t0, t1]."""
    win = [s for s in (samples or []) if t0 <= s["t"] <= t1]
    if len(win) < 2:
        return None
    span = win[-1]["t"] - win[0]["t"]
    if span <= 0:
        return None
    return (win[-1]["work"] - win[0]["work"]) / span


def cpu_stats(samples, t0, t1):
    vals = [s["cpu"] for s in (samples or []) if t0 <= s["t"] <= t1 and s["cpu"] >= 0]
    if not vals:
        return None, None
    return round(sum(vals) / len(vals), 1), round(max(vals), 1)


def main(d):
    base_wall = float(_read(os.path.join(d, "wall_scan_only.txt"), "0") or 0)
    load_only = _json(os.path.join(d, "load_load_only.json"))

    # Baseline work rate measured over the SAME window offset the loaded runs use,
    # so both sides exclude the generator's ramp-up.
    base_rate = None
    if load_only and load_only.get("samples"):
        s = load_only["samples"]
        t0 = s[0]["t"] + SETTLE_SECS
        base_rate = work_rate(s, t0, s[-1]["t"])
        base_cpu, _ = cpu_stats(s, t0, s[-1]["t"])
    else:
        base_cpu = None

    print("=" * 78)
    print("THROTTLE HEAD-TO-HEAD  (Linux endpoint, 8 cores, no affinity cap)")
    print("=" * 78)
    print("baseline scan (no load) : %.0fs" % base_wall)
    print("baseline load (no scan) : %s units/s at %s%% system CPU"
          % (("%.0f" % base_rate) if base_rate else "n/a", base_cpu))
    cfg = _read(os.path.join(d, "config_scan_only.txt"))
    if cfg:
        i = cfg.find("THROTTLE_CONFIG ")
        if i >= 0:
            c = json.loads(cfg[i + len("THROTTLE_CONFIG "):])
            print("thresholds              : high=%s critical=%s resume_margin=%s cores=%s affinity=%s"
                  % (c.get("high"), c.get("critical"), c.get("resume_margin"),
                     c.get("host_cores"), c.get("cpu_affinity_count")))
    print()

    hdr = ("%-8s %8s %9s %8s %10s %12s %9s %8s"
           % ("mode", "wall", "slowdown", "pauses", "paused_s", "load_units/s", "degrad", "cpu_avg"))
    print(hdr)
    print("-" * len(hdr))

    rows = []
    for mode in MODES:
        wall = float(_read(os.path.join(d, "wall_%s.txt" % mode), "0") or 0)
        ev = _events(os.path.join(d, "events_%s.jsonl" % mode))
        starts = [e for e in ev if e.get("event") == "pause_start"]
        ends = [e for e in ev if e.get("event") == "pause_end"]
        paused = sum(e.get("duration", 0.0) for e in ends)
        lg = _json(os.path.join(d, "load_%s.json" % mode))

        rate = cpu_avg = None
        if lg and lg.get("samples"):
            s = lg["samples"]
            t0 = s[0]["t"] + SETTLE_SECS          # scan begins here
            t1 = min(t0 + wall, s[-1]["t"])       # ...and runs for `wall`
            rate = work_rate(s, t0, t1)
            cpu_avg, _ = cpu_stats(s, t0, t1)

        slow = (wall / base_wall) if base_wall else None
        degr = (rate / base_rate) if (rate and base_rate) else None
        rows.append({"mode": mode, "wall": wall, "slowdown": slow, "pauses": len(starts),
                     "paused_s": paused, "rate": rate, "degradation": degr, "cpu": cpu_avg})

        print("%-8s %7.0fs %8s %8d %9.1fs %12s %9s %8s"
              % (mode, wall,
                 ("%.2fx" % slow) if slow else "n/a",
                 len(starts), paused,
                 ("%.0f" % rate) if rate else "n/a",
                 ("%.2f" % degr) if degr else "n/a",
                 ("%.1f%%" % cpu_avg) if cpu_avg is not None else "n/a"))

    print()
    print("slowdown    = scan wall-clock under load / scan alone (lower = faster scan)")
    print("degradation = competing work rate during scan / baseline (higher = kinder to host)")
    print()
    for mode in MODES:
        print("[%s] %s" % (mode, _read(os.path.join(d, "scan_%s.txt" % mode)) or "(no result)"))
    return rows


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
