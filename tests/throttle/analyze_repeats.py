#!/usr/bin/env python3
"""Aggregate repeated throttle rounds and report variance.

Consumes the directory produced by throttle_repeats.sh, whose tags carry a round
suffix (script_r1, os_r2, ...). Reports mean/min/max per condition so the spread is
visible, because a single run cannot distinguish a real effect from machine noise.

Conditions:
  scan_only   unloaded baseline wall-clock
  load_only   competing-workload baseline rate
  script_old  PRE-fix scanner (park until CPU drops)
  script      POST-fix scanner (proportional duty cycle)
  os / off    kernel-paced / no pacing

Usage: python3 analyze_repeats.py <results_dir>
"""
import glob
import json
import os
import re
import statistics
import sys

CONDITIONS = ["scan_only", "script_old", "script", "os", "off"]
SETTLE_SECS = 15.0


def _read(p, default=""):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return default


def _json(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _rounds(d, cond):
    """All round indices present for a condition (exact match, not prefix)."""
    out = []
    for p in glob.glob(os.path.join(d, "wall_%s_r*.txt" % cond)):
        m = re.search(r"wall_%s_r(\d+)\.txt$" % re.escape(cond), os.path.basename(p))
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def _events(p):
    out = []
    try:
        with open(p, "r", encoding="utf-8") as f:
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
    win = [s for s in (samples or []) if t0 <= s["t"] <= t1]
    if len(win) < 2:
        return None
    span = win[-1]["t"] - win[0]["t"]
    return (win[-1]["work"] - win[0]["work"]) / span if span > 0 else None


def _stat(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, None, None
    return (statistics.mean(vals), min(vals), max(vals))


def main(d):
    # Baselines
    base_walls = [float(_read(os.path.join(d, "wall_scan_only_r%d.txt" % r), "0") or 0)
                  for r in _rounds(d, "scan_only")]
    base_wall, bw_lo, bw_hi = _stat(base_walls)

    base_rates = []
    for p in sorted(glob.glob(os.path.join(d, "load_load_only_r*.json"))):
        lg = _json(p)
        if lg and lg.get("samples"):
            s = lg["samples"]
            base_rates.append(work_rate(s, s[0]["t"] + SETTLE_SECS, s[-1]["t"]))
    base_rate, _, _ = _stat(base_rates)

    print("=" * 92)
    print("THROTTLE REPEATS  -  variance and before/after on the duty-cycle fix")
    print("=" * 92)
    if base_wall:
        print("baseline scan (no load) : mean %.0fs  (min %.0fs / max %.0fs, n=%d)"
              % (base_wall, bw_lo, bw_hi, len(base_walls)))
    if base_rate:
        print("baseline load (no scan) : mean %.0f units/s (n=%d)" % (base_rate, len(base_rates)))
    print()

    hdr = "%-11s %3s %22s %9s %10s %14s %8s" % (
        "condition", "n", "wall mean (min/max)", "slowdown", "paused_s", "load units/s", "degrad")
    print(hdr); print("-" * len(hdr))

    for cond in CONDITIONS:
        if cond == "scan_only":
            continue
        rounds = _rounds(d, cond)
        if not rounds:
            continue
        walls, pauseds, rates = [], [], []
        for r in rounds:
            tag = "%s_r%d" % (cond, r)
            w = float(_read(os.path.join(d, "wall_%s.txt" % tag), "0") or 0)
            walls.append(w)
            ev = _events(os.path.join(d, "events_%s.jsonl" % tag))
            pauseds.append(sum(e.get("duration", 0.0) for e in ev if e.get("event") == "pause_end"))
            lg = _json(os.path.join(d, "load_%s.json" % tag))
            if lg and lg.get("samples"):
                s = lg["samples"]
                t0 = s[0]["t"] + SETTLE_SECS
                rates.append(work_rate(s, t0, min(t0 + w, s[-1]["t"])))
        wm, wlo, whi = _stat(walls)
        pm, _, _ = _stat(pauseds)
        rm, _, _ = _stat(rates)
        slow = (wm / base_wall) if (wm and base_wall) else None
        degr = (rm / base_rate) if (rm and base_rate) else None
        print("%-11s %3d %22s %9s %10s %14s %8s" % (
            cond, len(rounds),
            "%.0fs (%.0f/%.0f)" % (wm, wlo, whi),
            ("%.2fx" % slow) if slow else "n/a",
            ("%.0fs" % pm) if pm is not None else "n/a",
            ("%.0f" % rm) if rm else "n/a",
            ("%.2f" % degr) if degr else "n/a"))

    print()
    print("slowdown    = wall / unloaded baseline (lower is better)")
    print("degradation = competing work rate during scan / baseline (higher is better)")
    print("NOTE: paused_s sums per-worker pause_end durations; with N workers it can")
    print("      exceed wall-clock. An episode still open at scan end emits no pause_end,")
    print("      so treat it as a lower bound and cross-check 'paused Ns' in SCAN_RESULT.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
