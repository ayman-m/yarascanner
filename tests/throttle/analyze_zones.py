#!/usr/bin/env python3
"""Zone-by-zone throttle behaviour: below high -> above high -> above CRITICAL -> recovery.

Correlates THROTTLE_EVENT timestamps against the load generator's per-second CPU trace,
so each event is attributed to the load zone that was active when it fired.

Answers the two questions a flat-load test cannot:
  * does the CRITICAL branch (4.0 sleep ratio) actually engage above 90% CPU?
  * how fast does throttling STOP once load drops back below the threshold? Recovery is
    where the original bug lived - the old code required CPU below (high - resume_margin)
    and never got it while external load persisted.

Usage: python3 analyze_zones.py <results_dir>
"""
import bisect
import json
import os
import sys

ZONE_NAMES = {0: "idle", 1: "below high", 2: "above high", 3: "ABOVE CRITICAL",
              4: "recovery (below high)", 5: "idle"}
MODES = [("script_old", "pre-fix  (park until drop)"),
         ("script_new", "post-fix (duty cycle)"),
         ("os", "os   (kernel paced)"),
         ("off", "off  (no pacing)")]


def _json(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


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


def _read(p, d=""):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return d


def main(d):
    print("=" * 88)
    print("ZONE WALK  -  throttle behaviour across load zones (Linux, 8 cores, 2 workers)")
    print("=" * 88)
    print("profile: %s   (secs:duty per stage)" % _read(os.path.join(d, "profile.txt")))
    print("baseline scan (unloaded, cold cache): %ss" % _read(os.path.join(d, "wall_zbaseline.txt")))
    print()

    for tag, label in MODES:
        lg = _json(os.path.join(d, "load_%s.json" % tag))
        ev = _events(os.path.join(d, "events_%s.jsonl" % tag))
        wall = _read(os.path.join(d, "wall_%s.txt" % tag), "?")
        print("-" * 88)
        print("%-12s %s      wall=%ss   events=%d" % (tag, label, wall, len(ev)))
        if not lg or not lg.get("samples"):
            print("   (no load trace)")
            continue

        samples = lg["samples"]
        times = [s["t"] for s in samples]

        # Zone occupancy and observed CPU, straight from the generator's own trace.
        zones = {}
        for s in samples:
            z = zones.setdefault(s["stage"], {"cpu": [], "n": 0})
            z["cpu"].append(s["cpu"])
            z["n"] += 1

        # Attribute every event to the zone active at its timestamp.
        per_zone = {}
        for e in ev:
            i = min(bisect.bisect_left(times, e["t"]), len(samples) - 1)
            stage = samples[i]["stage"]
            b = per_zone.setdefault(stage, {"start": 0, "end": 0, "crit": 0, "slept": 0.0})
            if e.get("event") == "pause_start":
                b["start"] += 1
                if e.get("at_critical"):
                    b["crit"] += 1
            else:
                b["end"] += 1
                b["slept"] += e.get("slept", e.get("duration", 0.0))

        print("   %-24s %7s %9s %9s %9s %10s" %
              ("zone", "cpu avg", "starts", "ends", "critical", "slept_s"))
        for stage in sorted(zones):
            z = zones[stage]
            cpu = sum(z["cpu"]) / len(z["cpu"]) if z["cpu"] else 0.0
            b = per_zone.get(stage, {"start": 0, "end": 0, "crit": 0, "slept": 0.0})
            print("   %-24s %6.1f%% %9d %9d %9d %10.1f" %
                  (ZONE_NAMES.get(stage, "stage %d" % stage), cpu,
                   b["start"], b["end"], b["crit"], b["slept"]))

        # Recovery: last throttle activity vs the moment load dropped back below high.
        rec_start = next((s["t"] for s in samples if s["stage"] == 4), None)
        if rec_start and ev:
            after = [e for e in ev if e["t"] >= rec_start and e.get("event") == "pause_start"]
            if after:
                print("   recovery: throttling continued %.1fs into the recovery zone "
                      "(last pause_start)" % (max(e["t"] for e in after) - rec_start))
            else:
                print("   recovery: NO pause_start after load dropped - throttling stopped immediately")
        print("   %s" % _read(os.path.join(d, "scan_%s.txt" % tag)))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
