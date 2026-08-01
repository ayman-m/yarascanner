#!/usr/bin/env python3
"""Open-loop CPU load generator (Linux) for the YARA scanner throttle PoC.

Runs DIRECTLY on the endpoint (ssh), NOT as a Cortex Action Center payload, so it
is not subject to the agent's payload CPU-affinity cap and can create realistic
system-wide pressure the way ordinary user/service workloads do.

OPEN-LOOP BY DESIGN: the duty cycle is fixed. It deliberately does NOT adapt to
hold a system-CPU setpoint - a closed loop would back off as the scanner ramps up
and we would measure the control loop instead of the scanner's throttle.

Usage:
  python3 loadgen.py --profile "30:0,120:55,120:85,30:0" --out /tmp/loadgen.json
  python3 loadgen.py --calibrate --out /tmp/calibration.json
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import threading
import time

try:
    import psutil
except ImportError:
    psutil = None

# MUST exceed CPython's HASHLIB_GIL_MINSIZE (2048 bytes), or hashlib holds the GIL
# and N threads deliver exactly ONE core of load (measured: 12.5% on 8 cores).
# A large buffer also lengthens the GIL-released C-side window relative to
# re-acquisition contention, which is what lets threads actually parallelise.
WORK_BUFFER = b"yara-throttle-poc" * 65536   # ~1.06 MiB
DEFAULT_PROFILE = "30:0,120:55,120:85,30:0"
HARD_DEADLINE_SECS = 900.0                   # absolute cap, independent of profile
CALIBRATE_STEPS = [20.0, 35.0, 50.0, 65.0, 80.0, 95.0]
CALIBRATE_SECS_PER_STEP = 20.0


def do_work_unit():
    """One fixed-cost unit of work. Comparable across runs, modes and machines."""
    h = hashlib.sha256()
    h.update(WORK_BUFFER)
    h.digest()


def parse_profile(spec):
    """Parse "secs:duty,secs:duty" into [(secs, duty), ...]."""
    text = (spec or "").strip()
    if not text:
        raise ValueError("profile is empty")
    stages = []
    for chunk in text.split(","):
        if not chunk.strip():
            continue
        secs_txt, _, duty_txt = chunk.partition(":")
        secs = float(secs_txt.strip())
        duty = float(duty_txt.strip())
        if not 0.0 <= duty <= 100.0:
            raise ValueError("duty must be 0-100, got %s" % duty)
        if secs <= 0:
            raise ValueError("stage duration must be > 0, got %s" % secs)
        stages.append((secs, duty))
    if not stages:
        raise ValueError("profile is empty")
    return stages


def duty_slice(duty_percent, window_secs=0.1):
    """Split a scheduling window into (busy_secs, sleep_secs)."""
    duty = max(0.0, min(100.0, float(duty_percent)))
    busy = window_secs * (duty / 100.0)
    return busy, window_secs - busy


def widen_affinity():
    """Use every core. Harmless here, essential if ever run as an agent payload
    (the agent pins Windows payloads to 2 of 8 cores). Returns (before, after).

    Prefers stdlib os.sched_*affinity (Linux) so no third-party dep is required.
    """
    try:
        if hasattr(os, "sched_getaffinity"):
            before = sorted(os.sched_getaffinity(0))
            if len(before) < (os.cpu_count() or 1):
                os.sched_setaffinity(0, set(range(os.cpu_count())))
            return before, sorted(os.sched_getaffinity(0))
        if psutil is not None:
            p = psutil.Process()
            before = p.cpu_affinity()
            if len(before) < (os.cpu_count() or 1):
                p.cpu_affinity(list(range(os.cpu_count())))
            return before, p.cpu_affinity()
    except Exception:
        pass
    return None, None


class _ProcStatCpu:
    """System-wide CPU% from /proc/stat. Dependency-free Linux fallback for psutil.

    psutil is NOT installed on the test endpoints and installing packages on a
    lab VM to run a test is a bad trade, so this is the primary path on Linux.
    """

    def __init__(self):
        self._prev = None

    @staticmethod
    def _read():
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()
        vals = [int(v) for v in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)   # idle + iowait
        return sum(vals), idle

    def sample(self):
        try:
            total, idle = self._read()
        except Exception:
            return -1.0
        if self._prev is None:
            self._prev = (total, idle)
            return 0.0
        dt, di = total - self._prev[0], idle - self._prev[1]
        self._prev = (total, idle)
        if dt <= 0:
            return 0.0
        return round(100.0 * (dt - di) / dt, 1)


_PROC_STAT = _ProcStatCpu() if os.path.exists("/proc/stat") else None


def system_cpu():
    if _PROC_STAT is not None:
        return _PROC_STAT.sample()
    if psutil is not None:
        try:
            return psutil.cpu_percent(interval=None)
        except Exception:
            return -1.0
    return -1.0


class _Worker(threading.Thread):
    """Burns CPU on a fixed duty cycle. Counts completed work units."""

    def __init__(self, state):
        threading.Thread.__init__(self)
        self.daemon = True
        self.state = state
        self.units = 0

    def run(self):
        while not self.state["stop"]:
            busy, idle = duty_slice(self.state["duty"])
            if busy > 0:
                end = time.time() + busy
                while time.time() < end and not self.state["stop"]:
                    do_work_unit()
                    self.units += 1
            if idle > 0:
                time.sleep(idle)


def _spawn(state, n):
    workers = [_Worker(state) for _ in range(n)]
    for w in workers:
        w.start()
    return workers


def _stop(state, workers):
    state["stop"] = True
    for w in workers:
        w.join(timeout=5)


def run_profile(profile, hard_deadline=HARD_DEADLINE_SECS):
    cores = os.cpu_count() or 2
    workers_n = max(1, cores - 1)          # headroom so the box stays responsive
    before, after = widen_affinity()
    state = {"duty": 0.0, "stop": False}

    started = time.time()
    deadline = started + min(hard_deadline, sum(s for s, _ in profile) + 30)
    system_cpu()                           # prime psutil's delta counter
    workers = _spawn(state, workers_n)

    samples = []
    try:
        for stage_idx, (secs, duty) in enumerate(profile):
            state["duty"] = duty
            stage_end = time.time() + secs
            while time.time() < stage_end and time.time() < deadline:
                time.sleep(1.0)
                samples.append({
                    "t": round(time.time(), 3),
                    "work": sum(w.units for w in workers),
                    "cpu": system_cpu(),
                    "stage": stage_idx,
                    "duty": duty,
                })
            if time.time() >= deadline:
                break
    finally:
        _stop(state, workers)

    return {
        "mode": "run",
        "host": platform.node(),
        "platform": platform.system(),
        "cores": cores,
        "workers": workers_n,
        "affinity_before": before,
        "affinity_after": after,
        "profile": [[s, d] for s, d in profile],
        "started_at": started,
        "ended_at": time.time(),
        "samples": samples,
        "totals": {"work": sum(w.units for w in workers),
                   "elapsed": round(time.time() - started, 2)},
    }


def run_calibration():
    """Sweep duty and record achieved system CPU per step (load only, no scan).

    The generator must sit BELOW the scanner's high threshold on its own, so that
    the SCAN is what pushes the box across it. If the generator alone crosses the
    threshold, the scanner throttles at startup and the test proves nothing.
    """
    cores = os.cpu_count() or 2
    workers_n = max(1, cores - 1)
    before, after = widen_affinity()
    state = {"duty": 0.0, "stop": False}
    system_cpu()
    workers = _spawn(state, workers_n)

    steps = []
    try:
        for duty in CALIBRATE_STEPS:
            state["duty"] = duty
            time.sleep(3.0)                # settle before sampling
            system_cpu()
            readings = []
            end = time.time() + CALIBRATE_SECS_PER_STEP
            while time.time() < end:
                time.sleep(1.0)
                readings.append(system_cpu())
            steps.append({"duty": duty,
                          "cpu_mean": round(sum(readings) / len(readings), 1)
                          if readings else 0.0})
            print("  duty=%5.1f%% -> system_cpu=%5.1f%%" % (duty, steps[-1]["cpu_mean"]),
                  file=sys.stderr)
    finally:
        _stop(state, workers)

    moderate = max([s for s in steps if s["cpu_mean"] <= 55.0],
                   key=lambda s: s["duty"], default=None)
    heavy = max([s for s in steps if s["cpu_mean"] <= 72.0],
                key=lambda s: s["duty"], default=None)
    return {
        "mode": "calibrate",
        "host": platform.node(),
        "platform": platform.system(),
        "cores": cores,
        "workers": workers_n,
        "affinity_before": before,
        "affinity_after": after,
        "sweep": steps,
        "moderate_duty": moderate["duty"] if moderate else None,
        "heavy_duty": heavy["duty"] if heavy else None,
    }


def main():
    ap = argparse.ArgumentParser(description="Open-loop CPU load generator")
    ap.add_argument("--profile", default=DEFAULT_PROFILE,
                    help='stages as "secs:duty,secs:duty"')
    ap.add_argument("--calibrate", action="store_true",
                    help="sweep duty and report achieved system CPU per step")
    ap.add_argument("--out", help="write JSON here (also printed to stdout)")
    args = ap.parse_args()

    if psutil is None:
        print("WARNING: psutil missing - CPU samples will be -1", file=sys.stderr)

    result = run_calibration() if args.calibrate else run_profile(parse_profile(args.profile))
    blob = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print("wrote %s" % args.out, file=sys.stderr)
    print(blob)


if __name__ == "__main__":
    main()
