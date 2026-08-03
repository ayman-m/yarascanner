# CPU Impact Control — technical detail

Companion to the XDR YARA Scanner Guide. Read this if you need to answer *"will this scan
slow my machine, and how do you know?"*

The scanner bounds **its own share of the host**. It does not react to load other processes
create. This document explains the mechanism, what it guarantees, what it does not, and the
measurements behind those claims.

---

## 1. The guarantee

| `CONFIG_CPU_GUARANTEE` | Promise |
|---|---|
| `headroom` (default) | *"Your machine always retains at least N% CPU for everything else."* Target = `100 − CONFIG_CPU_HEADROOM_PCT − (what other processes are using)`. |
| `budget` | *"The scan never uses more than N% of your CPU."* Target = `CONFIG_CPU_BUDGET_PCT`, fixed. |
| `none` | No CPU governing. Low process priority still applies. |

Choose `headroom` unless you need a fixed number to put in a change request. It adapts: a
quiet machine gets a fast scan, a busy one gets a quiet scanner.

## 2. How it works

Once per second the governor measures:

```
own    = process_cpu_percent ÷ cpu_count      # this scan's share of the WHOLE host
others = system_cpu_percent − own             # everything else on the machine
target = per policy above, floored at CONFIG_CPU_FLOOR_PCT
```

It then adjusts a sleep ratio by proportional feedback on `own − target`. Each worker,
after finishing a file, sleeps `ratio × (time that file took)`.

Sleeping in proportion to work done — rather than a fixed interval — keeps the slowdown
factor stable regardless of file size, disk speed or machine class. The same configuration
behaves the same way on a laptop and a 32-core server.

**Why `others` is derived rather than measured directly:** the scanner reacts only to load
it is *not* causing, and only by shrinking its own share. It never stops. Under sustained
external pressure the target falls to `CONFIG_CPU_FLOOR_PCT` (default 5%) and the scan
continues slowly.

> **No throttle can create headroom that another process is consuming.** If something else
> is using 90% of the machine, the scanner cannot give you 30% free — it can only decline
> to make things worse. That is what the floor encodes.

## 3. Measured behaviour

Linux, 8 cores, `/usr` (93,116 files), 3 rounds, competing workload saturating the host:

| Condition | Wall clock | Time slept |
|---|---|---|
| idle host, `none` | 64 s | 0 s |
| idle host, `headroom` | 68 s | 0 s |
| **saturating load, `headroom`** | **153 s** | 40 s |
| saturating load, `budget=20%` | 131 s | 0 s |

**Governing an idle host costs about 6%.** Under heavy load the scan takes longer but
completes — degradation, never stalling.

Live telemetry captured with an external workload holding ~86% CPU:

| | Windows (loaded) | Linux (loaded) | Windows (control, no load) |
|---|---|---|---|
| `others` | 84.7–87.0% | 84.7–86.3% | 0.5–7.9% |
| `target` | 5.0 (floored) | 5.0 (floored) | 62–69 |
| `own` | 6.6–9.2% | 4.2–4.7% | 13.9–17.2% |
| sleep ratio | 3.2 → 4.1 | 1.75–2.28 | **0.0** |
| floor hits | 52 | 101 | **0** |

The control endpoint ran the same scan on the same platform with no competing load and
never throttled — the difference is attributable to the governor and nothing else.

## 4. What this does **not** claim

Honest framing matters more than a flattering one:

- **Throttling does not meaningfully protect the host.** Measured across 2, 4 and 8 emulated
  cores under saturating load, every mode preserved the competing workload within **−3% to
  +1% of not throttling at all**. The scanner runs a small number of threads and the OS
  scheduler already shares fairly.
- **The real value is predictability.** The scan never stalls on a busy machine, and the
  share it takes is a number you can state and verify afterwards.
- If you need a hard, kernel-enforced ceiling that survives a bug in the scanner, this is
  not that. It is self-governed.

## 5. Why this replaced the old `script` / `os` throttle modes

Earlier builds offered `throttle_mode = script | os | off`. `script` watched **system-wide**
CPU and paused the scan whenever it crossed a threshold; `os` dropped the process to the
operating system's idle priority tier. Both are gone. Four measured reasons:

**1. It reacted to load it did not cause.** System-wide CPU includes every other process on
the machine. On a busy host the scan paused itself for someone else's work, and kept pausing
for as long as that work continued. Measured: **285 s of a 347 s scan spent parked**, and up
to **65.9× slower** than the same scan unthrottled. Operators experienced this as a scan that
never finished.

**2. It bought almost nothing.** Across 2, 4 and 8 cores under saturating load, every mode
preserved the competing workload to within **−3% to +1%** of not throttling at all. The
slowdown was real; the protection was not.

**3. `os` mode starved.** The idle priority tier only gets CPU when nothing else wants it, so
on a saturated host the scan barely ran — **252 s versus 77 s** for the same work on 8 cores.

**4. You could not state what it would do.** *"Pause when system CPU exceeds 80%"* tells you
nothing about how much CPU the scan will use. There was no number to put in a change request
and nothing to check afterwards.

### What changed

| | Old (`script` / `os`) | New (CPU governor) |
|---|---|---|
| Watches | total system CPU | the scan's **own** share |
| Response | stop entirely, then resume | slow down proportionally |
| On a busy host | can park indefinitely | floors at `CONFIG_CPU_FLOOR_PCT` and keeps going |
| Can you state the impact? | no | yes — a percentage of the host |
| Can you verify it afterwards? | no | yes — §8 telemetry |

The honest summary: **the old design's cost was large and its benefit was near zero.** The new
one does not claim to protect the host either (§4) — what it adds is a bound you can state
before the scan, a guarantee the scan will finish, and evidence afterwards that the bound held.

**Nothing to change on upgrade.** The retired options are still accepted and translated, so
existing playbooks and scheduled jobs keep running: `throttle_mode=off` → `cpu_guarantee=none`,
and `throttle_mode=script` or `os` → `cpu_guarantee=headroom`.

## 6. Worker count

`CONFIG_WORKERS` defaults to **2**. Leave it there unless you have measured otherwise on
your storage.

| Workers | Wall clock (8-core Linux, 93k files, warm cache) |
|---|---|
| **2** | **71 s** |
| 4 | 93 s (+31%) |
| 8 | 101 s (+42%) |

More workers is **slower**. Scanning is disk-bound as well as CPU-bound, so additional
concurrent readers cause seek contention rather than useful overlap. The setting exists so
operators with fast NVMe can raise it after measuring — not as a default to tune upward.

## 7. Windows: the agent's own CPU ceiling

The Cortex agent pins payload processes to **2 CPU cores**, regardless of how many the host
has. Every scan records this:

```
THROTTLE_CONFIG {..., "host_cores": 8, "cpu_affinity_count": 2, "cpu_priority": "below_normal"}
```

Consequences:

- On an 8-core Windows host the scanner **cannot exceed roughly 25% of the machine**,
  whatever you configure. The agent has already applied coarse containment.
- On an **idle** Windows host the governor therefore does nothing: a 70% headroom target is
  unreachable from a 25% ceiling.
- Under **load** it does engage — when other processes push the target below 25%, the
  scanner is throttled down to it. Verified: with 86% external load the Windows target
  floored at 5% and the scanner was held to 6.6–9.2%.

## 8. Telemetry — verifying the promise after the fact

`performance_<run_id>.log` on the endpoint carries one header per run, plus a governor line
on meaningful change or every 30 seconds:

```
THROTTLE_CONFIG {"cpu_guarantee":"headroom","cpu_headroom_pct":30.0,"cpu_budget_pct":25.0,
                 "cpu_floor_pct":5.0,"platform":"Windows","host_cores":8,
                 "cpu_affinity_count":2,"cpu_priority":"below_normal"}

CPU_GOVERNOR    {"policy":"headroom","target":5.0,"own":8.7,"others":85.6,
                 "ratio":3.166,"slept_secs":24.71,"floor_hits":39,"t":1785689224.638}
```

| Field | Meaning |
|---|---|
| `target` | share of the host the scanner is aiming to stay under |
| `own` | share of the **whole host** this scan is using — should never exceed 100 |
| `others` | everything else on the machine |
| `ratio` | current sleep multiplier; 0.0 means not throttling |
| `slept_secs` | cumulative time surrendered |
| `floor_hits` | times the target hit the floor, i.e. the host was heavily loaded |

The same figures appear under `cpu_governor` in `scan_summary_<run_id>.json` — that is your
after-the-fact evidence that the promise held.

## 9. Tuning

| Symptom | Change |
|---|---|
| Scan too slow on a busy host | Lower `CONFIG_CPU_HEADROOM_PCT` (leaves less free, lets the scan use more), or switch to `budget` with a higher `CONFIG_CPU_BUDGET_PCT` |
| Need a fixed, stateable number | `CONFIG_CPU_GUARANTEE = "budget"` |
| Maintenance window, speed matters | `CONFIG_CPU_GUARANTEE = "none"` |
| Scan must always make progress | Raise `CONFIG_CPU_FLOOR_PCT` — the floor is the minimum share it will keep even on a saturated host |

Per-run overrides via the `options` string avoid re-uploading:

```
cpu_guarantee=budget,cpu_budget_pct=20
cpu_guarantee=none
```
