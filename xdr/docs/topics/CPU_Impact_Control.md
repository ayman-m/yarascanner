# CPU Impact Control — technical detail

*Applies to scanner **3.4.0**. History of changes: [release notes](../../../CHANGELOG.md).*

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

## 3. What it actually holds

Measured on a live endpoint while an unrelated workload held ~86% of the CPU, alongside a
control endpoint running the same scan with no competing load:

| | Under load | Control (no load) |
|---|---|---|
| Other processes | 84.7–87.0% | 0.5–7.9% |
| Governor target | 5.0 (floored) | 62–69 |
| **Scan's actual share** | **6.6–9.2%** | 13.9–17.2% |
| Sleep ratio | 3.2 → 4.1 | **0.0** |

The control endpoint never throttled, so the difference is attributable to the governor and
nothing else. Under load the scan slowed and kept going; it did not stall.

**Governing an idle host costs roughly 6%** in wall-clock time.

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

## 5. Upgrading from an earlier build

The retired options are still accepted and translated, so existing playbooks and scheduled
jobs keep running unchanged:

| Old option | Now |
|---|---|
| `throttle_mode=off` | `cpu_guarantee=none` |
| `throttle_mode=script` or `os` | `cpu_guarantee=headroom` |
| `cpu_high_threshold`, `cpu_critical_threshold`, `max_pause_secs` | accepted, value ignored |

There is no two-level *high* / *critical* threshold any more — §1 and §2 describe what
replaced it. For why that design changed and the measurements behind it, see the
[release notes](../../../CHANGELOG.md).

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

## 7. Platform differences

### Windows: the agent's own CPU ceiling

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

### macOS: the agent competes with the scan

macOS imposes **no affinity cap** — the scanner may use every core, and the run header
records this:

```
THROTTLE_CONFIG {..., "platform": "Darwin", "host_cores": 8, "cpu_affinity_count": 8, "cpu_priority": "nice=10"}
```

But a scan on macOS provokes heavy activity from the **Cortex agent's own processes**, which
monitor file access. Measured on macOS 15.1 (8 cores, arm64) while scanning `/Applications`,
`pmd` and `authorized` together held well over 100% CPU — and the governor correctly counts
that as `others` and yields to it.

The practical consequence:

- A macOS scan can spend much of its life at the **floor**, throttled by load its own
  activity provoked. Across one run: `others` moved 0% → 90%, the target fell 70% → 5%,
  and the scan surrendered 146 s across 96 floor hits.
- **The scan still completes** — that is what the floor guarantees — but expect it to take
  substantially longer on macOS than the same work on an idle Linux host.
- If macOS scans are too slow, raise `CONFIG_CPU_FLOOR_PCT`. The competing load is the
  security agent doing its job, so it will not go away on its own.

> An idle-host baseline is difficult to obtain on macOS for this reason: the agent reacts to
> the scan, so the machine stops being idle the moment scanning starts.

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
