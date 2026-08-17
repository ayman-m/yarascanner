# XSIAM YARA Scanner — Live Acceptance Test Plan
> Every one of the **297 catalogued XSIAM capabilities** is assigned here: to one of
> three live rounds, or to an explicitly-reasoned `not covered`. Nothing is left
> implicit. Criteria are agreed **before** any scan runs.

## How a capability was assigned
A capability belongs to the round whose conditions actually **drive** its code path,
not merely the round that touches it. Rule compilation happens in all three rounds;
it belongs to Round 3, where malformed and module-dependent packs actually probe it.
Delivery batching happens in every round; it belongs to Round 2, because only a flood
fills a batch.

The capability reference's own dimension is the prior — a structured signal, not a
prose match. Explicit per-capability overrides move the minority whose sharpest test
lives elsewhere. Every override and every hand-written name is checked against the
reference at generation time: a name matching nothing is a hard error, never a silent
no-op.

## Acceptance criterion format
| Field | Meaning |
|---|---|
| **Must be true** | The binary claim. It either holds in the evidence or it does not. |
| **Threshold** | The numeric or exact-value bar, where one exists. |
| **Setup** | What the run must do to reach this code — planted decoy, env var, rule shape, mid-run action. Absent means the standard run for that round reaches it. |
| **Evidence** | The exact artefact — file, `scan_summary` field, log line, or collector event type — that decides it. |
| *Priority* | `core` = a promise a customer would notice breaking. `supporting` = the mechanism behind one. `low` = diagnostic detail. |

A criterion that cannot fail is not a criterion. Each one below either names a
value to compare or an artefact whose absence is itself the failure.

### Where the evidence lives
Two places, and several capabilities can only be decided in the second:

- **On the endpoint** — `<scanner_dir>/logs/` (the six category logs plus the
  diagnostics sink), `alert/`, `evidence/`, `control/`, and
  `scan_summary_<run_id>.json`.
- **On the tenant** — the `yara_scans_raw` dataset, queried by `scan_id`. Event
  types such as `system_resource_snapshot` and `resource_monitoring_summary` appear
  in no log file at all, so the endpoint alone cannot decide them.

Bulk evidence is pulled back compressed and chunked. Action Center truncates a
script's stdout at 10,240 characters, so a single-line base64 of any real log comes
back cut mid-stream — Round 1's performance log alone was 390 KB.

## Decisions taken
These were open; they are settled as follows so execution is unambiguous.

| Decision | Choice | Why |
|---|---|---|
| Delivery channels | **ON** for every round | `match_delivery` / `telemetry_delivery` balance sheets are themselves catalogued capabilities. With uploads off they are structurally untestable — you cannot verify "totals always balance" against a channel that never ran. |
| Cancellation | **Inside Round 3**, not its own round | Cancellation is a resilience property and shares Round 3's evidence bundle. A whole-filesystem scan is also the only run long enough to cancel *mid-walk* rather than during teardown. |
| XDR tenant mirroring | **Not done** | Scope is XSIAM. The XDR edition has its own reference and its own rounds. |
| Round 1 failure policy | **stop-on-fail** | Resource discipline is foundational: if the governor or worker pool misbehaves, Round 2 and 3 timings are measuring a broken baseline. |
| Round 2 / 3 failure policy | **collect-through** | These probe independent properties. Halting on the first failure would hide the other 100+ results in the same evidence bundle, which is expensive to reproduce. |

## Coverage
| Round | Title | Capabilities | core | Endpoints | On failure |
|---|---|---|---|---|---|
| **1** | Resource discipline | 54 | 6 | `xsoar` | stop-on-fail |
| **2** | False-positive flood | 107 | 7 | `xsoar`, `thor` | collect-through |
| **3** | Precision and resilience | 113 | 18 | `xsoar`, `OfficeiMac`, `thor` | collect-through |
| — | Not covered | 23 | 0 | — | — |

**Total 297 / 297.** 271 asserted, 3 reachability probes, 23 not covered.

---

# Round 1 — Resource discipline

**Endpoints:** `xsoar`  
**On failure:** stop-on-fail  
**Capabilities:** 54 (6 core)

**Scenario.** A sustained real-filesystem scan on the 8-core Linux host with the CPU governor active. Long enough that monitors, the heartbeat, the worker pool and backpressure all reach steady state rather than finishing in a burst.

**Why these belong together.** Every assertion here is about how the scan consumes the host. These need TIME and CONCURRENCY to be real — a 20-file scan satisfies them vacuously.

## Traversal (3)

### `TRAV-011` Cancellable explicit-stack directory walk

*supporting* · on `xsoar`

- **Must be true** — A cancellation issued mid-walk is honoured within a single scandir: the process reaches a terminal state promptly and reports the run as cancelled, never as completed.
- **Threshold** — Process exit occurs <= 10s after the cancel.flag write (the XDR regression this replaced was a ~50s post-cancel tail); outcome == 'cancelled'; the result line must NOT begin 'Scan completed'; scan_summary.files_scanned is strictly less than the file count under the target. Do NOT use the console Cancel button — it hard-kills the payload and orphans the lifecycle row.
- **Setup** — During the xsoar whole-filesystem scan, at ~60s in, write control/cancel.flag over SSH. Capture `date +%s.%N` immediately before the write and again when the payload PID disappears from `ps`.
- **Evidence** — wall time between the control/cancel.flag write and process exit; `outcome` in logs/scan_summary_<run_id>.json (6765); the SCAN_RESULT line beginning `Scan cancelled (source=...)` (6616); terminal status `cancelled` from status_uploader.set_status (6642).

### `TRAV-041` Per-target progress and throughput reporting

*supporting* · on `xsoar`

- **Must be true** — Each resolved target is announced before its walk and produces exactly one completion record carrying files_found, scan_time_seconds and files_per_second, and files_found is a discovery count taken before the special-file test.
- **Threshold** — count('Target scan completed') == len(scan_targets) in scan_summary_<run_id>.json; sum of files_found across targets >= files_scanned + skip_breakdown['Special system file'] (discovery count is a superset of scanned); every files_per_second > 0 for targets with files_found > 0.
- **Evidence** — 'Scanning target i/N: <path>' system records with {'target_index','target_path'} in system_<run_id>.log (5929-5932); 'Target scan completed: <path>' statistics_critical records with {'target','files_found','scan_time_seconds','files_per_second'} (5992-6000).

### `TRAV-043` No-drop enqueue under backpressure

***core*** · on `xsoar`

- **Must be true** — Under sustained queue saturation the producer blocks and retries instead of dropping paths, so discovered files and processed files cannot silently diverge.
- **Threshold** — At least one saturation line appears; sum(files_found over targets) - (files_scanned + files_skipped - skip_breakdown['Skipped directory']) == 0 (exact reconciliation, no dropped paths).
- **Setup** — Long scan on xsoar with YARA_THREADS=1 and YARA_QUEUE_SIZE=2 so discovery outruns the workers, plus competing CPU load (stress-ng --cpu 6) to keep workers slow.
- **Evidence** — 'Scan queue saturated (N items) - backing off producer' in /opt/yara_scanner/logs/performance_<run_id>.log (4931-4934); per-target files_found from the 'Target scan completed' statistics records; files_scanned + files_skipped from the final metrics and scan_summary_<run_id>.json. Code: _enqueue_scan_path 4923-4941 (put timeout 1.0s, loop while scan_active).

## Performance (45)

### `PERF-001` CPU governor policy selection

***core*** · on `xsoar`

- **Must be true** — The configured policy is the one that runs: with YARA_CPU_GUARANTEE=headroom the governor is enabled and emits policy=headroom lines; with 'none' (or any unknown value) it is disabled and emits none at all.
- **Threshold** — Run A (default): cpu_policy == 'headroom' and count of 'CPU governor \|' lines > 0. Run B (YARA_CPU_GUARANTEE=none): cpu_policy == 'none' and count of 'CPU governor \|' lines == 0 and slept time 0.
- **Setup** — Two runs on xsoar over SSH, the second with `YARA_CPU_GUARANTEE=none` exported; both against the same target tree with the same competing load.
- **Evidence** — 'CPU governor \| policy=<p> target=..% own=..% others=..% ratio=..' lines in /opt/yara_scanner/logs/performance_<run_id>.log with structured data {policy,target,own,others,ratio,slept_secs,floor_hits} (_sample_governor 4917-4921, stats() 2720-2729); 'All monitoring systems activated' system event key cpu_policy (5866).

### `PERF-002` Headroom policy target computation

***core*** · on `xsoar`

- **Must be true** — Under headroom, target == 100 - headroom_pct - others for every emitted sample (until the floor clamps it), so rising external load shrinks the scanner's target instead of stopping it.
- **Threshold** — For every emitted sample with target > floor_pct: abs(target - (100 - 30 - others)) <= 0.2. On the idle prelude target ~= 70; after stress-ng starts, target falls by the same number of points that others rises, within one 0.5s sample interval.
- **Setup** — Long scan on xsoar; start `stress-ng --cpu 4 --timeout 300s` ~60s into the run and stop it ~60s later, so the sample series contains an idle-load-idle transition.
- **Evidence** — target, own and others fields in each 'CPU governor \|' performance record in performance_<run_id>.log; code compute_target 2665-2675, update 2677-2699 (others = max(0, system - own)).

### `PERF-003` Budget policy fixed ceiling

***core*** · on `xsoar`

- **Must be true** — Under budget the target is a constant equal to budget_pct for the whole run and never reacts to others, and floor_hits stays 0.
- **Threshold** — Every emitted sample has policy == 'budget' and target == CPU_BUDGET_PCT exactly (25.0 default), with zero variance across the run; floor_hits == 0 in the last record; others varies by >20 points across the run (proving the constancy is not just an idle host).
- **Setup** — Dedicated run on xsoar with `YARA_CPU_GUARANTEE=budget` exported, with the same stress-ng load transition as the headroom run.
- **Evidence** — 'CPU governor \| policy=budget target=25.0% ...' lines in performance_<run_id>.log; floor_hits in the same records' structured data. Code compute_target 2669-2670 (returns budget_pct before any others/floor logic).

### `PERF-004` CPU floor and floor_hits counter

*supporting* · on `xsoar`

- **Must be true** — When external load would drive the headroom target below floor_pct, the target is clamped to floor_pct and floor_hits increments, so the scanner keeps a minimum share and cannot be starved to a stall.
- **Threshold** — During the heavy-load window: target == 5.0 exactly and floor_hits strictly increases between consecutive records; files_scanned in the Scan Progress records still increases across that same window (non-zero forward progress while floored).
- **Setup** — Drive the host above 65% with unrelated work: `stress-ng --cpu 7 --timeout 240s` on the 8-core xsoar under default headroom=30, during a long scan.
- **Evidence** — target and floor_hits in the 'CPU governor \|' performance records; code compute_target 2671-2675 (if target < floor_pct: floor_hits += 1; return floor_pct).

### `PERF-005` Own-CPU normalisation across cores

*supporting* · on `xsoar`

- **Must be true** — The governor's own is a share of the whole 8-core machine, not of one core, so it is bounded by 100 and is about 1/8 of psutil's raw per-core process reading.
- **Threshold** — max(own) over the run <= 100.0; for time-aligned samples abs(own - raw_ps_percent/8) <= 5 percentage points; with 2 workers saturating, own must exceed 12.5 (which is what a missing normalisation would cap it near).
- **Setup** — Long scan on xsoar with YARA_THREADS=4 so the raw per-core reading can exceed 100%; sample `ps -o %cpu= -p <scanner pid>` once a second into a file for time alignment.
- **Evidence** — own field in 'CPU governor \|' performance records vs. the raw process CPU seen live via `top -b -n1 -p <pid>` / `ps -o %cpu -p <pid>` on xsoar; code normalise_own 2653-2663 (divide by cpu_count), update 2689.

### `PERF-006` Proportional sleep-ratio controller (GAIN, RATIO_MAX)

*supporting* · on `xsoar`

- **Must be true** — The sleep ratio moves by GAIN (0.05) per point of (own - target) between samples and is always clamped to [0, 20.0].
- **Threshold** — For every consecutive pair of records: 0.0 <= ratio <= 20.0, and where neither bound is active abs((ratio_n - ratio_n-1) - 0.05*(own_n - target_n)) <= 0.01; on an idle host ratio stays 0.0 for the whole run.
- **Setup** — Same loaded xsoar run as the headroom criterion; parse the performance log's structured data into a series.
- **Evidence** — ratio, own and target in consecutive 'CPU governor \|' performance records; code GAIN=0.05 / RATIO_MAX=20.0 at 2632-2633, update 2692-2695.

### `PERF-007` pace() — post-work proportional sleeping with a per-call cap

*supporting* · on `xsoar`

- **Must be true** — Sleeps `work_secs * sleep_ratio`, capped at PACE_CAP_SECS per call, and accumulates the total. Proportional sleeping keeps the slowdown factor stable across file sizes and machine speeds; the cap keeps any single pause short so cancellation and shutdown stay responsive. Returns 0.0 immediately when disabled or ratio is 0.
- **Evidence** — `slept_secs` in the governor stats dict (cumulative pacing time for the run). Wall-clock scan duration vs. `files_scanned` will diverge from an unthrottled baseline in proportion to it.

### `PERF-008` pace() call site is AFTER the YARA match, not before

*supporting* · on `xsoar`

- **Must be true** — The scan makes continuous forward progress under heavy external load - files_scanned strictly increases across every progress interval even while ratio is non-zero - because pacing follows the match instead of gating it.
- **Threshold** — Across the full heavy-load window there is no 90-second span in which files_scanned is unchanged while ratio > 0; the longest zero-progress gap is < 60s. A run that stalls with 0 files scanned and a non-zero ratio is a hard fail (this is the regression the governor replaced).
- **Setup** — Long scan on xsoar with `stress-ng --cpu 7` held for the middle 4 minutes of the run.
- **Evidence** — files_scanned in successive 'Scan Progress \| Files: N scanned, M skipped \| ...' statistics records in statistics_<run_id>.log (log_scan_progress 2090-2110, emitted every YARA_PROGRESS_LOG_SECS=30) correlated with ratio from the 'CPU governor \|' performance records; code scan_file 5012-5020 (_sample_governor, _work_started, rules.match, cpu_governor.pace).

### `PERF-009` Governor sampling cadence (rate limit)

*low* · on `xsoar`

- **Must be true** — Not assertable today: no artefact records when a sample was taken, only when a line was emitted, and emission is separately gated by the change/heartbeat policy.
- **Threshold** — n/a
- **Evidence** — None. _sample_governor 4887-4896 returns early on (now - last_governor_sample) < throttle_check_interval_secs without logging; the only emitted record is the change/heartbeat-gated 'CPU governor \|' line at 4917-4921, whose spacing measures the emit policy, not the sample rate.

### `PERF-011` psutil CPU-reading priming

*supporting* · on `xsoar`

- **Must be true** — The first governor sample of a busy scan reports a meaningful non-zero own, because both the process handle and the system reading were primed at construction and the handle is long-lived.
- **Threshold** — own > 0.0 and others >= 0.0 in the FIRST governor record of a run whose scan is already matching files at that timestamp (cross-check files_scanned > 0 in the nearest Scan Progress record). own == 0.0 on the first record of a busy run is a fail.
- **Setup** — Start the scan against a dense tree (many small files) so matching is underway before the first sample interval elapses.
- **Evidence** — The first 'CPU governor \|' record in performance_<run_id>.log, fields own and others; code YaraScanner.__init__ governor priming (self._governor_proc = psutil.Process(); cpu_percent(interval=None); psutil.cpu_percent(interval=None)) around 4390-4400.

### `PERF-012` Governor telemetry emission policy (change threshold + heartbeat)

*supporting* · on `xsoar`

- **Must be true** — A governor line is emitted at least once per GOVERNOR_HEARTBEAT_SECS even when nothing changes, and additionally whenever the ratio moves by >= 0.25 since the last emission.
- **Threshold** — On the idle baseline run: number of governor records >= floor(scan_duration_secs / 30) - 1, and no gap between consecutive records exceeds 35s. On the loaded run: every extra record beyond the heartbeat cadence has abs(ratio - previous emitted ratio) >= 0.25.
- **Setup** — Idle baseline run on xsoar of at least 5 minutes with no competing load (expect ratio=0.0 throughout, ~10+ heartbeat records).
- **Evidence** — Timestamps of 'CPU governor \|' records in performance_<run_id>.log; code 4912-4921 (changed >= 0.25 OR heartbeat >= GOVERNOR_HEARTBEAT_SECS, default 30 from line 335).

### `PERF-014` Worker thread pool, default 2 and operator-raisable

*supporting* · on `xsoar`

- **Must be true** — Scan workers are `ScanWorker-N` daemon threads. `YARA_THREADS` sets the count and is honoured as given; the default is 1 on <=2-core hosts, else 2. Two stays the default on any core count because measurement put it there: the work is disk-bound, and on 8-core Linux over /usr (93k files) 2 workers took 71 s, 4 took 93 s, 8 took 101 s. The old min(2, ...) ceiling additionally made the knob a no-op, so it was removed while the default was kept.
- **Evidence** — System event "YaraScanner initialized with N workers" with `max_workers` in its data; init event data `max_workers`; "All monitoring systems activated" `worker_threads`; per-tick `active_workers` in Scan Progress events; thread names ScanWorker-1/ScanWorker-2 in "Worker <name> started/stopped" system events; `worker_threads_used` in the final summary payload.

### `PERF-015` Worker startup timing event

*supporting* · on `xsoar`

- **Must be true** — Spawning the worker pool is measured and reported once as a critical (direct-send) performance event whose workers_started equals max_workers.
- **Threshold** — Exactly 1 such record per run; workers_started == max_workers; worker_startup_time_seconds < 1.0 even at YARA_THREADS=6; the record is present even on a run where the async webhook queue is backlogged.
- **Evidence** — 'Worker thread startup completed in X.XX seconds' performance record with data {'worker_startup_time_seconds','workers_started'}, sent via log_performance_critical (5900-5903).

### `PERF-016` Bounded scan queue

*supporting* · on `xsoar`

- **Must be true** — The scan queue never holds more than scan_queue_size paths, so scanner memory is independent of directory size.
- **Threshold** — max(queue_size) over all Scan Progress records <= scan_queue_size, exactly; and scanner RSS (peak_memory_mb, or `ps -o rss` sampled during the run) does not grow monotonically across a scan of a >1,000,000-entry tree - final RSS within 1.3x of RSS at the 2-minute mark.
- **Setup** — Long scan on xsoar over a very large tree with YARA_QUEUE_SIZE left at default (max_workers*2); sample `ps -o rss= -p <pid>` once a second over SSH.
- **Evidence** — scan_queue_size in the initialization event data (6358); queue_size in every 'Scan Progress' statistics record (2098, sourced from self.scan_queue.qsize() at 5471); code Queue(maxsize=self.config.scan_queue_size) at 4362, ScanConfig 2835-2837.

### `PERF-017` Producer backpressure on a full queue (never drops files)

*supporting* · on `xsoar`

- **Must be true** — On a full queue the producer counts the event, samples the governor, sleeps queue_backoff_secs and retries, and logs the saturation line on the 1st, 26th, 51st... occurrence rather than every time.
- **Threshold** — Saturation lines exist and the N reported in them equals scan_queue_size (queue at max); the number of such lines is <= ceil(observed backoff iterations / 25) - i.e. the log is rate-limited, not one line per Full; queue_size in the overlapping Scan Progress records == scan_queue_size.
- **Setup** — YARA_THREADS=1, YARA_QUEUE_SIZE=2 on a dense tree on xsoar with stress-ng load, so Full fires thousands of times.
- **Evidence** — 'Scan queue saturated (N items) - backing off producer' records in performance_<run_id>.log and their count vs. wall time (4928-4934, `if self.queue_full_events % 25 == 1`); queue_size in Scan Progress records; code queue_backoff_secs 2861.

### `PERF-018` Worker get timeout / graceful exit checks

*supporting* · on `xsoar`

- **Must be true** — Workers re-evaluate scan_active and the None sentinel at least every 5 seconds instead of blocking forever on an empty queue, so they stop promptly after discovery ends.
- **Threshold** — Every 'Worker ScanWorker-N stopped' record is within 6.0s of the 'Initiating worker thread cleanup' record; count of stopped records == max_workers.
- **Evidence** — Timestamps of 'Initiating worker thread cleanup' (5776) and each 'Worker ScanWorker-N stopped' system record with data {'files_processed','errors_encountered','average_processing_time_ms'} (4876-4882) in system_<run_id>.log; code _worker 4831-4833 (get(timeout=5.0)) and 4862 (except Empty: continue).

### `PERF-019` Sentinel-based worker shutdown with bounded joins

*supporting* · on `xsoar`

- **Must be true** — Cleanup posts one sentinel per worker and joins each with a 5s cap, reporting how many stopped and how many timed out, and never lets a stuck worker hang the run.
- **Threshold** — Exactly 1 'Worker cleanup:' record with N == max_workers and M == 0 on a healthy run; total elapsed between 'Initiating worker thread cleanup' and that record <= 5 * max_workers seconds; no 'Threads did not terminate' record.
- **Evidence** — System records 'Initiating worker thread cleanup' and 'Waiting for workers to terminate (max 30 seconds)' (5776, 5784); performance record 'Worker cleanup: N stopped, M timed out in X.Xs' (5813-5815); error record 'Threads did not terminate: [names]' (5808) when any survive. Code _perform_enhanced_cleanup 5778-5815.

### `PERF-020` Per-worker throughput reporting every 100 files

*supporting* · on `xsoar`

- **Must be true** — Each worker emits its own throughput/error-rate performance line on every 100th successfully processed file, with per-worker attribution.
- **Threshold** — For each worker, the files_processed values reported form the exact sequence 100, 200, 300, ...; the last reported value per worker is within 100 of that worker's final files_processed in its 'Worker ... stopped' record; number of distinct worker_id values == max_workers.
- **Setup** — Scan large enough that each worker processes >500 files (whole-filesystem or a dense tree on xsoar).
- **Evidence** — 'Worker Performance \| ScanWorker-N \| Files: X \| Avg Time: Y.Yms \| Error Rate: Z.Z%' records in performance_<run_id>.log with data {worker_id, files_processed, avg_processing_time_ms, error_rate_percent} (log_worker_performance 2113-2126; emit site _worker 4848-4854).

### `PERF-021` Per-worker processing-time ring buffer

*supporting* · on `xsoar`

- **Must be true** — Per-worker processing-time history is trimmed to the last 100 samples, so reported averages reflect recent work and the structure does not grow with the file count.
- **Threshold** — On a run where a worker processes >100,000 files, its final average_processing_time_ms differs from the mean of its last 100 'Worker Performance' Avg Time values by < 20%, and scanner RSS growth attributable to worker_processing_times is nil (final RSS within 1.3x of the 2-minute mark - same measurement as the bounded-queue criterion).
- **Setup** — Long scan on xsoar over a >100k-file tree; sample `ps -o rss= -p <pid>` once a second.
- **Evidence** — average_processing_time_ms in the 'Worker <id> stopped' system record (4876-4882) and Avg Time in the 'Worker Performance \|' records; scanner RSS sampled over the run. Code scan_file finally block 5104-5108 (append then trim to [-100:]).

### `PERF-022` Process priority lowering (CPU and I/O)

*supporting* · on `xsoar`

- **Must be true** — At startup the scanner process is de-prioritised - nice >= 10 on Linux plus ionice best-effort class level 7 - and the applied values are reported; a failure is recorded as an *_error key rather than aborting the scan.
- **Threshold** — cpu_priority == 'nice=10' and io_priority == 'best_effort:7'; live `ps -o ni` returns >= 10 and `ionice -p` returns 'best-effort: prio 7' for the scanner PID during the run; the record appears before the first 'Worker ScanWorker-1 started'.
- **Setup** — Run the scanner over SSH on xsoar as a normal user (nice can be raised, not lowered) and poll ps/ionice for the PID once the scan is underway.
- **Evidence** — 'Applied light profile process priority tuning' system record in system_<run_id>.log with data containing cpu_priority ('nice=10') and io_priority ('best_effort:7'), or cpu_priority_error / io_priority_error (_apply_light_process_priority 962-996, called from main() at 6207). Live cross-check on xsoar: `ps -o ni= -p <pid>` and `ionice -p <pid>`.

### `PERF-023` Optional performance monitor (StatisticsManager background thread)

*supporting* · on `xsoar`

- **Must be true** — The performance monitor is off by default and says so, and when explicitly enabled it starts a 5s-sampling daemon thread that logs a detail snapshot roughly every 30s and populates the peak/average metrics.
- **Threshold** — Run A (default): performance_monitoring_enabled == false, 0 'Performance Snapshot \|' records. Run B (YARA_ENABLE_PERF_MONITOR=true): count of 'Performance Snapshot \|' records == floor(scan_duration_secs / 30) +/- 2, peak_memory_mb > 0 and peak_cpu_percent > 0, and the thread stops ('Performance monitoring worker stopped') after the worker join, not before.
- **Setup** — Two runs on xsoar over the same tree, the second with `YARA_ENABLE_PERF_MONITOR=true` exported over SSH (Action Center cannot set env vars, so this must be the SSH-launched run).
- **Evidence** — Default run: 'Performance monitoring disabled in light profile' in statistics_<run_id>.log (1602) and performance_monitoring_enabled == false in the initialization event (6361) and in 'All monitoring systems activated' (5860-5867). Enabled run: 'Performance monitoring thread started' (1607), 'Performance monitoring worker started' (1611), and 'Performance Snapshot \| CPU: ..% \| Memory: ..MB (..%) \| Disk I/O: ... \| Network: ... \| Queue: n \| Workers: n' records (1700-1708); peak_cpu_percent / avg_cpu_percent / peak_memory_mb in the statistics summary (1769-1770). Code ENABLE_PERF_MONITOR = _env_bool('YARA_ENABLE_PERF_MONITOR', False) at 247; _monitoring_worker 1609-1630 (sleep 5, every 6th sample).

### `PERF-024` Optional system resource monitor (SystemResourceMonitor)

*supporting* · on `xsoar`

- **Must be true** — With resource monitoring enabled, a scan longer than 90s emits periodic `system_resource_snapshot` events at the 45 s upload cadence and exactly one terminal `resource_monitoring_summary`, and emits neither when the toggle is off.
- **Threshold** — snapshot_count >= floor(scan_duration_secs/45) - 1 and >= 1; resource_monitoring_summary count == 1; control run with the flag off yields 0 of both.
- **Setup** — xsoar, long scan under competing load. ENABLE_RESOURCE_MONITOR is False by default (line 246) - run over SSH with YARA_ENABLE_RESOURCE_MONITOR=1 (Action Center delivery cannot set env vars; alternatively flip the constant at line 246 in the uploaded copy). Run the identical scan a second time with it off as the negative control.
- **Evidence** — Wire events matched on the field `type` (not `log_type`; StandardLogEntry.to_dict) with values `system_resource_snapshot` (created/queued at PINNED_xsiam_current.py:2498) and `resource_monitoring_summary` (2597), filtered by scan_id; cross-checked against `<scanner_dir>/logs/uploads_<run_id>.log`.

### `PERF-025` Optional file-descriptor monitor

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — On Linux with FD monitoring enabled, the startup FD block runs once and records the ulimit and the baseline FD count, and records nothing at all when the toggle is off or on Windows.
- **Threshold** — Enabled Linux run: exactly 1 occurrence of each line, both with N > 0. Toggle-off run and the thor (Windows) run: 0 occurrences of either line.
- **Setup** — xsoar via SSH with YARA_ENABLE_FD_MONITOR=1. Note `ulimit -n` on xsoar first: if it is already >= 8192 the resource_limit_warning branch will not fire and its absence is the correct result, not a failure.
- **Evidence** — `<scanner_dir>/logs/system_<run_id>.log` lines `Current file descriptor limit: <N>` (emitted at 6294) and `Initial file descriptors in use: <N>` (6327); plus a `resource_limit_warning` typed event (6302-6307) only when the limit is < 8192.

### `PERF-026` Progress heartbeat thread

*supporting* · on `xsoar`

- **Must be true** — A scan lasting longer than log_interval produces repeated Scan Progress events from the dedicated heartbeat thread across the whole run, never zero.
- **Threshold** — progress_event_count >= floor(scan_duration_secs / 30) - 1, and strictly > 0. Zero events on a run longer than 30 s is a hard fail.
- **Evidence** — `<scanner_dir>/logs/statistics_<run_id>.log` lines matching `Scan Progress \| Files: ... \| Queue: <n> \| Rate: <r> files/sec` (LogManager.log_scan_progress, 2090), driven by `_progress_heartbeat` (5735) started as a daemon thread at 5906-5910.

### `PERF-027` Progress heartbeat interval and its clamp

*supporting* · on `xsoar`

- **Must be true** — Consecutive Scan Progress events are spaced at the configured interval, and setting the interval to 0 clamps to ~1 s rather than busy-spinning.
- **Threshold** — Default run: median inter-event gap in [28, 33] s. Clamp run with YARA_PROGRESS_LOG_SECS=0: median gap in [0.9, 1.5] s and total event count <= scan_duration_secs * 1.2 (i.e. no flood).
- **Setup** — Two xsoar runs over SSH: one default, one short (~120 s) run with YARA_PROGRESS_LOG_SECS=0 to exercise the clamp.
- **Evidence** — Timestamps of consecutive `Scan Progress \|` lines in `<scanner_dir>/logs/statistics_<run_id>.log`; config source `self.log_interval = max(1, _env_number("YARA_PROGRESS_LOG_SECS", 30, cast=int, minimum=1))` at line 2850.

### `PERF-028` Progress heartbeat lifetime spans the worker drain

*supporting* · on `xsoar`

- **Must be true** — Scan Progress events continue to be emitted after file discovery ends and stop only at the post-join heartbeat stop in cleanup.
- **Threshold** — At least 1 Scan Progress event timestamped after the last `Scanning target N/N` line; last Scan Progress timestamp <= Worker cleanup timestamp + 2 s (the join timeout) and >= last-discovery timestamp.
- **Setup** — Ensure the drain phase is long: point the scan at a directory whose files are slow to match (large files plus competing CPU load) so discovery finishes minutes before the queue drains.
- **Evidence** — Interleaved timestamps across `<scanner_dir>/logs/`: last `Scanning target N/N` line in system_<run_id>.log, all `Scan Progress \|` lines in statistics_<run_id>.log, and the `Worker cleanup: <k> stopped, <m> timed out in <t>s` line in performance_<run_id>.log (emitted just before `_progress_heartbeat_stop.set()` at 5815-5818).

### `PERF-029` Progress snapshot contents (capacity/backpressure telemetry)

*supporting* · on `xsoar`

- **Must be true** — Every Scan Progress event carries the full capacity/backpressure field set, with queue_size and active_workers reflecting real live values.
- **Threshold** — 100% of Scan Progress events contain all 9 metrics keys plus queue_size and top-level active_workers; active_workers in [0,2] (max_workers is capped at 2) and == 2 for at least one mid-scan event; queue_size > 0 for at least one event during discovery.
- **Evidence** — Wire event `type: "statistics"` for Scan Progress: top-level `queue_size`, `scan_rate_files_per_sec`, `active_workers`, and `metrics: {cpu_percent, memory_mb, disk_io_mb, network_mb, active_workers, elapsed_seconds, eta_seconds, junction_skips, unique_real_paths}` (built in `_log_progress`, 5426-5504); companion `System Resources \| CPU: … \| Memory: …MB \| Disk I/O: …MB \| Network: …MB` in performance_<run_id>.log.

### `PERF-030` Long-lived primed handle for progress metrics

*supporting* · on `xsoar`

- **Must be true** — cpu_percent reported by the progress heartbeat is non-zero from the second tick onward on an actively scanning host.
- **Threshold** — Of all Scan Progress events after the first, >= 90% have cpu_percent > 0.0; an all-zero series is the regression signature and is a hard fail.
- **Evidence** — `metrics.cpu_percent` in each Scan Progress event and the CPU value in the `System Resources \|` line of performance_<run_id>.log; source is the cached primed handle `self._progress_proc` in `_log_progress` (5440-5447).

### `PERF-031` Liveness-marker refresh from the heartbeat thread

*supporting* · on `xsoar`

- **Must be true** — running.json keeps advancing on a ~30 s cadence for the whole scan, including while the producer loop is blocked on a saturated queue.
- **Threshold** — max observed gap between consecutive `updated_at` values < 60 s and always < RUNNING_MARKER_STALE_SECS (180 s), including across every saturation window; file absent after the run completes (`_remove_running_marker`, 5822).
- **Setup** — Drive queue saturation: scan a directory tree with a very high file count so the producer outruns the 2 workers and blocks in _enqueue_scan_path.
- **Evidence** — `<scanner_dir>/control/running.json` - poll its `updated_at` field and mtime every 10 s over SSH; refresh path is `_maybe_refresh_running_marker` (5661) called from the heartbeat at 5759, rate-limited by RUNNING_MARKER_REFRESH_SECS = 30.0 (213). Correlate against `Scan queue saturated` lines in system_<run_id>.log.

### `PERF-032` ETA and rate estimation

*supporting* · on `xsoar`

- **Must be true** — When an ETA can be computed, a Time Estimates event accompanies the progress tick and its eta_seconds matches the value embedded in the Scan Progress metrics.
- **Threshold** — For every Scan Progress event whose metrics.eta_seconds is truthy there is a Time Estimates event within the same tick with identical eta_seconds; files_remaining == total_files_estimate - files_scanned where total_files_estimate = files_scanned + files_skipped + queue_size*2.
- **Evidence** — `<scanner_dir>/logs/statistics_<run_id>.log` line `Time Estimates \| ETA: H:MM:SS \| Rate: <r> files/sec \| Remaining: <n> files` with data `{eta_seconds, estimated_completion, current_rate_files_per_sec, files_remaining}` (log_time_estimates, 2150; emitted at 5505-5509 only under `if eta_seconds:`).

### `PERF-033` Scan-rate reporting in the terminal artefacts

*supporting* · on `xsoar`

- **Must be true** — All five throughput readouts are present and mutually consistent for the same run.
- **Threshold** — All five fields present and > 0; \|scan_rate_fps - average_scan_rate\| <= 0.05; scan_rate_fps == round(files_scanned / duration_secs, 2) recomputed from the same summary file.
- **Evidence** — (1) `scan_rate_files_per_sec` in each Scan Progress event; (2) `files_per_second` in the per-target completion data; (3) `average_scan_rate` in the `SCAN COMPLETED \| Time: … \| Rate: X.XX files/sec` statistics line (_log_final_results, 5517-5530); (4) `scan_rate_fps` in `<scanner_dir>/logs/scan_summary_<run_id>.json` (6777); (5) `scan_rate_files_per_second` in periodic `scan_status` events (3618).

### `PERF-034` No per-offset retention in memory (uploader)

*supporting* · on `xsoar`

- **Must be true** — Process RSS stays flat as detection volume grows - the uploader retains no per-offset accumulator.
- **Threshold** — Final memory_mb <= 2x the memory_mb of the first post-warmup tick, and <= 512 MB absolute, while total_detections grows by >= 10,000 over the same window; no monotone upward trend correlated with detection count (Pearson r < 0.5).
- **Setup** — Round 2's flood pack on xsoar, aimed at a directory guaranteed to produce >100k string offsets (e.g. a tree containing large text/log files) so the old 15 GB failure mode would be reproduced if it regressed.
- **Evidence** — `metrics.memory_mb` in successive Scan Progress events plotted against `total_detections` in the same events; corroborate on the host with `ps -o rss= -p <pid>` sampled every 15 s over SSH.

### `PERF-035` Per-finding network payload cap

*supporting* · on `xsoar`

- **Must be true** — Exactly one upload item is produced per (rule, file) finding regardless of offset count, carrying at most MAX_MATCH_SAMPLES_PER_FINDING offsets, while total_matches books every offset.
- **Threshold** — successful_uploads + failed_uploads + undelivered == number of distinct (rule, file) findings (cross-check against the block count in alert/*.txt); total_matches == sum of `Total string hits` across all alert blocks and is >> that number; len(offsets) <= 50 on every yara_match event.
- **Setup** — Plant one file that a flood rule hits thousands of times (e.g. a multi-MB text file full of the matched token) so a single finding produces >5,000 offsets. NOTE: the capability's config text is stale - the pinned source has `minimum=0` (line 164) and the consumer short-circuits on `<= 0` (3442), so 0 now means NO cap, not 'sample nothing'.
- **Evidence** — `match_delivery` in `<scanner_dir>/logs/scan_summary_<run_id>.json` (keys total_matches / successful_uploads / failed_uploads / undelivered, initialised at 3198-3201); the `Match delivery final: matches=… ok=… failed=… undelivered=…` line in uploads_<run_id>.log (3395); and the `offsets`/`strings` array length on a `type: "yara_match"` wire event for a known high-hit finding.

### `PERF-036` On-disk alert offset sampling (host disk footprint)

*supporting* · on `xsoar`

- **Must be true** — The alert text renders at most 50 offsets per finding while reporting the true total, keeping the per-finding file cost bounded independently of hit count.
- **Threshold** — k <= 50 for every block; the omitted-count line present whenever N > 50 and its number == N - k exactly; per-block byte cost <= 8 KB regardless of N; whole-run `alert_bytes_written` in scan_summary_<run_id>.json <= alert_dir_max_bytes.
- **Setup** — Same high-offset planted file as the per-finding cap criterion. Optionally re-run one target with YARA_MAX_ALERT_OFFSETS=0 over SSH to confirm the uncapped baseline is larger by orders of magnitude.
- **Evidence** — `<scanner_dir>/alert/<rule>.txt`: lines `Total string hits: <N>`, `Matched Strings (showing <k> of <N>):`, and the trailing `<N-k> further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=50). Counts above are complete; …` (written in _write_alerts, 5309-5327); file size from `ls -l`.

### `PERF-037` Matched-file copying off by default (disk write amplification)

*supporting* · on `xsoar`

- **Must be true** — By default the evidence ZIP contains no copies of matched files, only alert texts and file_mapping.txt; when enabled, copies are content-addressed and duplicate hashes are packaged once.
- **Threshold** — Default run: zero members whose name starts with `matched_files/`; `file_mapping.txt` present; one `alerts/<rule>.txt` member per triggered rule; ZIP size < 5 MB on a storm scan. Enabled run: every matched_files member name is a 64-hex-char SHA256 and member names are unique (no repeats).
- **Setup** — Default run plus one control run over SSH with YARA_COLLECT_MATCHED_FILES=1 against a directory containing two byte-identical matched copies, to prove the duplicate collapse.
- **Evidence** — `<scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` - list members with `unzip -l` over SSH; the log line `Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only (paths + SHA256 + alert texts, no matched file copies)` (4008); when on, the `Evidence ZIP: <u> unique file(s) packaged, <d> duplicate copy(ies) skipped` line (4019-4023).

### `PERF-038` Chunked hashing, matched files only

*supporting* · on `xsoar`

- **Must be true** — SHA256 is computed only for files that matched, and RSS is unaffected by matched-file size.
- **Threshold** — memory_mb does not rise by more than 64 MB across the tick that hashes a >= 1 GB matched file; every yara_match event has a non-null 64-hex file_sha256; a non-matching run over the same tree shows no equivalent read amplification in `disk_io_mb`.
- **Setup** — Plant one large (>= 1 GB) file that the flood pack matches on xsoar, and confirm a same-size non-matching file in the tree produces no hash.
- **Evidence** — `metrics.memory_mb` in Scan Progress events across the window in which a very large matched file is hashed; `_sha256_file(path, chunk_size=1024*1024)` at 933; the call site `self._calculate_match_sha256(file_path)` sits inside `if matches:` (5026-5027); `file_sha256` populated on every yara_match event.

### `PERF-039` Maximum scanned file size

*supporting* · on `xsoar`

- **Must be true** — Files larger than max_file_mb are skipped before rules.match() and are counted under the exact skip reason "File too large".
- **Threshold** — max_file_mb == 64 in the reported config; skip_reasons["File too large"] == the number of planted files > 64 MB; those paths appear in no alert file and in no yara_match event; a control run with YARA_MAX_MB=0 scans them (skip_reasons["File too large"] == 0).
- **Setup** — Plant three decoys on xsoar at 63 MB, 65 MB and 200 MB, all containing a string the ruleset matches, so the boundary is exercised in both directions. Optional control run with YARA_MAX_MB=0 over SSH.
- **Evidence** — `skip_reasons` and `files_skipped` in `<scanner_dir>/logs/scan_summary_<run_id>.json`; `max_file_mb` in the initialization event data and the scan-configuration statistics event; source guard `if max_bytes and st.st_size > max_bytes: return False, "File too large"` at 5005-5007 with `self.max_file_mb = _env_number("YARA_MAX_MB", 64, cast=int, minimum=0)` at 2820.

### `PERF-040` Bounded in-memory metric histories

*supporting* · on `xsoar`

- **Must be true** — Rolling metric stores never exceed their fixed capacities, so a long scan cannot grow monitoring memory.
- **Threshold** — data_points_collected <= 360 always; monitoring_duration_seconds == data_points_collected * 10 and saturates at 3600 on any scan longer than 60 min; alerts_triggered <= 100; process RSS does not grow with monitoring duration.
- **Setup** — Resource monitoring enabled (see the SystemResourceMonitor criterion) and a scan run long enough to be informative - ideally > 60 min so the 360-entry saturation is actually observed rather than assumed.
- **Evidence** — `data_points_collected` and `monitoring_duration_seconds` inside the `resource_monitoring_summary` event (get_resource_summary, 2565-2566), backed by `resource_history = deque(maxlen=360)` (2296), `alert_history = deque(maxlen=100)` (2297), `performance_history = deque(maxlen=1000)` (1526); plus `alerts_triggered` (2579).

### `PERF-041` Opportunistic upload batching (network cost control)

*supporting* · on `xsoar`

- **Must be true** — Under storm load events are shipped in large NDJSON batches approaching the 500-event cap, while a quiet scan sends immediately with no linger delay.
- **Threshold** — Storm run: mean events-per-request >= 100 and no request exceeds 500 events or 4 MiB; sum of per-batch n == successful_uploads exactly. Quiet control run (3 matches): 1 request carrying <= 3 events, sent within 2 s of the match (no linger).
- **Setup** — Two runs on xsoar: the flood pack, then a control run with a single narrow rule matching ~3 planted files.
- **Evidence** — `<scanner_dir>/logs/uploads_<run_id>.log` - count `YARA match batch uploaded: <n> event(s) (HTTP <code>)` lines (3307) and sum their n; compare against `match_delivery.successful_uploads` in scan_summary_<run_id>.json; batching is `_collect_batch(queue_obj, first_item, max_events, max_bytes)` at 757 with UPLOAD_BATCH_MAX_EVENTS = 500 (279/283).

### `PERF-042` Backlog-proportional shutdown drain budget

*supporting* · on `xsoar`

- **Must be true** — Each drain site announces a wait budget equal to min(60, max(15, pending*0.3)) seconds and nothing left queued past it is reported as delivered.
- **Threshold** — For every such line, T == min(60, max(15, N*0.3)) within 0.5 s; wall time actually spent at each site <= T + 5 s; `undelivered` in the summary equals the leftover queue depth reported at the drain, and undelivered is never silently folded into successful_uploads.
- **Setup** — Storm scan sized so a real backlog exists at shutdown (>= 200 queued items at drain time). Do not inject network failure on the live tenant - use natural backlog only.
- **Evidence** — uploads_<run_id>.log lines `Waiting for <N> pending match uploads (max <T>s)...` (3358), `Waiting for <N> pending standardized log uploads (max <T>s)...` (2250) and `Waiting for <N> pending uploads (max <T>s)...` (3515); plus `match_delivery.undelivered` in scan_summary_<run_id>.json (incremented at 3391) and the `Match delivery final: …` line (3395).

### `PERF-043` Per-run log/summary retention on the endpoint

*supporting* · on `xsoar`

- **Must be true** — After many runs, logs/ holds artefacts for at most LOG_KEEP_SCANS run_ids plus the current one, and alert/ and evidence/ are wiped at the start of each run.
- **Threshold** — distinct run_ids in logs/ <= LOG_KEEP_SCANS + 1 (default 10 + 1 = 11); zero orphaned `.json.tmp` files; the current run_id is always present; alert/ contains only the current run's rule files (no rule name from a previous run survives).
- **Setup** — Round 3 runs last, after rounds 1 and 2 have already produced many run_ids on xsoar. If fewer than 12 runs exist, run with YARA_LOG_KEEP=2 over SSH to force pruning. NOTE: the capability's config text is stale - `keep_scans=2` is now `LOG_KEEP_SCANS = _env_number("YARA_LOG_KEEP", 10, cast=int, minimum=0)` at line 356 and IS env-configurable.
- **Evidence** — `ls /opt/yara_scanner/logs` - count distinct run_ids across `alerts_/statistics_/scan_errors_/performance_/uploads_/system_/yara_processing_/diagnostics_/script_exceptions_*.log` and `scan_summary_*.json`; `.json.tmp` orphans; the retention line `Log retention applied: kept last <k> scans (<n> run IDs including current), removed <m> log files` in diagnostics_<run_id>.log (4110-4113); initial_cleanup's rmtree of alert_dir and evidence_dir (4117-4145).

### `PERF-044` Uploader/log threads are all daemon threads with bounded joins

*supporting* · on `xsoar`

- **Must be true** — Every background thread is joined within its timeout and no thread keeps the payload process alive after the shutdown sequence.
- **Threshold** — Zero occurrences of any 'did not terminate' / 'did not stop' warning; `m` (timed out) == 0 in the Worker cleanup line; process gone within 5 s of the last terminal event.
- **Evidence** — uploads_<run_id>.log warnings `Upload thread did not terminate within 60s timeout` (3372), `Upload thread did not stop within 60s timeout` (3538), `WARNING: Webhook thread did not terminate within 60s` (3894); the `Worker cleanup: <k> stopped, <m> timed out in <t>s` performance line; `Threads did not terminate: [...]` error line; and process exit observed with `ps -p <pid>` over SSH after the terminal event lands.

### `PERF-046` macOS disk-I/O telemetry is structurally zero

*supporting* · on `OfficeiMac`

- **Must be true** — Every disk-I/O figure the scanner reports is exactly 0 on macOS while the same fields are non-zero for an equivalent Linux scan, and the surrounding CPU/memory/network fields still report correctly on macOS.
- **Threshold** — OfficeiMac: 100% of System Resources lines and Scan Progress metrics report disk_io_mb == 0.0 while memory_mb > 0 and network_mb > 0. xsoar, same scan: disk_io_mb > 0 on >= 90% of ticks. Any dashboard/alert rule of the form 'disk_io rises with bytes scanned' must be documented as macOS-invalid.
- **Setup** — Run the identical rule pack and target scope on both OfficeiMac and xsoar in round 3; this path is ungated (heartbeat-driven) so no flags are needed. Do NOT scan Abdelrahman's MacBook Air.
- **Evidence** — A/B on the same ruleset: OfficeiMac vs xsoar. `<scanner_dir>/logs/performance_<run_id>.log` line `System Resources \| CPU: … \| Memory: …MB \| Disk I/O: 0.0MB \| Network: …MB` and the matching `type: "performance"` wire event field `data.disk_io_mb`; also `metrics.disk_io_mb` in Scan Progress. Source: the swallowed `except (AttributeError, NotImplementedError, psutil.AccessDenied): pass` around `process.io_counters()` at 5450-5456, leaving the pre-set `disk_io_mb = 0`.

### `PERF-047` monitoring_duration_minutes reports host uptime, not scan duration

*supporting* · on `xsoar`

- **Must be true** — system_resource_snapshot.monitoring_duration_minutes tracks host uptime, not scan or monitor duration, and disagrees with its sibling resource_monitoring_summary.monitoring_duration_seconds by roughly the host's uptime.
- **Threshold** — \|monitoring_duration_minutes*60 - host_uptime_secs\| <= 60; monitoring_duration_minutes*60 >> scan_duration_secs on a host up longer than the scan; monitoring_duration_seconds == data_points_collected * 10 and saturates at 3600. Either the field is renamed/fixed, or this mismatch is documented as a known trap - a snapshot whose minutes value equals scan wall time would mean the derivation changed.
- **Setup** — Resource monitoring enabled on xsoar; capture `cat /proc/uptime` over SSH at scan start to pin the expected value.
- **Evidence** — Two events from the same scan_id: `type: "system_resource_snapshot"` -> `data.monitoring_duration_minutes` (computed at 2487 from `psutil.boot_time()` captured at 2304) and `type: "resource_monitoring_summary"` -> `data.monitoring_duration_seconds` (2565). Ground truth: `uptime -s` / `cat /proc/uptime` on xsoar over SSH at the moment of the snapshot.

### `PERF-048` Light-profile priority tuning: outer failure emits a message with no data payload

*supporting* · on `xsoar`

- **Must be true** — The scanner renices itself at startup and reports exactly one of the two tuning outcomes, with the success message carrying a details dict and the process's real OS priority matching it.
- **Threshold** — Exactly 1 of the two lines present. On xsoar: details.cpu_priority == "nice=10", details.io_priority == "best_effort:7", `ps -o ni=` reports 10 and `ionice -p` reports 'best-effort: prio 7'; no cpu_priority_error / io_priority_error keys. On thor: details.cpu_priority == "below_normal" and Task Manager / Get-Process shows BelowNormal.
- **Setup** — None for the success path. The outer-failure branch (psutil.Process() raising) is deliberately NOT exercised - it cannot be injected safely on a live tenant; record it as a known unqueryable shape (no structured field exists to filter on, so wire-side detection must match the message text).
- **Evidence** — `<scanner_dir>/logs/system_<run_id>.log`, effectively the second line: success `Applied light profile process priority tuning` with `details` containing `cpu_priority` (and on Linux `io_priority`) - emitted at 991; outer failure `Could not apply light profile process priority tuning: <err>` with NO data key at all (994). Independently on the host: `ps -o ni= -p <pid>` and `ionice -p <pid>` over SSH during the scan.

## Lifecycle (6)

### `LIFE-005` Running marker (control/running.json) and liveness reporting

*supporting* · on `xsoar`

- **Must be true** — running.json is written with status 'compiling' before rule compilation, flips to 'running' when the watcher starts, carries the full payload, and is removed at the end of a normal run so cancel() reports no scan running.
- **Threshold** — A 0.5s poll from launch observes at least one sample with status=='compiling' followed by samples with status=='running'; every sample parses and contains all of {scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections}; file absent within 5s of a normal run's exit and cancel() then reports 'scanner running: no'.
- **Setup** — Launch with a deliberately large rule pack (>2000 rules) to widen the compile window; poll control/running.json every 0.5s over a second SSH session from launch to exit.
- **Evidence** — /opt/yara_scanner/control/running.json (written 4337 with 'compiling', 5608 with 'running', removed via _remove_running_marker at 5824); cancel()'s result line.

### `LIFE-006` Running-marker refresh from two independent sites

*supporting* · on `xsoar`

- **Must be true** — The timed progress-heartbeat keeps running.json fresh even while the discovery loop is blocked on a saturated scan queue, so a live long scan is never reported as dead.
- **Threshold** — Max gap between consecutive distinct updated_at values <= 30 + config.log_interval + 5s and always < RUNNING_MARKER_STALE_SECS (180); a cancel() status probe issued at any point during the run reports 'scanner running: yes'.
- **Setup** — Long scan on 8-core xsoar under competing load with YARA_QUEUE_SIZE=2 and YARA_THREADS=1 so _enqueue_scan_path blocks the producer; sample running.json every 5s for the whole run.
- **Evidence** — updated_at in /opt/yara_scanner/control/running.json sampled over the run (refresh gated by RUNNING_MARKER_REFRESH_SECS=30.0 at 5664, called from _progress_heartbeat at ~5758 and from the discovery loop at 5951); cancel()'s 'scanner running:' verdict.

### `LIFE-048` File-descriptor limit preflight and FD monitoring

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — On POSIX with FD monitoring enabled the scanner reads the ulimit at startup, warns and emits resource_limit_warning below 8192, records a baseline, and samples FD growth during the scan.
- **Threshold** — With `ulimit -n 4096` in the launching shell: 'Current file descriptor limit: 4096' present, exactly 1 resource_limit_warning event with data.recommended_limit == 65536, and >=1 'FD usage increased by' line for a scan of >5000 files. With `ulimit -n 65536`: 0 resource_limit_warning events. On thor (Windows): 0 of these lines and 0 resource_limit_warning events.
- **Setup** — Round-1 long scan on xsoar launched twice from a shell with `ulimit -n 4096` and then 65536, YARA_ENABLE_FD_MONITOR=true; one control run on thor to prove the Windows suppression.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log lines 'Current file descriptor limit: N', 'Initial file descriptors in use: N' (PINNED_xsiam_current.py:6294, :6327), 'FD usage increased by N (current: M)' (:5076) and 'WARNING: High FD usage: N'; collector event type='resource_limit_warning' with data {current_limit, recommended_limit, impact} (:6302).

### `LIFE-049` Light-profile process priority tuning at startup

*supporting* · on `thor`

- **Must be true** — The scanner de-prioritises itself at startup — nice >= 10 on POSIX (plus ionice best-effort/7 on Linux), BELOW_NORMAL on Windows — and records what it applied.
- **Threshold** — On xsoar: ps reports ni >= 10 for the scanner process and every worker thread's parent, `ionice -p` reports 'best-effort: prio 7'; the log data has no *_error key. On thor: PriorityClass == BelowNormal. Sample >=3 times across the run to prove it is not reset mid-scan.
- **Setup** — Round-1 long scan on xsoar with a competing CPU load (stress-ng --cpu 8 or 8x `yes > /dev/null`); poll ps/ionice every 30s for the run duration.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log 'Applied light profile process priority tuning' with data {'cpu_priority':'nice=10'\|'below_normal','io_priority':'best_effort:7'} or the *_error keys (PINNED_xsiam_current.py:962-991, called at :6207); out-of-band `ps -o pid,ni,comm -p <pid>` and `ionice -p <pid>` on xsoar, Task Manager / Get-Process priority on thor.

### `LIFE-050` Progress heartbeat spanning the whole scan

***core*** · on `xsoar`

- **Must be true** — A progress sample is emitted every log_interval for the entire scan including the post-discovery drain, with no gap longer than 2x the interval and none missing while workers are still draining.
- **Threshold** — count(progress entries) >= floor(duration_secs / log_interval) - 1; max inter-entry gap <= 2 x log_interval; the last progress entry's timestamp is within log_interval + 5s of the 'SCAN COMPLETED' line (proving it covered the drain, not just discovery); zero 'Progress heartbeat error' lines; on OfficeiMac disk_io_mb == 0 while cpu_percent and memory_mb are non-zero.
- **Setup** — Round-1 long scan on xsoar with YARA_PROGRESS_LOG_SECS=10 and a deep target that makes discovery finish well before the queue drains (e.g. a directory of 50k small files); repeat once on OfficeiMac to check the macOS io_counters guard.
- **Evidence** — Recurring 'Scan Progress' entries in <scanner_dir>/logs/statistics_<run_id>.log and performance_<run_id>.log and the matching collector events carrying files_scanned, files_skipped, detections, queue size, scan rate, cpu_percent, memory_mb, active_workers, elapsed_seconds, eta_seconds, junction_skips, unique_real_paths (_progress_heartbeat at PINNED_xsiam_current.py:5735-5744, thread start :5906-5910, stop+join(2) :5815-5818); failure line 'Progress heartbeat error: ...'.

### `LIFE-051` Producer backpressure instead of dropping files

***core*** · on `xsoar`

- **Must be true** — When the scan queue fills, the producer blocks and retries rather than dropping files, so discovered-file count equals scanned+skipped even under sustained saturation.
- **Threshold** — With YARA_QUEUE_SIZE=2 and YARA_THREADS=1 on a 50k-file target: >=1 'Scan queue saturated' line appears, zero 'Failed to enqueue file for scanning' lines, and files_scanned + files_skipped == the independent find census exactly (delta 0 — no dropped files).
- **Setup** — Round-1 run on xsoar with YARA_QUEUE_SIZE=2 YARA_THREADS=1 YARA_QUEUE_BACKOFF_SECS=0.05, scan_folder pointed at a pre-built 50,000-file directory whose exact count is captured with `find <dir> -type f \| wc -l` immediately before and after (nothing else writing there).
- **Evidence** — <scanner_dir>/logs/performance_<run_id>.log 'Scan queue saturated (N items) - backing off producer' emitted on every 25th queue-full event (PINNED_xsiam_current.py:4931-4934); scan_errors_<run_id>.log 'Failed to enqueue file for scanning: ...' with file_path (:4939); files_scanned + files_skipped in scan_summary_<run_id>.json versus an independent `find \| wc -l` census of the target.

---

# Round 2 — False-positive flood

**Endpoints:** `xsoar`, `thor`  
**On failure:** collect-through  
**Capabilities:** 107 (7 core)

**Scenario.** A ruleset that matches nearly every file, over a large seeded tree, on Linux and Windows. Drives caps, aggregation, batching, retry, the alert-footprint ceiling, and the delivery balance sheets to their limits.

**Why these belong together.** Caps and accounting are invisible until something overflows them. Only a flood fills a batch, trips a per-finding cap, or makes totals disagree.

## Traversal (2)

### `TRAV-038` Bulk attribution of a skipped directory's files

*supporting* · on `xsoar`

- **Must be true** — Every file inside an excluded walk root is counted exactly once under skip_reasons['Skipped directory'], so files_scanned + files_skipped reconciles with what is on disk and skip_rate is non-zero.
- **Threshold** — skip_rate > 0; skip_breakdown['Skipped directory'] equals the count from an independent `find` over the excluded roots (/proc,/sys,/dev,/run,/opt/yara_scanner,... on xsoar) within 2%; no double-count (value must not exceed that find count).
- **Setup** — Whole-filesystem default scan on xsoar; independently run `find /proc /sys /dev /run /opt/yara_scanner -type f \| wc -l` at the same time for the reconciliation baseline.
- **Evidence** — skip_breakdown['Skipped directory'] in the 'Skip reasons' statistics record and in comprehensive_final_report.file_processing.skip_breakdown (6094); skip_rate in the final metrics dict (5519); files_scanned / files_skipped in scan_summary_<run_id>.json (6771-6772). Code: scan_system 5951-5964 (files_skipped += len(files); skip_reasons['Skipped directory'] += len(files); no dirs pruning).

### `TRAV-039` Skip accounting and breakdown reporting

***core*** · on `xsoar`

- **Must be true** — Every skipped file lands in exactly one labelled skip_reasons bucket, the sum of buckets equals files_skipped, and the breakdown is emitted both periodically and at the end.
- **Threshold** — sum(skip_breakdown.values()) == total_skipped == scan_summary.files_skipped, exactly; at least floor(duration/YARA_PROGRESS_LOG_SECS) - 1 Scan Progress records exist.
- **Evidence** — 'Scan Progress \| Files: N scanned, M skipped \| ...' statistics records in statistics_<run_id>.log (log_scan_progress 2090-2110); final 'Skip reasons: ...' record with data {'total_skipped','skip_breakdown'} (5556-5557); file_processing.skip_breakdown in the comprehensive_final_report webhook event (6094); files_skipped in scan_summary_<run_id>.json (6772).

## Storage (33)

### `STOR-002` Four fixed subdirectories: logs/, alert/, evidence/, failed_rules/

*supporting* · on `xsoar`

- **Must be true** — All four subdirectories exist under scanner_dir after any run, including a run that produced no match and no rule failure.
- **Threshold** — All four present on both hosts. On a clean no-match run: alert/ and evidence/ empty (0 entries), failed_rules/ empty, logs/ non-empty. Directory creation must not depend on a match.
- **Setup** — Include one deliberately clean run (a rule that matches nothing) on each host so the 'created even when empty' half is actually tested.
- **Evidence** — `ls /opt/yara_scanner` (xsoar) and `ls /usr/local/yara_scanner` (OfficeiMac): must list `logs alert evidence failed_rules` (plus control); created by ScanConfig.__init__ at 2763-2765 (`for directory in [self.alert_dir, self.evidence_dir, self.failed_rules_dir]: os.makedirs(..., exist_ok=True)`).

### `STOR-004` Six per-category run logs in logs/

*supporting* · on `xsoar`

- **Must be true** — Each run produces exactly one run_id-stamped file per LogType category, and the wider *_<run_id>.log glob resolves to the documented larger set rather than six.
- **Threshold** — Exactly 8 files match on a clean run (6 categories + yara_processing_ + diagnostics_), 9 when script_exceptions_ exists; each of the six category names appears exactly once; `log_files_created` in the final statistics event (2180) lists exactly the six category paths and they all exist on disk.
- **Evidence** — `ls /opt/yara_scanner/logs/*_<run_id>.log` - the six LogManager categories `alerts_`, `statistics_`, `scan_errors_`, `performance_`, `uploads_`, `system_` (LogManager.log_files, 1843-1850) plus `yara_processing_` (ErrorLogger, 1248) and `diagnostics_` (setup_logging, 6055-6057), and `script_exceptions_` only when an exception was logged.

### `STOR-005` YARA-processing audit log (rule compilation trail)

*supporting* · on `xsoar`

- **Must be true** — The compilation summary block is written with counts that reconcile against the scan summary, and the failed_rules_dir pointer appears exactly when rules failed.
- **Threshold** — Total rules processed == valid + failed exactly; the summary's `valid_rules`/`failed_rules` equal the log's counts; `Failed rules saved to:` present iff failed > 0, and failed_rules/ then contains that many .yar files; `skipped_rules` (module-unavailable) is reported separately and is NOT folded into failed_rules.
- **Setup** — Round 3 pack must include (a) one syntactically broken rule and (b) one rule importing a module xsoar's yara 3.11.0 cannot provide (e.g. `import "dotnet"`), so the failed vs skipped classification split is actually exercised on both xsoar and OfficeiMac (yara 4.1.0) - the two hosts should classify differently.
- **Evidence** — `grep -A6 'COMPILATION SUMMARY' /opt/yara_scanner/logs/yara_processing_<run_id>.log` - `Total rules processed:`, `Valid rules compiled:`, `Failed rules skipped:`, `Success rate:` and conditionally `Failed rules saved to: <failed_rules_dir>` (log_compilation_summary, 1413-1431); cross-check `valid_rules`, `failed_rules`, `skipped_rules` in scan_summary_<run_id>.json (6773-6776).

### `STOR-006` Lazy script-exception log (no zero-byte file on clean runs)

*supporting* · on `xsoar`

- **Must be true** — script_exceptions_<run_id>.log is absent entirely on a run that logged no exception, and carries the init banner as its first content when it does exist.
- **Threshold** — Clean run: file does not exist (not present-and-zero-bytes). Run that logged an exception: file exists, first line is the banner, and its `=== EXCEPTION #N ===` count matches ExceptionLogger.exception_count.
- **Setup** — The whole-filesystem round-3 scan on xsoar is likely to hit at least one exception path naturally (unreadable /proc entries, vanished files); pair it with a narrow clean run to get the negative case. Do not inject a crash.
- **Evidence** — `ls /opt/yara_scanner/logs/script_exceptions_*.log`; the handler is built only inside `_ensure_logger` (1449) on the first `log_exception` call, writing `=== SCRIPT EXCEPTION LOG INITIALIZED ===`, Python version, platform, then `[timestamp] [EXCEPTION] ...` entries.

### `STOR-007` Per-run log files, truncating, no rotation and no size cap

*supporting* · on `xsoar`

- **Must be true** — Every log handler opens mode="w" against a run_id-stamped path, so no file is ever appended across runs, reopened, or rolled.
- **Threshold** — Run B creates a complete fresh set of *_<run_id_B>.log files; no file from run A changes mtime or size during run B; zero files matching `*.log.[0-9]*`; each per-run file's first line is the category's init banner (proving truncation, not append).
- **Evidence** — Two consecutive runs on xsoar: `ls -l --time-style=full-iso /opt/yara_scanner/logs/` before and after. All handlers are `logging.FileHandler(..., mode="w")` - LogManager._setup_logger, ErrorLogger._setup_error_logger (1261-1266), ExceptionLogger._ensure_logger (1460-1465). Absence of any `.1`/`.log.N` rotation suffix.

### `STOR-008` Reserved scanner_<run_id>.log path, self-excluded from scanning

*supporting* · on `xsoar`

- **Must be true** — scanner_<run_id>.log is never created by this edition, and a scan pointed at logs/ never counts that path in files_scanned.
- **Threshold** — Zero scanner_*.log files after any run; a scan explicitly targeting the logs directory records skip_reasons["Special system file"] >= 1 and never lists that path in any alert file or yara_match event.
- **Setup** — One extra round-3 run on xsoar with scan_folder pointed at /opt/yara_scanner/logs, and a planted scanner_<fake_run_id>.log there is NOT sufficient - the guard compares against the CURRENT run_id, so create the file at exactly `scanner_<current run_id>.log` is impossible pre-run; instead assert the zero-files half plus the Special-system-file skip accounting.
- **Evidence** — `ls /opt/yara_scanner/logs/scanner_*.log` (must be empty); `self.output_log = os.path.join(self.logs_dir, f"scanner_{self.run_id}.log")` at 2815; the exclusion `if normalized_path == scanner_log_path: return True` in `_is_special_file` (5116-5129, case-folded on Windows only); initial_cleanup lists output_log in paths_to_clean (4125) and recreates its parent (4143).

### `STOR-009` Per-rule alert text file (alert/<rule>.txt)

*supporting* · on `xsoar`

- **Must be true** — Exactly one alert text file exists per triggered rule, accumulating one well-formed block per matched file, with no interleaving corruption under two concurrent workers.
- **Threshold** — file count in alert/ == `unique_rules_triggered` in scan_summary_<run_id>.json; sum of block headers across all files == `matches` (total_detections) in the same summary; every block header is followed by a `File SHA256:` line with 64 hex chars; zero `Failed to write alert file` lines; no block header appears mid-line (lock held).
- **Setup** — The round-2 flood pack on both xsoar and thor, with >= 5 distinct rules firing so the per-rule file split is meaningful.
- **Evidence** — `ls /opt/yara_scanner/alert/` and `grep -c "^YARA rule '" alert/<rule>.txt`; block header `YARA rule '<rule>' matched file: <path>` followed by `File SHA256:` / `File Creation Time:` and an 80-char `=` separator (_write_alerts, 5288-5294, serialised under self.lock_alert); I/O failures surface as `Failed to write alert file: <err>` in scan_errors_<run_id>.log.

### `STOR-010` Uncapped per-string-ID census in the alert text

*supporting* · on `xsoar`

- **Must be true** — For every finding written below the alert byte ceiling, the full per-string-ID histogram is rendered and its values sum exactly to the reported total hit count, even when the offsets below are truncated.
- **Threshold** — For every block: sum(values in `Hits per string ID`) == N in `Total string hits`, and N == the `of <N>` figure in the `Matched Strings (showing k of N)` line; the census is present for 100% of blocks with strings that were NOT suppressed by the byte ceiling. NOTE the over-budget branch (5330-5340) writes `Total string hits` WITHOUT the per-ID census - those blocks must be excluded and must be exactly `alert_detail_suppressed` in number.
- **Setup** — Use a multi-string rule ($a/$b/$c) in the flood pack so the histogram has more than one key, plus one rule with an anonymous string to exercise the `$?` key.
- **Evidence** — In `alert/<rule>.txt`: `Total string hits: <N>` and `Hits per string ID: $a=12, $b=3, …` (sorted; a nameless match renders `$?`) - written before any offset at 5301-5308. Reconcile against `match_id_counts` on the corresponding `type: "yara_match"` wire event.

### `STOR-011` Offset cap in the alert text (MAX_ALERT_OFFSETS_PER_FINDING)

*supporting* · on `xsoar`

- **Must be true** — At most 50 offset triples are rendered per finding, the ratio is always stated, and the truncation note names the exact remaining count and the env knob.
- **Threshold** — k == min(50, N) for every block; count of `Offset:` lines in the block == k; the omitted line present iff N > 50 with its number == N - k exactly; a control run with YARA_MAX_ALERT_OFFSETS=0 renders all N (k == N) and produces a measurably larger file.
- **Setup** — High-offset planted file (>= 5,000 hits in one file for one rule) plus one control run over SSH with YARA_MAX_ALERT_OFFSETS=0 on a small target, to confirm 0 means 'no cap' and negative falls back to 50 (minimum=0 at line 341, no max(0,...) wrapper in the pinned source - the capability's config text is stale on that point).
- **Evidence** — In `alert/<rule>.txt`: `Matched Strings (showing <k> of <N>):`, the `String ID:` / `Offset:` / `Data:` triples, and `<N-k> further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=50). Counts above are complete; re-run \`yara -s\` against this file for every offset.` (5313-5327; `cap = MAX_ALERT_OFFSETS_PER_FINDING; shown = strings if cap <= 0 else strings[:cap]`).

### `STOR-012` Condition-only match detail in the alert text

*supporting* · on `xsoar`

- **Must be true** — A rule that fires on its condition alone writes a generated explanation block instead of an empty block, and the same text rides the uploaded finding.
- **Threshold** — For the planted condition-only rule: the alert block contains `Condition Match Details:` and a non-empty body, contains no `Matched Strings` line; the wire event message starts with `YARA rule-only match:` and its detail string is byte-identical to the alert body; match_count on that event == 1.
- **Setup** — Plant a condition-only rule in the round-2 pack, e.g. `rule CondOnly { condition: filesize > 10 }` (no strings section), so the branch actually fires on xsoar and thor.
- **Evidence** — In `alert/<rule>.txt`: `Condition Match Details:` between two 40-dash rules (the `elif condition_only_detail:` branch at 5341-5345, text from `_summarize_condition_only_match`, 576). On the wire: the `type: "yara_match"` event's message reads `YARA rule-only match: rule '<rule>' in <file>` and its detail field carries the identical text (passed as fallback_detail at 5277, consumed at 3415-3418).

### `STOR-013` Matched-bytes rendering (UTF-16 LE / UTF-8 / hex fallback)

*supporting* · on `xsoar`

- **Must be true** — Matched bytes are decoded for human reading - wide matches render as clean text with no embedded NULs, ASCII renders as text, binary renders as an even-length hex string.
- **Threshold** — Zero NUL bytes anywhere in any alert/*.txt; the wide-string decoy's Data line equals the plain token exactly; the binary decoy's Data line matches ^[0-9a-f]+$ with even length; the ASCII decoy's Data line equals the token. Same three assertions must hold for the same file rendered on thor.
- **Setup** — Plant three decoys per host and matching rules: (a) a file containing the token as UTF-16 LE with a `wide` rule string, (b) a plain ASCII token, (c) a non-printable byte sequence. thor is the host that matters most here - open the file in Notepad to confirm no null artefacts.
- **Evidence** — `Data:` lines in `alert/<rule>.txt` (rendered by `_render_match_data`, 1017-1040: UTF-16 LE when every odd byte is NUL and the decode is printable, else UTF-8 if printable, else `data.hex()`). Verify on the host with `grep -c $'\\x00' alert/<rule>.txt`.

### `STOR-014` evidence/file_mapping.txt (path -> SHA256 manifest)

*supporting* · on `xsoar`

- **Must be true** — file_mapping.txt contains a host header followed by exactly one `<path> \| <sha256>` line for every distinct matched file path that still exists on disk, with no duplicate path lines.
- **Threshold** — data-line count == count(distinct matched paths still present on disk); every hash is 64 lowercase hex and equals `sha256sum` of that path for a 20-path random sample; 0 duplicate path lines
- **Setup** — None beyond the flood itself — the FP pack must match thousands of distinct paths on both hosts.
- **Evidence** — /opt/yara_scanner/evidence/file_mapping.txt on xsoar and C:\yara_scanner\evidence\file_mapping.txt on thor — header lines `Hostname:`, `OS:`, `IP Addresses:`, then the column header `Original Path \| SHA256 Hash`; cross-checked against the distinct data.file_name values on type="yara_match" rows for the run's scan_id.

### `STOR-015` Evidence ZIP (evidence_<hostname>_<run_id>.zip)

*supporting* · on `xsoar`

- **Must be true** — Exactly one evidence_<hostname>_<run_id>.zip is written per run and it opens cleanly, containing file_mapping.txt at the archive root plus one alerts/<rule>.txt member per rule that produced an alert file.
- **Threshold** — exactly 1 ZIP in evidence/ carrying this run's run_id; zipfile.testzip() returns None; member count == 1 + count(alert/*.txt); alerts/ member count == scan_summary_<run_id>.json .unique_rules_triggered; ZIP size < 50 MB with the copy toggle off
- **Evidence** — `unzip -l /opt/yara_scanner/evidence/evidence_*_<run_id>.zip`; system_<run_id>.log line `Evidence collection completed successfully` (main() success path, ~line 6538).

### `STOR-016` Matched-file copy toggle (COLLECT_MATCHED_FILES)

*supporting* · on `xsoar`

- **Must be true** — With COLLECT_MATCHED_FILES off (the default) the evidence ZIP carries zero matched_files/ members and the metadata-only decision is recorded once in the system log.
- **Threshold** — 0 members under matched_files/; the quoted line appears exactly once; total bytes in evidence/ < 1% of the summed size of the matched files listed in file_mapping.txt
- **Setup** — Leave YARA_COLLECT_MATCHED_FILES unset on the primary flood runs on both xsoar and thor.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log exact line `Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only (paths + SHA256 + alert texts, no matched file copies)` with structured field collect_matched_files=false (emitted at 4006-4010 via EvidenceCollector._log); plus `unzip -l` member list.

### `STOR-017` Content-addressed dedupe of packaged matched files

*supporting* · on `xsoar`

- **Must be true** — With copying on, N paths holding identical bytes collapse to exactly one matched_files/<sha256> member and the skipped copies are accounted for, so every packaged arcname is unique.
- **Threshold** — U + D == data-line count of file_mapping.txt; every matched_files/ arcname is bare 64-hex with 0 repeats; U == count(distinct hashes in file_mapping.txt); with 5 byte-identical planted copies, D >= 4
- **Setup** — Extra xsoar run with YARA_COLLECT_MATCHED_FILES=true over a small planted tree (~200 files) containing 5 byte-identical copies of one matching file under different names.
- **Evidence** — system_<run_id>.log line `Evidence ZIP: <U> unique file(s) packaged, <D> duplicate copy(ies) skipped` with fields unique_files_packaged / duplicate_copies_skipped (4019-4024); the matched_files/ arcname list from `unzip -l`; `Error adding file to zip <path>: <e>` in diagnostics_<run_id>.log for write failures.

### `STOR-018` scan_summary_<run_id>.json — machine-readable per-run summary

*supporting* · on `xsoar`

- **Must be true** — Every run writes exactly one scan_summary_<run_id>.json carrying the 9-field identity header plus a run body whose outcome is exactly one of completed/cancelled/failed and matches what actually happened.
- **Threshold** — file present for all round-3 runs (xsoar whole-fs, OfficeiMac, cancelled run); outcome == "cancelled" on the cancelled run and "completed" on the clean ones; all listed keys present, none null except failure_reasons which may be []; match_delivery/telemetry_delivery are non-empty objects (written after uploader drain)
- **Evidence** — <scanner_dir>/logs/scan_summary_<run_id>.json — keys schema, edition, run_id, scan_id, rule_hash, hostname, os_info, ip_address, scanner_version, outcome, failure_reasons, scan_folder, scan_targets, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, match_delivery, telemetry_delivery (written at 6764-6790); system_<run_id>.log line `Scan summary written: scan_summary_<run_id>.json`.

### `STOR-019` Atomic summary write with temp cleanup

*supporting* · on `xsoar`

- **Must be true** — The summary appears atomically — no scan_summary_<run_id>.json.tmp survives any run and no reader ever sees a partially-written JSON.
- **Threshold** — 0 surviving .json.tmp files after each of the 3 runs including the cancelled one; 0 poll samples where the .json exists but fails json.load
- **Setup** — Poll <scanner_dir>/logs/ at 1 Hz from scan start through process exit on the cancelled run (the round already cancels mid-walk).
- **Evidence** — `ls <scanner_dir>/logs/*.json.tmp`; a 1 Hz SSH poll of logs/ attempting json.load on scan_summary_<run_id>.json through shutdown; scan_errors_<run_id>.log line `Failed to write scan summary JSON: <err>` (2236).

### `STOR-020` Log/summary retention across runs (keep last 2 scans)

*supporting* · on `xsoar`

- **Must be true** — After three successive runs logs/ retains artefacts for at most the current run plus 2 prior run_ids, and .json / .json.tmp files are pruned on the same pass as .log files.
- **Threshold** — distinct run_ids present in logs/ <= 3 after run 3; no scan_summary_*.json remains for the oldest run_id; M > 0 on run 3; the quoted retention line present once per run
- **Setup** — Run the scanner at least three times on xsoar within the round (whole-fs, cancelled, short re-run).
- **Evidence** — distinct run_ids parsed out of <scanner_dir>/logs/ filenames with `_(\d{8}_\d{6}_\d{6})\.(?:log\|json\|json\.tmp)$`; root-logger line `Log retention applied: kept last 2 scans (<N> run IDs including current), removed <M> log files` in diagnostics_<run_id>.log, plus `Cannot remove log file (in use): <path>` / `Log retention: <F> log files could not be removed` on failures.

### `STOR-021` Initial cleanup at scan start (alert/ and evidence/ wiped)

*supporting* · on `xsoar`

- **Must be true** — At scan start the previous run's alert/ and evidence/ contents are deleted outright and re-created empty, so only ONE run's alert texts and evidence ZIP ever exist on the host.
- **Threshold** — exactly 1 ZIP in evidence/ after run 2 and its name carries run 2's run_id; run 1's ZIP path no longer exists; 0 files in alert/ named for rules only present in run 1's pack; both `Removed:` lines for alert_dir and evidence_dir appear
- **Setup** — Two back-to-back FP flood runs on xsoar with different rule packs (different rule names) so run-1 residue would be visibly identifiable.
- **Evidence** — `ls <scanner_dir>/alert <scanner_dir>/evidence` after run 2; diagnostics_<run_id>.log lines `Starting initial cleanup of old data...`, one `Removed: <path>` per entry, then `Initial cleanup completed successfully` (or `Some cleanup operations failed - continuing with scan`).

### `STOR-022` failed_rules/ artefacts are never retention-managed

*supporting* · on `xsoar`

- **Must be true** — failed_rules/ accumulates one .yar per failed or module-skipped rule, grows monotonically across runs (it is absent from paths_to_clean and from the retention regex), and its file counts reconcile with the summary's failed_rules/skipped_rules.
- **Threshold** — count(failed_rule_*.yar) == scan_summary.failed_rules when failed_rules <= 10, and count(skipped_rule_*_<module>.yar) == scan_summary.skipped_rules; file count after run N+1 >= file count after run N for all runs (strictly monotonic, never pruned)
- **Setup** — Round-3 pack must include 2 deliberately uncompilable rules and 1 rule importing a module the Linux agent's yara 3.11.0 lacks (e.g. `import "cuckoo"`).
- **Evidence** — `ls <scanner_dir>/failed_rules/` before and after each run; each file's first lines — `// FAILED RULE - Compilation Error` + `// Error: ...`, `// SKIPPED RULE - Module '<m>' not available`, or `// RAW YARA CONTENT - Failed to split into individual rules`; scan_summary_<run_id>.json .failed_rules and .skipped_rules.

### `STOR-023` Cleanup script generated on disk (.bat / .sh)

*supporting* · on `xsoar`, `thor`

- **Must be true** — The cleanup script written to the scanner_dir root targets THIS run's real alert_dir and carries the platform's guard clause, with 0755 mode on POSIX.
- **Threshold** — the .bat contains literally `cd /d "C:\yara_scanner\alert"`, `if errorlevel 1 exit /b 0`, `ren *.txt *.alert` and nothing referencing c:\xdr-data; the .sh contains `cd "/opt/yara_scanner/alert" \|\| exit 0` and the mv loop, and `stat -c %a` == 755; both files persist after the run
- **Evidence** — /opt/yara_scanner/cleanup_script.sh and C:\yara_scanner\cleanup_script.bat; system_<run_id>.log line `Cleanup script decoded and ready for scheduling`.

### `STOR-024` .txt -> .alert rotation performed by the scheduled cleanup

*supporting* · on `xsoar`

- **Must be true** — The scheduled cleanup actually runs and renames every alert/*.txt to *.alert on both Linux and Windows.
- **Threshold** — 0 remaining *.txt and count(*.alert) == the pre-rotation *.txt count on BOTH hosts; Windows Last Result == 0 (not 1); Linux unit Result == success
- **Setup** — After each flood run, snapshot the alert dir listing, then wait 120 s on thor and until the systemd unit is inactive on xsoar, and re-list. Do not start a new scan in between (initial_cleanup would wipe the directory).
- **Evidence** — `ls /opt/yara_scanner/alert` and `dir C:\yara_scanner\alert` snapshotted at scan end and again after the scheduled time; `schtasks /query /tn CleanupScript /v /fo LIST` Last Result on thor; `systemctl show -p Result yara-cleanup.service` on xsoar.

### `STOR-025` Windows scheduled cleanup task (CleanupScript)

*supporting* · on `thor`

- **Must be true** — On Windows a one-shot CleanupScript task is created ~1 minute in the future running as SYSTEM, with the generated .bat as its action, force-overwriting any prior task of that name.
- **Threshold** — task exists; Task To Run == C:\yara_scanner\cleanup_script.bat; Run As User == SYSTEM; Schedule Type == One Time Only; the scheduled HH:MM is 60-120 s after the log line's timestamp; a pre-existing CleanupScript task from a prior run is replaced, not duplicated
- **Setup** — Pre-create a dummy CleanupScript task on thor before the run to prove /f overwrites it.
- **Evidence** — diagnostics_<run_id>.log line `Windows cleanup task scheduled for HH:MM` (logging.info after the schtasks /create at 4250-4264); system_<run_id>.log line `Windows cleanup task scheduled successfully`; `schtasks /query /tn CleanupScript /v /fo LIST`.

### `STOR-026` Linux systemd cleanup unit (yara-cleanup.service)

*supporting* · on `xsoar`

- **Must be true** — On Linux a root-owned /etc/systemd/system/yara-cleanup.service is written, daemon-reloaded, enabled and started, leaving a persistent boot-activated unit whose ExecStart is the generated script.
- **Threshold** — unit file exists with uid == 0; is-enabled == "enabled"; ExecStart path == `/bin/bash /opt/yara_scanner/cleanup_script.sh`; unit body contains Type=oneshot, User=root, WantedBy=multi-user.target; Result == success
- **Setup** — Deliver the xsoar flood run as root (the unit write and systemctl calls require it); record that the unit remains enabled after the run as the persistent-footprint observation.
- **Evidence** — `cat /etc/systemd/system/yara-cleanup.service`; `systemctl is-enabled yara-cleanup.service`; `systemctl show -p ExecStart -p Result yara-cleanup.service`; `stat -c %u` on the unit file; diagnostics_<run_id>.log `Linux cleanup service created and started` and system_<run_id>.log `Linux cleanup service scheduled successfully`.

### `STOR-027` macOS has no working scheduled-cleanup path

*supporting* · on `OfficeiMac`

- **Must be true** — On Darwin the cleanup scheduler takes the Linux branch and fails, the failure is recorded in the error channel, the scan still returns its result line, and no .txt -> .alert rotation ever occurs.
- **Threshold** — both error lines present (at minimum one); alert/ still holds >= 1 *.txt and exactly 0 *.alert 5 minutes after the run; cleanup_script.sh exists with mode 0755; /etc/systemd/system/yara-cleanup.service does not exist on the Mac; outcome == "completed" (the failure must not fail the scan)
- **Setup** — Round-3 OfficeiMac scan must hit at least one matching file (plant one decoy under a non-skipped path such as /Users/Shared/) so _check_for_alerts() returns True and the scheduler is actually entered.
- **Evidence** — /usr/local/yara_scanner/logs/scan_errors_<run_id>.log — `Failed to schedule cleanup: <err>` (CleanupManager._log level="error", 4201-4203; NOTE the capability's observe field is stale: the dead `hasattr(self.config, 'log_manager')` guard was removed so this line DOES fire) and main()'s `Error scheduling cleanup: <err>` (6551); /usr/local/yara_scanner/alert/ listing; /usr/local/yara_scanner/cleanup_script.sh; scan_summary_<run_id>.json .outcome.

### `STOR-028` Cleanup scheduling is suppressed on critical errors or zero alerts

*supporting* · on `xsoar`

- **Must be true** — Cleanup scheduling is suppressed on exactly two conditions — zero valid compiled rules, and no .txt in alert_dir — and on neither path is a task/unit created or the script rewritten.
- **Threshold** — zero-match run → the `No alerts found` line appears exactly once, cleanup_script.sh mtime unchanged from the prior run, and yara-cleanup.service ActiveEnterTimestamp does not advance; the documented third suppressor (error-log ratio > 0.5) is confirmed ABSENT from the pinned source — it was removed, not merely dead — so no criterion is asserted for it
- **Setup** — One extra short xsoar run with a pack that compiles cleanly but matches nothing (a unique 32-byte magic string known absent from the host).
- **Evidence** — system_<run_id>.log line `No alerts found, skipping cleanup scheduling`; diagnostics_<run_id>.log line `No valid YARA rules compiled - skipping cleanup to preserve diagnostics` (4192, and the same re-check in main() at 6542-6549 which logs `Cleanup skipped due to critical YARA processing errors`); mtime of <scanner_dir>/cleanup_script.sh; `systemctl show -p ActiveEnterTimestamp yara-cleanup.service`.

### `STOR-029` control/cancel.flag — cooperative cancel signal file

*supporting* · on `xsoar`

- **Must be true** — A mode=cancel invocation writes a parseable control/cancel.flag without initialising logging or compiling rules, and a running scan notices it and terminates with outcome "cancelled".
- **Threshold** — flag file exists and json.load succeeds; the cancel invocation returns in < 5 s and reports `scanner running: yes`; the scan process exits within 20 s of the flag's mtime (2 * CANCEL_POLL_SECS default 5 s + margin); outcome == "cancelled"
- **Setup** — Whole-filesystem scan on xsoar; invoke the scanner with mode=cancel via Action Center ~5 minutes in, while a live `ps`/uploads tail confirms the scan is mid-walk.
- **Evidence** — <scanner_dir>/control/cancel.flag (JSON); the cancel entry point's returned line `Cancel signal delivered (<flag_path>) \| scanner running: yes \| scan_id=<id>`; system_<run_id>.log line `Cancellation requested (source=action_center)`; scan_summary_<run_id>.json .outcome and .failure_reasons.

### `STOR-030` Stale cancel-flag detection and removal

*supporting* · on `xsoar`

- **Must be true** — A cancel.flag whose mtime predates process start (minus CANCEL_STALE_TOLERANCE_SECS) is deleted and the scan runs normally, while a flag written DURING rule compilation survives and cancels the scan.
- **Threshold** — Run A (flag pre-planted with mtime = now - 1h) → stale line present exactly once, cancel.flag absent 10 s into the scan, outcome == "completed"; Run B (flag written within 3 s of launch, during compilation) → no stale line, flag survives compilation, outcome == "cancelled"
- **Setup** — Run A: hand-write control/cancel.flag then `touch -d '1 hour ago'` it before launching. Run B: use a >2000-rule pack so compilation takes >10 s, and fire mode=cancel immediately after the scan action is dispatched.
- **Evidence** — system_<run_id>.log line `Removed stale cancel flag from a previous run` (5604) or `Could not evaluate pre-existing cancel flag: <e>`; presence/absence of <scanner_dir>/control/cancel.flag right after scan start; scan_summary_<run_id>.json .outcome.

### `STOR-031` control/running.json liveness marker (atomic, refreshed)

*supporting* · on `xsoar`

- **Must be true** — A live scan keeps running.json refreshed at least every RUNNING_MARKER_REFRESH_SECS throughout a long, loaded scan — including while the producer is deep in a directory tree — and the file is never observable half-written.
- **Threshold** — over a >= 15 min scan polled at 1 Hz: max gap between successive updated_at values <= 60 s (2x the 30 s refresh); files_scanned monotonically non-decreasing; 0 of the >900 samples fail json.load; running.json.tmp observed in 0 samples; a mode=cancel probe fired at the deepest point of the walk reports `scanner running: yes`
- **Setup** — Round-1 long scan on xsoar with competing load (stress-ng --cpu 4); poll <scanner_dir>/control/ at 1 Hz over a persistent paramiko session for the whole run, and fire one mode=cancel probe against a second, non-cancelled scan to read the liveness verdict without ending the run.
- **Evidence** — <scanner_dir>/control/running.json fields scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections; the transient <scanner_dir>/control/running.json.tmp; the cancel entry point's `scanner running: yes\|no` verdict against RUNNING_MARKER_STALE_SECS=180.

### `STOR-032` Control-file teardown at end of scan

*supporting* · on `xsoar`

- **Must be true** — After a run ends, neither running.json nor cancel.flag remains in control/, and a cancel consumed by one scan cannot also cancel the next.
- **Threshold** — control/ contains neither running.json nor cancel.flag after all 3 round-3 runs (cancelled run included); an idle-host cancel reports `scanner running: no \| scan_id=n/a`; the scan started immediately after the cancelled run reaches outcome == "completed"
- **Setup** — Immediately after the cancelled xsoar run, start a second short scan over a small planted tree and let it finish, to prove the flag was consumed.
- **Evidence** — `ls <scanner_dir>/control/` after each run; the cancel entry point's line `Cancel signal delivered (<path>) \| scanner running: no \| scan_id=n/a` when invoked against an idle host.

### `STOR-033` Scanner never quarantines, moves or deletes scanned files

*supporting* · on `xsoar`

- **Must be true** — No scanned or matched file is moved, renamed, deleted or modified — path, size, mtime and SHA256 are identical before and after the scan — and the only filesystem writes outside scanner_dir are the systemd unit.
- **Threshold** — 0 diffs across the pre/post manifest for every matched decoy (path, size, mtime, sha256 all identical); the newermt diff outside /proc,/sys,/run,/var/log contains only paths under /opt/yara_scanner and /etc/systemd/system/yara-cleanup.service; the quoted recovery line present in every truncated alert file
- **Setup** — Plant a decoy tree on xsoar (~20 matching files with distinct mtimes) and capture the manifest immediately before launching, and a whole-filesystem mtime baseline at scan start.
- **Evidence** — pre/post manifest of the planted decoy tree from `find <tree> -printf '%p %s %T@\n' \| sort` plus `sha256sum` of each matched file; the recovery line in <scanner_dir>/alert/<rule>.txt: `re-run \`yara -s\` against this file for every offset.`; a whole-filesystem `find / -newermt <scan_start>` diff.

### `STOR-034` Scanner working directory is excluded from its own scan

*supporting* · on `xsoar`, `thor`

- **Must be true** — scanner_dir and everything under it is excluded from its own scan by component-anchored matching — including the bare directory root os.walk yields — while a sibling whose name merely shares the prefix is scanned normally.
- **Threshold** — scan targeted at /opt/yara_scanner → excluded_targets == ["/opt/yara_scanner"], files_scanned == 0 and the WARNING fragment present; the whole-fs run produces 0 yara_match rows whose file_name is under /opt/yara_scanner despite alert texts containing the pack's trigger string; /opt/yara_scanner_backup/evil.bin produces >= 1 yara_match row
- **Setup** — Create /opt/yara_scanner_backup/evil.bin containing the pack's trigger string before the whole-fs run; run one extra scan targeted directly at /opt/yara_scanner. On thor, mirror with C:\yara_scanner_backup\evil.bin to exercise the case-folded Windows branch.
- **Evidence** — scan_summary_<run_id>.json .excluded_targets and .files_scanned; the result line fragment `WARNING: <N> requested target(s) EXCLUDED by the skip list, nothing under them was scanned: <path>` (6631); scan_errors_<run_id>.log `Requested scan target is excluded by the skip list, so nothing under it will be scanned: <path>` (5941-5945); type="yara_match" rows filtered on data.file_name.

### `STOR-035` End-of-run "COMPREHENSIVE STATISTICS SUMMARY" block in statistics_<run_id>.log

*supporting* · on `xsoar`

- **Must be true** — Every run ends its statistics log with the COMPREHENSIVE STATISTICS SUMMARY block; the per-worker table is populated for every worker regardless of config, while the CPU/memory half and scan_estimates.average_rate are real only when the perf monitor is enabled.
- **Threshold** — default run → block present exactly once, samples_collected == 0, all four CPU/mem values == 0.0, scan_estimates.average_rate == 0.0, but Worker Summary has exactly worker_count entries whose files_processed sum >= scan_summary.files_scanned; YARA_ENABLE_PERF_MONITOR=true run → samples_collected > 0, peak_cpu_percent > 0 and average_rate > 0; the block text appears in NO tenant row (grep the dataset for the header string returns 0)
- **Setup** — Run the round-1 loaded scan twice on xsoar — once with defaults, once with YARA_ENABLE_PERF_MONITOR=true — and pull both statistics_<run_id>.log files over SSH before the third run prunes them.
- **Evidence** — <scanner_dir>/logs/statistics_<run_id>.log — the literal line `COMPREHENSIVE STATISTICS SUMMARY` between two `====` rules, then `Performance Metrics: {...}` (peak_cpu_percent, avg_cpu_percent, peak_memory_mb, avg_memory_mb, samples_collected), `Time Estimates: {...}`, `Worker Summary: {...}` (per worker: files_processed, avg_processing_time_ms, error_rate_percent); corroborating line `Performance monitoring disabled in light profile` (1602).

## Delivery (54)

### `DELI-001` HTTP Collector NDJSON transport

***core*** · on `xsoar`

- **Must be true** — Every event leaving the endpoint goes out over exactly one code path — an HTTPS POST to the configured HTTP Collector with a bare Authorization header and Content-Type: text/plain — and no other destination or transport is used.
- **Threshold** — the scanner PID's outbound TCP peer set contains exactly one host — the configured collector; data.api_endpoint equals the configured DEFAULT_API_ENDPOINT; webhook_key_source == webhook_endpoint_source == "default"; every non-header line in uploads_<run_id>.log is an HTTP result line; 0 requests to any XDR API or lookup-dataset URL
- **Setup** — Capture `ss -tnp` at 1 Hz for the scanner PID for the duration of the thor and xsoar flood runs.
- **Evidence** — <scanner_dir>/logs/uploads_<run_id>.log (every batch result line); the type="system" scanner_initialization event's data.api_endpoint, data.webhook_key_source, data.webhook_endpoint_source (6364-6366); XQL rows with source="yara_scanner"; `ss -tnp` / tcpdump destination set captured on xsoar for the scanner PID during the run.

### `DELI-002` NDJSON-only multi-event encoding (JSON array is unsafe)

***core*** · on `xsoar`

- **Must be true** — The scanner's own success accounting reconciles exactly with rows actually queryable in the tenant, proving the body is NDJSON and not a silently-discarded JSON array.
- **Threshold** — sum of N over successful match-batch lines == XQL row count for type="yara_match" at that scan_id, exactly (delta == 0); likewise for telemetry types; a non-zero ok-count with a zero row count is an automatic fail
- **Setup** — Flood run producing >= 5,000 findings so an array-encoding regression would show as thousands of missing rows rather than an off-by-one.
- **Evidence** — uploads_<run_id>.log lines `YARA match batch uploaded: <N> event(s) (HTTP 2xx)` (3307); scan_summary_<run_id>.json .match_delivery and .telemetry_delivery; XQL `dataset = <collector dataset> \| filter scan_id = "<scan_id>" and type = "yara_match" \| count`.

### `DELI-003` Opportunistic (non-timer) batching with event and byte caps

*supporting* · on `xsoar`

- **Must be true** — Each uploader worker coalesces whatever is already queued into one POST up to the event/byte cap, with no linger timer — so a flood self-fills near-maximal batches while a 3-match scan sends immediately.
- **Threshold** — flood run → mean N >= 100, max N == 500, and total findings / count(batch lines) >= 50; control run with 3 matches → 1-3 batch lines all with N <= 3, and the first batch line's timestamp within 2 s of the first queue line's (no linger delay added)
- **Setup** — Pair each flood run with a 3-match control run on the same host using a narrow rule pack.
- **Evidence** — uploads_<run_id>.log lines `YARA match batch uploaded: <N> event(s) (HTTP 2xx)`; the per-finding queue line `Queued finding for upload: rule='X', file=Y, hits=<n>` with its timestamp; UPLOAD_BATCH_MAX_EVENTS (default 500) and UPLOAD_BATCH_MAX_BYTES (default 4 MiB).

### `DELI-005` Bounded retry with jittered exponential backoff

*supporting* · on `xsoar`

- **Must be true** — Only transient conditions (HTTP 408/429/5xx, Timeout, ConnectionError) are retried, at most MAX_RETRIES_PER_ITEM=2 attempts with delay in [0.5,1.0) x min(1.0 x 2^(attempt-1), 30); any other non-2xx fails immediately, and exhausted batches are counted as undelivered rather than lost silently.
- **Threshold** — 503 stub → exactly 2 attempts per batch then exactly one exhaustion line; every logged delay d satisfies 0.5 <= d <= 1.0 for attempt 1 and 1.0 <= d <= 2.0 for attempt 2; 403 stub → 0 `Retrying` lines and immediate failure; in both cases match_delivery.failed accounts for 100% of the events named in the exhaustion lines (nothing silently vanishes)
- **Setup** — Two extra xsoar runs with DEFAULT_API_ENDPOINT/DEFAULT_API_KEY in the uploaded payload edited to point at a local python http.server stub returning 503, then 403. No live tenant traffic; the stub logs every request so attempt counts are independently countable.
- **Evidence** — uploads_<run_id>.log lines `Batch upload failed (HTTP 503). Retrying in <d>s (attempt <a>/2, <n> event(s)).` (3314), `Batch upload network error (<Err>). Retrying in <d>s (attempt <a>/2, <n> event(s)).` (3329), `YARA match batch exhausted retries (<n> event(s) not delivered)` (3341); scan_summary_<run_id>.json .match_delivery failed/total counters.

### `DELI-007` Match finding grain: one upload item per (rule, file)

*supporting* · on `xsoar`

- **Must be true** — The findings channel emits exactly one yara_match event per distinct (rule, file) pair no matter how many string offsets matched.
- **Threshold** — row count == count(distinct (rule_id, file_name)) exactly, and 0 pairs appear on more than one row; sum(data.match_count) over all rows == sum of `Total string hits:` across all alert/*.txt; every uploads line reads `1 upload item`
- **Setup** — Flood pack must include at least one rule producing >10,000 offsets in a single file (a 1-2 byte common string against a large log) so a per-offset regression would be unmistakable.
- **Evidence** — XQL type="yara_match" for the scan_id, grouped by data.rule_id and data.file_name; uploads_<run_id>.log line `Added <N> local result entries for rule 'X' in file: Y (1 upload item, <K> of <N> sampled)` (3494-3497); alert/<rule>.txt `Total string hits: <N>` lines.

### `DELI-008` match_count vs sampled offsets/strings and the truncated flag

*supporting* · on `xsoar`

- **Must be true** — Each finding carries the true total hit count alongside a positionally-aligned sample of at most MAX_MATCH_SAMPLES_PER_FINDING offsets and strings, with truncated set exactly when match_count exceeds the sample length.
- **Threshold** — for every row len(json.loads(offsets)) == len(json.loads(strings)) <= 50 and truncated == (match_count > len(offsets)); >= 1 row with match_count > 50 shows exactly 50 sampled and truncated == true; every row with match_count <= 50 shows truncated == false and len(offsets) == match_count; with YARA_MAX_MATCH_SAMPLES=0 the sample is UNCAPPED (len(offsets) == match_count, truncated == false) — the capability's "floored at minimum=1, 0 falls back to default" text is STALE against the pinned source (line 164 uses minimum=0; the consumer at 3442 short-circuits on `<= 0`)
- **Setup** — Include a rule matching a very common short string so one file yields >10,000 hits; run one extra short xsoar variant with YARA_MAX_MATCH_SAMPLES=0 to pin the new 0-means-uncapped semantics.
- **Evidence** — XQL type="yara_match": data.match_count, data.offsets (JSON list string), data.strings (JSON list string), data.truncated, data.string_match_count.

### `DELI-009` Uncapped per-string-ID census in the finding (match_ids)

*supporting* · on `xsoar`

- **Must be true** — Every finding carries a complete, uncapped histogram of which rule string identifier fired and how many times, whose values sum to match_count even when the offset sample is truncated.
- **Threshold** — sum(match_ids.values()) == data.match_count for 100% of rows, including every row with truncated == true; for string matches the event's match_ids equals the alert file's `Hits per string ID` map (with the alert file's `$?` key aliasing the event's "" key); a condition-only finding shows match_ids == {"": 1}
- **Setup** — Flood pack must contain a multi-string rule ($a/$b/$c) so the census has more than one key to reconcile.
- **Evidence** — XQL type="yara_match" data.match_ids (JSON object, from _match_id_counts at 3438/3477); the matching local lines in <scanner_dir>/alert/<rule>.txt: `Total string hits: <N>` and `Hits per string ID: $a=<n>, $b=<n>` (5306-5308).

### `DELI-010` yara_match event payload shape (incl. dashboard-flattened aliases)

*supporting* · on `xsoar`

- **Must be true** — Every yara_match event carries all 17 documented data fields with the flattened dashboard aliases file_name/rule_id mirroring filename/rule, the configured threat_level, and one dateOfScan shared by the whole run.
- **Threshold** — 0 rows with a null/absent value in any listed field except file_creation_time (may be null where stat fails); file_name == filename and rule_id == rule in 100% of rows; threat_level == the alert_severity argument passed to the action ("high" on the thor run, "low" on xsoar) and is always one of low\|medium\|high; count(distinct dateOfScan) == 1 per scan_id; message matches the string-match form for every row with match_scope == "string"
- **Setup** — Pass alert_severity="high" on the thor flood run and leave xsoar at the default "low" to prove propagation rather than a hardcoded constant.
- **Evidence** — XQL type="yara_match": data.filename, data.rule, data.file_name, data.rule_id, data.threat_level, data.string, data.offset, data.match_scope, data.match_count, data.offsets, data.strings, data.match_ids, data.truncated, data.string_match_count, data.dateOfScan, data.file_sha256, data.file_creation_time; message text `YARA match: rule '<R>' in <F> (<N> string hit(s))`.

### `DELI-011` Condition-only match representation

*supporting* · on `xsoar`

- **Must be true** — A rule firing on its condition with no string instances still produces one finding, carrying match_scope="rule", an empty offset, a rule-only message, and a human-readable condition summary in the alert file.
- **Threshold** — >= 1 row with match_scope == "rule", offset == "", message starting `YARA rule-only match:`, match_count == 1, string_match_count == 0, and data.string a non-empty summary; the corresponding alert file contains the Condition Match Details block and no `Hits per string ID` line; the same file is still represented in exactly one type="alert" merged event
- **Setup** — Add a condition-only rule to the flood pack, e.g. `rule COND_ONLY { condition: filesize > 0 }`.
- **Evidence** — XQL type="yara_match" where data.match_scope == "rule": data.offset, data.string, data.string_match_count, data.match_count, message prefix `YARA rule-only match:`; <scanner_dir>/alert/<rule>.txt block `Condition Match Details:` between two `----` rules (5340-5344).

### `DELI-012` One merged alert event per matched file

*supporting* · on `xsoar`

- **Must be true** — Each matched file produces exactly ONE type="alert" event carrying the union of file and per-rule detail — never a second "YARA detection event" row for the same file.
- **Threshold** — alert row count == count(distinct matched file paths) == data-line count of file_mapping.txt; the string "YARA detection event" appears 0 times in the dataset and 0 times in any log on either host; rules_matched == rules_triggered element-wise for 100% of rows; len(detections) == data.match_count; events-per-finding ratio <= 1.05 (the pre-fix regression measured 2.07)
- **Setup** — Flood pack must have several rules matching the SAME files, so the merge is genuinely exercised (match_count > 1 on many alert rows).
- **Evidence** — XQL type="alert" for the scan_id: data.file_path, real_path, file_size, file_sha256, file_creation_time, match_count, rules_matched, rules_triggered, total_string_matches, detections[], detection_timestamp; <scanner_dir>/logs/alerts_<run_id>.log line `YARA matches found in <path> (<R> rule(s), <S> string hit(s))` (5044-5045).

### `DELI-013` Six categorized event types from the log channel

*supporting* · on `xsoar`

- **Must be true** — The five uploadable log categories reach the collector as events typed by category name, while LogType.UPLOAD is written to file and never uploaded, so upload bookkeeping cannot feed back into the upload channel.
- **Threshold** — each of the five types returns >= 1 row for the scan_id; type == "upload" returns exactly 0 rows; uploads_<run_id>.log has > 100 lines on the flood run (proving upload logging was active while producing no events)
- **Evidence** — XQL `type in ("alert","statistics","error","performance","system")` and `type = "upload"` filtered to the scan_id; <scanner_dir>/logs/uploads_<run_id>.log on disk; the guard `and log_type != LogType.UPLOAD` at 1981.

### `DELI-014` StandardLogEntry envelope on every event

*supporting* · on `xsoar`

- **Must be true** — Every event on every channel shares one envelope with the 9 mandatory fields populated, and omits empty message/level/data keys rather than sending nulls.
- **Threshold** — 100% of rows for the scan_id have all 9 mandatory fields non-null; source == "yara_scanner" and uploader_version == "enhanced_v2" on 100% of rows; timestamp_iso parses as UTC and abs(parse(timestamp_iso) - timestamp) < 1 s; 0 rows carry an explicitly null message, level or data key; filtering the dataset on source == "yara_scanner" returns exactly the same row count as filtering on the run's scan_id prefix
- **Evidence** — Raw JSON of any row for the scan_id: type, hostname, os_info, ipAddress, timestamp (epoch float), timestamp_iso (UTC ISO-8601), scan_id, uploader_version, source (StandardLogEntry.to_dict, 2022-2043).

### `DELI-015` Per-run scan_id correlation key

*supporting* · on `xsoar`

- **Must be true** — scan_id has the form <hostname>_<run_id>_yara_<rule_hash[:12]>, is unique per RUN, and its trailing 12 hex chars are stable for a given ruleset across hosts and re-runs.
- **Threshold** — the two xsoar flood runs with the identical pack yield 2 distinct scan_ids sharing the same trailing 12 hex chars; the xsoar and thor runs with that pack differ only in the hostname prefix and run_id; scan_id.endswith(rule_hash[:12]) is true in every summary; 0 scan_id collisions across all round-2 runs; run_id matches `\d{8}_\d{6}_\d{6}`
- **Setup** — Run the identical rule pack twice on xsoar and once on thor within the round.
- **Evidence** — scan_id on any event for each run; scan_summary_<run_id>.json .scan_id and .rule_hash; the construction at 2808.

### `DELI-016` Critical-path synchronous send with async fallback

*supporting* · on `xsoar`

- **Must be true** — Once-per-scan dashboard-critical signals bypass the batch queue and land in the tenant while the scan is still running with a deep backlog, falling back to the async queue only on failure and never being silently dropped.
- **Threshold** — the `Worker thread startup completed` row is queryable within 30 s of scan start; each `Target scan completed` row's ingest time precedes the run's final yara_match row by >= 60 s while the performance snapshots show queue_size > 10,000; 0 `Critical log dropped` lines in uploads_<run_id>.log; one `Target scan completed` row per scan target, no duplicates on a clean run
- **Setup** — Flood run with >= 20,000 findings across at least 2 scan targets so per-target completion fires while the batch queue is deeply backlogged; poll the dataset for the two critical messages every 15 s during the run rather than only after it.
- **Evidence** — XQL type="statistics" message `Target scan completed: <path>` and type="performance" message `Worker thread startup completed in <X>s`, with their ingest _time compared against the run's last type="yara_match" row; uploads_<run_id>.log lines `Critical log immediate send failed (HTTP <c>): <body> - falling back to async queue` (2037-2040), `Critical log immediate send raised <Err>: <e> - falling back to async queue (may deliver a duplicate if the request actually landed)` (2047-2050), `Critical log dropped for <type>: no async queue to fall back to` (2062-2064).

### `DELI-017` scan_status lifecycle events

*supporting* · on `xsoar`

- **Must be true** — For a given scan_id the ordered sequence of type="scan_status" events ends on a terminal value (completed\|cancelled\|interrupted\|error\|failed) and never on "finishing", and a cooperative mid-run cancel ends on exactly "cancelled".
- **Threshold** — last data.scan_status in {completed, cancelled, interrupted, error, failed}; for the cancelled run last == "cancelled"; count of rows with scan_status=="scanning" >= 1; zero runs terminating on "finishing".
- **Setup** — Whole-filesystem scan on xsoar; issue the cancel entry point (mode=cancel / argv cancel) roughly 60s in. Also collect an uncancelled OfficeiMac run as the completed control.
- **Evidence** — XQL rows where type="scan_status", filtered to the run's envelope scan_id, ordered by _time; field data.scan_status. Emission path verified at PINNED_xsiam_current.py:3599-3633 (upload_scan_status) with set_status at 3636-3639.

### `DELI-018` scanner_initialization event

*supporting* · on `xsoar`

- **Must be true** — Exactly one type="scanner_initialization" row per scan_id, and its data echoes the knob values the run actually used (max_workers, scan_queue_size, max_file_mb, monitoring flags) matching the env vars the run was launched with.
- **Threshold** — row count == 1 per scan_id; data.max_workers == the value passed via YARA_MAX_WORKERS (or the profile default); data.yara_version == "3.11.0" on xsoar.
- **Setup** — Launch the long xsoar run with an explicitly non-default YARA_MAX_WORKERS (e.g. 3) so the echo is falsifiable rather than tautological.
- **Evidence** — XQL type="scanner_initialization", fields data.max_workers, data.scan_queue_size, data.max_file_mb, data.scanner_profile, data.upload_enabled, data.telemetry_upload_enabled, data.yara_version. Built in main() and queued priority=True (PINNED:6394-6403).

### `DELI-019` statistics_summary checkpoints with per-type rate limiting

*supporting* · on `xsoar`

- **Must be true** — Both statistics_summary checkpoints share the single 'statistics' 60s rate-limit key, so a normal run ships the phase="initialization" row and suppresses the phase="scan_configuration" row emitted milliseconds later.
- **Threshold** — exactly 1 statistics_summary row with data.phase=="initialization" and 0 rows with data.phase=="scan_configuration" when the two emissions are <60s apart (they always are).
- **Evidence** — XQL type="statistics_summary" for the scan_id; field data.phase. Sites: main() phase='initialization' (PINNED:6422-6426), scan_system() phase='scan_configuration' (PINNED:5887-5890); gate _should_upload('statistics'), interval 60s.

### `DELI-020` scan_completion_summary event with honest outcome

*supporting* · on `xsoar`

- **Must be true** — Exactly one type="scan_completion_summary" row per run whose data.outcome agrees with both the SCAN_RESULT line and scan_summary_<run_id>.json's outcome, and which carries a non-empty cancel_source when cancelled.
- **Threshold** — row count == 1; data.outcome == JSON outcome == verb on SCAN_RESULT line; on the cancelled run data.outcome=="cancelled" and len(data.cancel_source) > 0.
- **Setup** — Cancel the xsoar whole-filesystem run mid-scan via the cancel flag (not the console Cancel button, which hard-kills).
- **Evidence** — XQL type="scan_completion_summary" (PINNED:6517, crash branch 6691), fields data.outcome, data.cancel_source, data.total_detections; cross-read against the Action Center result line and /opt/yara_scanner/logs/scan_summary_<run_id>.json field "outcome".

### `DELI-021` comprehensive_final_report event and efficiency score

*supporting* · on `xsoar`

- **Must be true** — One type="comprehensive_final_report" row per completed run whose data.upload_summary embeds the telemetry delivery book, and whose figures are mirrored to statistics_<run_id>.log.
- **Threshold** — row count == 1; data.upload_summary.summary.total_uploads > 0; data.detection_results.detection_rate_percent present; local mirror line exists with the identical score value.
- **Evidence** — XQL type="comprehensive_final_report" (created PINNED:6149-6156), fields data.scan_metadata, data.file_processing, data.detection_results, data.upload_summary, data.efficiency_score; local mirror line "COMPREHENSIVE SCAN REPORT \| Efficiency Score:" in /opt/yara_scanner/logs/statistics_<run_id>.log (PINNED:6162).

### `DELI-022` Scan-progress telemetry on a whole-scan heartbeat

*supporting* · on `xsoar`

- **Must be true** — A dedicated heartbeat thread emits type="statistics" "Scan Progress \|" events across the entire scan including the post-discovery worker drain, with active_workers readable as a top-level field.
- **Threshold** — for a scan of duration D seconds with log_interval L: row count >= floor(D/L) - 2 and >= 1; at least one row has a non-null top-level active_workers > 0; the timestamp gap between the last discovery-phase row and the final row shows rows continuing after discovery ends.
- **Setup** — Long xsoar scan (>10 min) with competing CPU load; set YARA_PROGRESS_LOG_SECS=15 so the expected row count is large enough to be falsifiable.
- **Evidence** — XQL type="statistics" where message starts "Scan Progress \|" (PINNED:2107); top-level field active_workers (flattened at PINNED:2102) plus nested metrics.cpu_percent/memory_mb/elapsed_seconds. Heartbeat thread PINNED:5735-5744, started 5906-5910.

### `DELI-023` Time-estimate telemetry

*supporting* · on `xsoar`

- **Must be true** — Once an ETA is computable the scanner emits type="statistics" "Time Estimates \|" events alongside progress ticks, carrying eta_seconds, estimated_completion, current_rate_files_per_sec and files_remaining.
- **Threshold** — on a scan longer than 5 minutes, row count >= 1; every row has eta_seconds > 0 and estimated_completion parseable as ISO8601; files_remaining is monotonically non-increasing across rows.
- **Evidence** — XQL type="statistics" where message starts "Time Estimates \|" (PINNED:2162), fields data.eta_seconds, data.estimated_completion, data.files_remaining; mirrored in statistics_<run_id>.log.

### `DELI-024` Worker performance telemetry

*supporting* · on `xsoar`

- **Must be true** — Each worker emits a type="performance" "Worker Performance \| ScanWorker-N" event every 100 files, a "Worker <id> stopped" system event on exit, and the run ends with one aggregated worker performance summary covering all configured workers.
- **Threshold** — for each worker w: rows(w) == floor(files_processed(w)/100); distinct ScanWorker ids seen == scanner_initialization.data.max_workers; exactly 1 "Worker performance summary" row and its worker_details length == max_workers.
- **Setup** — Long xsoar scan with >= 100*max_workers files so every worker crosses the cadence at least once.
- **Evidence** — XQL type="performance" message starting "Worker Performance \| ScanWorker-" (PINNED:2124, cadence guard 4848); type="system" "Worker <id> stopped" (PINNED:4877); "Worker performance summary: N workers processed files" (PINNED:5570). Local mirror performance_<run_id>.log.

### `DELI-025` CPU governor telemetry

*supporting* · on `xsoar`

- **Must be true** — The governor emits "CPU governor \| policy=..." performance events on a heartbeat as well as on ratio change, so a long scan on a steady host still produces recurring evidence rather than a single line.
- **Threshold** — for a scan of duration D with YARA_GOVERNOR_HEARTBEAT_SECS=H: row count >= floor(D/H) - 2 and >= 3 on a >30s scan; the disabled message appears 0 or exactly 1 time, never more.
- **Setup** — Run on xsoar (8 cores) with a competing CPU load started after the scan begins, so the ratio also changes at least once; set YARA_GOVERNOR_HEARTBEAT_SECS=30.
- **Evidence** — XQL type="performance" message starting "CPU governor \| policy=" (PINNED:4920), fields policy/target/own/others/ratio; heartbeat gate GOVERNOR_HEARTBEAT_SECS (PINNED:335, 4915); disable path message "CPU governor disabled - could not read CPU" (PINNED:4905).

### `DELI-026` system_resource_snapshot and resource_monitoring_summary events

*supporting* · on `xsoar`

- **Must be true** — With resource monitoring off (default) zero system_resource_snapshot rows exist; with YARA_ENABLE_RESOURCE_MONITOR=true rows appear about every 45s carrying the four flattened dashboard fields, plus exactly one resource_monitoring_summary at shutdown.
- **Threshold** — control run (flag default False, PINNED:246): snapshot rows == 0 and summary rows == 0. Instrumented run of duration D: snapshot rows within +/-2 of floor(D/45); all four flattened fields non-null on every row; resource_monitoring_summary rows == 1.
- **Setup** — Two xsoar runs: one default, one with YARA_ENABLE_RESOURCE_MONITOR=true.
- **Evidence** — XQL type="system_resource_snapshot" (PINNED:2498) with top-level proc_cpu_percent, proc_memory_mb, sys_cpu_percent, sys_memory_used_percent (PINNED:2491ff); type="resource_monitoring_summary" (PINNED:2597) with data.data_points_collected, cpu_stats, memory_stats.

### `DELI-027` Resource threshold alerts as error events

*supporting* · on `xsoar`

- **Must be true** — When resource monitoring is on and a sampled value exceeds its hardcoded threshold, a type="error" "RESOURCE ALERT: ..." event is emitted with alert_type/current_value/threshold, and the count is reflected in the summary's alerts_triggered.
- **Threshold** — default run: 0 rows. Monitored run under sustained competing load: rows >= 1, every row has current_value > threshold, and alerts_triggered == min(row count, 100) given the maxlen-100 history.
- **Setup** — On the YARA_ENABLE_RESOURCE_MONITOR=true run, drive system CPU above the alert threshold with a stress load for at least 60s so a breach is guaranteed.
- **Evidence** — XQL type="error" message starting "RESOURCE ALERT:" (PINNED:2460), fields data.alert_type, data.current_value, data.threshold; cross-check resource_monitoring_summary.data.alerts_triggered.

### `DELI-028` privilege_status event

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — privilege_status is emitted only on a non-root, non-Windows run; a root run emits zero rows, and on macOS the event still reports data.platform == "linux" (a known wart that must be recorded, not silently assumed correct).
- **Threshold** — non-root xsoar run: rows == 1 with running_as_root==false and recommended_action=="run_as_sudo"; root/sudo xsoar run: rows == 0; OfficeiMac non-root run: rows == 1 and data.platform observed literally equal to "linux".
- **Setup** — Run the whole-filesystem xsoar scan once as the unprivileged LINUX_USER and once under sudo; run OfficeiMac unprivileged.
- **Evidence** — XQL type="privilege_status" (PINNED:6271), fields data.running_as_root, data.recommended_action, data.platform; gates at PINNED:3109-3140 (is_root) nested under the non-Windows check.

### `DELI-029` resource_limit_warning event

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — With FD monitoring enabled on a non-Windows host whose ulimit -n is below 8192, exactly one type="resource_limit_warning" WARNING event is emitted carrying current_limit and recommended_limit; with the flag at its default, zero rows.
- **Threshold** — default run: rows == 0. Run with YARA_ENABLE_FD_MONITOR=true and ulimit -n set to 1024: rows == 1, level=="WARNING", data.current_limit == 1024, data.recommended_limit == 8192.
- **Setup** — On xsoar, launch one run under `ulimit -n 1024` with YARA_ENABLE_FD_MONITOR=true.
- **Evidence** — XQL type="resource_limit_warning" (PINNED:6302), fields data.current_limit, data.recommended_limit, level; local line "Current file descriptor limit: N" in system_<run_id>.log. Flag ENABLE_FD_MONITOR default False (PINNED:248).

### `DELI-030` Match-channel delivery accounting (successful / failed / undelivered)

*supporting* · on `xsoar`

- **Must be true** — The findings channel books balance: successful_uploads + failed_uploads + undelivered equals the number of upload ITEMS queued, and undelivered is non-zero only when items were genuinely stranded at drain expiry.
- **Threshold** — A + B + C == number of distinct (rule,file) findings for the run; total_matches N >= A+B+C (N counts offsets, not items); on the healthy-collector flood C == 0 and B == 0; when C > 0 the companion error line at PINNED:3399 is present.
- **Setup** — False-positive flood pack on xsoar and thor; count distinct (rule,file) pairs independently from the alert directory files to get the expected item denominator.
- **Evidence** — Final line of /opt/yara_scanner/logs/uploads_<run_id>.log: "Match delivery final: matches=N ok=A failed=B undelivered=C" (PINNED:3395-3396); the same dict verbatim as match_delivery in scan_summary_<run_id>.json.

### `DELI-031` Telemetry-channel delivery accounting (per type + undelivered)

*supporting* · on `xsoar`

- **Must be true** — WebhookUploader reports per-event-type totals plus an undelivered count equal to residual queue depth, so a delivery outage cannot read as a clean run.
- **Threshold** — summary.successful_uploads + failed_uploads + undelivered == summary.total_uploads; sum(by_type values) == total_uploads; healthy run: undelivered == 0 and success_rate_percent >= 99.0; black-hole run: success_rate_percent < 100 and the suffix clause present.
- **Setup** — Run the thor flood twice: once against the live collector, once with API_ENDPOINT pointed at an unroutable host so failures and stranding are forced.
- **Evidence** — telemetry_delivery block in /opt/yara_scanner/logs/scan_summary_<run_id>.json (summary.total_uploads/successful_uploads/failed_uploads/undelivered/success_rate_percent, by_type map, queue_size); uploads_<run_id>.log line "WebhookUploader stopped. Success rate: X%" with the "(N telemetry item(s) undelivered at shutdown)" suffix (PINNED:3897-3901); same dict as data.upload_summary in comprehensive_final_report.

### `DELI-032` Log-channel delivery accounting

*supporting* · on `xsoar`

- **Must be true** — LogManager emits one shutdown "Logging Summary" system event carrying total_logs, webhook success/fail, a by-type breakdown over all six LogType categories, and the six on-disk paths.
- **Threshold** — rows == 1; len(data.logs_by_type) == 6; len(data.log_files_created) == 6 and every path exists on the host; webhook_successful + webhook_failed <= total_logs_generated (strictly less, because the upload category is never sent).
- **Evidence** — XQL type="system" message starting "Logging Summary \| Total Logs:" (PINNED:2187-2194), fields data.total_logs_generated, data.webhook_successful_uploads, data.webhook_failed_uploads, data.logs_by_type, data.log_files_created.

### `DELI-033` Backlog-proportional shutdown drain window

*supporting* · on `xsoar`

- **Must be true** — Each of the three live drain sites announces a window computed as clamp(pending*DRAIN_PER_ITEM_SECS, DRAIN_MIN_SECS, DRAIN_MAX_SECS), and total post-scan drain time stays under the four-site worst case rather than a flat timeout.
- **Threshold** — for each announced line, M == clamp(N*0.3, 15, 60) within 1s; wall-clock from the last finding log line to process exit <= 240s; the dead-path line "Waiting for N pending uploads (max Ms)..." (PINNED:3515, no callers) appears 0 times.
- **Setup** — Flood scan on thor sized so the queues carry a real backlog at shutdown (>200 pending), so N varies between the sites and a flat window would be visibly wrong.
- **Evidence** — uploads_<run_id>.log lines "Waiting for N pending match uploads (max Ms)..." (PINNED:3358), "Waiting for N pending telemetry uploads (max Ms)..." (PINNED:3880), "Waiting for N pending standardized log uploads (max Ms)..." (PINNED:2250); _compute_drain_budget at PINNED:221.

### `DELI-034` Shutdown ordering that protects end-of-run events

*supporting* · on `xsoar`

- **Must be true** — The telemetry uploader survives _perform_enhanced_cleanup so both comprehensive_final_report and scan_completion_summary reach the tenant, and the idempotent second stop in main() does not re-pay a drain window.
- **Threshold** — both event types present with count == 1 each on a normal run; "Waiting for N pending telemetry uploads" appears exactly 1 time (not 2); scan_summary_<run_id>.json is written after the telemetry stop, so its telemetry_delivery.undelivered reflects the final queue depth.
- **Evidence** — XQL presence of type="comprehensive_final_report" and type="scan_completion_summary" for the run; count of "Waiting for N pending telemetry uploads" lines in uploads_<run_id>.log; _stop_done guards in ResultsUploader.stop()/WebhookUploader.stop_uploader().

### `DELI-035` Delivery shortfall surfaced on the operator's result line

*supporting* · on `xsoar`

- **Must be true** — When findings fail or are stranded, the SCAN_RESULT line names the loss in upload ITEMS (ok+failed+undelivered denominator), and telemetry failures separately append " \| Upload errors: N".
- **Threshold** — black-hole run: both clauses present; L == F+U; Q == match_delivery.successful+failed+undelivered from scan_summary JSON (NOT total_matches); N == telemetry_delivery.summary.failed_uploads. Healthy run: neither clause present.
- **Setup** — Run the thor flood with API_ENDPOINT set to an unroutable address (black hole) so both channels fail while findings still exist.
- **Evidence** — stdout / Action Center result line "SCAN_RESULT: ..." containing " \| WARNING: L of Q finding upload(s) NOT delivered (failed=F, undelivered=U) - local logs hold the complete record" (PINNED:6601-6606) and " \| Upload errors: N" (PINNED:6575).

### `DELI-036` Result line honesty: cancelled verb, skipped rules, excluded targets

*supporting* · on `xsoar`

- **Must be true** — The SCAN_RESULT line says "Scan cancelled (source=...)" rather than "Scan completed" on a cancelled run, reports module-skipped rules separately from failed rules, and names any requested target that the skip list excluded wholly.
- **Threshold** — cancelled run: line begins with "Scan cancelled" and contains "source="; excluded-target run: the excluded path string appears verbatim in the line and in JSON excluded_targets; rule pack containing an import of an unavailable module: the skipped-rules count is reported and is not folded into failed_rules.
- **Setup** — On xsoar, (a) cancel mid-run; (b) separately request a target that is entirely on the skip list; (c) include one rule importing a module libyara 3.11.0 lacks.
- **Evidence** — stdout SCAN_RESULT line (_verb/_skipped_txt/_excl_txt blocks, PINNED:6628-6647); excluded_targets accumulated at PINNED:5940 and echoed as a first-class key in scan_summary_<run_id>.json (PINNED:6769).

### `DELI-037` scan_summary_<run_id>.json with both delivery books

*supporting* · on `xsoar`, `thor`

- **Must be true** — Every run writes exactly one atomically-created scan_summary_<run_id>.json under <scanner_dir>/logs whose outcome agrees with the SCAN_RESULT line and which carries both match_delivery and telemetry_delivery, surviving cancellation and failure.
- **Threshold** — file exists and parses; schema == "yara_scan_summary/v1"; edition == "xsiam"; outcome matches the result-line verb; match_delivery.successful_uploads + failed_uploads + undelivered == count of distinct (rule,file) findings; no leftover .tmp file in the logs dir.
- **Setup** — Cancelled xsoar run plus a clean OfficeiMac run, reading the file over SSH on both hosts.
- **Evidence** — /opt/yara_scanner/logs/scan_summary_<run_id>.json (macOS: /usr/local/yara_scanner/logs) — keys schema, edition, run_id, scan_id, rule_hash, outcome, failure_reasons, scan_targets, excluded_targets, files_scanned, files_skipped, matches, match_delivery, telemetry_delivery. Written from main()'s finally block (PINNED:6764-6769) via LogManager.write_scan_summary (PINNED:2196).

### `DELI-038` Credential placeholder detection and early abort

*supporting* · on `xsoar`

- **Must be true** — A payload whose collector endpoint or key still holds a placeholder sentinel aborts before scanning any file, returns the SCAN ABORTED string, and still writes its local logs.
- **Threshold** — result text starts with "SCAN ABORTED"; process exit code == 1; zero files scanned; scan_errors_<run_id>.log contains the abort message; no alert files created.
- **Setup** — On xsoar, run a copy of the payload with API_ENDPOINT edited to the literal "http_collector_api" (and separately API_KEY to "http_collector_key"), pointed at a tiny target directory. Local-only, nothing reaches the tenant.
- **Evidence** — stdout "SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set..." (PINNED:6226); on-host scan_errors_<run_id>.log containing the abort message; files_scanned == 0. Sentinels _PLACEHOLDER_API_KEY / _PLACEHOLDER_API_ENDPOINT at PINNED:232-233.

### `DELI-039` Result printing and exit-code contract

*supporting* · on `xsoar`

- **Must be true** — Every direct invocation prints exactly one "SCAN_RESULT: <text>" line on stdout and exits 0 unless the text starts with scan failed / scan aborted / cancel failed (case-insensitive) or is empty.
- **Threshold** — count of lines matching ^SCAN_RESULT: == 1 in every run; clean run exit == 0; placeholder-credential run exit == 1; cancelled run exit == 0 (cancelled is not a failure verb).
- **Setup** — Run all three variants over SSH on xsoar capturing $? each time.
- **Evidence** — stdout of `python3 xsiam_yara_scanner.py <rules_b64> <folder>; echo $?` — print at PINNED:6837, is_success guard at PINNED:6839ff.

### `DELI-040` Cancel entry point and its delivery guarantee

*supporting* · on `xsoar`

- **Must be true** — The zero-input cancel path writes <scanner_dir>/control/cancel.flag, reports whether a scan is alive, and the cancelled run then unwinds cooperatively — producing the terminal scan_status, the cancelled scan_completion_summary and the scan summary JSON that a console hard-kill would destroy.
- **Threshold** — cancel returns "scanner running: yes"; the scan process exits within CANCEL_POLL_SECS + drain budget (<= 240s+poll); all three cancelled artefacts present; cancel() itself compiles no rules and creates no logs directory entries of its own.
- **Setup** — Start the xsoar whole-filesystem scan, wait ~60s, then invoke the cancel entry point in a second Action Center action; time the exit.
- **Evidence** — cancel() return string "Cancel signal delivered (<path>) \| scanner running: yes\|no \| scan_id=..." (PINNED:868); /opt/yara_scanner/control/cancel.flag on disk (PINNED:844); then scan_status row cancelled, scan_completion_summary data.outcome=="cancelled" with cancel_source, scan_summary_<run_id>.json outcome=="cancelled".

### `DELI-041` Throttled upload logging

*supporting* · on `xsoar`

- **Must be true** — Upload-path messages are rate-limited per bucket: the first 20 of a bucket in full, then a single suppression notice, then a running count every 1000 occurrences — so a collector outage during a flood cannot balloon the local log.
- **Threshold** — for the upload_err bucket: exactly 20 full lines, exactly 1 suppression notice, and running-count lines only at multiples of 1000; total uploads_<run_id>.log size stays under 10 MB despite >100k failed events.
- **Setup** — Thor flood with the collector black-holed, sized to generate at least 2000 upload failures.
- **Evidence** — uploads_<run_id>.log: 20 full "[upload_err]"-bucket lines, then "further similar messages suppressed; will summarize every 1000. Example: ...", then "N occurrences so far; latest: ...". _throttled_log at PINNED:3211 with defaults full=20, every=1000; call sites 3306/3313/3321/3328/3335/3340.

### `DELI-042` Bounded skip-reason labels in shipped aggregates

*supporting* · on `xsoar`

- **Must be true** — Per-file scan errors are collapsed to "Scan error (<ExceptionType>)" before entering skip_reasons, so shipped aggregates contain a small fixed key set with no filesystem paths regardless of how many files errored.
- **Threshold** — no key in skip_breakdown contains "/", "\\", or a quoted path; distinct skip_breakdown keys <= 20 even with >1000 errored files; serialized skip_breakdown JSON < 4 KB; scan_errors_<run_id>.log still shows the full per-file message with its path.
- **Setup** — Whole-filesystem xsoar scan as the unprivileged user so /proc, /sys and root-only paths generate thousands of OSError/yara.Error cases; plant one unreadable file and one deleted-mid-scan file to add distinct exception types.
- **Evidence** — comprehensive_final_report data.file_processing.skip_breakdown (PINNED:6094) and the "Skip reasons:" statistics event (PINNED:5557); _scan_error_reason at PINNED:999, applied at PINNED:5101. Per-file detail with real paths remains in scan_errors_<run_id>.log.

### `DELI-043` Matched-data rendering for the wire

*supporting* · on `xsoar`

- **Must be true** — Matched bytes are rendered printable before leaving the process: UTF-16LE for wide patterns, else UTF-8, else lowercase hex — never raw bytes with embedded NULs.
- **Threshold** — zero occurrences of \x00 in any data.string value; the wide-string decoy's match renders as the exact plaintext; the binary decoy's match renders as an even-length string matching ^[0-9a-f]+$.
- **Setup** — Include in the flood pack one rule with a `wide` string, one with a plain ascii string, and one hitting a non-UTF8 binary blob; plant matching decoy files on both xsoar and thor.
- **Evidence** — XQL match rows field data.string (rendered via _render_match_data, PINNED:1017, applied at 3431) and the "Data:" column in <scanner_dir>/alert/<rule>.txt (applied at PINNED:5317).

### `DELI-044` Local alert file as the uncapped offset record

*supporting* · on `xsoar`

- **Must be true** — For each matched file the alert file records a COMPLETE uncapped 'Hits per string ID' census while individual offsets are truncated to MAX_ALERT_OFFSETS_PER_FINDING with an explicit omission footer naming the knob.
- **Threshold** — census counts per string ID equal the true YARA hit counts exactly (verified with `yara -s` on one decoy); rendered offset lines per finding <= 50 at the default; when truncation occurs the footer is present and its omitted count == census_total - 50; with YARA_MAX_ALERT_OFFSETS=0 no truncation and no footer.
- **Setup** — Flood pack on thor including a rule that hits a Windows event log thousands of times; re-run one case with YARA_MAX_ALERT_OFFSETS=0 on a single small target to check the no-cap inverse.
- **Evidence** — <scanner_dir>/alert/<rule>.txt — the "Hits per string ID: ..." line (PINNED:5307), the offset block, and the footer "N further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=cap). Counts above are complete; ..." (PINNED:5324-5325). Note the directory is `alert` (singular), PINNED:2761.

### `DELI-045` No in-memory retention of per-offset detail

*supporting* · on `xsoar`

- **Must be true** — Process RSS stays flat with respect to total matched-offset count — the uploader keeps only bounded samples and counters, never a per-offset dict — and no per-offset JSON artefact is written.
- **Threshold** — peak RSS <= 600 MB and peak/median RSS ratio < 2.0 while total offsets exceed 500,000; RSS shows no monotone growth correlated with offset count (Pearson r < 0.5); zero files matching *results*.json or *matches*.json under <scanner_dir>.
- **Setup** — Thor flood tuned to produce >500k offsets (event logs); sample RSS every 5s from a parallel SSH session, and read total offsets afterwards from the alert-file censuses.
- **Evidence** — psutil RSS of the scanner PID sampled over SSH during the flood (or system_resource_snapshot proc_memory_mb with the monitor enabled), plotted against cumulative offsets from the alert-file censuses; directory listing of <scanner_dir> for any per-offset JSON.

### `DELI-046` Six per-category log files as the local delivery record

*supporting* · on `xsoar`, `thor`

- **Must be true** — Every run writes exactly six run-scoped category logs under <scanner_dir>/logs sharing one run_id, in the fixed "[ts.ms] [LEVEL] message" format, and uploads_<run_id>.log exists locally only.
- **Threshold** — exactly 6 category files present for the run's run_id; all six paths appear in data.log_files_created; first line of each parses against ^\[\d{4}-.*\] \[(INFO\|WARNING\|ERROR\|DEBUG)\] ; zero rows in the tenant carry type=="upload".
- **Evidence** — Listing of /opt/yara_scanner/logs after the run: alerts_, statistics_, scan_errors_, performance_, uploads_, system_ each suffixed <run_id>.log (paths PINNED:1843-1849), plus scan_summary_<run_id>.json; paths echoed in the Logging Summary event's data.log_files_created.

### `DELI-047` Upload channels can be disabled independently

*low* · on `xsoar`

- **Must be true** — The effective values of the two module-level channel switches are visible on the wire in scanner_initialization and are consistent with what each channel actually delivered.
- **Threshold** — data.upload_enabled == true and data.telemetry_upload_enabled == true on the shipped payload; match_delivery.successful_uploads > 0 and telemetry_delivery.summary.successful_uploads > 0, i.e. the echo is not contradicted by the books.
- **Setup** — None beyond the round. Note the disabled branches are NOT covered: their evidence lines live in the dead ResultsUploader.upload_results() (PINNED:3515/3557, no callers), and the switches have no env override, so proving the disabled path needs the log_manager wiring described in the capability's observe field.
- **Evidence** — XQL type="scanner_initialization" fields data.upload_enabled (UPLOAD_RESULTS) and data.telemetry_upload_enabled (UPLOAD_NON_MATCH_DATA); cross-checked against match_delivery and telemetry_delivery in scan_summary_<run_id>.json.

### `DELI-048` Queue-full handling on the findings channel

*supporting* · on `xsoar`

- **Must be true** — No finding is dropped for queue pressure — both upload queues are unbounded — so the 'Upload queue full' line never appears under a flood, and backlog is instead visible in the drain-time accounting.
- **Threshold** — occurrences of the queue-full line == 0 across both flood hosts; the drain line's N > 0 on at least one host, proving backlog existed and was still not dropped; match_delivery totals account for every finding.
- **Evidence** — uploads_<run_id>.log searched for "Upload queue full - skipping real-time upload for finding" (PINNED:3493); backlog evidence in "Waiting for N pending match uploads (max Ms)..." (PINNED:3358) and the leftover/undelivered block (PINNED:3391-3399).

### `DELI-049` Host identity (hostname / os_info / ipAddress) stamped on every uploaded event

*supporting* · on `xsoar`

- **Must be true** — Every uploaded row, the summary JSON and the evidence file_mapping header carry the same host identity triple, and on macOS the Darwin-major table resolves to a named release rather than the fallback string.
- **Threshold** — all rows for one scan_id share identical hostname/os_info/ipAddress; the three artefacts agree; on OfficeiMac (Darwin 24) os_info contains "Sequoia" and not "macOS (Darwin"; ipAddress on xsoar == 192.168.20.29 and is never "::1" nor a string starting "Unable to determine IP address".
- **Setup** — Run on both xsoar and OfficeiMac; read file_mapping.txt out of the evidence ZIP over SSH on each host.
- **Evidence** — Wire: top-level hostname, os_info, ipAddress on every StandardLogEntry. Local: scan_summary_<run_id>.json fields hostname/os_info/ip_address; evidence/file_mapping.txt header block "Host Information: / Hostname: / OS: / IP Addresses:". Source get_os_info() PINNED:372, get_system_info() PINNED:395, failure sentinel PINNED:408.

### `DELI-050` Second, non-canonical scan_id inside the "Scan configuration established" payload

*supporting* · on `xsoar`

- **Must be true** — The scan_config_data payload ships an inner scan_id of the form <hostname>_<YYYYmmdd_HHMMSS> that does not equal the envelope scan_id, so no consumer may join on it — a documented wart that must be confirmed present and confined to this one event.
- **Threshold** — data.scan_id != envelope scan_id; data.scan_id matches ^<hostname>_\d{8}_\d{6}$ with no microseconds and no _yara_ suffix; no other event type for the run carries a data.scan_id disagreeing with its envelope.
- **Evidence** — XQL type="statistics" with message=="Scan configuration established": compare data.scan_id against the row's envelope scan_id (inner built at PINNED:5876, canonical at PINNED:2808). Locally the same dict appears in statistics_<run_id>.log, showing both id forms in one file.

### `DELI-051` Uncapped per-rule detection breakdown in comprehensive_final_report

*supporting* · on `xsoar`

- **Must be true** — detection_breakdown ships one key per rule that fired with no cap, so under a broad rule pack this single event's payload grows linearly with the number of triggering rules — bounded only by the pack.
- **Threshold** — len(detection_breakdown) == unique_rules_triggered exactly; len(top_10_rules) == min(10, unique_rules_triggered); with a 300-rule flood pack the serialized detection_breakdown exceeds 5 KB — record the measured byte size as the regression baseline; alerts_<run_id>.log shows only 10 keys.
- **Setup** — Build the flood pack with at least 300 distinct rule names that all match, so an uncapped map is visibly different from a capped one.
- **Evidence** — XQL comprehensive_final_report: data.detection_results.detection_breakdown (PINNED:6101, uncapped) vs data.detection_results.top_10_rules (PINNED:6102, sliced to 10) vs data.detection_results.unique_rules_triggered; local twin top_10_detections in alerts_<run_id>.log (PINNED:5549).

### `DELI-052` efficiency_score formula (what the 0-100 number in the final report actually means)

*supporting* · on `xsoar`

- **Must be true** — efficiency_score is exactly 100 - (files_skipped/files_processed)*20 - (failed_rules/total_rules)*30, recomputable from fields in the same payload, and therefore never a health score and never below 50.
- **Threshold** — \|data.efficiency_score - recomputed\| <= 0.1; data.efficiency_score >= 50 on every run including the whole-filesystem scan that skips most files; the value in message equals the field value.
- **Setup** — Whole-filesystem xsoar scan (high skip rate) plus a rule pack containing at least one deliberately uncompilable rule, so both penalty terms are non-zero.
- **Evidence** — XQL comprehensive_final_report: data.efficiency_score (PINNED:6136-6145) recomputed from data.file_processing (files_skipped/files_processed) and data.rule_compilation (failed/valid); message "Comprehensive scan report - Efficiency Score: N/100" (PINNED:6154); local line in statistics_<run_id>.log (PINNED:6162).

### `DELI-054` LogManager's telemetry books over-count: total_logs increments before the upload gate

*supporting* · on `xsoar`

- **Must be true** — total_logs counts local log lines, not events handed to the wire — it is incremented before the upload gate — so total_logs strictly exceeds successful+failed by at least the upload-category count and must never be used as a delivery denominator.
- **Threshold** — total_logs_generated - (webhook_successful_uploads + webhook_failed_uploads) >= logs_by_type["upload"] and > 0 on every run; on a black-hole run the gap grows and the derived "success rate" in the message reads below 100% even though nothing was lost locally.
- **Setup** — Compare the healthy flood run against the black-hole flood run; no code change needed. The bare-except drop path at PINNED:1988-1989 is NOT covered — it has no realistic trigger and would leave no artefact, so proving it would need a dropped counter that does not exist.
- **Evidence** — Logging Summary system event data.total_logs_generated, data.webhook_successful_uploads, data.webhook_failed_uploads, data.logs_by_type (counter at PINNED:1977-1978, gate at PINNED:1980-1981, by_type map).

### `DELI-056` file_creation_time is null on most Linux filesystems (platform-asymmetric derivation)

*supporting* · on `xsoar`

- **Must be true** — The same planted file matched by the same rule yields a non-null file_creation_time and a `File Creation Time:` alert line on thor (Windows), and null with no such line on xsoar (Linux/ext4).
- **Threshold** — thor: >=1 finding with file_creation_time matching ^\d{4}-\d{2}-\d{2}T and >=1 alert file containing 'File Creation Time:'. xsoar: 100% of findings have file_creation_time == null and 0 alert files contain that string.
- **Setup** — Plant one byte-identical decoy file at a scanned path on both hosts so the same flood rule matches it on both; run the flood pack on both.
- **Evidence** — data.file_creation_time on the `yara_match` event (payload 3489) and data.file_creation_time on the per-file `alert` event; alert text C:\yara_scanner\alert\<rule>.txt vs /opt/yara_scanner/alert/<rule>.txt, line written at 5294 guarded at 5293.

### `DELI-057` Per-finding "Queued finding for upload" receipt in the uploads log (only local view of the truncated flag)

*supporting* · on `xsoar`

- **Must be true** — Every finding successfully queued writes exactly one `Queued finding for upload:` receipt, and the ` (truncated)` suffix appears if and only if that finding's hit count exceeds MAX_MATCH_SAMPLES_PER_FINDING (50), agreeing with the wire's data.truncated and a 50-entry decoded data.offsets.
- **Threshold** — count(receipt lines) == count(yara_match events for this scan_id); for every receipt carrying '(truncated)': match_count > 50 and len(json.loads(data.offsets)) == 50 exactly; for every receipt without it: len(json.loads(offsets)) == match_count; 0 occurrences of 'Upload queue full - skipping real-time upload'.
- **Setup** — Flood pack containing at least one rule whose string hits >50 times per file (e.g. a 1-2 byte string) plus one condition-only rule, run on xsoar and thor with a healthy collector.
- **Evidence** — /opt/yara_scanner/logs/uploads_<run_id>.log lines `Queued finding for upload: rule='X', file=Y, hits=N` (3487-3490) and `Added N local result entries for rule ...` (3496-3499); wire: yara_match data.truncated, data.match_count, data.offsets (JSON-encoded string, json.dumps at 3475).

### `DELI-058` performance_summary / performance_metrics blocks in the two terminal events

*supporting* · on `xsoar`

- **Must be true** — On a default long scan the performance block is present but structurally empty (peak/avg CPU and memory 0.0, current_performance null); with YARA_ENABLE_PERF_MONITOR=true the CPU/memory fields become non-zero and current_performance non-null, while io_efficiency stays 0.0 in both.
- **Threshold** — Run A (default): performance_summary.performance_metrics.peak_cpu_percent == 0.0, avg_cpu_percent == 0.0, peak_memory_mb == 0.0, current_performance is null, and the 'disabled in light profile' line present. Run B (monitor on): peak_cpu_percent > 0 and current_performance != null and that line absent. Both runs: performance_metrics.io_efficiency == 0.0.
- **Setup** — Two long scans on xsoar under the same competing load: one default, one with YARA_ENABLE_PERF_MONITOR=true.
- **Evidence** — data.performance_summary on the `comprehensive_final_report` event (set at 6126) and data.performance_metrics on `scan_completion_summary` (comprehensive_final_stats key, 6480/6497); locally the same dicts in /opt/yara_scanner/logs/statistics_<run_id>.log, plus the line `Performance monitoring disabled in light profile` (1602).

## Lifecycle (18)

### `LIFE-015` Honest undelivered accounting after the drain window

***core*** · on `xsoar`

- **Must be true** — Findings still queued when the drain window expires are counted as 'undelivered' (never attempted), distinct from 'failed_uploads', and the books balance against the number of findings queued.
- **Threshold** — successful_uploads + failed_uploads + undelivered == count of 'Queued finding for upload' receipt lines; on the black-holed run undelivered > 0 and the error line's N equals match_delivery.undelivered exactly; on the healthy flood run undelivered == 0 and failed_uploads == 0.
- **Setup** — Two flood runs on xsoar: one with a healthy collector, one with the endpoint black-holed so the drain expires with items queued.
- **Evidence** — /opt/yara_scanner/logs/uploads_<run_id>.log `Match delivery final: matches=… ok=… failed=… undelivered=…` (3395-3397) and the error line `N match upload(s) undelivered within the drain window` (3399-3401); `match_delivery` block in scan_summary_<run_id>.json.

### `LIFE-016` Idempotent uploader stop

*supporting* · on `xsoar`

- **Must be true** — ResultsUploader.stop() pays exactly one drain window per run despite being called from both cleanup and main()'s finally, while the webhook uploader stays alive long enough for the two terminal events to be queued after scan_system returns.
- **Threshold** — Exactly 1 'Match delivery final:' line per run; both terminal event types present exactly once for the scan_id; the elapsed time between the first drain announcement and the summary file mtime is <= one drain budget, not two.
- **Setup** — Same flood runs; no extra setup.
- **Evidence** — Count of `Match delivery final:` lines in /opt/yara_scanner/logs/uploads_<run_id>.log (3395); presence at the collector of `comprehensive_final_report` and `scan_completion_summary` events for the run's scan_id.

### `LIFE-017` scan_status lifecycle values and the terminal status

*supporting* · on `xsoar`

- **Must be true** — The local status trail contains the ordered non-terminal sequence and always ends with a terminal value that matches the run's outcome and result verb.
- **Threshold** — The sequence initializing -> starting_workers -> scanning -> finishing appears as an ordered subsequence; the LAST 'Scan status changed to' line is 'cancelled' on the cancel run, 'completed' on the clean run, 'failed' on the SIGINT run; that value equals scan_summary.outcome in every run.
- **Setup** — Read diagnostics_<run_id>.log for each round-3 variant (clean, cancelled, SIGINT, excluded-target).
- **Evidence** — /opt/yara_scanner/logs/diagnostics_<run_id>.log lines `Scan status changed to: <value>` (logging.info at 3638, handler installed at 6055-6057); `outcome` in scan_summary_<run_id>.json; the SCAN_RESULT verb.

### `LIFE-018` scan_status event payload

*supporting* · on `xsoar`

- **Must be true** — Every scan_status event carries the six base timing fields and elapsed_time_seconds increases monotonically across the phase sequence; the optional scanner_stats fields never appear, because set_status() is the sole caller and passes no stats.
- **Threshold** — All 6 base keys present on 100% of events; elapsed_time_seconds non-decreasing when events are ordered by scan_status phase; the 'finishing' event's elapsed_time_seconds > 300 on the long run; files_scanned/detections_found/current_file/scan_rate_files_per_second absent from every event (0 occurrences).
- **Setup** — Long (>10 min) scan on xsoar under competing load with a healthy collector; query the collector by scan_id.
- **Evidence** — Collector events of type 'scan_status' for the run's scan_id: data.{scan_id, scan_status, scan_start_time, current_time, elapsed_time_seconds, elapsed_time_formatted} (built 3575-3581); the scanner_stats block at 3584-3596 has no live caller (only call site is set_status at 3639).

### `LIFE-021` scan_completion_summary metrics block

*supporting* · on `xsoar`

- **Must be true** — Exactly one scan_completion_summary per run carries the full metrics block, with internally consistent counts and an error_summary derived from the skip-reason census.
- **Threshold** — Exactly 1 event per scan_id; all 12 keys present; files_processed == files_scanned + files_skipped; total_detections == scan_summary.matches; unique_rules_triggered == scan_summary.unique_rules_triggered; error_summary.scan_errors == sum of skip_reasons counts whose key contains 'error' (read from the statistics log).
- **Setup** — Flood run on xsoar with a healthy collector (large detection and skip counts make the consistency checks meaningful).
- **Evidence** — Collector event type='scan_completion_summary', data keys scan_duration_seconds, scan_duration_formatted, files_processed, files_scanned, files_skipped, total_detections, unique_rules_triggered, performance_metrics, webhook_upload_stats, log_generation_stats, error_summary{compilation_errors, scan_errors}, outcome (built 6485-6501).

### `LIFE-027` scan_summary_<run_id>.json artefact

***core*** · on `xsoar`

- **Must be true** — Every run that constructs a YaraScanner writes exactly one atomically-created scan_summary JSON, with no .tmp orphan left behind; a run that dies before the scanner is constructed writes none.
- **Threshold** — For clean, cancelled and SIGINT runs: exactly one summary file per run_id, json.load succeeds, and no scan_summary_<run_id>.json.tmp remains in logs/. For the alert_severity='bogus' run: no summary file for that run_id.
- **Setup** — Compare the logs directory listing after each round-3 variant.
- **Evidence** — /opt/yara_scanner/logs/scan_summary_<run_id>.json (written 2210-2231); system_<run_id>.log `Scan summary written: scan_summary_<run_id>.json` or scan_errors `Failed to write scan summary JSON:` / `Scan summary write failed:`.

### `LIFE-028` scan_summary field contract

***core*** · on `xsoar`

- **Must be true** — The summary carries the full header plus body contract, and its cross-cutting values agree with the result line and the delivery log.
- **Threshold** — All 9 header + 19 body keys present (note: the capability text omits alert_bytes_written / alert_detail_suppressed / alert_dir_max_bytes - they ARE written and must be asserted); schema == 'yara_scan_summary/v1' and edition == 'xsiam'; rule_hash is a 64-hex sha256 of the decoded rule text; matches equals the result line's match count; match_delivery equals the 'Match delivery final' numbers; scan_rate_fps == round(files_scanned/duration_secs, 2).
- **Setup** — Parse the summary from every round-3 variant plus the round-2 flood runs.
- **Evidence** — /opt/yara_scanner/logs/scan_summary_<run_id>.json - header keys schema/edition/run_id/scan_id/rule_hash/hostname/os_info/ip_address/scanner_version (2212-2221) and body keys outcome, failure_reasons, scan_folder, scan_targets, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, alert_bytes_written, alert_detail_suppressed, alert_dir_max_bytes, match_delivery, telemetry_delivery (6764-6784).

### `LIFE-029` Duration derivation for the summary

*supporting* · on `xsoar`

- **Must be true** — duration_secs is an honest elapsed value on both the normal path (scan_total_time) and the abnormal path where the run returned before scan_total_time was computed (time.time() - scan_start_time) - never 0 and never absent when scan_start_time was set.
- **Threshold** — Clean and cancelled runs: duration_secs > 0 and within 3s of the externally measured wall time. SIGINT run (which returns from the fatal branch at 6470, before main's scan_total_time is assigned at 6477, so the fallback branch is taken): duration_secs > 0, not null, and within 5s of the measured time from launch to SIGINT+shutdown.
- **Setup** — Record wall-clock launch and exit times over SSH for the clean, cancelled and SIGINT runs and compare against the field.
- **Evidence** — `duration_secs` in /opt/yara_scanner/logs/scan_summary_<run_id>.json (derived at 6753-6755).

### `LIFE-030` Operator result line composition

*supporting* · on `xsoar`

- **Must be true** — The result line is assembled from the mandatory stem plus each optional segment exactly when its condition holds, and each segment's numbers match the corresponding summary field.
- **Threshold** — Stem matches `^(Scan completed\|Scan cancelled \(source=[^)]+\)): \d+ files scanned \\| \d+ rules failed compilation( \\| \d+ rules skipped \(module unavailable\))? \\| \d+ matches found`; each optional segment appears in exactly the run that provokes it and in no other (module-skipped rules, ' \| Upload errors: N', ' \| WARNING: N of M finding upload(s) NOT delivered', ' \| WARNING: N requested target(s) EXCLUDED by the skip list'); every number in the line equals the matching scan_summary field.
- **Setup** — Round-3 variants plus one run with a rule pack containing a rule importing an unavailable module (e.g. `import "magic"` on the 3.11.0 libyara on xsoar), and one run whose targets include /proc.
- **Evidence** — The `SCAN_RESULT: ` stdout line / Action Center result field (composed at 6645-6647).

### `LIFE-032` Match-channel delivery shortfall on the result line

***core*** · on `xsoar`

- **Must be true** — When findings are lost, the result line names the loss as items-out-of-items (failed + undelivered over ok+failed+undelivered) and the numbers agree with the summary's match_delivery block.
- **Threshold** — Black-holed flood run: the segment is present, N == match_delivery.failed_uploads + match_delivery.undelivered, M == successful_uploads + N, and M equals the count of 'Queued finding for upload' receipts (NOT match_delivery.total_matches, which counts offsets). Healthy flood run: segment absent and match_delivery.failed_uploads == undelivered == 0.
- **Setup** — Two flood runs on xsoar, one with the collector black-holed, one healthy; ensure at least 50 distinct rule/file findings so N and M are unambiguous.
- **Evidence** — The `SCAN_RESULT: ` line segment ` \| WARNING: N of M finding upload(s) NOT delivered (failed=…, undelivered=…) - local logs hold the complete record` (6603-6608); `match_delivery` in scan_summary_<run_id>.json.

### `LIFE-033` Telemetry upload-error surfacing

*supporting* · on `xsoar`

- **Must be true** — Telemetry (non-finding) upload failures are surfaced on the result line and on stdout, with the count matching the summary's telemetry_delivery book.
- **Threshold** — Black-holed flood run: segment present with n == telemetry_delivery.failed_uploads and n > 0; stdout WARNING block present with the same N. Healthy run: segment absent and telemetry_delivery.failed_uploads == 0.
- **Setup** — Same two flood runs (black-holed vs healthy) on xsoar; capture full stdout, not just the SCAN_RESULT line.
- **Evidence** — Result-line segment ` \| Upload errors: <n>` (or ' \| Upload errors: unknown'); stdout two-line 'WARNING: N upload operations failed' block; `telemetry_delivery.failed_uploads` in scan_summary_<run_id>.json.

### `LIFE-052` Final results log with failure-aware label

*supporting* · on `xsoar`

- **Must be true** — The final results entry carries the correct label for the run's outcome and a complete set of totals, plus the top-rule, skip-reason and per-worker breakdowns.
- **Threshold** — Clean run: label == 'SCAN COMPLETED', no failure_reasons key, all of total_time_seconds/files_scanned/files_skipped/total_detections/average_scan_rate/detection_rate/skip_rate/junction_skips/unique_paths_scanned/path_deduplication_ratio present and non-null, and N in the worker summary == scanner_initialization max_workers. Broken-pack run: label == 'SCAN FAILED' with len(failure_reasons) >= 1.
- **Setup** — Compare the clean xsoar whole-FS run against the deliberately-broken-rule-pack run already needed for the compilation-fatal criterion.
- **Evidence** — <scanner_dir>/logs/statistics_<run_id>.log 'SCAN COMPLETED \| Time: ... \| Files: ... \| Detections: ... \| Rate: ...' (label chosen at PINNED_xsiam_current.py:5525) or the same line prefixed 'SCAN FAILED' in scan_errors_<run_id>.log with failure_reasons attached (:5535); 'Top detection rules: ...' (:5545); 'Skip reasons: ...' (:5556); performance_<run_id>.log 'Worker performance summary: N workers processed files' (:5570).

### `LIFE-054` Comprehensive final report event

*supporting* · on `xsoar`

- **Must be true** — Every completed run ships exactly one comprehensive_final_report whose sections are internally consistent with the local logs and whose efficiency_score follows the documented formula.
- **Threshold** — Exactly 1 such event per scan_id; file_processing.scanned/skipped equal scan_summary_<run_id>.json files_scanned/files_skipped exactly; rule_compilation.valid + failed == total; efficiency_score == max(0, 100 - skip_rate*20 - rule_failure_rate*30) recomputed from the same numbers, within 0.1; resource_summary present iff YARA_ENABLE_RESOURCE_MONITOR was true; zero 'Error generating comprehensive final report' lines.
- **Setup** — Run the xsoar whole-FS scan once with YARA_ENABLE_RESOURCE_MONITOR=true and once false, and recompute the score from the event's own fields.
- **Evidence** — Collector event type='comprehensive_final_report' with message 'Comprehensive scan report - Efficiency Score: X/100' (PINNED_xsiam_current.py:6149-6154) and sections scan_metadata / file_processing / detection_results / rule_compilation / system_info / performance_summary / [resource_summary] / upload_summary / efficiency_score (:6136-6145); the identical statistics_<run_id>.log line 'COMPREHENSIVE SCAN REPORT \| Efficiency Score: ...' (:6162); failure line 'Error generating comprehensive final report: ...'.

### `LIFE-056` Per-run identity: run_id, scan_id, rule_hash

*supporting* · on `xsoar`

- **Must be true** — Two runs of the same ruleset — on one host or on two — produce two distinct scan_ids, while rule_hash stays identical for identical rule text.
- **Threshold** — Across 2 sequential xsoar runs plus 1 OfficeiMac run with the identical pack: 3 distinct scan_id values and 3 distinct run_ids; scan_id matches ^<hostname>_\d{8}_\d{6}_\d{6}_yara_[0-9a-f]{12}$; rule_hash identical across all 3 and equal to `sha256` of the decoded rule text computed independently; no collector event carries a scan_id belonging to a different run.
- **Setup** — Run the same base64 pack twice on xsoar back-to-back and once on OfficeiMac; compute sha256 of the decoded rule text locally for comparison.
- **Evidence** — scan_summary_<run_id>.json fields run_id, scan_id and rule_hash; the <category>_<run_id>.log filenames under <scanner_dir>/logs; the scan_id carried on every collector event (ScanConfig.__init__ run_id/rule_hash/scan_id).

### `LIFE-057` Six per-run category logs plus two lazy diagnostic logs

*supporting* · on `xsoar`, `thor`

- **Must be true** — Each run opens exactly the six category logs plus yara_processing, all stamped with the run_id, and creates script_exceptions only when something actually threw.
- **Threshold** — Clean run: exactly 7 files matching *_<run_id>.log, no script_exceptions_<run_id>.log, and zero of them contain an 'upload' event forwarded back to the collector (no collector event whose type maps to the UPLOAD category). Run that throws: 8 files, script_exceptions_<run_id>.log non-empty. All 7/8 files opened mode='w' (a re-run with the same run_id is impossible, so assert first-line timestamp is within the run window).
- **Setup** — ls the logs dir immediately after each of the round-3 runs (clean whole-FS, and the broken-pack run that raises).
- **Evidence** — `ls <scanner_dir>/logs/*_<run_id>.log` — expect alerts_, statistics_, scan_errors_, performance_, uploads_, system_ (mapped at PINNED_xsiam_current.py:1844-1849), yara_processing_ (:1248), and script_exceptions_ only lazily (:1444); plus scan_summary_<run_id>.json.

### `LIFE-058` Logging summary at shutdown

*supporting* · on `xsoar`

- **Must be true** — Shutdown drains the webhook queue and reports a truthful upload tally whose successes plus failures equals the total logs forwarded.
- **Threshold** — Exactly 1 'Logging Summary' line per run (idempotent stop_logging, even though __del__ also calls it); X + Y == the number of webhook-forwarded logs; Z == round(X/(X+Y)*100); X + Y matches scan_summary telemetry_delivery attempted count within 0; under the FP flood Y == 0 on a healthy tenant.
- **Setup** — Round-2 flood on xsoar and thor with the match-everything pack; count events at the tenant for the scan_id and compare to X.
- **Evidence** — Last lines of <scanner_dir>/logs/system_<run_id>.log: 'Logging Summary \| Total Logs: N \| Webhook Uploads: X successful, Y failed \| Success Rate: Z%' (PINNED_xsiam_current.py:2188), plus the per-type counts and log-file map; cross-check against the telemetry_delivery book in scan_summary_<run_id>.json.

### `LIFE-059` Artefact retention across runs (bounded observability window)

*supporting* · on `xsoar`

- **Must be true** — initial_cleanup prunes per-run logs, scan summaries and orphaned .json.tmp files down to the configured number of newest run_ids, always keeping the current run.
- **Threshold** — NOTE the capability's 'keep_scans=2' is STALE — pinned :351-357 makes it LOG_KEEP_SCANS = _env_number('YARA_LOG_KEEP', 10, minimum=0). Run 4 scans with YARA_LOG_KEEP=2: after the 4th, exactly 2 distinct run_ids remain across logs/*.log AND logs/scan_summary_*.json, the current run_id is one of them, and a planted logs/scan_summary_19700101_000000_000000.json.tmp is gone. With the default (unset), all 4 survive.
- **Setup** — On xsoar, plant a fake orphaned .json.tmp with a valid run_id pattern, then run 4 short scans with YARA_LOG_KEEP=2 exported, listing logs/ between each.
- **Evidence** — Root-logger info 'Log retention applied: kept last N scans (M run IDs including current), removed X log files' (PINNED_xsiam_current.py:4111) and warnings 'Cannot remove log file (in use): ...'; the contents of <scanner_dir>/logs before and after; regex `_(\d{8}_\d{6}_\d{6})\.(?:log\|json\|json\.tmp)$` (:4066-4089).

### `LIFE-060` Root-logger quieting during a scan

*supporting* · on `xsoar`

- **Must be true** — A CLI run prints nothing on stdout until the single SCAN_RESULT line, while WARNING/ERROR still reach stderr.
- **Threshold** — On a clean run: out.txt contains exactly 1 non-empty line and it starts 'SCAN_RESULT: '. With YARA_MAX_MB=-1 also set: out.txt still has exactly 1 line, and err.txt contains the 'Ignoring out-of-range YARA_MAX_MB' warning. Counter-case (documented defect): on a run that hits main()'s critical-error path, out.txt has 4+ lines — assert that separately, do not let it pass silently here.
- **Setup** — Round-3 xsoar run invoked over SSH with stdout and stderr redirected to separate files.
- **Evidence** — Captured stdout and stderr of the process, separated (`... > out.txt 2> err.txt`); setup_logging's root-handler strip and WARNING pin; the SCAN_RESULT print at PINNED_xsiam_current.py:6837.

---

# Round 3 — Precision and resilience

**Endpoints:** `xsoar`, `OfficeiMac`, `thor`  
**On failure:** collect-through  
**Capabilities:** 113 (18 core)

**Scenario.** Whole-filesystem scans with planted decoys, malformed and module-dependent rule packs, symlink/junction traps, permission-denied paths, and a mid-run cancellation. Run on Linux, macOS and Windows for the platform-divergent paths.

**Why these belong together.** Correctness and failure handling need adversarial input. A clean scan cannot distinguish 'handles malformed rules' from 'never saw one'.

## Rules (38)

### `RULE-001` Base64-only rule input

***core*** · on `xsoar`

- **Must be true** — A rule pack delivered with a `b64:` prefix, embedded newlines, the URL-safe alphabet (`-`/`_`) and stripped `=` padding decodes to text byte-identical to the same pack delivered as canonical base64, while plain-text YARA is rejected outright.
- **Threshold** — rule_hash identical across all four lenient encodings of one pack and valid_rules equal in each; plain-text delivery produces exactly one VALIDATION_ERROR line, 0 files scanned and exit code 1.
- **Setup** — Deliver the same small 3-rule pack four times to xsoar: (a) canonical base64, (b) `b64:`-prefixed, (c) base64 with newlines every 64 chars, (d) URL-safe alphabet with all `=` padding stripped. Then a fifth run passing the raw YARA text unencoded.
- **Evidence** — /opt/yara_scanner/logs/yara_processing_<run_id>.log line `Using YARA rules from provided parameter` (written at line 2789); `rule_hash` and `valid_rules` in /opt/yara_scanner/logs/scan_summary_<run_id>.json; for the plain-text delivery, `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations` (line 665) and the stdout SCAN_RESULT/exit code.

### `RULE-003` Typed rule-input rejection codes

*supporting* · on `xsoar`

- **Must be true** — Each of the three pre-compile input failures writes its own distinct prefix token and no other, so the failure mode is machine-identifiable from the log alone.
- **Threshold** — Each of the three runs logs its own prefix exactly once and the other two prefixes zero times; all three exit non-zero with 0 files scanned.
- **Setup** — Three deliveries to xsoar: (a) yarafile = whitespace-only string; (b) yarafile = a 5-character base64 alphabet string such as `AAAAA` (re-padding yields a length that binascii rejects, forcing DECODE_ERROR); (c) yarafile = base64 of the text `this has no rule declarations`.
- **Evidence** — /opt/yara_scanner/logs/yara_processing_<run_id>.log - exactly one of `INPUT_ERROR: Empty YARA rules content provided` (line 644), `DECODE_ERROR: Base64 decode failed: ...` (653), `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations` (665).

### `RULE-004` Empty embedded ruleset guard

*supporting* · on `xsoar`

- **Must be true** — Invoking the scanner with no yarafile aborts the run rather than scanning the filesystem with zero rules.
- **Threshold** — files_scanned == 0, exit code != 0, and no scan_summary reporting a completed scan; the ValueError text appears exactly once.
- **Setup** — Run the payload on xsoar with the yarafile parameter omitted entirely (not empty-string - omitted, so the default YARA_RULE path is taken).
- **Evidence** — /opt/yara_scanner/logs/yara_processing_<run_id>.log `Using YARA rules from default configuration` followed by `CRITICAL: Failed to decode YARA rules: Default YARA_RULE is empty - must provide yarafile parameter` (raise at line 2794); stdout SCAN_RESULT line and exit code.

### `RULE-005` Comment- and string-aware pack parser

*supporting* · on `xsoar`

- **Must be true** — A `rule` keyword appearing inside a `//` comment, inside a `/* */` block, inside a double-quoted string literal, or inside a rule body is never counted or extracted as a rule declaration.
- **Threshold** — Both N values equal the true declared-rule count (5 in the planted pack) exactly - not 5+decoys - and failed extractions == 0.
- **Setup** — Plant a 5-rule pack containing: one `// rule fake_a` line comment, one `/* rule fake_b */` block comment, one string `$s = "rule fake_c {"`, and one rule body containing the word `rule` in a meta field.
- **Evidence** — /opt/yara_scanner/logs/diagnostics_<run_id>.log line `Found N rule start positions` (line 4784) and `Rule extraction complete: N successful, M failed` (4808); the system event `YARA Rules loaded: N rules, M imports` with data.total_rules_found in /opt/yara_scanner/logs/system_<run_id>.log (emitted line 6391).

### `RULE-006` private / global rule modifier capture

*supporting* · on `xsoar`

- **Must be true** — A rule declared `private rule X` or `global rule X` is extracted starting at the modifier keyword, so the modifier survives into the compiled source and the block passes the sanity regex.
- **Threshold** — valid_rules counts the private and global rules (valid_rules == 3 for the planted pack), zero "doesn't start with 'rule' keyword" warnings, and the failed_rule artifact's body starts with the literal `private`.
- **Setup** — Pack with `private rule P {...}`, `global rule G {...}`, one plain rule, plus one deliberately-broken `private rule PBad` (missing closing brace on its condition) to force the failed_rules artifact.
- **Evidence** — /opt/yara_scanner/failed_rules/failed_rule_<name>.yar (the deliberately-broken private rule) - its rule text must begin with `private rule`; absence of any `Rule <name> doesn't start with 'rule' keyword` warning (line 4441) in /opt/yara_scanner/logs/diagnostics_<run_id>.log and on stderr; `valid_rules` in scan_summary_<run_id>.json.

### `RULE-007` Pack splitting into preamble + individual rules

*supporting* · on `xsoar`

- **Must be true** — One syntactically broken rule in a multi-rule pack does not prevent the remaining rules from compiling and scanning.
- **Threshold** — valid_rules == 9 and failed_rules == 1 for a 10-rule pack with exactly one broken rule; the scan still reaches files_scanned > 0 and exit code 0.
- **Setup** — 10-rule pack where rule #4 has a syntax error (`condition: $a and`), the other 9 are valid and one of them matches a planted file.
- **Evidence** — COMPILATION SUMMARY block in /opt/yara_scanner/logs/yara_processing_<run_id>.log (`Total rules processed`, `Valid rules compiled`, `Failed rules skipped`, lines 1418-1426); `valid_rules` / `failed_rules` in scan_summary_<run_id>.json; per-rule files under /opt/yara_scanner/failed_rules/.

### `RULE-008` Duplicate import de-duplication in the preamble

*supporting* · on `xsoar`

- **Must be true** — Repeating the same import statement across many rules produces one preamble import, and every rule still compiles.
- **Threshold** — `Found N unique import statements` reports 1 while the system event's import_statements reports the raw count (20); valid_rules == 20; the preamble block in the failed_rule artifact contains `import "pe"` exactly once.
- **Setup** — 20-rule pack where every rule is preceded by its own `import "pe"` line, plus one deliberately-broken rule so a failed_rule artifact (and thus the preamble text) is written.
- **Evidence** — /opt/yara_scanner/logs/diagnostics_<run_id>.log line `Found N unique import statements` (line 4776 - now durable, root logger writes INFO to the diagnostics handler installed at line 6057); `import_statements` in the `YARA Rules loaded` system event; the preamble reproduced at the top of any /opt/yara_scanner/failed_rules/failed_rule_*.yar.

### `RULE-009` include statements passed through verbatim

*supporting* · on `xsoar`

- **Must be true** — An `include "..."` line is copied into the shared preamble unchanged and is never stripped by the module-availability filter, so a missing included file fails every rule rather than being silently dropped.
- **Threshold** — failed_rules == total rule count (3) and valid_rules == 0 when the included file is absent; the include line appears verbatim in every failed_rule artifact preamble.
- **Setup** — 3-rule pack headed by `include "/opt/yara_scanner/does_not_exist.yar"`, no such file created.
- **Evidence** — Preamble text at the top of /opt/yara_scanner/failed_rules/failed_rule_*.yar must contain the verbatim include line; libyara's `can't open include file` in the `=== RULE COMPILATION FAILURE #n ===` blocks of yara_processing_<run_id>.log; `failed_rules` in scan_summary_<run_id>.json.

### `RULE-010` Rule block sanity check

*supporting* · on `xsoar`

- **Must be true** — An extracted block that does not match the `^\s*(?:(?:private\|global)\s+)*rule\s+\w+` guard is dropped with a warning and counted in neither the valid nor the failed tally.
- **Threshold** — valid_rules + failed_rules == total_rules_found minus the number of dropped blocks, and that difference equals the count of "doesn't start with 'rule' keyword" lines.
- **Setup** — Pack whose rule discovery finds a block whose cleaned content loses its header - e.g. a rule whose declaration line is entirely inside a `/* */` that closes mid-block - so the cleaned text fails the guard regex.
- **Evidence** — stderr and /opt/yara_scanner/logs/diagnostics_<run_id>.log line `Rule <name> doesn't start with 'rule' keyword` (line 4441); `valid_rules` + `failed_rules` in scan_summary_<run_id>.json vs `total_rules_found` in the `YARA Rules loaded` system event.

### `RULE-011` Unnamed-rule fallback naming

*low* · on `xsoar` · **reachability probe** — assert only that the branch is reached, not that it behaves; two triage passes called this dead and one of them was already proved wrong

- **Must be true** — A rule whose name token is not a valid identifier is given a positional placeholder name and is still reported and written to disk rather than vanishing.
- **Threshold** — Exactly one placeholder-named failure block and one matching failed_rule_rule_<n>.yar exist; failed_rules in scan_summary counts it.
- **Setup** — Pack containing `rule 7bad { condition: true }` (name starts with a digit) among 4 valid rules.
- **Evidence** — `Rule Name: rule_<n>` inside a `=== RULE COMPILATION FAILURE #n ===` block in /opt/yara_scanner/logs/yara_processing_<run_id>.log (written at line 1370) and the file /opt/yara_scanner/failed_rules/failed_rule_rule_<n>.yar.

### `RULE-012` Agent module-availability probe

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — The probe reports the module set of this agent's own libyara build, and a module imported by the pack but outside the hardcoded probe list is still probed and reported.
- **Threshold** — The line is present exactly once per run; it lists a module that appears only in the pack's imports and not in ['pe','elf','cuckoo','magic','hash','math','dotnet','time']; and the xsoar (libyara 3.11.0) list differs from the OfficeiMac (4.1.0) list for the same pack.
- **Setup** — Include `import "console"` (or another module outside the probe list) in the pack; run the same pack on both xsoar and OfficeiMac and diff the two lines.
- **Evidence** — `Available YARA modules: ...` in /opt/yara_scanner/logs/yara_processing_<run_id>.log (line 4559) and in logs/diagnostics_<run_id>.log (4558).

### `RULE-013` cuckoo-availability callout

*supporting* · on `xsoar`

- **Must be true** — When the agent's libyara lacks the cuckoo module, a dedicated warning names cuckoo specifically rather than only appearing in the generic available-modules list.
- **Threshold** — On any endpoint whose `Available YARA modules:` line omits cuckoo, both lines are present exactly once; on an endpoint where cuckoo is present, neither line appears.
- **Evidence** — `YARA cuckoo module not available` in /opt/yara_scanner/logs/yara_processing_<run_id>.log (line 4563) and `YARA cuckoo module not available - rules using it will be skipped` on stderr (4562).

### `RULE-014` Unavailable preamble imports stripped

*supporting* · on `xsoar`

- **Must be true** — A file-level import naming a module the agent lacks is removed from the shared preamble, so rules that never reference that module still compile.
- **Threshold** — valid_rules == 4 (the cuckoo-free rules) and skipped_rules == 1 (the rule that actually uses cuckoo) for the planted pack; the stripped import string is absent from the reproduced preamble.
- **Setup** — Pack headed by `import "cuckoo"` on xsoar (libyara 3.11.0, no cuckoo), with 4 rules that never mention cuckoo, 1 rule that does, and 1 deliberately-broken rule to force a failed_rule artifact carrying the preamble.
- **Evidence** — `valid_rules` / `skipped_rules` in /opt/yara_scanner/logs/scan_summary_<run_id>.json; the preamble block at the top of any /opt/yara_scanner/failed_rules/failed_rule_*.yar must no longer contain the stripped import.

### `RULE-015` Pre-compile skip for rules importing missing modules

*supporting* · on `xsoar`

- **Must be true** — A rule carrying its own import for an unavailable module is counted as skipped, never as failed, and its text is preserved on disk.
- **Threshold** — skipped_rules == 3 and failed_rules == 0 for a pack of 3 self-importing cuckoo rules plus valid rules; one skipped_rule_*.yar per skipped rule; zero failed_rule_*.yar for those names.
- **Setup** — Pack with 3 rules each carrying their own `import "cuckoo"` inside the rule block, run on xsoar.
- **Evidence** — /opt/yara_scanner/failed_rules/skipped_rule_<rulename>_<module>.yar (written at lines 4614-4618) whose first line is `// SKIPPED RULE - Module '<mod>' not available`; log line `Skipping rule '<name>': uses unavailable module '<mod>'` (4611-4612) in yara_processing_<run_id>.log; `skipped_rules` / `failed_rules` in scan_summary_<run_id>.json.

### `RULE-016` Post-compile reclassification of inherited-import failures

*supporting* · on `xsoar`

- **Must be true** — A rule that fails only because it inherited a stripped preamble import is reclassified from failed to skipped, while a rule that merely contains the literal module name in a string is not.
- **Threshold** — The inheriting rule contributes to skipped_rules and produces no failed_rule_*.yar; the decoy rule whose only cuckoo reference is the string "cuckoo.conf" compiles and counts toward valid_rules (not skipped).
- **Setup** — Pack headed by `import "cuckoo"` on xsoar containing: rule A whose condition uses `cuckoo.network.http_request(...)` with no own import (inherits), and decoy rule B whose strings include `$s = "cuckoo.conf"` and whose condition is `$s`.
- **Evidence** — /opt/yara_scanner/failed_rules/skipped_rule_<rulename>_<module>.yar carrying `// (import inherited from the file-level preamble)` (lines 4661-4665); log line `Skipping rule '<name>': needs unavailable module '<mod>' (inherited from a file-level import)` (4656); `failed_rules` / `skipped_rules` in scan_summary_<run_id>.json.

### `RULE-017` Automatic import injection from module usage

*supporting* · on `xsoar`

- **Must be true** — A rule that references an available module by prefix without importing it has the import prepended before compilation, and therefore compiles.
- **Threshold** — One auto-injection line per affected rule (uncapped - 12 rules yield 12 lines), and valid_rules includes all 12; the same pack with injection unavailable would show them as undefined_identifier failures.
- **Setup** — 12-rule pack with no imports at all, each rule's condition using a different available prefix (`pe.`, `hash.`, `math.`, `elf.`, `time.`), run on xsoar.
- **Evidence** — `Auto-injected missing imports for rule '<name>': pe, hash` in /opt/yara_scanner/logs/yara_processing_<run_id>.log (line 4634); `valid_rules` in scan_summary_<run_id>.json.

### `RULE-018` Per-rule trial compile then namespaced whole-pack compile

*supporting* · on `xsoar`

- **Must be true** — The number of rules handed to the final namespaced yara.compile equals valid_rules, and the failed/skipped counts reported alongside it reconcile with the summary JSON.
- **Threshold** — N == valid_rules, M == failed_rules, K == skipped_rules, exactly - all three cross-checked against the SCAN_RESULT line in the same run.
- **Setup** — Use the mixed pack from the split-isolation and module-skip setups (valid + broken + cuckoo-importing rules) so all three counters are non-zero.
- **Evidence** — /opt/yara_scanner/logs/diagnostics_<run_id>.log line `Successfully built ruleset with N rules` with ` (M failed)` and ` (K skipped - missing modules)` appended when non-zero (built at lines 4732-4738, emitted 4738); `valid_rules`/`failed_rules`/`skipped_rules` in scan_summary_<run_id>.json; the SCAN_RESULT stdout line.

### `RULE-019` Duplicate rule names survive

*supporting* · on `xsoar`

- **Must be true** — Two rules sharing one name both compile (via per-rule namespacing) and both fire on a matching file, with match totals counting both hits while the unique-rule tally counts the name once.
- **Threshold** — valid_rules includes both copies; for a single matched file, matches increments by 2 while unique_rules_triggered counts the shared name once.
- **Setup** — In the flood pack, include two rules both named `flood_dup` with different string sets, both of which match the planted decoy file; run on xsoar and thor.
- **Evidence** — `valid_rules`, `matches` and `unique_rules_triggered` in /opt/yara_scanner/logs/scan_summary_<run_id>.json; `yara_match` upload events for that rule name; /opt/yara_scanner/alert/<rule>.txt.

### `RULE-020` Duplicate-name caveat in the rule-source map

*supporting* · on `xsoar`

- **Must be true** — With duplicate rule names, the condition-only explanation text is drawn from the LAST occurrence in the source, and the map holds one entry for the shared name.
- **Threshold** — The explanation quotes evidence unique to the second `flood_dup` definition (e.g. its distinctive meta purpose string) and never the first's.
- **Setup** — Make both `flood_dup` copies condition-only (no strings) with different `meta: purpose = "..."` values, the second carrying a distinctive marker token.
- **Evidence** — The `Condition Match Details:` block in /opt/yara_scanner/alert/<rule>.txt (written at line 5342); map built by _build_yara_rule_source_map keyed on lowercased name (lines 500-510 region, called from YaraScanner.__init__).

### `RULE-022` Per-file externals at match time

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — The four externals are populated per scanned file with the normalised path, its lowercase form, the basename and its lowercase form, so a filename-conditioned rule actually fires on the right file and only on it.
- **Threshold** — The `filename_lower == "yara_decoy_marker.bin"` rule fires on exactly the planted decoy and on zero other files on both hosts; the Windows-form rule (`filepath_lower contains "c:\\yara_decoys\\"`) fires on thor and not on xsoar, and the POSIX-form rule the reverse.
- **Setup** — Plant /opt/yara_decoys/yara_decoy_marker.bin on xsoar and C:\yara_decoys\yara_decoy_marker.bin on thor; include three externals-based rules in the flood pack: basename-equality, a backslash path fragment, and a forward-slash path fragment.
- **Evidence** — /opt/yara_scanner/alert/<rule>.txt file_path field and the `yara_match` upload event's file path; match call at line 5015-5018 using _build_yara_match_externals (894).

### `RULE-023` Non-short-circuiting match callback

*supporting* · on `xsoar`

- **Must be true** — Evaluation does not stop at the first matching rule - every rule that matches a file produces its own finding.
- **Threshold** — For a control file crafted to match all 12 flood rules, matches increments by 12 and 12 distinct alert/<rule>.txt files exist naming that file - not 1.
- **Setup** — Plant one control file containing every flood rule's trigger string; ensure it is inside the scanned scope on both xsoar and thor.
- **Evidence** — One /opt/yara_scanner/alert/<rule>.txt per triggered rule; one `yara_match` upload event per rule/file finding; `matches` and `unique_rules_triggered` in scan_summary_<run_id>.json; callback returning yara.CALLBACK_CONTINUE at lines 5110-5114, passed at 5018.

### `RULE-024` Condition-only (no-strings) rule support

*supporting* · on `xsoar`

- **Must be true** — A rule that matches on condition alone still produces a complete finding with a generated human-readable explanation and correctly zeroed string counters.
- **Threshold** — For every condition-only finding: match_scope == "rule", string_match_count == 0, offset == "", match_count == 1, and the Condition Match Details text names the MZ/PE check and the pe.imports function names from the rule source; no `Matched Strings` block present.
- **Setup** — Include in the flood pack a condition-only rule with `meta` purpose/severity/scope/author, tags, an `uint16(0) == 0x5A4D` check and two `pe.imports("kernel32.dll","...")` calls; guarantee PE files in scope on thor.
- **Evidence** — `Condition Match Details:` block in /opt/yara_scanner/alert/<rule>.txt (line 5342); the `yara_match` upload event fields `match_scope: "rule"` (line 3473), `offset: ""`, `match_count: 1`, `string_match_count: 0`, message `YARA rule-only match: rule '<r>' in <file>` (3457); is_rule_only_match derived at line 3420.

### `RULE-025` Per-rule compilation-failure diagnostics

*supporting* · on `xsoar`

- **Must be true** — Each failing rule yields a categorised diagnosis in the log AND - now that config.log_manager is bound before rules compile - a telemetry error event carrying the rule name, analysis and error line number.
- **Threshold** — For a 4-rule broken pack (one each of invalid pe field, syntax error, undefined identifier, duplicate definition): 4 failure blocks with 4 distinct diagnosis categories, `<-- ERROR HERE` on the line libyara reported, and 4 corresponding error events - event count == failed_rules.
- **Setup** — Craft one rule per failure category: `pe.no_such_field`, `condition: $a and`, a bare undefined identifier, and a rule redefining an identifier within itself.
- **Evidence** — `=== RULE COMPILATION FAILURE #n ===` blocks with `Rule Name:`, `Error:`, numbered source and `<-- ERROR HERE` in /opt/yara_scanner/logs/yara_processing_<run_id>.log (lines 1370-1392); the `YARA rule compilation failed: <rule>` error event with error_analysis / error_line_number / rule_length_lines / compilation_failure_number, gated at line 1397 on config.log_manager which main() binds at line 6206 before YaraScanner compiles at 6405.

### `RULE-026` failed_rules/ artifact directory

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — Every rule that fails to compile is written as a standalone reproducible .yar containing an error header, ISO timestamp, the shared preamble and the rule text.
- **Threshold** — For each of the 4 broken rules a matching failed_rule_*.yar exists whose preamble+rule text, saved locally and run through `yarac`, reproduces the same libyara error; counters remain the authority (writes are best-effort try/except).
- **Setup** — Same 4-category broken pack; pull the files off xsoar over SSH and re-compile them locally.
- **Evidence** — /opt/yara_scanner/failed_rules/failed_rule_<name>.yar (written 4682-4686) with header `// FAILED RULE - Compilation Error` and `// Error: ...`; also skipped_rule_<name>_<module>.yar and raw_yara_content.yar; dir created at line 2763/2765.

### `RULE-027` failed_rules/ is never pruned

*supporting* · on `xsoar`

- **Must be true** — Artifacts under failed_rules/ survive subsequent scans - initial_cleanup touches only alert_dir, evidence_dir and the output log, and log retention only touches logs/ - so they carry no run attribution.
- **Threshold** — After a second scan with a different broken pack, the first pack's failed_rule_*.yar files are all still present (count strictly increases, zero deletions), and no filename carries a run_id.
- **Setup** — Run the round-3 broken pack after rounds 1 and 2 have already deposited failed-rule artifacts on xsoar; snapshot the directory before and after over SSH.
- **Evidence** — Directory listing and mtimes of /opt/yara_scanner/failed_rules/ across runs; cleanup path list at lines 4122-4126; the ISO timestamp inside each file header.

### `RULE-030` Three-way valid / failed / skipped accounting

*supporting* · on `xsoar`

- **Must be true** — Skipped rules (agent libyara lacks the module) are booked separately from genuine compile failures, so a mostly-skipped pack cannot read as a clean zero-failure run.
- **Threshold** — For a pack of 5 valid + 3 broken + 4 cuckoo rules on xsoar: valid_rules == 5, failed_rules == 3, skipped_rules == 4; the SCAN_RESULT line carries both the `3 rules failed compilation` and `4 rules skipped (module unavailable)` clauses; a pack with zero skips omits the skipped clause entirely.
- **Setup** — Deliver the mixed 12-rule pack to xsoar, then a clean pack to confirm the skipped clause disappears.
- **Evidence** — `valid_rules`, `failed_rules`, `skipped_rules` in /opt/yara_scanner/logs/scan_summary_<run_id>.json (written at lines 6774-6777); the stdout SCAN_RESULT line's `... \| N rules failed compilation \| K rules skipped (module unavailable) \| ...` (skipped clause built at 6622-6623, present only when K > 0).

### `RULE-031` Compilation summary block

*supporting* · on `xsoar`

- **Must be true** — A fixed-format summary closes the compile phase with total processed (valid+failed only, excluding skips), valid, failed, success rate, and the failed-rules directory path when anything failed.
- **Threshold** — Total rules processed == valid_rules + failed_rules and explicitly EXCLUDES skipped_rules; Success rate == valid/(valid+failed)*100 to one decimal; the directory path line present iff failed_rules > 0.
- **Setup** — Same mixed 12-rule pack, where the excluded-skip arithmetic is visible (12 declared, 8 processed).
- **Evidence** — The `====`-delimited `COMPILATION SUMMARY` block in /opt/yara_scanner/logs/yara_processing_<run_id>.log with `Total rules processed:`, `Valid rules compiled:`, `Failed rules skipped:`, `Success rate: X.X%` (lines 1418-1426) and `Failed rules saved to: <path>` (1429).

### `RULE-032` All-skipped vs all-failed fatal distinction

*supporting* · on `xsoar`

- **Must be true** — When nothing compiles, the fatal message distinguishes an agent capability limit (skips, no failures, with the available module list quoted) from broken rule syntax, and both abort.
- **Threshold** — All-cuckoo pack on xsoar: message contains "agent capability limit", Skipped == N, Failed == 0. All-broken pack: message does NOT contain "agent capability limit", Failed == N, Skipped == 0. Both exit non-zero with 0 files scanned.
- **Setup** — Two runs on xsoar: (a) 4 rules all importing cuckoo, (b) 4 rules all with syntax errors.
- **Evidence** — stderr `CRITICAL: YARA rule compilation failed: No rules could run on this endpoint: all N rule(s) need YARA modules this agent's libyara build does not provide (available: ...). This is an agent capability limit, not a rule syntax error.` followed by `Valid rules: 0, Failed rules: 0, Skipped: N` (line 4725); `FINAL_COMPILATION_ERROR:` with the same text in yara_processing_<run_id>.log (4723).

### `RULE-034` Rule-pack hash and scan_id derivation

*supporting* · on `xsoar`

- **Must be true** — scan_id is `<hostname>_<run_id>_yara_<first 12 hex of SHA-256 of the decoded rule text>`, so the ruleset stays identifiable while every host and every re-run gets a distinct id.
- **Threshold** — Across xsoar and OfficeiMac running the identical pack, the hash12 segment is identical and equals sha256(decoded_text).hexdigest()[:12] computed independently; the hostname and run_id segments differ; two runs on one host share hash12 and differ in run_id; every uploaded event in a run carries that exact scan_id.
- **Setup** — Run the same pack twice on xsoar and once on OfficeiMac; compute the SHA-256 locally from the same decoded text.
- **Evidence** — `Scan ID: <host>_<run_id>_yara_<hash12> (rule hash: <hash12>...)` in /opt/yara_scanner/logs/yara_processing_<run_id>.log (line 2809); `scan_id` and full `rule_hash` in scan_summary_<run_id>.json (fields set at 2215-2216); the scan_id field on every uploaded event.

### `RULE-035` Rule/import census at initialization

*supporting* · on `xsoar`

- **Must be true** — The decoded pack is counted for rule declarations, import statements and character length before compilation, giving a pre-compile baseline against which pack attrition is measurable.
- **Threshold** — total_rules_found == the true declared-rule count of the pack (12), import_statements == the raw import count, rule_content_length == len(decoded text) exactly; and total_rules_found - valid_rules == failed_rules + skipped_rules + dropped blocks.
- **Setup** — Use the mixed 12-rule pack so attrition is non-zero.
- **Evidence** — System event `YARA Rules loaded: N rules, M imports` with data `{total_rules_found, import_statements, rule_content_length}` in /opt/yara_scanner/logs/system_<run_id>.log (emitted at line 6391 from the counts built at 6381-6389).

### `RULE-036` Brace-balance sanity check

*supporting* · on `xsoar`

- **Must be true** — An unbalanced brace count across the pack raises an advisory warning without blocking compilation, and the supporting per-line detail is now durably written to the diagnostics log.
- **Threshold** — For a pack with one missing closing brace: exactly one BRACE MISMATCH line, the `Total braces` line shows X == Y+1, and the run still proceeds to compile (valid_rules > 0) rather than aborting.
- **Setup** — Truncate the final rule of an otherwise-valid 5-rule pack mid-body so one `}` is lost.
- **Evidence** — stderr and /opt/yara_scanner/logs/diagnostics_<run_id>.log line `BRACE MISMATCH DETECTED!` (line 5408); the accompanying `Import statements: N` and `Total braces: X opening, Y closing` INFO lines (5400-5405), which reach diagnostics_<run_id>.log via the FileHandler installed at line 6057 - the older claim that they are suppressed is stale.

### `RULE-037` Console-noise caps on rule diagnostics

*supporting* · on `xsoar`

- **Must be true** — Console/warning output for skipped and failed rules is capped at 10 each while the on-disk record stays complete, so stderr line counts are never a valid rule tally.
- **Threshold** — With a 30-broken-rule pack: exactly 10 failed-rule stderr lines, 30 failure blocks in the log, 30 failed_rule_*.yar files, and failed_rules == 30 in scan_summary; stderr count != failed_rules.
- **Setup** — 30-rule pack, every rule syntactically broken in a distinct way, plus 15 cuckoo-importing rules on xsoar to also exercise the skip cap.
- **Evidence** — stderr `Failed rule <name>: <first 100 chars>` lines (capped at line 4691-region by the `failed_rules_count <= 10` guard) and `Skipping rule '<name>'...` lines (guard at 4611); versus `=== RULE COMPILATION FAILURE #n ===` blocks in yara_processing_<run_id>.log and files under /opt/yara_scanner/failed_rules/; per-50 progress line at 4644 now landing in diagnostics_<run_id>.log.

### `RULE-038` Rule-count propagation into scan telemetry

*low* · on `xsoar` · **reachability probe** — assert only that the branch is reached, not that it behaves; two triage passes called this dead and one of them was already proved wrong

- **Must be true** — Compilation results reach every telemetry surface consistently, and the final report's efficiency_score is reduced by the rule failure rate.
- **Threshold** — All four surfaces report the same valid/failed pair in one run and it equals scan_summary_<run_id>.json's valid_rules/failed_rules; none of them carries skipped_rules (only SCAN_RESULT and scan_summary do); efficiency_score for the mixed pack is at least 1 point below, and at most 30 points below, an all-valid control run.
- **Setup** — Run the mixed 12-rule pack and an all-valid control pack on xsoar and diff the two telemetry sets.
- **Evidence** — `YaraScanner initialized with N workers` event data {valid_rules, failed_rules} (built at line 4418); `scan_status` event fields valid_rules_count / failed_rules_count; `Scan configuration established` statistics event fields yara_rules_count / failed_rules_count; the comprehensive_final_report block `rule_compilation: {valid_rules_loaded, failed_rules_skipped, total_rules_processed, compilation_success_rate}` plus efficiency_score - all in /opt/yara_scanner/logs/system_<run_id>.log and on the wire.

### `RULE-039` Diagnostic-preserving cleanup suppression

*low* · on `xsoar` · **reachability probe** — assert only that the branch is reached, not that it behaves; two triage passes called this dead and one of them was already proved wrong

- **Must be true** — When rule compilation yields zero valid rules, the run leaves its own artefacts intact: no cleanup script is written to disk and no cleanup task/service is scheduled.
- **Threshold** — scan_summary.valid_rules == 0 AND cleanup_script.sh absent from scanner_dir (ls returns nothing) AND `systemctl list-units \| grep -i yara` returns no cleanup unit AND the suppression line appears exactly once. Control leg (valid rules present, alerts found): cleanup_script.sh IS written with mode 0755.
- **Setup** — Extra round-3 leg on xsoar: submit a rule pack in which every rule fails to compile (each rule body `condition: undefined_identifier_xyz`), so error_logger.has_errors is true and valid_rules_count == 0. Verify the filesystem over SSH, not just via Action Center output.
- **Evidence** — logs/diagnostics_<run_id>.log line `No valid YARA rules compiled - skipping cleanup to preserve diagnostics` (PINNED_xsiam_current.py:4184 — NOTE the observe field's quoted text `Critical errors detected - skipping cleanup to preserve diagnostic data` is STALE and does not exist in the pinned source); logs/system_<run_id>.log line `Cleanup skipped due to critical YARA processing errors` (6547); absence of <scanner_dir>/cleanup_script.sh (path built at 2811-2812); `valid_rules` in logs/scan_summary_<run_id>.json.

### `RULE-040` YARA runtime version banner

*supporting* · on `xsoar`

- **Must be true** — The processing log's opening banner and the scanner_initialization event report the same, correct interpreter and libyara identity for the agent that actually ran.
- **Threshold** — `YARA Version:` == 3.11.0 on xsoar and 4.1.0 on OfficeiMac; the banner value equals the event's `yara_version` byte-for-byte; the literal `Unknown` must not appear on either host; `Platform:` names the correct kernel (5.4.0-216 on xsoar, Darwin arm64 on OfficeiMac) — this is the anti-wrong-host check.
- **Evidence** — Head of logs/yara_processing_<run_id>.log: `=== YARA Processing Log ===`, `Python Version: ...`, `Platform: ...`, `YARA Version: ...` (1287-1290); `python_version` / `yara_version` in the scanner_initialization event data (6117-6118) and in the final report's system_info (6353-6354).

### `RULE-041` Lenient base64 rule-payload decoding (b64: prefix, URL-safe, unpadded)

*supporting* · on `xsoar`

- **Must be true** — The same ruleset submitted as canonical padded base64, unpadded, URL-safe-alphabet and `b64:`-prefixed decodes to byte-identical rule text and yields one identical rule_hash, while raw un-encoded YARA text is rejected with a logged error and no scan_summary.
- **Threshold** — 4 of 4 encodings produce one identical rule_hash; scan_id differs per run but the trailing `_yara_<12 hex>` component is identical across all four; the raw-plaintext leg emits exactly one of the two error lines, writes NO logs/scan_summary_<run_id>.json, and exits with `SCAN_STATUS: ERROR`.
- **Setup** — Five short xsoar runs with scan_folder pointed at one small planted decoy directory. Legs 1-4 submit the identical 3-rule pack encoded as: canonical padded, padding stripped, URL-safe alphabet (`-`/`_`), and `b64:`-prefixed with embedded newlines. Leg 5 submits the same rules as raw un-encoded YARA text.
- **Evidence** — `rule_hash` in logs/scan_summary_<run_id>.json (written at 2216) compared across the four runs; `scan_id` (2808) for the suffix check; on the negative leg, logs/yara_processing_<run_id>.log `DECODE_ERROR: Base64 decode failed: ...` (653) or `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations` (665).

### `RULE-042` Condition-only match explanation mined from the rule's own source text

*supporting* · on `xsoar`

- **Must be true** — A rule that fires with zero string instances still produces a populated explanation carrying the meta dump and the correct `Condition evidence:` clause, and that same sentence is the `string` field of its yara_match event with match_scope 'rule' and an empty offset.
- **Threshold** — For a strings-less rule with `uint16(0) == 0x5A4D and pe.imports("kernel32.dll","CreateRemoteThread")`: the block contains all three notes — 'checks for an MZ/PE header', 'references imports: CreateRemoteThread', 'uses the PE module for structural checks'. For a strings-less rule with `filesize < 100`: the block exists but contains NO `Condition evidence:` clause. For a reversed `0x5A4D == uint16(0)` rule: no MZ note (order-sensitive regex, 599). Event side: match_scope == 'rule', offset == '', match_count == 1, and `string` equals the alert-file block text exactly.
- **Setup** — Add three strings-less rules to the flood pack run on thor (PE targets): (a) MZ + two-arg pe.imports, (b) `filesize < 100`, (c) reversed `0x5A4D == uint16(0)`. Each must carry purpose/severity/scope/author meta and one tag so the meta dump is also exercised.
- **Evidence** — <scanner_dir>/alert/<rule>.txt block written under `Condition Match Details:` (5342-5345); yara_match event fields `match_scope`, `offset`, `string`, `match_count` (3470-3476).

### `RULE-043` yara-python version shim for match strings (3.x tuples vs 4.x StringMatch instances)

*supporting* · on `xsoar`

- **Must be true** — One flood pack produces byte-for-byte identical offset / string-id / data triples on the yara 3.11.0 Linux agent and the yara 4.1.0 Windows agent, with no sentinel values leaking into alerts or the wire.
- **Threshold** — Across xsoar (yara 3.11.0) and thor (yara 4.1.0): zero occurrences of `String ID: unknown`; zero occurrences of `Offset: -1`; for the byte-identical planted decoy the `Hits per string ID` map and the full offset list are identical on both hosts; `Total string hits` counts OFFSETS not distinct identifiers — a rule whose single `$a` occurs 3 times must report `Total string hits: 3` and `Hits per string ID: $a=3`.
- **Setup** — Plant one byte-identical decoy file on both xsoar and thor containing a known ASCII string at exactly 3 known offsets, and include a matching single-string rule in the flood pack. Fix YARA_MAX_ALERT_OFFSETS high enough (>=50) that the cap does not confound the comparison.
- **Evidence** — <scanner_dir>/alert/<rule>.txt: `Total string hits: N`, `Hits per string ID: $a=3, ...` (5306-5308) and each `String ID:` / `Offset:` / `Data:` block (5318-5320); yara_match event fields `offsets`, `strings`, `match_ids`, `string_match_count`, `truncated` (3474-3478); `total_string_matches` on the merged scan alert (5364).

## Traversal (36)

### `TRAV-001` Explicit scan folder parameter

***core*** · on `xsoar`

- **Must be true** — Any scan_folder value other than the literal 'default' (case-insensitive) confines the run to that path and is reported as limited scope in the log, the event and the summary.
- **Threshold** — With scan_folder=/opt/yara_decoys: scan_summary.scan_targets == ['/opt/yara_decoys'] exactly (length 1, absolute), scan_summary.scan_folder == '/opt/yara_decoys', the `Limited to specified targets` line present and the `Full system scan` line absent, and 100% of paths in logs/alerts_<run_id>.log are under /opt/yara_decoys. A control leg with scan_folder='DEFAULT' (upper case) must produce the `Full system scan` line — proving the .lower() gate.
- **Setup** — Plant /opt/yara_decoys on xsoar with one matching file; run one leg with scan_folder=/opt/yara_decoys and one with scan_folder='DEFAULT'.
- **Evidence** — logs/system_<run_id>.log `SCAN SCOPE: Limited to specified targets: [...]` (6375) versus `SCAN SCOPE: Full system scan (light profile throttling enabled)` (6377); `scan_targets` in the scanner_initialization event; `scan_folder` and `scan_targets` in logs/scan_summary_<run_id>.json (6767-6768).

### `TRAV-002` Comma-separated multi-target list

*supporting* · on `xsoar`

- **Must be true** — A single comma-separated scan_folder covers every listed location, with whitespace and surrounding single/double quotes stripped and empty entries dropped.
- **Threshold** — For scan_folder=` /opt/decoy_a , "/opt/decoy_b" ,,'/srv/decoy_c' ` : N == 3, target_count == 3, exactly 3 `Scanning target` lines numbered 1/3..3/3, scan_targets == ['/opt/decoy_a','/opt/decoy_b','/srv/decoy_c'] in that order with no quote characters, and at least one alert entry originating from each of the three.
- **Setup** — Plant /opt/decoy_a, /opt/decoy_b and /srv/decoy_c on xsoar, each holding exactly one matching file, and pass them as one comma list with leading/trailing whitespace, mixed quoting and one empty entry.
- **Evidence** — logs/yara_processing_<run_id>.log `Scan limited to N folder(s): [...]` (3047); `target_count` in the `Scan configuration established` statistics event (5876-5879, logs/statistics_<run_id>.log); one `Scanning target i/N: <path>` line per entry in logs/system_<run_id>.log (5931); `scan_targets` in logs/scan_summary_<run_id>.json.

### `TRAV-003` Per-target validation with independent rejection

*supporting* · on `xsoar`

- **Must be true** — An invalid entry in a multi-target list is named in a warning and dropped while every valid sibling is still scanned, and duplicate entries collapse to one target.
- **Threshold** — For scan_folder=`/opt/decoy_a,/opt/decoy_a,/opt/does_not_exist`: the warning names exactly ['/opt/does_not_exist'] with N == 1; scan_summary.scan_targets has length 1 (dedupe by abspath); scan_summary.outcome == 'completed'; the /opt/decoy_a match IS reported.
- **Setup** — Same planted decoys as the multi-target leg; add one deliberately non-existent path and one exact duplicate.
- **Evidence** — logs/yara_processing_<run_id>.log warning `Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]` (3043-3046) immediately followed by `Scan limited to N folder(s): [...]` (3047); `scan_targets` in logs/scan_summary_<run_id>.json.

### `TRAV-004` Hard failure when no requested target is valid

***core*** · on `xsoar`

- **Must be true** — When no comma-separated entry passes the isdir test the run aborts with an error instead of silently escalating to a whole-machine scan.
- **Threshold** — stderr contains `SCAN_STATUS: ERROR`; no scan_summary JSON exists for the run_id; NO `Scanning target` line was ever written (proving no fallback walk of `/` began); process exits in < 30s; no alert/ or evidence/ content produced.
- **Setup** — Round-3 leg on xsoar with scan_folder='/opt/nope,/srv/also-nope'.
- **Evidence** — stderr `SCAN_STATUS: ERROR` and stdout `CRITICAL ERROR: ...` from main's except block (6650-6660); the ValueError text `No valid scan directory among the specified scan folder(s): [...]` (3040-3041); absence of any logs/scan_summary_<run_id>.json for that run_id (write_scan_summary is guarded on scanner is not None).

### `TRAV-005` Windows whole-machine default target discovery

*supporting* · on `thor`

- **Must be true** — On Windows with scan_folder=default the discovered target set is exactly the fixed drive roots present on the box, de-duplicated and each terminated with a backslash.
- **Threshold** — The list equals the set returned by `Get-Volume \| ? DriveType -eq 'Fixed'` on thor; no duplicates under normcase(normpath); every entry ends with `\`; the hardcoded `['C:\\']` fallback (3100-3103) appears only if discovery genuinely found nothing. target_count == len(scan_targets).
- **Setup** — Short thor leg with scan_folder='default' and a rule pack that cannot match (e.g. a 64-byte random string), cancelled via control/cancel.flag as soon as the scanner_initialization event lands. Do NOT let a full C:\ walk run on thor's large attached disk — the discovery line is written during ScanConfig.__init__, seconds in.
- **Evidence** — logs\yara_processing_<run_id>.log `Light profile full-scope targets on Windows: ['C:\\', ...]` (3105); `targets` / `target_count` in the `Scan configuration established` statistics event (5876-5879); `scan_targets` in logs\scan_summary_<run_id>.json.

### `TRAV-006` Linux default target discovery (privilege-aware)

*supporting* · on `xsoar`

- **Must be true** — The default Linux scope matches the run's privilege exactly: `/` alone as root, otherwise only the readable subset of the five fallback roots.
- **Threshold** — Root leg (Action Center): exactly one of the three lines, the root variant, and scan_targets == ['/']. Non-root leg (SSH as LINUX_USER): the accessible-targets variant, scan_targets is a non-empty subset of ['/home','/tmp','/opt','/usr/local','/var/tmp'], and every entry independently passes `test -r` for that user; no path outside that set appears.
- **Setup** — Run the round-3 whole-filesystem scan on xsoar twice with scan_folder=default: once via Action Center (root) and once over paramiko SSH as LINUX_USER (non-root). Confirm euid per leg with `id -u` captured in the same session.
- **Evidence** — logs/yara_processing_<run_id>.log — `Light profile default scope on Linux: full filesystem` (3115) \| `Light profile default scope on Linux using accessible full-scan targets: [...]` (3131) \| warning `Light profile default scope fell back to '/' on Linux - many files may be inaccessible` (3127); `scan_targets` in logs/scan_summary_<run_id>.json.

### `TRAV-007` macOS default target discovery (privilege-aware)

*supporting* · on `OfficeiMac`

- **Must be true** — The default macOS scope matches the run's privilege: `/` plus the SIP note as root, otherwise the readable subset of home / Applications / Users Shared / usr local / opt, falling back to home alone.
- **Threshold** — Root leg: both root lines present and scan_targets == ['/']. Non-root leg: scan_targets is a non-empty subset of [$HOME,'/Applications','/Users/Shared','/usr/local','/opt'] with every entry readable by that user, and no unreadable entry present. Exactly one of the three branch lines is emitted per run.
- **Setup** — Run OfficeiMac with scan_folder=default under Action Center (root) and once as the console user. OfficeiMac is the only macOS in either tenant — do NOT substitute Abdelrahman's MacBook Air.
- **Evidence** — logs/yara_processing_<run_id>.log — `Light profile default scope on macOS: full filesystem` plus `Note: SIP restrictions still apply to /System/` (3142-3143) \| `Light profile default scope on macOS using accessible full-scan targets: [...]` (3152) \| `Light profile default scope on macOS fell back to the user home directory only` (3157); `scan_targets` in logs/scan_summary_<run_id>.json.

### `TRAV-009` Excluded-target warning (requested target wholly skipped)

*supporting* · on `xsoar`

- **Must be true** — A requested target that the skip list excludes wholesale is explicitly named as excluded rather than reported as an indistinguishable clean zero.
- **Threshold** — Leg A (scan_folder=/proc on xsoar): excluded_targets == ['/proc'], files_scanned == 0, the error-log line appears exactly once, and the WARNING clause is present on the result line. Leg B (scan_folder=/proc,/sys,/dev,/run): excluded_targets has 4 entries, the result line names exactly the first 3 and ends with ' ...'.
- **Setup** — Two extra short round-3 legs on xsoar with scan_folder='/proc' and scan_folder='/proc,/sys,/dev,/run' — all four are lin_skip_directory entries (2890-2901).
- **Evidence** — logs/scan_errors_<run_id>.log `Requested scan target is excluded by the skip list, so nothing under it will be scanned: <path>` with data `{'reason': 'skip_list'}` (5938-5943); the returned SCAN_RESULT line's ` \| WARNING: N requested target(s) EXCLUDED by the skip list, nothing under them was scanned: ...` (6629-6634); `excluded_targets` in logs/scan_summary_<run_id>.json (6769).

### `TRAV-010` Non-root system-path pre-flight advisory

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — A non-root run whose requested folders touch a privileged root logs the advisory and the privilege_status event, and still proceeds to scan rather than aborting.
- **Threshold** — Non-root leg with scan_folder='/etc' on xsoar: all advisory lines present, privilege_status.running_as_root == false and recommended_action == 'run_as_sudo', AND scan_summary.outcome == 'completed' with files_scanned > 0 (advisory only, not a hard stop). Root control leg: none of the advisory lines is emitted and running_as_root == true.
- **Setup** — SSH into xsoar as LINUX_USER (paramiko, password from .env — sshpass is not installed) and run with scan_folder='/etc'; on OfficeiMac run the same as the console user with scan_folder='/Library'.
- **Evidence** — logs/system_<run_id>.log `ERROR: System path scan requires elevated privileges` (6263) plus `Either run as root (sudo) or grant Full Disk Access` / `Either run as root or choose a different scan path` (6265); a `privilege_status` event with data `{'running_as_root': false, 'recommended_action': 'run_as_sudo'}` (6271-6281).

### `TRAV-012` Symlinked directories listed but never recursed

*supporting* · on `xsoar`

- **Must be true** — A directory symlink is listed in dirnames but never descended, so its contents are neither scanned twice nor able to create a traversal loop.
- **Threshold** — With /opt/decoy_real/hit.bin (matching) and /opt/decoy_scope/link -> /opt/decoy_real and /opt/decoy_scope/loop -> /opt/decoy_scope, scanning scan_folder=/opt/decoy_scope: exactly 0 alert entries (the real file is not under the scoped target and the link is not followed), and the loop causes no hang — `Target scan completed` for /opt/decoy_scope is emitted within 30s. With scan_folder=/opt/decoy_real,/opt/decoy_scope: exactly 1 alert entry, whose path is under /opt/decoy_real, never under /opt/decoy_scope/link.
- **Setup** — Plant /opt/decoy_real with one matching file, plus /opt/decoy_scope/link -> /opt/decoy_real and the self-referential /opt/decoy_scope/loop -> /opt/decoy_scope on xsoar.
- **Evidence** — paths in logs/alerts_<run_id>.log; `files_scanned` in logs/scan_summary_<run_id>.json; `files_found` on the `Target scan completed` statistics event (5951-5957).

### `TRAV-013` Unreadable directory entry demoted to a file

*supporting* · on `xsoar`

- **Must be true** — A scandir entry whose is_dir() raises OSError is appended to filenames and accounted for through the normal per-file error path rather than being silently dropped.
- **Threshold** — The planted entry contributes exactly 1 to one of those three keys; files_scanned + files_skipped for that target equals the entry count os.scandir reports for it; the entry never appears in logs/alerts_<run_id>.log.
- **Setup** — Non-root leg on xsoar (root bypasses the permission check): `mkdir -p /opt/decoy_scope/blocked/inner; chmod 000 /opt/decoy_scope/blocked; ln -s /opt/decoy_scope/blocked/inner /opt/decoy_scope/entry`. entry.is_dir() then stats through the 000 directory and raises PermissionError. Run with scan_folder=/opt/decoy_scope as LINUX_USER.
- **Evidence** — `file_processing.skip_breakdown` in the comprehensive_final_report event (6094) and the full `skip_breakdown` dict on the `Skip reasons: ...` statistics record (5556-5557, logs/statistics_<run_id>.log — note the human-readable line truncates to the first 5 reasons, so read the data dict) — one of `No read permission` (4990), `File does not exist` (4964) or `Scan error (<ExceptionType>)` (1014).

### `TRAV-014` Unreadable directory tolerated, subtree abandoned

*supporting* · on `xsoar`

- **Must be true** — A non-root whole-filesystem scan completes despite unreadable directories, and those directories deliberately produce no skip_reasons entry at all.
- **Threshold** — Non-root xsoar default-scope scan: outcome == 'completed', no `SCAN_STATUS: ERROR` on stderr, and the run does not abort at the first EACCES. Asymmetry assertion: files under a chmod-000 planted directory contribute 0 to EVERY skip_breakdown key, so files_scanned + files_skipped is strictly less than the true file count under the target (compute the truth with `find <target> -type f \| wc -l` as root over SSH).
- **Setup** — Use the non-root SSH leg of the xsoar scan (LINUX_USER, scan_folder=default) plus one planted chmod-000 directory containing 5 files under /opt/decoy_scope so the shortfall is a known, exact 5.
- **Evidence** — `outcome` in logs/scan_summary_<run_id>.json; the terminal SCAN_RESULT line; `file_processing.skip_breakdown` in the comprehensive_final_report event (6094); the scandir except arms at 5717-5721.

### `TRAV-015` Junction / reparse-point detection

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — Redirection points are correctly detected on POSIX via os.path.islink and feed the junction counters, so a symlinked file inside a listed root is recognised as a redirection rather than as an ordinary file.
- **Threshold** — On OfficeiMac with 3 planted symlinked files under /tmp: junction_skips == 3; path_deduplication_ratio == junction_skips / (files_scanned + files_skipped) * 100 to within 0.01; a byte-identical non-symlinked sibling is scanned normally and does not increment the counter.
- **Setup** — On OfficeiMac plant /opt/decoy_real/hit.bin (matching) and three symlinks /tmp/dl1, /tmp/dl2, /tmp/dl3 -> /opt/decoy_real/hit.bin plus a real copy /tmp/hit_real.bin; run with scan_folder=/tmp. Note /tmp itself is not in mac_skip_directory (only '/private/tmp/' is), so the target is walked.
- **Evidence** — `junction_skips` in the `Scan Progress` statistics metrics (5494) and `junction_skips` / `path_deduplication_ratio` in the final statistics data (5520-5522), logs/statistics_<run_id>.log.

### `TRAV-016` Per-platform problematic-junction skip list

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — Only reparse points whose path matches the platform list are skipped; an ordinary user symlink outside those roots is still followed and its target scanned.
- **Threshold** — Windows leg (thor, scan_folder=C:\Users\<THOR_USER>): every path containing `application data`, `local settings`, `my documents`, `documents and settings`, `default user` or `all users` that is a reparse point contributes to `Junction/symlink skip`, and no file is reported twice through both its junction path and its real path. Linux leg (xsoar): with a user symlink planted at /home/<u>/decoy_scope/userlink -> /opt/decoy_real/hit.bin, `Junction/symlink skip` == 0 (the Linux list is only /proc/self/fd and /proc/self/task, both already excluded at the directory level) and the target IS scanned.
- **Setup** — On thor scope the flood run to C:\Users\<THOR_USER> so the legacy junctions are encountered; on xsoar plant /home/<u>/decoy_scope/userlink -> /opt/decoy_real/hit.bin and include /home/<u>/decoy_scope in the flood target list.
- **Evidence** — `Junction/symlink skip` key in `file_processing.skip_breakdown` of the comprehensive_final_report event (6094) and in the `Skip reasons: ...` statistics data (5556-5557); `junction_skip_count` / `junction_skips` (5494, 5520); the list literals at 733-746.

### `TRAV-017` Directory-level junction pruning during the walk

*supporting* · on `xsoar`

- **Must be true** — A junction subdirectory matching the platform list is pruned in place before recursion and contributes nothing to any counter — the prune is silent by design.
- **Threshold** — Scanning C:\Users\<THOR_USER> on thor: no path containing `\Application Data\` appears in alerts or the evidence file_mapping; the planted matching file under C:\Users\<THOR_USER>\AppData\Roaming appears exactly ONCE (not once per junction alias); and the pruned subtree adds 0 to `Junction/symlink skip` and 0 to `Skipped directory` — a directory-level prune must be uncounted, unlike the file-level skip. This is the Windows-only half: on POSIX _walk_cancellable already refuses to push symlinked dirs, so the prune is a no-op there.
- **Setup** — On thor plant one matching file at C:\Users\<THOR_USER>\AppData\Roaming\decoy_hit.bin and run the flood pack with scan_folder=C:\Users\<THOR_USER> — avoids a recursive walk of thor's large attached disk.
- **Evidence** — absence of any path under the pruned junction in logs\alerts_<run_id>.log and in the evidence ZIP file_mapping; `files_skipped` and every key of `file_processing.skip_breakdown` in the comprehensive_final_report event (6094); prune site 5967.

### `TRAV-020` Skip by file extension (disk-image containers)

*supporting* · on `xsoar`

- **Must be true** — Every disk-image container extension is skipped without being opened, on every platform, and the skip is counted.
- **Threshold** — With 9 tiny planted files — test.iso, .img, .dmg, .vmdk, .vhd, .vhdx, .qcow, .qcow2, .sparsebundle — each containing the same matching string, plus one control test.bin: alerts contain exactly 1 entry (test.bin), skip_breakdown['Special system file'] increases by exactly 9, and no alert names any of the 9.
- **Setup** — Plant the 10 files in /opt/decoy_scope on xsoar and in ~/decoy_scope on OfficeiMac; scan_folder pointed at that directory.
- **Evidence** — `Special system file` in `file_processing.skip_breakdown` (6094, attribution site 5988) and in the `Skip reasons: ...` statistics data (5556-5557); logs/alerts_<run_id>.log; the extension set at 2862-2864.

### `TRAV-021` Skip by exact filename

*supporting* · on `xsoar`

- **Must be true** — The filename skip is exact-equality on the lowercased basename — not a substring or extension match.
- **Threshold** — Planted `.DS_Store`, `Thumbs.db` and `desktop.ini` (all containing the matching string) each contribute 1 to `Special system file` and produce 0 alerts, while byte-identical `thumbs.db.bak`, `mydesktop.ini` and `desktop.ini.txt` ARE scanned and DO produce alerts — 3 skips, 3 alerts. Case variation must not matter (`.DS_Store` vs `.ds_store` both skipped).
- **Setup** — Plant the 6 files in /opt/decoy_scope on xsoar and ~/decoy_scope on OfficeiMac.
- **Evidence** — `Special system file` in `file_processing.skip_breakdown` (6094); logs/alerts_<run_id>.log; the set `{'.ds_store','thumbs.db','desktop.ini'}` at 2865 and the check at 5133-5134.

### `TRAV-022` Skip by bounded path fragment

***core*** · on `xsoar`

- **Must be true** — Build/VCS/cache directory fragments are matched as bounded path components anywhere in the path AND at the bare walk-root tail, on a lowercased forward-slash path, without swallowing similarly-named siblings.
- **Threshold** — Leg A (scan_folder=/opt/decoy_scope): matching files under /opt/decoy_scope/node_modules/ and /opt/decoy_scope/.git/ produce 0 alerts and their counts land in `Skipped directory`, while /opt/decoy_scope/node_modules_backup/hit.bin DOES alert. Leg B (scan_folder=/opt/decoy_scope/node_modules — the bare-root tail case): excluded_targets == ['/opt/decoy_scope/node_modules'], files_scanned == 0, and the excluded-target WARNING appears on the result line.
- **Setup** — Plant /opt/decoy_scope/node_modules/hit.bin, /opt/decoy_scope/.git/hit.bin and /opt/decoy_scope/node_modules_backup/hit.bin on xsoar, all containing the same matching string. Ensure YARA_EXTRA_SKIP_PATHS (90) is unset so the deployer extension point does not confound the tuple.
- **Evidence** — `Skipped directory` in `file_processing.skip_breakdown` (6094, attribution site 5964); `excluded_targets` in logs/scan_summary_<run_id>.json for the bare-root leg; logs/alerts_<run_id>.log; the fragment tuple at 2866-2886 and the matcher at 5161-5164.

### `TRAV-023` Browser caches deliberately NOT skipped

*supporting* · on `xsoar`

- **Must be true** — Browser cache and profile directories are scanned, not skipped — the four fragments removed from skip_path_fragments must not have crept back in.
- **Threshold** — A matching file planted at ~/.mozilla/firefox/testprofile.default/cache2/decoy_hit.bin on xsoar produces exactly 1 alert entry and 1 yara_match event; the strings `mozilla/firefox/profiles/`, `/cache2/`, `user data/default/cache/` appear nowhere in the effective skip_path_fragments (dump it from the run's own config, or assert the alert exists). Same for %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\decoy_hit.bin on the thor leg.
- **Setup** — Create the firefox profile cache2 directory tree on xsoar and the Chrome cache tree on thor, each with one matching planted file, and include their parents in the scan scope.
- **Evidence** — logs/alerts_<run_id>.log entries and the corresponding yara_match events; `Skipped directory` / `Special system file` in skip_breakdown (6094) must NOT account for these paths; the removal comment block at 2889-2896 and the live tuple at 2866-2886.

### `TRAV-024` Browser force-scan allowlist (macOS carve-out)

*supporting* · on `OfficeiMac`

- **Must be true** — On macOS the force-scan allowlist re-opens browser caches that the broad /library/caches/ fragment would otherwise bury, while leaving every other path under Library/Caches skipped.
- **Threshold** — On OfficeiMac: byte-identical matching files at ~/Library/Caches/Google/Chrome/decoy_hit.bin, ~/Library/Caches/Chromium/decoy_hit.bin, ~/Library/Caches/Microsoft Edge/decoy_hit.bin and ~/Library/Caches/Firefox/decoy_hit.bin each produce exactly 1 alert entry (4 alerts total), while ~/Library/Caches/SomethingElse/decoy_hit.bin produces 0 and is counted under `Skipped directory`. A planted ~/Library/Caches/Google/Chrome/decoy.iso must still be skipped — filename/extension skips run before the allowlist.
- **Setup** — Plant the 4 allowlisted paths, 1 non-allowlisted sibling and 1 .iso inside an allowlisted path on OfficeiMac; run with scan_folder=$HOME/Library/Caches so the directory-root carve-out (portable_path + '/') is exercised too.
- **Evidence** — logs/alerts_<run_id>.log and the yara_match events; `Skipped directory` in `file_processing.skip_breakdown` (6094); the force_scan_fragments tuple at 2901-2912 and the pre-skip evaluation at 5150-5153.

### `TRAV-025` Boundary skips the force-scan allowlist cannot override

*supporting* · on `xsoar`

- **Must be true** — A browser-cache path under a mount boundary is still skipped — the force-scan allowlist is not applied at all when force_scan_never_under matches, so the carve-out cannot become an unbounded walk over mounted media.
- **Threshold** — Zero alert entries and zero yara_match events name any path under /Volumes/, while the byte-identical file at ~/Library/Caches/Google/Chrome/decoy_hit.bin DOES alert. The targeted leg (scan_folder=/Volumes/DECOY/Library/Caches/Google/Chrome) reports excluded_targets containing that path and files_scanned == 0.
- **Setup** — On OfficeiMac: `hdiutil create -size 20m -fs APFS -volname DECOY /tmp/decoy.dmg && hdiutil attach /tmp/decoy.dmg`, then plant /Volumes/DECOY/Library/Caches/Google/Chrome/decoy_hit.bin. Run both the whole-filesystem leg and one targeted leg. Detach and delete the image afterwards.
- **Evidence** — logs/alerts_<run_id>.log and yara_match events (must contain nothing under /Volumes/); `excluded_targets` in logs/scan_summary_<run_id>.json for the targeted leg; the boundary tuple at 2913-2924 and the guard at 5152-5153; '/Volumes/' is also an anchor in mac_skip_directory (2933-ish region).

### `TRAV-026` Windows skip folders with component-boundary matching

*supporting* · on `thor`

- **Must be true** — Windows skip roots match whole path components only, so vendor/security and scanner directories are excluded while a sibling whose name merely begins with a skip entry's is still scanned.
- **Threshold** — With scan_folder=`C:\yara_scanner,C:\yara_scanner_backup` on thor: excluded_targets == ['C:\yara_scanner'] with 0 files scanned under it, and the planted C:\yara_scanner_backup\decoy_hit.bin IS reported in alerts — the direct regression guard for the old bare-startswith bug. During the scoped flood run, no path under C:\Program Files\Palo Alto Networks, C:\$Recycle.Bin or C:\System Volume Information appears in alerts or file_mapping.
- **Setup** — On thor create C:\yara_scanner_backup\decoy_hit.bin containing the matching string before the flood run. Use the two-target scan_folder above rather than C:\ — never run a recursive whole-disk walk on thor.
- **Evidence** — `excluded_targets` in logs\scan_summary_<run_id>.json; logs\alerts_<run_id>.log and the evidence ZIP file_mapping; `Skipped directory` in `file_processing.skip_breakdown` (6094); the win_skip_folder list (2848-2888 region, normalised with the len<=3 drive-root guard) and the matcher at 5170-5178.

### `TRAV-027` Windows skip-drive mechanism

*supporting* · on `thor`

- **Must be true** — The drive-exclusion list ships empty, so no discovered volume is silently dropped between target discovery and traversal.
- **Threshold** — On the short thor default-scope leg: the number of `Scanning target i/N` lines equals len(scan_targets) equals the length of the discovered target list — no drive is dropped. Any drive present in discovery but absent from the `Scanning target` sequence means win_skip_drive was populated.
- **Setup** — Reuse the short thor default-scope leg (non-matching rule pack, cancelled shortly after discovery); read the two lists before the cancel takes effect.
- **Evidence** — logs\yara_processing_<run_id>.log `Light profile full-scope targets on Windows: [...]` (3105); the `Scanning target i/N: <path>` lines in logs\system_<run_id>.log (5931); `scan_targets` in logs\scan_summary_<run_id>.json; `self.win_skip_drive = []` (2925) and the check at 5167-5169.

### `TRAV-028` Linux skip directories

*supporting* · on `xsoar`

- **Must be true** — Linux skip prefixes exclude both the bare directory root and everything beneath it, and the excluded files are counted rather than vanishing.
- **Threshold** — On the root `/` scan of xsoar: zero paths under /proc, /sys, /dev, /run, /media, /lost+found, /var/run, /opt/traps or the scanner dir appear in alerts or file_mapping; skip_breakdown['Skipped directory'] > 0. Boundary guard: a planted /opt/traps_backup/decoy_hit.bin IS scanned and alerts (the trailing-slash form must not swallow the sibling). Confirm /opt/traps really exists on xsoar via `ps aux \| grep pmd` — it is root-only, so ls/du as LINUX_USER wrongly reads empty.
- **Setup** — Plant /opt/traps_backup/decoy_hit.bin on xsoar before the root whole-filesystem run.
- **Evidence** — logs/alerts_<run_id>.log and the evidence ZIP file_mapping; `Skipped directory` in `file_processing.skip_breakdown` (6094) and the `Skip reasons: ...` statistics data (5556-5557); the list at 2890-2901 and the matcher at 5181-5192.

### `TRAV-029` macOS skip directories with three matching semantics

*supporting* · on `OfficeiMac`

- **Must be true** — Each mac_skip_directory entry is matched by the semantics its shape implies — anchors only at their real top-level path, .app/ entries as bundle suffixes for any app name, and bare entries as components anywhere including the bare walk root.
- **Threshold** — On OfficeiMac, five planted byte-identical matching files: (a) ANCHOR — ~/System/decoy_hit.bin IS scanned and alerts, while nothing under /System appears in alerts; (b) BUNDLE — ~/decoy_scope/Zzz.app/Contents/Resources/decoy_hit.bin produces 0 alerts (matched regardless of app name); (c) FRAGMENT — ~/decoy_scope/node_modules/decoy_hit.bin produces 0 alerts while ~/decoy_scope/node_modulesx/decoy_hit.bin produces 1; (d) bare-root — a leg with scan_folder=~/decoy_scope/node_modules reports excluded_targets == that path. Case must not matter (~/system/ also skipped-equivalent behaviour for the…
- **Setup** — Plant the five decoys on OfficeiMac; run one leg with scan_folder=$HOME and one targeted leg with scan_folder=$HOME/decoy_scope/node_modules.
- **Evidence** — logs/alerts_<run_id>.log; `Skipped directory` in `file_processing.skip_breakdown` (6094); the list at 3086-3110 region (lowercased at construction) and the three-way matcher at 5196-5222.

### `TRAV-030` macOS AppleDouble and .DS_Store file skip

*supporting* · on `OfficeiMac`

- **Must be true** — On macOS, AppleDouble resource forks and .DS_Store files are skipped by basename after the directory checks, and never surface in alerts.
- **Threshold** — Planted ~/decoy_scope/._decoy_hit and ~/decoy_scope/.DS_Store, both containing the matching string, each contribute 1 to `Special system file` and produce 0 alerts; no path whose basename starts with `._` appears anywhere in logs/alerts_<run_id>.log across the whole OfficeiMac run; a control ~/decoy_scope/_decoy_hit (single underscore) IS scanned and alerts.
- **Setup** — Plant the three files on OfficeiMac in the round-3 decoy directory.
- **Evidence** — `Special system file` in `file_processing.skip_breakdown` (6094); logs/alerts_<run_id>.log; the checks at 5224-5228.

### `TRAV-032` Self-skip of the scanner's own directory and log file

***core*** · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — A whole-machine scan never scans the scanner's own artefacts — neither the scanner directory subtree nor the active output log — so the scanner cannot alert on its own rule text or logs.
- **Threshold** — On both the xsoar `/` run and the OfficeiMac default-scope run: zero alert entries and zero evidence file_mapping entries name any path under scanner_dir (default /opt/yara_scanner), including logs/scanner_<run_id>.log, alert/*.txt, evidence/*.zip and failed_rules/*; the subtree's files are counted under `Skipped directory`. Loudness guard: with a rule whose string is the literal `YARA rule '` (which appears verbatim in every alert/*.txt), a self-scan failure would produce alerts — assert there are none.
- **Setup** — Add one rule to the round-3 pack whose string literal is `YARA rule '` so any failure of the self-skip is unmissable; confirm YARA_SCANNER_DIR matches the directory actually used on each host before asserting.
- **Evidence** — logs/alerts_<run_id>.log and the evidence ZIP file_mapping (must name no path under scanner_dir); `Skipped directory` in `file_processing.skip_breakdown` (6094); the output_log short-circuit at 6600-6608 and the scanner_dir appended to each platform list (2900-2901, mac/win equivalents); scanner_dir root from YARA_SCANNER_DIR (2676-2702).

### `TRAV-033` Vendor security-agent path exclusions

***core*** · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — A YARA-matching decoy planted under a vendor install/log root (/opt/traps/ on xsoar, /Library/Application Support/PaloAltoNetworks/Traps/ and '/Library/Logs/PaloAltoNetworks/Cortex XDR/' on OfficeiMac) produces no alert, while an identical decoy at a lookalike NON-anchored path (/home/<user>/opt/traps/, ~/cyvera/) IS scanned and alerted.
- **Threshold** — 0 alert records whose file_path is under a vendor root; exactly 1 alert record for each lookalike decoy (2 of 2 on Linux, 2 of 2 on macOS).
- **Setup** — sudo mkdir -p /opt/traps && place a file matching the rule pack there; place the same content at /home/<LINUX_USER>/opt/traps/decoy and at /home/<LINUX_USER>/cyvera/decoy. On OfficeiMac place matching decoys under the two PaloAltoNetworks dirs and one at ~/Documents/cyvera/decoy. Run whole-filesystem default scan.
- **Evidence** — /opt/yara_scanner/logs/alerts_<run_id>.log (macOS: /usr/local/yara_scanner/logs/alerts_<run_id>.log) - grep for each decoy path; plus evidence/file_mapping.txt. Skip lists verified at PINNED_xsiam_current.py lin_skip_directory 2971-2979 ('/opt/traps/'), mac_skip_directory 2983-2993, win_skip_folder 2925-2941 (anchored roots, no 'cyvera' fragment); matcher _is_special_file 5116-5200.

### `TRAV-034` Maximum file size cap

***core*** · on `xsoar`

- **Must be true** — Every planted file larger than max_file_bytes is refused with skip reason 'File too large' and never hashed or matched, and the configured cap is disclosed as max_file_size_mb.
- **Threshold** — max_file_size_mb == 64 (default run); skip_breakdown['File too large'] == number of planted oversize files (plant 3, expect >=3); none of those paths appear in alerts_<run_id>.log.
- **Setup** — Plant 3 files of 80MB each (fallocate) under a scanned dir on xsoar, each containing the matching string. Optionally a second short run with YARA_MAX_MB=-1 exported over SSH to assert the ErrorLogger line 'Ignoring out-of-range YARA_MAX_MB' and that files_scanned > 0 (the negative-cap regression).
- **Evidence** — 'Scan configuration established' statistics record in /opt/yara_scanner/logs/statistics_<run_id>.log, field max_file_size_mb (built at 5877-5886); 'Skip reasons: ...' record data.skip_breakdown key 'File too large' (5556-5557); cap enforced at scan_file 5005-5007; max_file_mb=_env_number('YARA_MAX_MB',64,cast=int,minimum=0) at 2820-2821.

### `TRAV-035` Non-regular-file rejection

*supporting* · on `xsoar`

- **Must be true** — A named pipe, a character device and a unix socket inside the scan scope are refused with 'Not a regular file' and the scan completes rather than blocking on a read.
- **Threshold** — skip_breakdown['Not a regular file'] >= 3 (the planted FIFO, socket and device node), scan reaches outcome != timeout, and no worker sits >60s on any single file.
- **Setup** — On xsoar: mkfifo /home/<LINUX_USER>/fpdecoy/pipe1; python one-liner to bind a unix socket; sudo mknod a char device (or scan a dir containing a bind-mounted /dev entry). Whole-filesystem scan already reaches /dev but /dev/ is in lin_skip_directory, so the planted nodes must sit OUTSIDE the skip list.
- **Evidence** — skip_breakdown key 'Not a regular file' in the 'Skip reasons: ...' statistics record (5556-5557) and in the comprehensive_final_report file_processing.skip_breakdown (6094); gate at scan_file 5002-5003 (stat.S_ISREG after os.stat).

### `TRAV-036` Existence and read-access pre-checks

*supporting* · on `xsoar`

- **Must be true** — Files that vanish mid-walk are counted as 'File does not exist' and files unreadable by the scanner UID are counted as 'No read permission', each with a per-file system-log record carrying requires_root, owner_uid and file_mode.
- **Threshold** — Running as a non-root user, skip_breakdown['No read permission'] > 0 and the count of 'Permission denied:' lines in system_<run_id>.log equals that value; at least one such record has requires_root == true; all planted deleted-mid-walk files land under 'File does not exist'.
- **Setup** — Run the whole-filesystem scan on xsoar as LINUX_USER (NOT root) so /root, /etc/shadow etc. are unreadable. Concurrently delete ~20 files from a large scanned directory while the walk is in progress to drive the exists() arm.
- **Evidence** — skip_breakdown keys 'File does not exist' (5964) and 'No read permission' (4990) in the 'Skip reasons' statistics record; per-file lines 'Permission denied: <path>' with data {'file_path','file_mode','owner_uid','scanner_uid','requires_root'} in /opt/yara_scanner/logs/system_<run_id>.log (log_system at 4981, permission_info built 4970-4979).

### `TRAV-040` Bounded per-file error labels in the skip breakdown

*supporting* · on `xsoar`

- **Must be true** — Per-file scan exceptions collapse to the label 'Scan error (<ExceptionType>)', so skip_breakdown cardinality and byte size stay bounded no matter how many files error, while the full path and message survive in the error log.
- **Threshold** — Number of distinct skip_breakdown keys starting 'Scan error (' <= 10; no skip_breakdown key contains '/' or '\\'; len(json.dumps(skip_breakdown)) < 8192 bytes even with >1000 errored files; error_summary.scan_errors == sum of those keys.
- **Setup** — On xsoar, force a large error population: chmod 000 a directory tree of ~2000 files AFTER the walk enumerates it but before workers reach it (or mount a small tmpfs and unmount it mid-scan) so os.stat/rules.match raise for many distinct paths.
- **Evidence** — skip_breakdown keys in the 'Skip reasons' statistics record and in comprehensive_final_report.file_processing.skip_breakdown (6094); error_summary.scan_errors summing keys containing 'error' (6497); /opt/yara_scanner/logs/scan_errors_<run_id>.log for full detail. Code: _scan_error_reason 999-... , sole call site scan_file 5101.

### `TRAV-042` Scan-configuration disclosure event

*supporting* · on `xsoar`

- **Must be true** — Before any worker starts, the resolved target list, its length, worker count, size cap and rule counts are disclosed once as a statistics record and mirrored into the initialization event and scan_summary.
- **Threshold** — The three lists are byte-identical; target_count == len(targets); the record's timestamp precedes the first 'Worker ScanWorker-1 started' system record; yara_rules_count + failed_rules_count == number of rules in the delivered pack.
- **Evidence** — 'Scan configuration established' statistics record with data {'scan_id','os_info','targets','target_count','max_workers','max_file_size_mb','yara_rules_count','failed_rules_count'} (5875-5888) plus the matching statistics_summary webhook upload (5889-5892); 'YARA Scanner initialization completed' system event field scan_targets (6356); scan_targets in scan_summary_<run_id>.json (6768).

### `TRAV-044` Case-folding policy for path matching

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — Path matching is case-folded on Windows/macOS and case-preserved on Linux: on xsoar '/opt/traps/' is skipped while '/opt/Traps/' is scanned; on OfficeiMac both '/Library/Caches/' and '/library/caches/' are skipped.
- **Threshold** — On xsoar: 1 alert for the /opt/Traps/ decoy, 0 alerts for the /opt/traps/ decoy. On OfficeiMac: 0 alerts for decoys under either casing of Library/Caches.
- **Setup** — sudo mkdir -p /opt/Traps /opt/traps on xsoar with an identical matching decoy in each. On OfficeiMac create ~/Library/Caches/zz_decoy and (case-insensitive APFS makes the second path the same inode) verify via a lowercase symlinked directory path passed as an explicit scan target.
- **Evidence** — alerts_<run_id>.log presence/absence of each planted decoy; skip_breakdown['Skipped directory'] delta per run; code: _is_special_file normalized_path vs portable_path 5121-5135, Linux branch 5182-5192 (case-preserved), Darwin branch 5195+ (portable_path, entries lowercased at construction 3007+).

### `TRAV-046` Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink duplicate"

*low* · on `xsoar`

- **Must be true** — Two skip labels reach `skip_breakdown` that a skip-reason inventory built from the docs will miss. `"Permission denied"` (4989) fires when a file passes the `os.access` pre-check but raises PermissionError later (at `os.stat` or `rules.match`) — distinct from the pre-flight `"No read permission"` (4886). Unlike the pre-flight arm, which logs each denial to the system log (4877), this arm logs nothing at all; and because `error_summary.scan_errors` sums only skip_reasons keys containing 'error' (6330-6331), these files are counted in no error total anywhere — they exist only as a raw skip_breakdown key. Note the label `"Scan error (PermissionError)"` from `_scan_error_reason` (935-950) is NOT a third variant: `except PermissionError` (4987) precedes `except Exception` (4990), and 4997 is the only call site of `_scan_error_reason` in the file, so that string can never be produced.…
- **Evidence** — Read the `skip_breakdown` dict, not the summary JSON. On disk: `logs/statistics_<run_id>.log` (path built at 1781), the "Skip reasons: ..." record whose data carries `{'total_skipped', 'skip_breakdown'}` (5425-5430), and the "COMPREHENSIVE SCAN REPORT" statistics record (call 6001-6004, message string 6002, payload `final_report_data`). On the wire: the `comprehensive_final_report` webhook event (log_type set at 5989), field `data.file_processing.skip_breakdown` (5934), where `data.error_summary.scan_errors` (6330-6331) can be checked to confirm permission-denied files are excluded from it. NOT in `scan_summary_<run_id>.json` — that payload carries only `files_skipped` (6605), no breakdown (write_scan_summary payload 6597-6618). The pre-flight "No read permission" path is separately visible as per-file "Permission denied: <path>" lines in `logs/system_<run_id>.log` (log_system call…

### `TRAV-047` Windows default scan scope is every mounted volume, including network and removable drives

***core*** · on `thor`

- **Must be true** — With scan_folder unset or 'default', the resolved Windows target list is the normcase-deduped union of psutil mountpoints and every GetLogicalDrives letter that is a directory - so mapped network shares and removable volumes enter the default scope, not just C:\.
- **Threshold** — scan_targets equals, as a set, every root reported by `wmic logicaldisk get name,drivetype` that os.path.isdir() succeeds on - including any DriveType 3/4 (network) or 2 (removable) letter; it must NOT be ['C:\\'] when other letters are present.
- **Setup** — On thor: map a scratch network drive (`net use Z: \\\\<host>\\share`) and attach a small removable/VHD, then start a scan with scan_folder='default' and CANCEL it as soon as the initialization and SCAN SCOPE events land (~30s). Do NOT let the walk run - thor's large attached disk must not be traversed.
- **Evidence** — scan_targets in scan_summary_<run_id>.json (6768); 'YARA Scanner initialization completed' system event field scan_targets (6356) and the following 'SCAN SCOPE: Full system scan' system event; the line 'Light profile full-scope targets on Windows: [...]' in C:\yara_scanner\logs\yara_processing_<run_id>.log (3105, ErrorLogger's own INFO handler). Code: _default_discover_targets 3055-3105.

## Storage (2)

### `STOR-001` Scanner working directory (platform default + override)

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — Every artefact lands under the per-platform default root, and setting YARA_SCANNER_DIR relocates all of them without leaving anything at the default.
- **Threshold** — Default runs: the root exists on all three hosts with the expected per-OS path, created even on a run that matched nothing. Override run: logs/, alert/, evidence/, failed_rules/, control/ all appear under /tmp/yaratest and the default root gains no new run_id.
- **Setup** — On xsoar, one extra run over SSH with `YARA_SCANNER_DIR=/tmp/yaratest` (the override is env-only, so it cannot be exercised through Action Center delivery). Also verify a whitespace-only value falls back to the default.
- **Evidence** — `ls -la /opt/yara_scanner` on xsoar and `ls -la /usr/local/yara_scanner` on OfficeiMac; `_default_scanner_dir()` at 813-823 (Windows `C:\yara_scanner`, Darwin `/usr/local/yara_scanner`, else `/opt/yara_scanner`; blank/whitespace override ignored) and the parallel read in ScanConfig at 2740. Override check: `ls -la /tmp/yaratest`.

### `STOR-003` control/ subdirectory for cooperative-cancel state

*supporting* · on `xsoar`

- **Must be true** — control/ holds running.json for the duration of a live scan and gains cancel.flag when cancel is invoked, and its creation failure never aborts a scan.
- **Threshold** — running.json present throughout the scan and absent within 10 s of terminal state; cancel.flag appears within 2 s of the cancel invocation and is gone after the run finishes; scan_summary_<run_id>.json outcome == "cancelled".
- **Setup** — Round 3's mid-run cancellation on xsoar - poll `ls -la /opt/yara_scanner/control` over SSH every 2 s across the cancel. The permission-failure branch is not injected (would require chmod-ing a live scanner root); assert only that a normal run never reports the Cancel-failed string.
- **Evidence** — `ls -la /opt/yara_scanner/control` during and after the run: `running.json` present while scanning (written by `_write_running_marker`), `cancel.flag` present after `cancel()` and consumed at cleanup (`_clear_cancel_flag`, 5820-5821); the cancel entry point creates the dir itself at 838-842 and returns the literal `Cancel failed: cannot create control dir <path>: <err>` on failure; ScanConfig's own creation is wrapped in try/except at 2752-2756.

## Lifecycle (37)

### `LIFE-001` Scan entry point main(yarafile, scan_folder, alert_severity)

***core*** · on `xsoar`

- **Must be true** — main() exposes exactly three inputs, returns a non-empty single-line result string for every round-3 variant, and never propagates an exception to the caller.
- **Threshold** — Exactly 3 inputs shown in Action Center; for all 6 round-3 variants (default scope, explicit multi-target, excluded target, bogus severity, cancelled run, SIGINT run) the returned string is non-empty, contains no newline, and the process produces no uncaught traceback other than the deliberate 'CRITICAL ERROR' block.
- **Setup** — Run each round-3 variant both via Action Center and via CLI over SSH on xsoar; on OfficeiMac run the default-scope variant.
- **Evidence** — Action Center 'Run by entry point' input list for the uploaded script; the `SCAN_RESULT: ` stdout line (printed at 6837); the run-stamped log set under /opt/yara_scanner/logs/*_<run_id>.log.

### `LIFE-002` Cancel entry point cancel() — zero inputs

***core*** · on `xsoar`

- **Must be true** — cancel() takes zero inputs, writes control/cancel.flag without touching logging, rules or the collector, and truthfully reports whether a scan is alive.
- **Threshold** — Action Center shows 0 inputs; result matches `^Cancel signal delivered \(.*cancel\.flag\) \\| scanner running: (yes\|no) \\| scan_id=`; during a live scan it reports 'yes' and echoes the same scan_id as running.json; against no live scan it reports 'no'; the logs directory gains no new files as a result of the call.
- **Setup** — Invoke cancel() once mid-run against the long whole-filesystem scan, and once again 60s after that run has exited.
- **Evidence** — Action Center result string from the cancel entry point; /opt/yara_scanner/control/cancel.flag contents; absence of any new *_<run_id>.log file created by the cancel invocation.

### `LIFE-003` CLI dispatch and exit-code contract

*supporting* · on `xsoar`

- **Must be true** — argv[1..3] map to main()'s three inputs, argv[1]=='cancel' (case-insensitive) routes to cancel(), the result is printed with the 'SCAN_RESULT: ' prefix, and the exit code is 1 exactly when the result starts with 'scan failed'/'scan aborted'/'cancel failed' or is empty.
- **Threshold** — clean run -> exit 0; cancelled run -> result starts 'Scan cancelled (source=' and exit 0; alert_severity='bogus' -> result starts 'Scan failed' and exit 1; `python3 xsiam_yara_scanner.py CANCEL` -> result starts 'Cancel signal delivered' and exit 0; placeholder-credential run -> result starts 'Scan aborted' and exit 1.
- **Setup** — Run all five CLI invocations over paramiko SSH on xsoar capturing stdout and $? in one shell line; the placeholder-credential case uses an unedited copy of the script with API_KEY still 'http_collector_key'.
- **Evidence** — stdout line `SCAN_RESULT: ...` (6837) and `echo $?` captured in the same SSH command; branch at 6843-6848.

### `LIFE-004` Cancel flag file (control/cancel.flag)

***core*** · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — cancel() creates a parseable JSON flag at <scanner_dir>/control/cancel.flag containing requested_at_ms and source, the running scan consumes and removes it, and an unwritable control directory yields an explicit 'Cancel failed: cannot write' return instead of a silent success.
- **Threshold** — File exists within 1s of cancel() returning; json.load succeeds with keys {requested_at_ms, source} and source == 'action_center'; file absent within 5s of the cancelled run's process exit; with control/ chmod 500 the result string starts 'Cancel failed: cannot write' and exits 1.
- **Setup** — Mid-run cancel on the whole-filesystem scan; separately chmod 500 /opt/yara_scanner/control, invoke cancel(), then restore the mode.
- **Evidence** — /opt/yara_scanner/control/cancel.flag (path built at 844); the cancel entry point's returned string.

### `LIFE-007` Stale cancel-flag protection anchored at module import

*supporting* · on `xsoar`

- **Must be true** — A cancel.flag whose mtime predates process start (minus CANCEL_STALE_TOLERANCE_SECS=2.0) is deleted and does not cancel the new run, while a flag written during rule compilation is preserved and honoured.
- **Threshold** — Case A (flag backdated to now-3600 before launch): the 'Removed stale cancel flag' line is present and outcome == 'completed'. Case B (cancel() called ~2s into a large-pack compile): no such line, outcome == 'cancelled', cancel_source == 'action_center'.
- **Setup** — Case A: write control/cancel.flag then `touch -d '-1 hour'` it before launching. Case B: launch with a >5000-rule pack and fire cancel() 2s after launch, before the watcher starts.
- **Evidence** — /opt/yara_scanner/logs/system_<run_id>.log line `Removed stale cancel flag from a previous run` (5604) or `Could not evaluate pre-existing cancel flag: ...` (5606); `outcome` in scan_summary_<run_id>.json.

### `LIFE-008` Cancellation watcher thread and poll cadence

*supporting* · on `xsoar`

- **Must be true** — The CancelWatcher daemon observes a newly written flag within one poll interval, reports the flag's source, and never dies on a poll error.
- **Threshold** — (system-log timestamp of 'Cancellation requested') - (cancel.flag mtime) <= CANCEL_POLL_SECS (5) + 1s; a thread named CancelWatcher exists in the task dump taken mid-run; 0 'Cancel watcher error' lines.
- **Setup** — Mid-run cancel on the whole-filesystem scan; capture cancel.flag mtime with `stat -c %.3Y` immediately after cancel() returns and dump /proc/<pid>/task/*/comm before it.
- **Evidence** — /opt/yara_scanner/logs/system_<run_id>.log line `Cancellation requested (source=action_center)` (5586); thread name 'CancelWatcher' in /proc/<pid>/task/*/comm; /opt/yara_scanner/logs/scan_errors_<run_id>.log for `Cancel watcher error:`.

### `LIFE-009` _request_cancel — idempotent, first-source-wins, thread-safe

*supporting* · on `xsoar`

- **Must be true** — Repeated cancel deliveries produce exactly one cancellation, and the source recorded everywhere is the first one seen.
- **Threshold** — Exactly 1 'Cancellation requested' line in the run; the source value is identical across the system log, the result line and the summary JSON; outcome == 'cancelled'.
- **Setup** — Call cancel() three times about 1s apart during the whole-filesystem scan.
- **Evidence** — `Cancellation requested (source=` occurrences in /opt/yara_scanner/logs/system_<run_id>.log (5586); cancel_source in scan_summary_<run_id>.json / the SCAN_RESULT verb / scan_completion_summary data.cancel_source.

### `LIFE-010` Bounded cancellation latency in directory traversal (_walk_cancellable)

***core*** · on `xsoar`

- **Must be true** — Cancellation of a deep whole-filesystem walk is honoured within one scandir call, so the process exits promptly and stops early rather than completing the tree.
- **Threshold** — process exit - flag write <= 30s; 'Scan terminated by external signal' present; cancelled files_scanned < 60% of the baseline full-scan files_scanned; running.json absent at exit.
- **Setup** — Scan / on xsoar (whole filesystem, deep tree), issue cancel() during the discovery phase (within the first 60s); take a baseline uncancelled full-scan files_scanned first.
- **Evidence** — cancel.flag mtime vs process exit time (wall clock over SSH); `Scan terminated by external signal` in /opt/yara_scanner/logs/system_<run_id>.log (5923); files_scanned in scan_summary_<run_id>.json vs the uncancelled baseline run's files_scanned; running.json removal.

### `LIFE-011` Worker-side cancellation and drain

***core*** · on `xsoar`

- **Must be true** — Every worker thread exits its loop promptly after cancellation and logs a stop event with its own counters; the sentinel push wakes idle workers so none waits out the 5.0s queue timeout unnecessarily.
- **Threshold** — count(started) == count(stopped) == config.max_workers; each 'stopped' line carries all three data keys; the last 'stopped' line timestamp is within 10s of the 'Cancellation requested' line; 'Worker cleanup:' reports 0 timed out.
- **Setup** — Same cancelled whole-filesystem run; record config.max_workers from the 'YaraScanner initialized with N workers' line (4414).
- **Evidence** — /opt/yara_scanner/logs/system_<run_id>.log `Worker ScanWorker-N started` (4826) / `Worker ScanWorker-N stopped` pairs with data {files_processed, errors_encountered, average_processing_time_ms} (4872-4880); /opt/yara_scanner/logs/performance_<run_id>.log `Worker cleanup: X stopped, Y timed out in Z s`.

### `LIFE-012` Worker join with bounded timeout

*supporting* · on `xsoar`

- **Must be true** — Shutdown of a long, backlogged scan joins each worker with a 5s cap, accounts for stopped vs timed-out threads, names any survivor, and never blocks the run beyond that budget.
- **Threshold** — N + M == config.max_workers; T <= 5 * max_workers + 1s; for every unit of M there is exactly one matching 'did not finish' line naming a ScanWorker-K; the run still writes scan_summary_<run_id>.json afterwards.
- **Setup** — Long scan on 8-core xsoar with YARA_THREADS=8 and competing load (stress-ng or a parallel find), plus at least one very large file (>=1 GB, under YARA_MAX_MB) so a worker is mid-match at cleanup.
- **Evidence** — /opt/yara_scanner/logs/performance_<run_id>.log `Worker cleanup: N stopped, M timed out in T s` (5807-5809); /opt/yara_scanner/logs/scan_errors_<run_id>.log `Worker thread <name> did not finish - continuing anyway` (5797) and `Threads did not terminate: [...]` (5804).

### `LIFE-013` Cancel-flag consumption and marker removal at shutdown

*supporting* · on `xsoar`

- **Must be true** — A run removes cancel.flag only if it actually acted on a cancel, and always removes running.json, so a stale flag cannot cancel the next scan and cancel() cannot report a phantom live scan.
- **Threshold** — After the cancelled run: both files absent. After a normal (uncancelled) run: running.json absent, and a cancel.flag written 2s after that run exited still exists and is then honoured by the next run (outcome == 'cancelled').
- **Setup** — Sequence three runs on xsoar: (1) cancelled run, (2) clean run then drop a flag 2s post-exit, (3) next run started with that flag present.
- **Evidence** — Presence/absence of /opt/yara_scanner/control/cancel.flag and /opt/yara_scanner/control/running.json after each run (cleanup at 5820-5824).

### `LIFE-014` Backlog-proportional shutdown drain

*supporting* · on `xsoar`

- **Must be true** — Each drain site announces a wait budget computed as min(60, max(15, pending * 0.3)) from its own pending count, so a flood's large backlog gets proportionally more time and shutdown is still capped per site.
- **Threshold** — For every such line, X == min(DRAIN_MAX_SECS=60, max(DRAIN_MIN_SECS=15, N * DRAIN_PER_ITEM_SECS=0.3)) within 1s; at least one line has N >= 60 so X > 15 (proving proportionality, not the floor); total shutdown wall time <= 4 * 60s.
- **Setup** — Flood run on xsoar with the collector black-holed so a backlog of >=200 items exists at stop time; drive N high with a rule pack matching nearly every file.
- **Evidence** — /opt/yara_scanner/logs/uploads_<run_id>.log lines `Waiting for N pending match uploads (max Xs)...` (3357-3359) and `Waiting for N pending standardized log uploads (max Xs)...` (2251-2253).

### `LIFE-019` Outcome classification (completed / cancelled / failed)

***core*** · on `xsoar`

- **Must be true** — The summary's outcome follows the precedence cancel_requested > scan_failed > completed, and never records a crashed or cancelled run as 'completed'.
- **Threshold** — clean run -> outcome 'completed', failure_reasons == []; cancelled run -> 'cancelled'; SIGINT run -> 'failed' with failure_reasons containing 'Scan interrupted by user'; in all three, outcome agrees with the result verb and terminal status (3-way agreement, 0 mismatches).
- **Setup** — Round-3 variants: clean whole-filesystem run, cancelled run, SIGINT run over SSH.
- **Evidence** — `outcome` and `failure_reasons` in /opt/yara_scanner/logs/scan_summary_<run_id>.json (derived in main()'s finally at 6746-6752); the SCAN_RESULT verb; the terminal 'Scan status changed to' line.

### `LIFE-020` Outcome agreement in end-of-scan telemetry

*supporting* · on `xsoar`

- **Must be true** — A cancelled run's scan_completion_summary says cancelled with the source, and the statistics log mirrors it, rather than claiming success.
- **Threshold** — Cancelled run: data.outcome == 'cancelled', data.cancel_source == 'action_center', message matches `^Scan cancelled by operator after .* \(partial results\)$`, statistics log contains 'SCAN CANCELLED BY OPERATOR after' and 0 occurrences of 'SCAN COMPLETED SUCCESSFULLY'. Clean run: the exact inverse.
- **Setup** — Cancelled and clean whole-filesystem runs on xsoar with a healthy collector.
- **Evidence** — Collector event type='scan_completion_summary': data.outcome, data.cancel_source, message (built 6503-6515); /opt/yara_scanner/logs/statistics_<run_id>.log final line `SCAN CANCELLED BY OPERATOR after ...` vs `SCAN COMPLETED SUCCESSFULLY in ...` (6531-6532).

### `LIFE-023` Evidence and terminal telemetry survive a fatal failure

*supporting* · on `xsoar`

- **Must be true** — A run that found at least one match and then ended in the fatal-failure branch still emits terminal scan_status='failed' and still produces its evidence ZIP, before returning its result line.
- **Threshold** — Evidence ZIP exists, is non-empty, and contains the alert text for the planted match plus file_mapping; 'Evidence collected from failed scan' present; the last 'Scan status changed to' line is 'failed'; the result line starts 'Scan failed:' and reports 'Fatal failures: 1'.
- **Setup** — Run the scanner via CLI over SSH on xsoar with a rule that matches a planted decoy early, wait for the first match to be written to alert/, then send SIGINT to the process - the KeyboardInterrupt handler sets scan_failed=True and execution falls into the fatal-failure branch at 6444.
- **Evidence** — /opt/yara_scanner/evidence/evidence_<hostname>_<run_id>.zip; /opt/yara_scanner/logs/system_<run_id>.log `Evidence collected from failed scan` (6467) or the error lines `Evidence collection failed after fatal failure:` / `Could not emit terminal status after failure:` (6464/6469); terminal 'Scan status changed to: failed' in diagnostics_<run_id>.log.

### `LIFE-026` Guaranteed finalisation order in main()'s finally block

*supporting* · on `xsoar`

- **Must be true** — The finally block runs in the fixed order stop-stats -> results_uploader.stop -> webhook_uploader.stop -> write summary -> stop_logging, so the summary's delivery counts are final and its 'written' line still reaches the logs.
- **Threshold** — t('Match delivery final') < mtime(scan_summary json) < t('Logging Summary'); the 'Scan summary written' line is present in the log file (proving it landed before stop_logging); scan_summary.match_delivery equals the numbers in the 'Match delivery final' line exactly; on failure the stderr line 'Error during final cleanup:' is absent.
- **Setup** — Flood run with a long drain (black-holed collector) so the ordering window is wide enough to resolve at 1s granularity.
- **Evidence** — Timestamps of: `Match delivery final:` in uploads_<run_id>.log (3395), the mtime of scan_summary_<run_id>.json, `Scan summary written: scan_summary_<run_id>.json` in system_<run_id>.log (2227), and `Logging Summary \| Total Logs: ...` in system_<run_id>.log (2188).

### `LIFE-031` Cancelled runs never report 'Scan completed'

***core*** · on `xsoar`

- **Must be true** — A cancelled run's result verb is 'Scan cancelled (source=<src>)' and its partial counts are never presented as a completed scan.
- **Threshold** — Result line starts exactly 'Scan cancelled (source=action_center):'; 0 occurrences of 'Scan completed' in that run's result; outcome == 'cancelled'; terminal status == 'cancelled'; files_scanned strictly less than the baseline full-scan count.
- **Setup** — Cancelled whole-filesystem run on xsoar, with a prior uncancelled baseline for the file count comparison.
- **Evidence** — The SCAN_RESULT line's first token (verb chosen at 6614-6617); scan_summary_<run_id>.json outcome; the terminal 'Scan status changed to' line in diagnostics_<run_id>.log.

### `LIFE-034` Excluded-target detection

*supporting* · on `xsoar`, `OfficeiMac`, `thor`

- **Must be true** — A scan target the operator explicitly requested but which the platform skip list excludes wholesale is recorded, logged as an error, and named on the result line - never silently reported as a clean zero-file success.
- **Threshold** — With scan_folder='/proc' (in lin_skip_directory at 2969) on xsoar: exactly 1 error line naming /proc, excluded_targets == ['/proc'], result line contains the EXCLUDED warning with N == 1 and names /proc, files_scanned == 0. Same behaviour with '/opt/traps' and, on OfficeiMac, with '/System'. Control: a scanned normal directory yields excluded_targets == [] and no warning segment.
- **Setup** — Round-3 runs with scan_folder set to an excluded root on each platform (/proc and /opt/traps on xsoar, /System on OfficeiMac), plus a normal-directory control run.
- **Evidence** — /opt/yara_scanner/logs/scan_errors_<run_id>.log `Requested scan target is excluded by the skip list, so nothing under it will be scanned: <target>` with data {'target_path','reason':'skip_list'} (5937-5942); `excluded_targets` in scan_summary_<run_id>.json; the result line's ' \| WARNING: N requested target(s) EXCLUDED by the skip list' segment.

### `LIFE-035` Per-file outcome classification and skip reasons

*supporting* · on `xsoar`

- **Must be true** — Every discovered file lands in exactly one skip_reasons bucket drawn from the fixed reason vocabulary, and files_scanned + files_skipped reconciles with the sum of the skip_breakdown counts.
- **Threshold** — sum(skip_breakdown.values() for the not-scanned reasons) == files_skipped exactly (delta 0); every skip_breakdown key is a member of the fixed set {'File does not exist','No read permission','Special system file','Junction/symlink duplicate','Not a regular file','File too large','Permission denied','Skipped directory','Junction/symlink skip'} or matches ^Scan error \([A-Za-z]+\)$; 'Scanned but not matched' never appears as a SKIP key.
- **Setup** — Whole-filesystem scan on xsoar as the non-root LINUX_USER so 'No read permission' and 'Permission denied' both populate; plant a >64MB file, a FIFO (mkfifo), a dangling symlink and a symlink loop under /home/<user>/yara_decoys/ so the size, not-regular, does-not-exist and junction-duplicate buckets are all non-zero; run with YARA_MAX_MB=64 (default).
- **Evidence** — /opt/yara_scanner/logs/statistics_<run_id>.log line 'Skip reasons: <reason>(<n>), ...' with its data payload {'total_skipped':N,'skip_breakdown':{...}} (emitted at PINNED_xsiam_current.py:5556-5557), cross-checked against the collector event type='comprehensive_final_report' field data.file_processing.skip_breakdown (built at :6094) and scan_summary_<run_id>.json fields files_scanned / files_skipped.

### `LIFE-036` Bounded skip reason for per-file scan errors

*supporting* · on `xsoar`

- **Must be true** — Per-file scan exceptions collapse into at most a handful of type-named buckets so the shipped skip_breakdown stays small regardless of how many files error.
- **Threshold** — Number of skip_breakdown keys matching ^Scan error \( <= 5, and no skip_breakdown key contains a '/' or '\\' path separator or the substring 'could not open file' or 'Errno'; total JSON byte size of the serialised skip_breakdown < 4096 bytes even when scan_errors_<run_id>.log holds >1000 'Error scanning file' lines.
- **Setup** — On xsoar, drive at least 1000 per-file errors during the whole-FS scan: run a background loop that creates and immediately unlinks ~2000 files under /home/<user>/churn/ for the duration of the walk (vanish-between-stat-and-match), and chmod 000 a further 500 files owned by the scanning user after discovery starts.
- **Evidence** — skip_breakdown keys in statistics_<run_id>.log 'Skip reasons: ...' and in the comprehensive_final_report event (data.file_processing.skip_breakdown); the per-file detail in /opt/yara_scanner/logs/scan_errors_<run_id>.log lines 'Error scanning file <path>: ...' plus stderr 'File scan error: <path> - ...' (PINNED_xsiam_current.py:5093-5101, _scan_error_reason at :999).

### `LIFE-037` Per-file error tolerance in the worker loop

*supporting* · on `xsoar`

- **Must be true** — A per-item exception inside a worker is logged and counted but never terminates the worker or the scan; files_scanned keeps advancing past the error.
- **Threshold** — If >=1 'Worker <id> error:' line exists then outcome != 'failed' and files_scanned recorded after the last such line exceeds files_scanned at the first one; the number of workers reporting 'Worker <id> stopped' equals scanner_initialization max_workers (no worker dies early).
- **Setup** — Same churn/chmod decoy load as the bounded-skip-reason criterion; capture the statistics-log progress series so files_scanned can be compared across the timestamps of the worker error lines.
- **Evidence** — scan_errors_<run_id>.log lines 'Worker <id> error: <Type>: <msg>'; system_<run_id>.log 'Worker <id> stopped' event with its errors_encountered field; scan_summary_<run_id>.json outcome and files_scanned (PINNED_xsiam_current.py inner except in _worker vs outer _mark_scan_failed at :4870).

### `LIFE-038` Permission-denied diagnostics

*supporting* · on `xsoar`

- **Must be true** — Each unreadable file produces exactly one system-log diagnostic carrying file_path, file_mode, owner_uid, scanner_uid and requires_root, and is counted once under 'No read permission'.
- **Threshold** — count of 'Permission denied:' lines == skip_breakdown['No read permission']; every such line has scanner_uid == the numeric uid of LINUX_USER (not null) and requires_root == true for at least the /etc/shadow decoy; requires_root == true for every path under /etc, /boot, /var/log, /root.
- **Setup** — Run the xsoar whole-FS scan as the unprivileged LINUX_USER (NOT sudo) so /etc/shadow, /root and /var/log/* are unreadable; additionally plant /home/<user>/yara_decoys/noread.bin owned by the user with mode 000 to prove the non-root-owned branch also fires.
- **Evidence** — /opt/yara_scanner/logs/system_<run_id>.log 'Permission denied: <path>' with data {'file_path','file_mode','owner_uid','scanner_uid','requires_root'} (PINNED_xsiam_current.py:4967-4990); skip_breakdown['No read permission'] in statistics_<run_id>.log.

### `LIFE-039` Env-var guard: numeric tuning knobs fail safe

*supporting* · on `xsoar`

- **Must be true** — A numeric env knob that is unparseable or below its minimum is rejected with a warning and the documented default is used, so the scan still scans files.
- **Threshold** — With YARA_MAX_MB=-1 and YARA_THREADS=abc set: exactly 2 'Ignoring ...' warning lines on stderr, scan_summary_<run_id>.json files_scanned > 0 (the -1 regression would give 0), and the effective max_file_bytes behaves as 64MB (a planted 100MB file is bucketed 'File too large', a 1MB file is scanned).
- **Setup** — Round-1 long scan on xsoar launched twice: once clean for the baseline, once with YARA_MAX_MB=-1 YARA_THREADS=abc YARA_QUEUE_SIZE=0 exported; plant /home/<user>/yara_decoys/big_100mb.bin and small_1mb.bin first.
- **Evidence** — stderr WARNING lines 'Ignoring invalid <NAME>=... (expected a number) - using default ...' (PINNED_xsiam_current.py:79) and 'Ignoring out-of-range <NAME>=... (minimum ...) - using default ...' (:84); the effective values in the scanner_initialization event (max_workers, queue size) and scan_summary_<run_id>.json files_scanned.

### `LIFE-040` Env-var guard: boolean toggles fail safe

*supporting* · on `xsoar`

- **Must be true** — A malformed boolean env toggle warns and falls back to the source-literal default rather than crashing at import or silently disabling a monitor.
- **Threshold** — With YARA_ENABLE_PERF_MONITOR=maybe and YARA_ENABLE_RESOURCE_MONITOR=on: exactly 1 warning line (for the malformed one only), scanner_initialization.performance_monitoring_enabled == the source default (False) and resource_monitoring_enabled == true; process exit code is not 1 from a startup error.
- **Setup** — Round-1 run with YARA_ENABLE_PERF_MONITOR=maybe YARA_ENABLE_RESOURCE_MONITOR=on YARA_ENABLE_FD_MONITOR=yes exported.
- **Evidence** — stderr line 'Ignoring invalid <NAME>=... (expected true/false) - using default ...' (PINNED_xsiam_current.py:149, _env_bool at :135); the collector event type='scanner_initialization' fields performance_monitoring_enabled and resource_monitoring_enabled.

### `LIFE-041` Post-parse clamping of lifecycle knobs

*supporting* · on `xsoar`

- **Must be true** — Legal-but-unusable knob values are clamped after parsing: cancel poll >= 0.5s, log_interval >= 1s, scan_queue_size >= 2, max_workers >= 1, upload batch >= 1 event / >= 64KB — and no clamp busy-spins.
- **Threshold** — With YARA_PROGRESS_LOG_SECS=0 YARA_QUEUE_SIZE=0 YARA_CANCEL_POLL_SECS=0 YARA_THREADS=99: progress entries arrive at 1.0s +/- 0.3s intervals (not continuously) and total progress entries <= elapsed_seconds + 5; scan_queue_size >= 2. NOTE the min(2,...) worker cap named in the capability text is STALE — pinned :2834 is max(1, configured_workers), so YARA_THREADS=99 must yield max_workers == 99, not 2; assert 99 and flag the doc, do not assert <=2.
- **Setup** — Round-1 run on xsoar (8 cores) with YARA_PROGRESS_LOG_SECS=0 YARA_QUEUE_SIZE=0 YARA_CANCEL_POLL_SECS=0 YARA_THREADS=99 exported; sample per-thread CPU during the run to confirm no busy-spin.
- **Evidence** — scanner_initialization event fields max_workers and scan queue size; the cadence of 'Scan Progress' entries in statistics_<run_id>.log / performance_<run_id>.log (heartbeat interval); process CPU of the ProgressHeartbeat thread via `top -H -p <pid>` on xsoar. Source clamps at PINNED_xsiam_current.py:211 (CANCEL_POLL_SECS), :2834-2836 (max_workers, scan_queue_size), :2850 (log_interval), :283-284 (batch clamps).

### `LIFE-042` alert_severity input validation

*supporting* · on `xsoar`

- **Must be true** — An alert_severity outside {low,medium,high} is rejected, and the two entry points fail in their documented, different ways.
- **Threshold** — CLI with argv[3]='CRITICAL': stdout contains zero lines starting 'SCAN_RESULT:' and exit code == 1. CLI with argv[3]=' HIGH ' (padded/mixed case): accepted, scan proceeds, and alert payloads carry severity 'high'. argv[3] omitted/None: severity 'low'.
- **Setup** — Three short scans on xsoar limited to a single small folder (scan_folder=/home/<user>/yara_decoys) with argv[3] = 'CRITICAL', ' HIGH ', and omitted.
- **Evidence** — CLI path: stderr 'Critical startup error: Invalid alert_severity ...' with traceback, no 'SCAN_RESULT:' line on stdout, exit 1 (_parse_alert_severity at PINNED_xsiam_current.py:875; argv parse at :6818). Action Center path: stdout 'SCAN_RESULT: Scan failed: 0 files scanned \| ... \| Critical error occurred', exit 1.

### `LIFE-043` scan_folder validation and multi-target contract

*supporting* · on `xsoar`

- **Must be true** — A comma-separated scan_folder list is trimmed, de-duplicated by abspath, invalid entries are dropped with a loud warning, and an all-invalid list aborts rather than silently scanning everything.
- **Threshold** — Input ' /home/<user>/yara_decoys , "/home/<user>/yara_decoys/" , /home/<user>/other , /nope ' yields scan_targets of length exactly 2 (the quoted/trailing-slash duplicate deduped), one 'Ignoring 1 specified scan folder(s)' warning naming /nope, and files under /nope-free scopes only. Input '/nope,/alsonope' yields the SCAN_RESULT critical-error line and exit 1 with files_scanned == 0.
- **Setup** — Create /home/<user>/yara_decoys and /home/<user>/other on xsoar; run twice with the two scan_folder strings above.
- **Evidence** — /opt/yara_scanner/logs/yara_processing_<run_id>.log 'Scan limited to N folder(s): [...]' (PINNED_xsiam_current.py:3047) and the warning 'Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]' (:3043); scan_targets in scan_summary_<run_id>.json and in the scanner_initialization event; the ValueError text 'No valid scan directory among the specified scan folder(s): [...]' (:3040).

### `LIFE-044` Placeholder-collector-credential abort

***core*** · on `xsoar`

- **Must be true** — With UPLOAD_RESULTS on and unedited placeholder collector credentials, the run aborts before scanning anything and exits non-zero.
- **Threshold** — exit code == 1; stdout result line starts exactly 'SCAN ABORTED'; zero 'Target scan completed' lines in statistics_<run_id>.log and no alert file created under <scanner_dir>/alert/.
- **Setup** — On xsoar, run a copy of the script with DEFAULT_API_KEY/DEFAULT_API_ENDPOINT left at the shipped placeholders ('http_collector_key'/'http_collector_api'), UPLOAD_RESULTS unchanged, and YARA_SCANNER_DIR=/home/<user>/yara_abort_test so the real /opt/yara_scanner artefacts are not touched.
- **Evidence** — stdout 'SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. ...' (PINNED_xsiam_current.py:6222-6226); the same text in <scanner_dir>/logs/scan_errors_<run_id>.log; exit-code arm _rt.startswith('scan aborted') at :6845.

### `LIFE-045` Rule-compilation fatal errors terminate the run before scanning

***core*** · on `xsoar`

- **Must be true** — Each of the three fatal compilation cases stops the run before any file is scanned, with the case-specific message, and never writes a scan summary.
- **Threshold** — Case A (every rule syntactically broken): stderr message == 'No valid YARA rules could be compiled out of N rules.' with N == rules submitted, exit 1, no scan_summary_<run_id>.json. Case B (every rule imports a module libyara 3.11.0 on xsoar lacks, e.g. `import "dotnet"`): message contains 'an agent capability limit, not a rule syntax error'. Case C (content with no parseable rule blocks): failed_rules/raw_yara_content.yar exists and byte-equals the decoded input.
- **Setup** — Three short runs on xsoar with purpose-built packs: (A) 5 rules each with a deliberate syntax error; (B) 5 rules that all `import "dotnet"`/`import "magic"` (absent in the agent's libyara 3.11.0); (C) a blob that decodes to text with rule-like noise but no compilable rule body.
- **Evidence** — stderr 'CRITICAL: YARA rule compilation failed: <msg>' (PINNED_xsiam_current.py:4724) with the 'Valid rules: X, Failed rules: Y, Skipped: Z' line; <scanner_dir>/logs/yara_processing_<run_id>.log SPLIT_ERROR (:4572) / COMPILATION_ERROR / FINAL_COMPILATION_ERROR entries; <scanner_dir>/failed_rules/raw_yara_content.yar (:4580); absence of logs/scan_summary_<run_id>.json.

### `LIFE-046` Module-skipped rules counted separately from failures

***core*** · on `xsoar`

- **Must be true** — Rules the agent's libyara cannot run are reported as skipped, not as a clean zero-failure compile.
- **Threshold** — With a mixed pack of 10 runnable rules + 5 module-dependent rules on xsoar (libyara 3.11.0): scan_summary_<run_id>.json skipped_rules == 5, failed_rules == 0, valid_rules == 10, and the 'Skipped 5 rules due to unavailable modules' line is present.
- **Setup** — Mixed pack: 10 plain string rules plus 5 rules that `import "dotnet"` or `import "magic"`; run on xsoar so the module gap is real.
- **Evidence** — <scanner_dir>/logs/yara_processing_<run_id>.log line 'Skipped N rules due to unavailable modules' (PINNED_xsiam_current.py:4706) and the COMPILATION SUMMARY block (:1418); scan_summary_<run_id>.json field "skipped_rules" (written at :6777 — the capability's observe claim that the count reaches no file is STALE, it is now in the summary JSON).

### `LIFE-047` Privilege detection and privilege_status telemetry

*supporting* · on `xsoar`, `OfficeiMac`

- **Must be true** — Non-root runs on POSIX emit exactly one privilege_status event with running_as_root=false, and root runs emit none while still logging privilege locally.
- **Threshold** — Non-root xsoar run: exactly 1 privilege_status event, running_as_root == false, recommended_action == 'run_as_sudo'. Root xsoar run (sudo): 0 privilege_status events, and system log still carries a 'Running as: root' line. OfficeiMac non-root run: privilege_status present with data.platform == 'linux' — assert the hardcoded value and flag it as a defect for macOS.
- **Setup** — Three round-3 runs: xsoar as LINUX_USER, xsoar under sudo, OfficeiMac as the console user. Query the tenant for events with scan_id == the run's scan_id and type == 'privilege_status'.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log 'Running as: root\|non-root user on Linux\|macOS' plus the WARNING/TIP lines; collector event type='privilege_status' with data.running_as_root, data.recommended_action, data.platform (built inside `if not is_root:` at PINNED_xsiam_current.py:6271-6280).

### `LIFE-053` scan_system finally-block guarantee

*supporting* · on `xsoar`

- **Must be true** — Cleanup and the final books run on every exit path, including a mid-run cancellation, so workers are always joined and a final results line is always written.
- **Threshold** — On the cancelled run: both cleanup lines present, a final results line present, scan_summary_<run_id>.json exists with outcome == 'cancelled', and `ps -eLf` shows zero surviving scanner threads 10s after the process exits. Same three artefacts present on the clean run and on the broken-pack-after-init run.
- **Setup** — Round-3 cancellation: start the whole-FS scan on xsoar, wait until statistics shows >5000 files scanned, then run `python3 xsiam_yara_scanner.py cancel` from a second SSH session.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log '=== ENHANCED CLEANUP AND FINALIZATION ===' and 'Enhanced cleanup completed in X seconds'; the 'SCAN COMPLETED'/'SCAN FAILED' final line; scan_summary_<run_id>.json (scan_system's finally -> _perform_enhanced_cleanup at PINNED_xsiam_current.py:6019 then _log_final_results).

### `LIFE-055` Cleanup scheduling gated on rule-processing health

*supporting* · on `xsoar`

- **Must be true** — Self-cleanup is scheduled on healthy runs and deliberately skipped when nothing compiled, leaving artefacts on the endpoint for diagnosis.
- **Threshold** — Healthy run (valid_rules > 0): the 'scheduled successfully' line appears exactly once and the cleanup script/task exists. All-rules-fail run (valid_rules == 0 and has_errors): the 'Cleanup skipped' line appears, no cleanup task is registered (`crontab -l` / systemd timer list unchanged), and <scanner_dir>/logs still contains that run's files 5 minutes later.
- **Setup** — Reuse the deliberately-broken-rule-pack run on xsoar for the negative case; a normal whole-FS run for the positive case; snapshot `crontab -l` and `systemctl list-timers` before and after each.
- **Evidence** — <scanner_dir>/logs/system_<run_id>.log 'Cleanup task/service scheduled successfully' (PINNED_xsiam_current.py:6547) vs 'Cleanup skipped due to critical YARA processing errors' (:6549); scan_errors_<run_id>.log 'Error scheduling cleanup: ...'; the generated cleanup script on disk under <scanner_dir>.

### `LIFE-061` Scanner working-directory selection (shared by both entry points)

*supporting* · on `thor`

- **Must be true** — YARA_SCANNER_DIR relocates the whole working tree, and the cancel entry point resolves the same directory as the scan entry point.
- **Threshold** — With YARA_SCANNER_DIR=/home/<user>/yara_alt exported for BOTH the scan and the cancel invocation: all five subdirectories exist under /home/<user>/yara_alt, /opt/yara_scanner gains no new *_<run_id>.log, and the cancel result string names /home/<user>/yara_alt/control/cancel.flag which exists on disk. Unset: paths are /opt/yara_scanner on xsoar, /usr/local/yara_scanner on OfficeiMac, C:\yara_scanner on thor.
- **Setup** — Round-3 relocated run on xsoar plus a cancel from a second session with the same env var; one default-path run on each of xsoar, OfficeiMac and thor to confirm the per-platform defaults.
- **Evidence** — The directory tree <scanner_dir>/{logs,control,alert,evidence,failed_rules}; the flag path echoed in the cancel result string 'Cancel signal delivered (<scanner_dir>/control/cancel.flag)' (PINNED_xsiam_current.py:868); _default_scanner_dir at :813-822 (Windows C:\yara_scanner, Darwin /usr/local/yara_scanner, else /opt/yara_scanner).

### `LIFE-062` `cancel` as the first CLI argument (cancel keyword dispatch)

*supporting* · on `xsoar`

- **Must be true** — Passing `cancel` (any case, any surrounding whitespace) as argv[1] writes the cancel flag, reports whether a scan is alive, touches no logs, and the running scan finishes with outcome 'cancelled' promptly.
- **Threshold** — Cancel while a scan is live: result line reports 'scanner running: yes' with the live scan_id (matching control/running.json), cancel.flag exists with both JSON keys, exit 0; ZERO new *_<run_id>.log and zero new scan_summary_*.json created by the cancel process itself; the scanning process exits and writes outcome=='cancelled' within 10s of the flag's mtime. Cancel with nothing running (running.json older than 180s or absent): 'scanner running: no'. ' CANCEL ' and 'Cancel' behave identically.
- **Setup** — Round-3: start the xsoar whole-FS scan, wait for >5000 files scanned, then from a second SSH session run `python3 xsiam_yara_scanner.py ' CANCEL '`; snapshot the logs dir before and after the cancel invocation; repeat the cancel with no scan running.
- **Evidence** — stdout 'SCAN_RESULT: Cancel signal delivered (<scanner_dir>/control/cancel.flag) \| scanner running: yes\|no \| scan_id=<id>' (string at PINNED_xsiam_current.py:866-870, dispatch at :6822, print at :6837) or 'SCAN_RESULT: Cancel failed: ...' with exit 1 via the 'cancel failed' arm at :6846; the file <scanner_dir>/control/cancel.flag containing {"requested_at_ms":...,"source":"action_center"}; the cancelled run's scan_summary_<run_id>.json "outcome":"cancelled".

### `LIFE-063` Critical-error handler prints the Python traceback to STDOUT before the result line

*supporting* · on `xsoar`

- **Must be true** — When main() dies with an unhandled exception, stdout carries a multi-line traceback block ahead of the SCAN_RESULT line and the process sleeps ~2s — breaking any consumer that parses the first line and leaking absolute paths.
- **Threshold** — stdout line count before the SCAN_RESULT line >= 3 and the stdout text contains 'Traceback (most recent call last)' and at least one absolute endpoint path — record this as a CONFIRMED defect, not a pass; exit code == 1; wall-clock delta between the last log write and process exit >= 2.0s; scan_summary_<run_id>.json outcome == 'failed' with exactly 1 failure_reason.
- **Setup** — Drive main() into the critical-error path with the all-rules-syntactically-broken pack on xsoar (compilation failures raise out of YaraScanner.__init__ inside main's try), capturing stdout and stderr separately and timestamping process exit.
- **Evidence** — Process stdout: literal lines 'CRITICAL ERROR: Critical scanner error: <msg>', 'Error details: Traceback (most recent call last): ...', 'Process failed with critical error' (PINNED_xsiam_current.py:6659-6661) then 'SCAN_RESULT: Scan failed: ... \| Critical error occurred'; stderr 'SCAN_STATUS: ERROR' (:6656); time.sleep(2) at :6664; scan_errors_<run_id>.log 'CRITICAL_ERROR: ...'; scan_summary_<run_id>.json "outcome":"failed" with failure_reasons == ['Critical scanner error: <ExcType>'] (:6719, :6748).

### `LIFE-064` Placeholder-credential abort still wipes alert/, evidence/ and old run logs first — and writes no scan summary

*supporting* · on `xsoar`

- **Must be true** — The placeholder-credential abort is destructive, not side-effect-free: alert/ and evidence/ are emptied and old run logs pruned before the abort, and no scan_summary JSON is written for the aborted run.
- **Threshold** — Before the run, alert/ and evidence/ each hold >=1 file from a prior successful run and logs/ holds N+1 run_ids where N = LOG_KEEP_SCANS. After the abort: `ls <scanner_dir>/alert \| wc -l` == 0 and `ls <scanner_dir>/evidence \| wc -l` == 0; the oldest run_id's logs are gone; `test -e logs/scan_summary_<run_id>.json` fails; exit code == 1.
- **Setup** — On xsoar with YARA_SCANNER_DIR=/home/<user>/yara_abort_test: first do a real successful scan there to populate alert/ and evidence/ and several run_ids, then run the copy with placeholder DEFAULT_API_KEY/DEFAULT_API_ENDPOINT and diff the directory listings.
- **Evidence** — stdout 'SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. ...' exit 1; under <scanner_dir>: logs/scan_errors_<run_id>.log containing that text, a full set of alerts_/statistics_/scan_errors_/performance_/uploads_/system_<run_id>.log, alert/ and evidence/ present and EMPTY (rmtree+recreate inside CleanupManager.initial_cleanup, called at PINNED_xsiam_current.py:6213 before the credential check at :6222-6226), and the decisive negative: logs/scan_summary_<run_id>.json ABSENT.

---

# Not covered (6)

These are **not** silently dropped. Each has a stated reason, and each is a
candidate for a follow-up change rather than a test.

| ID | Capability | Reason | What would close it |
|---|---|---|---|
| `RULE-002` | Rule input size cap | `wont-run` | Rewrite Observe to: "Pass a base64 blob longer than 50,000,000 characters. stderr shows `YARA Scanner Critical Error: Critical scanner error: YARA rules input too large` followed by `SCAN_STATUS: ERROR` (main's handler, lines 6651-6656), and the SCAN_RESULT line reads `Scan failed: 0 files scanned \| ... \| Critical error occurred` with exit code 1. logs/yara_processing_<run_id>.log already exists with its 4-line banner and ends with `CRITICAL: Failed to decode YARA rules: YARA rules input too… |
| `RULE-021` | Compile-time externals declaration | `no-artefact` | A rule whose condition uses `filename_lower` compiles (counts toward `Valid rules compiled`) rather than producing an `undefined_identifier` entry in the compilation-failure block. |
| `RULE-028` | Un-splittable pack forensics | `cannot-construct` | `failed_rules/raw_yara_content.yar` prefixed `// RAW YARA CONTENT - Failed to split into individual rules`; `yara_processing_<run_id>.log` carries `COMPILATION_ERROR: No YARA rules found in provided content`. |
| `RULE-029` | Split-stage failure isolation | `wont-run` | `yara_processing_<run_id>.log`: `SPLIT_ERROR: Failed to split YARA rules: <exc>`. |
| `RULE-033` | Combined-compile failure reporting | `cannot-construct` | `yara_processing_<run_id>.log`: `COMBINED_COMPILATION_ERROR: <exc>` — distinct from `FINAL_COMPILATION_ERROR`, and the only path where valid_rules_count > 0 yet no scan runs. |
| `RULE-044` | Dead cached-hit dict ingestion path in match-field extraction | `needs-instrumentation` | UNOBSERVABLE: no live scan can reach it, so it cannot be a runtime test criterion. Every finding on a real scan takes the else-branch (993-995), because `matches` is always the return of self.rules.match(...) at 4911-4915. Confirmable only statically, or by a unit-level call such as _iter_hit_fields({'rule': 'r', 'strings': [(0, '$a', '4d5a')]}) asserting the returned data is b'MZ' (confirmed by direct execution). Making it observable on a scan would require a cache writer that persists hits… |
| `TRAV-008` | Unknown-platform target fallback | `wont-run` | Rewrite Observe to: "Both halves are now checkable: `Unknown platform - manual target specification required` in yara_processing_<run_id>.log (3162), and the exact line `Using default Unix target: ['/']` in <scanner_dir>/logs/diagnostics_<run_id>.log (logging.info at 5423). The sibling `Using default Windows targets: [...]` (5420) and `Using configured scan targets: [...]` (5415) land in the same file, so the branch actually taken is distinguishable." |
| `TRAV-018` | File-level junction skip, counted | `cannot-construct` | `Junction/symlink skip` key in the `Skip reasons: ...` statistics line (line 5411) and in `file_processing.skip_breakdown` of the `comprehensive_final_report` event (line 5917); `junction_skips` in `Scan Progress` metrics |
| `TRAV-019` | Real-path deduplication (present but disabled) | `disabled-by-design` | negative assertion: `unique_real_paths` in `Scan Progress` metrics and `unique_paths_scanned` in the final statistics data are always 0, and `Junction/symlink duplicate` never appears in `skip_breakdown`. If either becomes non-zero the flag was flipped |
| `TRAV-031` | No directory skipping on unrecognised platforms | `wont-run` | negative test: skip_breakdown contains no `Skipped directory` entries attributable to platform lists |
| `TRAV-037` | Second-line skip check inside the worker | `no-artefact` | `Special system file` appearing in `skip_breakdown` from the worker path (distinguishable in the local logs from the walk-loop attribution, which increments the same key at line 5843) |
| `TRAV-045` | macOS case-sensitivity probe file written to /tmp for every file that reaches the scan body | `needs-instrumentation` | UNOBSERVABLE from the scanner: no log line, no summary field. The two fields that would hint at it — `unique_real_paths` (5367, inside the additional_metrics dict shipped by log_scan_progress at 5372-5375) and `unique_paths_scanned` (5393, in _log_final_results) — are both `len(self.scanned_real_paths)` and are always 0, because the only `.add()` is at 4907 behind track_real_paths. To confirm it, watch the filesystem outside the scanner: `sudo fs_usage -w -f filesys \| grep CaSe_TeSt_YaRa` on… |
| `PERF-010` | Governor fail-open when CPU cannot be read | `unsafe-injection` | One performance log line: `CPU governor disabled - could not read CPU (<err>). Scan continues unthrottled.` and no further `CPU governor \|` lines for the rest of the run. |
| `PERF-013` | Governor sampling during producer backpressure | `unreachable` | `CPU governor \|` lines continue to appear interleaved with `Scan queue saturated (...)` lines on a scan where discovery outruns the workers. |
| `PERF-045` | File-descriptor leak sampling (skipped on every matched file, and on every skipped file) | `needs-instrumentation` | UNOBSERVABLE: a sample that finds nothing emits nothing, so you cannot tell whether a sample ran, was skipped by a match/skip path, or was lost to the unlocked increment. The only artefacts are threshold breaches in `<scanner_dir>/logs/system_<run_id>.log` (`logs_dir` built at 2686, SYSTEM file name at 1785): `Initial file descriptors in use: N` once at startup (6160), then `FD usage increased by <n> (current: <n>)` only when growth exceeds 100 (4970-4973) and `WARNING: High FD usage: <n>`… |
| `DELI-004` | Approximate byte accounting for batch sizing | `no-artefact` | Inspect request sizes at the collector or on the wire: batches stay near but can overshoot the cap by at most one event. A finding carrying an unusually large matched string is the case to test. |
| `DELI-006` | Circuit breaker on the telemetry channel | `unsafe-injection` | UNOBSERVABLE: With a dead collector, telemetry POSTs stop entirely for ~40 s windows while the queue grows; the per-type `total` in WebhookUploader.get_upload_statistics() (and scan_summary's telemetry_delivery) stays flat during an open window rather than inflating, and undelivered rises at shutdown. To close it: Minimal instrumentation: in CircuitBreaker.on_failure (1202-1210), emit on the two transitions into 'open' (after 1207 and after 1210) `logging.warning(f"Telemetry circuit opened… |
| `DELI-053` | Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the collector sees | `no-artefact` | On the wire: a lone JSON object with `Content-Type: application/json` arriving out of band from the `text/plain` NDJSON batches. Locally, in `uploads_<run_id>.log` (path 1784): on a non-2xx, `Critical log immediate send failed (HTTP <code>): ... - falling back to async queue` (1973-1976); on an exception, `Critical log immediate send raised <ExcType>: ... - falling back to async queue (may deliver a duplicate if the request actually landed)` (1983-1986); if the fallback itself fails or no… |
| `DELI-055` | Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-bounce) | `unsafe-injection` | On the wire: during an induced collector outage, event arrival order for a single `scan_id` diverges from the `timestamp` field ordering. Locally there is almost nothing: the open-circuit path writes NO line, and the only failure line this method produces is `Webhook unexpected error for batch: ...` (3693), which goes through `log_manager.log_error` into `scan_errors_<run_id>.log` — NOT the uploads log. On a plain non-2xx or on retry exhaustion this method logs nothing at all. The only… |
| `LIFE-022` | Fatal worker failure path | `wont-run` | Rewrite Observe to: "Instrumented, but not a live-scan criterion. When it fires, grep <scanner_dir>/logs/scan_errors_<run_id>.log for `Worker <thread-name> fatal error: <exc>` (log_manager.log_error at 4868-4869), followed by `Scan stopped due to fatal failures` (6451), scan_status 'failed' (6462) and outcome='failed' in scan_summary_<run_id>.json (6764). It cannot be provoked by file content - scan_file's blanket handler (5093-5099) and _worker's inner handler (4862-4866) absorb everything… |
| `LIFE-024` | Critical-error path in main() | `unsafe-injection` | stderr contains 'SCAN_STATUS: ERROR'; collector has a scan_completion_summary with data.status='critical_error'; <scanner_dir>/logs/script_exceptions_<run_id>.log exists (created lazily, only when an exception is logged); result line ends 'Critical error occurred'. |
| `LIFE-025` | KeyboardInterrupt handling | `no-delivery-path` | system log 'Scan interrupted by user (Ctrl+C)'; scan_status='interrupted' event; summary outcome='failed' with that reason; result line 'Scan failed: ...'. |
| `LIFE-065` | One failing scan target is abandoned mid-walk; the rest of the scan continues and still reports success | `wont-run` | Three-way check on one run. (1) `logs/scan_errors_<run_id>.log` contains `Error scanning target <path>: <exception>` (log_error 2010-2012 -> `_log_with_webhook` 1901-1911 -> LogType.ERROR file, mapped at 1782). (2) `logs/statistics_<run_id>.log` contains `Target scan completed: <target>` for every other target but **not** for that one — this is the load-bearing negative, and it holds only for this handler's exceptions, not for walk-level OS errors, which still reach the success path; the same… |

## Reachability probes (3)

Two independent triage passes marked these dead. A spot-check then found a false
positive among them — *Unnamed-rule fallback naming* does fire, on the
compile-failure path — because both passes hunted for **callers**, which is the wrong
test for a dead **branch** inside a live function. So none is deleted on the triage's
word. Round 3 probes whether the branch is reached; deletion needs a probe that comes
back empty.

| ID | Capability |
|---|---|
| `RULE-011` | Unnamed-rule fallback naming |
| `RULE-038` | Rule-count propagation into scan telemetry |
| `RULE-039` | Diagnostic-preserving cleanup suppression |
