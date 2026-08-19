# XDR YARA Scanner — Live Acceptance Test Plan

> Every one of the **467 catalogued XDR capabilities** is assigned here: to one
> of three live rounds, or to an explicitly-reasoned `not covered`. Nothing is left
> implicit. Criteria are agreed **before** any scan runs.

The rounds are **reshaped from the XSIAM three**, not copied. XSIAM ships findings
through one channel; XDR ships through two independent ones — Insert Parsed Alerts
and XQL lookup datasets — with different batching, different drains and separate
books. Round 2 is therefore delivery-specific rather than a general flood, so the
half of the scanner XSIAM has no equivalent of is tested directly rather than
incidentally.

Reshaped from the XSIAM three so that XDR's delivery subsystem gets a round of its own.
XSIAM ships findings through ONE channel (an HTTP Log Collector taking NDJSON). XDR ships
through TWO independent ones with completely different failure modes — Insert Parsed
Alerts (batched, rate-limited, requeueing, capped at 60 alerts per POST) and XQL lookup
datasets (sharded, monthly-rotated, separately drained and separately booked). Folding
that into a general "flood" round would leave the half of the scanner XSIAM has no
equivalent of tested only incidentally.

## Assignment rule

A capability belongs to the round whose conditions actually **drive** its code path, not
merely the round that touches it. Rule compilation happens in all three rounds; it belongs
to Round 3, where malformed and module-dependent packs actually probe it. Alert batching
happens in every round; it belongs to Round 2, because only a flood fills a batch.

The capability's dimension is a prior, not a rule. Move any capability whose sharpest test
lives in another round, and say why.

---

## Round 1 — Resource discipline and host footprint

**Scan shape:** a large, mostly-CLEAN tree (whole filesystem or a big real directory) with
a ruleset that matches almost nothing. Long enough to span many governor samples and
several progress heartbeats.

**Why clean:** findings are Round 2's subject. Here they are noise — a flood would saturate
delivery and change the timings this round is measuring.

**Drives:** worker pool sizing and lifecycle, the CPU governor (headroom/budget/none,
pacing, floor, sampling cadence), scan-queue sizing and saturation, FD monitoring, memory
and psutil sampling, performance snapshots, progress heartbeats, per-worker throughput
reporting — and everything the scanner WRITES to the endpoint: scanner-directory layout,
the seven log files, rotation and retention, the rule cache on disk, temp files, host
cleanup and its scheduled units.

**Failure policy:** stop-on-fail. Resource discipline is foundational — if the governor or
the worker pool misbehaves, Rounds 2 and 3 are measuring a broken baseline.

---

## Round 2 — Delivery, aggregation and telemetry under load

**Scan shape:** a FLOOD. A ruleset engineered to match essentially every file in a bounded
tree, sized to exceed the alert cap, fill batches, trip the per-minute rate limit, and push
both channels past their drain budgets.

**Drives, alert channel:** Insert Parsed Alerts batching and the 60-per-POST hard cap,
`ALERT_MIN_BATCH_INTERVAL` pacing, retry and exponential backoff, the rate-limited requeue
path and `ALERT_MAX_DELIVER_SECS`, the alert grain (one per file×rule, not per offset), the
within-scan dedup set, `CONFIG_ALERT_MAX_PER_SCAN` suppression and the per-rule storm
rollups that report it, the backlog-scaled end-of-scan drain, and the delivery books —
`findings / alerts_queued / successful_uploads / failed_uploads / undelivered / suppressed
/ rollups / requeued`.

**Drives, dataset channel:** lookup dataset schemas, sharding, monthly rotation, the
separate lookup drain budget and its own leftover accounting, rows-per-finding caps, and
the offset grain that distinguishes the dataset from the alert.

**Drives, shared:** the alert-directory byte ceiling, the delivery shortfall surfaced on
the Action Center result line, and throttled upload logging.

**The books are the spine of this round.** `ok + failed + undelivered` must reconcile
against what was ever queued, on BOTH channels. A criterion that only checks a field is
PRESENT passes on a broken build — that is exactly how the XSIAM double-count survived its
first criterion.

**Failure policy:** collect-through.

---

## Round 3 — Detection precision, targeting and lifecycle

**Scan shape:** crafted. Malformed and module-dependent rule packs, duplicate rule names,
planted decoys and controls, targeted paths, junctions and symlinks, deliberately bad
option strings and env values — plus a cancellation delivered mid-walk on a long scan.

**Drives:** rule decoding, validation, preamble and import handling, module-availability
probing, pack splitting, the compile cache and its sidecar, compile error classification;
scan-target resolution and its fallback ladder, every skip list and the force-scan
allowlist with its `force_scan_never_under` backstop, junction and reparse handling,
size and special-file gates; the options string and its validation and precedence,
cooperative cancellation, thread cleanup and shutdown ordering, per-file and fatal error
handling, skip-reason cardinality, the final report and `scan_summary_<run_id>.json`.

**Every skip predicate needs a POSITIVE and a NEGATIVE case.** "It skipped something" and
"it skips everything" are indistinguishable otherwise. Prefer the real path with a planted
sibling as the control, since absolute-path predicates cannot be reached by a synthetic
copy.

**Failure policy:** collect-through.

---

## Endpoints

This tenant has exactly two enrolled hosts, both GCP `e2-highcpu-8` (8 vCPU) in
`us-central1-f`:

| Host | OS | XDR agent |
|---|---|---|
| `xdr-agent` | Ubuntu 22.04 | 9.2.0.134 |
| `xdragent2` | Windows Server 2022 | 9.2.0.90 |

**There is no macOS endpoint on this tenant**, so Darwin-only capabilities cannot be
decided by any live run here and are marked `not_covered` with that reason. The sibling
XSIAM tenant's macOS host cannot stand in: the two editions are separate codebases.
Multi-platform capabilities that merely include a macOS leg keep their criterion and lose
that leg only.

## Settled decisions

| Decision | Choice | Why |
|---|---|---|
| Delivery channels | **ON** in every round | The delivery balance sheets are themselves catalogued capabilities; with uploads off they are structurally untestable. |
| Cancellation | **Round 3** | A resilience property, and a long crafted scan is the only run that can be cancelled mid-walk rather than during teardown. |
| Dataset writes | **ON** in every round | `write_dataset=false` would make the lookup half of Round 2 unreachable and would silently change Round 1's I/O profile. |
| Round 1 clean vs flood | **Clean** | A flood changes the timings Round 1 exists to measure. |

## Criterion format — every field required unless stated

| Field | Meaning |
|---|---|
| `must_be_true` | The binary claim. It either holds in the evidence or it does not. |
| `threshold` | The numeric or exact-value bar, where one exists. Empty when the claim is categorical. |
| `setup` | What the run must do to reach this code — planted decoy, env var, rule shape, mid-run action. Empty means the standard run for that round reaches it. |
| `evidence` | The exact artefact that decides it: a file path, a `scan_summary_<run_id>.json` field, a log line, or an XQL query over a named dataset. |
| `priority` | `core` = a promise a customer would notice breaking. `supporting` = the mechanism behind one. `low` = diagnostic detail. |

**A criterion that cannot fail is not a criterion.** Each must name a value to compare or an
artefact whose absence is itself the failure.

## Where evidence lives

- **On the endpoint** — `<scanner_dir>/logs/` (six category logs plus
  `diagnostics_<run_id>.log`), `alert/`, `evidence/`, `control/`, and
  `scan_summary_<run_id>.json`.
- **On the tenant** — XQL over `yara_scanner_matches_v3_*` and the scans/lifecycle
  datasets, plus the Insert Parsed Alerts side. Some capabilities can ONLY be decided here.

Action Center truncates a script's stdout at 10,240 characters, so bulk evidence must come
back compressed and chunked. Do not write a criterion whose evidence is "the whole log on
stdout".

## not_covered

Assign `not_covered` rather than inventing a criterion when the capability genuinely cannot
be decided on a live run — dead code, a dead constant, behaviour that leaves no artefact,
or an input no delivery path can carry. **State the reason concretely**, naming what would
be needed. 30 entries carry an inline ⚠ OBSERVABILITY GAP marker and are the obvious
candidates, but the marker is a prior, not a verdict: some marked entries are decidable by
a negative assertion, and some unmarked ones are not decidable at all.

## Coverage

| Round | Title | Capabilities | core | Endpoints | On failure |
|---|---|---|---|---|---|
| **1** | Resource discipline and host footprint | 134 | 27 | `xdr-agent` (Ubuntu 22.04) | stop-on-fail |
| **2** | Delivery, aggregation and telemetry under load | 106 | 44 | `xdr-agent` (Ubuntu 22.04), `xdragent2` (Windows Server 2022) | collect-through |
| **3** | Detection precision, targeting and lifecycle | 204 | 62 | `xdr-agent` (Ubuntu 22.04), `xdragent2` (Windows Server 2022) | collect-through |
| — | Not covered, each with a stated reason | 23 | — | — | — |
| | **Total** | **467** | **136** | | |

**444 of 467 capabilities carry a live criterion.**

---

# Round 1 — Resource discipline and host footprint

134 capabilities · 27 core · `xdr-agent` (Ubuntu 22.04) · stop-on-fail

## Rule Handling

### `RULE-010` ErrorLogger.close() — Windows file-handle release before cleanup

*supporting*

- **Must be true:** On Windows, with host cleanup enabled and the run completing, this run's yara_processing log is actually removed from disk — the handler was closed first, so os.remove() does not fail with WinError 32.
- **Threshold:** After the run: <scanner_dir>\logs\yara_processing_<run_id>.log does NOT exist, and neither does diagnostics_<run_id>.log; zero 'host cleanup could not remove' lines in the Action Center stderr/output; scan_summary_<run_id>.json outcome == "completed".
- **Setup:** Windows endpoint (xdragent2). Deliver a snippet with CONFIG_HOST_CLEANUP patched to "always" and CONFIG_HOST_CLEANUP_KEEP = "summary" — neither has an options-string or env equivalent, so the constant must be edited in the delivered payload. Run to normal completion (no cancel). Confirm over SSH (`gcloud compute ssh ayman@xdragent2 --zone=us-central1-f`) rather than through stdout.
- **Evidence:** Directory listing of <scanner_dir>\logs\ after the run (absence of yara_processing_<run_id>.log and diagnostics_<run_id>.log is the artefact); presence of scan_summary_<run_id>.json with outcome == "completed"; the Action Center output searched for the fragment 'host cleanup could not remove' (emitted via logging.warning from HostCleanup.run).
- **Negative control:** A PREVIOUS run's yara_processing_<other_run_id>.log left in the same logs_dir must still be present afterwards — HostCleanup matches on CleanupManager._extract_run_id_from_log_name and must delete only this run's files, never the retained scan history.
- **Why this round:** Departs from the RULE prior. The behaviour is only reachable when host cleanup runs, which requires outcome == "completed" — Round 3's mid-walk cancellation forecloses it, and ROUNDS.md places host cleanup and its scheduled units in Round 1's host-footprint scope.

### `RULE-053` Cache pruning by file count and total bytes (LRU)

*supporting*

- **Must be true:** After more distinct packs than the cap, the cache directory is bounded to RULE_CACHE_MAX_FILES entries and the entry evicted is the oldest by mtime, together with its sidecar.
- **Threshold:** After six sequential fresh-compile runs with six distinct packs: count of <scanner_dir>/rule_cache/rules_*.yarac == 5 (RULE_CACHE_MAX_FILES default); the missing one is the entry with the oldest mtime before run 6; its rules_<key>.yarac.meta.json is gone too (zero orphan .meta.json files remain); total bytes of the survivors <= 268435456 (RULE_CACHE_MAX_BYTES default, 256 MB).
- **Setup:** Six SSH-launched runs on xdr-agent against the Round 1 target tree, each with a one-byte-different variant of the same clean pack (append N trailing spaces) so each is a fresh compile — pruning runs only inside a successful save, so a cache hit would skip it. Then a seventh run with YARA_RULE_CACHE_MAX=10 exported.
- **Evidence:** `ls -l --time-style=full-iso <scanner_dir>/rule_cache/` after runs 5, 6 and 7; 'Rule compile FRESH' in each run's logs/system_<run_id>.log confirming all six took the save path.
- **Negative control:** Run 7 with YARA_RULE_CACHE_MAX=10 must leave 6 entries standing rather than 5. The eviction must be the cap doing work, not an unconditional sweep that keeps only the newest.
- **Why this round:** Departs from the RULE prior. This is a bound on <scanner_dir>'s disk footprint — Round 1's explicit 'the rule cache on disk' scope — and what drives it is the number of distinct packs compiled on the host, not anything about the rules. The six packs are one-byte variants of Round 1's own clean pack and need none of Round 3's crafted material.

### `RULE-054` Orphaned cache temp sweep with a 1-hour age gate

*low*

- **Must be true:** A save-temp older than the age gate is removed by the next successful save; one younger than the gate is spared, so a concurrent in-flight save from another per-action process is never deleted out from under it.
- **Threshold:** Plant two files in <scanner_dir>/rule_cache/: `rules_aged.yarac.99999.deadbeef.tmp` with mtime set to now − 7200s, and `rules_fresh.yarac.99998.cafebabe.tmp` with mtime now. After a run that performs a fresh compile and a successful save: the aged file is gone and the fresh file is still present, unchanged. Gate is exactly 3600 seconds.
- **Setup:** Over SSH: create both temps, `touch -d '-2 hours'` the aged one, then run with a pack not yet in the cache so the save path (and only then the prune) executes.
- **Evidence:** `ls -l --time-style=full-iso <scanner_dir>/rule_cache/*.tmp` before and after the run; 'Rule compile FRESH' in logs/system_<run_id>.log confirming the save path ran.
- **Negative control:** The sub-1-hour temp must survive. That is the whole point of the gate — a blanket wipe would delete a sibling process's in-flight save between rules.save(tmp) and os.replace(). If both disappear, the age gate is not being applied.
- **Why this round:** Departs from the RULE prior. The predicate is purely file-age hygiene inside <scanner_dir> — Round 1's explicit 'temp files' scope — and the rule pack's content is irrelevant, only that some run performs a successful save.

### `RULE-056` rule_cache survives end-of-run host cleanup

*core*

- **Must be true:** End-of-run host cleanup removes this run's artefacts but never touches rule_cache, which is a cross-run performance cache rather than this run's data.
- **Threshold:** With CONFIG_HOST_CLEANUP="always", CONFIG_HOST_CLEANUP_KEEP="summary" and outcome == "completed": every rules_*.yarac and rules_*.yarac.meta.json present before the run is still present afterwards with an unchanged sha256; <scanner_dir>/alert, <scanner_dir>/evidence and <scanner_dir>/failed_rules all exist and contain 0 entries; <scanner_dir>/logs contains scan_summary_<run_id>.json for this run_id and NO other file carrying this run_id — all eight must be gone: alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_ and diagnostics_<run_id>.log.
- **Setup:** Edit CONFIG_HOST_CLEANUP to "always" in the delivered script (it is a bare module constant, reachable through no env var or option). Run twice so a populated rule_cache and a previous run's logs both exist before the measured run.
- **Evidence:** `ls -l <scanner_dir>/rule_cache/ <scanner_dir>/alert/ <scanner_dir>/evidence/ <scanner_dir>/failed_rules/ <scanner_dir>/logs/`; `sha256sum <scanner_dir>/rule_cache/*`; `outcome` in logs/scan_summary_<run_id>.json.
- **Negative control:** The PREVIOUS run's per-category logs (a different run_id) in the same logs_dir must survive untouched. Otherwise 'rule_cache survived' is indistinguishable from 'cleanup did nothing at all', and the removal side of the claim is unverified.
- **Why this round:** Departs from the RULE prior. What drives this is host cleanup's removal list and the KEEP tier, not rule compilation — ROUNDS.md puts 'host cleanup and its scheduled units' and 'the rule cache on disk' in Round 1, and the criterion's evidence is entirely the post-run state of <scanner_dir>.

## Scan Targeting, Traversal & Skipping

### `TRAV-025` Producer backpressure: files are blocked on, never dropped

*core*

- **Must be true:** Under sustained queue saturation the producer blocks and retries rather than dropping paths, so the walker's discovery count and the workers' processed count reconcile exactly — no file is discovered and then silently lost.
- **Threshold:** At least one 'Scan queue saturated (' line appears in performance_<run_id>.log (emitted on every 25th Full event, so line_count ~= queue_full_events/25). Exact reconciliation, difference == 0: sum of 'files_found' over every 'Target scan completed' entry == files_scanned + files_skipped − skip_breakdown['Skipped directory'] − skip_breakdown['Junction/symlink skip']. scan_errors_<run_id>.log contains 0 occurrences of 'Failed to enqueue file for scanning:'. Defaults for reference: queue_backoff_secs 0.25s (YARA_QUEUE_BACKOFF_SECS), queue depth max(2, max_workers*2) = 4 at the default of 2 workers (YARA_QUEUE_SIZE).
- **Setup:** Round 1's long clean scan on xdr-agent, run to completion (a cancelled run loses in-flight queue items and breaks the identity by design). To force saturation, export YARA_THREADS=1 and YARA_QUEUE_SIZE=2 for one leg and add competing CPU load (stress-ng --cpu 6) so the single worker stays behind the walker.
- **Evidence:** logs/performance_<run_id>.log 'Scan queue saturated (N items) - backing off producer'; logs/scan_errors_<run_id>.log 'Failed to enqueue file for scanning:' with data {'file_path': ...}; per-target 'files_found' from every logs/statistics_<run_id>.log 'Target scan completed:' entry; "files_scanned"/"files_skipped" in logs/scan_summary_<run_id>.json; the 'Skip reasons:' entry data 'skip_breakdown'.
- **Why this round:** Round 1, not the TRAV prior of Round 3: ROUNDS.md assigns scan-queue sizing and saturation to Round 1, and only a long clean scan with the workers deliberately outpaced ever fills the queue. A crafted Round-3 target finishes before backpressure engages, so the saturation line never appears and the reconciliation is vacuous.

### `TRAV-026` Per-directory heartbeat call during the walk (rate-limited to YARA_HEARTBEAT_SECS)

*supporting*

- **Must be true:** Running-status heartbeats land on a fixed cadence for the whole scan and are rate-limited to at most one per interval despite two independent callers (the per-directory walker call and the dedicated HeartbeatWorker thread), and the on-disk liveness marker advances with them.
- **Threshold:** SCANS_HEARTBEAT_SECS default 600 (YARA_HEARTBEAT_SECS, line 389); HeartbeatWorker polls every 30s (HEARTBEAT_THREAD_POLL_SECS, line 400). On a Round-1 scan of wall duration D > 1800s, over the yara_scanner_scans_v3_* rows for this run_id with status == 'running' and message == 'heartbeat', sorted ascending: every consecutive pair differs in event_timestamp_ms by >= 600000 and <= 660000 — never two rows inside one interval, which is what the _heartbeat_lock check-and-set at lines 5449-5453 must guarantee, and never a skipped interval; and the row count lies in [floor(D/660), floor(D/600)] (the gate re-arms at the moment it is passed, so a walker parked between polls stretches each period to at most 630s and the count drifts below floor(D/600) on a long run — this range is the drift-proof form). <scanner_dir>/control/running.json exists from the moment the walk starts (first written by _start_cancellation_watcher at line 5340, before any heartbeat) through the whole scan, its mtime advances at most once per 600s thereafter, and it is absent after the run (_remove_running_marker, line 7208).
- **Setup:** None beyond Round 1's long clean scan — it must exceed 1800s so at least two intervals elapse.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "running" and message = "heartbeat" | fields event_timestamp_ms | sort asc event_timestamp_ms`; mtime of <scanner_dir>/control/running.json sampled over the run (written atomically via temp + os.replace, so a reader never sees a half-written file); its absence after the run (_remove_running_marker).
- **Why this round:** Round 1, not the TRAV prior of Round 3: ROUNDS.md assigns progress heartbeats to Round 1, and the 600s gate is only falsifiable on a run that spans several intervals. Round 3's crafted legs are deliberately short and would emit zero heartbeat rows, making the cadence claim vacuous.

### `TRAV-034` Windows drive-letter exclusion list (present but permanently empty)  <sub>windows</sub>

*low*

- **Must be true:** No drive is excluded by the drive-letter list: on a Windows default-scope run, every discovered drive root is walked and produces files, and none is recorded as an excluded target or bulk-counted as a skipped directory. The list is initialised to [] and nothing else in the file writes to it — no env var, no options key (absent from _VALID_OPTION_KEYS) — so a non-empty result here means the constant was edited and a whole volume silently lost coverage.
- **Threshold:** Windows leg of Round 1 with scan_folder='default': for EVERY entry T in the 'Scan configuration established' data 'targets' list, (a) T does not appear in scan_summary_<run_id>.json "excluded_targets", and (b) there is a 'Target scan completed: T' statistics entry with files_found > 0. Those two together fully decide the claim — a populated win_skip_drive makes _is_special_file(T) true at line 6522, which appends T to excluded_targets and forces every walk root under it to the bulk-skip branch, so files_found for T would be exactly 0. Drop the unmeasurable 'far below' clause. Note for any future non-empty list: the comparison is `os.path.splitdrive(os.path.normpath(path.lower()))[0].rstrip(":")`, so only a LOWER-CASE, colon-less entry ('c', not 'C:') can ever match.
- **Setup:** None beyond Round 1's clean full-scope Windows scan on xdragent2 — the assertion needs every drive root to actually be walked, which a short cancelled leg cannot provide.
- **Evidence:** "excluded_targets" in logs\scan_summary_<run_id>.json; logs\statistics_<run_id>.log 'Scan configuration established' data 'targets' and one 'Target scan completed: <root>' entry per target with data 'files_found'; the 'Skip reasons:' entry data 'skip_breakdown' key 'Skipped directory'.
- **Negative control:** The control must come from the SAME run, not from other legs: on this Windows Round-1 run, skip_breakdown must carry a non-zero 'Special system file' count AND at least one walk-root exclusion must be recorded (skip_breakdown['Skipped directory'] > 0, which the scanner's own directory under win_skip_folder guarantees on any full C:\ walk). That proves this run is capable of recording an exclusion at all, so 'no drive was excluded' is distinguishable from 'exclusions are never recorded'.
- **Why this round:** Round 1 rather than the TRAV prior of Round 3: this is decidable only as a NEGATIVE assertion across every drive root, and only Round 1's default-scope clean scan walks all of them. It is a marked entry, but the marker is wrong here — 'the list is empty, so nothing is excluded' is the documented behaviour and it is falsifiable by exactly the artefacts above.

### `TRAV-049` DORMANT: real-path de-duplication across junctions (track_real_paths is hard-wired off)

*low*

- **Must be true:** Real-path de-duplication is off on every run and cannot be switched on from the wire: unique_paths_scanned is 0 in the final metrics, unique_real_paths is 0 in EVERY progress entry, and "Junction/symlink duplicate" never appears in skip_breakdown — on a scan that scanned hundreds of thousands of files.
- **Threshold:** final-metrics 'unique_paths_scanned' == 0 and 'path_deduplication_ratio' derived only from junction_skips; 'unique_real_paths' == 0 in all N progress entries with N >= 5; occurrences of "Junction/symlink duplicate" across all logs == 0; files_scanned > 100000
- **Setup:** Round 1's whole-filesystem clean scan, long enough to emit at least five "Scan Progress" entries. Additionally confirm no option turns it on: passing options with track_real_paths must be rejected with "Unknown option 'track_real_paths'. Valid keys: ..." — it is absent from _VALID_OPTION_KEYS.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log: every "Scan Progress | Files: ..." entry's data.metrics.unique_real_paths, and the "SCAN COMPLETED | Time: ..." entry's data.unique_paths_scanned; the "Skip reasons: ..." entry's data.skip_breakdown; source: `self.track_real_paths = False` in ScanConfig (bare literal, no env var) gating both scan_file dedup blocks
- **Negative control:** files_scanned must be large and non-zero in the same run — a scan that scanned nothing would satisfy "unique_paths_scanned == 0" vacuously.
- **Why this round:** Departs from the traversal prior (Round 3). The claim is quantified over EVERY progress entry, which needs a run long enough to emit many of them and a large scanned population to make the zero meaningful; Round 1 is defined as the long clean scan spanning many heartbeats, and Round 3's crafted tree may emit only one progress entry.

### `TRAV-051` Read-permission gate with per-file permission diagnostics (unbounded, unthrottled)

*supporting*

- **Must be true:** Every read-denied file produces exactly one unthrottled, uncapped "Permission denied: <path>" line in the system log — the line count equals the skip count exactly, with no dedup, no sampling and no rate limit, so the log's growth is linear in the number of denials.
- **Threshold:** `grep -c 'Permission denied:' <scanner_dir>/logs/system_<run_id>.log` == skip_breakdown["No read permission"] == file_processing.skip_breakdown["No read permission"] in the COMPREHENSIVE SCAN REPORT, exactly (delta 0); the count must be >= 1 for the criterion to be exercised
- **Setup:** Round 1 full-scope scan on OfficeiMac, where TCC gates access() on protected user trees for a process without Full Disk Access and drives the denial count into the thousands. Record the resulting system_<run_id>.log byte size alongside the count. If the count comes back 0 on all three endpoints, record the capability as UNEXERCISED — do not pass it on a vacuous 0 == 0.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log lines "Permission denied: <path>" with the JSON diagnostic blob appended by LogManager._log (fields file_path, file_mode, owner_uid, scanner_uid, requires_root); <scanner_dir>/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown["No read permission"]; the "COMPREHENSIVE SCAN REPORT | Efficiency Score: NN.N/100" entry's file_processing.skip_breakdown
- **Negative control:** Readable files in the same trees must still be scanned (files_scanned > 0) and must NOT appear on any "Permission denied:" line. The scanner's own permission_denials list is genuinely unobservable (its only references are the append and the hasattr guard), so the log-line count is the proxy — do not claim to have measured the list.
- **Why this round:** Departs from the traversal prior (Round 3). The catalogued risk is host FOOTPRINT — an uncapped, unthrottled per-file write on a plain non-rotating FileHandler — which only a full-scope scan with thousands of denials can size. A Round 3 crafted tree with one planted unreadable file cannot distinguish "unthrottled" from "throttled".

### `TRAV-057` files_skipped on the wire: every scan-lifecycle row carries the skip count

*core*

- **Must be true:** Every lifecycle row of the run carries a files_skipped value that is a consistent snapshot of the local counter, non-decreasing across the status progression, and exactly equal on the terminal row to scan_summary_<run_id>.json's files_skipped.
- **Threshold:** XQL returns >= 3 rows for the run (one 'initiated', >= 1 'running', exactly 1 terminal); files_skipped == 0 on 'initiated', strictly > 0 and monotonically non-decreasing across 'running', and on the terminal row equal to scan_summary files_skipped with delta 0; terminal status == "completed"
- **Setup:** Round 1's whole-filesystem clean scan, which must run longer than SCANS_HEARTBEAT_SECS (600 s) so at least one 'running' row is emitted, and which skips large trees (/proc, /sys, C:\$Recycle.Bin, scanner_dir) so the column is non-zero. write_dataset must be left at its default True.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, files_scanned, files_skipped, elapsed_secs, event_timestamp_ms | sort asc event_timestamp_ms`; the resolved dataset name is echoed in scan_summary_<run_id>.json field "scans_dataset"; source: _emit_scan_row snapshots files_skipped under lock_counts, scans_schema declares files_skipped as "number", call sites are 'initiated', 'running' (heartbeat) and the terminal row in _perform_enhanced_cleanup
- **Negative control:** files_scanned on the same rows must also be non-zero and non-decreasing — a build that wrote the skip count into both columns, or zeroed one, must not read as a pass.
- **Why this round:** Departs from both the traversal prior (Round 3) and ROUNDS.md's dataset-channel-in-Round-2 default. What drives this column is a LARGE skip population plus a run long enough to emit 'running' heartbeats at the 600 s cadence. Round 2's bounded flood tree is engineered so nearly every file MATCHES, which means almost nothing is skipped and the column would be 0 on every row — the criterion could not fail. Round 1's whole-filesystem clean scan supplies both conditions.

### `TRAV-064` Scan status transitions are effectively unobservable (and their uploader is never called)

*low*

- **Must be true:** A clean run records the five-state progression in the diagnostics log in order and transmits none of it: no scan-status HTTP call is ever attempted, so the only tenant-side lifecycle signal is the yara_scanner_scans_v3_<shard> rows.
- **Threshold:** diagnostics_<run_id>.log contains "Scan status changed to: <s>" exactly once for each of initializing, starting_workers, scanning, finishing, completed, in that order, and no abort state (interrupted/error/failed) on a clean run; occurrences of "Scan status uploaded successfully", "Scan status upload failed: HTTP" and "Scan status upload error" across all logs == 0
- **Setup:** Round 1's clean uncancelled full-scope run. The abort-state variants belong to Round 3's cancel and are not asserted here.
- **Evidence:** <scanner_dir>/logs/diagnostics_<run_id>.log lines "Scan status changed to: <status>" (ScanStatusUploader.set_status, logging.info into the root FileHandler installed by setup_logging); the absence of the three upload_scan_status result lines, which are its only possible output; tenant side: XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status` returns initiated/running/completed and nothing resembling the five internal states
- **Negative control:** The diagnostics log must be non-empty and contain other logging.info records from the same run (e.g. "Using configured scan targets: ...", "Comprehensive final report generated - Efficiency Score: ..."), so a missing or unwritable handler cannot masquerade as "no upload lines".
- **Why this round:** Departs from the traversal prior (Round 3). The canonical five-state sequence with no abort states, plus the negative assertion that nothing was ever transmitted, requires an uncancelled run; Round 3's run is cancelled mid-walk by design and would end in cancelled/interrupted. Round 1's long clean scan is the one that produces the full clean progression, and ROUNDS.md already places the seven endpoint log files there.

## Performance & Resource Management

### `PERF-001` CPU governor policy selector (headroom / budget / none)

*core*

- **Must be true:** The policy that actually runs is the one configured, and it reads the same on all four artefacts at once; 'none' truly disables the governor rather than relabelling it; an unrecognised value aborts the run instead of silently falling back.
- **Threshold:** Run A (default): scan_summary.throttle_mode == 'headroom' AND scan_summary.cpu_governor.policy == 'headroom' AND the SCAN_RESULT line contains 'cpu=headroom' AND every yara_scanner_scans_v3_* row for this run_id has throttle_mode == 'headroom' AND the CPU_GOVERNOR line count is > 0. Run B (cpu_guarantee=none): all four read 'none', CPU_GOVERNOR line count == 0, cpu_governor.samples_taken == 0, total_paused_secs == 0.0. Run C (cpu_guarantee=bogus): stdout carries "Invalid cpu_guarantee 'bogus'. Use headroom, budget, or none." and the SCAN_RESULT line begins 'Scan failed:'; no scan_summary_<run_id>.json is written for that run.
- **Setup:** Three runs on the same target tree: A default; B with options `cpu_guarantee=none`; C with options `cpu_guarantee=bogus`. ScanConfig raises before LogManager exists in run C, so its only evidence is stdout.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json fields `throttle_mode` and `cpu_governor.policy` (written by LogManager.write_scan_summary); grep -c 'CPU_GOVERNOR {' <scanner_dir>/logs/performance_<run_id>.log; the Action Center SCAN_RESULT line built in run() (`... | cpu-slept Ns | {config.posture}`); XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, throttle_mode`.

### `PERF-002` Headroom policy — always leave N% of the host free

*core*

- **Must be true:** Under headroom the emitted target equals 100 - cpu_headroom_pct - others on every sample above the floor, so rising external load shrinks the scanner's target instead of stopping it.
- **Threshold:** cpu_headroom_pct == 30.0 in the THROTTLE_CONFIG line. For every CPU_GOVERNOR line with target > cpu_floor_pct (5.0): abs(target - (100.0 - 30.0 - others)) <= 0.2 (both fields are rounded to 1 dp by CpuGovernor.stats). Adaptivity: use a MODERATE load that keeps the computed target above the floor — `stress-ng --cpu 2` on the 8-core host (others ≈ 25, target ≈ 45), started ~90s in and stopped 300s later. Across that idle→loaded→idle transition, restricted to lines where target > 5.0, `others` must move by more than 15 points and abs(delta_target + delta_others) <= 0.5 (equal magnitude, opposite sign). If the heavy-load run is reused instead, the transition clause must be evaluated only on the sample sub-series where 100-30-others > 5.0; on the floored samples target is pinned at 5.0 by design and must NOT be required to track others.
- **Setup:** Round 1's long clean scan; start `stress-ng --cpu 6 --timeout 300s` about 90s in and stop it 300s later so the sample series contains an idle-load-idle transition.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — the `THROTTLE_CONFIG {...}` line's cpu_headroom_pct, and the `target`/`own`/`others` fields of every `CPU_GOVERNOR {...}` JSON line (CpuGovernor.compute_target / CpuGovernor.update, where others = max(0, system - own)).

### `PERF-003` Budget policy — fixed cap on the scanner's share

*core*

- **Must be true:** Under budget the target is a constant equal to cpu_budget_pct for the whole run and never reacts to `others`, and the floor never engages.
- **Threshold:** Every CPU_GOVERNOR line has policy == 'budget' and target == 25.0 exactly, with zero variance across the run, while `others` varies by more than 20 points across the same series (proving the constancy is not merely an idle host). scan_summary.cpu_governor.floor_hits == 0 and scan_summary.cpu_governor.policy == 'budget'.
- **Setup:** Dedicated Round 1 run with options `cpu_guarantee=budget`, same target tree and the same stress-ng load transition as the headroom run.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `CPU_GOVERNOR {...}` lines (fields policy, target, others); <scanner_dir>/logs/scan_summary_<run_id>.json fields cpu_governor.policy and cpu_governor.floor_hits.

### `PERF-004` CPU floor — the anti-stall guarantee (headroom policy only)

*supporting*

- **Must be true:** When external load would drive the headroom target below cpu_floor_pct the target is clamped to exactly cpu_floor_pct and floor_hits increments, and the scan keeps making forward progress while floored.
- **Threshold:** cpu_floor_pct == 5.0 in THROTTLE_CONFIG. During the heavy-load window: at least one CPU_GOVERNOR line with target == 5.0 and floor_hits strictly increasing between consecutive such lines; scan_summary.cpu_governor.floor_hits > 0; files_scanned in the Scan Progress lines spanning that same window increases by more than 0 (no stall).
- **Setup:** Headroom run with `stress-ng --cpu <all cores> --timeout 240s` held long enough that 100 - 30 - others < 5, i.e. sustained others > 65%.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `CPU_GOVERNOR {...}` fields target and floor_hits; <scanner_dir>/logs/scan_summary_<run_id>.json cpu_governor.floor_hits; <scanner_dir>/logs/statistics_<run_id>.log `Scan Progress | Files: N scanned` lines bracketing the load window.
- **Negative control:** On the idle prelude of the same run (others < 65), target must be 100 - 30 - others (~70 on an idle host), never 5.0, and floor_hits must not increment — the clamp must not fire when it is not needed.

### `PERF-005` Process-CPU normalisation to a whole-machine share

*supporting*

- **Must be true:** `own` is a whole-machine percentage (raw psutil process reading divided by host core count), so a multi-worker scanner is held to the configured share of the machine and not to 1/N of it.
- **Threshold:** DECIDER (the only clause that separates a normalised from an un-normalised build): on a budget run with options `cpu_guarantee=budget,cpu_budget_pct=25,workers=8` on the 8-core Linux endpoint, the scanner's WHOLE-MACHINE CPU share measured externally for the whole scan (pidstat -p <pid> 5, %CPU divided by host_cores; or Get-Counter '\Process(python*)\% Processor Time' / host_cores) must agree with the median steady-state `own` on the CPU_GOVERNOR lines to within 5 percentage points. An un-normalised build fails this by ~22 points (logged own ~25 while the process actually uses ~25/8 ≈ 3% of the machine). SUPPORTING: steady-state `own` >= 15.0 and <= 35.0 on the budget run; THROTTLE_CONFIG host_cores equals the endpoint's real core count and is the denominator (own == round(raw_psutil_pct / host_cores, 1)). Range arm: on a HEADROOM run on an otherwise idle 8-core host with workers=8 (target ≈ 70), max(own) across all CPU_GOVERNOR lines must be <= 100.0 — drop the 'saturating' framing, since with the governor enabled the scanner is held at the target and with cpu_guarantee=none no CPU_GOVERNOR line is emitted at all.
- **Setup:** Budget run with options `cpu_guarantee=budget,workers=8` on the 8-core Linux endpoint, with an external per-process CPU sampler running over SSH for the whole scan.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `CPU_GOVERNOR {...}` field `own` and `THROTTLE_CONFIG {...}` field `host_cores`; the external pidstat/Get-Counter capture taken over `gcloud compute ssh xdr-agent` for the whole scan, aligned to the governor `t` timestamps. Code: CpuGovernor.normalise_own (raw_pct / self.cpu_count), called from CpuGovernor.update; the CpuGovernor(...) construction in YaraScanner.__init__ omits cpu_count, so the denominator is os.cpu_count().

### `PERF-006` Sleep-ratio controller (proportional gain and runaway clamp)

*supporting*

- **Must be true:** The sleep ratio is bounded on both ends and moves in the direction of the CPU error — it never goes negative on an under-target scanner and never exceeds RATIO_MAX on a sustained over-target one.
- **Threshold:** Bounds: 0.0 <= ratio <= 20.0 on every CPU_GOVERNOR line and in scan_summary.cpu_governor.ratio, on every run (RATIO_MAX = 20.0, and max(0.0, ...) is the lower clamp). Direction, stated over WINDOWS rather than consecutive emissions: max(ratio) over the loaded window minus max(ratio) over the idle prelude must be >= 0.25 (the emission threshold), and at least one loaded-window line must have own > target with ratio > 0.0. Decay: over the idle tail (the last 120s of a run where every emitted line has own < target), ratio must be strictly lower than the loaded-window maximum and the final line's ratio, plus scan_summary.cpu_governor.ratio, must be exactly 0.0 — never negative. Do NOT require monotonicity between consecutive emitted lines: emission is sampled (change >= 0.25 OR 30s heartbeat), so unobserved intervening samples can move the ratio either way.
- **Setup:** Same headroom run as PERF-002, with the stress window ending well before the scan does so the idle tail is long enough for the ratio to decay.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `CPU_GOVERNOR {...}` field `ratio` as a time series ordered by field `t`; <scanner_dir>/logs/scan_summary_<run_id>.json cpu_governor.ratio. Code: CpuGovernor.update — `max(0.0, min(self.RATIO_MAX, self.sleep_ratio + self.GAIN * error))` with GAIN = 0.05 and RATIO_MAX = 20.0.

### `PERF-007` Per-file proportional pacing (the actuator)

*core*

- **Must be true:** The governor actually sleeps — total_paused_secs is non-zero once the ratio is non-zero — and no single pace() sleep can exceed PACE_CAP_SECS, so paused time can never exceed one second per file scanned.
- **Threshold:** On the loaded headroom run: scan_summary.total_paused_secs > 0.0. On every run: scan_summary.total_paused_secs <= scan_summary.files_scanned * 1.0 (PACE_CAP_SECS). The three reports of the same number agree: scan_summary.total_paused_secs == scan_summary.cpu_governor.slept_secs exactly, == total_paused_secs on the terminal yara_scanner_scans_v3_* row exactly, and == the integer in 'cpu-slept Ns' on the SCAN_RESULT line when rounded to 0 dp.
- **Setup:** Headroom run with the stress-ng window (PERF-002). To exercise the cap, include at least 20 files of 30-60 MB in the tree so per-file work time is long enough that work_secs * ratio would exceed 1.0s.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json fields `total_paused_secs`, `cpu_governor.slept_secs`, `files_scanned`; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status != "running" | fields total_paused_secs`; the SCAN_RESULT line's 'cpu-slept Ns' fragment. Code: CpuGovernor.pace, sole call site in YaraScanner.scan_file immediately after rules.match.
- **Negative control:** On the `cpu_guarantee=none` run, total_paused_secs must be exactly 0.0 on all three artefacts — the cap must not be achieved by the actuator never running when it should.

### `PERF-008` Governor sampling rate limit

*supporting*

- **Must be true:** Consecutive governor samples are never closer together than config.throttle_check_interval_secs, and that interval is the knob that controls it.
- **Threshold:** Default run: THROTTLE_CONFIG check_interval == 1.0; every CPU_GOVERNOR line's `secs_since_last_sample` >= 0.99 (the gate is `now - self.last_governor_sample < self.config.throttle_check_interval_secs`, so no two consumed samples are closer than the configured interval); the first emitted line carries secs_since_last_sample == null (last_sample_gap is None on the first update). Contrast run with YARA_GOVERNOR_INTERVAL_SECS=0: THROTTLE_CONFIG check_interval == 0.0; median secs_since_last_sample < 0.05; scan_summary.cpu_governor.samples_taken >= 0.9 * files_scanned (with the gate open, scan_file samples once per file that reaches rules.match) versus samples_taken <= 1.2 * duration_secs on the default run — the ratio between the two runs' samples_taken is the discriminator. DROP the scan_rate_fps clause: the added cost is one extra psutil pair per file and is not separable from run-to-run variance; if a directional check is wanted, record scan_rate_fps for both runs as an observation, not a pass bar.
- **Setup:** Two runs on the same tree, the second with YARA_GOVERNOR_INTERVAL_SECS=0 exported. This knob is read with a bare float() (not _env_number), so a non-numeric value crashes the run at ScanConfig — do not set one accidentally.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `THROTTLE_CONFIG {...}` field check_interval and every `CPU_GOVERNOR {...}` field secs_since_last_sample; <scanner_dir>/logs/scan_summary_<run_id>.json fields cpu_governor.samples_taken, files_scanned, scan_rate_fps. Code: YaraScanner._sample_governor interval gate; call sites in scan_file and _enqueue_scan_path.

### `PERF-009` Governor fail-open on unreadable CPU

*supporting*

- **Must be true:** A healthy run never trips the fail-open path: the disable line is absent and the sampler demonstrably ran to the end of the scan rather than having silently switched itself off mid-run.
- **Threshold:** grep -c 'CPU governor disabled - could not read CPU (' performance_<run_id>.log == 0. Liveness, bounded by the actual call sites rather than the clock: scan_summary.cpu_governor.samples_taken > 0 while cpu_governor.policy is 'headroom' or 'budget' (samples_taken == 0 with an enabled policy is the silent-constructor signature, _governor_proc = None); and samples_taken >= 0.8 * min(files_scanned, (duration_secs / check_interval)). Continuity to the end of the WORKING phase, not the end of the run: the last CPU_GOVERNOR line's `t` must be within 60s of the last 'Scan Progress' line whose files_scanned advanced (sampling has no call site during cleanup, the worker joins or the uploader drain). scan_summary.cpu_governor.secs_since_last_sample non-null and <= 60.
- **Setup:** Standard Round 1 run — no injection. The positive (fault-injected) case is not reachable: psutil.Process.cpu_percent cannot be made to raise on a live endpoint without editing the scanner.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — absence of the exact fragment 'CPU governor disabled - could not read CPU (' emitted by YaraScanner._sample_governor's except branch; <scanner_dir>/logs/scan_summary_<run_id>.json fields cpu_governor.samples_taken, cpu_governor.secs_since_last_sample, duration_secs.
- **Why this round:** Kept in Round 1 as a negative assertion rather than not_covered: a build that disables the governor prematurely (over-broad try, or the constructor's silent _governor_proc = None path) produces exactly the artefacts named — a disable line, or samples_taken far below duration/interval with total_paused_secs frozen. The constructor variant writes no line anywhere and is only distinguishable via samples_taken == 0 while policy is headroom/budget.

### `PERF-010` Governor telemetry: change-triggered plus heartbeat emission

*supporting*

- **Must be true:** Emission is decoupled from sampling: far fewer lines are written than samples taken, yet no gap in the series exceeds the heartbeat, and every line carries the full stats field set.
- **Threshold:** On a scan of duration >= 600s with default settings: scan_summary.cpu_governor.samples_taken >= 400 AND the CPU_GOVERNOR line count <= samples_taken / 4 AND line count >= floor(duration_secs / GOVERNOR_HEARTBEAT_SECS) - 2 — decoupling is proved by 'far fewer lines than samples' plus 'at least the heartbeat floor', not by a 10x bound that the change-triggered path legitimately breaches during a load ramp (GAIN 0.05 x a large error moves the ratio ~1.0 per sample, so every sample of the ramp clears the 0.25 gate). Every consecutive pair of `t` values differs by <= 35.0s except across any stretch where Scan Progress files_scanned does not advance (sampling has no call site when no file completes and the producer is not blocked). Every line parses as JSON with exactly the keys policy, target, own, others, ratio, slept_secs, floor_hits, samples_taken, secs_since_last_sample, t. At least one change-triggered line: two consecutive lines less than GOVERNOR_HEARTBEAT_SECS apart whose `ratio` differs by >= 0.25.
- **Setup:** Round 1 long clean scan with the stress window, so both the heartbeat path and the 0.25-ratio-delta path fire.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `CPU_GOVERNOR {...}` lines (parse each as JSON); <scanner_dir>/logs/scan_summary_<run_id>.json cpu_governor.samples_taken. Code: YaraScanner._sample_governor emission block (`changed or heartbeat`), CpuGovernor.stats field list, GOVERNOR_HEARTBEAT_SECS = _env_number('YARA_GOVERNOR_HEARTBEAT_SECS', 30).
- **Negative control:** With YARA_GOVERNOR_HEARTBEAT_SECS=5 the line count must rise by roughly 6x on the same tree — the suppression must be the heartbeat interval, not a broken emitter.

### `PERF-011` psutil CPU sampler priming

*supporting*

- **Must be true:** Both psutil samplers are primed in the constructor, so the very first governor sample and the very first progress sample carry real CPU figures instead of psutil's initial 0.0.
- **Threshold:** The FIRST `CPU_GOVERNOR` line of the run has own > 0.0 and others >= 0.0 (own == 0.0 on the first line is the un-primed signature). The FIRST `System Resources | CPU:` line's data.cpu_percent > 0.0, and at most one such line in the whole run has cpu_percent == exactly 0.0.
- **Setup:** Round 1 run on a host that is not idle at scan start — the stress-ng window should already be running when the scan begins, or start the scan while the rule compile phase is still burning CPU.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — first `CPU_GOVERNOR {...}` line's `own` field, and first `System Resources | CPU: X.X% | Memory: ...` line's data blob key `cpu_percent`. Code: YaraScanner.__init__ primes self._governor_proc.cpu_percent(interval=None) and psutil.cpu_percent(interval=None); YaraScanner._log_progress reuses the same primed handle.

### `PERF-012` THROTTLE_CONFIG startup header in the performance log

*supporting*

- **Must be true:** Exactly one self-describing THROTTLE_CONFIG header is written per run, carrying the complete governor configuration, so the run's throttle behaviour is interpretable from the performance log alone.
- **Threshold:** grep -c '^.*THROTTLE_CONFIG {' performance_<run_id>.log == 1. The JSON parses and contains all eleven keys: priority_tier, check_interval, cpu_guarantee, cpu_headroom_pct, cpu_budget_pct, cpu_floor_pct, platform, host_cores, cpu_affinity_count, cpu_priority, io_priority. On a default run: priority_tier == 'standard', check_interval == 1.0, cpu_guarantee == 'headroom', cpu_headroom_pct == 30.0, cpu_budget_pct == 25.0, cpu_floor_pct == 5.0, host_cores == the endpoint's real core count. Every value must match the corresponding scan_summary/SCAN_RESULT value for the same run.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — the line beginning 'THROTTLE_CONFIG {'; cross-checked against <scanner_dir>/logs/scan_summary_<run_id>.json throttle_mode and the SCAN_RESULT posture fragment. Code: _apply_light_process_priority's log_manager.log_performance('THROTTLE_CONFIG ' + json.dumps({...})).

### `PERF-013` Below-normal process priority and I/O priority demotion

*core*

- **Must be true:** The scanner process actually runs demoted on the host — the recorded priority matches what the OS reports for the live PID, not merely what the scanner claims.
- **Threshold:** Linux endpoint: system log data.cpu_priority matches 'nice=N' with N >= 10, data.io_priority == 'best_effort:7', and `ps -o ni= -p <pid>` during the scan returns the same N while `ionice -p <pid>` reports 'best-effort: prio 7'. Windows endpoint: data.cpu_priority == 'below_normal', no io_priority key in the system-log data blob (THROTTLE_CONFIG carries io_priority: null), and Get-Process -Id <pid> reports PriorityClass BelowNormal. No cpu_priority_error / io_priority_error key present in the data blob.
- **Setup:** Round 1 run on the Linux endpoint plus one on the Windows endpoint. Capture the live PID from <scanner_dir>/control/running.json and sample the OS view while the scan is in its active phase.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log — the 'Applied process priority tuning' entry's data keys cpu_priority / io_priority; <scanner_dir>/logs/performance_<run_id>.log THROTTLE_CONFIG keys cpu_priority / io_priority; <scanner_dir>/control/running.json field `pid`; the ps/ionice or Get-Process capture. Code: _apply_light_process_priority, sole call site in run() passing throttle_mode='standard'.

### `PERF-014` DEAD CODE: idle-tier ("os") priority branch

*low*

- **Must be true:** The retired idle tier is unreachable on every delivery path: no run can produce idle-class priority, and the retired option that used to select it is translated away rather than honoured.
- **Threshold:** Across every round-1 run, including one delivered with options `throttle_mode=os`: THROTTLE_CONFIG priority_tier == 'standard' on every run; grep for '"cpu_priority": "idle"' in system_<run_id>.log returns 0 matches; the keys background_mode and background_mode_error never appear in any 'Applied process priority tuning' data blob; and on the throttle_mode=os run scan_summary.throttle_mode == 'headroom' (migrate_throttle_option maps 'os' -> 'headroom' and drops the retired key) rather than the action failing with an unknown-key ValueError.
- **Setup:** One extra run delivered with options `throttle_mode=os` to confirm the retired key is translated, not honoured and not rejected.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log THROTTLE_CONFIG field priority_tier; <scanner_dir>/logs/system_<run_id>.log 'Applied process priority tuning' data blob; <scanner_dir>/logs/scan_summary_<run_id>.json throttle_mode. Code: _apply_light_process_priority os_mode flag and its three branches; _THROTTLE_MODE_MAP / migrate_throttle_option; the only call site passes the literal 'standard'.
- **Negative control:** The 'standard' tier must still demote: on the same runs data.cpu_priority matches 'nice=N' with N >= 10 on Linux (the branch is max(int(current_nice), 10), so a payload already niced above 10 correctly records the higher value — requiring exactly 'nice=10' would fail a correct build), or == 'below_normal' on Windows. 'Never idle' must not be satisfied by the whole priority function silently no-opping — a cpu_priority_error key in the 'Applied process priority tuning' data blob, or a 'Could not apply process priority tuning' system-log entry, fails this criterion.
- **Why this round:** Marked as an observability gap, but decidable by the negative: the absence of the idle artefacts plus the presence of the standard ones is exactly what a build that re-enabled the branch would break. Only the affirmative execution of the branch is unreachable, and that is what makes the negative assertion meaningful.

### `PERF-015` CPU affinity capture (Cortex agent core pinning)

*supporting*

- **Must be true:** The scanner records the core set it is actually allowed to run on, and that record reflects the Cortex agent's real pinning on the delivery path rather than the host's full core count.
- **Threshold:** Windows endpoint, delivered through Action Center: data.cpu_affinity is a list, data.cpu_affinity_count == len(that list), and cpu_affinity_count < host_cores (measured on this tenant: 2 of 8). The same cpu_affinity_count appears in THROTTLE_CONFIG. No cpu_affinity_error key present.
- **Setup:** Deliver the scan to the Windows endpoint via the Action Center API, NOT over SSH — an SSH-launched process is not pinned by the agent and would show cpu_affinity_count == host_cores, which does not test this.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log 'Applied process priority tuning' data keys cpu_affinity / cpu_affinity_count / cpu_affinity_error; <scanner_dir>/logs/performance_<run_id>.log THROTTLE_CONFIG field cpu_affinity_count. Code: _apply_light_process_priority's process.cpu_affinity() block.
- **Negative control:** On the Linux endpoint (no agent pinning) cpu_affinity_count must equal host_cores and cpu_affinity must be the full core list — the capture must report the real restriction, not a constant.

### `PERF-016` host_cores recorded outside the affinity try-block

*supporting*

- **Must be true:** host_cores is present and a positive integer on every platform, including one where the affinity call fails — the governor's own-share denominator is never lost.
- **Threshold:** On every endpoint platform reached: system-log data.host_cores is an int >= 1, equals THROTTLE_CONFIG host_cores, and neither is null; both equal the endpoint's real core count. This must hold on runs where the affinity capture SUCCEEDED (Linux/Windows: data.cpu_affinity is a list) — proving host_cores is recorded on its own line before the try. DARWIN ARM (the branch the criterion exists for): on a macOS endpoint, data.cpu_affinity == 'unrestricted', data.cpu_affinity_count == data.host_cores, and data.host_cores is still the real core count. If the fleet has no macOS endpoint, record the darwin arm as UNREACHED — do not mark the criterion passed from the Linux/Windows pair alone. DROP the clause 'own == round(raw process pct / host_cores, 1) within 0.1': the raw psutil process reading is never written to any artefact, so it is not decidable here; that comparison lives in PERF-005 via the external sampler.
- **Setup:** Round 1 runs on Linux, Windows and macOS endpoints. If no macOS endpoint is available, the AttributeError path is instead reachable on any platform only by inspection, and the criterion is decided on the Linux/Windows pair alone plus the equality with THROTTLE_CONFIG.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log 'Applied process priority tuning' data.host_cores and data.cpu_affinity; <scanner_dir>/logs/performance_<run_id>.log THROTTLE_CONFIG host_cores. Do NOT use system_info.cpu_count inside the COMPREHENSIVE SCAN REPORT blob in statistics_<run_id>.log — LogManager._log truncates any data blob at 4000 chars with '...(truncated)', so a large skip_breakdown cuts that field off.
- **Negative control:** On the macOS run, host_cores must be populated even though cpu_affinity fell back to 'unrestricted' — the affinity failure must not take the denominator with it. Positive control on the same fleet: on Linux/Windows, where cpu_affinity() succeeds, host_cores must be the same value it takes on macOS-style fallback — i.e. host_cores must never be sourced from the affinity call. If no macOS endpoint exists this control is UNREACHED, not satisfied.

### `PERF-017` Worker thread count and the auto (cores // 2) mode

*core*

- **Must be true:** The configured worker count is the number of threads actually spawned, it is reported identically in all four places, and workers=0 selects the auto (cores // 2, floor 2) resolution rather than zero workers.
- **Threshold:** Default run: max_workers == 2 in the 'YaraScanner initialized with N workers' data blob AND in init_data.max_workers of both 'YARA Scanner initialization completed' and 'YARA Scanner initialized successfully'; count of distinct 'Worker ScanWorker-N started' entries == 2, names contiguous ScanWorker-1..ScanWorker-2; and data.workers_started == 2 in the 'Worker thread startup completed in' performance record. Run with options `workers=0` on the 8-core Linux endpoint: max_workers == 4 (max(2, 8 // 2)) and 4 worker-started entries. Run with YARA_THREADS=6: max_workers == 6 and 6 worker-started entries. system_info.worker_threads_used in the COMPREHENSIVE SCAN REPORT is a BEST-EFFORT fifth source only: that blob is json.dumps(sort_keys=True) truncated at 4000 chars by LogManager._log, and system_info sorts last, so on a scan with a large skip_breakdown the field is legitimately absent — its absence must not fail this criterion, and its presence-with-a-wrong-value must.
- **Setup:** Three runs: default; options `workers=0`; YARA_THREADS=6 exported.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log entries 'YaraScanner initialized with N workers' (data.max_workers), 'Worker ScanWorker-N started' (one per thread, from the `name=f'ScanWorker-{i+1}'` spawn loop in scan_system), and 'YARA Scanner initialization completed' / 'YARA Scanner initialized successfully' (init_data.max_workers); <scanner_dir>/logs/performance_<run_id>.log 'Worker thread startup completed in X.XX seconds' (data.workers_started). Code: ScanConfig `_cfg_workers = self._opt_workers if self._opt_workers is not None else CONFIG_WORKERS` (CONFIG_WORKERS = 2), `configured_workers = _env_number('YARA_THREADS', _cfg_workers, cast=int, minimum=1)`, `max_workers = configured_workers if configured_workers > 0 else max(2, cpu_count // 2)`.
- **Negative control:** YARA_THREADS=0 must NOT select auto — _env_number's minimum=1 rejects it and falls back to CONFIG_WORKERS (2). Only the options key `workers=0` reaches the auto branch. A build where YARA_THREADS=0 yields 4 workers on the 8-core host fails this.

### `PERF-018` Worker pool startup and naming

*supporting*

- **Must be true:** Exactly one worker-startup record is written, its workers_started matches max_workers, and pool construction is effectively free rather than a measurable share of the scan.
- **Threshold:** grep -c 'Worker thread startup completed in' performance_<run_id>.log == 1; data.workers_started == config max_workers exactly; data.worker_startup_time_seconds < 1.0 for pools up to 8 threads. The record appears before the first 'Scan Progress' line in statistics_<run_id>.log by wall-clock timestamp.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — the 'Worker thread startup completed in X.XX seconds' entry with data keys worker_startup_time_seconds and workers_started; <scanner_dir>/logs/system_<run_id>.log 'Worker ScanWorker-N started' entries for the name check. Code: scan_system's `threading.Thread(target=self._worker, name=f'ScanWorker-{i+1}', daemon=True)` loop and the following log_performance call.

### `PERF-019` Bounded scan queue (the memory ceiling for file discovery)

*supporting*

- **Must be true:** The queue is genuinely bounded at the reported size — live queue depth never exceeds it — and the size derives from max_workers * 2 with a hard floor of 2 that an out-of-range value cannot defeat.
- **Threshold:** Default run (2 workers): init_data.scan_queue_size == 4, and no 'Scan Progress' line reports Queue: > 4. Run with YARA_QUEUE_SIZE=1: scan_queue_size == 4 (the _env_number minimum=2 rejects 1 and returns the default max_workers*2, and max(2, ...) is the second guard) — never 1, never 0. Run with `workers=0` on the 8-core host: scan_queue_size == 8.
- **Setup:** Three runs: default; YARA_QUEUE_SIZE=1 exported; options `workers=0`. Plus the YARA_QUEUE_SIZE=8 control below.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log — the 'YARA Scanner initialization completed' entry's init_data.scan_queue_size; <scanner_dir>/logs/statistics_<run_id>.log 'Scan Progress | ... | Queue: N | ...' lines and their data.queue_size. Code: ScanConfig `self.scan_queue_size = max(2, _env_number('YARA_QUEUE_SIZE', self.max_workers * 2, cast=int, minimum=2))`; Queue(maxsize=config.scan_queue_size) in YaraScanner.__init__.
- **Negative control:** YARA_QUEUE_SIZE=8 (a valid in-range value) must be honoured as exactly 8 — the floor must reject only out-of-range values, not override every operator setting.

### `PERF-020` Producer backpressure — block, never drop

*core*

- **Must be true:** Under sustained queue saturation the producer blocks and retries instead of dropping paths, so discovered files and processed files reconcile exactly.
- **Threshold:** At least one 'Scan queue saturated' line appears. Exact reconciliation on a run with outcome == 'completed': sum(files_found across all 'Target scan completed' records) == files_scanned + files_skipped - skip_breakdown['Skipped directory'] - skip_breakdown['Junction/symlink skip'], with difference exactly 0.
- **Setup:** Long Round 1 scan with YARA_THREADS=1 and YARA_QUEUE_SIZE=2 so discovery outruns the workers, plus `stress-ng --cpu 6` to keep workers slow. Must complete, not be cancelled — a cancel breaks the identity because the enqueue loop exits early.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'Scan queue saturated (N items) - backing off producer'; <scanner_dir>/logs/statistics_<run_id>.log 'Target scan completed: <path>' records (data.files_found) and the 'Skip reasons: ...' record's data.skip_breakdown; <scanner_dir>/logs/scan_summary_<run_id>.json files_scanned / files_skipped / outcome. Code: YaraScanner._enqueue_scan_path (`while self.scan_active: put(path, timeout=1.0)` retrying on Full), and the scan_system counting sites for 'Skipped directory', 'Junction/symlink skip' and 'Special system file'.
- **Negative control:** The identity must not be satisfiable by a scanner that enqueues nothing: files_scanned on the same run must be > 0 and skip_breakdown must NOT account for the whole tree.

### `PERF-021` Queue-saturation event counter with 1-in-25 log sampling

*low*

- **Must be true:** Saturation logging is sampled at 1 in 25, so the line count is a bounded proxy for backpressure rather than one line per blocked put — and the raw counter appears in no artefact.
- **Threshold:** On the YARA_THREADS=1 / YARA_QUEUE_SIZE=2 run: the 'Scan queue saturated' line count is at least 2, and line_count * 25 is within one order of magnitude of the independently estimated blocked-put count (saturated wall-clock seconds / (1.0s put timeout + queue_backoff_secs)). The string 'queue_full_events' appears in no file under <scanner_dir> (grep -r returns 0), confirming the counter is not exported anywhere.
- **Setup:** Same saturation run as PERF-020.
- **Evidence:** grep -c 'Scan queue saturated' <scanner_dir>/logs/performance_<run_id>.log; grep -r 'queue_full_events' <scanner_dir>/ ; <scanner_dir>/logs/statistics_<run_id>.log Scan Progress lines to bound the saturated interval. Code: YaraScanner._enqueue_scan_path — `self.queue_full_events += 1; if self.queue_full_events % 25 == 1:`.
- **Negative control:** The FIRST saturation event must always be logged (1 % 25 == 1), so a run that saturates even once must never produce zero lines — the sampler must not swallow the first occurrence.

### `PERF-022` Governor sampling from the blocked producer

*supporting*

- **Must be true:** Governor readings keep flowing while the producer is blocked and no file is completing, proving the producer path samples rather than relying on worker-side sampling.
- **Threshold:** Identify a window of at least 90s during which (a) 'Scan queue saturated' lines are being written and (b) Scan Progress files_scanned advances by no more than 2. Within that window at least 3 CPU_GOVERNOR lines appear, and no gap between consecutive `t` values exceeds 32.0s (GOVERNOR_HEARTBEAT_SECS 30 + one put timeout 1.0 + queue_backoff_secs 0.25 + slack). cpu_governor.samples_taken must be strictly greater than files_scanned on that run.
- **Setup:** YARA_THREADS=1, YARA_QUEUE_SIZE=2, YARA_PROGRESS_LOG_SECS=10, and a tree containing several 40-60 MB files (under the 64 MB max_file_mb gate) with a string-heavy ruleset, so a single worker is parked inside rules.match for minutes while the producer keeps hitting Full.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'Scan queue saturated (N items) - backing off producer' lines and `CPU_GOVERNOR {...}` `t` values, interleaved by timestamp; <scanner_dir>/logs/statistics_<run_id>.log Scan Progress data.files_scanned; <scanner_dir>/logs/scan_summary_<run_id>.json cpu_governor.samples_taken and files_scanned. Code: the `self._sample_governor()` call inside _enqueue_scan_path's Full handler, before the backoff sleep.

### `PERF-027` Per-worker throughput logging every 100 files — and why its Error Rate is structurally 0.0%

*low*

- **Must be true:** Worker Performance lines are emitted on the 100-file trigger but gated to at most one per WORKER_REPORT_MIN_SECS per worker, and their Error Rate is always 0.0% because errors_encountered counts only worker-loop exceptions, never per-file scan failures.
- **Threshold:** Every 'Worker Performance |' line reports 'Error Rate: 0.0%' and data.error_rate_percent == 0.0, on a run whose honest per-file failure count is demonstrably non-zero: sum of every skip_breakdown entry representing a failure ('Scan error (<Type>)', 'No read permission', 'Permission denied', 'File does not exist') > 0. Cross-check on the same run: every 'Worker ScanWorker-N stopped' record has data.errors_encountered == 0 while its data.files_processed > 0 and the run's failure count above is > 0 — that pair is the defect, and it needs no planting. data.files_processed on every Worker Performance line is an exact multiple of 100 (the trigger is `files_processed % 100 == 0 and files_processed > 0`). Per worker, no two lines closer than WORKER_REPORT_MIN_SECS (30.0s). Total line count <= max_workers * ceil(duration_secs / 30). Do NOT plant chmod-000 files to force the failures: os.access(R_OK) short-circuits before rules.match so they would read as 'No read permission', and the payload runs as root/SYSTEM so they are not denied at all. A live whole-filesystem Round 1 scan supplies vanishing and locked files naturally.
- **Setup:** Round 1 long clean scan on a live filesystem — files vanishing or locking between the access check and rules.match produce the 'Scan error (...)' skip reasons naturally. Add ~50 unreadable files (chmod 000) to guarantee them.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'Worker Performance | ScanWorker-N | Files: … | Avg Time: …ms | Error Rate: …%' lines with data keys worker_id / files_processed / avg_processing_time_ms / error_rate_percent; the honest counterparts are <scanner_dir>/logs/statistics_<run_id>.log's 'Skip reasons: …' record (data.skip_breakdown) and <scanner_dir>/logs/system_<run_id>.log's 'Worker ScanWorker-N stopped' record (data.files_processed alongside data.errors_encountered). Code: YaraScanner._worker — the only errors_encountered increment is in the worker-loop `except Exception` branch; scan_file's per-file failures return (False, reason) and never touch it.
- **Negative control:** A scan too short to span one 30s interval must still produce one Worker Performance line per worker that reaches 100 files (_worker_report_due returns True when last_report is 0). The rate gate must suppress repeats, not the first sample.

### `PERF-028` Per-worker timing ring buffer capped at 100 samples — and the end-of-run summary that reports its length as a file count

*supporting*

- **Must be true:** The per-worker timing buffer is trimmed to its last 100 samples, and the end-of-run summary reports that buffer length as though it were a file count — so on any worker that processed more than 100 files the summary understates the truth, while the system-log stop record does not.
- **Threshold:** On a run where every worker processed more than 100 files: the 'Worker performance summary' record's data.worker_details.<worker>.files_processed == 100 exactly for every worker, while the corresponding 'Worker ScanWorker-N stopped' data.files_processed is > 100; and sum(worker_details.*.files_processed) == 100 * max_workers, which is strictly less than scan_summary.files_scanned. The number of workers named in worker_details == max_workers.
- **Setup:** Round 1 long clean scan sized so each worker handles well over 100 files (>= 1,000 files total at 2 workers).
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log — the 'Worker performance summary: N workers processed files' record's data.worker_details; <scanner_dir>/logs/system_<run_id>.log 'Worker ScanWorker-N stopped' data.files_processed; <scanner_dir>/logs/scan_summary_<run_id>.json files_scanned. Code: scan_file's finally block (`if len(self.worker_processing_times[worker_id]) > 100: ... = [-100:]`) and the summary construction in _log_final_results which uses len(times) as files_processed.
- **Negative control:** On a short run where a worker processed fewer than 100 files, that worker's worker_details.files_processed must equal its true stop-record files_processed — the trim must not alter counts below the cap.

### `PERF-029` Progress heartbeat thread (whole-scan progress telemetry)

*core*

- **Must be true:** Progress telemetry spans the whole scan, not just file discovery: Scan Progress lines continue at the configured interval after discovery has finished, and an out-of-range interval falls back to the default rather than busy-spinning.
- **Threshold:** Default run: consecutive 'Scan Progress' lines are 30 +/- 2s apart; total count >= floor(duration_secs / 30) - 1; at least 2 of them are timestamped AFTER the last 'Target scan completed' record. Run with YARA_PROGRESS_LOG_SECS=0: cadence stays 30 +/- 2s and the line count is <= duration_secs/30 + 2 — it must NOT approach one line per loop iteration (_env_number minimum=1 rejects 0 and returns the 30 default; max(1, ...) is the second guard).
- **Setup:** Two runs on the same tree, the second with YARA_PROGRESS_LOG_SECS=0 exported. The tree must be large enough that worker matching continues well past discovery.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log 'Scan Progress | Files: N scanned, M skipped | Detections: D | Queue: Q | Rate: R files/sec' lines and their file timestamps; the 'Target scan completed: <path>' records in the same file mark the end of discovery. Code: YaraScanner._progress_heartbeat (`while not self._progress_heartbeat_stop.wait(self.config.log_interval)`), thread start in scan_system, stop/join in _perform_enhanced_cleanup after the worker joins.
- **Negative control:** YARA_PROGRESS_LOG_SECS=5 (a valid in-range value) must be honoured as 5s spacing — the clamp must reject only out-of-range values, not pin every run to 30s.

### `PERF-030` Progress snapshot holds lock_counts across psutil calls

*supporting*

- **Must be true:** Every progress tick is one coherent snapshot taken under lock_counts — the Scan Progress line and the Time Estimates line emitted in the same tick satisfy an exact arithmetic identity that only holds if no worker advanced the counters between them.
- **Threshold:** For every tick that emits both lines: Time Estimates data.files_remaining == Scan Progress data.files_skipped + 2 * Scan Progress data.queue_size, exactly, with zero mismatched pairs across the whole run (total_files_estimate = files_scanned + files_skipped + queue_size*2, and files_remaining = that minus files_scanned). On a busy scan with >= 20 ticks and a non-empty queue, at least 15 such pairs must exist and all must match.
- **Setup:** Round 1 long clean scan with YARA_PROGRESS_LOG_SECS=10 and YARA_THREADS=4 so counters move fast between ticks and a dropped lock would show immediately.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log — consecutive pairs of 'Scan Progress | ...' (data keys files_scanned, files_skipped, queue_size) and 'Time Estimates | ETA: ... | Rate: ... | Remaining: N files' (data key files_remaining). Code: YaraScanner._log_progress — the whole body including the psutil block, update_scanner_stats, calculate_time_estimates and both log calls is inside `with self.lock_counts:`.
- **Negative control:** The identity must not hold vacuously: at least 15 of the paired ticks must have queue_size > 0 and files_skipped > 0, and files_scanned must increase between consecutive ticks.

### `PERF-031` Progress sampler reuses the primed psutil handle

*supporting*

- **Must be true:** The progress sampler reuses the constructor-primed Process handle rather than building a fresh one per tick, so its CPU reading is real from the first tick instead of being permanently 0.0.
- **Threshold:** The first 'System Resources | CPU:' line has data.cpu_percent > 0.0, and at most 1 of all such lines in the run reports exactly 0.0. data.memory_mb > 0.0 on every line. No 'Error collecting system metrics:' entry appears in scan_errors_<run_id>.log.
- **Setup:** Round 1 run with YARA_PROGRESS_LOG_SECS=10 so several ticks land during the active phase.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'System Resources | CPU: X.X% | Memory: …MB | Disk I/O: …MB | Network: …MB' lines and their data keys cpu_percent / memory_mb (LogManager.log_system_resources routes to log_performance); <scanner_dir>/logs/scan_errors_<run_id>.log for the absence of 'Error collecting system metrics:'. Code: YaraScanner._log_progress — `process = getattr(self, '_governor_proc', None) or getattr(self, '_progress_proc', None)`, priming only on the fallback path.

### `PERF-033` ETA and completion-time estimation

*supporting*

- **Must be true:** An ETA is produced from the live rate and the queue-derived total estimate, it is internally consistent with the rate it reports, and it is deliberately absent from scan_summary_<run_id>.json.
- **Threshold:** For every 'Time Estimates' line: abs(data.eta_seconds - data.files_remaining / data.current_rate_files_per_sec) <= 1.0, and data.current_rate_files_per_sec > 0. At least 5 such lines on a scan of >= 300s. The COMPREHENSIVE SCAN REPORT's performance_summary.scan_estimates carries the same five keys (total_files_estimate, completion_estimate, current_rate, average_rate, eta_seconds). scan_summary_<run_id>.json contains no key named 'scan_estimates' and no key named 'eta_seconds' (`jq 'has("scan_estimates")'` == false).
- **Setup:** Round 1 long clean scan with YARA_PROGRESS_LOG_SECS=10.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log 'Time Estimates | ETA: … | Rate: … files/sec | Remaining: N files' lines with data keys eta_seconds / estimated_completion / current_rate_files_per_sec / files_remaining, and the 'COMPREHENSIVE SCAN REPORT | Efficiency Score: …' record's performance_summary.scan_estimates; <scanner_dir>/logs/scan_summary_<run_id>.json for the absence. Code: YaraScanner._log_progress ETA block, StatisticsManager.calculate_time_estimates (300s / 5s window arithmetic), get_current_stats_for_upload.

### `PERF-034` Scan-lifecycle heartbeat thread (dataset 'running' rows)

*core*

- **Must be true:** Running-status lifecycle rows land on their configured cadence for the whole scan and carry live, advancing counters — and the local liveness marker advances with them.
- **Threshold:** With YARA_HEARTBEAT_SECS=120 and YARA_HEARTBEAT_POLL_SECS=30 on a scan of >= 600s: at least 4 rows with status='running' and message='heartbeat' for the run_id; consecutive event_timestamp_ms gaps in [120s, 150s]; files_scanned strictly non-decreasing and strictly increasing between the first and last running row; elapsed_secs strictly increasing. <scanner_dir>/control/running.json's updated_at advances by at least 3 distinct values across the same period, and its status reads 'running'.
- **Setup:** Round 1 long clean scan with YARA_HEARTBEAT_SECS=120 and YARA_HEARTBEAT_POLL_SECS=30 exported (the 600s default would produce too few rows to test cadence). Poll running.json over SSH every 10s for the duration.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "running" | fields event_timestamp_ms, files_scanned, files_skipped, elapsed_secs, total_paused_secs, message | sort asc event_timestamp_ms`; <scanner_dir>/control/running.json fields updated_at / status / files_scanned. Code: _start_heartbeat_thread, _heartbeat_worker (`time.sleep(HEARTBEAT_THREAD_POLL_SECS)`), _maybe_heartbeat, _write_running_marker (atomic temp + os.replace).

### `PERF-035` Heartbeat gate is lock-protected against duplicate rows

*supporting*

- **Must be true:** The check-and-set on _last_heartbeat is atomic across its two callers, so no heartbeat interval ever produces two running rows — even though the walker loop and the heartbeat thread both call it.
- **Threshold:** Run this on its OWN run — a separate Round 1 scan of >= 600s with YARA_HEARTBEAT_SECS=120 and YARA_HEARTBEAT_POLL_SECS=5 (not PERF-034's run, which pins the poll to 30; one run cannot carry both values). For that run_id: no two status='running' rows share an event_timestamp_ms; no two are less than 120s apart; zero pairs within 2s of each other; row count with status='running' == floor(scan_duration_secs / 120) +/- 1. With poll=5 the walker loop and _heartbeat_worker contend on the gate ~24 times per emission interval, which is the condition a missing lock would expose.
- **Setup:** Same run as PERF-034, with YARA_HEARTBEAT_POLL_SECS=5 (well below the 120s emission gate) so the thread and the walker contend on the gate many times per interval — the condition that would expose a missing lock.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "running" | comp count() as n by event_timestamp_ms | filter n > 1` must return zero rows; and the sorted event_timestamp_ms series for the gap check. Code: _maybe_heartbeat's `with self._heartbeat_lock:` around the `now - self._last_heartbeat < SCANS_HEARTBEAT_SECS` test and assignment; call sites in scan_system's walker loop and _heartbeat_worker.
- **Negative control:** The gate must suppress only duplicate heartbeats: the same run must still show exactly one status='initiated' row and exactly one terminal row (status in completed/cancelled/failed). A run showing zero of either means the gate is suppressing non-heartbeat rows.

### `PERF-036` Paused-seconds accounting on every lifecycle row

*supporting*

- **Must be true:** total_paused_secs is present on every lifecycle row, never decreases across a run, and the terminal row agrees exactly with the scan summary and the operator-facing result line.
- **Threshold:** Every row for the run_id (initiated, running x N, terminal) carries a numeric total_paused_secs. The series ordered by event_timestamp_ms is non-decreasing, with the initiated row at 0.0. On the loaded run the terminal row's total_paused_secs > 0.0 and equals scan_summary.total_paused_secs exactly (both are round(slept_total, 2)) and equals scan_summary.cpu_governor.slept_secs exactly; round(terminal total_paused_secs) equals the integer in the SCAN_RESULT 'cpu-slept Ns' fragment.
- **Setup:** Round 1 headroom run with the stress-ng window (PERF-002) so pacing actually occurs; without external load the ratio stays 0 and every row reads 0.0, which makes the monotonicity check vacuous.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, event_timestamp_ms, total_paused_secs | sort asc event_timestamp_ms`; <scanner_dir>/logs/scan_summary_<run_id>.json total_paused_secs and cpu_governor.slept_secs; the Action Center SCAN_RESULT line's 'cpu-slept Ns'. Code: _emit_scan_row's `with self.lock_throttle: paused = round(self.cpu_governor.slept_total, 2)` and the row's total_paused_secs field; the summary write in run()'s finally block.

### `PERF-040` StatisticsManager background performance sampler

*supporting*

- **Must be true:** The sampler is off by default and on when the env flag is set, and the double call to start_monitoring produces exactly one thread — not two, and not two 'started' lines.
- **Threshold:** Default run: 'Performance monitoring disabled in light profile' appears exactly 2 times in statistics_<run_id>.log (start_monitoring is called from StatisticsManager.__init__ and again from run()), 'Performance monitoring thread started' appears 0 times, and 'Performance Snapshot |' appears 0 times in performance_<run_id>.log. Run with YARA_ENABLE_PERF_MONITOR=true: 'Performance monitoring thread started' appears exactly 1 time (the second call finds the thread alive and logs nothing), 'disabled in light profile' 0 times, 'Performance monitoring worker started' 1 time, and 'Performance Snapshot |' line count >= 1. The 'All monitoring systems activated' record's performance_monitoring matches the flag in both runs.
- **Setup:** Two runs on the same tree, the second with YARA_ENABLE_PERF_MONITOR=true exported. The scan must exceed 180s so at least 6 snapshots (5s apart) accumulate.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log lines 'Performance monitoring disabled in light profile' / 'Performance monitoring thread started'; <scanner_dir>/logs/performance_<run_id>.log 'Performance monitoring worker started', 'Performance Snapshot |', 'Performance monitoring worker stopped'; <scanner_dir>/logs/system_<run_id>.log 'All monitoring systems activated' data.performance_monitoring. Code: StatisticsManager.start_monitoring (guarded on config.enable_performance_monitoring, then on thread liveness), _monitoring_worker (`time.sleep(5)`), ScanConfig's YARA_ENABLE_PERF_MONITOR parse.

### `PERF-041` Performance history ring buffer and peak/average metrics

*low*

- **Must be true:** Peak and average metrics are computed over a buffer capped at 1000 snapshots, and samples_collected reports the buffer length — which saturates at the cap rather than counting all samples taken.
- **Threshold:** With YARA_ENABLE_PERF_MONITOR=true on a scan of >= 300s: samples_collected >= round(duration_secs / 5) AND <= round((duration_secs + compile_seconds + 60) / 5), where compile_seconds comes from scan_summary — the monitor thread starts in StatisticsManager.__init__, before rule compilation and before scan_start_time, so its uptime strictly exceeds duration_secs and an equality band of +/-3 fails a correct build. On a scan of >= 6000s (or with the deque pre-filled): samples_collected == 1000 exactly and does not exceed it. peak_cpu_percent >= avg_cpu_percent and peak_memory_mb >= avg_memory_mb, both > 0. On the DEFAULT run (monitor off), the same block reports samples_collected == 0 and all four metrics == 0.0. scan_summary_<run_id>.json contains no 'performance_metrics' key. The 1000-cap arm needs a scan longer than 83 minutes; if none is run, record the cap arm as UNREACHED rather than passed.
- **Setup:** The YARA_ENABLE_PERF_MONITOR=true run from PERF-040, plus the default run as the zero control. The 1000-cap arm needs a scan longer than 83 minutes; if none is run, record the cap arm as unreached rather than passed.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log — the 'COMPREHENSIVE STATISTICS SUMMARY' block's `Performance Metrics: {...}` JSON (keys peak_cpu_percent, avg_cpu_percent, peak_memory_mb, avg_memory_mb, samples_collected) and the 'COMPREHENSIVE SCAN REPORT | Efficiency Score: …' record's performance_summary.performance_metrics; <scanner_dir>/logs/scan_summary_<run_id>.json for the absence. Code: `self.performance_history = deque(maxlen=1000)`, _update_performance_metrics, log_comprehensive_stats.
- **Negative control:** The cap must bound the buffer, not the metrics. Decidable form: on the >= 6000s run, peak_cpu_percent and peak_memory_mb must each be >= the maximum cpu_percent / memory_mb visible on any 'Performance Snapshot |' line in the run — including lines written in the first 83 minutes, before the deque saturated and the 1-in-6 emitter went silent (peaks are max()-accumulated in _update_performance_metrics and never recomputed from the deque, so a build that recomputed them from the sliding window would report a peak lower than an early logged snapshot). Do NOT phrase the control as 'the max of the last 1000 snapshots': individual snapshots are never written to any artefact, so that quantity cannot be recovered from the evidence.

### `PERF-042` Sampled performance-detail logging (1 in 6 snapshots)

*low*

- **Must be true:** Performance Snapshot lines are written once per six collected snapshots — about every 30s — and stop entirely once the 1000-sample deque saturates, because the emission gate tests the buffer length rather than a sample counter.
- **Threshold:** Anchor everything to the monitor's own clock, not scan_start_time. Cadence: consecutive 'Performance Snapshot |' lines are 30 +/- 3s apart (6 x the 5s sleep); line count == floor(min(T_mon, 5000) / 30) +/- 2, where T_mon is the interval from the '=== Performance Monitoring Started ===' / 'Performance monitoring worker started' line to 'Performance monitoring worker stopped' — the thread starts in StatisticsManager.__init__, before compilation and before scan_start_time, so measuring against duration_secs fails a correct build by ~compile_seconds/30 lines. Saturation arm (run > 5000s of monitor uptime): the LAST 'Performance Snapshot |' line's timestamp is within 60s of monitor-start + 5000s, no such line appears afterwards, and samples_collected == 1000 — the gate tests len(performance_history) against a deque(maxlen=1000), and 1000 % 6 == 4, so emission stops permanently while sampling continues. If no run exceeds 5000s of monitor uptime, record the saturation arm as UNREACHED.
- **Setup:** The YARA_ENABLE_PERF_MONITOR=true run from PERF-040, extended to a whole-filesystem target so it runs past 90 minutes. A shorter run decides only the 30s-cadence half.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'Performance Snapshot | CPU: … (system …) | Memory: … | Disk I/O: … | Network: … | Queue: N | Workers: M' lines and their file timestamps; <scanner_dir>/logs/statistics_<run_id>.log COMPREHENSIVE STATISTICS SUMMARY samples_collected. Code: StatisticsManager._monitoring_worker — `if len(self.performance_history) % 6 == 0: self._log_performance_details(snapshot)` against a deque(maxlen=1000); once len pins at 1000, 1000 % 6 == 4, so the condition is never true again.
- **Negative control:** The suppression must be the 1-in-6 gate and the deque saturation, not a dead emitter: during the first 83 minutes the lines must actually appear at ~30s spacing, and samples_collected must keep rising to 1000 after the lines stop.

### `PERF-043` Snapshot enrichment with live scanner counters

*low*

- **Must be true:** current_performance is null on a default run and carries live queue/worker counters when the performance monitor is enabled — the enrichment no-ops on an empty deque rather than erroring, and never reaches scan_summary.
- **Threshold:** Default run: performance_summary.current_performance is exactly null in the COMPREHENSIVE SCAN REPORT and performance_metrics.current_performance is exactly null in the 'SCAN COMPLETED SUCCESSFULLY' statistics entry; no error entry mentioning update_scanner_stats appears in scan_errors_<run_id>.log; 'Performance Snapshot |' line count is 0. Run with YARA_ENABLE_PERF_MONITOR=true (and YARA_PROGRESS_LOG_SECS=10): current_performance is a non-null object whose queue_size is an int in [0, scan_queue_size] and whose active_workers is an int in [0, max_workers]. Do NOT require its files_scanned > 0 — enrichment writes only into performance_history[-1] while _monitoring_worker appends a fresh zeroed snapshot every 5s, and the progress heartbeat is stopped before stats_manager.stop_monitoring(), so the FINAL element is normally un-enriched. Prove enrichment where it is actually visible: at least one 'Performance Snapshot |' line must report 'Workers: N' with N > 0 (active_workers is only ever non-zero via update_scanner_stats), whereas the default run has no such line at all. Both runs: scan_summary_<run_id>.json has no 'current_performance' key.
- **Setup:** The default / YARA_ENABLE_PERF_MONITOR=true pair from PERF-040. The report is written after the workers join, so active_workers may legitimately be 0 in the final snapshot — bound it, do not require > 0.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log — the 'COMPREHENSIVE SCAN REPORT | Efficiency Score: …' record's performance_summary.current_performance, and the 'SCAN COMPLETED SUCCESSFULLY in …' record's performance_metrics.current_performance (that record's data is comprehensive_final_stats, whose 'performance_metrics' key holds the whole get_current_stats_for_upload dict; the separate 'SCAN COMPLETED' line written by _log_final_results carries final_metrics only and has no performance data — do not use it). <scanner_dir>/logs/performance_<run_id>.log 'Performance Snapshot | … | Queue: N | Workers: M' lines for the enrichment probe; <scanner_dir>/logs/scan_errors_<run_id>.log; <scanner_dir>/logs/scan_summary_<run_id>.json for the absence. Code: StatisticsManager.update_scanner_stats (guarded by `if self.performance_history:`, mutating only performance_history[-1]), its call site inside YaraScanner._log_progress, and get_current_stats_for_upload's `current_snapshot.to_dict() if current_snapshot else None`.

### `PERF-044` SystemResourceMonitor thread (host-level resource sampling)

*supporting*

- **Must be true:** The host-level monitor is not constructed at all when its flag is off — so neither its 'started' nor its 'disabled' line can appear — and when on it samples at 10s and records to the performance log at 45s.
- **Threshold:** Default run: 'System resource monitoring started' 0 occurrences AND 'System resource monitoring disabled in light profile' 0 occurrences in system_<run_id>.log (the instantiation gate in scan_system means the class's own disabled branch is unreachable); 'System resources - CPU:' 0 occurrences in performance_<run_id>.log; the 'All monitoring systems activated' record has resource_monitoring == false; the COMPREHENSIVE SCAN REPORT has no 'resource_summary' key. Run with YARA_ENABLE_RESOURCE_MONITOR=true on a scan >= 300s: 'System resource monitoring started' exactly 1; 'System resources - CPU: …%, Memory: …MB' lines spaced 45 +/- 10s with count >= 5; the closing 'Resource monitoring completed: N snapshots, M alerts' line reports N == round(duration_secs / 10) +/- 3; resource_summary.data_points_collected == N; 'All monitoring systems activated' resource_monitoring == true.
- **Setup:** Two runs on the same tree, the second with YARA_ENABLE_RESOURCE_MONITOR=true exported.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log 'System resource monitoring started' / 'System resource monitoring disabled in light profile' and the 'All monitoring systems activated' data.resource_monitoring; <scanner_dir>/logs/performance_<run_id>.log 'System resource monitoring worker started', 'System resources - CPU: X.X%, Memory: X.XMB' and 'Resource monitoring completed: N snapshots, M alerts'; <scanner_dir>/logs/statistics_<run_id>.log COMPREHENSIVE SCAN REPORT resource_summary. Code: scan_system's `self.resource_monitor = None; if self.config.enable_resource_monitoring: self.resource_monitor = SystemResourceMonitor(...)`; SystemResourceMonitor.__init__ (monitoring_interval 10, upload_interval 45), start_monitoring, _monitoring_worker.
- **Negative control:** The disabled state must be proved positively by resource_monitoring == false in 'All monitoring systems activated', not by absence alone — absence is also what a crashed monitor thread produces.

### `PERF-045` Resource alert thresholds (CPU / memory / disk)

*supporting*

- **Must be true:** Each resource alert fires strictly above its own literal threshold and names that threshold in the record, and the alert count reconciles between the error log and both summaries.
- **Threshold:** With the resource monitor on and process CPU driven above 90 (process-relative percent, so >90 needs the scanner using more than ~0.9 of a core): at least one 'RESOURCE ALERT: high_cpu - X.X% exceeds threshold of 90%' entry with data.threshold == 90 and data.current_value > 90. Count of 'RESOURCE ALERT:' entries in scan_errors_<run_id>.log == resource_summary.alerts_triggered in the COMPREHENSIVE SCAN REPORT == M in 'Resource monitoring completed: N snapshots, M alerts', all three equal (capped at 100 by the alert_history deque — if the count reaches 100, assert only >= 100). Any high_memory entry has data.threshold == 85; any high_disk_usage entry has data.threshold == 95.
- **Setup:** Round 1 run with YARA_ENABLE_RESOURCE_MONITOR=true and options `cpu_guarantee=none,workers=4` so the scanner is not paced and its own process CPU exceeds 90% of one core, on a target tree of large files that keeps the workers CPU-bound.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log 'RESOURCE ALERT: <type> - X.X% exceeds threshold of N%' entries with data keys alert_type / current_value / threshold; <scanner_dir>/logs/performance_<run_id>.log 'Resource monitoring completed: N snapshots, M alerts'; <scanner_dir>/logs/statistics_<run_id>.log COMPREHENSIVE SCAN REPORT resource_summary.alerts_triggered. Code: SystemResourceMonitor._check_resource_alerts with alert_thresholds {'cpu_percent': 90, 'memory_percent': 85, 'disk_usage_percent': 95}, all strict `>` comparisons.
- **Negative control:** On the same run, zero high_memory and zero high_disk_usage entries must appear, verified against what the code actually compares: the SCANNER PROCESS's memory share (psutil Process.memory_percent — sample `ps -o rss= -p <pid>` against MemTotal, or read data.process.memory_percent off the 'System resources - CPU:' lines) must stay below 85, and the host's '/' usage (`df /`, matching system.disk_used_percent) below 95. Do NOT use host-wide memory (`free`, psutil.virtual_memory().percent): _check_resource_alerts reads resource_data['process']['memory_percent'], never system.memory_used_percent, so a host at 92% RAM correctly triggers nothing. All three alert types firing together would mean the comparison, not the CPU load, is what triggered them.

### `PERF-046` Resource and alert history ring buffers

*supporting*

- **Must be true:** On a monitored scan whose monitored span exceeds 75 minutes the resource ring buffer saturates instead of growing: the end-of-run summary reports data_points_collected == 360 and monitoring_duration_seconds == 3600 exactly, even though the monitored span was far longer.
- **Threshold:** deque maxlens 360 (resource_history) and 100 (alert_history); monitoring_interval literal 10, so monitoring_duration_seconds == data_points_collected * 10 and both saturate at 360/3600. Saturated run (monitored span >= 75 min, allowing for per-snapshot collection cost on top of the 10s sleep): data_points_collected == 360 and monitoring_duration_seconds == 3600. Drop the alerts_triggered clause unless the run is driven past 100 alerts (thresholds are 90% process CPU / 85% process memory / 95% disk usage); it is not falsifiable otherwise.
- **Setup:** Round 1 long scan launched over SSH with YARA_ENABLE_RESOURCE_MONITOR=true against a tree large enough to run >60 min (the 360-slot buffer fills at one snapshot per 10s). Without the env var SystemResourceMonitor is never constructed and none of these fields exist.
- **Evidence:** data.data_points_collected, data.monitoring_duration_seconds and data.alerts_triggered on the single 'Resource monitoring completed: N snapshots, M alerts' record in <scanner_dir>/logs/performance_<run_id>.log — its ' | data=' JSON is get_resource_summary() verbatim and is small enough to survive the 4000-char cap. Do NOT rely on resource_summary inside the 'COMPREHENSIVE SCAN REPORT | Efficiency Score:' record: that payload is json.dumps(sort_keys=True) truncated at 4000 chars, and resource_summary sorts late enough to be the first key cut.
- **Negative control:** A monitored run of ~20 monitored minutes must report data_points_collected ~= 120 (monitored_secs/10, tolerance +/-10%) and monitoring_duration_seconds == data_points_collected*10, both BELOW the caps. A build reporting 360/3600 on both runs is printing constants rather than measuring a ring buffer.

### `PERF-047` Resource trend classification

*low*

- **Must be true:** The '10-minute' trend averages are computed over the ENTIRE resource history, not the last 10 minutes — trends.data_points equals the total snapshot count so far rather than the ~60 samples a 600s window would hold, because the recent_cutoff variable in _calculate_resource_trends is computed and never used to filter.
- **Threshold:** On a monitored scan running >20 min: trends.data_points must INCREASE monotonically across successive 'System resources - CPU: ' records and exceed 60 by the end (a live 600s window at the 10s sampling interval would plateau at ~60), and the LAST such record's trends.data_points must be within 6 of data_points_collected in the end-of-run summary (the 45s upload_interval means the last emission trails the final count by ~4-5 samples). Slope labels: cpu_trend 'increasing' when (last-first)/n > 2, 'decreasing' when < -2; memory_trend at +/-5; both stay 'stable' until at least 5 samples exist; the whole trends dict is {} below 2 samples.
- **Setup:** Same monitored Round 1 run (YARA_ENABLE_RESOURCE_MONITOR=true), >20 min long. These records are emitted on the 45s upload_interval, not the 10s sampling interval.
- **Evidence:** data.trends.{cpu_trend,memory_trend,cpu_avg_10min,memory_avg_10min,data_points} on the 'System resources - CPU: ' records in <scanner_dir>/logs/performance_<run_id>.log, compared against data_points_collected in the 'Resource monitoring completed: ' record in the same file.
- **Negative control:** The FIRST 'System resources - CPU: ' record on the same run (emitted at ~10s, when last_upload_time is still 0 and only one snapshot exists) must carry trends == {} — the <2-sample guard. And across records 8 through the last, trends.data_points must keep climbing past 60 rather than plateauing at ~60: a build that actually applied recent_cutoff would flatten there. Without both, 'unfiltered window' and 'short run' leave identical evidence.

### `PERF-048` Resource monitor stopped AFTER worker join, not at discovery end

*supporting*

- **Must be true:** Resource and statistics monitoring keep running through the post-discovery worker drain: in performance_<run_id>.log file order the 'Resource monitoring completed:' record appears strictly AFTER the 'Worker cleanup:' record, and the last 'Scan Progress' record post-dates the end of directory discovery.
- **Threshold:** Byte offset of 'Resource monitoring completed: ' > byte offset of 'Worker cleanup: ' in the same performance_<run_id>.log; at least one 'Scan Progress | Files:' record is timestamped more than log_interval (30s default) after the final 'Scanning target ' system record; and the last 'Scan Progress' record is within log_interval + 5s of the 'Worker cleanup: ' record (NOT of 'SCAN COMPLETED | Time:', which is written by _log_final_results only after _perform_enhanced_cleanup has also drained both uploaders — alert drain up to 300s + 60s join, lookup drain up to 600s).
- **Setup:** Round 1 run with YARA_ENABLE_RESOURCE_MONITOR=true against a directory of many small files with YARA_THREADS=1, so discovery finishes minutes before the queue drains and a monitor stopped at discovery end would be visibly truncated.
- **Evidence:** Line ordering of 'Worker cleanup: ' (log_performance in _perform_enhanced_cleanup) and 'Resource monitoring completed: ' in <scanner_dir>/logs/performance_<run_id>.log; timestamps of 'Scan Progress | Files:' records vs the 'SCAN COMPLETED | Time:' record in logs/statistics_<run_id>.log.

### `PERF-049` File-descriptor sampling every 1000 CLEAN scanned files  <sub>linux, darwin</sub>

*low*

- **Must be true:** With FD monitoring enabled a reading is taken once per 1000 files processed, and each warning line fires only on its own threshold — 'FD usage increased by N' only when the count exceeds the startup baseline by more than 100, 'WARNING: High FD usage: N' only when the absolute count exceeds 900.
- **Threshold:** fd_check_interval = 1000 (bare instance literal); delta threshold 100 (strictly greater); absolute threshold 900 (strictly greater). Sample count is driven by scan_file CALLS, not by files_skipped: define scan_file_calls = files_scanned + (files_skipped - skip_breakdown['Skipped directory'] - skip_breakdown['Junction/symlink skip'] - skip_breakdown['Special system file']), treating absent keys as 0. Then count of 'WARNING: High FD usage: ' lines == floor(scan_file_calls/1000) +/- 1. Launch the wrapper from a shell that has already run `ulimit -n 65536` before pre-opening the ~950 descriptors, or the scan dies on EMFILE under the default 1024 soft limit.
- **Setup:** Round 1 long clean scan launched over SSH on the Linux endpoint with YARA_ENABLE_FD_MONITOR=true, from a wrapper that pre-opens ~950 descriptors before exec (`for i in $(seq 20 970); do eval "exec $i>/dev/null"; done; exec python3 xdr_yara_scanner.py ...`). num_fds() then reads >900 on every sample so each sample leaves a line, while initial_fd_count is measured with those already open so the delta stays ~0. fd_samples_taken has no reader anywhere in the scanner, so a threshold line is the only live proxy for a sample.
- **Evidence:** Count of lines matching 'WARNING: High FD usage: ' in <scanner_dir>/logs/system_<run_id>.log, against files_scanned in logs/scan_summary_<run_id>.json and data.skip_breakdown in the 'Skip reasons: ' record of logs/statistics_<run_id>.log (needed to subtract the three discovery-level skip reasons that never call scan_file).
- **Negative control:** On that same run zero lines matching 'FD usage increased by ' may appear — the count never rises 100 above its own baseline, so the delta rule must stay silent while the absolute rule fires. A run that emits both, or neither, cannot separate 'sampled and within threshold' from 'never sampled'.

### `PERF-050` Startup file-descriptor limit probe  <sub>linux, darwin</sub>

*supporting*

- **Must be true:** With FD monitoring enabled on POSIX the scanner reads the descriptor limit at startup and warns only when it is below 8192; the probe itself still runs (and records a baseline) on a healthy host.
- **Threshold:** 8192. Run launched with `ulimit -n 4096`: exactly one 'Current file descriptor limit: 4096', one 'WARNING: Low file descriptor limit (4096)' and one 'Consider running: ulimit -n 65536 before starting scanner'. Run launched with `ulimit -n 65536`: 'Current file descriptor limit: 65536' present and zero 'WARNING: Low file descriptor limit' lines.
- **Setup:** Two short Round 1 runs over SSH on the Linux endpoint with YARA_ENABLE_FD_MONITOR=true, launched from shells with `ulimit -n 4096` and `ulimit -n 65536` respectively (rlimits are inherited by the `bash -c 'ulimit -n'` subprocess the probe shells out to).
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log lines 'Current file descriptor limit: ', 'WARNING: Low file descriptor limit (', 'Consider running: ulimit -n 65536 before starting scanner', 'Initial file descriptors in use: '.
- **Negative control:** The 65536 run must still emit 'Current file descriptor limit: 65536' AND 'Initial file descriptors in use: N' — the probe runs, only the warning is withheld. Absence of all three would mean the probe was skipped entirely, which is not the same as a healthy host.

### `PERF-051` FD monitoring flag plumbing (two-name handoff)  <sub>linux, darwin</sub>

*supporting*

- **Must be true:** config.monitor_fd_usage reaches YaraScanner only via the startup probe: 'Initial file descriptors in use: N' is present if and only if FD sampling happens later in the same run, and with YARA_ENABLE_FD_MONITOR unset neither appears even on a multi-hour scan.
- **Threshold:** Default run (flag unset): 0 lines matching 'Current file descriptor limit:', 0 matching 'Initial file descriptors in use:', 0 matching 'FD usage increased by', 0 matching 'WARNING: High FD usage:'. Enabled run of comparable length: exactly 1 'Initial file descriptors in use:' and >=1 FD sample line.
- **Setup:** Pair the default Round 1 run with the YARA_ENABLE_FD_MONITOR=true pre-opened-descriptor run from PERF-049. No scan_summary field or init_data key echoes monitor_fd_usage or initial_fd_count, so these exact lines are the whole record of the handoff.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log on both runs — presence/absence of 'Initial file descriptors in use: ' (set at the same place config.monitor_fd_usage is set to True) and of the later sample lines.
- **Negative control:** The enabled run must produce sample lines; otherwise 'the flag never arrived at YaraScanner' is indistinguishable from 'monitoring arrived and was simply quiet'.

### `PERF-075` DEAD CODE: _get_scanner_stats aggregate

*low*

- **Must be true:** The aggregate never runs: no artefact this run produces carries the two keys that are unique to its return value.
- **Threshold:** Zero occurrences of 'performance_snapshots' and zero of 'resource_alerts' across all seven files in <scanner_dir>/logs/ and in scan_summary_<run_id>.json — on a run where the resource monitor IS enabled, so the internal branch that would add 'resource_alerts' is satisfiable.
- **Setup:** The monitored Round 1 run (YARA_ENABLE_RESOURCE_MONITOR=true). With the monitor off, the absence of 'resource_alerts' would be explained by the internal gate rather than by the function having no caller.
- **Evidence:** `grep -c 'performance_snapshots\|resource_alerts' <scanner_dir>/logs/*` == 0, and the same grep over logs/scan_summary_<run_id>.json.
- **Negative control:** On the same run the LIVE aggregates must be present — resource_summary inside the 'COMPREHENSIVE SCAN REPORT' record and the 'Resource monitoring completed: ' record in performance_<run_id>.log — so a zero grep proves this function is dead rather than that reporting failed wholesale.
- **Why this round:** Marked unobservable, but decidable by negative assertion on two distinctive key names. Round 1's monitored run is the configuration in which the function, if it were called, would have the most to say.

### `PERF-076` DEAD CODE: periodic scan-status upload

*low*

- **Must be true:** No periodic scan-status POST is ever attempted, and live progress telemetry reaches the tenant only through the scans-dataset heartbeat rows.
- **Threshold:** Zero lines matching 'Scan status uploaded successfully' and zero matching 'Scan status upload failed: HTTP' in diagnostics_<run_id>.log, on a run longer than 20 minutes (status_upload_interval is 60s, so a live path would have had ~20 chances). On the same run, at least 2 rows with status 'running' in yara_scanner_scans_v3_* (SCANS_HEARTBEAT_SECS 600).
- **Setup:** Round 1 long scan (>20 min) at defaults. UPLOAD_NON_MATCH_DATA is False and upload_scan_status has no call site, so both gates would have to fail for a POST to occur.
- **Evidence:** <scanner_dir>/logs/diagnostics_<run_id>.log — the root-logger sink where those two logging.info/warning lines would land; XQL `dataset = yara_scanner_scans_v3_* | filter scan_id = "<scan_id>" and status = "running"`.
- **Negative control:** The 'Scan status changed to: ' lines MUST be present in the same diagnostics file — set_status runs on every transition, so their presence proves the sink is working and the missing upload lines are the dead path, not a lost log file.
- **Why this round:** Marked unobservable, but decidable as a two-sided negative/positive: the dead POST leaves nothing, while the live replacement (heartbeat rows) must be there. Only a long Round 1 run gives the heartbeat time to fire.

### `PERF-079` End-of-run performance summary lines

*core*

- **Must be true:** A successful run emits exactly one SCAN COMPLETED statistics record and no SCAN FAILED error record, plus the worker-performance summary, and the returned action result line's headline numbers agree with scan_summary.
- **Threshold:** Exactly 1 line beginning 'SCAN COMPLETED | Time: ' in statistics_<run_id>.log and 0 beginning 'SCAN FAILED | Time: ' in scan_errors_<run_id>.log; its Files and Detections values equal scan_summary files_scanned/files_skipped/matches; its printed Rate equals data.average_scan_rate in that same record's payload to +/-0.01 (both are files_scanned/total_time measured inside scan_system, BEFORE the uploader drains). Separately, scan_summary.scan_rate_fps == round(files_scanned/duration_secs, 2) using run()'s wall clock — the two rates are legitimately different numbers and must not be equated. The result line's 'cpu-slept Ns' equals round(total_paused_secs) and its posture segment equals scan_summary.posture exactly.
- **Setup:** Standard Round 1 run; capture the SCAN_RESULT line from the Action Center action result (Action Center truncates stdout at 10,240 chars, so read the result line itself, not a dumped log).
- **Evidence:** 'SCAN COMPLETED | Time: ' in <scanner_dir>/logs/statistics_<run_id>.log; 'Worker performance summary: N workers processed files' in logs/performance_<run_id>.log; the returned 'Scan completed: … | cpu-slept …s | alerts=… dataset=… files=… cpu=… mode=scan' line; logs/scan_summary_<run_id>.json.
- **Negative control:** 'Worker performance summary: 0 workers processed files' on a run that scanned files is a failure, not a pass — the record's mere presence does not prove the per-worker timing accounting ran.

### `PERF-080` Both psutil monitors are OFF by default — every performance figure in the final report is structurally zero

*core*

- **Must be true:** On a default run neither psutil monitor starts, and every figure sourced from them is zero or absent — while the heartbeat-sourced figures (cpu_percent, memory_mb, network_mb in Scan Progress) are still populated.
- **Threshold:** Default run: init_data performance_monitoring_enabled == false and resource_monitoring_enabled == false; the 'All monitoring systems activated' data shows performance_monitoring false and resource_monitoring false; 'Performance monitoring disabled in light profile' present and 'Performance monitoring thread started' absent; 'System resource monitoring started' absent; 0 lines matching 'Performance Snapshot | '; the COMPREHENSIVE STATISTICS SUMMARY Performance Metrics block shows samples_collected 0 with peak/avg cpu and memory 0.0; the 'COMPREHENSIVE SCAN REPORT' data has NO resource_summary key. Simultaneously data.metrics.memory_mb > 0 in Scan Progress records.
- **Setup:** None — the default Round 1 run reaches it. Pair with the YARA_ENABLE_PERF_MONITOR=true / YARA_ENABLE_RESOURCE_MONITOR=true run used for PERF-046/047/048 as the control.
- **Evidence:** logs/system_<run_id>.log ('YARA Scanner initialization completed' init_data; 'All monitoring systems activated'); logs/statistics_<run_id>.log ('Performance monitoring disabled in light profile'; 'COMPREHENSIVE STATISTICS SUMMARY'; 'COMPREHENSIVE SCAN REPORT'); logs/performance_<run_id>.log (absence of 'Performance Snapshot | ').
- **Negative control:** The enabled control run must flip every one of those — 'Performance monitoring thread started' and 'System resource monitoring started' present, samples_collected > 0, resource_summary present. Without it, 'off by default' and 'monitors broken' leave identical evidence.

### `PERF-081` Per-file permission denials accumulate in an unbounded list that nothing ever reads

*supporting*

- **Must be true:** Process RSS grows with the number of unreadable files encountered and never plateaus, and no artefact ever reports the accumulated list.
- **Threshold:** On a planted tree of 200,000 unreadable files: memory_mb NET rise from the first 'Scan Progress' record after the first 'Permission denied: ' line to the last such record before the denials stop must be >= 50 MB (200,000 five-key dicts plus their path and mode strings is roughly 60-80 MB on CPython 3.11+), with no sustained plateau in the last third — the trace need not be point-wise monotonic, since RSS legitimately dips with allocator trimming. The root-privileged control run over the same tree must stay within 15 MB peak-to-trough. Zero occurrences of 'permission_denials' anywhere in <scanner_dir>/logs/ or scan_summary_<run_id>.json (contrast _seen_findings, capped at 150,000, and worker_processing_times, which is trimmed).
- **Setup:** Plant a directory of 200,000 zero-length files owned by root with mode 000 inside the Round 1 target on the Linux endpoint; run once as a non-root user (denials accumulate) and once as root (control).
- **Evidence:** data.metrics.memory_mb across 'Scan Progress | Files:' records in <scanner_dir>/logs/statistics_<run_id>.log for both runs, aligned to the cumulative count of 'Permission denied: ' lines in logs/system_<run_id>.log; `grep -c permission_denials <scanner_dir>/logs/*`.
- **Negative control:** The root control run must scan the same 200,000 files with zero 'Permission denied: ' lines and flat memory_mb — otherwise the RSS rise could be attributed to file count or queue depth rather than to the denial list.

### `PERF-082` Unthrottled 'Permission denied' system-log line — one record per unreadable file

*supporting*

- **Must be true:** Exactly one system-log record is written per unreadable file, with no throttling, sampling or dedup, and the count reconciles exactly with the skip breakdown.
- **Threshold:** Count of lines matching 'Permission denied: ' in system_<run_id>.log == data.skip_breakdown['No read permission'] in the 'Skip reasons: ' record == 200,000 for the planted tree; each such line carries ' | data={"file_mode":' and '"requires_root":'; zero 'further similar messages suppressed' lines exist for this text. Note the separate skip key 'Permission denied' (from the PermissionError handler) has no colon-space form, so the grep does not collide with it.
- **Setup:** Same planted 200,000-file unreadable tree, non-root Round 1 run.
- **Evidence:** Line count and data= payloads in <scanner_dir>/logs/system_<run_id>.log; data.skip_breakdown in the 'Skip reasons: ' record in logs/statistics_<run_id>.log; files_skipped in logs/scan_summary_<run_id>.json; file size of system_<run_id>.log versus the root control run.
- **Negative control:** On the same run the other high-volume skip paths must produce NO per-file line at all — 'Skipped directory' and 'Special system file' each increment their skip counter silently. That shows the per-file record here is specific to this branch rather than a generic per-skip log, and that its absence of throttling is the property under test.

### `PERF-083` Mislabelled resource-monitor telemetry: monitoring_duration_minutes is host uptime

*low*

- **Must be true:** monitoring_duration_minutes tracks host uptime rather than scan or monitor duration, and disagrees with its sibling monitoring_duration_seconds by roughly the host's uptime.
- **Threshold:** Capture the host boot EPOCH once (`awk '/btime/{print $2}' /proc/stat`, or `date -d "$(uptime -s)" +%s`), which does not drift. Then for EVERY 'System resources - CPU: ' record: |monitoring_duration_minutes*60 - (record_timestamp_epoch - boot_epoch)| <= 60. On the same run monitoring_duration_minutes*60 must exceed duration_secs in scan_summary by roughly the pre-scan uptime, and monitoring_duration_seconds in the end-of-run 'Resource monitoring completed:' record must equal data_points_collected * 10 (monitoring_interval literal 10) — that sibling is the correctly scoped figure. system_boot_time, monitoring_interval and the 3600s alert window are bare literals, not configurable.
- **Setup:** Monitored Round 1 run with YARA_ENABLE_RESOURCE_MONITOR=true on a host whose uptime greatly exceeds the scan; capture `cat /proc/uptime` over SSH at scan start. On a default run this payload does not exist at all.
- **Evidence:** data.monitoring_duration_minutes on the 'System resources - CPU: ' records in <scanner_dir>/logs/performance_<run_id>.log; data.monitoring_duration_seconds in the 'Resource monitoring completed: ' record in the same file; duration_secs in logs/scan_summary_<run_id>.json; /proc/uptime on the endpoint.
- **Negative control:** On the same run the sibling monitoring_duration_seconds must track the MONITOR (== data_points_collected * 10, far smaller than uptime) while monitoring_duration_minutes tracks the HOST. If both tracked the same clock the mislabelling claim would be unsupported; if neither did, the payload would simply be broken rather than mislabelled.

### `PERF-084` Per-tick 'Network: X MB' is the whole host's traffic since boot, not the scanner's uploads

*low*

- **Must be true:** The network figure in the progress heartbeat is a host-wide cumulative counter, not this scan's uploads — the FIRST tick already reports a large value matching host totals rather than starting near zero.
- **Threshold:** The first 'System Resources | … | Network: X MB' line has X within 5% of (bytes_sent + bytes_recv)/1048576 read from /proc/net/dev at the same moment, and X is orders of magnitude larger than this scan's own upload volume; the identical value appears as data.metrics.network_mb in the matching 'Scan Progress' record. Cadence is YARA_PROGRESS_LOG_SECS, default 30, clamped to >= 1.
- **Setup:** Standard Round 1 run; sample `cat /proc/net/dev` over SSH at the moment of the first heartbeat.
- **Evidence:** 'System Resources | CPU:' records in <scanner_dir>/logs/performance_<run_id>.log; data.metrics.network_mb in 'Scan Progress | Files:' records in logs/statistics_<run_id>.log; /proc/net/dev on the endpoint.
- **Negative control:** On the monitored run, SystemResourceMonitor's own 'System resources - CPU: ' records carry a network payload that starts near 0 and grows with the scan (it captures a baseline and reports deltas). Both figures reading the same way — both large or both near zero — would mean one of the two derivations changed.

### `PERF-086` Governor final state persisted as a structured cpu_governor block in the run summary

*core*

- **Must be true:** The cpu_governor block is always written to the run summary, and the same slept total is reported identically in all four places that report it.
- **Threshold:** cpu_governor.slept_secs == total_paused_secs in the same file exactly; == total_paused_secs on the terminal yara_scanner_scans_v3_* row for this scan_id; == the integer in the result line's 'cpu-slept Ns' after rounding. The block carries policy, target, own, others, ratio, slept_secs, floor_hits, samples_taken and secs_since_last_sample. floor_hits > 0 (a cumulative counter) is the positive test for floor entry. For pacing, take the positive evidence from the CPU_GOVERNOR records in performance_<run_id>.log: max(ratio) across those records > 0 together with slept_secs > 0. Do NOT require cpu_governor.ratio > 0 in the summary — it is the LAST sample and decays to 0.0 within ~10 samples of the competing load stopping, unless `stress-ng` is run through to the end of the scan.
- **Setup:** Round 1 run under competing CPU load (`stress-ng --cpu 7` for the middle of the run on the 8-core Linux endpoint) so ratio and slept_secs are non-zero and floor entry is actually attempted.
- **Evidence:** The cpu_governor object and the sibling total_paused_secs in <scanner_dir>/logs/scan_summary_<run_id>.json (written atomically via os.replace); total_paused_secs on the yara_scanner_scans_v3_* row; the 'cpu-slept' segment of the returned result line; the 'CPU_GOVERNOR ' records in logs/performance_<run_id>.log.
- **Negative control:** A control run with YARA_CPU_GUARANTEE=none must still WRITE the block — policy 'none', slept_secs 0.0, floor_hits 0, samples_taken 0, target null — with a result line reading 'cpu-slept 0s'. The block is null only when scanner.cpu_governor is missing entirely, so 'governor disabled' and 'governor object absent' must not look the same.

### `PERF-087` Per-worker throughput reports are time-gated, not file-count-gated

*supporting*

- **Must be true:** The number of 'Worker Performance |' lines per worker tracks scan DURATION rather than file count: two scans of equal wall time emit the same number per worker even when one processes far more files, and setting the gate to 0 restores the files/100 behaviour.
- **Threshold:** YARA_WORKER_REPORT_SECS default 30 (0 disables the gate). Per-worker line count == floor(worker_active_secs/30) +/- 1, valid only while that worker processes at least 100 SCANNED files per 30s window (the 100-file trigger remains the sampling point and files_processed excludes skips). The two equal-duration runs must BOTH satisfy that proviso while differing ~50x in total files — e.g. many tiny files versus the same file count against a 500-rule pack — otherwise the slower run legitimately emits fewer lines. With YARA_WORKER_REPORT_SECS=0: per-worker line count == floor(that worker's data.files_processed / 100) from the last line's payload.
- **Setup:** Three Round 1 runs of roughly equal duration — (a) many small files, (b) far fewer, slower files, (c) run (a) repeated with YARA_WORKER_REPORT_SECS=0 exported over SSH.
- **Evidence:** Count of 'Worker Performance | ' lines per worker_id in <scanner_dir>/logs/performance_<run_id>.log; data.files_processed on the last such line per worker; duration_secs in logs/scan_summary_<run_id>.json.
- **Negative control:** A short scan (< 30s wall time) in which each worker still processes at least 100 files must emit EXACTLY ONE 'Worker Performance |' line per worker — _worker_report_due returns True when last_report is 0, so the first sample always lands. Zero lines there would mean the gate swallows everything; more than one would mean the gate is not applied. A short scan of fewer than 100 files per worker proves nothing either way and must not be used.

### `PERF-088` Governor sampling-cadence counters (`samples_taken`, `secs_since_last_sample`)

*supporting*

- **Must be true:** samples_taken counts readings CONSUMED by the governor and diverges sharply from the number of emitted governor log lines, and secs_since_last_sample stays near the sampling interval — so a stalled sampler is distinguishable from a quiet one.
- **Threshold:** On a scan longer than 300s under the default governor: cpu_governor.samples_taken > 10x the count of lines beginning 'CPU_GOVERNOR ' in performance_<run_id>.log (1.0s sampling via YARA_GOVERNOR_INTERVAL_SECS versus 30s GOVERNOR_HEARTBEAT_SECS emission), and cpu_governor.secs_since_last_sample <= 3.0. For the absolute cadence, anchor on an interval the sampler actually spans rather than duration_secs: samples_taken must be within 20% of (timestamp of 'Worker cleanup: ' minus timestamp of '=== ACTIVE SCANNING PHASE STARTED ===') / 1.0s — compile time, target resolution and the uploader drains are inside duration_secs but take no governor samples.
- **Setup:** Standard Round 1 long scan on a largely idle host — a steady ratio is precisely the case where emission falls back to the 30s GOVERNOR_HEARTBEAT_SECS heartbeat and the divergence between sampling and emission is largest.
- **Evidence:** cpu_governor.samples_taken and cpu_governor.secs_since_last_sample in <scanner_dir>/logs/scan_summary_<run_id>.json; count of lines beginning 'CPU_GOVERNOR ' in logs/performance_<run_id>.log (emitted on a >=0.25 ratio change or the 30s heartbeat, not per sample).
- **Negative control:** On the YARA_CPU_GUARANTEE=none control run, samples_taken must be 0 and secs_since_last_sample null with zero 'CPU_GOVERNOR ' lines — a disabled governor counts nothing, so a non-zero samples_taken there would mean the counter is being incremented outside update().

## Local Storage & Host Footprint

### `STOR-001` Scanner working directory root (scanner_dir) and its platform defaults

*supporting*

- **Must be true:** With YARA_SCANNER_DIR set, EVERY artefact of the run is created under that root and none under the platform default; with it unset the root is exactly the platform literal for the endpoint's OS.
- **Threshold:** Run A (no override, Linux endpoint): /opt/yara_scanner/logs/scan_summary_<run_id_A>.json exists. Run B (YARA_SCANNER_DIR=/opt/yara_lab): /opt/yara_lab/logs/scan_summary_<run_id_B>.json exists, /opt/yara_lab holds logs+control+alert+evidence+failed_rules+rule_cache, and `ls /opt/yara_scanner -R | grep <run_id_B>` returns ZERO hits. Platform literals: C:\yara_scanner (Windows) | /usr/local/yara_scanner (Darwin) | /opt/yara_scanner (everything else).
- **Setup:** Two Round-1 runs on the Linux endpoint. Run B's snippet prelude does os.environ["YARA_SCANNER_DIR"]="/opt/yara_lab". This env var IS late-bound (read inside _default_scanner_dir on every call), unlike the module-level YARA_* constants, which are already evaluated by the time the snippet footer executes.
- **Evidence:** `ls -la /opt/yara_lab` and `ls -R /opt/yara_scanner | grep <run_id_B>` over SSH; logs/scan_summary_<run_id_B>.json under the overridden root.
- **Negative control:** Run A, with no override, must still land in /opt/yara_scanner — the override must not persist into a later run on the same host.

### `STOR-002` Fixed subdirectory layout under scanner_dir (logs, control, alert, evidence, failed_rules — plus rule_cache)

*supporting*

- **Must be true:** logs, control, alert, evidence and failed_rules exist under scanner_dir after a run that produced zero matches and zero failed rules; rule_cache is the only conditional one and is present whenever caching is enabled.
- **Threshold:** Zero-match Round-1 run: `ls -1 /opt/yara_scanner` lists exactly logs, control, alert, evidence, failed_rules, rule_cache (plus cleanup_script.sh only if a PRIOR run left one — this run's gate skips generation). alert/ holds 0 entries and failed_rules/ holds 0 entries; evidence/ holds exactly 2 entries — file_mapping.txt and evidence_<hostname>_<run_id>.zip — both of which are written unconditionally on every completed run and are therefore NOT evidence of a match. rule_cache/ holds >=1 rules_*.yarac. Control run with RULE_CACHE_ENABLED rebound False against a fresh scanner_dir: logs, control, alert, evidence and failed_rules all exist, rule_cache is absent (it is created only inside _rule_cache_dir(), which is reached only under the RULE_CACHE_ENABLED gate).
- **Setup:** The zero-match Round-1 run. For the control half, the prelude must REBIND the module global (RULE_CACHE_ENABLED = False) — setting os.environ["YARA_RULE_CACHE"] has no effect, it is read at import before the footer runs — and point YARA_SCANNER_DIR at a root that has never cached.
- **Evidence:** `ls -1 /opt/yara_scanner`; `ls /opt/yara_scanner/rule_cache`; `ls -1 /opt/yara_lab` for the cache-disabled control.
- **Negative control:** alert/, evidence/ and failed_rules/ must be present-and-empty on the zero-match run, never absent — creation must not depend on a match or a failed rule.

### `STOR-003` run_id — microsecond timestamp that names every per-run file

*supporting*

- **Must be true:** Exactly one run_id token, matching ^\d{8}_\d{6}_\d{6}$, names every per-run artefact, and the same token is what the summary, the scan_id, the evidence ZIP name and the tenant-side rows carry.
- **Threshold:** Take the set difference of `ls -1 /opt/yara_scanner/logs` before and after the run. EVERY new entry matches ^(alerts|statistics|scan_errors|performance|uploads|system|yara_processing|diagnostics)_T\.log$ or ^scan_summary_T\.json$ for ONE token T, and T matches ^\d{8}_\d{6}_\d{6}$ (8 new .log files + 1 .json on a clean run). scan_summary.run_id == T; scan_summary.scan_id == "<hostname>_" + T + "_yara_" + exactly 12 lowercase hex; the new file in evidence/ is named evidence_<hostname>_T.zip. XQL over the decoy's rows: every row for that scan_id has run_id == T and scan_date == T[:8] (dedup returns exactly one pair), and the row count is >= 1 — a zero-row result is a FAIL, not a pass.
- **Setup:** The Round-1 run with the SINGLE planted decoy, not the zero-match run — the zero-match run emits no matches rows at all, which makes the XQL half of this criterion unfalsifiable. Snapshot `ls -1 /opt/yara_scanner/logs` and `ls -1 /opt/yara_scanner/evidence` immediately before delivering the scan so the run's own artefacts can be identified by set difference rather than by assumption.
- **Evidence:** `ls /opt/yara_scanner/logs`; run_id/scan_id/hostname in logs/scan_summary_<run_id>.json; `ls /opt/yara_scanner/evidence`; XQL: dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" | fields run_id, scan_date | dedup run_id, scan_date
- **Negative control:** A prior run's files in the same logs/ directory must keep their OWN run_id — the token must not be rewritten across runs.

### `STOR-004` Six per-category structured log files (alerts / statistics / errors / performance / uploads / system)

*supporting*

- **Must be true:** All six category files exist after any run — including one with zero alerts and zero errors — the system log opens with the LogManager banner and closes with the logging summary, and the per-category counts in that summary equal the records actually on disk.
- **Threshold:** 6 files present (alerts_, statistics_, scan_errors_, performance_, uploads_, system_<run_id>.log). First record of system_<run_id>.log contains 'Enhanced Log Manager initialized with standardized logging'; its last record contains 'Logging Summary | Total Logs: N' whose data.logs_by_type has exactly the six keys alert/statistics/error/performance/upload/system and sums to data.total_logs_generated == N. Count RECORDS as lines matching ^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[ (a message with an embedded newline is still one record). Then: records(alerts_) == logs_by_type['alert']; records(scan_errors_) == logs_by_type['error']; records(uploads_) == logs_by_type['upload']; records(system_) == logs_by_type['system'] + 1. For statistics_ and performance_ the counter is BYPASSED by StatisticsManager, which holds LogManager's own loggers and writes through them without going through _log, so assert instead: records(statistics_) - S == logs_by_type['statistics'] and records(performance_) - P == logs_by_type['performance'], where S is the count of records matching '=== Statistics Manager Initialized ===', '=== Statistics Manager Stopped ===', 'Performance monitoring thread started', 'Performance monitoring disabled in light profile', 'COMPREHENSIVE STATISTICS SUMMARY', 'Performance Metrics: ', 'Time Estimates: ', 'Worker Summary: ' and the bare '===...===' separator records around them, and P is the count matching '=== Performance Monitoring Started ===', '=== Performance Monitoring Ended ===', 'Performance monitoring worker started', 'Performance monitoring worker stopped' and 'Performance Snapshot | CPU: '. S and P must both be > 0 — a build in which they are zero has silently rerouted StatisticsManager and is itself a regression.
- **Setup:** The zero-match Round-1 run, so the 'created even when nothing happened' half is actually tested.
- **Evidence:** The six files under /opt/yara_scanner/logs; the first and last records of system_<run_id>.log and the JSON data blob on the 'Logging Summary | Total Logs:' line.
- **Negative control:** scan_errors_<run_id>.log must be PRESENT (possibly zero-byte) on a clean run, never absent — every handler is opened eagerly with mode="w".

### `STOR-008` Orphaned scan_summary *.tmp sweep at scan start

*low*

- **Must be true:** A pre-existing scan_summary_*.tmp under logs/ is deleted by the next scan's startup sweep, while a .tmp that does not carry that prefix is left untouched.
- **Threshold:** Planted logs/scan_summary_20200101_000000_000000.json.tmp does not exist after the next run; planted logs/keepme.tmp still exists with its original mtime.
- **Setup:** Before the run: `touch /opt/yara_scanner/logs/scan_summary_20200101_000000_000000.json.tmp /opt/yara_scanner/logs/keepme.tmp`.
- **Evidence:** `ls -la /opt/yara_scanner/logs/*.tmp` before and after the run. No log line records the sweep — the method emits nothing here, and it runs before setup_logging installs the diagnostics handler — so disk state is the only evidence.
- **Negative control:** keepme.tmp — a .tmp not starting with scan_summary_ — must survive with an unchanged mtime; the sweep must be prefix-scoped, not a blanket *.tmp wipe.

### `STOR-009` Log retention — keep only the last N scans' logs and summaries

*supporting*

- **Must be true:** After the scan, logs/ holds artefacts for exactly LOG_KEEP_SCANS distinct run_ids with the current run counted INSIDE that budget (not on top of it), and older runs lose their .json summaries on the same pass as their .log files.
- **Threshold:** LOG_KEEP_SCANS default 10. With logs/ cleared, 15 synthetic groups planted, plus the current run: distinct run_ids matching _(\d{8}_\d{6}_\d{6})\.(?:log|json)$ in logs/ after the run == 10 exactly (NOT 11 — keep_run_ids is the newest 10 keys and the current run is itself the newest key, so keep_run_ids.add(run_id) is a no-op here); the surviving set is exactly {current run_id, 20250115..20250107}; the 6 oldest planted groups (20250101..20250106) are gone, both their .log and their .json files.
- **Setup:** Immediately before delivering the scan, clear every existing run_id group out of logs/ over SSH (`rm -f /opt/yara_scanner/logs/*_[0-9]*_[0-9]*_[0-9]*.log /opt/yara_scanner/logs/*_[0-9]*_[0-9]*_[0-9]*.json`) so the ONLY groups present are the ones this criterion plants — otherwise real groups from the rest of the Round-1 series occupy the keep window and every planted group is pruned. Then plant 15 groups: for d in 01..15 -> touch logs/system_202501${d}_000000_000000.log and logs/scan_summary_202501${d}_000000_000000.json. To vary the count, the prelude must REBIND the module global LOG_KEEP_SCANS; os.environ["YARA_LOG_KEEP"] is read at import, before the snippet footer runs, and has no effect.
- **Evidence:** run_ids parsed out of `ls /opt/yara_scanner/logs` before and after. The 'Log retention applied: kept last N scans' line is a bare logging.info emitted BEFORE setup_logging installs the diagnostics handler, so it reaches no file on this edition — verify on disk only, never in diagnostics_<run_id>.log.
- **Negative control:** Files in logs/ that do not end .log/.json, and files whose name carries no parseable run_id, must be untouched by the prune.

### `STOR-010` Current run is force-protected from retention

*supporting*

- **Must be true:** The current run's own log set is never a retention casualty even when the keep window is entirely occupied by OTHER run_ids: with LOG_KEEP_SCANS floored to 1 and newer-sorting run_id groups planted, the current run's eight .log files plus its scan_summary survive alongside exactly the one planted group the sort retained — and they survive only because of the explicit current-run guard, not because of the sort.
- **Threshold:** With LOG_KEEP_SCANS rebound to 0 (keep_count = max(1,0) = 1) and 3 future-dated groups planted: distinct run_ids in logs/ after the run == 2 — the newest planted group 20991231_235959_000003 (retained by the sort) and the current run_id (retained ONLY by keep_run_ids.add(self.config.run_id)); the other two future groups are gone. All eight of the current run's files — alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_ and diagnostics_<run_id>.log — plus scan_summary_<run_id>.json are present. The catalogue's Observe ('the current run's seven files survive alongside exactly one prior run's set') is WRONG on the file count and on 'prior' and must not be used as the bar.
- **Setup:** Round-1 short run with the prelude rebinding the module global LOG_KEEP_SCANS = 0 (exercising the max(1, keep) floor). Clear logs/ of pre-existing run_id groups, then plant 3 groups whose run_ids sort NEWER than the current run — e.g. 20991231_235959_000001/2/3, each as system_<rid>.log + scan_summary_<rid>.json. Future-dating is what makes the test discriminating: with past-dated plants the current run is the newest key and the sort alone retains it, so the criterion passes even against a build with the guard deleted.
- **Evidence:** `ls /opt/yara_scanner/logs` after the run, grouped by run_id.
- **Negative control:** None of the current run's files may be missing. Seven of the eight (the six category logs plus yara_processing) already exist on disk when the prune runs — LogManager is constructed at run() before cleanup_manager.initial_cleanup(), and ErrorLogger inside ScanConfig before that — so they are genuine deletion candidates that the guard is what spares. Conversely, the two non-newest planted future groups MUST be deleted: if all three survive, the prune did not run at all and the criterion has proved nothing.

### `STOR-011` Log-file deletion failures are tolerated, not fatal

*low*

- **Must be true:** A log entry the prune cannot delete neither aborts the retention pass nor fails the scan: the undeletable entry survives, its deletable sibling from the same old run is still removed, and the run completes normally.
- **Threshold:** After the run: logs/system_20250101_000000_000000.log (planted as a DIRECTORY, so os.remove raises IsADirectoryError, an OSError) still exists; logs/alerts_20250101_000000_000000.log (planted as a regular file with the same run_id) is gone; logs/scan_summary_<run_id>.json exists with outcome == 'completed'.
- **Setup:** Before the run, over SSH: clear logs/ of pre-existing run_id groups, then plant exactly 10 groups NEWER than 20250101 but older than the current run (e.g. touch logs/system_202506{01..10}_000000_000000.log), so that with LOG_KEEP_SCANS at its default 10 the keep window is {current run, 20250610..20250602} and the 20250101 group is unambiguously outside it. Then plant the failure pair: `mkdir /opt/yara_scanner/logs/system_20250101_000000_000000.log` and `touch /opt/yara_scanner/logs/alerts_20250101_000000_000000.log`. Confirm from disk that at least one 202506xx group was also removed — if nothing was pruned, the code path under test never ran and the result is void, not a pass.
- **Evidence:** `ls -la /opt/yara_scanner/logs` after the run; outcome in logs/scan_summary_<run_id>.json. The 'Cannot remove log file (in use):' / 'Log retention: N log files could not be removed' warnings are NOT usable evidence — they are bare logging.warning calls made before setup_logging runs, so they reach stderr only and appear in none of the seven log files.
- **Negative control:** The deletable sibling must still be removed — the failure must stay contained to the one path and must not abort the enclosing retention loop.

### `STOR-014` Progress-heartbeat writes to statistics AND performance logs on a fixed cadence for the whole scan

*supporting*

- **Must be true:** The progress heartbeat runs for the WHOLE scan (not just discovery) on a fixed cadence, and every tick writes one Scan Progress record to statistics and one System Resources record to performance.
- **Threshold:** config.log_interval default 30s (YARA_PROGRESS_LOG_SECS, read inside ScanConfig.__init__ so os.environ in the prelude does work here). For a Round-1 scan whose active phase lasts D seconds: count('Scan Progress | Files: ') in statistics_<run_id>.log >= floor(D/30) - 2; no gap between consecutive Scan Progress timestamps exceeds 45s; count('System Resources | CPU: ') in performance_<run_id>.log + count('Error collecting system metrics') in scan_errors_<run_id>.log == count('Scan Progress | Files: ') exactly; the last Scan Progress record's files_scanned strictly exceeds the first's.
- **Setup:** The long Round-1 scan; no extra setup — the heartbeat thread starts with the scan and is stopped in _perform_enhanced_cleanup.
- **Evidence:** statistics_<run_id>.log 'Scan Progress | Files: N scanned, M skipped | Detections: D | Queue: Q | Rate: R files/sec'; performance_<run_id>.log 'System Resources | CPU: x% | Memory: yMB | Disk I/O: zMB | Network: wMB'; scan_errors_<run_id>.log for the metrics-failure escape hatch.
- **Negative control:** Fewer System Resources records than Scan Progress records WITHOUT a matching 'Error collecting system metrics' line is a fail — the pairing must hold on every tick, and zero Scan Progress records on a multi-minute scan is the regression this exists to catch.

### `STOR-015` config.output_log (scanner_<run_id>.log) — DEAD as a log file, but load-bearing as a path

*low*

- **Must be true:** No scanner_<run_id>.log is ever created on any platform: the path is only ever used as an initial-cleanup target and a self-exclusion probe, and nothing in the scanner writes it.
- **Threshold:** `ls /opt/yara_scanner/logs/scanner_*.log` returns nothing after every Round-1 run, and the count stays 0 across the whole retention series (12+ runs). The similarly-named scan_errors_<run_id>.log and system_<run_id>.log are DIFFERENT files and must both be present.
- **Evidence:** `ls /opt/yara_scanner/logs/scanner_*.log` (must be empty) contrasted with `ls /opt/yara_scanner/logs/*_<run_id>.log`, which must list exactly alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_ and diagnostics_.
- **Negative control:** The assertion must not sweep up the real logs: system_<run_id>.log and scan_errors_<run_id>.log must both still exist. A glob that matched them would make this criterion pass vacuously.

### `STOR-016` initial_cleanup wipes the previous run's alert/ and evidence/ directories wholesale

*supporting*

- **Must be true:** The second run deletes the first run's alert/ and evidence/ contents outright before scanning, so exactly one run's alert texts and exactly one evidence ZIP ever exist on the host.
- **Threshold:** After run 2: evidence/ holds exactly two entries — file_mapping.txt and evidence_<host>_<run_id_2>.zip — and run 1's ZIP path no longer exists (file_mapping.txt is rewritten every run, so its presence is not evidence of survival; the ZIP name carries the run_id and is the discriminator). alert/ holds no file named for a rule that only run 1's pack contained. system_<run_id_2>.log contains 'Initial cleanup completed'.
- **Setup:** Two consecutive Round-1 runs whose packs use DISJOINT rule names, both matching the single planted decoy, with no third run in between.
- **Evidence:** `ls -la /opt/yara_scanner/alert /opt/yara_scanner/evidence` after run 2; 'Initial cleanup completed' in system_<run_id_2>.log. The per-path 'Removed: <path>' and 'Initial cleanup completed successfully' lines inside the method are bare logging.info emitted before setup_logging installs the diagnostics handler and reach NO file — do not assert on them.
- **Negative control:** logs/ (within the retention window), failed_rules/ and rule_cache/ must all still hold run 1's content after run 2 — only alert_dir, evidence_dir and output_log are in paths_to_clean.

### `STOR-021` Evidence ZIP creation and naming

*core*

- **Must be true:** Every completed run produces exactly one evidence ZIP named evidence_<hostname>_<run_id>.zip, and it is produced even when the run matched nothing.
- **Threshold:** Zero-match Round-1 run: the file exists and `unzip -l` lists exactly one member, file_mapping.txt. One-decoy Round-1 run: exactly two members, file_mapping.txt and alerts/<rule>.txt. The name's hostname and run_id equal scan_summary.hostname and scan_summary.run_id. system_<run_id>.log contains 'Evidence collection completed successfully' and diagnostics_<run_id>.log contains 'Evidence collection completed. Zip file created at: /opt/yara_scanner/evidence/evidence_<hostname>_<run_id>.zip'.
- **Setup:** Both Round-1 runs (the zero-match one and the one with the single planted decoy).
- **Evidence:** `ls -l /opt/yara_scanner/evidence/`; `unzip -l` on the ZIP; the two quoted log lines. The ZIP is referenced nowhere in scan_summary_<run_id>.json, so disk is the only place to look.
- **Negative control:** 'Evidence collection completed successfully' only proves collect_evidence() returned — it must NOT be accepted in place of the file on disk. A run where that line is present but no ZIP exists is a fail.
- **Why this round:** Kept in Round 1 rather than Round 2 because the ZIP is written on EVERY completed run and the sharper test is the clean one — it proves creation does not depend on a match, which a flood cannot show.

### `STOR-024` Metadata-only evidence ZIP is the default (collect_files=false)

*supporting*

- **Must be true:** With the shipped default the ZIP is metadata-only: no file bytes are copied, the decision is logged with its value, and the posture string surfaced in the summary says so.
- **Threshold:** system_<run_id>.log contains 'Evidence: collect_files=false - packaging metadata only (no matched file copies)' with data {"collect_files": false}; `unzip -l` shows zero matched_files/ entries; scan_summary.posture contains the token 'files=off' (posture format: 'alerts=<on|off> dataset=<on|off> files=<on|off> cpu=<policy> mode=<mode>').
- **Setup:** Either default Round-1 run — no option change.
- **Evidence:** The quoted line in system_<run_id>.log; `unzip -l /opt/yara_scanner/evidence/evidence_<host>_<run_id>.zip`; the posture field in logs/scan_summary_<run_id>.json.
- **Negative control:** The Round-3 collect_files=true run must NOT emit that line and its posture must read 'files=on' — the message and the posture must track the actual gate rather than being emitted unconditionally.

### `STOR-025` Evidence ZIP bundles only alert/*.txt — .alert files are excluded by design

*low*

- **Must be true:** The ZIP's alerts/ members come from alert/*.txt only, and once the scheduled cleanup has renamed them the resulting .alert files have no counterpart in any archive.
- **Threshold:** One-decoy Round-1 run: `unzip -l` lists alerts/<rule>.txt and ZERO members ending in .alert. After the cleanup unit has run: /opt/yara_scanner/alert holds <rule>.alert and zero .txt files, while the ZIP written earlier still holds alerts/<rule>.txt with the same byte size.
- **Setup:** The Round-1 run with the single planted decoy. Evidence collection runs BEFORE cleanup scheduling, so the ZIP is always built while the files are still .txt. On Linux the unit is started synchronously at scheduling time — re-list alert/ immediately after run() returns; on Windows wait 120s for the schtasks fire.
- **Evidence:** `unzip -l /opt/yara_scanner/evidence/evidence_<host>_<run_id>.zip`; `ls /opt/yara_scanner/alert` at scan end and again after rotation.
- **Negative control:** The ZIP must not omit alert texts altogether — alerts/<rule>.txt must be present. Only the .alert extension is excluded, so an empty alerts/ prefix is a fail, not a pass.

### `STOR-028` Runtime-generated cleanup script (cleanup_script.sh / .bat) in scanner_dir root

*supporting*

- **Must be true:** When at least one alert .txt exists, a cleanup script is generated at the scanner_dir root whose cd target is THIS run's real alert directory, executable on POSIX, with no trace of the historical hardcoded paths.
- **Threshold:** /opt/yara_scanner/cleanup_script.sh exists with an mtime inside the run window; its content is exactly the SIX lines '#!/bin/bash', 'cd "/opt/yara_scanner/alert" || exit 0', 'for file in *.txt; do', '    [ -e "$file" ] || continue', '    mv "$file" "${file%.txt}.alert"', 'done' — six lines, LF-terminated; `stat -c %a` == 755; zero occurrences of the substring 'xdr-data'. On Windows: cleanup_script.bat contains, in order, '@echo off', 'cd /d "C:\yara_scanner\alert"', 'if errorlevel 1 exit /b 0', 'ren *.txt *.alert'. Do NOT assert CRLF: the file is written in text mode with newline=None, so the '\r\n' in the template is translated again and each line terminates 0d 0d 0a — assert that byte sequence (or assert the four command lines in order and ignore terminators). system_<run_id>.log contains 'Cleanup script decoded and ready for scheduling'.
- **Setup:** The Round-1 run with the single planted decoy, so alert/ holds exactly one .txt at scheduling time.
- **Evidence:** `cat /opt/yara_scanner/cleanup_script.sh`; `stat -c %a /opt/yara_scanner/cleanup_script.sh`; the quoted system-log line.
- **Negative control:** The zero-match Round-1 run must leave no cleanup_script.* with a fresh mtime — generation is gated on at least one alert .txt existing, and a script regenerated on a no-alert run would be the failure.

### `STOR-029` Alert rotation: .txt → .alert, executed by the scheduled task, not by the scan

*supporting*

- **Must be true:** Every alert/*.txt present at scheduling time becomes <same basename>.alert and no .txt remains — and the rename is performed by the scheduled unit, which is the only artefact proving the unit actually ran.
- **Threshold:** Establish K, the pre-rotation set, from the evidence ZIP, which is built at 7826-7828 BEFORE cleanup is scheduled at 7834-7838: `unzip -l evidence_<host>_<run_id>.zip` lists exactly K members under alerts/, all ending .txt, with their uncompressed sizes. After the unit has run: alert/ holds 0 files ending .txt and exactly K files ending .alert, with basenames and byte sizes matching the ZIP's alerts/ members one-for-one. Linux: `systemctl show -p Result yara-cleanup.service` == 'Result=success', and because `systemctl start` blocks on a Type=oneshot unit the rename is already complete when run() returns. Windows: the rename appears within 120s and `schtasks /query /tn CleanupScript /v /fo LIST` reports Last Result 0.
- **Setup:** The one-decoy Round-1 run. Plant the non-.txt control MID-SCAN, over SSH, after initial_cleanup has recreated alert/ and after the first alert .txt appears (`touch /opt/yara_scanner/alert/notes.md`) — a pre-run plant is wiped by initial_cleanup's rmtree of alert_dir and proves nothing. Do NOT start another scan afterwards; the next initial_cleanup wipes alert/ and destroys the evidence.
- **Evidence:** `unzip -l /opt/yara_scanner/evidence/evidence_<host>_<run_id>.zip` for the pre-rotation alerts/*.txt inventory and sizes; `ls -l /opt/yara_scanner/alert` after the invocation returns for the post-rotation state; `systemctl show -p Result yara-cleanup.service` (Linux) / `schtasks /query /tn CleanupScript /v /fo LIST` (Windows). No API surface exposes this — it is SSH/on-box only.
- **Negative control:** The mid-scan-planted alert/notes.md must survive the rotation untouched, since the generated script globs *.txt only. It must also be ABSENT from the ZIP's alerts/ members, because _create_evidence_zip filters on .txt (4741-4743) — a single plant therefore controls both the rotation glob and the archive filter.

### `STOR-030` Windows scheduled task 'CleanupScript' registered as SYSTEM  <sub>windows</sub>

*supporting*

- **Must be true:** On Windows a single one-shot task named CleanupScript is registered to run the generated .bat as SYSTEM about a minute after the scan, replacing any prior task of that name rather than duplicating or failing on it.
- **Threshold:** `schtasks /query /tn CleanupScript /v /fo LIST` shows TaskName \CleanupScript, Task To Run == C:\yara_scanner\cleanup_script.bat, Run As User == SYSTEM, Schedule Type == One Time Only, and a Start Time equal to the 'Cleanup script decoded and ready for scheduling' record's timestamp truncated to the minute PLUS exactly 60 seconds — i.e. between 1 and 60 seconds after that record, never 60 to 120, because the scheduler formats now+1min with '%H:%M' and drops the seconds. Cross-check against the 'Windows cleanup task scheduled for HH:MM' line in diagnostics_<run_id>.log: the queried Start Time must equal that HH:MM exactly. Exactly one task with that name exists; system_<run_id>.log contains 'Windows cleanup task scheduled successfully'.
- **Setup:** The one-decoy run on the Windows endpoint (xdragent2 over SSH as user `ayman`). Pre-create a dummy CleanupScript task before the run to prove the /f flag overwrites rather than errors.
- **Evidence:** `schtasks /query /tn CleanupScript /v /fo LIST` over SSH; the quoted system-log line; the scheduled time also appears as 'Windows cleanup task scheduled for HH:MM' in logs/diagnostics_<run_id>.log — that IS reachable on this edition, because cleanup scheduling runs after setup_logging installs the root INFO FileHandler (the catalogue's 'UNOBSERVABLE' note is stale).
- **Negative control:** A run with zero alerts on the same Windows host must leave the pre-existing task's Start Time unchanged — scheduling must be gated, not unconditional.

### `STOR-031` Linux (and any non-Windows/non-Darwin) systemd unit /etc/systemd/system/yara-cleanup.service — written, ENABLED, never removed  <sub>linux</sub>

*supporting*

- **Must be true:** On a systemd Linux host the unit file is written root-owned, enabled and started, and nothing in the scanner ever removes it — it outlives the run and every subsequent scan.
- **Threshold:** /etc/systemd/system/yara-cleanup.service exists, `stat -c %u` == 0, and contains 'Type=oneshot', 'ExecStart=/bin/bash /opt/yara_scanner/cleanup_script.sh', 'User=root', 'WantedBy=multi-user.target'; `systemctl is-enabled yara-cleanup.service` == 'enabled'; `systemctl show -p Result yara-cleanup.service` == 'Result=success'; the file still exists after the NEXT scan on the same host.
- **Setup:** The one-decoy Round-1 run on the Linux endpoint as root, followed by one more scan to prove non-removal.
- **Evidence:** `ls -l /etc/systemd/system/yara-cleanup.service`, `stat -c %u`, `systemctl is-enabled yara-cleanup.service`, `systemctl show -p Result yara-cleanup.service` over SSH.
- **Negative control:** 'Linux cleanup service scheduled successfully' in system_<run_id>.log must NOT be accepted as proof of anything — _schedule_linux_cleanup swallows FileNotFoundError, PermissionError and CalledProcessError, so the caller logs success even when no unit was created. The on-disk file and is-enabled state are the only evidence.

### `STOR-033` Cleanup scheduling is gated on at least one alert .txt existing

*supporting*

- **Must be true:** A run that produced no alert .txt schedules nothing: no cleanup script is generated and no task/unit/daemon is created or re-triggered.
- **Threshold:** Zero-match Round-1 run: system_<run_id>.log contains 'No alerts found, skipping cleanup scheduling'; no cleanup_script.sh/.bat carries an mtime inside the run window; `systemctl show -p ExecMainStartTimestamp yara-cleanup.service` is byte-identical before and after the run (or the unit is absent on a host that has never scanned with a match); alert/ is empty.
- **Setup:** The Round-1 run whose pack matches nothing at all — the same short run used to plant and verify retention.
- **Evidence:** The quoted line in system_<run_id>.log; `stat -c %Y /opt/yara_scanner/cleanup_script.sh` before and after; `systemctl show -p ExecMainStartTimestamp yara-cleanup.service` before and after.
- **Negative control:** The one-decoy Round-1 run in the same round MUST schedule. Note that run() logs 'Cleanup task/service scheduled successfully' on BOTH runs — the caller emits it whenever schedule_final_cleanup returns without raising, including when the gate skipped everything — so that line can never be used as the discriminator; only the script mtime and the unit timestamp can.

### `STOR-036` control/running.json — atomically-refreshed liveness marker

*supporting*

- **Must be true:** control/running.json exists for the whole scan, is refreshed atomically with live counters and this process's PID, and is removed when the scan ends — including on a normal completion, not just a cancel.
- **Threshold:** Mid-scan the file parses and carries exactly the keys scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections; pid equals the live scanner PID from `ps`; run_id equals the current run's; status == 'running'. Across two samples taken more than SCANS_HEARTBEAT_SECS apart, updated_at strictly increases and files_scanned is non-decreasing. After run() returns, /opt/yara_scanner/control/running.json does not exist. Zero running.json.tmp observed at any 1 Hz poll.
- **Setup:** The long Round-1 scan, with the prelude REBINDING the module global SCANS_HEARTBEAT_SECS = 60 so a refresh is observable inside the run (os.environ["YARA_HEARTBEAT_SECS"] is read at import, before the snippet footer runs, and has no effect). Poll over SSH at 1 Hz.
- **Evidence:** Successive `cat /opt/yara_scanner/control/running.json` samples; `ps -o pid=,args= -p <pid>`; `ls /opt/yara_scanner/control/` after the run; the 1 Hz `ls control/running.json.tmp` poll.
- **Negative control:** The marker must be gone after a NORMAL completion too — _remove_running_marker sits in scan_system's finally block, so a file surviving a clean run would make every subsequent cancel invocation report a phantom 'scanner running: yes'.

### `STOR-039` rule_cache/ — compiled-ruleset disk cache (XDR-only; the XSIAM twin has none)

*core*

- **Must be true:** The second of two consecutive runs with byte-identical rules loads the compiled bundle from disk instead of recompiling: compile_source flips 'fresh' to 'cache', the same rules_<40hex>.yarac file is reused, and compile_seconds collapses.
- **Threshold:** Run 1: compile_source == 'fresh' and exactly one new file under <scanner_dir>/rule_cache whose basename matches ^rules_[0-9a-f]{40}\.yarac$. Run 2: compile_source == 'cache', identical basename, compile_seconds <= 0.10 x run 1's compile_seconds AND < 5.0 s; run 2's system log has >= 1 'Rule cache HIT rules_' record and 0 'Rule compile FRESH' records.
- **Setup:** Empty <scanner_dir>/rule_cache, then two consecutive Round 1 runs on the same endpoint with the identical rule pack (YARA_RULE_CACHE unset, i.e. enabled).
- **Evidence:** compile_source and compile_seconds fields in logs/scan_summary_<run_id>.json (both runs); 'Rule cache HIT <basename> load=<s>s (valid=N failed=N skipped=N)' and 'Rule compile FRESH <s>s' records in logs/system_<run_id>.log; `ls -l <scanner_dir>/rule_cache`.
- **Negative control:** A third run with YARA_RULE_CACHE=0 exported (SSH-launched — an Action Center snippet cannot set module-scope env) must recompile: compile_source == 'fresh', 'Rule compile FRESH' present, 'Rule cache HIT' absent — while the existing .yarac keeps the same size and mtime (no save, no LRU utime touch). That distinguishes 'caching disabled' from 'cache directory missing'.

### `STOR-042` Rule-cache atomic save with PID+random temp naming

*supporting*

- **Must be true:** A successful cache save publishes the bundle atomically and leaves no temp behind: after a fresh-compile run the cache directory holds the .yarac and its .meta.json and zero rules_*.tmp files, with no save-failure record emitted.
- **Threshold:** After the run: exactly 1 new rules_<40hex>.yarac, exactly 1 matching rules_<40hex>.yarac.meta.json, 0 files matching rules_*.tmp, and 0 occurrences of 'Rule cache save failed (non-fatal):' in logs/system_<run_id>.log.
- **Setup:** Empty <scanner_dir>/rule_cache, then the first Round 1 run (fresh compile).
- **Evidence:** `ls -a <scanner_dir>/rule_cache`; logs/system_<run_id>.log; compile_source == 'fresh' in logs/scan_summary_<run_id>.json.
- **Negative control:** Force the save to fail with a mechanism root cannot bypass. On the Linux endpoint (xdr-agent, ext4): `chattr +i /opt/yara_scanner/rule_cache` after the run starts but before the compile finishes — the immutable flag blocks entry creation for root too, while `os.makedirs(exist_ok=True)` on the already-existing directory still succeeds. Then logs/system_<run_id>.log must carry exactly 1 'Rule cache save failed (non-fatal): ' record, the scan must still reach outcome == 'completed' (caching is best-effort, never fatal), no rules_*.yarac and no rules_*.tmp may appear, and no .meta.json may be left without its bundle. Clear with `chattr -i` afterwards. Do NOT use chmod — it is a no-op against the SYSTEM/root context the payload runs in. This proves the temp+os.replace ordering: a non-atomic writer would leave a truncated .yarac that the next run would then load.

### `STOR-043` Rule-cache orphan .tmp sweep, age-gated at 1 hour

*low*

- **Must be true:** The orphan-temp sweep is age-gated: a planted rules_*.tmp older than the gate is deleted by the next successful cache save, while one with a current mtime is left alone.
- **Threshold:** Gate = 3600 s (bare literal in _prune_rule_cache, not customer-reachable). After the run: the >1 h temp is absent; the current-mtime temp is still present with its size unchanged; the run's own rules_<40hex>.yarac and .meta.json exist.
- **Setup:** Empty <scanner_dir>/rule_cache, then plant two files in it: rules_stale.tmp with mtime set to now-7200 s and rules_fresh.tmp with mtime now. Run a Round 1 scan whose compile is FRESH (cache miss), because _prune_rule_cache is invoked only from _save_rule_cache.
- **Evidence:** `ls -l <scanner_dir>/rule_cache` before and after the run; 'Rule compile FRESH' in logs/system_<run_id>.log confirming the save path ran.
- **Negative control:** rules_fresh.tmp must survive run 1 — the age gate exists to spare a concurrent per-action process's in-flight save. For the hit-path control, RE-PLANT both temps (a fresh-mtime rules_fresh2.tmp and an mtime-now-7200 rules_stale2.tmp) after run 1 and before a follow-up run that HITS the cache: BOTH must still be present afterwards, because _prune_rule_cache is reachable only from _save_rule_cache and the hit path never saves. A build that swept on every run would delete rules_stale2.tmp there, and one with no age gate would delete rules_fresh.tmp in run 1.

### `STOR-046` rule_cache is deliberately exempt from HostCleanup

*supporting*

- **Must be true:** At its most aggressive setting host cleanup still never touches the cross-run cache: after a completed run with CONFIG_HOST_CLEANUP='always' and CONFIG_HOST_CLEANUP_KEEP='nothing', every pre-existing rule_cache bundle is still present with its original size, and <scanner_dir>/control still exists.
- **Threshold:** Before/after `ls -l <scanner_dir>/rule_cache`: no basename removed and no size changed (this run's own new entry may be added); <scanner_dir>/control is present; <scanner_dir>/logs contains 0 files carrying this run's run_id (keep='nothing' removes the summary too).
- **Setup:** A DEDICATED short cleaned run against a small tree — not the main Round 1 scan, which cleanup would strip of the artefacts every other Round 1 criterion reads. Set CONFIG_HOST_CLEANUP='always', CONFIG_HOST_CLEANUP_KEEP='nothing', and seed rule_cache with at least two rules_*.yarac from earlier runs.
- **Evidence:** `ls -l <scanner_dir>/rule_cache`, `ls <scanner_dir>` and `ls <scanner_dir>/logs` before and after the run; HostCleanup.run's removal set is the logs_dir name loop plus evidence_dir / alert_dir / failed_rules_dir only — neither rule_cache nor control_dir appears in it.
- **Negative control:** alert/, evidence/ and failed_rules/ from the SAME run must come back empty and logs/ must lose this run's files. Without that, 'rule_cache survived' is indistinguishable from 'cleanup never ran' — which is exactly what a mis-set CONFIG_HOST_CLEANUP, a non-'completed' outcome, or a missing summary would produce.

### `STOR-050` HostCleanup — opt-in end-of-run removal of this run's on-host working files

*core*

- **Must be true:** Cleanup is genuinely opt-in and genuinely removes: with CONFIG_HOST_CLEANUP='off' the run's whole working set survives on disk; with 'always' and outcome=='completed' the same run's seven per-category logs, its diagnostics log, and the entire contents of alert/, evidence/ and failed_rules/ are gone the moment the process exits.
- **Threshold:** Control run (off): 8 files in <scanner_dir>/logs carrying that run_id — alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_, diagnostics_ — plus scan_summary_<run_id>.json, and >= 1 entry each under alert/ and evidence/. Cleaned run (always, keep='summary'): exactly 1 file in logs/ carrying that run_id, namely scan_summary_<run_id>.json, and 0 entries under alert/, evidence/ and failed_rules/.
- **Setup:** Two dedicated short runs against the same small tree, differing only in CONFIG_HOST_CLEANUP (set via a snippet prelude assigning the module global — it is read at runtime in run()'s finally, so a prelude assignment takes effect). Plant an always-matching decoy file in the tree so BOTH runs produce at least one alert/<rule>.txt and a non-empty file_mapping.txt. Run the CONTROL ('off') run FIRST and capture `ls` of logs/, alert/ and evidence/ before starting the cleaned run — the cleaned run's initial_cleanup would otherwise wipe the control's alert/ and evidence/ and make the control arm unreadable. Keep the cleaned run OUT of the main Round 1 scan; it deletes the artefacts every other Round 1 criterion reads.
- **Evidence:** `ls <scanner_dir>/logs` and `ls <scanner_dir>/alert <scanner_dir>/evidence <scanner_dir>/failed_rules` after each run. Decide this on disk state only: the 'Host cleanup removed N path(s)' message is a bare logging.info emitted after close_diagnostics_handler() has already detached the only file sink, so it reaches nothing.
- **Negative control:** CONFIG_HOST_CLEANUP is deliberately not an options key. Passing options='host_cleanup=always' must raise ValueError from _parse_options_string — which runs OUTSIDE run()'s try block — so Action Center stdout shows 'SNIPPET_ERROR:' with the exact text "Unknown option 'host_cleanup'. Valid keys: collect_files, cpu_budget_pct, cpu_floor_pct, cpu_guarantee, cpu_headroom_pct, create_alerts, lookup_shard, tenant_id, workers, write_dataset" (ten keys, ', '.join(sorted(_VALID_OPTION_KEYS))) and NO new run_id appears in logs/ (ScanConfig never ran). A build that silently accepted the key would start a scan and delete files. Second control: options='throttle_mode=off' must NOT raise — it is in _RETIRED_OPTION_KEYS and is translated, so rejection there would be a regression in the opposite direction.

### `STOR-051` HostCleanup KEEP tiers (nothing / summary / evidence)

*supporting*

- **Must be true:** The three KEEP tiers select exactly what survives — 'summary' leaves only scan_summary_<run_id>.json, 'evidence' additionally leaves the evidence ZIP, 'nothing' leaves no trace of the run_id — and an unrecognised value is silently treated as 'summary' rather than rejected, because VALID_KEEP is declared but never enforced.
- **Threshold:** keep='summary': logs/ holds exactly 1 file with this run_id (scan_summary_<run_id>.json) and <scanner_dir>/evidence holds 0 entries. keep='evidence': same 1 log file AND exactly 1 evidence/evidence_<hostname>_<run_id>.zip. keep='nothing': 0 files anywhere under <scanner_dir> carrying this run_id, while rule_cache/ and control/ are untouched. keep='bogus': byte-for-byte the same outcome as keep='summary', with no error raised, no warning logged and outcome == 'completed'.
- **Setup:** Four dedicated short completed runs with CONFIG_HOST_CLEANUP='always' and CONFIG_HOST_CLEANUP_KEEP set to 'summary', 'evidence', 'nothing' and 'bogus' in turn.
- **Evidence:** `ls <scanner_dir>/logs`, `ls <scanner_dir>/evidence`, and `find <scanner_dir> -name '*<run_id>*'` after each run; the four runs' scan_summary contents captured before the cleaned run of the 'nothing' tier (read it via the SCAN_RESULT line instead, since the file is deleted).
- **Negative control:** The 'bogus' run is the control that proves VALID_KEEP is inert: an enforcing build would reject it (or fall back loudly), while this build must quietly take the 'summary' branch. Second control: no run at any tier may remove another run_id's files or the rule_cache/control directories.

### `STOR-052` HostCleanup refuses to delete unless the summary JSON durably exists

*core*

- **Must be true:** With CONFIG_HOST_CLEANUP='always' on an otherwise completed run, a failed summary write causes cleanup to remove nothing at all: this run's alert files, evidence ZIP and logs are all still on disk.
- **Threshold:** 0 paths removed — the run's alert/*.txt count, evidence/evidence_<hostname>_<run_id>.zip and all files carrying this run_id in logs/ are unchanged in number and size before and after process exit; scan_errors_<run_id>.log contains exactly 1 'Failed to write scan summary JSON: ' record; logs/scan_summary_<run_id>.json does not exist.
- **Setup:** Start a short scan with CONFIG_HOST_CLEANUP='always' (snippet prelude assignment or SSH-launched), then make the summary write fail with a mechanism root cannot bypass: on Linux (xdr-agent, ext4) `chattr +i /opt/yara_scanner/logs` once the scan is underway. The immutable flag blocks entry CREATION and RENAME in that directory even for root, so both the scan_summary_<run_id>.json.tmp open and the os.replace fail, while the already-open per-category FileHandlers keep appending to their existing files. `chmod a-w` is a no-op here and must not be used. Clear with `chattr -i` after the run. (On the Windows endpoint the equivalent is an explicit Deny-Write ACE for SYSTEM on C:\yara_scanner\logs, but prefer the Linux arm.)
- **Evidence:** 'Failed to write scan summary JSON: ' record in logs/scan_errors_<run_id>.log (write_scan_summary's except branch, line 2476); `ls -l <scanner_dir>/logs <scanner_dir>/alert <scanner_dir>/evidence` captured immediately before and after the run; absence of logs/scan_summary_<run_id>.json AND of scan_summary_<run_id>.json.tmp; `lsattr -d /opt/yara_scanner/logs` before and after, to prove the immutable flag was actually in force for the window that mattered.
- **Negative control:** The identical run with logs/ writable must clean up fully — otherwise 'refused' is indistinguishable from 'cleanup is broken'. Also confirm no half-written scan_summary_<run_id>.json.tmp is left behind: the except branch removes its own temp.

### `STOR-053` HostCleanup on_delivery gate — refuses when there is no delivery channel to verify

*core*

- **Must be true:** With CONFIG_HOST_CLEANUP='on_delivery' and BOTH CONFIG_CREATE_ALERTS and CONFIG_WRITE_DATASET off, cleanup is refused even though delivery_shortfall is empty — an empty shortfall with no channel means 'nothing was attempted', not 'everything landed', so the local copy is kept.
- **Threshold:** delivery_shortfall == "" and outcome == 'completed' in scan_summary_<run_id>.json, yet logs/ still holds all 8 files carrying this run_id plus the summary, and alert/ and evidence/ still hold this run's contents. posture in the same summary reads 'alerts=off dataset=off ...'.
- **Setup:** A dedicated short run with CONFIG_HOST_CLEANUP='on_delivery' and options='create_alerts=false,write_dataset=false'. This is a deliberate one-off deviation from the settled 'delivery channels ON in every round' decision — the capability is defined precisely by their absence and is unreachable with either channel on.
- **Evidence:** delivery_shortfall, outcome and posture fields in logs/scan_summary_<run_id>.json; `ls <scanner_dir>/logs <scanner_dir>/alert <scanner_dir>/evidence` after the run. Decide on disk state: the refusal reason ('on_delivery has no delivery channel to verify (alerts and dataset writes are both off) - keeping the local copy') is a bare logging.info emitted after the diagnostics handler is closed and reaches no file.
- **Negative control:** The same 'on_delivery' setting WITH at least one channel on and delivery_shortfall == "" must clean up — proving the refusal comes from the missing channel and not from on_delivery being broken. Second control: CONFIG_HOST_CLEANUP='always' with both channels off must still clean up, since 'always' is the documented way to opt all the way out of this gate.

### `STOR-055` HostCleanup closes log FileHandlers before deleting (Windows WinError 32)

*supporting*

- **Must be true:** On Windows all SEVEN per-category log files for a cleaned run are actually deleted — including yara_processing_<run_id>.log, which ErrorLogger owns separately from LogManager's six and which no code closed before this handler-closing step existed.
- **Threshold:** After a completed run on the Windows endpoint with CONFIG_HOST_CLEANUP='always', KEEP='summary': `dir C:\yara_scanner\logs` shows 0 files matching alerts_<run_id>.log, statistics_<run_id>.log, scan_errors_<run_id>.log, performance_<run_id>.log, uploads_<run_id>.log, system_<run_id>.log or yara_processing_<run_id>.log — 7 of 7 gone — with only scan_summary_<run_id>.json remaining for that run_id.
- **Setup:** A dedicated short cleaned run delivered to the Windows endpoint (xdragent2), where the file-locking semantics make the failure observable; Linux tolerates unlinking an open file and never showed the symptom.
- **Evidence:** `dir C:\yara_scanner\logs` over SSH after the run; the run_id read from the SCAN_RESULT line's scan context or from the surviving scan_summary_<run_id>.json. Decide on disk listing: cleanup's own per-path failures go through the log=logging.warning callback bound at the HostCleanup.run call site, which reaches no structured log by then.
- **Negative control:** yara_processing_<run_id>.log is the discriminating file — an earlier build closed only LogManager's six handlers and deleted six of seven. A criterion that only counts 'most files gone' cannot see that regression, so the seventh must be named explicitly. Second control: the previous runs' log files in the same directory must all survive.

### `STOR-056` HostCleanup recreates alert/evidence/failed_rules empty after wiping

*supporting*

- **Must be true:** After a cleaned run the three working directories still EXIST and are empty — they are recreated after the wipe, not left absent — while logs/ keeps only what the KEEP tier spared.
- **Threshold:** <scanner_dir>/alert, <scanner_dir>/evidence and <scanner_dir>/failed_rules are all present as directories and each contains exactly 0 entries; logs/ contains exactly 1 file carrying this run_id at keep='summary'.
- **Setup:** The dedicated completed cleaned run (CONFIG_HOST_CLEANUP='always'), against a tree that produced at least one alert file and one failed-rule dump so the directories were non-empty going in.
- **Evidence:** `ls -ld <scanner_dir>/alert <scanner_dir>/evidence <scanner_dir>/failed_rules` and `ls -A` on each, after the run.
- **Negative control:** Absent is the failure, not the pass: the scheduled rename task cd's into alert_dir and initial_cleanup assumes these directories exist. A build that only rmtree'd them would leave 0 entries too — the `ls -ld` existence check is what separates the two. At keep='evidence' the evidence directory must contain the ZIP rather than be empty, which is the complementary control.

### `STOR-057` HostCleanup identifies this run's logs the same way retention does

*supporting*

- **Must be true:** Cleanup removes only THIS run's log files: with three prior runs' log sets present, exactly the current run_id's files disappear and all three prior run_id groups survive intact.
- **Threshold:** Before: 4 distinct run_ids present in logs/, the three prior ones with their full file sets. After the cleaned run: 0 files carrying the current run_id except scan_summary_<run_id>.json (keep='summary'), and the file count for each of the 3 prior run_ids is unchanged. Every removed name matched the retention regex _(\d{8}_\d{6}_\d{6})\.(?:log|json)$ used by CleanupManager._extract_run_id_from_log_name.
- **Setup:** Run three ordinary short scans first (leave CONFIG_HOST_CLEANUP='off' and YARA_LOG_KEEP at its default 10 so retention does not prune them), then the fourth run with CONFIG_HOST_CLEANUP='always'.
- **Evidence:** `ls <scanner_dir>/logs` before and after, grouped by the run_id embedded in each filename; the four run_ids taken from each run's scan_summary_<run_id>.json.
- **Negative control:** The three prior run_ids are the control — a prefix or glob-based implementation would take neighbours with it. Second control: files in logs/ that carry no parseable run_id must also be left alone; plant a file named `notes.log` in logs/ and confirm it survives, since the regex requires the full _YYYYMMDD_HHMMSS_ffffff stamp.

### `STOR-063` Resource-monitor sampling histories are ring-buffered (memory, not disk)

*supporting*

- **Must be true:** The sampling histories are bounded ring buffers held only in memory — the sample counts never exceed their maxlens however long the scan runs, no per-sample file is written anywhere — and turning the monitors off does NOT empty the performance log.
- **Threshold:** maxlens: performance_history 1000, resource_history 360, alert_history 100. Monitors-on run, monitored for T seconds: the 'Performance Metrics:' block in the COMPREHENSIVE STATISTICS SUMMARY reports samples_collected <= 1000 always, and == 1000 exactly once T > 5,500 s; it must also be >= 0.80 * min(1000, T/5) so a monitor that silently stopped is caught. The 'Resource monitoring completed: N snapshots, M alerts' record's data_points_collected <= 360 always, == 360 once T > 4,000 s, and >= 0.80 * min(360, T/10). Once performance_history is full, 'Performance Snapshot |' records stop entirely (the emit gate is `len(self.performance_history) % 6 == 0` at line 2016 and 1000 % 6 != 0) — that cessation is expected, not a failure. Default run (both flags off): 0 'Performance Snapshot |' records, but >= 1 '=== Performance Monitoring Started ===' and '=== Performance Monitoring Ended ===' pair, >= floor(duration/30) - 1 'System Resources |' records, >= 1 'Worker Performance |' record and exactly 1 'Worker cleanup: ' record, plus exactly 1 'Performance monitoring disabled in light profile' record in statistics_<run_id>.log. `find <scanner_dir>` shows no per-sample artefact.
- **Setup:** Two Round 1 runs over the same large tree: one at defaults, one SSH-launched with YARA_ENABLE_PERF_MONITOR=1 and YARA_ENABLE_RESOURCE_MONITOR=1 exported. Size the monitored run past 5,000 s (perf) / 3,600 s (resource) so the caps are actually reached rather than merely not exceeded.
- **Evidence:** 'COMPREHENSIVE STATISTICS SUMMARY' section of logs/statistics_<run_id>.log, specifically the samples_collected key of its 'Performance Metrics:' JSON block; the 'Resource monitoring completed: N snapshots, M alerts' record and its data_points_collected field in logs/performance_<run_id>.log; 'Performance Snapshot | CPU: ...% (system ...%) | Memory: ...MB (...%) | Disk I/O: R:...MB W:...MB | Network: S:...MB R:...MB | Queue: n | Workers: n' records in the same file; performance_monitoring_enabled / resource_monitoring_enabled in the 'YARA Scanner initialization completed' init_data in logs/system_<run_id>.log; `find <scanner_dir> -type f -newermt <scan start>`.
- **Negative control:** The default run must still leave a NON-empty performance_<run_id>.log. 'Ring-buffered in memory' must not be read as 'no telemetry': the banner pair, the per-heartbeat 'System Resources |' lines, 'Worker Performance |' lines and the 'Worker cleanup:' line all land with both monitors off, and scan_summary_<run_id>.json legitimately has NO performance_metrics field — its absence there is correct, not a failure.

### `STOR-066` Runtime fingerprint (embedded Python, platform, yara binding version) written at the head of yara_processing_<run_id>.log before any rule work

*supporting*

- **Must be true:** The agent's runtime identity is recorded at the top of yara_processing_<run_id>.log before any rule work begins, and the same three values reappear in the system log's init_data — but the libyara version proper is in neither and can only be recovered from the rule-cache sidecar.
- **Threshold:** The first four records of logs/yara_processing_<run_id>.log are, in order, '=== YARA Processing Log ===', 'Python Version: ', 'Platform: ' and 'YARA Version: ', all at a byte offset lower than the first 'Available YARA modules: ' record. init_data.python_version / init_data.platform / init_data.yara_version appear in logs/system_<run_id>.log exactly twice each — on 'YARA Scanner initialization completed' and on 'YARA Scanner initialized successfully' — and match the yara_processing values. The libyara version is captured ONLY in rule_cache/rules_<key>.yarac.meta.json: its 'yara' value splits on '/' into exactly 4 fields, field 1 == the 'YARA Version: ' value in yara_processing (yara.__version__), field 2 == yara.YARA_VERSION, field 3 == platform.system() and field 4 == platform.machine(). Fields 3 and 4 as a combined '<system>/<machine>' tag appear in 0 log files. Do NOT assert that field 2's value is absent from the logs: on this fleet's agents (yara-python 4.1.0 Windows / 3.11.0 Linux) the binding and libyara versions are the same string, so that assertion fails a correct build.
- **Setup:** Any Round 1 run whose compile is FRESH, so a .meta.json sidecar is written and the libyara-version claim is checkable.
- **Evidence:** `head -6 logs/yara_processing_<run_id>.log` (match by record prefix, not by physical line number — sys.version embeds a newline on CPython/Linux, so 'Python Version:' spans two physical lines there); init_data keys in logs/system_<run_id>.log; `cat <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json` and split its 'yara' value on '/'; `grep -rc 'YARA_VERSION' logs/` == 0 (the identifier is never printed); an independent read of yara.__version__ and yara.YARA_VERSION on the same endpoint (SSH-launched one-liner, or a snippet prelude printing both) so the sidecar's two fields can be attributed rather than assumed.
- **Negative control:** The fingerprint must PRECEDE rule work, not merely exist: the 'Python Version:' record must appear BEFORE 'Available YARA modules: ' in the same file, so a run that dies during module probing still leaves the agent's identity behind. Second control: the sidecar's 'yara' value must have exactly 4 slash-separated fields and its 3rd and 4th (platform.system()/platform.machine()) must be absent from every log file — a build that wrote only yara.__version__ into the cache key would collide a 3.11-Linux bundle with a 4.1-Windows bundle, and the missing platform fields are what detect that. Whether fields 1 and 2 happen to be equal is a property of the agent's yara-python build, not of the scanner, and must not be treated as a failure.

### `STOR-068` StatisticsManager bypasses LogManager and writes raw, multi-line blocks into statistics_/performance_<run_id>.log

*low*

- **Must be true:** StatisticsManager writes straight to LogManager's category loggers rather than through LogManager._log, so its summary blocks arrive as raw multi-line JSON with no ' | data=' envelope, no key sorting and no 4000-char cut — and its bookend markers prove the monitor covered the whole scan.
- **Threshold:** In logs/statistics_<run_id>.log: exactly 1 'COMPREHENSIVE STATISTICS SUMMARY' record; the physical line immediately after the 'Worker Summary: {' record begins with two spaces and a double quote (json.dumps indent=2) and does NOT begin with '['; 0 occurrences of ' | data=' on any of the 'Performance Metrics: ', 'Time Estimates: ' or 'Worker Summary: ' lines; 0 occurrences of '...(truncated)' inside those blocks. The '=== Statistics Manager Initialized ===' marker precedes every 'Scan Progress |' record and '=== Statistics Manager Stopped ===' follows the last one; logs/performance_<run_id>.log contains exactly 1 '=== Performance Monitoring Started ===' and exactly 1 '=== Performance Monitoring Ended ===', in that order, bracketing every 'System Resources |' record. The Worker Summary block carries one error_rate_percent per worker, count == max_workers.
- **Setup:** The main Round 1 scan — long enough that every worker processes files, otherwise worker_summary serializes as '{}' on one line and the multi-line claim is vacuous.
- **Evidence:** `grep -n 'COMPREHENSIVE STATISTICS SUMMARY' logs/statistics_<run_id>.log` then reading the following physical lines; the '=== Statistics Manager Initialized ===' / '=== Statistics Manager Stopped ===' markers in the same file; the '=== Performance Monitoring Started ===' / '=== Performance Monitoring Ended ===' pair in logs/performance_<run_id>.log; timestamps of the first and last 'Scan Progress |' records for the bracketing check.
- **Negative control:** Records that DO go through LogManager must look different in the same file — the 'Skip reasons: ' and 'COMPREHENSIVE SCAN REPORT | ' records must carry the ' | data={' single-line envelope with sorted keys. If both shapes look alike, the bypass has been removed (or the report has been routed around the cap), and the 4000-char behaviour asserted elsewhere no longer holds.

### `STOR-069` Logging counters under-report by construction, and yara_processing_<run_id>.log is missing from log_files_created

*low*

- **Must be true:** The reported log counters are a floor, never a completeness check: the six category files hold strictly more physical lines than 'Total Logs' claims, and log_files_created enumerates six paths with yara_processing_<run_id>.log absent even though the file exists on disk.
- **Threshold:** log_files_created has exactly 6 entries, keyed alert / statistics / error / performance / upload / system, and contains no path matching yara_processing_ — while <scanner_dir>/logs/yara_processing_<run_id>.log exists and is non-empty. `wc -l` summed over alerts_ + statistics_ + scan_errors_ + performance_ + uploads_ + system_<run_id>.log is strictly greater than the 'Total Logs: N' value (the counter misses StatisticsManager's direct-to-logger lines, every continuation line of a multi-line record, and the Logging Summary record itself, which is counted after the snapshot is taken). The identical log_generation_stats dict appears in both the 'Scan completed successfully in ' system record and the 'SCAN COMPLETED SUCCESSFULLY in ' statistics record.
- **Setup:** Any completed Round 1 run — the counters are written by stop_logging on every run.
- **Evidence:** The 'Logging Summary | Total Logs: N' record and its log_files_created / logs_by_type data in logs/system_<run_id>.log; `wc -l` over the six category files; `ls -l logs/yara_processing_<run_id>.log`; the log_generation_stats block inside the 'Scan completed successfully in ' and 'SCAN COMPLETED SUCCESSFULLY in ' records.
- **Negative control:** Strictly greater, not merely different: a build whose counter over-reported (or that counted physical lines) would break the invariant in the other direction and must fail. Second control: yara_processing_<run_id>.log must exist and be non-empty on the same run — 'missing from the manifest' is only a real gap if the file is really there, and its absence from log_files_created is precisely why an operator relying on that list would miss the rule-compilation trail.

### `STOR-070` Evidence ZIP is produced on every completed scan, including zero-match runs — its existence proves nothing

*core*

- **Must be true:** A completed scan that matched nothing still produces an evidence ZIP, and that ZIP carries no findings — so ZIP existence must never be read as 'evidence was collected'; only the manifest row count answers that.
- **Threshold:** Zero-match run (scan_summary matches == 0): exactly 1 file evidence/evidence_<hostname>_<run_id>.zip; `unzip -l` lists exactly 1 member, file_mapping.txt; 0 lines in that member match [0-9a-f]{64}; 0 members whose name starts with 'alerts/' or 'matched_files/'. Matching run (Round 2 flood, collect_files default false): the same path additionally lists exactly one alerts/<rule>.txt member per triggered rule (count == unique_rules_triggered in scan_summary) and still 0 matched_files/ members.
- **Setup:** Round 1's clean scan, with the ruleset verified to yield matches == 0 in scan_summary_<run_id>.json. If the Round 1 pack produces even one match, add a dedicated control run whose only rule keys off a 64-byte random nonce string that cannot occur on the host.
- **Evidence:** `unzip -l <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` over SSH; `unzip -p <zip> file_mapping.txt | grep -cE '[0-9a-f]{64}'`; matches and unique_rules_triggered in logs/scan_summary_<run_id>.json; the 'Evidence: collect_files=false - packaging metadata only (no matched file copies)' record in logs/system_<run_id>.log.
- **Negative control:** The matching run is the control that stops this from reading as 'the ZIP is always empty': its member list must grow with alerts/<rule>.txt entries. And a CANCELLED run must produce NO evidence ZIP at all (collect_evidence is called only on the success and fatal-failure paths), which is the asymmetry an operator inspecting a cancelled host will hit.
- **Why this round:** Round 1's deliberately-clean scan IS the zero-match run this capability is about; no other round can produce one, since Round 2 floods and Round 3 plants decoys.

### `STOR-072` The root diagnostics handler is closed before host cleanup

*supporting*

- **Must be true:** The eighth per-run file handler — the root FileHandler that setup_logging installs for diagnostics_<run_id>.log — is closed before host cleanup runs, so on Windows that file is actually deleted instead of surviving every scan forever.
- **Threshold:** After a completed run on the Windows endpoint with CONFIG_HOST_CLEANUP='always' and KEEP='summary': 0 files named diagnostics_<run_id>.log under C:\yara_scanner\logs, and the only file carrying that run_id is scan_summary_<run_id>.json. On the same endpoint with cleanup off, diagnostics_<run_id>.log exists and is non-empty — proving the file was produced and then removed, not never written.
- **Setup:** Two dedicated short runs on the Windows endpoint (xdragent2) differing only in CONFIG_HOST_CLEANUP; both must reach outcome == 'completed', since close_diagnostics_handler() sits inside the completed-only branch.
- **Evidence:** `dir C:\yara_scanner\logs` over SSH after each run; the run_id read from the surviving scan_summary_<run_id>.json. Decide on disk listing: cleanup's own removal/error messages go through the plain logging module after the handler is detached, so they reach nothing.
- **Negative control:** The off-run is the control — without it, an absent diagnostics file could just mean the sink was never created (setup_logging falls back to WARNING-only when the FileHandler cannot be opened). Second control: on a CANCELLED run the handler must stay OPEN, so diagnostics_<run_id>.log must exist afterwards and contain zero 'Host cleanup' lines; that is what makes the silence asserted for the outcome gate real evidence rather than a closed sink.

## Delivery, Aggregation & Telemetry

### `DELI-035` Scans-dataset heartbeat cadence

*supporting*

- **Must be true:** 'running' lifecycle rows are emitted on a fixed cadence, no more often than the heartbeat interval and no later than one poll period after it, and each is accompanied by a refresh of the on-disk liveness marker; the two callers never both pass the gate and double-emit.
- **Threshold:** At least 3 rows with status='running' and message='heartbeat' for this run_id; every consecutive pair of their event_timestamp_ms values differs by between 600s and 635s (600s gate plus one 30s poll plus 5s slack); no two heartbeat rows share an interval shorter than 600s; the first heartbeat's event_timestamp_ms is at least 600s after the 'initiated' row's; <scanner_dir>/control/running.json updated_at advances on the same cadence while the scan runs.
- **Setup:** Round 1 whole-tree clean scan running for at least 35 minutes so at least three heartbeat intervals elapse.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>" and status = "running" | fields event_timestamp_ms, files_scanned, message | sort asc event_timestamp_ms`; <scanner_dir>/control/running.json updated_at sampled over SSH during the run.
- **Negative control:** The first heartbeat must NOT fire at scan start — _last_heartbeat is primed to the scan start time, so a row within the first 600s means the priming was lost. Duplicate rows inside one interval mean the check-and-set lock is gone.
- **Why this round:** Departs from the delivery prior. The claim is about a 600-second cadence holding over many intervals; only Round 1's long, mostly-clean whole-tree scan spans enough of them to distinguish a correct cadence from a broken one. Round 2's bounded flood may not span a single interval, which would make the criterion vacuous there.

### `DELI-036` Independent heartbeat thread (decoupled from the directory walker)

*supporting*

- **Must be true:** Heartbeat rows keep arriving on cadence while the directory walker is blocked on scan-queue backpressure, i.e. the heartbeat is not driven by walk progress.
- **Threshold:** Across a window in which performance_<run_id>.log shows at least one 'Scan queue saturated (<n> items) - backing off producer' line and the scans rows' files_scanned increases by less than 2% of the run total, the consecutive heartbeat event_timestamp_ms deltas still fall within 600-635s — the same bound as an unsaturated window in the same run.
- **Setup:** Round 1 long clean scan configured for saturation (single worker and a small scan queue), with competing CPU load so workers stay slow and the producer parks in _enqueue_scan_path's retry loop for minutes at a time.
- **Evidence:** XQL heartbeat rows for the run_id (event_timestamp_ms, files_scanned); <scanner_dir>/logs/performance_<run_id>.log 'Scan queue saturated (<n> items) - backing off producer' timestamps to locate the parked window.
- **Negative control:** The heartbeat must not speed UP when the walker is fast — an unsaturated window in the same run must also show 600-635s deltas, not shorter ones. Equal cadence in both windows is the claim; only a stalled or accelerated cadence fails.
- **Why this round:** Departs from the delivery prior for the same reason as DELI-035, and additionally because the property under test is 'the heartbeat survives a parked walker' — walker starvation under queue saturation is Round 1's subject, not Round 2's.

### `DELI-064` CPU governor telemetry heartbeat (CPU_GOVERNOR lines)

*supporting*

- **Must be true:** performance_<run_id>.log carries a CPU_GOVERNOR time series with no gap longer than the heartbeat even when the ratio never moves, and scan_summary.cpu_governor is the same stats object holding the run's final values.
- **Threshold:** GOVERNOR_HEARTBEAT_SECS = 30 (YARA_GOVERNOR_HEARTBEAT_SECS); sampling gate throttle_check_interval_secs = 1.0s. For every consecutive pair of 'CPU_GOVERNOR {' lines, t[i+1] - t[i] <= 31.5s. Line count >= floor((t_last - t_first) / 30) — anchor the count to the span between the FIRST and LAST CPU_GOVERNOR timestamps, not to scan_summary duration_secs, because compilation, evidence collection, the final report and both drains contribute to duration_secs while emitting no samples. Additionally require t_first <= 60s after the 'Scan status changed to: scanning' line in diagnostics_<run_id>.log and t_last within 60s of the 'Scan status changed to: finishing' line, so a governor that stops emitting mid-scan is still caught. Every payload parses as JSON and carries policy, target, own, others, ratio, slept_secs, floor_hits, samples_taken, secs_since_last_sample plus t; scan_summary_<run_id>.json cpu_governor carries the same nine keys.
- **Setup:** Round 1's long clean scan on an otherwise idle host, so the ratio does not move and only the heartbeat can produce lines — the case the heartbeat exists for.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log lines beginning 'CPU_GOVERNOR {'; scan_summary_<run_id>.json cpu_governor.
- **Negative control:** With cpu_guarantee="none" the governor's enabled flag is False and _sample_governor returns before reading CPU — that run must emit ZERO 'CPU_GOVERNOR {' lines. The heartbeat must not fire for a disabled governor.
- **Why this round:** Catalogued in the delivery chunk, but nothing about it is delivery-driven: it is a performance-log cadence that only a long, steady, mostly-idle scan can prove. Round 2's flood changes exactly the timings this measures, which is why ROUNDS.md puts the governor in Round 1.

### `DELI-070` Log retention across runs (delivery diagnostics window)

*supporting*

- **Must be true:** After more than LOG_KEEP_SCANS runs on one endpoint, logs_dir holds files for exactly LOG_KEEP_SCANS distinct run_ids — the current run always among them — older runs' .log and .json files are gone, and no orphaned atomic-write temp remains.
- **Threshold:** LOG_KEEP_SCANS = 10 (YARA_LOG_KEEP). After the 12th run: count of distinct run_ids matching the retention regex `_(\d{8}_\d{6}_\d{6})\.(?:log|json)$` == 10; count of scan_summary_*.json == 10; count of scan_summary_*.tmp == 0; the newest run_id is present. (Pruning runs at scan START, after LogManager has already created the current run's six files, so the current run_id is already among the newest ten.)
- **Setup:** Twelve short back-to-back scans on the Linux endpoint over SSH, with CONFIG_HOST_CLEANUP left at its "off" default so nothing else removes files.
- **Evidence:** `ls <scanner_dir>/logs` after the 12th run. The 'Log retention applied: kept last N scans …' summary is a logging.info emitted from initial_cleanup, which runs BEFORE setup_logging installs the diagnostics handler and while root is still at WARNING — it reaches nothing. 'Cannot remove log file (in use): …' (logging.warning) is the only failure signal that can reach stderr.
- **Negative control:** <scanner_dir>/rule_cache, /control, /alert and /evidence must be untouched by retention — it removes only .log/.json files inside logs_dir whose embedded run_id is not retained, and the current run's files must survive every prune.
- **Why this round:** Catalogued in the delivery chunk as the diagnostics window, but nothing delivery-shaped drives it: it is repeat-run host footprint, which ROUNDS.md explicitly assigns to Round 1 ('the seven log files, rotation and retention').

## Scan Lifecycle, Control & Error Handling

### `LIFE-001` Action Center scan entry point (main) — only 3 operator inputs

*core*

- **Must be true:** Invoking the `main` entry point with only yarafile / scan_folder / alert_severity resolves every other behaviour knob to its CUSTOMER CONFIG constant: no options string is parsed (opts is empty, so _pick returns the kwarg for all ten keys) and the resolved posture is exactly the CONFIG default posture, not a value carried in from anywhere else.
- **Threshold:** scan_summary_<run_id>.json "posture" equals the string `alerts=on dataset=on files=off cpu=headroom mode=scan` character-for-character (CONFIG_CREATE_ALERTS=True, CONFIG_WRITE_DATASET=True, CONFIG_COLLECT_FILES=False, CONFIG_CPU_GUARANTEE="headroom", CONFIG_MODE="scan"); "throttle_mode" == "headroom"; the system-log initialization data blob reports max_workers == 2 (CONFIG_WORKERS), scan_queue_size == 4 (max_workers*2), max_file_mb == 64, and default_alert_severity == the third input actually supplied.
- **Setup:** Round 1's standard clean-tree run, delivered through the Action Center `main` entry point (or the snippet footer's run(rules, folder, severity) call) with no options string and no YARA_* env overrides exported.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json fields "posture" and "throttle_mode"; <scanner_dir>/logs/system_<run_id>.log line `YARA Scanner initialization completed | data={...}` (keys max_workers, scan_queue_size, max_file_mb, default_alert_severity); the same posture string as the trailing ` | ` field of the `SCAN_RESULT: Scan completed: …` line in the Action Center action result.
- **Negative control:** Repeating the identical invocation with alert_severity="high" must leave the posture string byte-identical — alert_severity is not one of the five posture fields, so a build that leaked it into posture (or into throttle_mode) fails here while still looking correct on a single run.
- **Why this round:** Departs from the LIFE dimension's Round 3 prior. The claim is 'every knob not among the three inputs resolves to its CONFIG_* constant', and only Round 1's baseline run is delivered through main() with no options string and no env overrides — Rounds 2 and 3 deliberately carry option strings and env knobs that would make the claim untestable.

### `LIFE-021` running.json liveness marker — write, heartbeat refresh, removal

*supporting*

- **Must be true:** control/running.json exists for the whole scan with updated_at advancing on the heartbeat cadence, identifies the live process, and is REMOVED once scan_system's finally completes — its presence after the process exits means the run died before that finally.
- **Threshold:** Sampled every 10s during the run: the file exists, `updated_at` is monotonically non-decreasing and advances at least once in every SCANS_HEARTBEAT_SECS + HEARTBEAT_THREAD_POLL_SECS + 5s window (155s at YARA_HEARTBEAT_SECS=120 with the 30s poll default) — NOT once per bare heartbeat interval; `pid` equals the running scanner pid, `scan_id` equals the run's config.scan_id, and `status` == "running". After process exit: `test -e <scanner_dir>/control/running.json` is FALSE and no `running.json.tmp` remains.
- **Setup:** Round 1's long clean scan on xdr-agent with YARA_HEARTBEAT_SECS=120 exported so the marker refreshes several times inside the run; poll with `cat`/`stat` over SSH every 10s, tightening to 1s cadence once `=== ENHANCED CLEANUP AND FINALIZATION ===` appears so the removal window is actually observed.
- **Evidence:** Successive <scanner_dir>/control/running.json samples; post-exit `ls -1 <scanner_dir>/control/`.
- **Negative control:** The marker must NOT be removed when file discovery ends — sampling control/ at 1s cadence, it must still be present at a moment when system_<run_id>.log has written `=== ENHANCED CLEANUP AND FINALIZATION ===` but not yet `Enhanced cleanup completed in`, proving removal is tied to scan_system's finally (which runs after _perform_enhanced_cleanup returns) and not to the walker.
- **Why this round:** Departs from the LIFE Round 3 prior: the refresh half of the claim needs a run long enough to span several heartbeat intervals, which only Round 1's whole-tree scan provides. Round 3's crafted runs end before the cadence becomes visible, and its cancel path exercises removal only.

### `LIFE-023` Scan phase ordering in scan_system

*supporting*

- **Must be true:** Phases run in a fixed order and each banner appears exactly once: rule compilation completes before the scan is announced, discovery precedes cleanup, and the lifecycle rows follow the same order.
- **Threshold:** In system_<run_id>.log the line offsets satisfy `YaraScanner initialized with 2 workers` < `=== ENHANCED SYSTEM SCAN INITIATED ===` < `=== ACTIVE SCANNING PHASE STARTED ===` < `=== ENHANCED CLEANUP AND FINALIZATION ===` < `Enhanced cleanup completed in`, each with occurrence count == 1. The scans_v3 rows for the run_id, sorted by event_timestamp_ms, read `initiated` first, then ≥1 `running`, then exactly one terminal status.
- **Setup:** Round 1's clean scan with YARA_HEARTBEAT_SECS=120 so at least one running row lands inside the run.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, message, event_timestamp_ms | sort asc event_timestamp_ms`.
- **Negative control:** No `running` row may carry an event_timestamp_ms later than the terminal row's, and the `initiated` row's timestamp must precede the `=== ENHANCED SYSTEM SCAN INITIATED ===` banner — the row is emitted before the banner in scan_system.
- **Why this round:** Departs from the LIFE Round 3 prior because the ordering claim includes at least one `running` heartbeat row between initiated and terminal, which only Round 1's long clean scan produces.

### `LIFE-024` Scan-lifecycle rows in the yara_scanner_scans dataset

*core*

- **Must be true:** The scans dataset carries this run's full lifecycle and nothing else: exactly one `initiated` row, exactly one terminal row, at least one `running` heartbeat row, no status outside {initiated, running, completed, cancelled, failed}, and every row carrying the run's tenant_id / hostname / run_id and a non-empty posture.
- **Threshold:** count(status="initiated") == 1; count(status in {completed,cancelled,failed}) == 1; count(status="running") >= floor(scan_summary.duration_secs / SCANS_HEARTBEAT_SECS) − 1; count of any other status == 0; every row's run_id equals the run's run_id and posture is non-empty; zero `Failed to emit scan-lifecycle row: ` lines in scan_errors_<run_id>.log.
- **Setup:** Round 1's clean scan with write_dataset at its CONFIG default (True) and YARA_HEARTBEAT_SECS=120.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | comp count() by status` and a second query returning tenant_id, hostname, posture per row; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** A short run with options="write_dataset=false" must produce ZERO rows for its own run_id while still completing normally — proving the guard in _emit_scan_row, not an empty or mis-sharded dataset.
- **Why this round:** The dataset channel is Round 2's subject, but these rows are cadence-driven, not load-driven: only Round 1's long clean run produces the `running` rows that make the row set complete, and Round 1 is the only round whose terminal status must be `completed`.

### `LIFE-025` Terminal lifecycle row emitted after workers drain but before uploaders stop

*core*

- **Must be true:** The terminal row is emitted after the worker join and before the uploaders are stopped — so its counters are final AND it actually reaches the dataset instead of being dropped by a stopped uploader.
- **Threshold:** The terminal row's files_scanned, files_skipped and detections equal scan_summary_<run_id>.json's files_scanned, files_skipped and matches EXACTLY; the row is present in the dataset; scan_summary "dataset_delivery" shows dropped == 0 (a row queued after the uploader thread died is counted there, never sent). The run counts only if a real backlog existed at the join: the last `Scan Progress | … | Queue: N | …` line in statistics_<run_id>.log before `=== ENHANCED CLEANUP AND FINALIZATION ===` must show N >= 1000, so a pre-join emission would understate files_scanned by four figures rather than by single digits.
- **Setup:** Round 1's clean scan with YARA_QUEUE_SIZE=20000 exported so file discovery genuinely outruns the workers and tens of thousands of files are still queued when discovery ends — that backlog is what separates 'emitted after the join' from 'emitted before it'. Do NOT use the default queue (max_workers*2 == 4): _enqueue_scan_path's blocking backpressure pins the outstanding work to ~6 files, which cannot decide the claim.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status in ("completed","cancelled","failed") | fields files_scanned, files_skipped, detections`; scan_summary_<run_id>.json files_scanned / files_skipped / matches and the "dataset_delivery" block.
- **Negative control:** The same three-way equality must also hold on Round 3's cancelled run (status "cancelled"), where the un-drained backlog at the moment of cancellation is largest — a build that emitted the row before the join would fail there most visibly.
- **Why this round:** Placed with the worker-pool lifecycle it is an ordering claim about. Round 1's clean whole-tree scan leaves the largest worker backlog at the moment discovery ends, which is exactly the condition that separates 'emitted after the join' from 'emitted before it'.

### `LIFE-026` Heartbeat lifecycle row and its independent thread

*supporting*

- **Must be true:** The heartbeat row lands on the SCANS_HEARTBEAT_SECS cadence from a thread independent of the walker, so it keeps arriving while the walker is blocked in scan-queue backpressure, and the per-interval gate never emits two rows for one interval.
- **Threshold:** With YARA_HEARTBEAT_SECS=120 and YARA_HEARTBEAT_POLL_SECS=30: every consecutive pair of `running` rows has an event_timestamp_ms gap in [120s, 155s] (interval + one poll + slack); no two `running` rows fall within 120s of each other; control/running.json `updated_at` advances on the same cadence; zero `Heartbeat worker error: ` lines in scan_errors_<run_id>.log.
- **Setup:** Round 1's clean scan with YARA_THREADS=1 and YARA_QUEUE_SIZE=2 exported so discovery outruns the workers and the walker parks in _enqueue_scan_path's retry loop for minutes at a time — under a walker-only heartbeat that window would produce no rows at all.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "running" | fields event_timestamp_ms | sort asc event_timestamp_ms`; <scanner_dir>/control/running.json samples; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** HEARTBEAT_THREAD_POLL_SECS is only the poll cadence and must not itself emit: a repeat with YARA_HEARTBEAT_POLL_SECS=5 and YARA_HEARTBEAT_SECS=120 must keep the row gaps at ≥120s, not collapse them to ~5s.
- **Why this round:** Same reasoning as LIFE-024: emission is gated by SCANS_HEARTBEAT_SECS, a cadence, not by delivery load. The sharp test — a walker parked in scan-queue backpressure — is a Round 1 resource-discipline condition.

### `LIFE-027` Progress-heartbeat thread spanning the whole scan

*supporting*

- **Must be true:** A dedicated heartbeat thread emits progress for the WHOLE scan, not just for file discovery: `Scan Progress |` lines recur at log_interval from the start of scanning until shutdown, including after discovery has ended while workers are still draining the queue.
- **Threshold:** log_interval default 30s (YARA_PROGRESS_LOG_SECS, clamped to >=1). count(`Scan Progress | Files:`) in statistics_<run_id>.log >= floor(scan_summary.duration_secs / 30) - 2; every consecutive gap between those lines <= 45s; at least one `Scan Progress |` line is timestamped AFTER `=== ENHANCED CLEANUP AND FINALIZATION ===` in system_<run_id>.log and BEFORE the `Worker cleanup:` line in performance_<run_id>.log — that interval is where 'spans the whole scan, not just discovery' is actually decided, since the heartbeat is stopped only after the worker join; count(`System Resources | CPU:`) in performance_<run_id>.log == count(`Scan Progress | Files:`) in statistics_<run_id>.log; zero `Progress heartbeat error: ` lines in scan_errors_<run_id>.log.
- **Setup:** Round 1's clean scan on the Linux endpoint xdr-agent (psutil's process.io_counters() exists there, so the resource block is never partially skipped and the two counts are legitimately equal), with YARA_QUEUE_SIZE=20000 exported so a real worker backlog survives the end of file discovery. At the default queue size the walker is blocked by backpressure and the cleanup banner follows the last `Target scan completed:` within seconds, so no progress line can land after discovery on a correct build.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log, <scanner_dir>/logs/performance_<run_id>.log, <scanner_dir>/logs/scan_errors_<run_id>.log for the run_id.
- **Negative control:** The first `Scan Progress |` line must appear no earlier than (log_interval - 1s) after `=== ACTIVE SCANNING PHASE STARTED ===` — the thread waits a full interval before its first sample, but it is started a few statements BEFORE that banner is written, so a hard `>= log_interval` bound fails a correct build by milliseconds. A line at t~0 still means something other than the heartbeat is writing it.

### `LIFE-028` Shutdown sequence in _perform_enhanced_cleanup

*supporting*

- **Must be true:** Shutdown runs in a fixed order — banner, sentinels to workers, bounded join, worker-cleanup performance line, terminal lifecycle row, uploader stop, completion line — and the join is bounded by the 5s-per-thread literal, not by the 30 seconds the preceding log line claims.
- **Threshold:** By timestamp: `=== ENHANCED CLEANUP AND FINALIZATION ===` < `Initiating worker thread cleanup` < `Waiting for workers to terminate (max 30 seconds)` < performance `Worker cleanup: 2 stopped, 0 timed out in Z.Zs` < uploads `Alert delivery final: ` < system `Enhanced cleanup completed in N.N seconds`. The elapsed between the `Waiting for workers…` line and the `Worker cleanup:` line is ≤ 5.0 × max_workers seconds (≤10s at CONFIG_WORKERS=2) — never approaching 30s.
- **Setup:** Round 1's clean scan (standard delivery, default worker count).
- **Evidence:** Timestamps of the named lines in <scanner_dir>/logs/system_<run_id>.log, <scanner_dir>/logs/performance_<run_id>.log and <scanner_dir>/logs/uploads_<run_id>.log for the same run_id.
- **Negative control:** `Enhanced cleanup completed in` must be the LAST of the six — an `Alert delivery final:` timestamped after it would mean the uploaders were stopped outside the cleanup, which is the exact ordering bug the terminal-row placement depends on.
- **Why this round:** Round 3 lists shutdown ordering, but the ordering is only distinguishable when there is real work at each step — a full worker backlog to join and a real uploader drain to pay. Round 1's long clean scan supplies both; a 200-file crafted run collapses the whole sequence into one second.

### `LIFE-029` Worker-thread join timeout is non-fatal

*supporting*

- **Must be true:** The worker join is bounded per thread and non-fatal: shutdown never spends more than the 5s literal per worker, a timed-out worker is logged and skipped rather than aborting shutdown, and on a healthy run nothing times out.
- **Threshold:** performance_<run_id>.log line `Worker cleanup: X stopped, Y timed out in Z.Zs` with X == max_workers == 2, Y == 0, and X + Y == len(scan_threads) == max_workers; Z <= 5.0 x max_workers (<=10.0s at CONFIG_WORKERS=2) in every case — do NOT assert Z <= 1.0, since each worker must drain the files queued ahead of the sentinel while the governor paces it; zero `did not finish - continuing anyway` and zero `Threads did not terminate: ` lines in scan_errors_<run_id>.log; the run still produces its result line and scan_summary.
- **Setup:** Round 1's clean scan. All workers are daemon=True, so even a genuine hang cannot hold the process open past the join.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log `Worker cleanup: `; <scanner_dir>/logs/scan_errors_<run_id>.log; <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** X + Y must equal max_workers exactly. A build that lost a thread from the join list would still report `0 timed out` and pass a naive check, but would show X + Y == 1 here.
- **Why this round:** Worker-pool lifecycle belongs to Round 1. The positive case cannot be forced from outside — scan_file's stat gate rejects non-regular files (`Not a regular file`), so a FIFO or device node cannot hang a worker — so the criterion is written as the bounded/negative form Round 1 can actually decide.

### `LIFE-048` Root-logger INFO records land in diagnostics_<run_id>.log

*supporting*

- **Must be true:** Root-level INFO records emitted after setup_logging() reach logs/diagnostics_<run_id>.log and never reach stdout, whose budget is reserved for the single result line; WARNING and above additionally reach stderr.
- **Threshold:** After a completed run: logs/diagnostics_<run_id>.log exists, is non-empty, and contains 'Scan status changed to: scanning' and 'Comprehensive final report generated - Efficiency Score: '. Captured stdout contains exactly one non-empty line and it starts 'SCAN_RESULT: ' — zero occurrences of either diagnostics string. With YARA_MAX_MB=-1 exported: stdout is still exactly one line and stderr contains 'Ignoring out-of-range'. Records emitted BEFORE setup_logging (initial_cleanup's 'Starting initial cleanup of old data...', 'Log retention applied: ') appear in NO file — do not assert their presence.
- **Setup:** Round-1 clean scan launched over SSH on xdr-agent with `> out.txt 2> err.txt`. The Action Center payload cannot decide the stdout half (its footer prints, its stderr is not returned), so the stdout/stderr separation must come from the SSH run.
- **Evidence:** <scanner_dir>/logs/diagnostics_<run_id>.log; out.txt and err.txt from the SSH invocation; <scanner_dir>/logs/system_<run_id>.log for the two post-setup_logging category probes ('YARA Scanner initialization completed', '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ==='); the diagnostics FileHandler installed by setup_logging (level INFO) alongside the WARNING StreamHandler.
- **Negative control:** Text written through a categorized logger (propagate=False) must NOT be duplicated into diagnostics, probed with records emitted AFTER setup_logging: 'YARA Scanner initialization completed' (system category, run() line 7663) and '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===' (run() line 7852) must each appear exactly once in system_<run_id>.log and ZERO times in diagnostics_<run_id>.log. Do NOT use 'Enhanced Log Manager initialized with standardized logging' — LogManager.__init__ emits it before the diagnostics handler exists, so it can never land there either way.
- **Why this round:** Round 1 owns everything the scanner writes to the endpoint, including the seven log files and this eighth diagnostics sink; it is a footprint property, not an input-driven one.

### `LIFE-052` Dead/unused lifecycle constants and config attributes

*low*

- **Must be true:** track_real_paths is off for the whole run, so no file is ever skipped as a junction/symlink DUPLICATE and the real-path set stays empty — while genuine junction/symlink skips are still counted, proving the absence is the dormant dedup and not a broken walker.
- **Threshold:** Across every 'Scan Progress | Files: ' record in logs/statistics_<run_id>.log: data.metrics.unique_real_paths == 0 in every record; the final 'Skip reasons: ' record's data.skip_breakdown has no key 'Junction/symlink duplicate' (0 occurrences of that exact string in the whole logs/ tree); _log_final_results' data carries unique_paths_scanned == 0 and junction_skips consistent with the platform below. LIVE CONTROL — Windows (xdragent2) run whose target includes C:\Users (which carries the legacy 'Application Data' / 'My Documents' / 'Local Settings' junctions): data.skip_breakdown['Junction/symlink skip'] > 0 and data.metrics.junction_skips > 0 in the same run, while unique_real_paths is still 0. On xdr-agent (Linux) 'Junction/symlink skip' is legitimately 0 — /proc/ is skipped wholesale and the Linux predicate only matches /proc/self/fd|/proc/self/task — so there the live control must be a different populated reason instead (data.skip_breakdown['Skipped directory'] > 0 or ['No read permission'] > 0), proving the walker's skip accounting works while the dedup stays dormant.
- **Setup:** Round-1 clean scan on BOTH hosts: xdr-agent (Linux) for the dormant-dedup assertions plus a non-junction live skip reason, and xdragent2 (Windows) over C:\Users for the junction positive. Planting an ordinary symlink under a Linux decoy tree does NOT reach the predicate. The other five entries (WORKER_GET_TIMEOUT_SECS, light_profile, batch_size, performance_log_interval, statistics_upload_interval) have no reader anywhere and leave no artefact; they are not asserted.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log — the 'Scan Progress | Files: …' records' `| data={…}` blob (path data.metrics.unique_real_paths and data.metrics.junction_skips) and the 'Skip reasons: …' record's data.skip_breakdown.
- **Negative control:** On the Windows run 'Junction/symlink skip' (the live reason) must be present while 'Junction/symlink duplicate' (the dormant one) is absent — asserting the absence of the substring 'Junction/symlink' would fail a correct build. On the Linux run BOTH strings are absent, so the control there is the other populated skip reason: a run with zero entries in skip_breakdown would mean the walker never skipped anything, not that dedup is dormant.
- **Why this round:** Round 1 drives the progress heartbeats and the statistics log where the only observable half of this entry lives; the dead constants themselves are not testable in any round.

### `LIFE-054` logs/scanner_<run_id>.log — declared, cleaned, self-excluded, never written

*low*

- **Must be true:** The declared output_log is never created: after any run the logs directory holds the seven real per-run files (six LogManager categories plus yara_processing) and diagnostics, and no scanner_<run_id>.log, on any run_id.
- **Threshold:** After every Round-1 run: `ls <scanner_dir>/logs/scanner_*.log` returns nothing (exit 1 / zero matches) for every run_id present in the directory; the same directory contains exactly one each of alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_ and diagnostics_ for the current run_id, plus scan_summary_<run_id>.json.
- **Setup:** None beyond the standard Round-1 run; take the listing before host cleanup can remove anything (CONFIG_HOST_CLEANUP defaults to 'off').
- **Evidence:** `ls <scanner_dir>/logs/` after the run; the Logging Summary record's data.log_files_created map in <scanner_dir>/logs/system_<run_id>.log, which must list exactly the six category paths and must NOT list scanner_<run_id>.log.
- **Negative control:** The eight files that DO exist must all be present and non-empty in the same listing — asserting only the absence of scanner_*.log would also pass on a run that wrote nothing at all.
- **Why this round:** Round 1 owns the scanner-directory layout and the per-run log file set; this is a pure footprint assertion.

### `LIFE-057` Log retention across runs (keep last N scans) plus orphan-temp sweep

*core*

- **Must be true:** Retention bounds the endpoint's observability window to the newest N run_ids across BOTH logs and JSON summaries, always keeps the current run, and sweeps orphaned scan_summary_*.tmp files — it never deletes a run inside the window.
- **Threshold:** With YARA_LOG_KEEP=2 exported and four short sequential scans: after the fourth, the set of run_ids derivable from <scanner_dir>/logs/*.log and *.json (regex _(\d{8}_\d{6}_\d{6})\.(log|json)$) has exactly 2 members, one of which is the fourth run's run_id; the planted logs/scan_summary_19700101_000000_000000.json.tmp is gone; zero 'Cannot remove log file' warnings on stderr. With YARA_LOG_KEEP unset (default 10): all four run_ids survive. With YARA_LOG_KEEP=0: exactly 1 run_id survives (the floor is max(1, …), not 0).
- **Setup:** Four short Round-1 scans launched over SSH on xdr-agent with `YARA_LOG_KEEP=2` exported in the environment — LOG_KEEP_SCANS is read at MODULE scope, so an Action Center snippet prelude runs too late to change it (the prelude executes after the module body). Plant logs/scan_summary_19700101_000000_000000.json.tmp before the run. The 'Log retention applied: kept last N scans …' line is emitted by logging.info from initial_cleanup, which runs BEFORE setup_logging installs the diagnostics sink, so it reaches no file — decide this on the directory listing, not on that line.
- **Evidence:** `ls <scanner_dir>/logs/` before and after each of the four runs, reduced to distinct run_ids; the absence of the planted .json.tmp; stderr for 'Cannot remove log file (in use): <path>', 'Cannot remove log file <path>: <e>' and 'Log retention: N log files could not be removed'.
- **Negative control:** Files that do not match the run_id regex — <scanner_dir>/rule_cache/*, cleanup_script.sh, and a planted logs/README.txt — must all survive every retention pass; retention must prune only per-run .log/.json artefacts.
- **Why this round:** Round 1 explicitly drives rotation and retention as part of the host footprint, and it is the only round that runs the same shape repeatedly enough to fill and overflow the window.

### `LIFE-058` initial_cleanup — previous run's alert/evidence wiped at scan start

*supporting*

- **Must be true:** Each scan starts from empty alert/ and evidence/ directories — the previous run's alert texts and evidence ZIP are removed and both directories recreated — while the retained logs of other runs are untouched.
- **Threshold:** Plant <scanner_dir>/alert/ZZZ_planted.txt and <scanner_dir>/evidence/ZZZ_planted.bin immediately before the run: after the run both planted files are absent (0 files matching ZZZ_planted*), alert/ and evidence/ both exist, and evidence/ contains only this run's evidence_<hostname>_<run_id>.zip and file_mapping.txt. system_<run_id>.log contains exactly one 'Initial cleanup completed' line (the run()-side record; initial_cleanup's own 'Initial cleanup completed successfully' is logging.info emitted before setup_logging and reaches no file — do not assert it).
- **Setup:** Round-1 clean scan, with the two planted files created immediately before delivery. To exercise the locked-file branch on Windows, repeat on xdragent2 holding an open handle on an alert/*.txt and check stderr.
- **Evidence:** `ls <scanner_dir>/alert/ <scanner_dir>/evidence/` before and after; <scanner_dir>/logs/system_<run_id>.log line 'Initial cleanup completed'; stderr warning 'Cannot remove <path> - may be in use' on the locked-file variant.
- **Negative control:** A previous run's retained logs (logs/*_<older run_id>.log within the LOG_KEEP_SCANS window) and <scanner_dir>/rule_cache/ must still be present after initial_cleanup — the wipe is scoped to alert/, evidence/ and output_log, and must not reach into logs/ or the rule cache.
- **Why this round:** Round 1 owns the scanner-directory layout and the start-of-run wipe that defines the endpoint's steady-state footprint.

### `LIFE-059` schedule_final_cleanup gating (critical errors / error ratio / no alerts)

*supporting*

- **Must be true:** The scheduled cleanup unit is installed only when this run actually produced alert files: a run with zero alerts records the skip and installs nothing, while a run with at least one alert/*.txt writes the cleanup script and schedules the platform unit.
- **Threshold:** Run A (clean scan, zero matches): system_<run_id>.log contains 'No alerts found, skipping cleanup scheduling' exactly once and does NOT contain 'Cleanup script decoded and ready for scheduling'; <scanner_dir>/cleanup_script.sh|.bat does not exist afterwards. Run B (same host, one planted file matching a trivial rule): system_<run_id>.log contains 'Cleanup script decoded and ready for scheduling' and the platform line ('Linux cleanup service scheduled successfully' / 'Windows cleanup task scheduled successfully' / 'macOS cleanup LaunchDaemon scheduled') exactly once each, and cleanup_script.sh|.bat exists. Both runs: 'Cleanup task/service scheduled successfully' appears exactly once — run() logs it unconditionally after the call returns, so it is NOT evidence that anything was scheduled; and 0 occurrences of 'Error scheduling cleanup: ' in scan_errors_<run_id>.log.
- **Setup:** Two Round-1 deliveries on the same endpoint. Delete <scanner_dir>/cleanup_script.* before run A — neither initial_cleanup nor host cleanup removes it, so a leftover from an earlier run would falsify the absence check. Run B needs one planted file under the target that the pack matches. Deliver via Action Center (payload runs as root/SYSTEM) so the scheduling call is not refused for privilege reasons.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log lines 'No alerts found, skipping cleanup scheduling', 'Cleanup script decoded and ready for scheduling', '<platform> cleanup … scheduled …', 'Cleanup task/service scheduled successfully'; presence/absence of <scanner_dir>/cleanup_script.bat|.sh; `ls <scanner_dir>/alert/*.txt`.
- **Negative control:** The suppressor is alerts-only: run A must still schedule nothing even though it completed successfully, and run B must schedule even though it produced compile warnings — a run with failed rules but at least one valid rule and one alert must NOT hit the 'No valid YARA rules compiled - skipping cleanup to preserve diagnostics' branch.
- **Why this round:** Round 1 explicitly drives host cleanup and its scheduled units; the gate is about what the scanner leaves installed on the endpoint.

### `LIFE-060` Cleanup script generated from the real alert dir (path-drift fix)

*supporting*

- **Must be true:** The generated cleanup script targets THIS deployment's real alert directory — the path it cd's into equals <scanner_dir>/alert exactly — so the scheduled rename actually operates on the files the scanner wrote.
- **Threshold:** POSIX: <scanner_dir>/cleanup_script.sh is mode 0755, its first line is '#!/bin/bash', and its second line is exactly `cd "<scanner_dir>/alert" || exit 0`, with <scanner_dir> taken from data.log_files_created in the 'Logging Summary' record of system_<run_id>.log (or from YARA_SCANNER_DIR / the platform default) — scan_summary carries no paths — and never the historical hardcoded /opt/xdr-data. Windows: cleanup_script.bat contains `cd /d "<scanner_dir>\alert"` and the line `ren *.txt *.alert`. Rename proof, Linux: the scanner itself starts the oneshot unit during the run, so after the scan alert/ holds 0 *.txt and K *.alert, where K equals the number of `alerts/*.txt` members in this run's evidence ZIP (packaged at line 4740, before scheduling). Rename proof, Windows: list alert/ immediately after the scan (K *.txt, 0 *.alert), run `schtasks /run /tn CleanupScript`, list again (0 *.txt, K *.alert).
- **Setup:** The alert-producing Round-1 run (run B of LIFE-059). On Linux do NOT expect to observe the pre-rename state — take K from `unzip -l <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip | grep '^.*alerts/'`. On Windows record `ls <scanner_dir>/alert/` immediately after the scan, then `schtasks /run /tn CleanupScript`, then list again.
- **Evidence:** The literal contents of <scanner_dir>/cleanup_script.sh|.bat; data.log_files_created in the 'Logging Summary' record of <scanner_dir>/logs/system_<run_id>.log (to resolve the real <scanner_dir>); `unzip -l <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` for the alerts/*.txt member count; `ls <scanner_dir>/alert/` after the scan (and before/after the schtasks run on Windows).
- **Negative control:** With an overridden YARA_SCANNER_DIR the generated cd path must follow it — a script still naming the default directory is the path-drift regression this exists to prevent.
- **Why this round:** Round 1 owns host cleanup and its scheduled units; the script is an artefact left on the endpoint.

### `LIFE-061` Platform-specific cleanup scheduling and its non-fatal failure modes

*supporting*

- **Must be true:** The scheduled unit installed matches the platform, and a scheduling failure is non-fatal — the scan still returns its normal completed result line rather than failing.
- **Threshold:** Linux (Action Center delivery, runs as root): /etc/systemd/system/yara-cleanup.service exists, is owned by uid 0, and `systemctl is-enabled yara-cleanup.service` succeeds. Windows (xdragent2): `schtasks /query /tn CleanupScript` exits 0. macOS: /Library/LaunchDaemons/com.yarascanner.cleanup.plist exists and `launchctl list` shows com.yarascanner.cleanup. Non-root variant (SSH, YARA_SCANNER_DIR overridden to a user-writable path): err.txt carries exactly one of 'Linux cleanup scheduling requires root - skipping (cosmetic only)' / 'macOS cleanup scheduling requires root…' / 'systemctl not found - skipping Linux cleanup scheduling (cosmetic only)'; /etc/systemd/system/yara-cleanup.service is NOT created (or is unchanged from before the run); under the OVERRIDDEN scanner dir the full eight-file log set and scan_summary_<run_id>.json are present, $OVERRIDE/logs/scan_errors_<run_id>.log has 0 'Error scheduling cleanup: ' lines, and the result line still begins 'Scan completed:'.
- **Setup:** The alert-producing Round-1 run delivered twice: once through Action Center (root/SYSTEM) against the default /opt/yara_scanner for the positive case, and once over SSH on xdr-agent as the ordinary gcloud SSH user (NOT `ayman`, which is the xdragent2 Windows account) with `YARA_SCANNER_DIR=$HOME/yara_scanner_nonroot` exported so the scanner has a writable working directory, and `2> err.txt`. Remove any pre-existing unit file/task before the root run.
- **Evidence:** /etc/systemd/system/yara-cleanup.service (+ `stat -c %u`), `schtasks /query /tn CleanupScript`, /Library/LaunchDaemons/com.yarascanner.cleanup.plist; err.txt for the privilege warnings; $YARA_SCANNER_DIR/logs/scan_errors_<run_id>.log for 'Error scheduling cleanup: '; the SCAN_RESULT line.
- **Negative control:** The non-root run must still complete and still write its full log set and scan_summary — a scheduling failure that turned the run into 'Scan failed' would be the regression.
- **Why this round:** Round 1 explicitly drives host cleanup and its scheduled units, which are persistent artefacts installed on the customer endpoint.

### `LIFE-062` End-of-run host cleanup — opt-in deletion of this run's working files

*core*

- **Must be true:** With host cleanup enabled, a completed run removes THIS run's working files per the keep tier and nothing else: this run's per-run logs go, the summary survives under keep=summary, another run's retained logs and the rule cache survive, and alert/ evidence/ failed_rules/ come back existing and empty.
- **Threshold:** keep='summary', mode='always', completed run: 0 files matching logs/*_<run_id>.log (including yara_processing_<run_id>.log and diagnostics_<run_id>.log), logs/scan_summary_<run_id>.json still present and json-parseable; the previous run's logs/*_<older run_id>.log all still present, byte count unchanged; <scanner_dir>/rule_cache/ unchanged (same file list and mtimes); alert/, evidence/ and failed_rules/ all exist and contain 0 entries. keep='nothing': the summary is gone too. keep='evidence': evidence/ retains this run's evidence_<hostname>_<run_id>.zip while alert/ and failed_rules/ are emptied. Default (CONFIG_HOST_CLEANUP='off'): nothing is removed on any run.
- **Setup:** Three Round-1 deliveries with the snippet prelude rebinding the module constants before run() is called — prelude="CONFIG_HOST_CLEANUP='always'; CONFIG_HOST_CLEANUP_KEEP='summary'" (then 'nothing', then 'evidence'). They are deliberately NOT reachable through the options string (_parse_options_string rejects unknown keys against _VALID_OPTION_KEYS), so the prelude or an edited constant is the only delivery. Take a full `find <scanner_dir> -type f` listing before and after each run.
- **Evidence:** `find <scanner_dir> -type f` before/after each run; <scanner_dir>/logs/scan_summary_<run_id>.json (must survive under summary/evidence, must be gone under nothing); the directory entries of alert/, evidence/, failed_rules/, rule_cache/; stderr 'host cleanup could not remove <path>: <err>' and 'Host cleanup failed: …'. Note the affirmative 'Host cleanup removed N path(s)' line is logging.info emitted AFTER close_diagnostics_handler() has detached the file sink, so it reaches no file and no stderr — decide this on the filesystem, not on that line.
- **Negative control:** Another run's logs inside the LOG_KEEP_SCANS window and <scanner_dir>/rule_cache must be byte-identical before and after — host cleanup is scoped to this run_id plus the three wholesale directories, and must never reach into retained history or the cross-run compile cache.
- **Why this round:** Round 1 explicitly drives host cleanup; the affirmative removal path requires a completed run with delivery intact, which is Round 1's clean shape.

### `LIFE-064` Log handlers closed BEFORE host cleanup because Windows refuses to delete open files

*supporting*

- **Must be true:** On Windows, all eight per-run file handlers are closed before host cleanup unlinks the logs — so a cleaned run leaves no *_<run_id>.log behind, including the two that are not LogManager's (yara_processing and diagnostics).
- **Threshold:** On xdragent2, completed run with prelude CONFIG_HOST_CLEANUP='always', keep='summary': `dir C:\yara_scanner\logs\*_<run_id>.log` returns 0 files — specifically 0 for yara_processing_<run_id>.log and 0 for diagnostics_<run_id>.log; scan_summary_<run_id>.json survives; stderr contains 0 lines matching 'host cleanup could not remove' and 0 containing 'WinError 32'.
- **Setup:** Deliver the scan to xdragent2 (Windows) with prelude="CONFIG_HOST_CLEANUP='always'"; run it over SSH as `ayman` (PowerShell) redirecting stderr to a file, so the WinError signature is capturable. Repeat once on xdr-agent (Linux) to confirm the ordering is not Windows-only cosmetic — POSIX unlinks open files, so a Linux pass alone cannot decide this.
- **Evidence:** Directory listing of C:\yara_scanner\logs filtered to the run_id; presence of scan_summary_<run_id>.json; captured stderr for 'host cleanup could not remove <path>: [WinError 32]…'.
- **Negative control:** Another run's retained logs on the same Windows host must survive the same cleanup — a handler-closing regression shows up as exactly the current run's files surviving, so the control distinguishes 'nothing was deleted' from 'this run was deleted'.
- **Why this round:** Round 1 owns host cleanup and the per-run log file set; the ordering is a footprint property of the shutdown path, not an input-driven one.

### `LIFE-065` stop_logging idempotence and the final logging summary

*supporting*

- **Must be true:** Logging is finalised exactly once per run despite stop_logging being reachable from three places (the host-cleanup block, the unconditional finally call, and __del__): exactly one Logging Summary record is written, it is the last line of the system log, and its per-type counts reconcile with its total.
- **Threshold:** Exactly 1 line matching 'Logging Summary \| Total Logs: [0-9]+' in <scanner_dir>/logs/system_<run_id>.log, and it is the file's last non-empty line; sum(data.logs_by_type.values()) == data.total_logs_generated == the N printed in the message; data.log_files_created has exactly 6 entries (alert, statistics, error, performance, upload, system) and every path it names exists on disk.
- **Setup:** A single standard Round-1 completed run with CONFIG_HOST_CLEANUP at its 'off' default, so the system log survives to be read. Do NOT add a host-cleanup-enabled repeat: stop_logging is already called twice on every completed run (once from the finally's completed-outcome block ahead of the should_run gate, once from the unconditional call below it), and enabling host cleanup deletes system_<run_id>.log before the assertion can be made.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log final record 'Logging Summary | Total Logs: N | data={"log_files_created": {...}, "logs_by_type": {...}, "total_logs_generated": N}'.
- **Negative control:** The count must be exactly 1, not >=1 — two Logging Summary lines are the specific regression (a lost _stopped guard), and a run with zero would mean the finally block never reached it.
- **Why this round:** Round 1 owns the per-run log lifecycle and what the scanner leaves on disk.

### `LIFE-066` Monitoring lifecycle and its stop-once guards

*supporting*

- **Must be true:** Both optional monitors are OFF by default and are announced as such, both flip on when their env toggle is set, and each is stopped exactly once per run despite stop_monitoring being reachable from cleanup, the finally block and __del__.
- **Threshold:** Default run: statistics_<run_id>.log contains exactly 2 'Performance monitoring disabled in light profile' lines (StatisticsManager.__init__ line 1988 and run() line 7712 both call start_monitoring, and the disabled branch is unguarded) and 0 'Performance monitoring thread started'; system_<run_id>.log contains 0 'System resource monitoring started' AND 0 'System resource monitoring disabled in light profile' (the monitor object is never constructed when the toggle is off, so neither line can appear — asserting the 'disabled' line would fail a correct build); the comprehensive report's data blob has no 'resource_summary' key. Toggled run (YARA_ENABLE_PERF_MONITOR=true, YARA_ENABLE_RESOURCE_MONITOR=true): exactly 1 'Performance monitoring thread started' (the second start_monitoring call finds the thread alive and logs nothing), 0 'disabled in light profile', exactly 1 'System resource monitoring started', exactly 1 'Resource monitoring completed: N snapshots, M alerts' in performance_<run_id>.log with N > 0, and 'resource_summary' present in the report. Both runs: exactly 1 '=== Statistics Manager Stopped ===' in statistics_<run_id>.log and exactly 1 '=== Performance Monitoring Ended ===' in performance_<run_id>.log.
- **Setup:** Two Round-1 scans of the same duration on xdr-agent, the second with prelude="import os; os.environ['YARA_ENABLE_PERF_MONITOR']='true'; os.environ['YARA_ENABLE_RESOURCE_MONITOR']='true'" — both are read at ScanConfig.__init__, which runs inside run(), so the snippet prelude reaches them.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log ('Performance monitoring disabled in light profile' / 'Performance monitoring thread started' / '=== Statistics Manager Stopped ==='); <scanner_dir>/logs/system_<run_id>.log ('System resource monitoring started'); <scanner_dir>/logs/performance_<run_id>.log ('=== Performance Monitoring Ended ===', 'Resource monitoring completed: …'); the 'COMPREHENSIVE SCAN REPORT | Efficiency Score:' data blob for the resource_summary key.
- **Negative control:** The 2-vs-1 asymmetry is itself the control: two 'disabled in light profile' lines prove BOTH start_monitoring call sites ran, while one 'thread started' line proves the started branch is guarded by the is_alive() check. A build emitting only one disabled-line would mean a call site was dropped; two 'thread started' lines would mean the guard was lost. Separately, the stop lines must appear exactly once on BOTH runs — StatisticsManager.stop_monitoring's _stopped guard must hold whether or not the monitor thread was ever started, so a build that only guards the started case fails on the default run.
- **Why this round:** Round 1 explicitly drives memory/psutil sampling and performance snapshots; a long clean scan is what gives the monitors time to reach steady state.

### `LIFE-067` File-descriptor monitoring setup block (POSIX only, off by default)  <sub>linux, darwin</sub>

*supporting*

- **Must be true:** With FD monitoring enabled on POSIX the preflight records the limit and the baseline FD count, and the scan itself does not leak descriptors — no growth line is ever emitted across a whole-tree scan; with it disabled, none of those lines exist at all.
- **Threshold:** Enabled run on xdr-agent: exactly 1 'Current file descriptor limit: N' and exactly 1 'Initial file descriptors in use: M' in system_<run_id>.log, with N == the host's `ulimit -n`; 'WARNING: Low file descriptor limit (N)' present iff N < 8192; across the whole scan 0 occurrences of 'FD usage increased by ' and 0 of 'WARNING: High FD usage: ' (a leak would need >100 net FDs above baseline or >900 total). Default run: 0 occurrences of all four strings. Windows run with the toggle on: 0 occurrences (the whole block is POSIX-gated and _maybe_sample_fds returns early on Windows).
- **Setup:** Three Round-1 deliveries: xdr-agent default, xdr-agent with prelude="import os; os.environ['YARA_ENABLE_FD_MONITOR']='true'", and xdragent2 with the same prelude. The scan must exceed 1000 files processed so the fd_check_interval=1000 sampler actually fires at least once.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log lines 'Current file descriptor limit: N', 'WARNING: Low file descriptor limit (N)', 'Initial file descriptors in use: M', 'FD usage increased by K (current: C)', 'WARNING: High FD usage: C'; the host's `ulimit -n`; scan_summary.files_scanned to confirm >1000 files were processed.
- **Negative control:** The two preflight lines must be PRESENT on the enabled run while the two growth lines are ABSENT — asserting the growth lines would fail a correct (non-leaking) build, and asserting nothing at all would pass a build where the toggle silently did nothing.
- **Why this round:** Round 1 explicitly drives FD monitoring; a long, wide, mostly-clean walk is the only shape that could expose a descriptor leak.

### `LIFE-073` Remaining-thread join in the successful path

*low*

- **Must be true:** A completed run reaches its terminal banner with the worker pool wound down: the banner is written exactly once, and any thread still alive at that point is bounded-joined rather than abandoned or waited on indefinitely.
- **Threshold:** Completed Round-1 run: exactly 1 '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===' line in system_<run_id>.log, and it is the last system record before the 'Logging Summary | Total Logs:' record. The system records immediately preceding it are 'Evidence collection completed successfully' and 'Cleanup task/service scheduled successfully' — the banner must follow both, proving the join ran after, not instead of, the tail of run(). If a 'Waiting for N remaining threads to terminate' line is present then N >= 1 and the banner's timestamp is at most 2*N seconds later (join timeout=2s per thread); that 2s-per-thread bound applies ONLY to this gap and must NOT be applied to the distance from 'Enhanced cleanup completed in Xs', which is separated by evidence packaging and cleanup scheduling. Cancelled and failed runs: 0 occurrences of the banner.
- **Setup:** The standard Round-1 long scan, plus the Round-3 cancelled and failed runs for the absence half. Compare the '[YYYY-MM-DD HH:MM:SS.mmm]' prefixes of consecutive system-log records.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log lines 'Evidence collection completed successfully', 'Cleanup task/service scheduled successfully', 'Waiting for N remaining threads to terminate' and '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===' with their '[YYYY-MM-DD HH:MM:SS.mmm]' prefixes, plus the trailing 'Logging Summary | Total Logs: N' record.
- **Negative control:** 'Waiting for N remaining threads to terminate' is emitted only when at least one thread is still alive after _perform_enhanced_cleanup's join; a healthy run normally emits none, so requiring its presence would fail a correct build.
- **Why this round:** Round 1 drives worker pool sizing and lifecycle; the thread-join tail is only meaningful after a long scan with a full pool.

### `LIFE-075` Run identity: run_id, scan_id and their propagation

*core*

- **Must be true:** Every run has one identity that every artefact agrees on: run_id names all nine per-run files, scan_id embeds that run_id, and the same pair appears in the summary, the liveness marker and the tenant rows — two runs of the same pack never collide.
- **Threshold:** Single run: run_id matches ^\d{8}_\d{6}_\d{6}$; scan_id == '<hostname>_<run_id>_yara_<12 hex>' where the 12 hex are the first 12 chars of sha256(decoded rule text) computed independently; every file under logs/ for this run ends '_<run_id>.log' or '_<run_id>.json'; scan_summary.run_id/scan_id match; <scanner_dir>/control/running.json (read mid-run) carries the same scan_id and run_id; XQL over yara_scanner_scans_v3_* and yara_scanner_matches_v3_* for this scan_id returns rows whose run_id column equals run_id, and 0 rows carrying a different scan_id for the same run_id. Two back-to-back runs of the identical pack on one host: 2 distinct run_ids and 2 distinct scan_ids, with the same trailing 12-hex rule-hash prefix in both.
- **Setup:** Two sequential Round-1 scans with the identical base64 pack; capture <scanner_dir>/control/running.json while the first is still walking; compute sha256 of the decoded pack locally for comparison. Note scan_summary has no rule_hash field in this edition — take the hash prefix from scan_id and from the yara_processing 'Scan ID: … (rule hash: …)' line.
- **Evidence:** run_id/scan_id in <scanner_dir>/logs/scan_summary_<run_id>.json; `ls <scanner_dir>/logs/`; <scanner_dir>/control/running.json; <scanner_dir>/logs/yara_processing_<run_id>.log line 'Scan ID: <scan_id> (rule hash: <12hex>...)'; XQL over yara_scanner_scans_v3_* and yara_scanner_matches_v3_* filtered on scan_id.
- **Negative control:** The two runs must NOT share a scan_id even though the rule text (and therefore the hash prefix) is identical — a scan_id keyed on the ruleset alone is the collision this design replaced.
- **Why this round:** Round 1 is foundational and stop-on-fail: run_id is what names the log set, drives retention's regex and selects host cleanup's files, so LIFE-057/062/064 all measure nothing if identity is broken.

### `LIFE-076` Scanner version self-identification

*low*

- **Must be true:** Every run identifies the build it came from in two independent places that agree: the machine-readable summary and the yara_processing header.
- **Threshold:** scan_summary_<run_id>.json scanner_version == '3.3.0'; yara_processing_<run_id>.log contains exactly one line 'YARA Scanner VERSION 3.3.0 (released 2026-08-17)'; the two version strings are identical.
- **Setup:** None — any Round-1 run reaches both.
- **Evidence:** scanner_version in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/logs/yara_processing_<run_id>.log line 'YARA Scanner VERSION <version> (released <date>)'.
- **Negative control:** A run whose scan crashed before the scanner existed still writes the yara_processing VERSION line (ScanConfig emits it) but no summary — so the two sources are not redundant, and the summary field must not be the only assertion.
- **Why this round:** Round 1 is the first round to touch the endpoint and is where the deployed build must be pinned before any other result is attributable.

### `LIFE-078` "All monitoring systems activated" — the run's monitoring and delivery switch record (and why performance_metrics is all zeros)

*supporting*

- **Must be true:** One record states exactly which optional subsystems were live for this run, and it tells the truth: with the performance monitor off the end-of-run performance block is structurally empty, and with it on the same block carries real samples.
- **Threshold:** Default run: exactly 1 'All monitoring systems activated' record in system_<run_id>.log with data.statistics_monitoring == true, data.performance_monitoring == false, data.resource_monitoring == false, data.match_upload_enabled == true, data.worker_threads == init_data.max_workers, data.cpu_guarantee == scan_summary.throttle_mode; and in the same run's 'Scan completed successfully in …' record, data.performance_metrics.performance_metrics.{peak_cpu_percent, avg_cpu_percent, peak_memory_mb, avg_memory_mb, io_efficiency} are all 0.0 with data.performance_metrics.current_performance null. Monitor-on run (YARA_ENABLE_PERF_MONITOR=true): data.performance_monitoring == true, peak_cpu_percent > 0 and current_performance non-null; io_efficiency stays 0.0 in both runs.
- **Setup:** Two Round-1 scans under the same load, the second with prelude="import os; os.environ['YARA_ENABLE_PERF_MONITOR']='true'". Note the nesting: comprehensive_final_stats['performance_metrics'] is the WHOLE get_current_stats_for_upload() dict, so the metric path is data.performance_metrics.performance_metrics.<field>.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log records 'All monitoring systems activated | data={…}' and 'Scan completed successfully in … | data={…}'; the mirrored 'SCAN COMPLETED SUCCESSFULLY in …' record in statistics_<run_id>.log; init_data.max_workers; throttle_mode in scan_summary_<run_id>.json.
- **Negative control:** The zeros must be accompanied by a non-empty rest-of-record (files_processed, total_detections, log_generation_stats populated) — an all-zero comprehensive block would mean the stats manager died, not that the optional monitor was off.
- **Why this round:** Round 1 drives the monitors and the psutil sampling this record describes; the flood would change the very numbers being compared.

### `LIFE-081` init_data initialisation disclosure record — emitted twice, includes the tenant API URL

*low*

- **Must be true:** The initialisation disclosure is emitted twice under two different messages carrying one and the same payload, and that payload truthfully names the credential sources and the tenant URL this run would have delivered to.
- **Threshold:** In system_<run_id>.log: exactly 1 'YARA Scanner initialization completed' and exactly 1 'YARA Scanner initialized successfully'; the `| data={…}` blob of the two lines is byte-identical; neither blob ends with '...(truncated)'; data.xdr_api_url equals the tenant base URL the run delivered to (same host as the datasets named in scan_summary.matches_dataset were created under); data.xdr_api_key_source, xdr_api_id_source and xdr_api_url_source are all 'default' on a snippet-injected build; data.upload_enabled == true and data.match_only_upload_mode == true.
- **Setup:** Any Round-1 run. If the blob ends '...(truncated)' (LogManager._log caps at 4000 chars and sort_keys pushes the xdr_* keys near the end), reduce the target list and re-run before concluding a field is missing.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log records 'YARA Scanner initialization completed | data={…}' and 'YARA Scanner initialized successfully | data={…}'; matches_dataset / scans_dataset in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** An unconfigured build (placeholder credentials) never reaches these records at all — it returns the 'SCAN ABORTED — XDR API credentials are not set' line first — so their presence is itself proof that credential resolution succeeded.
- **Why this round:** Round 1 owns what the scanner writes on the endpoint; this record is a disclosure artefact, not an input-driven behaviour.

### `LIFE-082` A failed category logger silently falls back to the root logger

*supporting*

- **Must be true:** No category log channel is silently lost: every path the run names as a created log file actually exists on disk and is non-empty, so a scan that lost a channel cannot be mistaken for one that had nothing to say.
- **Threshold:** After every run in the round: for each of the 6 paths in the Logging Summary record's data.log_files_created, the file exists and is > 0 bytes; the set of those 6 basenames equals {alerts_,statistics_,scan_errors_,performance_,uploads_,system_}_<run_id>.log; captured stderr contains 0 lines matching 'Failed to setup logger for ' and 0 matching 'Failed to setup error logger: '; and diagnostics_<run_id>.log contains ZERO occurrences of category text emitted AFTER setup_logging — specifically 'YARA Scanner initialization completed' (system category, run() line 7663) and '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===' (run() line 7852) — each of which must appear exactly once in system_<run_id>.log. A category logger that fell back to the root logger would duplicate exactly those records into diagnostics. Do NOT probe with 'Enhanced Log Manager initialized with standardized logging': LogManager.__init__ emits it before the diagnostics handler exists, so it can never land there either way.
- **Setup:** No fault injection — this is asserted as an invariant over every Round-1 run, from the SSH invocation so stderr is captured. There is no supported way to make one FileHandler fail while the other seven succeed (the run_id is not known before the run, so the target filename cannot be pre-blocked), which is why the criterion is a negative one.
- **Evidence:** data.log_files_created in the 'Logging Summary | Total Logs: N' record of <scanner_dir>/logs/system_<run_id>.log; `ls -l` of the six named paths; captured stderr; grep of <scanner_dir>/logs/diagnostics_<run_id>.log for the two post-setup_logging system-category strings 'YARA Scanner initialization completed' and '=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ==='.
- **Negative control:** diagnostics_<run_id>.log must still contain its own root-logger INFO lines ('Scan status changed to: ', 'Comprehensive final report generated - Efficiency Score: ') — the assertion is that CATEGORY text is absent from it, not that the file is empty.
- **Why this round:** Round 1 owns the seven per-run log files; the degradation this guards against is a footprint/observability property that every subsequent round's evidence depends on, so it belongs to the stop-on-fail round.

---

# Round 2 — Delivery, aggregation and telemetry under load

106 capabilities · 44 core · `xdr-agent` (Ubuntu 22.04), `xdragent2` (Windows Server 2022) · collect-through

## Rule Handling

### `RULE-063` Rule identity in the delivered alert name

*core*

- **Must be true:** The alert name identifies the FINDING — rule, file basename, a stable 8-hex hash of the full path, and host — so two same-named files in different directories are two alerts, and re-running the identical scan mints none.
- **Threshold:** Measured on a BOUNDED repeat pair, not the full flood: a subtree whose distinct (rule, file) findings are fewer than CONFIG_ALERT_MAX_PER_SCAN (500), containing the two byte-identical planted copies, run twice against the same host. Both runs must show alert_delivery.suppressed == 0 and alert_delivery.rollups == 0, so every finding alerted. Then: every non-rollup alert_name for those scans matches `^YARA Match: <rule> \| <basename> \(#[0-9a-f]{8}\) \| Host: <hostname>$`; the two planted copies yield exactly 2 distinct alert_names differing only in the 8-hex tag; the SET of distinct alert_names for that host is identical between run 1 and run 2 (0 new names), while alert_delivery.findings on run 2 equals run 1's and is > 0 — the alerts were re-sent and merged, not skipped. The naming shape may additionally be sampled on the flood run, but the idempotency count may not.
- **Setup:** Round 2 flood tree containing byte-identical copies of one matching decoy at <tree>/dirA/decoy_same_name.bin and <tree>/dirB/decoy_same_name.bin; run the flood twice against the same host.
- **Evidence:** alert_name values on the Insert Parsed Alerts side, filtered to this hostname and the two scan windows; `alert_delivery.findings` and `alert_delivery.successful_uploads` in logs/scan_summary_<run_id>.json for both runs.
- **Negative control:** Rollup alerts from the flood run must be named `YARA Match Storm: <rule> | Host: <hostname>` — no basename, no path tag. If the path tag appears on rollups too, the identity is being built from the wrong branch and a storm would mint one rollup per file. Additionally, on the bounded pair both planted copies must appear inside alert_delivery.findings (suppressed == 0 on both runs), so a missing alert_name is never explained away by the cap.

### `RULE-064` Per-rule storm rollup alert

*core*

- **Must be true:** Past the per-scan alert cap the alert channel stops queuing per-finding alerts and queues exactly one rollup per rule that had suppressions, and the alert books reconcile across the cap.
- **Threshold:** alert_delivery.findings == 500 exactly (CONFIG_ALERT_MAX_PER_SCAN); alert_delivery.suppressed == (distinct (rule, file) findings in the run) − 500; alert_delivery.rollups == the number of distinct rules with at least one suppressed finding; alert_delivery.alerts_queued == findings + rollups; logs/uploads_<run_id>.log carries 'Queued R storm-rollup alert(s) covering S suppressed finding(s)' with R == rollups and S == suppressed; the tenant shows exactly R alerts whose alert_name begins 'YARA Match Storm:'.
- **Setup:** Round 2 flood sized to produce at least 900 distinct (rule, file) findings spread across at least 4 rules, so several rules exceed the cap and the rollup count is greater than 1.
- **Evidence:** the `alert_delivery` object in logs/scan_summary_<run_id>.json (keys findings, suppressed, rollups, alerts_queued); logs/uploads_<run_id>.log line 'Queued N storm-rollup alert(s) covering M suppressed finding(s)'; alert_name search on the tenant for 'YARA Match Storm:'.
- **Negative control:** A run under the cap (Round 3's crafted scan, well below 500 findings) must show suppressed == 0, rollups == 0, alerts_queued == findings, and zero 'YARA Match Storm:' alerts on the tenant. Otherwise 'the cap fired' is indistinguishable from 'the cap fires always'.

### `RULE-065` Rule name as a first-class dataset column

*core*

- **Must be true:** Each (rule, file) finding is ONE dataset row carrying the rule name, the TRUE offset total, a sample capped at CONFIG_LOOKUP_ROWS_PER_FINDING_MAX, and a truncation flag — so the real count stays queryable even when the embedded sample is capped.
- **Threshold:** For a planted file matched at exactly 200 offsets by one rule: exactly 1 row for that (scan_id, rule, filename); match_count == 200; the `offsets` JSON array has length 50 and `strings` has length 50 (default cap); truncated == true; the values of the `string_ids` JSON object sum to 200; logs/uploads_<run_id>.log carries "Rule '<rule>' matched <path> at 200 offsets; embedded a sample of 50 in the dataset row (truncated=true".
- **Setup:** Round 2 flood tree plus one planted file containing exactly 200 occurrences of the rule's pattern across two string identifiers, and a second planted file containing exactly 12.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "<rule>" | fields filename, match_count, truncated, offsets, string_ids`; logs/uploads_<run_id>.log truncation line.
- **Negative control:** The 12-offset file must give truncated == false, `offsets` length == 12 == match_count, and NO truncation line in uploads_<run_id>.log. The cap must bite only above 50 — a truncated flag set on every row makes match_count untrustworthy.

### `RULE-066` Per-rule detection tally and top_rules ranking

*supporting*

- **Must be true:** The tally counts every Match (not every file), and top_rules is a descending top-10 slice of it that reconciles against the dataset rows for the same scan.
- **Threshold:** With at least 15 rules triggering, ALL of them declaring at least one string (no condition-only rules in the flood pack — a stringless Match is tallied but writes no row): scan_summary unique_rules_triggered equals the number of distinct rules with at least one hit and is >= 15; `top_rules` is a list of exactly 10 [rule, count] pairs, non-increasing in count, with top_rules[0][1] == the maximum count; logs/alerts_<run_id>.log carries 'Top detection rules: ' naming exactly 5 rule(count) pairs with a data payload whose `top_10_detections` has exactly 10 keys and whose `unique_rules_triggered` equals the summary's. The dataset reconciliation applies only when scan_summary delivery_shortfall == "": then for each of the 10 entries the XQL row count for that rule under this scan_id equals the entry's count. If delivery_shortfall is non-empty, compare the XQL count against the entry's count minus the lookup channel's leftover from `dataset_delivery` instead, and state which form was used.
- **Setup:** Round 2 flood ruleset engineered so at least 15 distinct rules fire, with clearly unequal hit counts so the ordering is testable.
- **Evidence:** `unique_rules_triggered`, `top_rules` and `matches` in logs/scan_summary_<run_id>.json; logs/alerts_<run_id>.log line 'Top detection rules: ... | data={..."top_10_detections":{...}}'; XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" | comp count() by rule`.
- **Negative control:** On the Round 1 clean run (zero detections) the 'Top detection rules:' line must be ABSENT from alerts_<run_id>.log — it is gated on total_detections > 0 — and scan_summary top_rules must be an empty list with unique_rules_triggered == 0.
- **Why this round:** Departs from the RULE prior. The top-10 slice and the 5-of-10 render only do anything once more than ten rules trigger, which only Round 2's flood ruleset produces; in Round 3's crafted scan the slice is a no-op and the criterion would pass vacuously.

### `RULE-067` Per-rule alert text files in alert_dir

*core*

- **Must be true:** One <rule>.txt per triggering rule, whose string-ID census is complete and uncapped while the offset listing is capped at CONFIG_ALERT_OFFSETS_PER_FINDING_MAX with an explicit omission notice — so a truncated listing never implies lost counts.
- **Threshold:** For the 200-offset finding, <scanner_dir>/alert/<rule>.txt contains 'Total string hits: 200'; a 'Hits per string ID: ' line whose values sum to 200 and match the dataset row's `string_ids` object exactly; 'Matched Strings (showing 50 of 200):'; exactly 50 'Offset: ' lines in that block; and '150 further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50).'. One .txt file exists per distinct triggering rule name and no more.
- **Setup:** Same Round 2 planted pair as RULE-065 (200-offset and 12-offset files).
- **Evidence:** <scanner_dir>/alert/<rule>.txt; XQL match_count and string_ids for the same (scan_id, rule, filename); `alert_bytes_written` and `alert_detail_suppressed` in logs/scan_summary_<run_id>.json.
- **Negative control:** The 12-offset finding's block must read 'Matched Strings (showing 12 of 12):' with no omission notice, while still carrying its own 'Total string hits: 12' census. And on this run alert_detail_suppressed must be 0 — if the alert-directory byte ceiling was reached the offset detail is dropped for a different reason, which would confound the cap test.

## Performance & Resource Management

### `PERF-053` Chunked hashing of matched files

*supporting*

- **Must be true:** Hashing a very large matched file does not read it into memory — process RSS across the tick that hashes a >=1 GB matched file rises by far less than the file's size, and the file still gets a complete SHA256.
- **Threshold:** _sha256_file chunk_size 1 MB (FileHasher.calculate_sha256's evidence-path fallback reads 4 KB). Run this scan with YARA_PROGRESS_LOG_SECS=1 (the value is clamped to >=1) so the hashing window spans several heartbeats, and in parallel sample RSS over SSH at <=0.5s (`while :; do ps -o rss= -p <pid>; sleep 0.5; done`). Across the hashing window neither trace may rise by more than 64 MB, versus the >=1 GB rise a full-file read would produce. Independently: the file's SHA256 in file_mapping.txt must equal `sha256sum` computed on the endpoint, proving the chunked loop covered every byte and not a prefix.
- **Setup:** Plant one >=1 GB file that the Round 2 flood pack matches inside the flood tree. Keep YARA_PROGRESS_LOG_SECS at its 30s default so the hashing window is sampled by at least one heartbeat.
- **Evidence:** data.metrics.memory_mb across successive 'Scan Progress | Files:' records in <scanner_dir>/logs/statistics_<run_id>.log with YARA_PROGRESS_LOG_SECS=1, plus the external `ps -o rss=` trace over SSH; the 'Original Path | SHA256 Hash' table in <scanner_dir>/evidence/file_mapping.txt (also at the ZIP root) compared against `sha256sum <path>` run on the endpoint; file_sha256 on the corresponding yara_scanner_matches_v3_* row.
- **Negative control:** On the same run, a >=1 GB NON-matching file must produce no RSS excursion at all and no file_mapping.txt line — it never enters the hashing branch. And the planted matched file's SHA256 must match an independently computed `sha256sum`: a build that hashed only the first chunk would also keep RSS flat and would be indistinguishable from correct chunking without this.
- **Why this round:** Hashing only runs inside the `if matches:` branch, so Round 1's clean tree never enters this code at all. The flood guarantees the call happens, and a planted large matched file is what makes the RSS claim measurable.

### `PERF-054` Hash only on match (no full read per scanned file)

*supporting*

- **Must be true:** SHA256 is computed only for files that matched: an equally sized NON-matching file in the same tree appears in no hash artefact — no file_mapping.txt line, no alert/<rule>.txt entry, no matches row and no file_sha256 anywhere — while the matching one appears in all of them.
- **Threshold:** Line count of the 'Original Path | SHA256 Hash' section of <scanner_dir>/evidence/file_mapping.txt == the number of distinct filename values in yara_scanner_matches_v3_* for this scan_id, and contains zero planted non-matching paths. Drop the disk_io_mb clause: read_bytes counts only storage-layer fetches, so a page-cached re-read of a just-scanned file registers ~0 and the 1x-vs-2x signature cannot appear on a correct build.
- **Setup:** Inside the Round 2 tree plant a 2 GB file the pack matches and a byte-different 2 GB file it does not, placed so the two are scanned in distinguishable heartbeat windows.
- **Evidence:** <scanner_dir>/evidence/file_mapping.txt entries; file_sha256 in the 'YARA matches found in <path>' alert records in logs/alerts_<run_id>.log (the non-matching file must have no such record at all); XQL over yara_scanner_matches_v3_* filtered to this scan_id for the distinct filename set.
- **Negative control:** The planted non-matching 2 GB file must appear in NO alert/<rule>.txt, no file_mapping.txt line and no matches row, while the matching one appears in all three — otherwise 'hashes only matches' and 'hashes nothing at all' look the same.
- **Why this round:** The claim is about what happens on the match branch versus the clean branch; Round 1's clean tree exercises only the clean branch and can never show the contrast.

### `PERF-055` Per-offset match detail is never retained in memory

*supporting*

- **Must be true:** A rule producing tens of thousands of offsets inside one file does not grow the scanner's RSS in proportion to offsets — memory_mb stays flat across the storm — while the per-string-ID census written to alert/<rule>.txt stays complete and only the rendered offsets are sampled.
- **Threshold:** Run with YARA_PROGRESS_LOG_SECS=1 and/or an external `ps -o rss=` sample at <=0.5s across the storm window; memory_mb must vary by < 64 MB across it. 'Total string hits: N' in alert/<rule>.txt equals match_count on the corresponding matches row; the counts on the 'Hits per string ID: ' line sum to that same N (the census is uncapped); exactly 50 'Offset:' blocks are rendered for that finding. Confirm scan_summary_<run_id>.json alert_detail_suppressed == 0 for the run, otherwise the byte ceiling (CONFIG_ALERT_DIR_MAX_BYTES) rather than the offset cap explains the file's shape.
- **Setup:** Round 2 flood plus one planted large text file and a short unanchored string pattern that hits it >= 20,000 times.
- **Evidence:** data.metrics.memory_mb across 'Scan Progress | Files:' records in <scanner_dir>/logs/statistics_<run_id>.log; the 'Total string hits: ' and 'Hits per string ID: ' lines in <scanner_dir>/alert/<rule>.txt (bundled as alerts/<rule>.txt in evidence_<hostname>_<run_id>.zip); match_count and string_ids on the yara_scanner_matches_v3_* row for that (rule, file).
- **Negative control:** On the same run a finding with fewer than 50 offsets must render EVERY offset, read 'showing K of K' and carry no omission note — proving the 50 is a cap and not a fixed slice. And a rule producing 20,000 offsets across 20,000 SEPARATE files (rather than one) must produce the same flat memory_mb trace: that separates 'per-offset detail is not retained' from 'this particular file was small enough not to matter'.

### `PERF-056` Finding-dedup set bounded at 150,000 entries

*supporting*

- **Must be true:** The within-scan dedup set collapses a re-presented (rule, file) pair to a single finding while it holds fewer than 150,000 entries, and the set itself never grows past that bound.
- **Threshold:** 150,000 entries. With a file reachable through two overlapping scan targets: alert_delivery.findings + alert_delivery.suppressed equals the number of distinct (rule, filename) pairs for this scan_id, not twice it.
- **Setup:** Round 2 with scan_folder naming both a parent directory and one of its own subdirectories, so every file under the subdirectory is enqueued and scanned twice and each (rule, file) pair is presented to add_match twice. The flood pack matches all of them.
- **Evidence:** alert_delivery.findings and alert_delivery.suppressed in <scanner_dir>/logs/scan_summary_<run_id>.json (and the 'Alert delivery final: findings=… suppressed=…' record in logs/uploads_<run_id>.log), against an XQL count of distinct rule+filename groups: `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" | comp count() by rule, filename`.
- **Negative control:** Two DIFFERENT rules matching the same file, and the same rule matching two different files, must each yield two separate findings on the same run — the key is the pair, so a build that collapsed on either half alone would still pass the duplicate case. Note the bound's own arithmetic bite (a duplicate presented after the 150,000th entry is counted twice) is only reachable on a scan with more than 150,000 distinct findings; below that the value 150,000 is not falsifiable from a run.

### `PERF-057` Local alert-file offset sampling

*supporting*

- **Must be true:** alert/<rule>.txt renders at most CONFIG_ALERT_OFFSETS_PER_FINDING_MAX offsets per (rule, file) and states the omission explicitly, while the per-string-ID census above it stays uncapped and complete.
- **Threshold:** 50 (bare literal; no env var and no options key). Header reads 'Matched Strings (showing 50 of <N>):' with N the true hit count; exactly 50 'Offset:' lines follow for that finding; the trailing note reads '<N-50> further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50)'.
- **Setup:** Same planted >=20,000-offset file as PERF-055, inside the Round 2 flood.
- **Evidence:** <scanner_dir>/alert/<rule>.txt, and the same content as alerts/<rule>.txt inside <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip.
- **Negative control:** A finding with fewer than 50 offsets on the same run must render every offset, carry NO 'further offset(s) omitted' note, and read 'showing K of K' — otherwise a build that truncated every finding would be indistinguishable from a working cap.

### `PERF-058` Dataset row payload sampling per finding

*supporting*

- **Must be true:** A (rule, file) finding with more offsets than the cap produces ONE dataset row whose match_count is the true total, whose offsets array holds exactly the capped sample, and whose truncated flag is true — and the truncation is announced in the uploads log.
- **Threshold:** 50 (CONFIG_LOOKUP_ROWS_PER_FINDING_MAX; the catalogue's 'no env var' note is stale — it is _env_number('YARA_LOOKUP_ROWS_PER_FINDING', 50, minimum=0)). For the >=20,000-offset finding: length of the offsets JSON array == 50, length of strings == 50, match_count == the true hit count, truncated == true.
- **Setup:** Same planted high-offset file. Add a control run with YARA_LOOKUP_ROWS_PER_FINDING=0, in which offsets carries every offset and truncated is false, to prove the cap is the knob and not a fixed slice.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "<rule>"` — fields match_count, offsets, strings, string_ids, truncated; the 'Rule '<rule>' matched <file> at N offsets; embedded a sample of 50 in the dataset row (truncated=true' record in <scanner_dir>/logs/uploads_<run_id>.log.
- **Negative control:** A finding with fewer than 50 offsets on the same run must carry truncated == false with offsets length == match_count, and must produce no 'embedded a sample of' line — otherwise 'everything is truncated' and 'the cap works' are indistinguishable.

### `PERF-059` Structured log payload truncation

*low*

- **Must be true:** A structured data payload longer than 4000 characters is cut and explicitly marked on the log line, while scan_summary_<run_id>.json — written by write_scan_summary, a different path with no cap — is complete JSON.
- **Threshold:** 4000 characters. On the truncated record the substring after ' | data=' is exactly 4014 characters and ends with '...(truncated)'. Because json.dumps is called with sort_keys=True, what survives the cut is deterministic and the record must break mid-key rather than at a JSON boundary. logs/scan_summary_<run_id>.json parses cleanly with `python3 -m json.tool` and contains no '...(truncated)' anywhere.
- **Setup:** Round 1 whole-filesystem scan — its skip_breakdown and detection_breakdown push the final report's payload well past 4000 characters. This is the most reliable record to reproduce it on.
- **Evidence:** The 'COMPREHENSIVE SCAN REPORT | Efficiency Score: ' record in <scanner_dir>/logs/statistics_<run_id>.log on the Round 2 FLOOD run — its detection_breakdown carries one key per rule that fired, which with a several-hundred-rule flood pack deterministically pushes the payload past 4000 characters; <scanner_dir>/logs/scan_summary_<run_id>.json from the same run.
- **Negative control:** A short record in the same file on the same run — 'Scan configuration established', or the 'Skip reasons: ' record — must carry its full data= JSON with no marker and must parse as complete JSON. A build that truncated every payload would look identical on the large record alone.

### `PERF-064` Alert POST pacing against the shared rate limit

*core*

- **Must be true:** Alert POSTs carry at most 60 alerts each and are spaced at least ALERT_MIN_BATCH_INTERVAL apart, so a flooding endpoint stays under the shared ~600 alerts/min Insert Parsed Alerts ceiling.
- **Threshold:** ALERT_BATCH_SIZE hard-clamped to 60 by min(); ALERT_MIN_BATCH_INTERVAL 7s; ALERT_FLUSH_SECS 10s for partials. Startup line reads 'Upload worker thread started (batch=60)'; every 'Alert batch ok (N alerts, HTTP 2xx)' has N <= 60; consecutive successful-batch timestamps are >= 7.0s apart (0.2s clock slack). Reconciliation is valid ONLY when no '[alert_upload_ok] further similar messages suppressed' line exists in uploads_<run_id>.log — _throttled_log emits just the first 20 successful batches; assert that notice is absent (CONFIG_ALERT_MAX_PER_SCAN=500 keeps the count near 9) and then that the sum of N equals alert_delivery.successful_uploads. Derive the per-minute ceiling from the pacing rather than from the line set: with POSTs >= 7s apart, at most 9 fit in any rolling 60s window, so <= 540 alerts/min.
- **Setup:** Standard Round 2 flood, sized past CONFIG_ALERT_MAX_PER_SCAN (500) so the queue stays full and complete 60-alert batches are the norm rather than the exception.
- **Evidence:** 'Upload worker thread started (batch=' and the 'Alert batch ok (' records with their log timestamps in <scanner_dir>/logs/uploads_<run_id>.log; the sum of N over those lines must equal alert_delivery.successful_uploads in logs/scan_summary_<run_id>.json.
- **Negative control:** A partial trailing batch (N < 60, flushed on the 10s idle timer) is expected and is not a violation — the pacing rule bounds the interval and the maximum size, not the minimum. Only a POST with N > 60, or a gap under 7s, fails this.

### `PERF-065` Backlog-scaled alert drain window

*core*

- **Must be true:** The end-of-scan alert drain window is computed from the real backlog, and everything queued is accounted for exactly once — nothing left after the window is booked as delivered.
- **Threshold:** For the 'Draining N pending alert(s) (~M batches, up to Xs)...' line: M == ceil(N/60) and X == min(300, max(60, M*15)) exactly (ALERT_DRAIN_SECS 60, ALERT_DRAIN_MAX_SECS 300, ALERT_MIN_BATCH_INTERVAL+8). Wall time from that line to 'Alert delivery final:' <= X + 65s (drain plus the 60s THREAD_CLEANUP_TIMEOUT join). Books balance: alerts_queued == successful_uploads + failed_uploads + undelivered, and alerts_queued == findings + rollups.
- **Setup:** Round 2 flood sized so at least 200 alerts are still queued when the scan finishes.
- **Evidence:** 'Draining ' and 'Alert delivery final: findings=' records in <scanner_dir>/logs/uploads_<run_id>.log; alert_delivery.{findings,alerts_queued,successful_uploads,failed_uploads,undelivered,suppressed,rollups,requeued} in logs/scan_summary_<run_id>.json.
- **Negative control:** A small control scan whose queue empties inside the window must report undelivered == 0 with alerts_queued and successful_uploads both non-zero, and must not emit the 'Draining' line at all when nothing is pending. A build that always books leftovers, or never does, fails one side or the other.

### `PERF-066` Rate-limit requeue with a global wall-clock budget

*supporting*

- **Must be true:** A batch that exhausts its retries because it was RATE-LIMITED is put back on the queue rather than dropped, but only while the global delivery budget is unspent — and the requeued alerts are reported and do eventually land.
- **Threshold:** MAX_RETRIES_PER_ITEM 4; ALERT_MAX_DELIVER_SECS 900s (YARA_ALERT_MAX_DELIVER_SECS); ALERT_REQUEUE_ENABLED default on. Assert the BOOKS rather than a line sum: on the enabled run alert_delivery.requeued > 0, no 'Alert batch rate-limited after 4 attempts; requeuing' line is timestamped more than 900s after 'Upload worker thread started', at least one such line is followed later by a successful 'Alert batch ok' line, and critically alerts_queued == successful_uploads + failed_uploads + undelivered still balances exactly — the worker re-puts requeued alerts WITHOUT re-incrementing alerts_queued, so a build that double-booked them would break this identity while the line sum stayed plausible. Treat the sum-over-lines check as valid only if no '[alert_requeue] further similar messages suppressed' notice appears.
- **Setup:** Round 2 flood run concurrently from 3+ endpoints against the same API key so the shared ~600/min Insert Parsed Alerts ceiling is genuinely tripped — the requeue branch is only reachable via a real 429/'rate limit' response, not by injection.
- **Evidence:** 'Alert batch rate-limited after ' and the requeued= field of 'Alert delivery final: ' in <scanner_dir>/logs/uploads_<run_id>.log; alert_delivery.requeued in logs/scan_summary_<run_id>.json (grafted on by get_upload_stats).
- **Negative control:** A control run with YARA_ALERT_REQUEUE=0 under the same concurrent load must show requeued == 0, failed_uploads >= 60 (at least one whole rate-limited batch booked as failed rather than requeued), and the same alerts_queued == ok + failed + undelivered identity still balancing. That proves the requeue is the flag's doing rather than the limit never being tripped, and that neither path leaks or double-counts.

### `PERF-067` Backlog-scaled lookup drain budget and per-batch deadline

*core*

- **Must be true:** The lookup drain budget is derived from the actual row backlog, the per-batch retry loop refuses an attempt that cannot finish inside it, and anything never attempted is booked undelivered instead of silently lost.
- **Threshold:** For 'Lookup drain: N rows pending (~M batches), budget Xs': M == ceil(N/500) and X == min(600, max(150, M*45)) exactly (LOOKUP_DRAIN_TIMEOUT 150, LOOKUP_DRAIN_MAX_SECS 600, LOOKUP_DRAIN_PER_BATCH_SECS 45). Wall time to 'Lookup dataset worker stopped (batches=' <= X + 10s. dataset_delivery.undelivered equals the leftover row count named in the scan_errors line. Add a POSITIVE deadline run: repeat the flood with YARA_LOOKUP_DRAIN_SECS=30, which makes the per-batch deadline monotonic + max(1, 30-20) = +10s against a 120s read timeout, so every attempt after the first is refused — 'Lookup batch deadline reached (N rows) after 1 attempts; stopping retries' must then appear for each retried batch, dataset_delivery.send_failures must be non-zero, and the drain must still exit inside its budget.
- **Setup:** Round 2 flood sized so at least 5,000 rows are queued on the matches dataset at shutdown.
- **Evidence:** 'Lookup drain: ', 'Lookup batch deadline reached (' and 'Lookup dataset worker stopped (batches=' in <scanner_dir>/logs/uploads_<run_id>.log; 'Lookup drain budget expired with N rows undelivered' in logs/scan_errors_<run_id>.log; dataset_delivery in logs/scan_summary_<run_id>.json.
- **Negative control:** On a healthy flood the 'Lookup batch deadline reached' line must be ABSENT and dataset_delivery.undelivered 0 while records_added is non-zero. A build that short-circuits retries unconditionally would emit the line on every run and still look 'bounded'.

### `PERF-068` Lookup write jitter and per-target batch timers

*supporting*

- **Must be true:** Rows are POSTed in batches of at most LOOKUP_DATASET_BATCH_SIZE, and each target dataset carries its OWN idle-flush anchor, so when the worker loop goes idle the sparse scans dataset flushes on its own 30s clock rather than inheriting the matches batch's timer — while a continuously non-empty queue defers every idle flush, because the per-target timer is only consulted in the queue.get() Empty branch.
- **Threshold:** 500 rows / 30s idle flush / 0-2s pre-write jitter (YARA_LOOKUP_BATCH, YARA_LOOKUP_FLUSH_SECS, YARA_LOOKUP_WRITE_JITTER). Startup line reads 'batch_size: 500'; every 'Lookup batch ok (N rows)' has N <= 500 and the modal N on the flood is 500. Per-target timer: on a run whose match stream has gaps (or with the flood's tail, after the workers stop producing), a queued scans row is POSTed within 30s + 2s jitter + 1s of the loop going idle, independently of when the last matches batch flushed. Separately record that during the sustained-flood phase, when the queue never empties, NO small-N batch appears — the idle flush is unreachable there by construction.
- **Setup:** Standard Round 2 flood (>5,000 matches) at default settings so full batches occur alongside the sparse lifecycle rows.
- **Evidence:** 'Lookup dataset upload thread starting (datasets: <matches>, <scans>; batch_size: 500)' and the 'Lookup batch ok (' records with timestamps in <scanner_dir>/logs/uploads_<run_id>.log; row counts per dataset via XQL over yara_scanner_matches_v3_* and yara_scanner_scans_v3_* filtered to this scan_id.
- **Negative control:** During the sustained phase the scans rows must NOT appear (queue never idles, so no per-target flush fires); during the idle/tail phase a small-N 'Lookup batch ok' line must appear within ~33s of the scans row being queued even if a 500-row matches batch flushed moments earlier. Both halves are needed: without the first, 'per-target timer' and 'single global timer' are indistinguishable; without the second, the timer could simply be dead.

### `PERF-069` Concurrent final flush of the two lookup datasets

*supporting*

- **Must be true:** At shutdown the pending matches batch and the pending scans batch are flushed concurrently on separate threads, not one after the other.
- **Threshold:** Measure elapsed drain time against the SUM versus the MAX of the two batches' service times. Establish per-batch service time from mid-scan 'Lookup batch ok' spacing on the same run (t_matches for 500-row batches, t_scans for 1-3 row ones). Then wall time from the last pre-drain uploads_<run_id>.log record to 'Lookup dataset worker stopped (batches=' must be <= max(t_matches, t_scans) + LOOKUP_WRITE_JITTER_SECS + 5s, and strictly less than t_matches + t_scans. Both final 'Lookup batch ok' lines must precede 'Lookup dataset worker stopped' and fall inside the scaled _drain_budget (falling back to LOOKUP_DRAIN_TIMEOUT 150s).
- **Setup:** Round 2 flood ending while both datasets hold pending rows — the terminal lifecycle row is emitted before the uploaders are stopped, so the scans target always has one.
- **Evidence:** Timestamps and row counts of the last 'Lookup batch ok (' records in <scanner_dir>/logs/uploads_<run_id>.log (the line does not name its target, so the batch size discriminates: lifecycle batches are 1-3 rows, matches batches up to 500); 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)' in the same file; XQL confirming both datasets received rows for this scan_id.
- **Negative control:** A control run whose final drain has only ONE target pending (e.g. write_dataset on but a scan with zero matches, so only the scans batch remains) takes the `len(pending) <= 1` sequential arm: its drain time must equal that single batch's service time. That calibrates the measurement and proves it can resolve one service time from two — without it, 'concurrent' and 'sequential with a fast merge' leave the same evidence.

### `PERF-070` Uploader threads are daemons with bounded joins

*supporting*

- **Must be true:** Both uploader threads are joined within their own bounded budgets and neither keeps the payload process alive after shutdown — the alert thread at THREAD_CLEANUP_TIMEOUT, the lookup thread at its backlog-scaled drain budget.
- **Threshold:** 60s alert join (THREAD_CLEANUP_TIMEOUT). On a healthy flood: 'Upload thread terminated successfully' present and 'Upload thread did not terminate within 60s timeout' absent; 'Lookup uploader thread did not stop within Xs' absent; the payload PID is gone within 10s of the SCAN_RESULT line.
- **Setup:** Round 2 flood carrying a real end-of-scan backlog on both channels; watch the PID over SSH on the Linux endpoint from the moment the result line appears.
- **Evidence:** 'Upload thread terminated successfully' / 'Upload thread did not terminate within ' and 'Lookup uploader thread did not stop within ' in <scanner_dir>/logs/uploads_<run_id>.log; 'Lookup drain budget expired with ' in logs/scan_errors_<run_id>.log; `ps -p <pid>` after the result line.
- **Negative control:** If either timeout line DOES appear on the deliberately over-sized backlog run, the matching undelivered counter must be non-zero and the process must still exit — a run that reports an abandoned join while claiming zero undelivered means the books lied about what the join dropped.

### `PERF-074` DEAD CONFIG: batch_size / performance_log_interval / statistics_upload_interval

*low*

- **Must be true:** None of the three assigned-but-never-read ScanConfig values governs anything observable: the live lookup batch size is 500 (not 1000), the progress cadence is 30s (not 60), and no log family shows a 120s periodicity.
- **Threshold:** Dead values 1000 / 120 / 60. Modal N in 'Lookup batch ok (N rows)' == 500 and never 1000; median spacing of 'Scan Progress | Files:' records == 30s ± 2 (YARA_PROGRESS_LOG_SECS default); no record family in <scanner_dir>/logs/ shows a 120s ± 5 periodicity.
- **Setup:** Standard Round 2 flood at default settings, so full lookup batches actually occur and the batch-size assertion has something to bite on.
- **Evidence:** Row counts on 'Lookup batch ok (' lines and the 'Lookup dataset upload thread starting (datasets: …; batch_size: 500)' line in <scanner_dir>/logs/uploads_<run_id>.log; timestamps of 'Scan Progress | Files:' records in logs/statistics_<run_id>.log.
- **Negative control:** Setting YARA_LOOKUP_BATCH=250 must move the modal batch to 250. That proves the observed 500 comes from the live LOOKUP_DATASET_BATCH_SIZE knob rather than coincidentally matching some other constant.
- **Why this round:** The entry is marked unobservable, but it is decidable as a negative assertion — the claim 'these constants are inert' fails if a build wires them up. The sharpest of the three observables is the real upload batch size, which is a Round 2 artefact.

### `PERF-089` FD sampling runs once per file PROCESSED, before every early return

*supporting*

- **Must be true:** FD sampling reaches files that MATCHED: on a scan where essentially every file matches, samples still occur once per 1000 files processed rather than approximately never.
- **Threshold:** fd_check_interval 1000, counter advanced under lock_counts at the top of scan_file before every early return. Define scan_file_calls = files_scanned + (files_skipped - skip_breakdown['Skipped directory'] - skip_breakdown['Junction/symlink skip'] - skip_breakdown['Special system file']), absent keys treated as 0. Count of 'WARNING: High FD usage: ' lines == floor(scan_file_calls/1000) +/- 1 on a run where matches ~= files_scanned; the pre-fix placement (after the match return) would give ~0. Launch the wrapper from a shell that has already run `ulimit -n 65536` before pre-opening the ~950 descriptors, otherwise the scan dies on EMFILE under the default 1024 soft limit.
- **Setup:** Round 2 flood on the Linux endpoint, launched over SSH with YARA_ENABLE_FD_MONITOR=true from a wrapper that pre-opens ~950 descriptors before exec, so every sample exceeds the 900 absolute threshold and therefore writes a line. This indirection is necessary: fd_samples_taken and last_fd_count have no reader anywhere in the scanner or its outputs, so a threshold line is the only live artefact a sample can produce.
- **Evidence:** Count of lines matching 'WARNING: High FD usage: ' in <scanner_dir>/logs/system_<run_id>.log; files_scanned, files_skipped and matches in logs/scan_summary_<run_id>.json; and data.skip_breakdown in the 'Skip reasons: ' record of logs/statistics_<run_id>.log, needed to subtract the three discovery-level skip reasons that never call scan_file.
- **Negative control:** The same flood on Linux WITHOUT the pre-opened descriptors must emit zero such lines while still scanning the same file count, and a Windows control run must emit zero regardless of the env var (the platform guard sits after the counter advance). Both show the line count tracks sampling reach against the threshold rather than merely 'the scan ran'.
- **Why this round:** Prior is Round 1, but the property under test is that sampling survives the MATCH return. Round 1's clean tree produces almost no matches and therefore cannot distinguish the fixed placement from the old one; only a flood in which nearly every file matches can falsify it.

## Local Storage & Host Footprint

### `STOR-012` Structured log `data` payload capped at 4000 characters per line

*low*

- **Must be true:** Every structured data payload written to the six category logs is either at most 4000 characters or exactly 4014 ending in '...(truncated)' — never a length in between, never longer, and never a short payload wearing the truncation marker.
- **Threshold:** Cap literal is 4000 and the suffix '...(truncated)' is 14 characters, so a truncated blob is exactly 4014. Across all six logs: 0 records whose blob length lies in (4000, 4014) or exceeds 4014, and 0 records whose blob is shorter than 4014 yet ends with '...(truncated)'. On the flood run, the 'COMPREHENSIVE SCAN REPORT | Efficiency Score:' record in statistics_<run_id>.log has a blob of exactly 4014 ending in '...(truncated)'.
- **Setup:** Round-2 flood pack containing >=200 distinct rules that all fire, so detection_breakdown alone pushes the final report's payload past 4000 characters.
- **Evidence:** statistics_<run_id>.log line beginning 'COMPREHENSIVE SCAN REPORT | Efficiency Score:'; a scan of all six logs splitting each record on its FIRST ' | data=' (records are delimited by the '[YYYY-MM-DD HH:MM:SS.mmm] [' prefix, so a message containing a newline still counts as one record).
- **Negative control:** A small-payload record in the same run — e.g. any 'Scan Progress | Files: ...' statistics record — must carry its full JSON with no '...(truncated)' marker; the cap must not fire on payloads under the limit.
- **Why this round:** The cap is a log-writing mechanic (storage prior, Round 1), but only Round 2's flood reliably builds a payload past 4000 characters: the guaranteed overflowing record is the final report, whose nested detection_breakdown needs hundreds of distinct firing rules. A Round-1 clean run has an empty detection_breakdown and would never trip it.

### `STOR-013` Upload-log volume suppression (_throttled_log buckets)

*supporting*

- **Must be true:** The upload-log throttle emits the first 20 messages of a bucket verbatim, then exactly one suppression notice, then one running-count line per 1000 further occurrences — so a flood cannot put one line per finding into uploads_<run_id>.log.
- **Threshold:** Defaults are full=20, every=1000 (bare defaults in the _throttled_log signature, line 3544). Records in uploads_<run_id>.log are prefixed '[YYYY-MM-DD HH:MM:SS.mmm] [INFO] '; every pattern below must be ANCHORED after that prefix, because the suppression and running-count lines quote the suppressed message back verbatim (msg[:120]) and an unanchored grep double-counts them. With F == scan_summary.matches and F >= 1021: count of records matching ^\[[0-9-]{10} [0-9:.]{12}\] \[INFO\] Added [0-9]+ matches for rule ' == 20 exactly; exactly ONE record matching ^\[[0-9-]{10} [0-9:.]{12}\] \[INFO\] \[added_matches\] further similar messages suppressed; will summarize every 1000\. Example: ; count of records matching ^\[[0-9-]{10} [0-9:.]{12}\] \[INFO\] \[added_matches\] [0-9]+ occurrences so far; latest:  == floor(F/1000).
- **Setup:** Round-2 flood sized so scan_summary.matches >= 1021 (add_match is called once per file x rule finding, so F equals the summary's matches while UPLOAD_RESULTS is on).
- **Evidence:** Anchored `grep -cE` on the three patterns above in /opt/yara_scanner/logs/uploads_<run_id>.log (verify the anchoring by also running the unanchored 'Added [0-9]+ matches for rule ' grep and confirming it returns 21 + floor(F/1000), which is the echo effect this criterion must not be fooled by); .matches in logs/scan_summary_<run_id>.json.
- **Negative control:** A bucket that fired <=20 times in the same run must show every one of its messages and NO '[<bucket>] further similar messages suppressed' line — use alert_upload_ok, which is bounded to roughly (CONFIG_ALERT_MAX_PER_SCAN 500 + rollups) / ALERT_BATCH_SIZE 60 ≈ 10 batches. The throttle must not suppress low-volume buckets.

### `STOR-018` alert/<rule>.txt — one append-only text file per matching rule, uncapped in file count

*core*

- **Must be true:** alert/ carries exactly one text file per triggered rule, its blocks reconcile with the run's detection total, and concurrent workers never corrupt a block.
- **Threshold:** Count of files in alert/ named <rule>.txt or <rule>.alert == scan_summary.unique_rules_triggered; summed over those files, count of lines matching ^YARA rule ' == scan_summary.matches; every block header is followed by a 'File SHA256:' line of exactly 64 lowercase hex; zero 'Failed to write alert file:' lines in scan_errors_<run_id>.log; no block header appears mid-line (writes are serialised under lock_alert).
- **Setup:** Round-2 flood with >=5 distinct rules firing and >=2 workers. Take the listing BEFORE any subsequent scan (initial_cleanup wipes alert/) and count .alert as well as .txt: on Linux the cleanup unit is started synchronously during this run's own finalization, so the files have already been renamed by the time run() returns.
- **Evidence:** `ls /opt/yara_scanner/alert`; `grep -c "^YARA rule '" /opt/yara_scanner/alert/*`; unique_rules_triggered and matches in logs/scan_summary_<run_id>.json; scan_errors_<run_id>.log.
- **Negative control:** A rule in the pack that did NOT fire must have no file at all — the file count must not exceed unique_rules_triggered, or the per-rule split has degenerated into one file per rule in the pack.

### `STOR-019` Alert offsets sampled per finding; per-string-ID census kept complete

*core*

- **Must be true:** Per-finding offsets in the local alert text are sampled at 50 while the per-string-ID census stays complete, and the same finding's dataset row reports the TRUE total with truncated=true and a 50-entry sample.
- **Threshold:** Precondition: scan_summary.alert_detail_suppressed == 0 for this run (a non-zero value means the byte ceiling fired and the sampled-offsets branch was bypassed; the run is void for this criterion, not a fail). CONFIG_ALERT_OFFSETS_PER_FINDING_MAX == 50 (bare literal) and CONFIG_LOOKUP_ROWS_PER_FINDING_MAX == 50 (YARA_LOOKUP_ROWS_PER_FINDING default). For the planted file with N > 50 hits of one rule: the block reads 'Matched Strings (showing 50 of N):', contains exactly 50 lines matching ^Offset: , and carries '<N-50> further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50). Counts above are complete; re-run `yara -s` against this file for every offset.' followed by the closing 40-dash rule; 'Total string hits: N' and the values in 'Hits per string ID: ' sum to N exactly; the dataset row for that (rule, file) has match_count == N, truncated == true and exactly 50 entries in the offsets JSON array; uploads_<run_id>.log carries "Rule '<rule>' matched <file> at N offsets; embedded a sample of 50 in the dataset row (truncated=true; full detail retained in local results)."
- **Setup:** Plant one file with >=5,000 hits of a single rule string into the Round-2 flood tree, and size that tree (or raise YARA_ALERT_DIR_MAX_MB for this invocation) so the run finishes under the alert-directory byte ceiling. If the flood is deliberately sized to trip the 256 MB ceiling for the ceiling criterion, run this criterion's planted-file check as a SECOND, bounded Round-2 invocation instead — once _alert_bytes_written crosses CONFIG_ALERT_DIR_MAX_BYTES the per-offset block is replaced by the 'Offset detail omitted' branch and none of the offset assertions below can hold.
- **Evidence:** The block in /opt/yara_scanner/alert/<rule>.txt; the quoted line in uploads_<run_id>.log; XQL: dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "<rule>" and filename = "<planted path>" | fields match_count, truncated, offsets
- **Negative control:** A finding with K <= 50 hits must render 'Matched Strings (showing K of K):', carry NO 'further offset(s) omitted' line, and its dataset row must have truncated == false — the cap must not mark small findings as sampled.

### `STOR-020` evidence/file_mapping.txt — path→SHA256 manifest with a host header, silently lossy on both edges

*supporting*

- **Must be true:** file_mapping.txt carries an 8-line header and exactly one '<path> | <sha256>' row per distinct matched path that still existed and hashed at collection time, with no duplicates, and any shortfall against the matched-file count is explained by a vanished path or a logged hashing error rather than being silent.
- **Threshold:** Header is exactly 8 lines — 'Host Information:', 'Hostname: ...', 'OS: ...', 'IP Addresses: ...', an 80-dash rule, a BLANK line, 'Original Path | SHA256 Hash', an 80-dash rule — NOT the 6 the catalogue's Observe claims, so data rows = total lines - 8. Data rows == count of distinct 'YARA matches found in ' lines in alerts_<run_id>.log minus (paths no longer on disk + 'Error calculating hash for' lines in diagnostics_<run_id>.log); every hash is 64 lowercase hex and matches `sha256sum` for a random 20-row sample; 0 duplicate path rows.
- **Setup:** The Round-2 flood (thousands of distinct matched paths). The manifest is written regardless of collect_files, so no option change is needed.
- **Evidence:** /opt/yara_scanner/evidence/file_mapping.txt and the identical member at the ZIP root; 'YARA matches found in <path>' lines in alerts_<run_id>.log; 'Error calculating hash for <path>:' in logs/diagnostics_<run_id>.log — this IS reachable now, because setup_logging installs an INFO FileHandler on the root logger well before evidence collection runs; the catalogue's 'UNOBSERVABLE' note predates that handler.
- **Negative control:** A matched path that still exists and hashes cleanly must never be missing from the manifest. A shortfall accompanied by neither a missing file nor a hash-error line is the failure this criterion exists to catch.

### `STOR-061` Matched files are hashed once: SHA256 computed per match, reused by evidence

*supporting*

- **Must be true:** One SHA256 is computed per matched FILE and reused everywhere: the digest in alert/<rule>.txt, the row in evidence/file_mapping.txt and the file_sha256 column of the matches dataset are the same value, identical across every rule that hit that file, and equal to an independently computed digest.
- **Threshold:** For >= 20 distinct matched files: the 'File SHA256: <h>' value, the file_mapping.txt row for that path, the dataset row's file_sha256 and an independent `sha256sum`/`Get-FileHash` on the host all agree, all 64 lowercase hex. For at least one file matched by K >= 3 rules, all K 'File SHA256:' values are byte-identical. Row count in evidence/file_mapping.txt == count of 'YARA matches found in ' records in alerts_<run_id>.log. 0 occurrences of 'Failed to hash matched file ' in scan_errors_<run_id>.log.
- **Setup:** Round 2's flood, with at least three rules engineered to hit the same planted file so the K>=3 case exists.
- **Evidence:** 'File SHA256:' lines in <scanner_dir>/alert/<rule>.txt; the '<path> | <sha256>' rows in <scanner_dir>/evidence/file_mapping.txt; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields filename, rule, file_sha256`; `sha256sum` run over SSH on the same paths; 'Failed to hash matched file <path>: ' in logs/scan_errors_<run_id>.log.
- **Negative control:** A large NON-matching file planted in the same tree must appear in neither file_mapping.txt nor any alert file and must produce no digest anywhere — hashing is gated inside `if matches:`, so a build that hashed every scanned file would put it in the manifest. That control is what separates 'hashed once' from 'hashed always'.
- **Why this round:** Findings are Round 2's subject. Round 1 is deliberately clean, so no file is hashed at all and the cross-artefact identity has nothing to compare; the flood gives a large sample and files matched by several rules at once, which is what makes 'once per file, not once per rule' visible.

### `STOR-062` Per-offset match detail is deliberately NOT retained in memory

*core*

- **Must be true:** Process memory stays flat as detection volume grows — the uploader keeps no per-offset accumulator — and no results file of any kind is written under scanner_dir.
- **Threshold:** Over the flood: the final 'System Resources | ... Memory: X MB' reading is <= 2.0x the first reading taken after the 2-minute mark and <= 512 MB absolute, while alert_delivery.total_matches in scan_summary_<run_id>.json exceeds 100,000 offsets over the same window. Additionally, split the heartbeat series into halves by cumulative total_detections: the mean memory_mb of the second half must be <= 1.5x the mean of the first, even though the second half carries several times the detections. Do NOT use a Pearson correlation between memory_mb and cumulative detections — a bounded but monotonically drifting RSS correlates near 1.0 and would fail a correct build. `ls <scanner_dir>` shows only logs, control, alert, evidence, failed_rules, rule_cache and cleanup_script.sh/.bat (written by schedule_final_cleanup whenever the run produced an alert) — and no results dump of any name.
- **Setup:** Round 2's flood, including at least one multi-MB text file that a single rule hits thousands of times so one finding alone contributes >5,000 offsets — that is the shape that produced the ~15 GB RSS failure the design note records.
- **Evidence:** 'System Resources | CPU: <c>% | Memory: <m>MB | Disk I/O: <d>MB | Network: <n>MB' records in logs/performance_<run_id>.log with structured data {cpu_percent, memory_mb, disk_io_mb, network_mb} — emitted from _log_progress every config.log_interval (default 30 s, YARA_PROGRESS_LOG_SECS) via LogManager.log_system_resources and NOT gated by any monitor flag; total_detections in the paired 'Scan Progress |' record in logs/statistics_<run_id>.log, which is the series to bucket the memory readings against; alert_delivery.total_matches and matches in logs/scan_summary_<run_id>.json; `ps -o rss= -p <pid>` sampled every 15 s over SSH; `find <scanner_dir> -maxdepth 1`.
- **Negative control:** total_matches must actually reach six figures — flat memory on a scan with few offsets proves nothing, so the offset volume is a precondition of the criterion, not a bonus. Second control: 'not retained' must not become 'not counted' — the per-string census in alert/<rule>.txt ('Total string hits: N') and match_count on the dataset rows must still reconcile to the same total_matches, so the offsets are dropped from memory, never from the books.

### `STOR-064` Final comprehensive report lands only in statistics_<run_id>.log — and is cut at 4000 chars, losing scan_metadata / system_info / rule_compilation first

*supporting*

- **Must be true:** The comprehensive report exists only as a truncated prefix on one statistics line: json.dumps sorts keys, so the cut sacrifices rule_compilation, scan_metadata and system_info first, and those values are recoverable only from the init_data payload in the system log.
- **Threshold:** Exactly 1 record in logs/statistics_<run_id>.log matching 'COMPREHENSIVE SCAN REPORT | Efficiency Score: '; its serialized data blob is exactly 4000 characters followed by the literal '...(truncated)'; the line contains '"detection_results"' (first alphabetically, always survives) and 0 occurrences of '"rule_compilation"', '"scan_metadata"' or '"system_info"'; the same values (platform, python_version, yara_version, hostname, os_info, ip_addresses, scan_targets) ARE present in the 'YARA Scanner initialization completed' record's data in logs/system_<run_id>.log.
- **Setup:** Round 2's flood with a pack of >= 200 distinctly-named rules, so detection_results.detection_breakdown alone exceeds 4000 characters and the cut is guaranteed.
- **Evidence:** `grep 'COMPREHENSIVE SCAN REPORT' logs/statistics_<run_id>.log` and character-count of the data= blob; `grep -c '"system_info"'` / '"scan_metadata"' / '"rule_compilation"' on that same line; the init_data payload in logs/system_<run_id>.log. The report is never uploaded — despite the function name upload_final_comprehensive_report it emits no network traffic, so there is no tenant-side copy to fall back on.
- **Negative control:** The efficiency score itself must remain readable — it is in the message header, outside the truncated blob — so a truncated report is degraded, not destroyed. And the cap must be the 4000-char LogManager._log limit, not a report-specific one: confirm the same '...(truncated)' marker cannot appear on the small comprehensive_final_stats payloads attached to the 'Scan completed successfully in ' system record and the 'SCAN COMPLETED SUCCESSFULLY in ' statistics record on the same run.
- **Why this round:** Departs from the Round 3 'final report' prior: the truncation is driven purely by payload size, and only the flood's large detection_breakdown pushes the serialized blob past 4000 chars. In Round 3 the same report comes in well under the cap, where this criterion would FAIL a correct build rather than merely pass vacuously.

### `STOR-065` alerts_<run_id>.log carries TWO structured records per matched file, and is the only artefact holding the junction-resolved real_path

*supporting*

- **Must be true:** Every matched file produces exactly two structured records in alerts_<run_id>.log — 'YARA matches found in <path>', which is the only artefact carrying the junction-resolved real_path, and 'YARA detection event: N rules triggered in <basename>', which carries the per-file detection breakdown. Their counts each equal the number of DISTINCT matched files, not the finding count, and the two grains reconcile: summed top-level match_count on the first record type equals the run's finding total, while summed total_string_matches on the second equals the offset total.
- **Threshold:** count('YARA matches found in ') == count('YARA detection event: ') == number of distinct matched file paths (cross-check against the row count of evidence/file_mapping.txt). Sum of the top-level 'match_count' field over all 'YARA matches found in ' records == matches in scan_summary_<run_id>.json — equivalently, sum of len(rules_triggered) over the 'YARA detection event' records, since that record has no top-level match_count. Sum of 'total_string_matches' over the 'YARA detection event' records == alert_delivery.total_matches in that summary, and is strictly greater than matches. Every 'YARA matches found in ' record has a non-empty real_path key; no 'YARA detection event' record has one.
- **Setup:** Round 2's flood — no special setup; the standard flood run reaches this.
- **Evidence:** `grep -c 'YARA matches found in ' logs/alerts_<run_id>.log` and `grep -c 'YARA detection event: '` on the same file; the top-level match_count and real_path keys inside the first record type's data= JSON and the total_string_matches / rules_triggered / detections keys inside the second's; matches and alert_delivery.total_matches in logs/scan_summary_<run_id>.json; row count of <scanner_dir>/evidence/file_mapping.txt. Note the nested detections[].match_count is len(strings) for that rule (offset grain) — do not sum it against `matches`.
- **Negative control:** The counts must track FILES, not findings: on a flood where every file trips several rules, matches (findings) is several times the record count — if the two are equal, the per-file record is being emitted per rule. Second control: LogManager's per-category loggers are named loggers at INFO with propagate=False (lines 2249, 2288), so setup_logging's root-handler stripping must not suppress them — a run where diagnostics_<run_id>.log exists must still show both record types in alerts_<run_id>.log. Do NOT assert the with-delivery-off behaviour: the contract settles both channels ON in every round, so that half is not reachable and would be an unfalsifiable clause.
- **Why this round:** Findings are Round 2's subject and the flood is what makes the two grains (file-level records vs offset-level totals) diverge by orders of magnitude, which is what the reconciliation tests. The junction-specific divergence of real_path from file_path is Round 3's junction capability; here the claim is that the key is present and populated on every record.

### `STOR-071` Alert-directory byte ceiling degrades detail, never counts (`YARA_ALERT_DIR_MAX_MB`)

*core*

- **Must be true:** Once the alert directory's byte budget is reached, per-offset DETAIL stops being rendered while every per-finding count keeps being written — so the local counts still reconcile exactly against the matches dataset, and the number of degraded findings is booked.
- **Threshold:** With YARA_ALERT_DIR_MAX_MB=1 (CONFIG_ALERT_DIR_MAX_BYTES = 1048576) and a flood ruleset: count of 'Total string hits: ' lines across <scanner_dir>/alert/*.txt == alert_delivery.findings + alert_delivery.suppressed in scan_summary_<run_id>.json (every distinct rule x file finding with >= 1 string hit is still written). count of 'Offset detail omitted: alert directory byte budget reached (YARA_ALERT_DIR_MAX_MB).' lines == alert_detail_suppressed in the same summary, and is > 0. count of 'Matched Strings (showing ' lines == count('Total string hits: ') - alert_detail_suppressed. For every rule R: sum of the N values in R's 'Total string hits: N' lines == sum of match_count over R's rows in yara_scanner_matches_v3_* for this run_id. scan_summary's alert_dir_max_bytes == 1048576 and alert_bytes_written >= 1048576.
- **Setup:** Round 2's flood, SSH-launched with YARA_ALERT_DIR_MAX_MB=1 exported so the ceiling is reached early in the run (Action Center delivery cannot set module-scope env). Clear <scanner_dir>/alert first — initial_cleanup does this, but confirm.
- **Evidence:** <scanner_dir>/alert/*.txt (the three line families above); alert_dir_max_bytes, alert_bytes_written, alert_detail_suppressed and the alert_delivery block in logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp sum(match_count) by rule`.
- **Negative control:** Do NOT assert that `du -s <scanner_dir>/alert` stays under the ceiling — the over-budget test is evaluated BEFORE each write and the compact records keep adding bytes, so a correct build deliberately overshoots. The real control is the counts arm: alert_delivery counts and the dataset totals must be UNCHANGED relative to a same-flood run with YARA_ALERT_DIR_MAX_MB=0 (ceiling disabled), where alert_detail_suppressed == 0 and every finding renders its 'Matched Strings (showing ...)' block. Degradation must cost detail only, never a count.

## Delivery, Aggregation & Telemetry

### `DELI-001` Master upload kill-switch (UPLOAD_RESULTS)

*core*

- **Must be true:** On the shipped build both XDR channels are live: the lookup worker starts, finding alerts are queued, and neither the disabled-channel line nor an all-zero delivery book appears. The negative branch is asserted by absence, which is what makes the criterion able to fail on a build that flipped the literal to False.
- **Threshold:** uploads_<run_id>.log contains 'Lookup dataset worker started' exactly once and at least one line starting "Queued finding alert: rule='"; the string 'Lookup dataset uploads disabled (write_dataset=false, UPLOAD_RESULTS off, or XDR URL not configured)' appears 0 times; scan_summary_<run_id>.json alert_delivery.total_matches > 0, alert_delivery.alerts_queued > 0, dataset_delivery.queued > 0.
- **Setup:** Standard Round 2 flood run with default posture (create_alerts and write_dataset both true).
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log (log_upload from LookupDatasetUploader._worker and ResultsUploader.add_match's 'queued_match' throttled bucket); <scanner_dir>/logs/scan_summary_<run_id>.json fields alert_delivery.total_matches, alert_delivery.alerts_queued, dataset_delivery.queued.
- **Negative control:** The line is shared by three causes, so its ABSENCE is only meaningful when the other two are ruled out. Paired control: the DELI-003 run with options='write_dataset=false' MUST emit that same line exactly once — proving the line is not specific to UPLOAD_RESULTS. Therefore the kill-switch is isolated only by the conjunction: disabled line absent AND posture contains 'dataset=on' AND scan_summary matches_dataset is non-empty (a real XDR URL was resolved). Asserting the line is absent on a write_dataset=false run would fail a correct build.

### `DELI-002` Insert Parsed Alerts channel enable (create_alerts)

*core*

- **Must be true:** create_alerts gates ONLY the alert channel: with it off no alert is ever queued or POSTed, while the lookup dataset channel keeps writing the same matches rows for the same tree. The posture string reported to the operator agrees with the observed behaviour in both runs.
- **Threshold:** Run A (default): scan_summary_<run_id>.json.posture contains 'alerts=on'; alert_delivery.alerts_queued == alert_delivery.findings + alert_delivery.rollups and is > 0. Run B (options='create_alerts=false'): posture contains 'alerts=off'; count of "Queued finding alert: rule='" lines == 0; count of 'Alert batch ok (' lines == 0; alert_delivery.alerts_queued == 0 AND alert_delivery.findings == 0 AND alert_delivery.suppressed == 0; dataset_delivery.records_added > 0 and the COUNT(DISTINCT rule, filename) over the matches dataset for run B's run_id equals the same count for run A's run_id (same tree, same pack).
- **Setup:** Two Round 2 flood runs over the same tree and ruleset, the second delivered with options='create_alerts=false'. Every rule in the pack MUST carry a strings section — a condition-only rule produces match_count == 0, which yields neither a dataset row nor an alert and breaks the cross-channel comparison.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json fields posture, alert_delivery.{alerts_queued,findings,rollups}, dataset_delivery.records_added; <scanner_dir>/logs/uploads_<run_id>.log line counts; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | stats count()`.
- **Negative control:** Run B's dataset channel must be untouched — its matches-dataset row count must equal run A's for the same tree. A drop there means create_alerts is gating more than the alert channel.

### `DELI-003` Lookup dataset channel enable (write_dataset)

*core*

- **Must be true:** write_dataset off suppresses the ENTIRE dataset channel including the scan-lifecycle stream, not just match rows, while the alert channel is unaffected; and the dataset names still stamped into the summary are not evidence that anything was written.
- **Threshold:** Run B (options='write_dataset=false'): the line 'Lookup dataset uploads disabled (write_dataset=false, UPLOAD_RESULTS off, or XDR URL not configured)' appears exactly 1 time; scan_summary_<run_id>.json dataset_delivery.queued == batches_sent == records_added == records_updated == records_skipped == send_failures == rows_unconfirmed == undelivered == 0, while dataset_delivery.dropped > 0 and equals the number of (rule,file) findings that produced at least one string hit (i.e. run A's COUNT(DISTINCT rule, filename) over the matches dataset); scan_errors_<run_id>.log contains exactly 1 line 'Lookup uploader thread not alive - dropping rows for ' naming run B's matches_dataset; XQL over yara_scanner_scans_v3_* filtered to run B's run_id returns 0 rows (no 'initiated', no terminal row); posture contains 'dataset=off'; alert_delivery.successful_uploads > 0. Run A (default): the disabled line appears 0 times, dataset_delivery.dropped == 0, and the scans dataset holds >= 2 rows for run A's run_id.
- **Setup:** Two Round 2 flood runs over the same tree, the second delivered with options='write_dataset=false'.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log (LookupDatasetUploader.__init__ else-branch); <scanner_dir>/logs/scan_errors_<run_id>.log 'Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)' (LookupDatasetUploader._enqueue); <scanner_dir>/logs/scan_summary_<run_id>.json fields dataset_delivery.* (all nine keys), posture, matches_dataset, scans_dataset, alert_delivery.successful_uploads; XQL `dataset = yara_scanner_scans_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>"`.
- **Negative control:** scan_summary matches_dataset/scans_dataset are still populated in run B (the write-back to config precedes the gate), so those names must NOT be read as delivery. The dropped counter is the paired positive control: it proves the rows were built and offered and then refused for want of a worker, rather than the finding path having been silently skipped — a build that gated add_match on write_dataset would show dropped == 0 AND the same all-zero delivery, which the dropped > 0 clause is what distinguishes.

### `DELI-004` Alert batching into one insert_parsed_alerts POST

*core*

- **Must be true:** Alerts leave as batched lists, never one POST per alert, and no POST ever carries more than the 60-alert XDR ceiling; the effective batch size the worker announces is the clamped value.
- **Threshold:** uploads_<run_id>.log contains exactly one line 'Upload worker thread started (batch=60)'; every 'Alert batch ok (N alerts, HTTP 200)' line has 1 <= N <= 60; at least one line has N == 60 (batches genuinely fill under flood); and the sum of N over all 'Alert batch ok (' lines equals scan_summary_<run_id>.json alert_delivery.successful_uploads exactly. Clamp probe (endpoint shell, YARA_ALERT_BATCH=200 exported before the payload): the announcement still reads 'batch=60'.
- **Setup:** Round 2 flood sized so more than 120 findings are queued before the alert cap. The clamp probe needs the env var set in the process environment before module import, so it runs over SSH on the Linux endpoint rather than through the Action Center payload.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log lines 'Upload worker thread started (batch=<n>)' (ResultsUploader._upload_worker) and 'Alert batch ok (<n> alerts, HTTP <code>)' (_upload_alert_batch, throttled bucket 'alert_upload_ok'); scan_summary_<run_id>.json alert_delivery.successful_uploads.
- **Negative control:** The 'alert_upload_ok' bucket is throttled at 20 full lines (_throttled_log full=20), so the sum-equals-successful_uploads identity is only valid while successful batches stay under 20 — at the default CONFIG_ALERT_MAX_PER_SCAN=500 that holds (max 9 finding batches plus rollups). If the run produced more than 20 successful batches the sum clause must be dropped, not failed; the N <= 60 and N == 60 clauses still stand.

### `DELI-005` Partial alert batch idle flush

*supporting*

- **Must be true:** A partial batch is POSTed on the idle timer during the scan rather than being held until shutdown, and never earlier than the flush interval measured from the previous flush.
- **Threshold:** At least one 'Alert batch ok (N alerts, HTTP 200)' line with N < 60 has a timestamp strictly earlier than the 'Draining ... pending alert(s)' line (i.e. it flushed mid-scan, not at stop); its gap from the preceding 'Alert batch ok' line is >= 10.0s; and no 'Alert batch ok' line with N < 60 that is timestamped BEFORE the 'Draining ' line has a gap from the preceding flush of < 10.0s. Partial batches at or after the 'Draining ' line (and the final one before 'Upload worker thread stopped') are excluded — the sentinel/stop flushes bypass the idle timer by design.
- **Setup:** Round 2 flood whose matching tree is walked first and is small enough that the alert queue goes idle with a partial batch outstanding while the walk continues over a large clean remainder.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch ok (<n> alerts, HTTP <code>)' timestamps (LogManager formatter, ms resolution) and the 'Draining <n> pending alert(s) (~<m> batches, up to <x>s)...' line from ResultsUploader.stop.
- **Negative control:** A full 60-alert batch must NOT be subject to the 10s wait — size-triggered flushes may appear less than 10s after the previous flush, and the timing clause applies only to lines with N < 60. Equally, the terminal drain flush must NOT be held for 10s: asserting the interval on the post-'Draining' partial would fail a correct build.

### `DELI-006` Alert POST pacing against the ~600 alerts/min ceiling

*core*

- **Must be true:** Consecutive alert POSTs are separated by at least the minimum inter-POST interval even while the queue is saturated, so the scanner cannot self-inflict the shared per-API-key rate limit.
- **Threshold:** For every consecutive pair of 'Alert batch ok (' lines in uploads_<run_id>.log, the timestamp delta is >= 6.95s (7s pacing, allowing ms rounding); the run is genuinely saturated (at least one N == 60 batch AND a 'Draining <n> pending alert(s)' line is present); and steady-state throughput (sum of N over all ok lines MINUS the first line's N, divided by the elapsed seconds from the first ok line to the last) is <= 600 alerts/min. The first POST is unpaced by design (_last_alert_post starts at 0.0) and must be excluded from the throughput numerator.
- **Setup:** Round 2 flood producing more than 300 queued alerts so the queue is never empty between POSTs.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch ok (<n> alerts, HTTP <code>)' timestamps; the 'Draining <n> pending alert(s) (~<m> batches, up to <x>s)...' line; ALERT_MIN_BATCH_INTERVAL pacing sleep in ResultsUploader._upload_alert_batch.
- **Negative control:** The pacing must apply ONLY to the alert channel — 'Lookup batch ok (<n> rows)' lines in the same log may be closer together than 7s. Requiring the 7s gap on lookup POSTs would fail a correct build.

### `DELI-007` Alert batch retry ladder with exponential backoff + jitter

*supporting*

- **Must be true:** A retryable alert POST failure is retried exactly four times with a doubling, jittered backoff, and the terminal failure is booked to failed_uploads and written to the error log rather than being silently dropped.
- **Threshold:** For a single failing batch: retry lines 'Retry 1/4', 'Retry 2/4', 'Retry 3/4', 'Retry 4/4' each appear once, followed by 'Alert batch abandoned after 4 attempts (<n> alerts lost)' in scan_errors_<run_id>.log; the printed delay for attempt k lies in [0.5*2^(k-1), 1.0*2^(k-1)] seconds (k=1: 0.5-1.0; k=2: 1.0-2.0; k=3: 2.0-4.0; k=4: 4.0-8.0), capped at 30.0; across the first 20 retry lines the delays are not all equal to their ceiling (jitter is present); alert_delivery.failed_uploads == sum of <n> over all abandonment lines.
- **Setup:** Dedicated Round 2 probe run whose snippet prelude rebinds `_build_xdr_insert_alerts_url` to an in-process 127.0.0.1 responder that refuses connections (or answers HTTP 503 with no Retry-After), leaving the lookup channel pointed at the real tenant.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch failed (HTTP <code>). Body: ... Retry <k>/4 in <x>s.' and 'Alert batch network error: ... Retry <k>/4 in <x>s.' (throttled bucket 'alert_upload_retry'); <scanner_dir>/logs/scan_errors_<run_id>.log 'Alert batch abandoned after 4 attempts (<n> alerts lost)'; scan_summary_<run_id>.json alert_delivery.failed_uploads.
- **Negative control:** On the healthy tenant run of the same flood, zero 'Retry <k>/4' lines and zero 'Alert batch abandoned' lines must appear and failed_uploads must be 0 — the ladder must not fire on success.

### `DELI-008` Retry-After header honoured on alert throttling

*supporting*

- **Must be true:** When the alert endpoint returns a retryable status carrying a numeric Retry-After header, the printed retry delay equals that header value verbatim and displaces both the backoff ladder and the rate-limited cooldown; a non-numeric header falls back to the ladder instead of erroring.
- **Threshold:** Stub answering 429 with 'Retry-After: 11': every retry line reads 'Retry <k>/4 in 11.0s.' for k=1..4 — a value outside the ladder's range for k=1..3 (max 4.0s) and outside the rate-limited cooldown (14.0s). Stub answering 429 with 'Retry-After: soon': no line prints 11.0s; the delays fall back to the rate-limited cooldown floor of >= 14.0s and no exception is logged.
- **Setup:** Round 2 probe run whose prelude starts an in-process HTTP responder on 127.0.0.1, rebinds `_build_xdr_insert_alerts_url` to it and sets XDR_AUTH_TYPE='advanced' to skip the auth probe. Two variants: numeric header, then non-numeric header.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch failed (HTTP 429) [rate-limited]. Body: ... Retry <k>/4 in <x>s.' (_upload_alert_batch Retry-After parse); the stub's own request log for the wall-clock spacing between attempts.
- **Negative control:** A retryable response carrying NO Retry-After header in the same probe must produce ladder/cooldown delays, never 11.0s — otherwise the header parse is being applied where no header exists.

### `DELI-009` Rate-limit classification from status code OR response body

*supporting*

- **Must be true:** A batch is classified rate-limited on HTTP 429 OR on any retryable status whose body contains the substring 'rate limit', and only such batches get the doubled-pacing cooldown; a transport error clears the classification.
- **Threshold:** Variant A (HTTP 500, body contains 'Exceeding the rate limit', no Retry-After): every retry line carries the literal ' [rate-limited]' marker and the printed delay is >= 14.0s (2 * ALERT_MIN_BATCH_INTERVAL). Variant B (HTTP 500, body 'internal error', no Retry-After): no ' [rate-limited]' marker on any line and every delay <= 8.0s (the plain ladder ceiling at attempt 4). Variant C (three rate-limited 500s, then connection refused on attempt 4, with ALERT_REQUEUE_ENABLED true and the delivery budget not expired): the batch produces 'Alert batch abandoned after 4 attempts (<n> alerts lost)' and NO 'Alert batch rate-limited after 4 attempts; requeuing' line, and alert_delivery.requeued does not increase across that batch — proving the transport error cleared the classification the three preceding 500s had set.
- **Setup:** Round 2 probe run with the in-process responder bound to `_build_xdr_insert_alerts_url`, cycling the three response variants across successive batches.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log retry lines from the 'alert_upload_retry' bucket, checked for the exact substring ' [rate-limited]' and the printed '<x>s' delay; for Variant C also the 'alert_requeue' bucket line 'Alert batch rate-limited after 4 attempts; requeuing <n> alerts for a later window.' (must be absent for that batch) and <scanner_dir>/logs/scan_errors_<run_id>.log 'Alert batch abandoned after 4 attempts (<n> alerts lost)'; scan_summary_<run_id>.json alert_delivery.requeued.
- **Negative control:** Variant B is the load-bearing negative: a build that classifies every 5xx as rate-limited would pass Variant A and fail here. The 14s floor must NOT be applied when a numeric Retry-After is present — that case is DELI-008's, and asserting the floor there would fail a correct build.

### `DELI-010` Requeue rate-limited alert batches for a later window

*core*

- **Must be true:** A batch that exhausts its retries because it was rate-limited is put back on the queue rather than dropped, requeued alerts are NOT re-counted into alerts_queued (so the delivery books still balance), and requeuing stops once the global delivery budget expires.
- **Threshold:** With ALERT_REQUEUE_ENABLED true and the budget rebound to 60s: at least one line 'Alert batch rate-limited after 4 attempts; requeuing <n> alerts for a later window.'; scan_summary_<run_id>.json alert_delivery.requeued > 0; alert_delivery.successful_uploads + failed_uploads + undelivered == alert_delivery.alerts_queued EXACTLY (requeues must not inflate the denominator); the last requeuing line's timestamp is <= (timestamp of 'Upload worker thread started (batch=60)') + 60s + 30s; after that point rate-limited batches produce 'Alert batch abandoned after 4 attempts' instead.
- **Setup:** Round 2 probe run whose prelude rebinds `_build_xdr_insert_alerts_url` to an in-process responder returning HTTP 500 with body 'Exceeding the rate limit' and sets ALERT_MAX_DELIVER_SECS = 60 (read at upload-thread start, after the prelude).
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch rate-limited after 4 attempts; requeuing <n> alerts for a later window.' (bucket 'alert_requeue') and the requeued= field of the 'Alert delivery final: ...' line; scan_summary_<run_id>.json alert_delivery.{requeued,alerts_queued,successful_uploads,failed_uploads,undelivered}.
- **Negative control:** Control run with the prelude setting ALERT_REQUEUE_ENABLED = False against the same responder: zero 'requeuing' lines, alert_delivery.requeued == 0, and the same batches instead land in failed_uploads — the books must still balance in both runs.

### `DELI-011` HTTP 2xx with a JSON `false` body counted as a failure

*supporting*

- **Must be true:** A 2xx response whose body is the bare JSON boolean false is booked as a failure, not a success; any other 2xx body shape — including an unparseable one — is booked as a success.
- **Threshold:** Responder variant returning HTTP 200 with body `false`: scan_errors_<run_id>.log contains 'XDR Insert Parsed Alerts returned false'; alert_delivery.successful_uploads == 0; alert_delivery.failed_uploads > 0 and failed_uploads + undelivered == alerts_queued exactly; zero 'Alert batch ok (' lines. Responder variant returning HTTP 200 with body `{"reply": "ok"}`: zero 'returned false' lines; failed_uploads == 0; successful_uploads > 0 and successful_uploads + undelivered == alerts_queued exactly.
- **Setup:** Round 2 probe run with the in-process responder bound to `_build_xdr_insert_alerts_url`, run twice with the two body shapes.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log 'XDR Insert Parsed Alerts returned false' (throttled bucket 'alert_upload_err', error level); scan_summary_<run_id>.json alert_delivery.{successful_uploads,failed_uploads,alerts_queued}.
- **Negative control:** The dict-body variant is the control: a build that treats ANY falsy body (empty dict, empty list, empty string) as failure would fail it. Only `isinstance(parsed, bool)` may gate the verdict.

### `DELI-012` Backlog-scaled end-of-scan alert drain

*supporting*

- **Must be true:** The end-of-scan drain window is computed from the actual pending backlog rather than a flat timeout, is floored and capped by the two constants, and the announcement is emitted only when there is a backlog to drain.
- **Threshold:** The line 'Draining <N> pending alert(s) (~<M> batches, up to <X>s)...' satisfies M == ceil(N/60) and X == min(300, max(60, M*15)) exactly (X printed with no decimals, from `drain_secs = min(ALERT_DRAIN_MAX_SECS, max(ALERT_DRAIN_SECS, batches * (ALERT_MIN_BATCH_INTERVAL + 8)))`); the wall time from that line to 'Upload worker thread stopped' is <= X + THREAD_CLEANUP_TIMEOUT (60s) + 5s; on a run whose alert queue is empty at stop, the 'Draining ' line appears 0 times.
- **Setup:** Round 2 flood sized so at least 120 alerts are still queued when the walk ends (put the matching tree last), plus the Round 1 clean run as the empty-queue control.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Draining <n> pending alert(s) (~<m> batches, up to <x>s)...' and 'Upload worker thread stopped' (ResultsUploader.stop / _upload_worker exit).
- **Negative control:** The Round 1 clean run (no findings, empty alert queue at stop) must contain zero 'Draining ' lines — a build that announces a drain unconditionally would still show a plausible-looking number and pass a presence-only check.

### `DELI-013` Alert thread join timeout

*supporting*

- **Must be true:** The join on the upload thread is bounded: exactly one of the two outcome lines is written, and on a healthy run it is the success one, reached within the drain window plus the join timeout.
- **Threshold:** Exactly one of 'Upload thread terminated successfully' / 'Upload thread did not terminate within 60s timeout' appears in uploads_<run_id>.log; on the healthy flood it is 'Upload thread terminated successfully'; the timestamp delta from the 'Draining <n> pending alert(s) (~<m> batches, up to <x>s)...' line to that outcome line is <= X + 60 + 2 seconds, where X is the announced drain window.
- **Setup:** Round 2 flood with a real backlog at stop (same run as DELI-012).
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log lines 'Upload thread terminated successfully' and 'Upload thread did not terminate within 60s timeout' (ResultsUploader.stop join block); the 'Draining ...' line timestamp.
- **Negative control:** Both lines must never appear in the same run — they are mutually exclusive branches of one if/elif. Two occurrences would indicate stop() ran twice, which the _stop_done guard must prevent.

### `DELI-014` Honest leftover accounting for undelivered alerts

*core*

- **Must be true:** Alerts still queued when the drain budget expires are counted as undelivered and stay counted: nothing booked undelivered is later also booked successful. The summary JSON — written after the uploader stops — must reproduce the ledger line's ok= value exactly, never a larger one.
- **Threshold:** scan_summary_<run_id>.json alert_delivery.successful_uploads == the ok= value in the 'Alert delivery final:' line, and alert_delivery.undelivered == that line's undelivered= value, byte-for-byte equal in both directions. undelivered > 0 iff the line '<n> alert(s) undelivered within the drain budget (shared rate-limit ceiling)' is present in scan_errors_<run_id>.log with the same n. On the healthy flood: undelivered == 0 and that error line is absent.
- **Setup:** Two Round 2 runs: (a) healthy tenant flood; (b) probe run with the in-process responder returning HTTP 500 'Exceeding the rate limit' and the prelude setting ALERT_DRAIN_MAX_SECS = 20 so the drain budget genuinely expires with a backlog.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert delivery final: findings=<> queued=<> ok=<> failed=<> undelivered=<> suppressed=<> rollups=<> requeued=<>'; <scanner_dir>/logs/scan_errors_<run_id>.log '<n> alert(s) undelivered within the drain budget (shared rate-limit ceiling) — the yara_scanner_matches dataset holds the complete record'; scan_summary_<run_id>.json alert_delivery.{successful_uploads,undelivered}.
- **Negative control:** Run (b) must show its losses as failed_uploads where batches were actually attempted and only the never-attempted residue as undelivered — a build that re-books attempted-and-failed alerts as undelivered would make ok+failed+undelivered exceed alerts_queued, which DELI-015's identity then catches.

### `DELI-015` Alert delivery books (upload_stats fields)

*core*

- **Must be true:** The alert channel's books reconcile: everything ever queued is accounted for exactly once as delivered, failed or undelivered; queued equals findings plus rollups; and the offset-grain counter is a strict superset of the finding grain. All nine fields are present in the summary and agree with the final ledger line.
- **Threshold:** alert_delivery contains exactly the nine keys total_matches, findings, alerts_queued, successful_uploads, failed_uploads, suppressed, rollups, undelivered, requeued. successful_uploads + failed_uploads + undelivered == alerts_queued (exact). alerts_queued == findings + rollups (exact). total_matches >= findings + suppressed, and strictly greater on a multi-string flood. Every one of the eight ledger-line fields equals its JSON counterpart.
- **Setup:** Round 2 flood on the healthy tenant, plus the DELI-007 and DELI-010 probe runs so the identity is checked with non-zero failed_uploads and non-zero requeued as well as on the clean path.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json alert_delivery object (ResultsUploader.get_upload_stats); <scanner_dir>/logs/uploads_<run_id>.log 'Alert delivery final: findings=<> queued=<> ok=<> failed=<> undelivered=<> suppressed=<> rollups=<> requeued=<>'.
- **Negative control:** Presence of the fields is not the test — a build that double-books a requeued alert keeps all nine keys and still writes the line. The exact equalities are what fail. Conversely, alerts dropped by an alert_dict build error legitimately shrink ok+failed below alerts_queued, so any run with a non-zero 'alert_build_err' bucket must be excluded rather than failed.

### `DELI-016` Alert grain is one alert per (rule, file) finding, deduped within scan

*core*

- **Must be true:** The alert channel emits one alert per (rule, file) finding — not per matched offset — and dedupes on that pair within the scan, so a file matched by three rules yields three findings and a rule hitting one file at 10,000 offsets yields one.
- **Threshold:** alert_delivery.findings + alert_delivery.suppressed == COUNT(DISTINCT rule, filename) over the matches dataset for this run_id (exact). alert_delivery.total_matches == SUM(match_count) over the same rows (exact). total_matches / (findings + suppressed) > 1 on the flood (offset grain strictly coarser than finding grain). A planted file matched by exactly 3 distinct rules contributes exactly 3 to findings+suppressed.
- **Setup:** Round 2 flood whose pack contains one rule with an unanchored short string that hits a large file thousands of times, plus one planted file crafted to match three distinct rules. Every rule in the pack must carry a strings section (a condition-only rule produces no string hits and no dataset row, breaking the identity).
- **Evidence:** scan_summary_<run_id>.json alert_delivery.{findings,suppressed,total_matches}; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count_distinct(rule, filename), sum(match_count)`.
- **Negative control:** The dedup key is (rule, full path), not rule alone and not basename — two files with the same basename in different directories matched by one rule must contribute 2, not 1. The 150,000-entry memory bound on the dedup set is not exercised at the default 500-finding cap and must not be asserted.

### `DELI-017` Alert storm cap per scan

*core*

- **Must be true:** Per-finding alerting stops exactly at the per-scan cap, the remainder is tallied as suppressed rather than lost, and the cap cannot be moved from an options string.
- **Threshold:** On a flood producing more than 500 distinct (rule,file) findings: alert_delivery.findings == 500 exactly; alert_delivery.suppressed == (distinct findings) - 500 and is > 0; findings + suppressed == the matches-dataset distinct (rule,file) count for the run_id. Sub-cap control run (< 500 distinct findings): suppressed == 0, rollups == 0, findings == the distinct count. Options rejection: a delivery with options='alert_max_per_scan=100' returns a SNIPPET_ERROR containing "Unknown option 'alert_max_per_scan'" and no scan starts.
- **Setup:** Round 2 flood engineered for >500 distinct (rule,file) findings; a second bounded run under 500 as the control; a third one-line delivery carrying the rejected option.
- **Evidence:** scan_summary_<run_id>.json alert_delivery.{findings,suppressed,rollups}; XQL distinct (rule,filename) count over yara_scanner_matches_v3_* for the run_id; the Action Center stdout SNIPPET_ERROR traceback for the options run (_parse_options_string ValueError).
- **Negative control:** The sub-cap run is the load-bearing negative — a build with an off-by-one or an always-on cap would still show findings==500 on the flood but would suppress on the small run too. Suppression must never reduce the DATASET row count: the matches dataset must still carry every suppressed finding.

### `DELI-018` Per-rule storm rollup alerts at scan end

*core*

- **Must be true:** Every rule that had findings suppressed produces exactly one rollup alert naming that rule and host, the rollups cover the whole suppressed population, and no rollup is minted for a rule that suppressed nothing.
- **Threshold:** alert_delivery.rollups == the number of distinct rules with at least one suppressed finding; the line 'Queued <N> storm-rollup alert(s) covering <M> suppressed finding(s)' has N == alert_delivery.rollups and M == alert_delivery.suppressed exactly; XQL over the alerts dataset, filtered to alerts whose parsed alert_description.scan_id equals THIS run's scan_id, returns exactly N alerts whose alert_name matches 'YARA Match Storm: <rule> | Host: <hostname>', one per suppressing rule, each carrying alert_description.match_data.rollup == true and match_data.suppressed_count, with those counts summing to M.
- **Setup:** The DELI-017 over-cap flood, with the pack shaped so at least three distinct rules exceed the cap and at least one rule matches fewer than the cap so it contributes no rollup.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Queued <n> storm-rollup alert(s) covering <m> suppressed finding(s)' (ResultsUploader._queue_rollup_alerts); scan_summary_<run_id>.json alert_delivery.{rollups,suppressed} and scan_id; XQL `dataset = alerts | filter alert_name contains "YARA Match Storm: "`, then parse alert_description and keep only rows whose scan_id equals this run's scan_id (a scan-window filter is unsafe: the rollup alert_name is stable per rule+host and XDR updates the existing alert on a repeat storm).
- **Negative control:** The rule that stayed under the cap must have NO storm alert. On the sub-cap control run the 'Queued ... storm-rollup' line must be absent entirely (the method returns before logging when nothing was suppressed) — asserting a 'Queued 0 storm-rollup' line would fail a correct build.

### `DELI-019` Alert identity: rule + basename + 8-char path hash + host

*supporting*

- **Must be true:** Alert identity is (rule, basename, 8-hex hash of the full path, host): two same-named files in different directories produce two distinct alerts, and re-scanning the same file produces the same alert_name so XDR updates rather than duplicates.
- **Threshold:** Two planted files with identical basenames at different absolute paths, both matched by one rule, yield exactly 2 alerts whose names both match 'YARA Match: <rule> | <basename> (#<8 hex>) | Host: <hostname>' and whose 8-hex tags differ; each tag equals the first 8 hex characters of sha1(<full path> encoded utf-8, errors='replace'), computable offline. Idempotency half: a SECOND run over a tree whose distinct (rule,file) finding count is below CONFIG_ALERT_MAX_PER_SCAN (so alert_delivery.suppressed == 0 in both runs) produces no NEW alert_name string — the set of alert_name values is identical across the two runs.
- **Setup:** Round 2, two planted decoys sharing a basename at different paths (e.g. <tree>/a/svchost_decoy.bin and <tree>/b/svchost_decoy.bin), both matching one dedicated rule. The identity half runs on the full flood; the idempotency half runs twice over a BOUNDED sub-tree producing fewer than 500 distinct (rule,file) findings, so the cap never selects a different subset between runs.
- **Evidence:** XQL `dataset = alerts | filter alert_name contains "YARA Match: "` over the two scan windows, joined to scan_id via the parsed alert_description; scan_summary_<run_id>.json scan_id for each run.
- **Negative control:** A file whose path resolves empty would take the literal tag '#nopath'; that branch must not fire for either decoy. And the tag must be exactly 8 hex characters — not the full sha1 — or the identity string changes shape.

### `DELI-020` Alert wire payload shape and placeholder network fields

*supporting*

- **Must be true:** Every alert reaches XDR with the pinned vendor/product identity, the placeholder network fields at their fixed values, and a local IP taken from the host's first non-loopback IPv4 — with the payload self-declaring that the network fields are meaningless.
- **Threshold:** For every alert whose parsed alert_description.scan_id equals this run's scan_id: vendor == 'Custom', product == 'YARA Scanner', action_local_port == 65535, action_remote_port == 65535, action_remote_ip == '127.0.0.1', action_status == 'Reported'; action_local_ip is a dotted IPv4 that does not start with '127.' and equals the first non-loopback IPv4 of the endpoint (read directly from the host, or from scan_summary_<run_id>.json ip_address only when that value itself contains a '.'); event_timestamp falls between the run's start and end; the parsed alert_description carries network_fields_are_placeholders == true.
- **Setup:** Round 2 flood on an endpoint with a routable IPv4 (the standard lab VMs qualify).
- **Evidence:** XQL over the alerts dataset filtered to alerts whose parsed alert_description.scan_id equals this run's scan_id — fields vendor/product/action_local_ip/action_local_port/action_remote_ip/action_remote_port/action_status/event_timestamp; scan_summary_<run_id>.json ip_address and duration_secs.
- **Negative control:** On an IPv6-only host the fallback to 127.0.0.1 is correct behaviour, so the 'not 127.0.0.1' clause applies only to endpoints that have a non-loopback IPv4 — asserting it unconditionally would fail a correct build. Equally, action_local_ip and scan_summary.ip_address are selected differently (first dotted non-loopback vs ip_addresses[0]); requiring them equal on a dual-stack host would fail a correct build.

### `DELI-021` alert_description JSON envelope

*supporting*

- **Must be true:** alert_description is a JSON string that parses into exactly the nine-key envelope, the embedded match_data carries at most three hit samples, and the dataset-only fields never leak into the alert.
- **Threshold:** json.loads(alert_description) succeeds and its top-level keys are exactly {source, tenant_id, scan_id, hostname, os_info, ip_address, message, network_fields_are_placeholders, match_data} for EVERY alert of this scan_id, rollups included; source == 'yara_scanner'. For every alert whose match_data does NOT carry rollup == true: len(match_data.matches_sample) == min(3, match_data.match_count) — so a 1-hit finding shows exactly 1 sample and a 5,000-hit finding shows exactly 3 — and each sample matches '<string_id>@<offset>'. The keys 'file_size' and 'scan_folder' appear nowhere in any envelope.
- **Setup:** Round 2 flood containing at least one planted single-hit finding and one many-thousand-hit finding, so both ends of the 3-sample cap are present.
- **Evidence:** XQL over the alerts dataset for this scan_id, parsing alert_description; cross-check match_count against the matching row in XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>"`.
- **Negative control:** The 3 is a cap, not a pad: the single-hit finding must show one sample. A build that always emits three would pass an 'at most 3' check and fail here. file_size and scan_folder exist on the dataset row for the same finding — their presence there and absence in the envelope is the paired control. Storm-rollup alerts carry no matches_sample key by design (_queue_rollup_alerts' data dict omits it); asserting the sample rule on them would fail a correct build.

### `DELI-022` Alert severity mapping

*supporting*

- **Must be true:** The run's alert_severity parameter is the sole driver of alert severity — no code path sets threat_level — and the same value independently drives the dataset row's severity field; both map through the same table.
- **Threshold:** Run with alert_severity='high': yara_processing_<run_id>.log contains 'Default XDR alert severity: high'; every alert of that scan_id has severity 'High'; every matches-dataset row for that run_id has severity == 'High'. Run with alert_severity='low': the log line reads 'low', every alert severity is 'Low' and every row severity is 'Low'. Across both runs zero alerts carry 'Medium'. Invalid value ('urgent'): the Action Center stdout carries the line "CRITICAL ERROR: Critical scanner error: Invalid alert_severity 'urgent'. Use low, medium, or high." and the result line begins 'SCAN_RESULT: Scan failed: 0 files scanned'; no scan_summary_<run_id>.json and no logs/ files are produced for a new run_id (ScanConfig raised before LogManager was built).
- **Setup:** Three Round 2 deliveries over the same bounded flood tree with alert_severity set to 'high', 'low' and 'urgent' respectively.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log 'Default XDR alert severity: <value>' (ErrorLogger's own INFO FileHandler); XQL over the alerts dataset filtered to this run's scan_id via parsed alert_description (severity column) and over yara_scanner_matches_v3_* (severity field); for the invalid run, the Action Center stdout lines 'CRITICAL ERROR: Critical scanner error: ...' and 'SCAN_RESULT: Scan failed: ...' emitted by run()'s own except block (well inside the 10,240-character cap) — NOT a SNIPPET_ERROR traceback, which run() prevents by catching the ValueError itself.
- **Negative control:** 'Medium' must appear only when alert_severity == 'medium'. Because threat_level is never populated anywhere in the source, an alert whose severity differs from the run parameter's mapping means the severity_map default has started firing — that is the failure, not a variant.

### `DELI-023` Throttled upload logging buckets

*supporting*

- **Must be true:** Each repetitive upload-log bucket prints its first 20 messages in full, then exactly one suppression notice, then only a running count every 1000 — so a sustained failure is visible without ballooning the log.
- **Threshold:** Blackhole probe run, bucket 'alert_upload_retry': exactly 20 plain 'Alert batch network error: ... Retry <k>/4 in <x>s.' lines, then exactly one line beginning '[alert_upload_retry] further similar messages suppressed; will summarize every 1000. Example: ', then lines '[alert_upload_retry] <n> occurrences so far; latest: ' only for n in {1000, 2000, ...}, with the trailing text truncated to at most 120 characters. Healthy flood, bucket 'queued_match' with 500 findings: exactly 20 "Queued finding alert: rule='" lines, exactly one '[queued_match] further similar messages suppressed' line, and zero '[queued_match] <n> occurrences so far' lines (500 < 1000).
- **Setup:** The DELI-007 blackhole probe run for the retry bucket; the standard Round 2 flood for the queued_match bucket.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log for the 'upload'-level buckets (alert_upload_ok, alert_upload_retry, alert_requeue, queued_match, queue_full, added_matches) and <scanner_dir>/logs/scan_errors_<run_id>.log for the 'error'-level buckets (alert_upload_err, alert_build_err, rollup_err).
- **Negative control:** A bucket that never exceeds 20 occurrences must emit NO suppression notice — on the healthy flood the 'alert_upload_ok' bucket (about 9 batches) must have zero '[alert_upload_ok] further similar messages suppressed' lines. 'Lookup batch ok' lines go through log_upload directly and are NOT throttled; asserting a suppression notice for them would fail a correct build.

### `DELI-024` Lookup dataset naming: prefix + schema version + shard + monthly rotation

*core*

- **Must be true:** Both dataset names are assembled from all four segments in order, are stamped into the scan summary verbatim, match the names the uploader thread announces, and are the names that actually hold this run's rows.
- **Threshold:** scan_summary_<run_id>.json matches_dataset matches ^yara_scanner_matches_v3_[a-z][a-z0-9_]{0,33}_[0-9a-f]{6}_20\d{4}$ and scans_dataset is the identical string with '_matches_' replaced by '_scans_'; the trailing 6 digits equal run_id[:6]; both strings appear verbatim inside the single line 'Lookup dataset upload thread starting (datasets: <matches>, <scans>; batch_size: 500)'; XQL against each literal name filtered to this run_id returns > 0 rows.
- **Setup:** Standard Round 2 flood run.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json fields matches_dataset, scans_dataset and schema == 'yara_scan_summary/v1'; <scanner_dir>/logs/uploads_<run_id>.log 'Lookup dataset upload thread starting (datasets: ..., ...; batch_size: <n>)'; XQL against the two literal dataset names.
- **Negative control:** Empty matches_dataset/scans_dataset in the summary is a real failure mode (the write-back to config sits in a bare try/except), so blank strings must fail rather than be skipped — the uploader's thread-start line is the cross-check that the names existed, not a substitute for the summary fields.

### `DELI-025` Per-writer lookup dataset sharding

*core*

- **Must be true:** Each endpoint writes its own dataset by default, so no two hosts ever write the same lookup dataset; the shard selector's 'none' family produces an unsharded name rather than a literal 'none' label.
- **Threshold:** Default runs on two different endpoints produce two different matches_dataset values in scan_summary_<run_id>.json, each ending '_<slug of that host>_<6 hex>_<YYYYMM>' where the 6 hex == sha1(that host's RAW hostname).hexdigest()[:6]; querying each endpoint's literal matches dataset name returns rows for that endpoint's run_id only, and 0 rows for the other endpoint's run_id. Run with options='lookup_shard=none': matches_dataset == 'yara_scanner_matches_v3_<YYYYMM>' with no shard segment, and the string '_none_' appears nowhere in either dataset name.
- **Setup:** Round 2 flood delivered to two endpoints simultaneously (which is also what exercises the concurrency the sharding exists to defuse), plus a third delivery to one of them with options='lookup_shard=none'.
- **Evidence:** scan_summary_<run_id>.json matches_dataset on each endpoint; XQL over yara_scanner_matches_v3_* grouping distinct hostname per dataset.
- **Negative control:** 'none', 'shared' and 'off' all reach the unsharded branch; any other literal (e.g. 'wave1') is slugified into a shard segment. An EMPTY value does NOT: options='lookup_shard=' is falsy and falls back to LOOKUP_DATASET_SHARD ('endpoint'), producing the per-host sharded name — asserting the unsharded name for the empty label would fail a correct build. The load-bearing negative is that a build treating 'none' as a label produces a dataset ending '_none_<hash>_<YYYYMM>', which still looks well-formed and passes a regex-only check.

### `DELI-026` Shard label slugification with collision-proof hash

*supporting*

- **Must be true:** An arbitrary shard label is slugified to XDR-legal form and suffixed with a 6-hex hash of the ORIGINAL label, so two labels that slugify identically still land in different datasets and a label starting with a digit is still legal.
- **Threshold:** Run with options='lookup_shard=Prod Site #1': matches_dataset ends '_prod_site_1_<h>_<YYYYMM>' where h == sha1('prod site #1').hexdigest()[:6] (the label is lowercased before hashing). Run with options='lookup_shard=site-1' and run with options='lookup_shard=site_1': both slugify to 'site_1' but the 6-hex suffixes DIFFER, so the two runs write two distinct datasets. Run with options='lookup_shard=2026wave': the segment begins 'h_2026wave_'. A label longer than 32 characters is truncated to exactly 32 slug characters before the hash is appended.
- **Setup:** Five short Round 2 deliveries to one endpoint, each carrying a different lookup_shard label: 'Prod Site #1', 'site-1', 'site_1', '2026wave', and one label of at least 40 characters (e.g. 'emea_datacenter_rack_seventeen_row_four_north'). The hashes are computed offline from the LOWERCASED label strings (LookupDatasetUploader lowercases shard_cfg before _dataset_shard_suffix); the >32-char run decides the truncation clause.
- **Evidence:** scan_summary_<run_id>.json matches_dataset for each of the four runs; XQL `dataset = yara_scanner_matches_v3_*` listing the resulting dataset names.
- **Negative control:** The 'site-1' / 'site_1' pair is the load-bearing negative: a build that hashes the SLUG instead of the original label produces one dataset for both and passes every single-label check. Note the default 'endpoint' branch hashes the RAW hostname (not lowercased), so that suffix must be computed from the un-lowercased hostname.

### `DELI-027` Monthly lookup dataset rotation

*supporting*

- **Must be true:** Rotation appends the run's own month to both dataset names and is genuinely switchable off, and the suffix is derived from the run_id rather than from wall-clock at query time.
- **Threshold:** Default run: matches_dataset and scans_dataset both end '_' + run_id[:6], and that value equals the YYYYMM of the run's start date (scan_date is run_id.split('_',1)[0]). Probe run with prelude `import os; os.environ['YARA_LOOKUP_ROTATION']='none'`: neither name carries a trailing _YYYYMM (both end with the 6-hex shard suffix), the substring '_none' appears in neither name, and for EACH of the two unrotated names exactly one _ensure_one outcome line appears naming it — "'<name>' created (schema fields: 22)", "'<name>' already exists - will append rows", or "'<name>' already exists (reported via add_dataset 500) - will append rows" — followed by rows landing there (XQL against the literal unrotated name filtered to the probe run_id returns > 0 rows).
- **Setup:** Standard Round 2 flood, plus one probe delivery whose prelude sets YARA_LOOKUP_ROTATION=none in os.environ before calling run() (the value is read inside LookupDatasetUploader.__init__, so a prelude assignment is seen).
- **Evidence:** scan_summary_<run_id>.json matches_dataset/scans_dataset and run_id for both runs; <scanner_dir>/logs/uploads_<run_id>.log 'Lookup dataset '<name>' created (schema fields: 22)' or ''<name>' already exists - will append rows'.
- **Negative control:** Rotation off must produce a name with NO month segment, not a literal '_none' segment. The cross-month behaviour (a new month minting a new dataset) cannot be forced inside one test window and must not be asserted; the run_id-derived suffix equality is what is checkable.

### `DELI-028` Lookup schema version tag in the dataset name

*core*

- **Must be true:** The shipped row shape matches the live v3 dataset's fixed schema — no field is silently skipped — and bumping the version tag creates a fresh dataset rather than attempting an in-place schema change.
- **Threshold:** Default run: both dataset names carry the segment '_v3_'; scan_summary_<run_id>.json dataset_delivery.records_skipped == 0 and every 'Lookup batch ok (<n> rows): added=<a>, updated=<u>, skipped=<s>' line has s == 0. Probe run with prelude `LOOKUP_SCHEMA_VERSION = "99"`: the uploads log shows 'Lookup dataset 'yara_scanner_matches_v99_...' created (schema fields: 22)', that run's rows land there with skipped=0, and XQL over the v3 dataset returns 0 rows for the probe run's run_id.
- **Setup:** Standard Round 2 flood, plus one probe delivery whose prelude rebinds the module global LOOKUP_SCHEMA_VERSION (read at LookupDatasetUploader construction, after the prelude runs).
- **Evidence:** scan_summary_<run_id>.json matches_dataset, scans_dataset, dataset_delivery.records_skipped; <scanner_dir>/logs/uploads_<run_id>.log 'Lookup batch ok (<n> rows): added=<a>, updated=<u>, skipped=<s>' and 'Lookup dataset '<name>' created (schema fields: 22)'; XQL against both the v3 and v99 dataset names filtered on run_id.
- **Negative control:** records_skipped == 0 on the DEFAULT run is the load-bearing assertion — XDR skips unknown fields silently, so a row-shape change shipped without a version bump shows up nowhere else. The probe run must leave the v3 dataset untouched; rows appearing in both would mean the version tag is not actually reaching the name.

### `DELI-029` Explicit dataset pre-creation (get_datasets probe then add_dataset)

*supporting*

- **Must be true:** Both datasets are proven to exist before any row is POSTed — via the probe or by creating them — and the first add_data never fails with 'Dataset not found'.
- **Threshold:** For each of the two dataset names exactly one of these lines appears: 'Lookup dataset '<name>' already exists - will append rows', 'Lookup dataset '<name>' created (schema fields: 22)', or 'Lookup dataset '<name>' already exists (reported via add_dataset 500) - will append rows'; the field count on any create line is exactly 22 for both datasets; the uploads log contains zero 'Lookup batch failed (HTTP 400' lines and zero 'Lookup dataset create failed (HTTP' lines; every one of the two lines precedes the first 'Lookup batch ok (' line in file order.
- **Setup:** Round 2 flood on a month where the datasets already exist (repeat run), plus the first run of a fresh shard/month to exercise the create branch.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log lines from LookupDatasetUploader._ensure_one; scan_summary_<run_id>.json dataset_delivery.records_added.
- **Negative control:** On the repeat run the create branch must NOT fire — an 'already exists' outcome with a spurious create line would mean the probe result is being ignored. Probe failure is tolerated by design ('get_datasets probe failed (HTTP <code>): ...; will attempt add_dataset anyway.'), so that line alone must not fail the criterion.

### `DELI-030` add_dataset 'already exists' error body treated as success

*supporting*

- **Must be true:** When the existence probe misses a dataset that is really there, XDR's HTTP 500 'already exists' body is read as success — no error is logged, no create is retried, and the run appends to the existing dataset rather than failing.
- **Threshold:** Probe run whose prelude rebinds XDR_GET_DATASETS_PATH to a non-existent path: uploads_<run_id>.log contains 'get_datasets probe failed (HTTP <code>): ...; will attempt add_dataset anyway.' twice, then 'Lookup dataset '<name>' already exists (reported via add_dataset 500) - will append rows' twice; scan_errors_<run_id>.log contains zero 'Lookup dataset create failed (HTTP' lines; dataset_delivery.records_added > 0; scan_summary_<run_id>.json matches_dataset is byte-identical to the previous run's.
- **Setup:** One Round 2 probe delivery to an endpoint whose datasets already exist, with the prelude setting `XDR_GET_DATASETS_PATH = "/public_api/v1/xql/get_datasets_does_not_exist"` so the probe cannot find them and the add_dataset already-exists branch is forced.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log (LookupDatasetUploader._ensure_one probe-failure and already_exists branches); <scanner_dir>/logs/scan_errors_<run_id>.log; scan_summary_<run_id>.json matches_dataset, dataset_delivery.records_added.
- **Negative control:** The run must not mint a differently-named dataset to work around the failure — the dataset name is unchanged, and the standard run on the same host must show the ordinary ''<name>' already exists - will append rows' line instead, proving the 500 branch is only reached when the probe genuinely misses.

### `DELI-031` Matches dataset row schema (22 fields on the wire)

*core*

- **Must be true:** Every matches row carries all 22 declared fields with the v3 finding grain, and the JSON-encoded columns are internally consistent: the string-ID census totals the true match count, the offsets/strings samples are equal-length and capped, and truncated is true exactly when the sample is short.
- **Threshold:** An XQL projection naming all 22 fields (tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, rule, filename, file_size, file_sha256, file_creation_time, scan_folder, match_count, offsets, strings, string_ids, truncated, severity, event_timestamp_ms, date_of_scan) returns every one of them non-null for every row of this run_id, and no scanner-written field outside that list appears in the dataset's schema (engine columns such as _time are excluded from the comparison). For every row: match_count >= 1; json array length of offsets == json array length of strings == min(match_count, 50); truncated == (match_count > 50); the values of the string_ids JSON object sum to match_count exactly; run_id equals this run's run_id and scan_date equals run_id[:8].
- **Setup:** Round 2 flood containing at least one finding with more than 50 offsets and at least one with fewer, so both sides of the truncated predicate are present.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>" | fields tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, rule, filename, file_size, file_sha256, file_creation_time, scan_folder, match_count, offsets, strings, string_ids, truncated, severity, event_timestamp_ms, date_of_scan` (all 22 projected, so a missing column is a query error rather than a silent pass); cross-check against <scanner_dir>/logs/uploads_<run_id>.log line "Rule '<rule>' matched <file> at <n> offsets; embedded a sample of <k> in the dataset row (truncated=true; full detail retained in local results)."
- **Negative control:** A finding with match_count <= 50 must have truncated == false and must carry ALL its offsets, not a sample — a build that always truncates would pass an 'offsets length <= 50' check and fail here. The string_ids census is uncapped even when offsets are sampled, so its sum must equal match_count on truncated rows too.

### `DELI-032` Scans lifecycle row schema (22 fields on the wire)

*supporting*

- **Must be true:** Every lifecycle row carries all 22 declared fields, its derived numbers are internally consistent, and the legacy-named throttle_mode column actually reports the CPU-governor policy rather than a retired throttle value.
- **Threshold:** An XQL projection naming all 22 fields (tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, status, scan_folder, files_scanned, files_skipped, detections, valid_rules, failed_rules, scan_rate_fps, elapsed_secs, total_paused_secs, throttle_mode, posture, event_timestamp_ms, message) returns every one of them for every row of this run_id. For every row with elapsed_secs > 0: abs(scan_rate_fps - files_scanned/elapsed_secs) <= max(0.02, 0.01 * scan_rate_fps) — elapsed_secs is stored rounded to 2 dp while scan_rate_fps was computed from the unrounded value. Ordered by event_timestamp_ms, files_scanned and elapsed_secs are non-decreasing. throttle_mode == 'headroom' (the run's cpu_guarantee) and is never one of 'off'/'script'/'os'. posture equals scan_summary_<run_id>.json.posture verbatim.
- **Setup:** Standard Round 2 flood (any run long enough to emit at least the initiated and terminal rows).
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>" | fields tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, status, scan_folder, files_scanned, files_skipped, detections, valid_rules, failed_rules, scan_rate_fps, elapsed_secs, total_paused_secs, throttle_mode, posture, event_timestamp_ms, message | sort asc event_timestamp_ms`; scan_summary_<run_id>.json posture and throttle_mode.
- **Negative control:** The 'initiated' row legitimately has files_scanned == 0 and elapsed_secs ~ 0, so the scan_rate_fps consistency clause applies only to rows with elapsed_secs > 0 — applying it to the initiated row would fail a correct build.

### `DELI-033` Scan lifecycle row emission (initiated / running / completed / cancelled / failed)

*core*

- **Must be true:** A run writes exactly one 'initiated' row, zero or more 'running' heartbeats, and exactly one terminal row whose status matches the outcome the summary reports — never two terminals, never none.
- **Threshold:** XQL over the scans dataset filtered to run_id: count(status='initiated') == 1; count(status in ('completed','cancelled','failed')) == 1; the terminal status equals scan_summary_<run_id>.json.outcome exactly; the initiated row has the minimum event_timestamp_ms and the terminal row the maximum; every other row has status == 'running' and message == 'heartbeat'; the terminal row's files_scanned equals scan_summary.files_scanned.
- **Setup:** Standard Round 2 flood for the completed path. The 'cancelled' and 'failed' variants are produced by Round 3's mid-walk cancellation and its induced-failure run and are checked against this same identity there.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>" | fields status, message, files_scanned, event_timestamp_ms | sort asc event_timestamp_ms`; scan_summary_<run_id>.json outcome and files_scanned.
- **Negative control:** No lifecycle row for this run_id may appear in any OTHER shard's scans dataset. Decide it with literal names rather than an engine pseudo-field: query this run's own `yara_scanner_scans_v3_<shard>_<YYYYMM>` (expect the full row set) and, separately, the other test endpoint's `yara_scanner_scans_v3_<other-shard>_<YYYYMM>` and the unsharded `yara_scanner_scans_v3_<YYYYMM>`, each filtered to this run_id — both must return 0 rows.

### `DELI-034` Terminal lifecycle row emitted BEFORE the uploaders are stopped

*core*

- **Must be true:** The terminal row is enqueued while the lookup uploader is still alive, so it actually reaches the tenant: the dashboard-visible terminal row exists and nothing was dropped for want of a live uploader thread.
- **Threshold:** scan_summary_<run_id>.json dataset_delivery.dropped == 0; scan_errors_<run_id>.log contains zero lines matching 'Lookup uploader thread not alive - dropping rows for'; XQL returns exactly one terminal row for this run_id whose files_scanned equals scan_summary.files_scanned (proving it was emitted after the workers drained, not before).
- **Setup:** Round 2 flood with a large lookup backlog at shutdown, so the ordering is under real pressure rather than trivially satisfied by an empty queue.
- **Evidence:** scan_summary_<run_id>.json dataset_delivery.dropped and files_scanned; <scanner_dir>/logs/scan_errors_<run_id>.log 'Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)'; XQL terminal row for the run_id.
- **Negative control:** dropped == 0 alone is not sufficient and the terminal row alone is not sufficient — both must hold. A build that emits the row after stop() shows dropped >= 1 AND a missing terminal row, and the drop line is suppressed after the first occurrence, so the counter is the reliable half.

### `DELI-038` Lookup batch size (rows per add_data POST)

*core*

- **Must be true:** Rows are POSTed in batches of at most the configured size, the announced size is the effective one, and the dataset channel's books reconcile: every queued row is accounted for as landed, unconfirmed, never-sent, dropped, or in an abandoned batch.
- **Threshold:** uploads_<run_id>.log contains 'Lookup dataset upload thread starting (datasets: <matches>, <scans>; batch_size: 500)'; every 'Lookup batch ok (<n> rows)' line has n <= 500 and at least one has n == 500; the count of 'Lookup batch ok (' lines == dataset_delivery.batches_sent exactly (these lines go through log_upload directly and are not throttled). Books: dataset_delivery.queued - undelivered - rows_unconfirmed - (sum of <n> over all 'Lookup batch abandoned after <k> attempt(s) (<n> rows lost)' lines) == records_added + records_updated + records_skipped. `dropped` is NOT part of this identity — _enqueue's dropped branch returns before incrementing queued, so dropped rows were never in the queued denominator; assert dropped separately. On the healthy flood: dropped == undelivered == rows_unconfirmed == send_failures == 0 and records_added + records_updated + records_skipped == queued exactly.
- **Setup:** Round 2 flood producing more than 1,500 matches rows so multiple full batches are sent; the DELI-042 stub run supplies the non-zero send_failures case for the general form of the identity.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Lookup dataset upload thread starting (...; batch_size: <n>)' and 'Lookup batch ok (<n> rows): added=<a>, updated=<u>, skipped=<s>'; <scanner_dir>/logs/scan_errors_<run_id>.log 'Lookup batch abandoned after <k> attempt(s) (<n> rows lost)'; scan_summary_<run_id>.json dataset_delivery (all nine keys).
- **Negative control:** dataset_delivery.queued counts rows for BOTH datasets, so the matches-dataset row count alone must not be used as the denominator — the scans lifecycle rows (initiated + heartbeats + terminal) are part of queued and their omission would make a correct build appear short.

### `DELI-039` Per-target lookup flush timers

*supporting*

- **Must be true:** Each destination dataset flushes on its own timer, so the low-volume scans stream is never held behind a large matches backlog: a lifecycle row is queryable on the tenant while the matches backlog is still draining.
- **Threshold:** Structural (always decidable, healthy flood): the count of 'Lookup batch ok (<n> rows)' lines >= ceil(matches-row count for this run_id / 500) + ceil(scans-row count for this run_id / 500), no line ever reports more than 500 rows, and the sum of n over all lines equals dataset_delivery.queued — proving matches and scans rows are never merged into one batch. Timer (on the idle-gap run described in the setup): an XQL query issued at least 180s after start, while the matches dataset still holds fewer rows for this run_id than its final count, returns the 'initiated' row for this run_id; and at least one 'Lookup batch ok (<n> rows)' line with n <= 5 appears between two 'Lookup batch ok (500 rows)' lines in file order.
- **Setup:** Two runs. (a) Round 2 flood with a matches backlog of several thousand rows, for the structural clauses. (b) A run shaped so the lookup queue actually goes idle mid-scan — the matching sub-tree walked FIRST, followed by a large clean remainder (the DELI-005 shape) — so the worker's queue.get() raises Empty and the per-target 30s sweep is exercised; poll the tenant with XQL during that quiet stretch. Under an unbroken flood the Empty branch is never entered and the scans batch cannot flush on its timer, so the timer clauses must not be asserted on run (a).
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_<shard>_<YYYYMM> | filter run_id = "<run_id>"` issued mid-run, and the same over yara_scanner_matches_v3_* for the in-flight row count; <scanner_dir>/logs/uploads_<run_id>.log 'Lookup batch ok (<n> rows): ...' line sequence.
- **Negative control:** The 'Lookup batch ok' line does not name its target dataset, so a small-N line is only evidence of the scans stream when the matches stream is demonstrably mid-backlog — a small-N line at end of scan is just the final partial matches batch and must not be counted. A 'Lookup batch ok (501 rows)' line would mean the per-target batching collapsed. And a run with no Empty period must not be failed on the timer clauses: the sweep is unreachable there by design.

### `DELI-040` Pre-write jitter before every add_data POST

*low*

- **Must be true:** Every add_data POST is preceded by a random delay drawn from [0, jitter], paid once per batch outside the retry loop — so the inter-batch spacing carries a spread proportional to the jitter setting, and setting the jitter to zero removes it.
- **Threshold:** Probe run with the prelude rebinding LOOKUP_WRITE_JITTER_SECS = 30: across at least 25 consecutive 'Lookup batch ok (' gaps, (max gap - min gap) >= 15.0s and the mean gap exceeds the control run's mean by between 8.0s and 22.0s (expected +15s = 30/2). Control run with the prelude rebinding LOOKUP_WRITE_JITTER_SECS = 0 over the same tree: (max gap - min gap) is at least 12.0s smaller than the jittered run's, and its mean gap is the smaller of the two.
- **Setup:** Two Round 2 probe deliveries over the same bounded flood tree producing at least 27 lookup batches (>= 13,500 matches rows) so 25+ inter-batch gaps are available in each run, differing only in the rebound module global LOOKUP_WRITE_JITTER_SECS (read at call time inside _send_batch, so a prelude assignment takes effect). Both runs must write to the same shard and month so server-side merge cost is comparable.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Lookup batch ok (<n> rows): ...' timestamps (ms resolution) for both runs; scan_summary_<run_id>.json dataset_delivery.batches_sent to confirm equal batch counts across the two runs.
- **Negative control:** At the shipped 2s default the added mean delay is ~1s, inside the server-merge variance, so the default run cannot decide this and must not be used as the measurement. The jitter is paid once per _send_batch call, not per retry — retry spacing in a failing run must NOT be expected to grow with the jitter setting.

### `DELI-041` Full-jitter backoff for add_data retries (distinct from the alert ladder)

*supporting*

- **Must be true:** Lookup retries use full-jitter backoff — a uniform draw over a growing ceiling, not a doubling ladder — and it is a different ladder from the alert channel's in the same run.
- **Threshold:** For every 'Retry <k>/6 in <x>s.' line on the lookup channel: x >= 0.2 and x <= max(0.4, min(6.0, 2.0^k)) — so k=1: x <= 2.0; k=2: x <= 4.0; k>=3: x <= 6.0; and across the six lines of one batch the delays are NOT monotonically non-decreasing (at least one later attempt has a strictly smaller delay than an earlier one). In the same run the alert channel's 'Retry <k>/4 in <x>s.' delays DO satisfy 0.5*2^(k-1) <= x <= 2^(k-1).
- **Setup:** Round 2 probe run whose prelude rebinds `_build_xdr_lookups_add_data_url` and `_build_xdr_insert_alerts_url` to an in-process 127.0.0.1 responder returning HTTP 500 with a body containing no rate-limit text, and rebinds LOOKUP_DRAIN_TIMEOUT = 900 so the per-batch deadline cannot truncate the ladder.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Lookup batch failed (HTTP 500). Body: ... Retry <k>/6 in <x>s.' and 'Lookup batch network error: ... Retry <k>/6 in <x>s.' (_lookup_backoff_delay) versus 'Alert batch failed (HTTP 500). ... Retry <k>/4 in <x>s.' (_exp_backoff_delay) in the same file.
- **Negative control:** Full jitter can legitimately draw a large value early and a small one late, so 'delays increase with k' must NOT be asserted for the lookup channel — that is the alert channel's property and asserting it here would fail a correct build. A single batch's six draws could by chance be increasing; require the non-monotonic property across at least three abandoned batches.

### `DELI-042` add_data retry cap

*supporting*

- **Must be true:** A batch gets at most the configured number of POST attempts against retryable failures; exhausting them books one send_failure and logs the batch as lost with its true row count, rather than looping or vanishing silently.
- **Threshold:** For one abandoned batch: retry lines 'Retry 1/6' through 'Retry 6/6' each appear exactly once, followed by 'Lookup batch abandoned after 6 attempt(s) (<n> rows lost)' in scan_errors_<run_id>.log with n equal to that batch's row count; zero 'Lookup batch deadline reached' lines (proving the cap, not the deadline, ended it); dataset_delivery.send_failures == the number of 'Lookup batch abandoned' lines.
- **Setup:** Round 2 probe run whose prelude rebinds `_build_xdr_lookups_add_data_url` to an in-process responder returning HTTP 500 (no rate-limit text) and rebinds LOOKUP_DRAIN_TIMEOUT = 900 so the per-batch wall-clock deadline (budget minus 20s) cannot short-circuit the ladder — at the shipped 150s default with a 120s read timeout the deadline trips after roughly 10s and the abandonment line reports fewer than 6 attempts.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Lookup batch failed (HTTP 500). Body: ... Retry <k>/6 in <x>s.' and 'Lookup batch deadline reached (<n> rows) after <m> attempts; stopping retries so the drain exits within budget.'; <scanner_dir>/logs/scan_errors_<run_id>.log 'Lookup batch abandoned after <k> attempt(s) (<n> rows lost)'; scan_summary_<run_id>.json dataset_delivery.send_failures.
- **Negative control:** On the healthy tenant flood there must be zero 'Lookup batch abandoned' lines and dataset_delivery.send_failures == 0. And the abandonment message reports the ACTUAL attempt count reached, so a run where the deadline fired legitimately shows fewer than 6 — asserting exactly 6 without neutralising the deadline would fail a correct build.

### `DELI-043` Split connect/read timeouts for add_data

*supporting*

- **Must be true:** Connect-phase and read-phase failures of an add_data POST are bounded by DIFFERENT timeouts and classified differently. With the tenant's TCP connect blackholed, each POST attempt fails ~5s after its connect begins, the echoed requests exception carries '(connect timeout=5)', dataset_delivery.rows_unconfirmed stays 0 and no 'Lookup batch read-timed-out' line is emitted (isinstance(e, requests.exceptions.ReadTimeout) is False for a ConnectTimeout, so that branch is not taken and the loss is booked as send_failures). With a peer that completes the TCP handshake and never answers, the batch's first 'Lookup batch network error:' line carries 'Read timed out. (read timeout=120)' and appears no sooner than 120s after that attempt's POST began.
- **Threshold:** LOOKUP_POST_TIMEOUT = (5, 120): the 5s connect half is a literal, the 120s read half is YARA_LOOKUP_READ_TIMEOUT. Measure BOTH probes from the 'XDR auth probe (advanced) network error:' line that immediately precedes each batch error, not from batch start: with XDR_AUTH_TYPE=auto, _probe_auth_type re-probes get_datasets at DEFAULT_TIMEOUT_SECS=20 before every attempt because a network error is deliberately not cached, so a batch start is ~25s (blackhole) / ~140s (hung peer) ahead of its own error line. Connect probe: each 'Lookup batch network error:' line lands <= 8s after that preceding probe-error line (5s connect + 3s slack). Read probe: >= 120.0s after it. Every network-error line ends 'Retry n/6 in Xs.' (LOOKUP_ADD_DATA_MAX_RETRIES = 6), but n reaches only 1 on both probes — the per-batch deadline (LOOKUP_DRAIN_TIMEOUT-20 = 130s vs a 120s read timeout) refuses attempt 2 after ~10s, so exactly one POST is made and the batch ends 'Lookup batch abandoned after 1 attempt(s) (N rows lost)'.
- **Setup:** Two supplementary flood runs on the Linux endpoint (xdr-agent), driven over SSH, each sized so at least one full 500-row batch is POSTed. (a) `iptables -A OUTPUT -d <tenant-ip> -p tcp --dport 443 -j DROP` for the connect probe — DROP, not REJECT: a REJECT gives ECONNREFUSED (NewConnectionError), not a ConnectTimeout. (b) For the read probe do NOT use a TLS listener — requests verifies certificates, so a self-signed peer raises requests.exceptions.SSLError during the handshake and the read phase is never reached. Use a plain TCP listener that accepts and never writes, with the snippet prelude setting DEFAULT_XDR_API_URL = 'http://127.0.0.1:<port>' (ScanConfig re-reads DEFAULT_XDR_API_URL into the XDR_API_URL global at config time, so a prelude assignment takes effect). Note get_datasets/add_dataset/insert_parsed_alerts use DEFAULT_TIMEOUT_SECS=20, not LOOKUP_POST_TIMEOUT, so only the add_data batch shows the 120s bound.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log lines matching 'Lookup batch network error:' — their timestamps relative to the immediately preceding 'XDR auth probe (advanced) network error:' line, and the requests exception text they echo: '(read timeout=120)' for the hung peer vs '(connect timeout=5)' for the blackhole; presence/absence of 'Lookup batch read-timed-out'; scan_errors_<run_id>.log 'Lookup batch abandoned after 1 attempt(s)'; scan_summary_<run_id>.json dataset_delivery.rows_unconfirmed and dataset_delivery.send_failures.
- **Negative control:** The read-timeout branch must NOT capture connect-phase errors: the blackhole run must leave dataset_delivery.rows_unconfirmed == 0 and emit zero 'Lookup batch read-timed-out' lines, while dataset_delivery.send_failures > 0 and one 'Lookup batch abandoned after 1 attempt(s) (N rows lost)' line appears per batch — a ConnectTimeout is booked as an accounted failure, never as 'unconfirmed'.

### `DELI-044` Read-timeout attempt cap and the 'rows_unconfirmed' verdict

*core*

- **Must be true:** A read timeout is never blind-retried past the cap: the batch is POSTed at most LOOKUP_TIMEOUT_MAX_ATTEMPTS times, then abandoned as UNCONFIRMED — rows_unconfirmed increases by exactly len(batch), send_failures does NOT increase for that batch, and no third POST of the same rows is made.
- **Threshold:** LOOKUP_TIMEOUT_MAX_ATTEMPTS = 2 (YARA_LOOKUP_TIMEOUT_ATTEMPTS default) — one retry. For a full batch the line reads 'Lookup batch read-timed-out 2x (500 rows)' (LOOKUP_DATASET_BATCH_SIZE = 500). Exactly ONE generic 'Lookup batch network error:' line precedes it for that batch. dataset_delivery.rows_unconfirmed == 500 x (number of read-timed-out full batches); dataset_delivery.send_failures unchanged by them.
- **Setup:** The DELI-043 (b) hung-peer probe using the corrected listener (plain TCP over http://, not TLS — a self-signed TLS peer raises SSLError and never reaches the read phase), with the snippet prelude ALSO setting LOOKUP_DRAIN_TIMEOUT = 360. At the shipped 150s the per-batch deadline (budget-20 = 130s) refuses the second attempt long before the read cap can be reached. 360 rather than 300 because with XDR_AUTH_TYPE=auto each attempt first spends DEFAULT_TIMEOUT_SECS=20 in an uncached get_datasets auth probe, so attempt 1 ends at ~140s and the retry gate needs now+120 <= budget-20. Size the planted tree so at least one full 500-row batch is queued.
- **Evidence:** uploads_<run_id>.log 'Lookup batch read-timed-out 2x (500 rows); the server merge may have committed anyway - stopping retries to avoid duplicate rows (counted as rows_unconfirmed).'; the count of 'Lookup batch network error:' lines preceding it for that batch; scan_summary_<run_id>.json dataset_delivery.rows_unconfirmed and dataset_delivery.send_failures.
- **Negative control:** A connect-phase timeout must NOT count toward the 2-attempt cap and must NOT increment rows_unconfirmed — on the DELI-043 (a) blackhole run rows_unconfirmed stays 0 and the loss is booked as send_failures with a 'Lookup batch abandoned after 1 attempt(s)' line. Do NOT claim the connect path 'keeps the full 6-attempt budget': at the shipped 150s budget the per-batch deadline refuses attempt 2 on the connect path as well, so the distinguishing fact is the BOOKING (send_failures vs rows_unconfirmed), not the attempt count.

### `DELI-045` Per-batch wall-clock deadline so the drain cannot be killed mid-POST

*supporting*

- **Must be true:** A retry that cannot finish inside the drain budget is REFUSED and the batch exits through the accounted-loss path, never silently killed mid-POST: the 'Lookup batch deadline reached' line is followed in the same run by 'Lookup batch abandoned after M attempt(s) (N rows lost)' with the same M, and dataset_delivery.send_failures increments by exactly 1 for that batch. The refusal never pre-empts the FIRST POST — at least one attempt is always made regardless of how the knobs are tuned.
- **Threshold:** Deadline = batch start + max(1.0, drain_budget - 20). At shipped values (LOOKUP_DRAIN_TIMEOUT = 150 during the scan, since _drain_budget is None until stop()) the deadline is +130s, so against a 120s read timeout the SECOND attempt is necessarily refused: the line reads 'Lookup batch deadline reached (N rows) after 1 attempts' and the abandoned line reads 'after 1 attempt(s) (N rows lost)', with the SAME N on both and N == 500 on a full batch. The count of 'Lookup batch deadline reached' lines with M == 0 must be 0.
- **Setup:** The DELI-043 (b) hung-peer probe at SHIPPED drain values (no prelude override), using the corrected listener from DELI-043: a plain TCP listener that accepts and never writes, with DEFAULT_XDR_API_URL = 'http://127.0.0.1:<port>' set in the snippet prelude. Size the planted tree so at least one FULL 500-row batch is queued before the drain, otherwise the row count on the line is the partial batch size.
- **Evidence:** uploads_<run_id>.log 'Lookup batch deadline reached (N rows) after M attempts; stopping retries so the drain exits within budget.'; scan_errors_<run_id>.log 'Lookup batch abandoned after M attempt(s) (N rows lost)'; scan_summary_<run_id>.json dataset_delivery.send_failures.
- **Negative control:** On the standard Round 2 flood against the live tenant, zero 'Lookup batch deadline reached' lines appear — the refusal must fire only when the remaining budget genuinely cannot cover another read timeout, not on every retry.

### `DELI-046` add_data response row accounting with dual key names

*core*

- **Must be true:** The 2xx response is parsed under BOTH the documented key names (added/updated/skipped) and the ones XDR actually returns ("rows added"/"rows updated"/"rows skipped"), so records_added is the true landed count across both lookup datasets and not silently 0: dataset_delivery.records_added equals the number of matches rows PLUS the number of scans-lifecycle rows XQL returns for this run_id, and the per-batch added= values sum to it.
- **Threshold:** For every 'Lookup batch ok (N rows): added=A, updated=U, skipped=S' line, A+U+S == N. Sum of A over all such lines == dataset_delivery.records_added, exactly. (XQL count over yara_scanner_matches_v3_* for the run_id) + (XQL count over yara_scanner_scans_v3_* for the run_id) == dataset_delivery.records_added, exactly, with no tolerance — the matches count ALONE is short by the lifecycle rows, because _send_batch credits the shared upload_stats regardless of which of the two datasets the batch targeted. dataset_delivery.batches_sent == the number of 'Lookup batch ok' lines.
- **Evidence:** uploads_<run_id>.log 'Lookup batch ok (N rows): added=…, updated=…, skipped=…'; scan_summary_<run_id>.json dataset_delivery.{records_added,records_updated,records_skipped,batches_sent}; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count() as rows` AND `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | comp count() as rows`, summed.
- **Negative control:** The parser must not report added=N when nothing landed: on DELI-073's stunted-schema probe the same responses must yield added=0, skipped=N — the dual-key acceptance must read the server's real verdict, not default every field to a positive number.

### `DELI-047` Concurrent final drain of the two lookup datasets

*supporting*

- **Must be true:** At end of scan BOTH lookup datasets are flushed in the same final drain and neither is starved: the run's remaining matches rows land, the terminal scans-lifecycle row lands, 'Lookup dataset worker stopped' is emitted only after both drain threads have been joined, and the whole drain fits inside the join budget.
- **Threshold:** Zero 'Lookup uploader thread did not stop within Xs' lines; dataset_delivery.undelivered == 0; exactly one row with status == "completed" for the run_id in yara_scanner_scans_v3_* AND the run's remaining matches rows present in yara_scanner_matches_v3_*. Attribute the two branches on the TENANT, not in the log: the 'Lookup batch ok (N rows): added=…' line carries no dataset name, so no log line can be assigned to 'the matches batch' or 'the scans batch'. The last two 'Lookup batch ok' lines are within LOOKUP_DRAIN_PER_BATCH_SECS = 45s of each other and both precede 'Lookup dataset worker stopped' in file order.
- **Setup:** Round 2 flood sized so matches rows are still queued at stop() AND at least one scans-lifecycle row is pending, so pending targets > 1 and the concurrent branch is taken rather than the single-target serial branch.
- **Evidence:** uploads_<run_id>.log: the two trailing 'Lookup batch ok (N rows)' lines and their timestamps, then 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)'; scan_summary_<run_id>.json dataset_delivery.undelivered; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status`.
- **Negative control:** A run with only ONE dataset pending at drain time must take the serial branch (len(pending) <= 1) and emit a single trailing 'Lookup batch ok' line — the criterion must not read a one-batch drain as a failed concurrent drain. Reach it with a short run whose matches queue is already empty at stop(), leaving only the terminal lifecycle row pending.

### `DELI-048` Backlog-scaled lookup drain budget

*core*

- **Must be true:** The final-flush budget scales with the actual backlog rather than being a flat window: the budget printed on the 'Lookup drain:' line equals min(600, max(150, ceil(pending_rows/500) x 45)) for the pending_rows reported on that same line.
- **Threshold:** LOOKUP_DRAIN_TIMEOUT = 150, LOOKUP_DRAIN_PER_BATCH_SECS = 45, LOOKUP_DRAIN_MAX_SECS = 600, LOOKUP_DATASET_BATCH_SIZE = 500. Exact match, budget printed with 0 decimals. The run must reach pending_rows > 1700 (>= 4 batches) so the computed budget exceeds the 150s floor and the claim is not vacuous.
- **Setup:** Round 2 flood with a ruleset matching essentially every file, over a tree large enough that the 30s idle flush timer has not drained the matches queue by scan end.
- **Evidence:** uploads_<run_id>.log 'Lookup drain: N rows pending (~M batches), budget Xs'; absence of 'Lookup uploader thread did not stop within Xs'; scan_summary_<run_id>.json dataset_delivery.undelivered.
- **Negative control:** The line is gated on pending_rows > 0 — a run that ends with an empty lookup queue must emit NO 'Lookup drain:' line at all while still emitting 'Lookup dataset worker stopped'.

### `DELI-049` Honest leftover accounting for undelivered dataset rows

*core*

- **Must be true:** Rows still queued when the drain budget expires are booked undelivered and reported as an error, never allowed to read as delivered: dataset_delivery.undelivered equals the N in the scan_errors line, queued - (records_added + records_updated + records_skipped) >= undelivered, and delivery_shortfall names them explicitly.
- **Threshold:** Exact equality between the N in 'Lookup drain budget expired with N rows undelivered' and scan_summary dataset_delivery.undelivered. delivery_shortfall contains the substring '<N> never sent'. undelivered > 0 on the probe run (otherwise the claim is vacuous).
- **Setup:** Round 2 flood delivered with a snippet prelude setting LOOKUP_DRAIN_TIMEOUT = 5 and LOOKUP_DRAIN_MAX_SECS = 5, so the drain cannot clear the backlog. (At budget 5 the per-batch deadline floors at 1.0s, so each batch still makes exactly one POST — some rows land, the rest are stranded, which is the mixed case the accounting exists for.)
- **Evidence:** scan_errors_<run_id>.log 'Lookup drain budget expired with N rows undelivered (counted in dataset_delivery.undelivered)'; scan_summary_<run_id>.json dataset_delivery.{queued,records_added,records_updated,records_skipped,undelivered} and delivery_shortfall.
- **Negative control:** The standard Round 2 run at the shipped budget must show dataset_delivery.undelivered == 0 and emit NO such line — the accounting must not fire on a drain that actually completed.

### `DELI-050` Dropped-row accounting when the lookup worker is not alive

*supporting*

- **Must be true:** Rows offered to a lookup uploader with no live worker are COUNTED, not silently discarded, and the diagnostic line is emitted exactly once no matter how many rows are dropped. On a healthy flood the path is never taken (dropped == 0, no line); on a run where the worker was never started, dropped equals the number of rows offered, queued stays 0, and exactly one line appears.
- **Threshold:** Healthy flood: dataset_delivery.dropped == 0 and count('Lookup uploader thread not alive') == 0. Probe run (options="write_dataset=false", where the worker thread is never started but add_match still calls lookup_uploader.add()): dataset_delivery.queued == 0, dataset_delivery.dropped == the number of (rule, file) findings with match_count > 0, and exactly 1 line 'Lookup uploader thread not alive - dropping rows for yara_scanner_matches_v3_… (further drops suppressed)'.
- **Setup:** The Round 2 flood for the healthy arm, plus one short supplementary run over the same small planted tree with options="write_dataset=false" for the drop arm (a separate probe run — it does not change the round's baseline, which keeps dataset writes ON).
- **Evidence:** scan_errors_<run_id>.log (the line is a log_error call, so it lands there and not in uploads); scan_summary_<run_id>.json dataset_delivery.{dropped,queued}.
- **Negative control:** The _drop_logged latch must suppress only the LOG line, not the counter — on the probe run dropped must be strictly greater than 1 while the line count stays exactly 1.

### `DELI-051` Lookup delivery books (upload_stats fields)

*core*

- **Must be true:** dataset_delivery carries all nine integer counters and they reconcile against what was ever queued: records_added + records_updated + records_skipped + rows_unconfirmed + undelivered <= queued always, with exact equality on a run where send_failures == 0 and dropped == 0; and the five numbers printed on the 'Lookup dataset worker stopped' line equal the JSON's batches_sent / records_added / records_updated / records_skipped / send_failures.
- **Threshold:** Exactly these nine keys present with integer values: queued, batches_sent, records_added, records_updated, records_skipped, send_failures, dropped, rows_unconfirmed, undelivered. Equality is exact on the clean flood run; the inequality holds on every run.
- **Evidence:** scan_summary_<run_id>.json dataset_delivery; uploads_<run_id>.log 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)'.
- **Negative control:** The worker-stopped line must NOT be treated as the complete view — it omits dropped, rows_unconfirmed and undelivered. Prove that on DELI-049's shrunk-drain run, where 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)' prints a clean-looking five numbers while the JSON shows dataset_delivery.undelivered > 0. Do NOT use DELI-050's write_dataset=false probe: there the worker thread is never started, so the worker-stopped line is never written at all and the contrast is undecidable.

### `DELI-052` Per-finding dataset row cap and the `truncated` flag

*core*

- **Must be true:** Each (rule, file) finding produces ONE row whose embedded offset sample is capped while its counts stay true: len(json.loads(offsets)) == min(match_count, 50), len(json.loads(strings)) == len(json.loads(offsets)), and truncated == (match_count > 50). match_count carries the real offset total, never the sampled one.
- **Threshold:** CONFIG_LOOKUP_ROWS_PER_FINDING_MAX = 50 (YARA_LOOKUP_ROWS_PER_FINDING; not an options key). For the storm finding: offsets array length exactly 50, truncated == true, and match_count equals the 'Total string hits: N' value in <scanner_dir>/alert/<rule>.txt for the same file.
- **Setup:** Plant three files under the flood tree: one ~5 MB file containing >= 5,000 copies of a short literal, one containing exactly 50 copies, one containing 3 — with a rule matching that literal.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields rule, filename, match_count, truncated, offsets, strings`; uploads_<run_id>.log "Rule '<rule>' matched <file> at N offsets; embedded a sample of 50 in the dataset row (truncated=true; full detail retained in local results)."
- **Negative control:** The 50-hit control file must produce truncated == false with all 50 offsets embedded and NO 'embedded a sample of' line — the cap fires strictly ABOVE 50, not at it. The 3-hit file must show offsets length 3 and truncated == false.

### `DELI-053` Uncapped per-string-ID census on the wire

*supporting*

- **Must be true:** string_ids is a JSON object of per-identifier counts whose values sum EXACTLY to match_count on every row — including rows whose offsets sample was truncated. The census is never sampled.
- **Threshold:** For every matches row of the run: sum(json.loads(string_ids).values()) == match_count. On the storm row (match_count >= 5000, truncated == true) the sum is still the full match_count, not 50. The object has >= 2 keys for the multi-string rule.
- **Setup:** Write the DELI-052 storm rule with at least two distinct string identifiers (e.g. $ext2 and $note1) so the census object is non-trivial, and plant a file where both fire with different frequencies.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields rule, filename, match_count, string_ids, truncated`.
- **Negative control:** The identity must also hold on the un-truncated control rows — the census must not be correct only in the capped case, which would mean it was being derived from the sample rather than accumulated across every offset.

### `DELI-054` Local alert-file offset sampling (mirrors the dataset sample)

*supporting*

- **Must be true:** <scanner_dir>/alert/<rule>.txt caps the printed offsets at 50 while its counts stay complete: the header reads 'Matched Strings (showing 50 of <T>):', an omission note accounts for exactly T-50 further offsets and names the constant, and the 'Hits per string ID:' values sum to T, where T equals the dataset row's match_count for the same (rule, file).
- **Threshold:** CONFIG_ALERT_OFFSETS_PER_FINDING_MAX = 50, a bare literal with no env override. The note reads exactly '<T-50> further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50). Counts above are complete; re-run `yara -s` against this file for every offset.' T == the 'Total string hits: T' line on the same finding == the XQL row's match_count.
- **Setup:** The DELI-052 storm file. scan_summary_<run_id>.json alert_detail_suppressed must be 0 for the run — past CONFIG_ALERT_DIR_MAX_BYTES the whole 'Matched Strings' block is replaced by the counts-only branch, in which case this claim does not apply.
- **Evidence:** <scanner_dir>/alert/<rule>.txt (alert_dir = <scanner_dir>/alert); scan_summary_<run_id>.json alert_detail_suppressed; the matching XQL matches row's match_count.
- **Negative control:** The 50-hit control file must print 'Matched Strings (showing 50 of 50):' with NO omission note, and the 3-hit file 'Matched Strings (showing 3 of 3):' — the note must be absent whenever nothing was actually omitted.

### `DELI-056` delivery_shortfall — the single 'did this land?' verdict

*core*

- **Must be true:** delivery_shortfall is the empty string if and only if, for every ENABLED channel, alerts_queued == successful_uploads and queued == records_added + records_updated + records_skipped; when non-empty it names the exact counts and is mirrored once into the error log.
- **Threshold:** Non-empty form is byte-exact: 'alerts: <lost> of <queued> NOT delivered' and/or 'dataset rows: <lost> of <queued> NOT confirmed (<n> unconfirmed, <m> never sent)', joined by '; ' and suffixed ' — findings are complete in the local logs on this endpoint'. rows_unconfirmed counts as NOT delivered; records_skipped counts as delivered. scan_errors_<run_id>.log carries 'DELIVERY INCOMPLETE — <shortfall>' exactly once on the completed path (em dash) or 'DELIVERY INCOMPLETE - <shortfall>' on the cancelled path (hyphen), and zero times when the field is empty.
- **Setup:** Two Round 2 runs: the clean flood for the empty arm, and DELI-049's shrunk-drain flood for the non-empty arm.
- **Evidence:** scan_summary_<run_id>.json delivery_shortfall, alert_delivery, dataset_delivery; scan_errors_<run_id>.log 'DELIVERY INCOMPLETE'.
- **Negative control:** A channel that is OFF must contribute nothing: a run with options="create_alerts=false" must never produce an 'alerts:' clause in the shortfall, however the alert counters read — the arms are gated on config.create_alerts / config.write_dataset, not on the counters.

### `DELI-057` Delivery shortfall surfaced on the Action Center result line

*core*

- **Must be true:** The one line the operator sees carries the shortfall verbatim: the action's stdout line beginning 'SCAN_RESULT: ' ends with ' | ' followed by exactly the scan_summary delivery_shortfall string when that field is non-empty, and contains neither 'NOT delivered' nor 'NOT confirmed' when it is empty.
- **Threshold:** Byte-for-byte equality of the suffix against scan_summary_<run_id>.json delivery_shortfall. The SCAN_RESULT line is present within Action Center's 10,240-character stdout cap (the snippet footer is the only writer to stdout; root logging goes to diagnostics_<run_id>.log, not stdout).
- **Setup:** Deliver DELI-049's shrunk-drain flood through the Action Center via build_scanner_snippet. Do NOT assert on the CLI __main__ print or its exit code: the snippet rewrites `if __name__ == "__main__":` to `if False:`, so that path never executes — the line comes from the footer's own print('SCAN_RESULT: ' + str(run(...))).
- **Evidence:** The Action Center action's returned stdout, e.g. 'SCAN_RESULT: Scan completed: … | alerts: 12 of 40 NOT delivered — findings are complete in the local logs on this endpoint'; scan_summary_<run_id>.json delivery_shortfall for the comparison.
- **Negative control:** The cancelled path must carry the same suffix on its 'Scan cancelled by operator: …' result string — the shortfall must not be dropped merely because the outcome was a cancel, which is the outcome where partial results matter most.

### `DELI-058` Host cleanup gated on confirmed delivery

*core*

- **Must be true:** With mode "on_delivery", this run's artefacts are removed only when its delivery_shortfall is empty and a delivery channel actually existed; with the shipped default "off", nothing is ever removed. The KEEP tier decides what survives.
- **Threshold:** CONFIG_HOST_CLEANUP defaults to "off", CONFIG_HOST_CLEANUP_KEEP to "summary". Run 1 (defaults): all 8 per-run .log files and the .json remain; alert/ and evidence/ still hold this run's content. Run 2 (on_delivery, non-empty shortfall): identical — nothing removed. Run 3 (on_delivery, empty shortfall): zero .log files carrying THIS run_id remain, alert/ and evidence/ exist but are EMPTY (rmtree then makedirs), and of this run's files only scan_summary_<run_id>.json remains. Scope every count to files whose embedded run_id equals this run's — earlier runs' .log/.json files are still present by design and must be excluded, or the assertion contradicts this criterion's own negative control.
- **Setup:** Three Action Center runs whose snippet prelude sets CONFIG_HOST_CLEANUP: (1) left at "off"; (2) "on_delivery" combined with DELI-049's shrunk drain so the shortfall is non-empty; (3) "on_delivery" against the healthy tenant. Inspect the endpoint over SSH after each.
- **Evidence:** `ls -la <scanner_dir>/logs <scanner_dir>/alert <scanner_dir>/evidence` after each run. The reason string is NOT observable: close_diagnostics_handler() runs immediately before HostCleanup is constructed, so its logging.info calls reach nothing and only 'Host cleanup failed: …' (logging.warning) could reach stderr. List the directory instead.
- **Negative control:** A PREVIOUS run's logs and summary, and <scanner_dir>/rule_cache, must survive untouched — removal is keyed on this run_id via CleanupManager._extract_run_id_from_log_name, and rule_cache is never a target. Also: with both channels off, on_delivery must REFUSE (there is no delivery to verify), keeping the only copy.
- **Why this round:** ROUNDS.md lists host cleanup under Round 1's host-footprint drives, but the gate under test is 'confirmed delivery'. Only Round 2's flood can produce the non-empty delivery_shortfall that exercises the refusal branch, which is the branch whose failure deletes a customer's only copy of the findings.

### `DELI-060` XDR auth mode: per-request HMAC (Advanced) or plain key (Standard), auto-probed

*supporting*

- **Must be true:** With XDR_AUTH_TYPE left at "auto" the tenant is probed exactly ONCE per run and the winner is cached for every subsequent request; with it pinned to "advanced" no probe runs at all. Both runs deliver.
- **Threshold:** Auto run: exactly 1 occurrence of 'XDR auth type detected: advanced' in uploads_<run_id>.log, zero occurrences of 'XDR auth probe inconclusive; defaulting to advanced', and dataset_delivery.records_added > 0. Pinned run: zero occurrences of 'XDR auth type detected:' and dataset_delivery.records_added > 0.
- **Setup:** Two runs: the standard Round 2 flood (auto), and one with a snippet prelude rebinding the module global XDR_AUTH_TYPE = "advanced" (the env var is read at import time, so setting os.environ in the prelude would be too late).
- **Evidence:** uploads_<run_id>.log lines 'XDR auth type detected: <auth>' / 'XDR auth probe inconclusive; defaulting to advanced' / 'XDR auth probe (<auth>) network error: …'; scan_summary_<run_id>.json dataset_delivery.records_added.
- **Negative control:** A transient probe failure must NOT be cached: on the DELI-043 (a) blackhole run, 'XDR auth probe (advanced) network error:' must appear MORE THAN ONCE across the run — _probe_auth_type returns 'advanced' without setting _RESOLVED_AUTH_TYPE and logs directly rather than through _throttled_log, so each attempt is visible.

### `DELI-061` Tenant identity tagging on every alert and every row

*supporting*

- **Must be true:** Every matches row, every scans row and the scan summary for one run carry the SAME non-empty tenant_id: derived from the API URL when CONFIG_TENANT_ID is empty, and exactly the supplied label when options tenant_id is set.
- **Threshold:** count(distinct tenant_id) == 1 across yara_scanner_matches_v3_* and yara_scanner_scans_v3_* for the run_id; equal to scan_summary_<run_id>.json tenant_id and to the 'Tenant ID: <id>' line in yara_processing_<run_id>.log. On the derived run it equals the api-<tenant> capture from XDR_API_URL and is never the literal 'unknown'. On the override run all of them read exactly 'acme-lab'.
- **Setup:** The standard Round 2 flood (derived), plus one short run with options="tenant_id=acme-lab".
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count() by tenant_id`; the same over yara_scanner_scans_v3_*; scan_summary_<run_id>.json tenant_id; yara_processing_<run_id>.log 'Tenant ID:'; the tenant_id key inside the alert_description JSON on the delivered XDR alerts.
- **Negative control:** The override must NOT change where rows land — scan_summary matches_dataset must be identical between the two runs, because sharding is keyed on hostname, not tenant.

### `DELI-062` Idempotent endpoint URL construction

*supporting*

- **Must be true:** Each builder appends its path only when the base does not already end with it, and tolerates trailing slashes: with the base given as '<base>///' all four endpoints resolve and deliver, and no failure text anywhere contains a doubled segment; with the base given as the full insert_parsed_alerts path, alerts still deliver.
- **Threshold:** Run A ('<base>///'): dataset_delivery.records_added > 0 AND alert_delivery.successful_uploads > 0 AND zero occurrences of '//public_api' in uploads_<run_id>.log. Run B (base == '<base>/public_api/v1/alerts/insert_parsed_alerts'): alert_delivery.successful_uploads > 0. Paths are XDR_INSERT_PARSED_ALERTS_PATH=/public_api/v1/alerts/insert_parsed_alerts, XDR_LOOKUPS_ADD_DATA_PATH=/public_api/v1/xql/lookups/add_data, XDR_GET_DATASETS_PATH=/public_api/v1/xql/get_datasets, XDR_ADD_DATASET_PATH=/public_api/v1/xql/add_dataset.
- **Setup:** Two short Action Center runs whose snippet prelude rewrites DEFAULT_XDR_API_URL as above.
- **Evidence:** uploads_<run_id>.log — every requests exception echoes the resolved URL, e.g. 'Lookup batch network error: … with url: /public_api/v1/xql/lookups/add_data'; yara_processing_<run_id>.log 'XDR API URL: <base>'; scan_summary_<run_id>.json alert_delivery and dataset_delivery. Delivery success itself is the positive signal.
- **Negative control:** Run B's LOOKUP channel is EXPECTED to fail (the alert path is not idempotent for the lookup builder) — that failure must be ACCOUNTED, i.e. dataset_delivery.send_failures > 0 and a non-empty delivery_shortfall, never silent. A silent zero there would mean the builder swallowed a broken URL.

### `DELI-063` uploads_<run_id>.log — the delivery observability artefact

*core*

- **Must be true:** Exactly one uploads_<run_id>.log exists per run (mode="w"), every delivery outcome class lands in it, and nothing it emits is duplicated into another category log (propagate=False).
- **Threshold:** logs_dir holds exactly 8 .log files carrying this run_id (alerts, statistics, scan_errors, performance, uploads, system from LogManager; yara_processing from ErrorLogger; diagnostics from setup_logging) plus one .json. uploads_<run_id>.log contains >= 1 line matching each of 'XDR auth type detected:', 'Lookup dataset upload thread starting (datasets:', "Lookup dataset '", 'Lookup batch ok (', 'Alert batch ok (', 'Alert delivery final:'. 'Alert delivery final:' and 'Lookup dataset worker stopped' each appear 0 times in the other seven per-run logs. Any structured data blob on a line is <= 4000 characters before the '...(truncated)' marker.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log and grep -c over the other seven per-run log files.
- **Negative control:** Delivery ERROR lines deliberately go elsewhere: 'Lookup batch abandoned after' and 'alert build error (skipping one)' are log_error calls and must appear in scan_errors_<run_id>.log, never in uploads_<run_id>.log — the split must not be read as a missing line.

### `DELI-065` DEAD CODE: CircuitBreaker class is never instantiated

*low*

- **Must be true:** No circuit-breaker behaviour ever engages during a sustained delivery outage: no batch is ever skipped without a POST (a live breaker would fail batches fast, with zero attempts, while the circuit was open), retries continue to the documented per-batch caps rather than stopping early for a cooldown, no artefact anywhere names a circuit, and the delivered scanner source contains the symbol exactly once (its definition).
- **Threshold:** grep -c 'CircuitBreaker' on the scanner file build_scanner_snippet reads == 1 (verified: only the class definition line). grep -ci 'circuit' across the eight per-run logs == 0. On the outage run every enqueued batch is POSTed at least once — zero 'Lookup batch abandoned after 0 attempt(s)' lines — and each batch stops only at its documented bound: a lookup batch ends either at 'Retry 6/6' or at a 'Lookup batch deadline reached' refusal, and at least one alert batch reaches 'Retry 4/4' (MAX_RETRIES_PER_ITEM = 4) followed by 'Alert batch abandoned after 4 attempts'. Do NOT assert an inter-attempt gap below CIRCUIT_RESET_TIMEOUT_SECS = 40: with XDR_AUTH_TYPE=auto each attempt first spends DEFAULT_TIMEOUT_SECS=20 in an uncached auth probe and up to 20s more in the POST, plus up to 8s of backoff, so ~48s between consecutive alert attempts is correct behaviour on a blackholed tenant. CIRCUIT_FAILURE_THRESHOLD = 5 and CIRCUIT_RESET_TIMEOUT_SECS = 40 are consumed only as CircuitBreaker.__init__ defaults.
- **Setup:** DELI-043's (a) blackhole probe, so every POST fails and more than 5 consecutive failures occur — the exact condition a live breaker would trip on.
- **Evidence:** The scanner source delivered for this run; uploads_<run_id>.log retry lines ('Retry n/6 in Xs.' for lookups, 'Retry n/4 in Xs.' for alerts) and their timestamps.
- **Negative control:** The absence of a breaker must not read as unbounded retrying: each batch must still STOP after its cap — 6 attempts for lookups, 4 for alerts — and book the loss. Both ceilings holding is what distinguishes 'no breaker' from 'no bounds at all'.

### `DELI-066` DEAD CODE: ResultsUploader.upload_results() is never called

*low*

- **Must be true:** The dead finalizer never runs on any delivery, and the live shutdown path does — so the absence proves dead code rather than a dead log sink.
- **Threshold:** In uploads_<run_id>.log, counts of 'FINALIZING UPLOAD PROCESS', 'UPLOAD STATISTICS', 'Upload success rate', 'Upload thread stopped successfully' and 'Real-time upload completed' are all 0; count('Upload thread terminated successfully') + count('Upload thread did not terminate within 60s timeout') == 1. Note the one-word difference: 'stopped' is the dead path, 'terminated' is the live one.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log.
- **Negative control:** The live line is the positive control — if neither 'Upload thread terminated successfully' nor 'Upload thread did not terminate within 60s timeout' appears, the five zero counts prove nothing, because the alert channel would not have shut down at all.

### `DELI-067` DEAD CODE: ScanStatusUploader.upload_scan_status() is never called and is double-gated off

*low*

- **Must be true:** upload_scan_status never executes on any delivery — none of its three outcome lines appear and it puts no traffic on Insert Parsed Alerts — while set_status IS running and IS logged, proving the sink is live and the absence is dead code.
- **Threshold:** In diagnostics_<run_id>.log: count('Scan status changed to: ') >= 5 (initializing, starting_workers, scanning, finishing, completed) and count('Scan status uploaded successfully') + count('Scan status upload failed') + count('Scan status upload error') == 0. scan_summary alert_delivery.alerts_queued == findings + rollups exactly (no extra status alerts on the wire). UPLOAD_NON_MATCH_DATA is a bare literal False; status_upload_interval=60 and last_status_upload are likewise dead.
- **Evidence:** <scanner_dir>/logs/diagnostics_<run_id>.log; scan_summary_<run_id>.json alert_delivery.{findings,rollups,alerts_queued}.
- **Negative control:** The real status channels must still be populated, so the dead uploader's silence is not read as 'no scan status anywhere': <scanner_dir>/control/running.json exists during the scan and the yara_scanner_scans_v3_* lifecycle rows carry the transitions.
- **Why this round:** The catalogue marks this an observability gap on the premise that set_status's logging.info reaches nothing because setup_logging strips root handlers and pins WARNING. That is stale: setup_logging now installs an INFO FileHandler for diagnostics_<run_id>.log on the root logger and sets root to INFO, and it runs before YaraScanner (and therefore ScanStatusUploader) is constructed — so all nine set_status calls are observable. Placed in Round 2 because if the dead path were live it would POST to Insert Parsed Alerts and break that round's book reconciliation.

### `DELI-068` DORMANT: _build_xdr_parsed_alert single-alert payload builder

*low*

- **Must be true:** Every Insert Parsed Alerts POST carries a BATCH built by _upload_alert_batch, never a single-alert payload from the dormant builder: the per-POST alert counts reach the batch size and account for every successful upload.
- **Threshold:** grep -c '_build_xdr_parsed_alert' on the delivered scanner source == 1 (its definition). On the flood, max n over 'Alert batch ok (n alerts, HTTP 200)' == 60 (ALERT_BATCH_SIZE, hard-clamped to XDR's cap). Sum of n over all 'Alert batch ok (' lines == scan_summary alert_delivery.successful_uploads, exactly.
- **Setup:** Round 2 flood sized to fill at least one full 60-alert batch.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log 'Alert batch ok (N alerts, HTTP 200)'; scan_summary_<run_id>.json alert_delivery.successful_uploads; the delivered scanner source.
- **Negative control:** A partial trailing batch (n < 60) is legitimate and must NOT be read as the single-alert path — only n == 1 on EVERY POST would indicate the dormant builder had gone live.

### `DELI-069` DEAD BRANCH: 'Upload queue full' / 'Lookup dataset queue full' handlers

*low*

- **Must be true:** Neither delivery queue is bounded, so neither backpressure handler ever fires even under the flood, and no alert is lost to a full queue: alerts_queued accounts for every finding queued plus every rollup, with no residual.
- **Threshold:** count('Upload queue full - skipping alert for finding') in uploads_<run_id>.log == 0; count('Lookup dataset queue full - dropping record') in scan_errors_<run_id>.log == 0. alert_delivery.alerts_queued == alert_delivery.findings + alert_delivery.rollups, exactly. Both queues are constructed as Queue() with no maxsize.
- **Setup:** Round 2 flood, sized to exceed CONFIG_ALERT_MAX_PER_SCAN (500) so rollups are also queued.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log; <scanner_dir>/logs/scan_errors_<run_id>.log; scan_summary_<run_id>.json alert_delivery.{findings,rollups,alerts_queued}.
- **Negative control:** The SCAN queue is a different queue and IS bounded by config.scan_queue_size — its 'Scan queue saturated (N items) - backing off producer' line in performance_<run_id>.log may legitimately appear and must not be counted against this claim.

### `DELI-073` records_skipped counted as DELIVERED in the delivery verdict

*core*

- **Must be true:** Rows the server SKIPS are booked as landed by the delivery verdict: a run whose matches-dataset add_data responses report skipped=N, added=0 finishes with delivery_shortfall == "" and outcome == "completed" while XQL returns zero matches rows for that run_id — the single 'did this land?' field says yes for rows that are not in the dataset.
- **Threshold:** dataset_delivery.records_skipped == the number of MATCHES rows queued for the run; dataset_delivery.records_added == the XQL row count over yara_scanner_scans_v3_* for the run_id and is > 0, NOT 0 — upload_stats is shared by the one uploader that writes both datasets, and only the matches dataset is stunted. records_added + records_updated + records_skipped == dataset_delivery.queued, hence delivery_shortfall == "" (present but empty — the landed sum counts skipped, and skipped is not reflected anywhere in the shortfall string) and outcome == "completed", while the XQL row count over yara_scanner_matches_v3_* for the run_id == 0. With CONFIG_HOST_CLEANUP="on_delivery" the cleanup gate would return True on that run, since should_run only tests the shortfall.
- **Setup:** Pre-create yara_scanner_matches_v3_<shard>_<YYYYMM> on the tenant with a deliberately stunted schema (tenant_id and scan_id only) using xdr_data_management.py, then run the flood — _ensure_one finds it and appends ('Lookup dataset … already exists - will append rows'), and rows carrying unknown fields are skipped server-side. Interacts with LOOKUP_SCHEMA_VERSION (3).
- **Evidence:** scan_summary_<run_id>.json dataset_delivery.{queued,records_added,records_updated,records_skipped}, delivery_shortfall, outcome; uploads_<run_id>.log carries BOTH 'Lookup batch ok (N rows): added=0, updated=0, skipped=N' (the matches batches) and 'Lookup batch ok (M rows): added=M, updated=0, skipped=0' (the scans batches) — the line does not name its dataset, so attribute by the added/skipped split; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count()` and the same over yara_scanner_scans_v3_*.
- **Negative control:** On the standard Round 2 run against a correctly-schema'd dataset, records_skipped must be 0 and records_added must equal queued and equal the SUM of the matches and scans XQL counts for the run_id — the skipped bucket must not absorb rows that actually landed, or the probe above would be indistinguishable from a healthy run.

### `DELI-074` Lookup dataset re-created mid-scan when it disappears under the writer

*supporting*

- **Must be true:** A mid-scan HTTP 400 'dataset not found' triggers exactly ONE recreate for that batch (bounded by recreate_attempted) and the recreated dataset is then written to; any other non-2xx outside the retryable set counts one send_failure and returns immediately without recreating. The retry that follows the recreate is subject to the same per-batch wall-clock deadline as any other retry, so the batch must end in one of two ACCOUNTED ways — 'Lookup batch ok (N rows)' or 'Lookup batch deadline reached … after 1 attempts' followed by 'Lookup batch abandoned after 1 attempt(s) (N rows lost)' with send_failures += 1 — never silently.
- **Threshold:** LOOKUP_ADD_DATA_MAX_RETRIES = 6; the retryable status set is exactly {408, 429, 500, 502, 503, 504}. Per batch, at most 1 line containing 'recreating and retrying this batch once.' (bounded by recreate_attempted), followed by "Lookup dataset '<name>' created (schema fields: 22)" or "Lookup dataset '<name>' already exists - will append rows", then 'Lookup batch ok (N rows)'. With the widened LOOKUP_DRAIN_TIMEOUT there must be zero 'Lookup batch deadline reached' lines for the recreated batch. scan_errors_<run_id>.log carries no 'Dataset recreation failed:' line.
- **Setup:** Delete the run's matches shard dataset from the tenant while the flood is mid-flight (xdr_data_management.py delete-dataset), timed between two 'Lookup batch ok' lines. Add a snippet prelude setting LOOKUP_DRAIN_TIMEOUT = 300 so the post-recreate retry is actually reachable: at the shipped 150s the in-scan per-batch deadline is start+130 against a 120s read timeout, leaving ~10s of headroom from batch start, which the 400 plus the two recreate round trips routinely exceed — making the primary arm a coin flip. _ensure_datasets runs only once, at startup, so without this branch the scan would keep failing for its whole remaining lifetime.
- **Evidence:** uploads_<run_id>.log sequence: "Lookup batch failed (HTTP 400, dataset not found) - '<dataset>' appears to have been deleted mid-scan; recreating and retrying this batch once." -> "Lookup dataset '<name>' created (schema fields: 22)" -> 'Lookup batch ok (N rows)'; scan_errors_<run_id>.log; scan_summary_<run_id>.json dataset_delivery.send_failures.
- **Negative control:** A 400 WITHOUT 'not found' in the body — and any 401/403/404 — must NOT trigger a recreate: send_failures increments by exactly 1, no 'recreating and retrying' line appears, and no retry is attempted.

### `DELI-079` Alert channel's startup narration is unreachable — uploads log never records whether alerts are on

*supporting*

- **Must be true:** The alert channel's own startup and disable narration never reaches uploads_<run_id>.log — ResultsUploader is constructed with log_manager=None, and both the channel decision and the worker-thread start run before the late attach — while the LOOKUP channel's equivalent narration DOES reach it, proving the sink is live and the absence is a construction-order defect.
- **Threshold:** In uploads_<run_id>.log the counts of 'Starting real-time upload thread...', 'Real-time upload thread started successfully', 'Upload worker thread started (batch=', 'XDR_API_URL not configured - real-time match upload disabled' and 'Parsed-alerts upload disabled (create_alerts=false)' are ALL 0 — both on a run where alerts are on and demonstrably delivering (>= 1 'Alert batch ok (') and on a run with options="create_alerts=false". count('Lookup dataset upload thread starting (datasets:') == 1 on both, as the positive control.
- **Setup:** Two runs: the standard Round 2 flood, and one short run with options="create_alerts=false". (The attach happens after a blocking LookupDatasetUploader construction that makes two HTTP round trips, so the worker's first line is reliably emitted while log_manager is still None.)
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log; yara_processing_<run_id>.log 'Runtime posture: alerts=on dataset=on files=… cpu=… mode=…'; scan_summary_<run_id>.json posture.
- **Negative control:** The INTENDED state must remain readable — 'alerts=on' / 'alerts=off' in scan_summary posture and in the 'Runtime posture:' line must correctly track the create_alerts setting on both runs. What is lost is visibility of the START, not of the configuration.

### `DELI-080` Both uploader worker loops swallow unexpected exceptions and keep running

*supporting*

- **Must be true:** An unexpected exception inside either uploader's loop is logged and the thread keeps running, so no subsequent row or alert is silently lost: on the flood dataset_delivery.dropped is 0, no 'Lookup uploader thread not alive' line appears, the terminal lifecycle row lands, and the alert books still balance — and those facts hold even if loop-error lines are present.
- **Threshold:** scan_summary dataset_delivery.dropped == 0; count('Lookup uploader thread not alive') == 0; exactly one row with status == "completed" for the run_id in yara_scanner_scans_v3_*; alert_delivery.successful_uploads + failed_uploads + undelivered <= alerts_queued. Any 'Upload worker unexpected error: …' line must render as '<TypeName>: <msg>' or a bare '<TypeName>' when str(e) is empty — never a dangling colon.
- **Setup:** Round 2 flood against the live tenant; the DELI-043 (a) blackhole probe as a stress variant, where transport exceptions are guaranteed.
- **Evidence:** scan_errors_<run_id>.log 'Lookup worker loop error (continuing): <e>' and 'Upload worker unexpected error: <Type>: <msg>'; scan_summary_<run_id>.json dataset_delivery.dropped and alert_delivery; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, event_timestamp_ms`.
- **Negative control:** The thread-DEATH path must stay distinguishable from the survive-and-continue path: a dead worker logs 'Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)' exactly once and increments dropped. A surviving thread and a dead one must never produce the same evidence.

### `DELI-082` An exception while building one alert dict silently shrinks the batch

*supporting*

- **Must be true:** No alert is lost between the queue and the wire: the per-item build never fails, and the alert books close exactly — alerts_queued == successful_uploads + failed_uploads + undelivered, with no unexplained residual.
- **Threshold:** count('alert build error (skipping one)') == 0 in scan_errors_<run_id>.log — the message is routed through _throttled_log at its DEFAULT level="error", so it lands in scan_errors, NOT uploads (first 20 emitted, then summarised every 1000). Equality holds exactly on a run whose uploads log shows 'Upload thread terminated successfully' (stop() then drains the queue precisely, sentinels excluded); universally the sum is <= alerts_queued. A positive residual with no 'Alert batch failed' line is this defect, and delivery_shortfall then reads 'alerts: X of N NOT delivered'.
- **Setup:** Round 2 flood sized to fill many 60-alert batches.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log; scan_summary_<run_id>.json alert_delivery.{alerts_queued,successful_uploads,failed_uploads,undelivered}; uploads_<run_id>.log 'Alert delivery final:' and 'Upload thread terminated successfully'.
- **Negative control:** Requeued alerts must NOT inflate the books: requeued= on the final line can be large while alerts_queued stays equal to findings + rollups, because the requeue path re-puts without re-counting. A rising requeued must not be mistaken for a residual.

### `DELI-083` The alert worker honours the stop flag before dequeuing

*core*

- **Must be true:** Once the alert books are published they stay true: scan_summary alert_delivery.successful_uploads equals the ok= value on the 'Alert delivery final:' line (the JSON is read after stop() emitted that line), and ok + failed + undelivered never exceeds alerts_queued — an item booked undelivered is never afterwards delivered and counted a second time.
- **Threshold:** JSON alert_delivery.successful_uploads == the ok= integer on the 'Alert delivery final:' line, exactly. successful_uploads + failed_uploads + undelivered <= alerts_queued. On the backlog run, undelivered > 0 must coexist with that equality — the drift measured on the sibling edition was 12,146 booked undelivered while ok climbed by 1,000 afterwards.
- **Setup:** Round 2 flood delivered with a snippet prelude raising CONFIG_ALERT_MAX_PER_SCAN to 20000, sized so at least 5,000 alerts are still queued at stop(). 1,200 is not enough: the drain window budgets 15s per batch while a batch actually costs ~8-9s, so ~2,500-3,000 alerts clear inside the 300s cap plus the 60s join. Grow the planted tree (or shrink ALERT_DRAIN_MAX_SECS is NOT acceptable — it would change the mechanism under test) until scan_summary alert_delivery.undelivered > 0 is actually observed. The sentinel lands at the BACK of the queue, so the worker must chew through everything ahead of it. The stop flag is set on every run, cancelled or not — a mid-walk cancel is neither necessary nor sufficient.
- **Evidence:** uploads_<run_id>.log 'Alert delivery final: findings=… queued=… ok=… failed=… undelivered=… suppressed=… rollups=… requeued=…'; scan_summary_<run_id>.json alert_delivery. Pinned by tests/test_xdr_delivery_books_balance.py.
- **Negative control:** The deliberate requeue window must survive: stop() runs its requeue-ENABLED drain FIRST, with the flag still False, and that must still happen — evidenced by 'Draining N pending alert(s) (~M batches, up to Xs)...' in uploads_<run_id>.log and a non-zero requeued= when the tenant rate-limits. A stop-flag check that shortened that window would cause the loss it exists to prevent.
- **Why this round:** ROUNDS.md settles cancellation into Round 3, but this capability is not driven by cancellation: stop() sets the same flag at the end of every run. What makes the defect reachable is a backlog that outlives the 60s join, and only Round 2's flood produces one.

## Scan Lifecycle, Control & Error Handling

### `LIFE-030` Second, idempotent uploader stop in run()'s finally block

*supporting*

- **Must be true:** The uploader stop in run()'s finally is idempotent: after _perform_enhanced_cleanup has already stopped both uploaders, the second call returns immediately without re-paying a drain window, so each channel closes its books exactly once.
- **Threshold:** `grep -c 'Alert delivery final: ' uploads_<run_id>.log` == 1 — that line is written inside ResultsUploader.stop() after the _stop_done guard, so it is the assertion that actually decides idempotence; `grep -c 'Draining .* pending alert' uploads_<run_id>.log` <= 1 and `grep -c 'Lookup drain: ' uploads_<run_id>.log` <= 1; every number in the single `Alert delivery final:` line equals the matching field of scan_summary "alert_delivery" (findings, alerts_queued, successful_uploads, failed_uploads, undelivered, suppressed, rollups, requeued) — a second stop() would re-add its leftover count to undelivered and break that equality; the wall clock from the `Enhanced cleanup completed in` line to process exit is < ALERT_DRAIN_SECS (60s), since run()'s finally is all that runs after it. Do NOT time the gap between `Alert delivery final:` and `Enhanced cleanup completed in` — the lookup drain sits inside it. Do NOT use the count of `Lookup dataset worker stopped (` as an idempotence check — it is written by the worker thread on exit, not by stop().
- **Setup:** Round 2's flood, sized so a real backlog exists at stop (≥2,000 findings queued) and both drain windows are genuinely entered.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log; the `Enhanced cleanup completed in` timestamp in <scanner_dir>/logs/system_<run_id>.log paired with the SSH command's own process-exit wall clock; <scanner_dir>/logs/scan_summary_<run_id>.json "alert_delivery" and "dataset_delivery".
- **Negative control:** The `Lookup drain: N rows pending` line is written only when rows are actually pending, so a run whose lookup queue is empty at stop must show ZERO of them — assert at most one, never exactly one, or a correct build fails.

### `LIFE-034` _delivery_shortfall — the single "did the findings land?" answer

*core*

- **Must be true:** _delivery_shortfall is computed once and is the one answer to 'did the findings land?': it is "" if and only if BOTH channels' books balance; its numbers are exactly (alerts_queued − successful_uploads) and (queued − records_added − records_updated − records_skipped); the identical text appears in scan_summary.delivery_shortfall, on the SCAN_RESULT line and in the `DELIVERY INCOMPLETE — ` scan_errors line; and on both channels the books reconcile against what was ever queued.
- **Threshold:** Alert channel, exact with no slack: successful_uploads + failed_uploads + undelivered == alerts_queued; alerts_queued == findings + rollups; findings + suppressed == the number of distinct (rule,file) findings, and findings == min(distinct findings, CONFIG_ALERT_MAX_PER_SCAN = 500) under the flood. Dataset channel: (queued - records_added - records_updated - records_skipped) equals the 'NOT confirmed' number printed in the shortfall text, and records_added + records_updated + records_skipped + rows_unconfirmed + undelivered + dropped <= queued. Identical-text clause: the SCAN_RESULT tail and the text after `DELIVERY INCOMPLETE — ` in scan_errors_<run_id>.log are byte-identical (both render the same `shortfall` string); scan_summary.delivery_shortfall is a SECOND call to _delivery_shortfall in run()'s finally, so require byte-identity with those two only after confirming the lookup worker settled inside its window (uploads_<run_id>.log contains `Lookup dataset worker stopped (` and NO `Lookup uploader thread did not stop within`) — otherwise require only that the field is non-empty and that its `alerts: X of Y NOT delivered` clause matches. When both losses are 0, "delivery_shortfall" is the empty string (not null, not absent) and scan_errors_<run_id>.log contains zero `DELIVERY INCOMPLETE` lines.
- **Setup:** Round 2's flood: a ruleset matching essentially every file in a bounded tree, sized above CONFIG_ALERT_MAX_PER_SCAN (500) and above the ~600 alerts/min server ceiling so suppression, rollups, retry, requeue and both drain budgets all fire. Both channels ON.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "alert_delivery", "dataset_delivery", "delivery_shortfall"; the single `Alert delivery final: findings=… queued=… ok=… failed=… undelivered=… suppressed=… rollups=… requeued=…` line and the `Lookup dataset worker stopped (batches=… added=… updated=… skipped=… failures=…)` line in uploads_<run_id>.log; the tail of the `SCAN_RESULT: ` line; the `DELIVERY INCOMPLETE — ` line in scan_errors_<run_id>.log; and BOTH XQL counts — `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count()` PLUS `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | comp count()` — summed before comparing against records_added + records_updated, because those counters are credited across both target datasets.
- **Negative control:** A clean run with a handful of matches, both channels on, must report delivery_shortfall == "" and log no `DELIVERY INCOMPLETE` line — the shortfall must not fire merely because a channel was exercised, and "" must be present as an empty string rather than the field being omitted.

### `LIFE-050` ResultsUploader.upload_results — dead finalisation path

*low*

- **Must be true:** The alert channel is finalised by stop(), never by the dead upload_results(): the flood's uploads log carries exactly one 'Alert delivery final:' ledger line and zero lines from the dead path.
- **Threshold:** On every Round-2 flood run: exactly 1 line matching '^.*Alert delivery final: findings=' in logs/uploads_<run_id>.log (one, not two — stop() is called from _perform_enhanced_cleanup and again from run()'s finally, and _stop_done must collapse them); 0 occurrences of 'FINALIZING UPLOAD PROCESS' and 0 of 'UPLOAD STATISTICS' in that file. The single ledger line's ok + failed + undelivered == queued, and its queued equals scan_summary.alert_delivery.alerts_queued.
- **Setup:** Standard Round-2 flood with create_alerts on; no extra setup. Cross-check the same run's scan_summary.alert_delivery block.
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log — 'Alert delivery final: findings=… queued=… ok=… failed=… undelivered=… suppressed=… rollups=… requeued=…'; absence of 'FINALIZING UPLOAD PROCESS' and 'UPLOAD STATISTICS'; the alert_delivery block in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** A run whose queue drained early must still emit the ledger line exactly once with undelivered=0 — the assertion is 'exactly one', not 'at least one'; a second ledger line would mean a second drain window was paid.
- **Why this round:** The dead path's absence is only meaningful next to a live drain that actually had a backlog to finalise, which is the flood; Round 2 is where the alert ledger is read anyway.

### `LIFE-063` Host cleanup refuses to run without a durable summary, and when there is no delivery channel

*core*

- **Must be true:** Host cleanup under mode='on_delivery' refuses to delete whenever it cannot prove the findings landed: a run with a non-empty delivery shortfall keeps every local artefact, and so does a run with no delivery channel at all — the same _delivery_shortfall value that the summary records is the one the gate consults.
- **Threshold:** Run A (Round-2 flood, prelude CONFIG_HOST_CLEANUP='on_delivery', tenant reachable but pushed past the drain so alerts or dataset rows go undelivered): scan_summary.delivery_shortfall is a non-empty string, and afterwards logs/*_<run_id>.log, alert/ and evidence/ are ALL still present and non-empty, AND failed_rules/ still holds the F failed_rule_*.yar + S skipped_rule_*.yar artefacts the compile produced (make this discriminating by giving the flood pack one syntactically broken rule and one rule importing+using an unavailable module, so F and S are non-zero) — `find <scanner_dir> -type f` is identical before and after run()'s finally block. Run B (same flood, everything delivered): scan_summary.delivery_shortfall == "" and this run's logs/*_<run_id>.log are gone. Run C (create_alerts=false,write_dataset=false via the options string, on_delivery): nothing removed even though delivery_shortfall is "" — an empty shortfall with no channel must not read as success. Run D (mode='always' on a run whose outcome is 'cancelled' or 'failed'): nothing removed, because the whole block is gated on outcome == 'completed'.
- **Setup:** Four deliveries. A and B are the Round-2 flood with prelude="CONFIG_HOST_CLEANUP='on_delivery'" and a pack that additionally carries one deliberately broken rule and one rule importing+using an unavailable module (cuckoo), so failed_rules/ is non-empty and the refusal check is discriminating rather than vacuous — A black-holed or rate-limit-saturated so the drain expires with items queued, B healthy. C is a short scan with options='create_alerts=false,write_dataset=false' (a deliberate departure from the channels-ON default, for this gate only). D is a cancelled flood with prelude="CONFIG_HOST_CLEANUP='always'".
- **Evidence:** delivery_shortfall, alert_delivery and dataset_delivery in <scanner_dir>/logs/scan_summary_<run_id>.json; `find <scanner_dir> -type f` after each run; <scanner_dir>/logs/uploads_<run_id>.log 'Alert delivery final: … ok=… failed=… undelivered=…'. The 'Host cleanup skipped: <reason>' line is NOT usable evidence: close_diagnostics_handler() detaches the diagnostics FileHandler two statements before it is emitted, and root's remaining StreamHandler is pinned at WARNING, so that logging.info reaches nothing.
- **Negative control:** Run B proves the refusals are not a blanket refusal — with the books balanced, the same mode does delete. A build that never deletes passes A/C/D and fails B.
- **Why this round:** Departs from the lifecycle prior: this gate is driven entirely by the delivery books (queued vs ok/failed/undelivered on both channels), and only Round 2's flood produces a genuine shortfall to refuse on.

### `LIFE-071` XDR auth-type probe on first use (auto), with caching and no-cache-on-network-error

*supporting*

- **Must be true:** With XDR_AUTH_TYPE at its 'auto' default the tenant's auth style is probed exactly once per run and cached — every later request reuses the resolved answer instead of re-probing — and an explicit XDR_AUTH_TYPE skips the probe entirely.
- **Threshold:** Default flood run against the healthy tenant: exactly 1 line 'XDR auth type detected: advanced' in logs/uploads_<run_id>.log (this tenant is Advanced/HMAC), 0 lines 'XDR auth probe inconclusive; defaulting to advanced', 0 lines 'XDR auth probe (advanced) network error: ' — one probe line total, no matter how many hundreds of alert batches and lookup batches the flood POSTs. Run with XDR_AUTH_TYPE='advanced' exported at module scope: 0 occurrences of all three probe lines, and delivery still succeeds (successful_uploads > 0). Offline variant (tenant unreachable at probe time): the network-error line appears and is NOT cached — it may recur, so assert >= 1 rather than == 1 there.
- **Setup:** Round-2 flood with the default auth setting; plus one flood launched over SSH on xdr-agent with XDR_AUTH_TYPE=advanced exported before python starts (the constant is read at module scope, so a snippet prelude is too late).
- **Evidence:** <scanner_dir>/logs/uploads_<run_id>.log lines 'XDR auth type detected: <auth>', 'XDR auth probe (<auth>) network error: …', 'XDR auth probe inconclusive; defaulting to advanced'; the alert_delivery.successful_uploads and dataset_delivery.records_added fields in scan_summary_<run_id>.json to confirm the resolved auth actually worked.
- **Negative control:** A build that re-probed per request would show many 'XDR auth type detected:' lines under the flood; a build that never probed would show none while still delivering — the explicit-XDR_AUTH_TYPE run is the control that separates 'cached' from 'never ran'.
- **Why this round:** Departs from the lifecycle prior: the probe is the first step of both delivery channels, and only a flood proves the result is cached rather than re-probed per POST.

### `LIFE-074` Terminal "completed" status emission is best-effort and last

*core*

- **Must be true:** The authoritative terminal signal is a lifecycle row that actually reaches the tenant: every completed run lands exactly one scans-dataset row with status='completed' for its scan_id, and the best-effort local emission never reports a failure.
- **Threshold:** Round-2 flood, completed: XQL `dataset = yara_scanner_scans_v3_* | filter scan_id = "<scan_id>" | comp count() by status` returns a 'completed' bucket whose count() == 1 and an 'initiated' bucket whose count() == 1; a 'running' bucket with count() >= 1 is required ONLY when the run exceeded SCANS_HEARTBEAT_SECS (default 600s) or was launched with YARA_HEARTBEAT_SECS exported low — on a shorter flood its absence is correct and must not be asserted. The completed row's files_scanned and detections equal scan_summary.files_scanned and scan_summary.matches exactly; logs/scan_errors_<run_id>.log has 0 lines containing 'Could not emit terminal scan status: '. On the cancelled variant the terminal row's status is 'cancelled' and on the failed variant 'failed' — never two terminal rows for one scan_id.
- **Setup:** The Round-2 flood with write_dataset on, sized so the terminal row is queued behind a large backlog of match rows (the row is emitted at _perform_enhanced_cleanup line 7019, before the uploaders are stopped, so it must survive the lookup drain). To make the heartbeat half decidable, either size the flood to run longer than SCANS_HEARTBEAT_SECS (600s) or launch it over SSH on xdr-agent with YARA_HEARTBEAT_SECS=30 exported before python starts — it is read at MODULE scope, so an Action Center prelude is too late. Query the tenant after the run.
- **Evidence:** XQL over yara_scanner_scans_v3_* filtered on this run's scan_id (status, files_scanned, detections, run_id columns); <scanner_dir>/logs/scan_errors_<run_id>.log for 'Could not emit terminal scan status: '; <scanner_dir>/logs/scan_summary_<run_id>.json (files_scanned, matches, scan_id) and its dataset_delivery block.
- **Negative control:** The 'initiated' row must be present for the same scan_id — a query returning only the terminal row would mean the lifecycle stream was lost, not that the terminal emission worked. Use the 'running' rows as an additional control ONLY on the long / heartbeat-lowered run, where they are actually reachable.
- **Why this round:** Departs from the lifecycle prior: the authoritative artefact is a lookup-dataset row that must survive the lookup drain budget, and only the flood puts a real backlog in front of it.

---

# Round 3 — Detection precision, targeting and lifecycle

204 capabilities · 62 core · `xdr-agent` (Ubuntu 22.04), `xdragent2` (Windows Server 2022) · collect-through

## Rule Handling

### `RULE-001` Base64 YARA rule input decoding (yarafile parameter)

*core*

- **Must be true:** When yarafile is supplied, the provided-parameter branch is the one that runs and the default-configuration branch never does: the run compiles the delivered pack, not an embedded one.
- **Threshold:** Exactly 1 occurrence of 'Using YARA rules from provided parameter' and exactly 0 of 'Using YARA rules from default configuration' in yara_processing_<run_id>.log; the 'YARA Scanner initialization completed' record in system_<run_id>.log carries rule_source == "provided parameter" in its data= blob; and, for THIS run only, the pack must be all-well-formed (no syntax errors, no module-dependent rules) so valid_rules == the pack's declared rule count and failed_rules == skipped_rules == 0. Do not reuse a crafted/malformed pack for this criterion.
- **Setup:** Standard Round 3 delivery — any crafted pack passed as yarafile.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log line 'Using YARA rules from provided parameter' (ErrorLogger INFO, ScanConfig); 'rule_source' key inside the data= blob of the 'YARA Scanner initialization completed' record in <scanner_dir>/logs/system_<run_id>.log; valid_rules in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** The RULE-007 run (yarafile omitted) must produce the mirror image — 'Using YARA rules from default configuration' exactly once and the provided-parameter line zero times — proving the branch is selected by the argument, not written unconditionally.

### `RULE-002` Base64 tolerance: b64: prefix, URL-safe alphabet, whitespace, auto-padding

*core*

- **Must be true:** Four lenient encodings of one identical pack all decode to byte-identical text, and an input that is genuinely not decodable is rejected with the DECODE_ERROR token rather than being silently truncated into a partial ruleset.
- **Threshold:** The trailing 12 hex characters of scan_id are identical across all four encodings, and valid_rules/failed_rules/skipped_rules are identical across all four; the fifth run logs 'DECODE_ERROR: Base64 decode failed:' exactly once, writes no scan_summary_<run_id>.json and emits no scans row.
- **Setup:** Five deliveries of one pack (chosen/padded so its canonical base64 contains both '+' and '/'): (a) canonical base64, (b) same with a 'b64:' prefix, (c) same wrapped at 64 chars with newlines and interior spaces, (d) URL-safe alphabet ('-'/'_') with all '=' padding stripped; (e) yarafile = the literal string 'AAAAA' (5 data chars — re-padding to 8 still leaves a count binascii rejects).
- **Evidence:** 'Scan ID: <scan_id> (rule hash: <12 chars>...)' in <scanner_dir>/logs/yara_processing_<run_id>.log for runs a-d; scan_id / valid_rules / failed_rules / skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; for run (e) the 'DECODE_ERROR: Base64 decode failed:' line plus 'CRITICAL: Failed to decode YARA rules:' in the same log and the absence of <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** Runs (a)-(d) must NOT log DECODE_ERROR — the leniency must accept all four forms, not reject anything non-canonical. Run (e) must NOT log INPUT_ERROR or VALIDATION_ERROR (the three rejection tokens are mutually exclusive).

### `RULE-004` Empty / whitespace-only rule input rejection

*supporting*

- **Must be true:** A whitespace-only yarafile is rejected with the INPUT_ERROR token before any decode is attempted, and the run aborts inside ScanConfig — no scanner object, no summary, no lifecycle row.
- **Threshold:** Exactly 1 'INPUT_ERROR: Empty YARA rules content provided' line and 0 DECODE_ERROR / 0 VALIDATION_ERROR lines; 0 files scanned; no <scanner_dir>/logs/scan_summary_<run_id>.json for that run_id; XQL over yara_scanner_scans_v3_* returns 0 rows for that run_id.
- **Setup:** Deliver yarafile as the three-character string '   ' (truthy, so ScanConfig takes the provided-parameter branch — an empty string would instead fall through to the RULE-007 default-configuration branch).
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log lines 'Using YARA rules from provided parameter', 'INPUT_ERROR: Empty YARA rules content provided' and 'CRITICAL: Failed to decode YARA rules: Empty YARA rules content provided'; absence of <scanner_dir>/logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>"` returns 0 rows.
- **Negative control:** A control delivery of base64('rule ok { condition: true }') in the same session must log zero INPUT_ERROR lines and must write scan_summary_<run_id>.json — the guard must reject blank input only, not every input.

### `RULE-005` Decoded-content validation: must contain a 'rule' declaration

*supporting*

- **Must be true:** Content that decodes cleanly but contains no line-anchored 'rule <name>' declaration is rejected with the VALIDATION_ERROR token and the run aborts before any scanner object exists.
- **Threshold:** Exactly 1 "VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations" line, 0 INPUT_ERROR and 0 DECODE_ERROR lines; no scan_summary_<run_id>.json; 0 rows in yara_scanner_scans_v3_* for that run_id.
- **Setup:** Two deliveries: (a) yarafile = base64('this pack declares nothing at all') — decodes cleanly, no rule declaration; (b) the same text with the single line 'rule marker_only { condition: true }' appended.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log "VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations" plus the 'CRITICAL: Failed to decode YARA rules:' echo; absence of <scanner_dir>/logs/scan_summary_<run_id>.json for run (a); valid_rules == 1 in scan_summary_<run_id>.json for run (b).
- **Negative control:** Run (b) — identical text plus one anchored rule — must log zero VALIDATION_ERROR lines and reach valid_rules == 1, proving the guard keys on the declaration and not on the surrounding text.

### `RULE-006` Rule text encoding fallback (UTF-8 then Latin-1 then replace)

*supporting*

- **Must be true:** A pack whose decoded bytes are not valid UTF-8 still decodes and compiles via the Latin-1 fallback, and the recovered character is the Latin-1 code point, not a U+FFFD replacement.
- **Threshold:** Zero 'DECODE_ERROR' lines in yara_processing; valid_rules equals the count of well-formed rules in the pack; the dumped failed-rule artefact contains the byte pair C3 A9 (UTF-8 encoding of U+00E9 'é') at the planted position and contains zero occurrences of EF BF BD (U+FFFD).
- **Setup:** Pack of 2 rules whose raw bytes are Latin-1, not UTF-8: rule A is deliberately broken (condition: $a and) and carries a comment line `// author: caf<0xE9>` containing a lone 0xE9 byte; rule B is valid. Base64 the raw byte sequence. Note the third tier ('replace') is unreachable — latin-1 decodes every possible byte sequence — so only the UTF-8 -> Latin-1 transition is testable.
- **Evidence:** `hexdump -C <scanner_dir>/failed_rules/failed_rule_A.yar` (the file is written with encoding="utf-8", so the recovered code point is re-encoded there); absence of any 'DECODE_ERROR: Base64 decode failed' line in <scanner_dir>/logs/yara_processing_<run_id>.log; valid_rules in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** The same two rules delivered as genuine UTF-8 must yield identical valid_rules/failed_rules and the identical C3 A9 byte pair in the dump — proving the Latin-1 path recovered usable text rather than mangling it into something that merely happened to compile.

### `RULE-007` Embedded YARA_RULE fallback (empty by default = hard abort)

*core*

- **Must be true:** Omitting yarafile aborts the run with the named default-is-empty error instead of scanning the filesystem with zero rules.
- **Threshold:** Exactly 1 'Using YARA rules from default configuration' line followed by exactly 1 'CRITICAL: Failed to decode YARA rules: Default YARA_RULE is empty - must provide yarafile parameter'; 0 files scanned; non-zero exit; no scan_summary_<run_id>.json; 0 rows in yara_scanner_scans_v3_* for that run_id.
- **Setup:** Run the payload with the yarafile parameter omitted entirely (not empty-string-in-a-quoted-arg — omitted, so run()'s `if yarafile:` is False).
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log lines 'Using YARA rules from default configuration' and 'CRITICAL: Failed to decode YARA rules: Default YARA_RULE is empty - must provide yarafile parameter'; the Action Center SCAN_RESULT line and exit code; absence of <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** Every other Round 3 run (yarafile supplied) must log 'Using YARA rules from default configuration' zero times — the abort must be reachable only by omission, never by a delivered pack.

### `RULE-008` rule_hash — SHA-256 of the decoded rule text

*core*

- **Must be true:** scan_id is exactly hostname + '_' + run_id + '_yara_' + the first 12 hex chars of SHA-256(decoded rule text): the same pack on the same host twice yields the same 12-char suffix but different scan_ids, and two different packs yield different suffixes — and that one scan_id is the identical value on the summary, every matches row and every scans row.
- **Threshold:** For each run, scan_id == f"{hostname}_{run_id}_yara_{sha256(decoded_pack_text.encode('utf-8')).hexdigest()[:12]}" computed independently - exact string match. Runs A and B (same pack): trailing 12 chars identical, full scan_id different. Run C (one meta string altered): trailing 12 chars differ from A. In XQL, count_distinct(scan_id) == 1 per run over yara_scanner_scans_v3_* (lifecycle rows are always written); over yara_scanner_matches_v3_* assert count_distinct(scan_id) == 1 ONLY because each pack is required to include a string-bearing rule that matches a planted decoy file - without a planted match the matches dataset has 0 rows for the run.
- **Setup:** Three Round 3 deliveries: A and B are byte-identical packs to the same endpoint; C is A with one meta string altered.
- **Evidence:** 'Scan ID: <scan_id> (rule hash: <12 chars>...)' in <scanner_dir>/logs/yara_processing_<run_id>.log; the top-level scan_id key in <scanner_dir>/logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count_distinct(scan_id)` and the same over yara_scanner_scans_v3_*.
- **Negative control:** Runs A and B must NOT collide on scan_id - a shared rule-hash-only scan_id is the exact regression the hostname+run_id prefix was added to fix. Additionally, all three packs must each contain at least one rule with a `strings:` section matching a planted decoy: a condition-only rule produces match_count == 0 in add_match and therefore no dataset row at all, which would make the XQL half of this criterion vacuous rather than passing.
- **Why this round:** Prior is Round 3 and stays there: scan_id is the join key Round 2's books rely on, but the claim under test is its DERIVATION from the rule text, which only a multi-pack crafted round can vary.

### `RULE-009` yara_processing_<run_id>.log — the rule-handling audit trail

*supporting*

- **Must be true:** Every run that gets as far as ScanConfig creates exactly one yara_processing_<run_id>.log, opened in mode='w' with its own INFO FileHandler (propagate=False), whose first five lines are the fixed banner - and it carries the rule-handling trail independently of the root logger, whose only stderr sink is pinned to WARNING.
- **Threshold:** File exists for every run_id in the round, including the aborted RULE-004/005/007 deliveries and the cache-HIT runs; line 1 == '=== YARA Processing Log ===', lines 2-4 begin 'Python Version:', 'Platform:', 'YARA Version:', line 5 is 50 '=' characters (after the '[ts] [LEVEL] ' prefix); the file also contains 'YARA Scanner VERSION' and exactly one of 'Using YARA rules from provided parameter' / 'Using YARA rules from default configuration' - lines written unconditionally in ScanConfig before the decode branch, and therefore present on aborted, fresh-compile and cache-HIT runs alike. Do NOT key on 'Available YARA modules:' or 'CRITICAL: Failed to decode YARA rules:'; neither is written on a cache-HIT run.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log - head -5 of the file plus a grep for 'YARA Scanner VERSION' and the two 'Using YARA rules from ...' variants; the run_id in the filename must equal config.run_id (format YYYYMMDD_HHMMSS_ffffff).
- **Negative control:** A second run in the same logs_dir must produce a SEPARATE yara_processing_<run_id>.log with its own banner — mode='w' must not truncate or append to the previous run's file, since log retention (LOG_KEEP_SCANS) relies on one file per run_id.
- **Why this round:** Assigned Round 3 rather than Round 1's log-file inventory: this is the EIGHTH per-run log, outside the six category logs plus diagnostics_<run_id>.log that Round 1 enumerates, and it is the only one whose content is entirely rule-driven — including on the pre-scanner abort runs that exist only in Round 3.

### `RULE-011` YARA module availability probe (per-agent libyara capability detection)

*core*

- **Must be true:** The probe's reported module list is the agent's real libyara capability set — every module it names compiles when a rule imports it, every default it omits causes an importing rule to be SKIPPED not failed — and on a cache HIT the line is not written at all.
- **Threshold:** Fresh-compile run: exactly 1 'Available YARA modules:' line in yara_processing_<run_id>.log; for each of the 8 defaults, the rule keyed to it lands in valid_rules iff the module is on that line, and produces exactly one <scanner_dir>/failed_rules/skipped_rule_<name>_<module>.yar iff it is not; valid_rules + skipped_rules == 8 and failed_rules == 0. Cache-HIT run: 0 occurrences of 'Available YARA modules:' while compile_source == "cache", valid_rules and failed_rules equal to run 1's, and the sidecar-restored skipped count read from the 'Rule cache HIT rules_<key>.yarac load=...s (valid=N failed=M skipped=S)' line in system_<run_id>.log - NOT from scan_summary, whose skipped_rules is 0 on any cache hit.
- **Setup:** Probe pack of 8 rules, rule i carrying its own `import "<m_i>"` for m_i in ['pe','elf','cuckoo','magic','hash','math','dotnet','time'] and a trivial condition. Deliver once against an emptied <scanner_dir>/rule_cache/ (fresh), then deliver the byte-identical pack again (cache hit).
- **Evidence:** 'Available YARA modules: <comma list>' in <scanner_dir>/logs/yara_processing_<run_id>.log (ErrorLogger INFO; the same text also reaches <scanner_dir>/logs/diagnostics_<run_id>.log via the root INFO handler); <scanner_dir>/failed_rules/skipped_rule_*.yar file set; valid_rules / skipped_rules / failed_rules and compile_source in <scanner_dir>/logs/scan_summary_<run_id>.json; 'Rule cache HIT rules_<key>.yarac load=...' in <scanner_dir>/logs/system_<run_id>.log.
- **Negative control:** A module the probe DOES list must never produce a skipped_rule_*.yar - the probe must not be reporting a static list. Pack construction: put all 8 `import "<m_i>"` lines at file level ABOVE the first rule and give rule i a condition that actually USES m_i (pe.is_pe, elf.type, math.entropy(0,filesize)>0, hash.md5(0,1)=="x", time.now()>0, magic.type() contains "x", dotnet.number_of_streams>0, cuckoo.network.http_request(/x/)). Do NOT attach the imports to individual rules: an import above a `rule` line is absorbed into the PREVIOUS rule's block by the splitter, and an import inside the braces is a syntax error that would land an available-module rule in failed_rules. And the cache-HIT run must not merely be quiet: system_<run_id>.log's 'Rule cache HIT ... (valid=N failed=M skipped=S)' must reproduce run 1's three counts, so the missing module line is the suppression and not a broken run. scan_summary.skipped_rules reading 0 on the HIT run is CURRENT behaviour, not a failure of this criterion.

### `RULE-012` Probe candidate set extended from the submitted rules' own imports

*supporting*

- **Must be true:** A module outside the eight hardcoded candidates is genuinely probed when the pack imports it — reported as available when libyara has it, and reported absent (with the importing rule SKIPPED, not silently trusted) when it does not.
- **Threshold:** 'Available YARA modules:' contains the extra module name for the supported case, and its comma list equals (the subset of the 8 defaults this agent actually has, as established by RULE-011) plus exactly that one extra name - assert set equality against RULE-011's baseline line, not an absolute count. It does NOT contain 'zz_not_a_module' for the bogus case, and the rule importing it yields exactly one <scanner_dir>/failed_rules/skipped_rule_Y_zz_not_a_module.yar with skipped_rules incremented by 1 and failed_rules unchanged.
- **Setup:** Determine one module this agent's libyara provides outside the 8 defaults (e.g. `console` on libyara >= 4.2) by a one-line probe first. Then deliver a pack with a file-level `import "<extra>"` plus rule X using it, and a second rule Y carrying its own `import "zz_not_a_module"`.
- **Evidence:** 'Available YARA modules:' line in <scanner_dir>/logs/yara_processing_<run_id>.log; valid_rules / skipped_rules / failed_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/failed_rules/skipped_rule_Y_zz_not_a_module.yar.
- **Negative control:** 'zz_not_a_module' must NOT appear on the Available line - extending the candidate set from the source must not degrade into trusting the source. Placement requirement: `import "zz_not_a_module"` must sit INSIDE rule Y's extracted block, i.e. on a line after Y's declaration (after its closing brace is fine - a trailing top-level import still compiles); an import written above `rule Y` is attributed by _split_yara_rules to the preceding rule, which would name the wrong rule in the skipped_rule_*.yar filename.

### `RULE-013` Duplicate module probe on a fresh compile (wasted work)

*low*

- **Must be true:** On a cache-enabled cold compile the module probe runs twice, so a compile whose cost is dominated by the probe takes roughly double the time it takes with the rule cache disabled — the same pack, the same fresh compile, the only difference being one extra probe pass.
- **Threshold:** compile_seconds(run A, YARA_RULE_CACHE default/enabled, rule_cache dir emptied) >= 1.8 x compile_seconds(run B, YARA_RULE_CACHE=0), with compile_seconds(B) >= 0.20 so the ratio clears the 2-decimal rounding floor; compile_source == "fresh" in BOTH runs.
- **Setup:** Probe-dominated pack: one trivial `rule probe_ok { condition: true }` preceded by 400 lines `import "zzmod001"` .. `import "zzmod400"` (all unavailable, so all are stripped from the preamble and the rule still compiles). Raise the import count until compile_seconds(B) >= 0.20. Run A: delete <scanner_dir>/rule_cache/ first, leave YARA_RULE_CACHE unset. Run B: YARA_RULE_CACHE=0 — read at module import time, so export it in the shell for an SSH run on xdr-agent or prepend os.environ["YARA_RULE_CACHE"]="0" ahead of the scanner body in the snippet.
- **Evidence:** compile_seconds and compile_source in <scanner_dir>/logs/scan_summary_<run_id>.json for both runs; corroborate with 'Rule compile FRESH <n>s' in <scanner_dir>/logs/system_<run_id>.log. The delta is exactly one probe pass: _load_or_compile_rules stamps _compile_seconds immediately after _compile_yara_rules returns and BEFORE _save_rule_cache, so cache-write cost is excluded from the comparison.
- **Why this round:** The catalogue calls this unobservable, but it is decidable without a code change: _get_available_yara_modules probes the 8 defaults UNION the pack's own imports, so a pack with hundreds of unresolvable imports makes one probe pass the dominant term in compile_seconds, and YARA_RULE_CACHE toggles the first pass on and off. Round 3 because the discriminator is a crafted rule shape, not a resource-discipline measurement.

### `RULE-014` Cuckoo-module absence warning

*low*

- **Must be true:** On an agent whose libyara lacks cuckoo, the dedicated warning names cuckoo specifically on both sinks; on a cache HIT (where _compile_yara_rules never runs) it is absent.
- **Threshold:** Fresh compile on a cuckoo-less agent: exactly 1 WARNING line 'YARA cuckoo module not available' in yara_processing and exactly 1 'YARA cuckoo module not available - rules using it will be skipped' in the Action Center stderr/output. Cache-HIT run of the identical pack: 0 occurrences of either line.
- **Setup:** Any Round 3 fresh-compile delivery to an agent whose 'Available YARA modules:' line omits cuckoo (established by RULE-011), then a second byte-identical delivery to take the cache HIT.
- **Evidence:** 'YARA cuckoo module not available' in <scanner_dir>/logs/yara_processing_<run_id>.log; 'YARA cuckoo module not available - rules using it will be skipped' in the Action Center action output (root logger's WARNING StreamHandler) and in <scanner_dir>/logs/diagnostics_<run_id>.log; compile_source in <scanner_dir>/logs/scan_summary_<run_id>.json to tell the two runs apart.
- **Negative control:** Run two in-round controls on the same cuckoo-less agent instead of requiring a cuckoo-capable endpoint: (a) SPECIFICITY - the same pack also imports a second unavailable module (e.g. 'zz_not_a_module', confirmed absent from the 'Available YARA modules:' line); no '<that module> module not available' warning may appear on either sink, proving the warning is hardcoded to cuckoo and not emitted for every missing module; (b) PROBE-LINKAGE - the run's 'Available YARA modules:' line must omit cuckoo, so the warning tracks the probe result rather than firing unconditionally. Then the cache-HIT run of the identical pack must show 0 occurrences of either line while compile_source == "cache".

### `RULE-015` Preamble extraction and de-duplication (import/include hoisting)

*supporting*

- **Must be true:** A repeated import is hoisted into the shared preamble exactly once regardless of how many rules carry it, while distinct imports are all kept — the reported unique count is post-dedup and post-availability-filter.
- **Threshold:** For a 20-rule pack each carrying `import "pe"`, plus one `import "elf"` and one `include` of a file that EXISTS (create an empty <scanner_dir>/inc_empty.yar on the endpoint first): 'Found 3 unique import statements' in diagnostics (pe + elf + the include - len(imports) is counted after dedup and after the availability filter, and includes are gathered into that same list), while the initialization census reports import_statements == 21 (the census regex is `import\s+`, which never matches an `include` line); the preamble reproduced at the top of any failed_rule_*.yar contains `import "pe"` exactly once.
- **Setup:** 20 valid rules each preceded by `import "pe"`, one rule preceded by `import "elf"`, one `include "<scanner_dir>/none.yar"` line placed with the imports, and one deliberately-broken rule so a failed_rule artefact is written carrying the preamble text. Run on a pe- and elf-capable agent.
- **Evidence:** 'Found 3 unique import statements' in <scanner_dir>/logs/diagnostics_<run_id>.log; 'import_statements' inside the data= blob of the 'YARA Rules loaded: N rules, M imports' record in <scanner_dir>/logs/system_<run_id>.log; the preamble block at the top of <scanner_dir>/failed_rules/failed_rule_<broken>.yar. Residual gap: which imports were dropped as unavailable is only 'Skipping unavailable module in preamble:' at logging.debug, below the root INFO handler, so the drop list itself is not recoverable — RULE-016 decides that by absence instead.
- **Negative control:** `import "elf"` must survive alongside `import "pe"` - dedup keys on the stripped line text, so two DIFFERENT imports must both appear; a count of 1 would mean the hoist collapsed distinct modules rather than duplicates. The included file must exist: an unresolvable include is hoisted verbatim and fails every rule (see RULE-017), which would leave zero valid rules and abort the run before the pack's dedup behaviour could be read off a healthy compile.

### `RULE-016` Unavailable preamble imports are stripped from the shared preamble

*core*

- **Must be true:** A file-level import naming a module this agent lacks is removed from the shared preamble, so rules that never touch that module still compile — and an import naming an available module is left untouched.
- **Threshold:** For a pack headed by `import "cuckoo"` and `import "pe"` on a cuckoo-less, pe-capable agent: valid_rules == 4 (the cuckoo-free rules), skipped_rules == 1 (the rule that actually uses cuckoo), failed_rules == 1 (the deliberately-broken rule); the preamble reproduced at the top of failed_rule_<broken>.yar contains `import "pe"` and contains zero occurrences of `import "cuckoo"`.
- **Setup:** Pack headed by `import "cuckoo"` and `import "pe"` containing: 4 rules that never mention cuckoo (one of which uses pe.is_pe), 1 rule whose condition uses cuckoo.network.http_request(...), and 1 rule with a syntax error to force the failed_rule artefact that reproduces the preamble.
- **Evidence:** <scanner_dir>/failed_rules/failed_rule_<broken>.yar — its preamble block (written above the rule body) must contain `import "pe"` and not `import "cuckoo"`; valid_rules / skipped_rules / failed_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; 'Found N unique import statements' in <scanner_dir>/logs/diagnostics_<run_id>.log counting only the survivors.
- **Negative control:** `import "pe"` must remain in the reproduced preamble and the pe-using rule must land in valid_rules. A filter that stripped everything would show the same skipped_rules count for cuckoo while silently breaking every pe rule.

### `RULE-017` `include` directives hoisted verbatim and never filtered

*supporting*

- **Must be true:** An `include` line is copied into the shared preamble unchanged and is never subject to the module-availability filter, so an unresolvable include fails every rule loudly instead of being silently dropped.
- **Threshold:** For a 3-rule pack headed by an include of a nonexistent file: failed_rules == 3, valid_rules == 0, skipped_rules == 0; each <scanner_dir>/failed_rules/failed_rule_*.yar carries an '// Error:' header naming the include problem and reproduces the include line verbatim; the run aborts with 'FINAL_COMPILATION_ERROR: No valid YARA rules could be compiled out of 3 rules.'
- **Setup:** 3-rule pack headed by `include "<scanner_dir>/does_not_exist.yar"` and, on a cuckoo-less agent, also `import "cuckoo"`. Do not create the included file.
- **Evidence:** <scanner_dir>/failed_rules/failed_rule_*.yar — the verbatim include line in each preamble block and the '// Error:' header; 'FINAL_COMPILATION_ERROR: No valid YARA rules could be compiled out of 3 rules.' in <scanner_dir>/logs/yara_processing_<run_id>.log plus the 'CRITICAL: YARA rule compilation failed:' / 'Valid rules: 0, Failed rules: 3, Skipped: 0' pair on Action Center stderr; failed_rules / valid_rules in <scanner_dir>/logs/scan_summary_<run_id>.json if written.
- **Negative control:** The `import "cuckoo"` in the same preamble MUST be stripped (absent from the reproduced preamble) while the include survives — the two are gathered by the same loop, so this proves the filter discriminates on the import form rather than passing or dropping the whole preamble wholesale.

### `RULE-018` Rule boundary splitting into individually-compiled units

*core*

- **Must be true:** The splitter finds exactly one unit per line-anchored rule declaration and no more, and every extracted block is a complete, brace-balanced rule body — the three-way valid/failed/skipped tally reconciles to the true declared-rule count.
- **Threshold:** For a 12-rule pack carrying two decoys: 'Found 12 rule start positions' and 'Rule extraction complete: 12 successful, 0 failed' in diagnostics; valid_rules + failed_rules + skipped_rules == 12 in scan_summary; every failed_rule_*.yar body has equal counts of '{' and '}'.
- **Setup:** 12 well-formed rules (1 deliberately broken so a dumped body can be brace-checked) plus two decoys that must NOT be counted: a line `// rule commented_out {` and, inside a rule's strings section, `$s = "rule fake_decoy {"`. Neither begins a line with the `rule` keyword, so a correct splitter reports 12, not 14.
- **Evidence:** 'Found 12 rule start positions', 'Rule extraction complete: 12 successful, 0 failed' and 'Split result: 12 rules extracted' in <scanner_dir>/logs/diagnostics_<run_id>.log; valid_rules / failed_rules / skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; brace balance of <scanner_dir>/failed_rules/failed_rule_<broken>.yar. failed_extractions is only ever logged, never persisted, so the counts are the only durable signal.
- **Negative control:** The two decoys must not appear as rule starts: a count of 13 or 14 means a comment or a string literal was mis-split, which would truncate the surrounding rule's body and silently change what it matches.

### `RULE-019` `private rule` / `global rule` are not recognised as rule starts

*core*

- **Must be true:** A `private rule` (or `global rule`) declared before the first plain rule is never extracted as a unit, so a plain rule that references it fails to compile with an undefined-identifier error and the helper leaves no artefact of its own.
- **Threshold:** failed_rules == 1, valid_rules == 1, skipped_rules == 0; <scanner_dir>/failed_rules/failed_rule_main.yar exists with an '// Error:' line containing 'undefined identifier "helper"'; there is NO failed_rule_helper.yar and NO skipped_rule_main_*.yar in <scanner_dir>/failed_rules/; diagnostics_<run_id>.log reads exactly 'Found 2 rule start positions' and 'Found 2 rule declarations' (the two PLAIN rules, main and control_plain - the private rule is not line-anchored and is never extracted), while system_<run_id>.log's census reads 'YARA Rules loaded: 3 rules, 0 imports' (its regex is unanchored and does count the private rule). The 3-vs-2 gap is the discarded helper; a value of 3 on either diagnostics line would mean the modifier had been treated as a rule start.
- **Setup:** Pack, in this order and with no imports: (1) `private rule helper { strings: $h = "HELPERTOKEN" condition: $h }`, (2) `rule main { condition: helper }`, (3) `rule control_plain { strings: $c = "CONTROLTOKEN" condition: $c }`. The private rule must come FIRST — placed between two plain rules it would instead be absorbed into the preceding rule's block, a different outcome.
- **Evidence:** <scanner_dir>/failed_rules/failed_rule_main.yar '// Error:' header; the directory listing of <scanner_dir>/failed_rules/ showing no helper artefact; 'Found 2 rule start positions' in <scanner_dir>/logs/diagnostics_<run_id>.log; valid_rules / failed_rules / skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; the 'YARA Rules loaded: 3 rules, 0 imports' record in <scanner_dir>/logs/system_<run_id>.log (its unanchored count DOES see the private rule, so the 3-vs-2 gap is the discarded helper).
- **Negative control:** rule control_plain must compile and count toward valid_rules — the splitter must drop only the modifier-prefixed declaration, not everything it fails to anchor on. And _module_missing_from_compile_error must NOT reclassify main as skipped: 'helper' is not in the source's imported-module set, so an undefined identifier that is a rule name must stay a FAILURE.

### `RULE-020` Everything before the first rule declaration is discarded (except imports)

*supporting*

- **Must be true:** Non-import material placed ahead of the first rule declaration is discarded and cannot contaminate the first rule's compiled source, while an import placed in that same region IS retained in the shared preamble.
- **Threshold:** valid_rules == 5 and failed_rules == 1 (only the deliberately-broken rule) and skipped_rules == 0 — the junk line contributes zero additional failures; the preamble reproduced at the top of failed_rule_<broken>.yar contains `import "pe"` exactly once; the 'YARA Rules loaded: N rules' census exceeds valid_rules+failed_rules+skipped_rules by exactly the number of `rule <name>` occurrences planted in the discarded region (0 here).
- **Setup:** Pack whose first three lines are, in order: `NOT_YARA_PREAMBLE_JUNK = 12345` (no braces, so the brace-balance check is not confounded), `import "pe"`, and a blank line — followed by 5 valid rules (one using pe.is_pe) and 1 rule with a syntax error to force the preamble-carrying dump. Run on a pe-capable agent.
- **Evidence:** valid_rules / failed_rules / skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; the preamble block at the top of <scanner_dir>/failed_rules/failed_rule_<broken>.yar; 'Found 6 rule start positions' in <scanner_dir>/logs/diagnostics_<run_id>.log; the 'YARA Rules loaded: 6 rules, 1 imports' record in <scanner_dir>/logs/system_<run_id>.log.
- **Negative control:** `import "pe"` from the discarded region must survive into the preamble and the pe-using rule must compile — the 'except imports' half is what stops this from being an indiscriminate truncation. And if the junk were NOT discarded it would be prepended to the first rule's source and that rule would fail, taking failed_rules to 2.
- **Why this round:** The catalogue marks this unobservable because nothing records the discarded region. It is decidable by a negative assertion instead: planted junk that leaves zero trace in the compile outcome IS the evidence that it was discarded, and the surviving import proves the exception clause.

### `RULE-023` Per-rule namespace assignment (ns_<index>_<rulename>)

*core*

- **Must be true:** Per-rule namespacing lets two rules share a name and both fire, while isolating each rule from every other rule's identifiers — a cross-rule reference cannot resolve even when both rules are in the same pack.
- **Threshold:** Duplicate half: valid_rules counts both copies; for the single planted decoy file, scan_summary matches increases by 2 while unique_rules_triggered counts 'dup_probe' once; XQL returns exactly 2 rows with rule == 'dup_probe' and the same filename for that scan_id; <scanner_dir>/alert/dup_probe.txt contains exactly 2 blocks reading "YARA rule 'dup_probe' matched file: <decoy path>". Reference half: failed_rules includes rule_b with '// Error:' containing 'undefined identifier "rule_a"'.
- **Setup:** Pack containing (a) two rules both named `dup_probe` with different string sets, both matching one planted decoy file; (b) `rule rule_a { strings: $x = "XTOK" condition: $x }` and `rule rule_b { condition: rule_a }`.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "dup_probe" | fields filename, match_count`; matches and unique_rules_triggered in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/alert/dup_probe.txt; <scanner_dir>/failed_rules/failed_rule_rule_b.yar.
- **Negative control:** The alert channel dedups on (rule, filename), so the duplicate pair must yield 2 dataset rows but only 1 queued alert — a criterion that only counted alerts would read the duplicate as a single hit. And rule_a itself must compile and match (valid, with its own dataset row), proving rule_b's failure is namespace isolation and not a broken rule_a.

### `RULE-024` Every rule is compiled twice on a fresh compile

*supporting*

- **Must be true:** A fresh compile puts every rule through BOTH an individual trial compile and the combined namespaced compile: one broken rule is isolated instead of killing the pack (only possible if compiled individually first), and the survivors still arrive as one working ruleset (only possible via the second, combined compile).
- **Threshold:** Run A (rule_cache emptied): compile_source == "fresh", valid_rules == 199, failed_rules == 1, files_scanned > 0, exit code 0, and exactly 1 <scanner_dir>/failed_rules/failed_rule_*.yar. Run B (byte-identical pack, immediately after): compile_source == "cache", valid_rules == 199 and failed_rules == 1 restored from the sidecar, and compile_seconds(B) <= 0.25 x compile_seconds(A).
- **Setup:** 200-rule pack, exactly one rule syntactically broken (`condition: $a and`), at least one valid rule matching a planted decoy. Empty <scanner_dir>/rule_cache/ before run A; deliver the identical pack again for run B.
- **Evidence:** compile_source, compile_seconds, valid_rules, failed_rules, files_scanned in <scanner_dir>/logs/scan_summary_<run_id>.json for both runs; 'Rule compile FRESH <n>s' and 'Rule cache HIT rules_<key>.yarac load=<n>s (valid=199 failed=1 skipped=0)' in <scanner_dir>/logs/system_<run_id>.log; <scanner_dir>/rule_cache/rules_<key>.yarac and its .meta.json sidecar.

### `RULE-025` Compile-time external variables (filepath, filename)

*core*

- **Must be true:** Exactly two externals are declared at compile time — filepath and filename — so rules keying on either compile, and a rule keying on any other external name fails with an undefined identifier rather than being quietly accepted.
- **Threshold:** valid_rules includes both externals rules; zero failed_rule_*.yar carrying 'undefined identifier "filename"' or 'undefined identifier "filepath"'; the control rule referencing `filepath_lower` produces exactly one <scanner_dir>/failed_rules/failed_rule_<name>.yar whose '// Error:' line contains 'undefined identifier "filepath_lower"'.
- **Setup:** Pack with (a) `rule ext_filename { condition: filename matches /ext_probe/ }`, (b) `rule ext_filepath { condition: filepath contains "<planted dir>" }`, and (c) control `rule ext_bogus { condition: filepath_lower contains "x" }` — filepath_lower is an XSIAM-edition external that this edition does not declare.
- **Evidence:** valid_rules / failed_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/failed_rules/failed_rule_ext_bogus.yar '// Error:' header; absence of failed_rule_ext_filename.yar and failed_rule_ext_filepath.yar in <scanner_dir>/failed_rules/.
- **Negative control:** ext_bogus must FAIL. If it compiled, the externals dict would be broader than the two names the match-time call actually populates, and such a rule would then evaluate against a permanently empty string — matching nothing, forever, with no error anywhere.

### `RULE-026` Per-file external population at match time

*core*

- **Must be true:** filepath and filename are repopulated for each scanned file with that file's own path and basename, so a rule whose only discriminator is the external fires on exactly the intended file and on no other - while an identically-contented sibling inside the same scanned tree does not.
- **Threshold:** Each externals rule must AND its external test with a string that both planted files contain (e.g. `$m = "EXTPROBE"`), so match_count > 0 and a dataset row is actually emitted. Then: rule ext_filename produces exactly 1 row in yara_scanner_matches_v3_* for the scan_id, with filename == the planted probe file; the identically-contented sibling produces 0 rows for that rule. Rule ext_filepath produces one row per file under the planted directory and 0 rows for the control files, which must sit INSIDE the scan target but outside the planted directory. <scanner_dir>/alert/ext_filename.txt contains exactly one 'matched file:' block.
- **Setup:** Plant two byte-identical files with different names in one target directory: yara_ext_probe.bin and yara_ext_sibling.bin (identical content, so no content-based rule can distinguish them), plus 3 more files in a sibling directory outside the target. Pack: `rule ext_filename { condition: filename == "yara_ext_probe.bin" }` and `rule ext_filepath { condition: filepath contains "<planted dir>" }`.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule in ("ext_filename","ext_filepath") | fields rule, filename`; <scanner_dir>/alert/ext_filename.txt and <scanner_dir>/alert/ext_filepath.txt.
- **Negative control:** yara_ext_sibling.bin - identical content, same directory, different name - must match the shared string but NOT match ext_filename; without it, a rule that matched everything and a rule driven by the external are indistinguishable. The 3 control files for ext_filepath must be inside the scan target (a sibling directory of the planted dir, not outside the target), otherwise they are never scanned and their absence from the results is explained by targeting rather than by the external. Note also that the externals are populated only after the regular-file and max_file_bytes gates, so an oversized file is never given a chance to match via the external at all.

### `RULE-027` Automatic injection of missing module imports per rule (MODULE_USAGE_PATTERNS)

*supporting*

- **Must be true:** A rule referencing an available module by prefix without importing it has that import prepended before compilation and therefore compiles — but only for the eight modules in the usage table, and only when the import is genuinely absent.
- **Threshold:** Exactly 4 "Auto-injected missing imports for rule '<name>'" lines, uncapped - one each for the hash-, math-, elf- and time-using rules; the pe-using rule produces NO injection line because the control rule's own `import "pe"` is hoisted into the shared preamble and lands in preamble_imports for every rule. All 5 module-using rules and the control rule land in valid_rules; the console-using rule produces exactly one <scanner_dir>/failed_rules/failed_rule_<name>.yar with '// Error:' containing 'undefined identifier "console"'. (Alternative pack that restores a 5-for-5 count: drop pe from the five prefixes and have the control rule import and use a module none of the five touch.)
- **Setup:** Pack with no file-level imports: 5 rules whose conditions each use a different available prefix (pe., hash., math., elf., time.); 1 control rule that carries its own `import "pe"` and uses pe.is_pe; 1 rule using `console.log(...)` with no import anywhere in the pack. Run on an agent whose Available list covers pe/hash/math/elf/time.
- **Evidence:** "Auto-injected missing imports for rule '<name>': <modules>" lines in <scanner_dir>/logs/yara_processing_<run_id>.log (also mirrored into diagnostics_<run_id>.log); valid_rules / failed_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/failed_rules/failed_rule_<console rule>.yar.
- **Negative control:** The control rule that already imports pe must produce NO injection line - and neither may the pe-using rule, for the same reason: the hoisted preamble import satisfies both. That shared-preamble suppression is itself the discriminator between 'the injector consults already_imported' and 'the injector fires on any module prefix it sees'. The console rule must FAIL rather than be reclassified as skipped - console is absent from MODULE_USAGE_PATTERNS and is never imported in the source, so _module_missing_from_compile_error correctly declines to rescue it.

### `RULE-028` Skip classification case 1 — explicit inline import of an unavailable module

*core*

- **Must be true:** A rule carrying its own import for a module this agent lacks is classified as SKIPPED before any compile is attempted, never as a compilation failure, and its source is preserved with the single-line header that identifies this path.
- **Threshold:** skipped_rules == 3 and failed_rules == 0 for the three self-importing cuckoo rules; exactly 3 <scanner_dir>/failed_rules/skipped_rule_<name>_cuckoo.yar files, each whose FIRST header line is "// SKIPPED RULE - Module 'cuckoo' not available" and which contains ZERO occurrences of '// (import inherited from the file-level preamble)'; zero failed_rule_*.yar for those three names.
- **Setup:** Pack of 3 rules each carrying `import "cuckoo"` inside its own rule block (no file-level cuckoo import), plus 2 rules each carrying their own `import "pe"`, delivered to a cuckoo-less, pe-capable agent.
- **Evidence:** <scanner_dir>/failed_rules/skipped_rule_<name>_cuckoo.yar (head -2 of each); "SKIP (module unavailable): rule '<name>' requires 'cuckoo'" lines in <scanner_dir>/logs/yara_processing_<run_id>.log; skipped_rules / failed_rules / valid_rules in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** The two rules with their own `import "pe"` must compile into valid_rules and produce no skipped_rule_*.yar - the inline-import scan must key on availability, not on the presence of an import line. Zero skipped and five skipped are both failures. PLACEMENT (load-bearing): every per-rule import must be written on a line AFTER that rule's closing brace and BEFORE the next `rule` declaration - that is the only position _split_yara_rules assigns to the rule's own block AND the only one that still compiles (a trailing top-level import is legal YARA; an import between the braces is a syntax error, which would book the two pe control rules as FAILED; an import above the `rule` line is absorbed into the preceding rule's block, or dropped into the discarded pre-first-rule region for the first rule).

### `RULE-029` Skip classification case 2 — REMOVED usage-regex heuristic (documented dead path)

*core*

- **Must be true:** A rule that merely contains a module name as literal text — with no import of its own — is compiled and can match, even when the pack imports that unavailable module elsewhere; the removed usage-regex heuristic no longer drops it.
- **Threshold:** The decoy rule appears in valid_rules; there is NO <scanner_dir>/failed_rules/skipped_rule_<decoy>_cuckoo.yar and NO failed_rule_<decoy>.yar; the decoy produces >= 1 row in yara_scanner_matches_v3_* for the planted file containing the literal string.
- **Setup:** On a cuckoo-less agent, deliver a pack headed by `import "cuckoo"` containing (a) decoy `rule cuckoo_string_probe { strings: $s = "cuckoo.conf" condition: $s }` with no import of its own, and (b) a genuine `rule cuckoo_user { condition: cuckoo.network.http_request(/x/) }` that inherits the preamble import. Plant a file whose content contains the text 'cuckoo.conf'.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "cuckoo_string_probe"`; valid_rules and skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json; directory listing of <scanner_dir>/failed_rules/ (no artefact for the decoy); <scanner_dir>/alert/cuckoo_string_probe.txt.
- **Negative control:** cuckoo_user — in the SAME pack, same run — must still be classified as skipped (skipped_rule_cuckoo_user_cuckoo.yar). A build that keeps the decoy by disabling skip classification entirely would show that too, so the genuine cuckoo user must remain skipped for this to prove the discrimination rather than the removal of the whole mechanism.

### `RULE-030` Post-hoc module-missing reclassification from the compile error

*core*

- **Must be true:** A rule that fails to compile only because its declaring preamble import was stripped is reclassified from FAILED to SKIPPED off the actual libyara error, and its dump carries the second header line that distinguishes this path from the inline-import case.
- **Threshold:** The pack must also carry at least one rule that compiles cleanly (e.g. a plain string rule with no module use), otherwise valid_sources is empty, the run aborts at FINAL_COMPILATION_ERROR and no scan_summary is written. With that rule present: the inheriting rule contributes to skipped_rules and NOT to failed_rules; exactly one <scanner_dir>/failed_rules/skipped_rule_<name>_cuckoo.yar whose header line 1 is "// SKIPPED RULE - Module 'cuckoo' not available on this agent" and whose line 2 is exactly '// (import inherited from the file-level preamble)'; no failed_rule_<name>.yar for that rule; scan_summary reports skipped_rules == 1, failed_rules == 1, valid_rules >= 1.
- **Setup:** Pack headed by `import "cuckoo"` on a cuckoo-less agent, containing rule A whose condition uses cuckoo.network.http_request(...) with no import of its own, plus one genuinely broken rule (syntax error) so failed_rules is non-zero and the two classes are visibly separated.
- **Evidence:** <scanner_dir>/failed_rules/skipped_rule_A_cuckoo.yar (head -2); "SKIP (module unavailable): rule 'A' needs 'cuckoo' (inherited from a file-level import)" in <scanner_dir>/logs/yara_processing_<run_id>.log; skipped_rules / failed_rules / valid_rules in <scanner_dir>/logs/scan_summary_<run_id>.json - which is only written because the pack includes a compiling rule; on an all-skipped/all-failed pack YaraScanner.__init__ raises and run()'s finally block skips the summary write entirely (`scanner is not None` guard).
- **Negative control:** The syntactically-broken rule in the same run must stay in failed_rules with a failed_rule_*.yar and no skipped_rule_*.yar — the reclassifier requires all three of (libyara said 'undefined identifier "<name>"', the name is imported somewhere in the source, and the module is genuinely unavailable), so a plain syntax error must never be laundered into a skip.

### `RULE-031` Skipped-rule source dumps

*supporting*

- **Must be true:** Every skipped rule's source is written to <scanner_dir>/failed_rules/ with a timestamped header, and the directory is never pruned at scan start — a later run's dumps accumulate alongside an earlier run's rather than replacing them.
- **Threshold:** Run A: count of skipped_rule_*.yar == skipped_rules in scan_summary, and each file's '// Date:' header and mtime fall between run A's run_id timestamp (YYYYMMDD_HHMMSS prefix) and its end time. Run B (a pack with skipped_rules == 0, delivered afterwards): run A's skipped_rule_*.yar files are ALL still present with unchanged mtimes.
- **Setup:** Run A = the RULE-028/RULE-030 pack (non-zero skipped_rules). Run B = a clean pack importing only available modules. Both with CONFIG_HOST_CLEANUP at its default "off" (host cleanup would rmtree failed_rules_dir and invalidate the persistence claim).
- **Evidence:** `ls -l --time-style=full-iso <scanner_dir>/failed_rules/` before and after run B; the '// Date:' line inside each skipped_rule_*.yar; skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json for both runs.
- **Negative control:** Run B must not delete run A's dumps: CleanupManager.initial_cleanup wipes alert_dir, evidence_dir and output_log at scan start but deliberately does NOT touch failed_rules_dir. If run A's files vanish, the diagnostics an operator needs after a bad pack are being destroyed by the next scan.
- **Why this round:** Retention is nominally Round 1's subject, but Round 1's clean pack produces zero skipped and zero failed rules, so the artefacts whose retention is in question only exist in Round 3.

### `RULE-032` Failed-rule source dumps (with resolved preamble)

*supporting*

- **Must be true:** Every compilation failure produces exactly one failed_rule_<name>.yar containing the four header lines, the resolved preamble, then the rule body VERBATIM — pre-injection, which is why a rule that received auto-injected imports does not reproduce standalone.
- **Threshold:** Add at least one cleanly-compiling rule to the pack so the run reaches scan_summary. Then: the number of failed_rule_*.yar files whose '// Date:' header (and mtime) falls inside THIS run's window - or, equivalently, after emptying <scanner_dir>/failed_rules/ immediately before the run - equals failed_rules in scan_summary; each file's first two lines are '// FAILED RULE - Compilation Error' and '// Error: <libyara message>'; the preamble block equals the surviving imports (post-strip); for the rule that has an 'Auto-injected missing imports' line in yara_processing, its dumped file contains ZERO occurrences of that injected `import` statement.
- **Setup:** Pack headed by `import "pe"` (available) and `import "cuckoo"` (unavailable), containing 3 syntactically broken rules, one of which also uses `hash.md5(...)` without importing hash (so it receives an auto-injection and still fails).
- **Evidence:** <scanner_dir>/failed_rules/failed_rule_*.yar file set (scoped by mtime to this run, or with the directory emptied beforehand) and contents; "Auto-injected missing imports for rule '<name>': hash" in <scanner_dir>/logs/yara_processing_<run_id>.log; failed_rules in <scanner_dir>/logs/scan_summary_<run_id>.json, which exists only because the pack carries a compiling rule alongside the three broken ones.
- **Negative control:** The reproduced preamble must contain `import "pe"` and must NOT contain `import "cuckoo"` — the dump reproduces the RESOLVED preamble that was actually compiled, not the submitted one. A dump carrying the stripped import would send an operator chasing a failure the agent never saw.

### `RULE-033` raw_yara_content.yar dump when the split yields zero rules

*supporting*

- **Must be true:** When input passes the decode-stage rule check but the line-based splitter finds zero rule starts, the whole submitted text is dumped to one fixed path and the run aborts with the named COMPILATION_ERROR — the input is never silently treated as an empty ruleset.
- **Threshold:** <scanner_dir>/failed_rules/raw_yara_content.yar exists, its first line is '// RAW YARA CONTENT - Failed to split into individual rules', and its body equals the decoded pack byte-for-byte; exactly 1 'COMPILATION_ERROR: No YARA rules found in provided content' line; 'Found 0 rule start positions' in diagnostics; 0 files scanned; no valid ruleset (run aborts).
- **Setup:** Exploit the divergence between the two rule regexes: decode_yara_rules matches `(?m)^\s*rule\s+\w+` across the WHOLE text (its `\s+` spans newlines), while _split_yara_rules applies `^\s*rule\s+\w+` per line. Deliver base64 of a pack whose only declaration is split across two lines:\n  rule\n    evil_split_probe\n  {\n      condition: true\n  }\nThis passes decode validation and yields zero rule starts.
- **Evidence:** <scanner_dir>/failed_rules/raw_yara_content.yar; 'COMPILATION_ERROR: No YARA rules found in provided content' in <scanner_dir>/logs/yara_processing_<run_id>.log; 'Saved raw YARA content to: <path>' at ERROR level, so it also reaches the Action Center output; 'Found 0 rule declarations' and 'Found 0 rule start positions' in <scanner_dir>/logs/diagnostics_<run_id>.log.
- **Negative control:** The same pack with the declaration on one line (`rule evil_split_probe {`) must produce NO raw_yara_content.yar and valid_rules == 1 — the dump must fire on an empty split, not on every run. Note raw_yara_content.yar has a fixed name and is not run-scoped, so delete any stale copy before the run.

### `RULE-034` Compilation-error forensics (_analyze_compilation_error)

*supporting*

- **Must be true:** Each compilation failure emits one structured error record whose error_analysis classifies the libyara message into the right category and severity, with the identifying detail extracted — the classifier is live, not a dead branch.
- **Threshold:** Four planted failures produce exactly four 'YARA rule compilation failed: <rule_name> | data={...}' lines in scan_errors, with compilation_failure_number 1..4 and no repeats; error_analysis.error_category / severity are respectively invalid_pe_field/high (with invalid_field populated), syntax_error/high (with unexpected_token populated), undefined_identifier/medium, duplicate_definition/low; every payload carries error_message, error_type, error_line_number, rule_length_lines. The data blob is capped at 4000 chars, so keep each rule body short enough that error_analysis is not truncated.
- **Setup:** Pack of 4 broken rules plus 1 valid rule (so the run does not abort at FINAL_COMPILATION_ERROR): (1) `condition: pe.bogus_field_name == 1` on a pe-capable agent; (2) `condition: $a and`; (3) `condition: nosuchthing`; (4) two strings both named `$a`.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log — lines matching 'YARA rule compilation failed: <rule_name> | data=' with the JSON blob's error_analysis object; failed_rules == 4 in <scanner_dir>/logs/scan_summary_<run_id>.json. Note this lands in scan_errors_<run_id>.log, not diagnostics_<run_id>.log, and reaches it only because run() late-binds config.log_manager before YaraScanner compiles — a guard that used to be permanently False.
- **Negative control:** Rule (3)'s undefined identifier must be classified undefined_identifier and stay in failed_rules — it must NOT be reclassified as a module skip, since 'nosuchthing' is not in the source's imported-module set. And the one valid rule must produce zero 'YARA rule compilation failed' lines.

### `RULE-035` Full failed-rule body echoed into the processing log with an error-line marker

*low*

- **Must be true:** Every failed rule — uncapped — gets a numbered failure block in the processing log carrying its full numbered body, and the ERROR HERE marker lands on the line libyara named.
- **Threshold:** For a pack with 15 broken rules: exactly 15 '=== RULE COMPILATION FAILURE #N ===' blocks numbered 1..15 (uncapped), while <scanner_dir>/logs/diagnostics_<run_id>.log carries only 10 'Failed rule <name>:' warnings; each block contains 'Rule Name:', 'Error:', 'Error Type:' and one numbered line per line of the rule body; a block whose libyara message contained 'line N' has exactly one '<-- ERROR HERE' marker on line N, and a block whose message carried no line number has zero markers.
- **Setup:** Pack with NO imports (so source_with_preamble equals the rule body and libyara's line numbers align with the dumped body's numbering), containing 15 rules with syntax errors on known lines plus 1 valid rule so the run does not abort.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log — count of '=== RULE COMPILATION FAILURE #' occurrences and the numbered body lines within each block; 'Failed rule ' warning count in <scanner_dir>/logs/diagnostics_<run_id>.log; failed_rules == 15 in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** The 10-line console throttle applies only to the logging.warning summaries — the failure BLOCKS must not be capped. 10 blocks for 15 failures would mean an operator silently loses the bodies of the last five.

### `RULE-036` Compilation summary block with success rate

*supporting*

- **Must be true:** The COMPILATION SUMMARY totals only valid+failed and excludes module-skipped rules, and its success rate is computed over that same restricted denominator — so a pack with skipped rules reports a smaller total than the summary JSON's three-way tally.
- **Threshold:** With V valid, F failed and S skipped all > 0: 'Total rules processed: V+F' exactly; 'Valid rules compiled: V'; 'Failed rules skipped: F'; 'Success rate: <round(V/(V+F)*100,1)>%'; and V+F is strictly less than valid_rules+failed_rules+skipped_rules in scan_summary, by exactly S.
- **Setup:** Mixed pack on a cuckoo-less, pe-capable agent producing all three classes: e.g. 6 valid rules, 3 syntactically broken, 4 cuckoo-importing (V=6, F=3, S=4 -> 'Total rules processed: 9' against a JSON tally of 13).
- **Evidence:** The 'COMPILATION SUMMARY' block in <scanner_dir>/logs/yara_processing_<run_id>.log ('Total rules processed', 'Valid rules compiled', 'Failed rules skipped', 'Success rate', and 'Failed rules saved to: <scanner_dir>/failed_rules'); valid_rules / failed_rules / skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** 'Total rules processed' must NOT equal 13. If it did, skipped rules would be folded into the success rate and an agent-capability limit would read as a rule-quality problem — the exact confusion the separate skipped counter exists to prevent.

### `RULE-037` First-10 throttle on skipped-rule warnings

*low*

- **Must be true:** The 10-line console throttle is a SHARED budget across both skip paths — inline-import skips and inherited-import reclassifications draw from one counter, so 10 lines total, not 10 per path — while the on-disk dumps and the reported count stay complete.
- **Threshold:** For 6 inline-import cuckoo rules followed by 8 preamble-inheriting cuckoo rules: exactly 10 lines in yara_processing beginning 'SKIP (module unavailable):' summed across BOTH wordings (6 of the 'requires' form, 4 of the 'needs ... (inherited from a file-level import)' form) — not 14, and not 10+10; 14 skipped_rule_*.yar files; 'Skipped 14 rules due to unavailable modules'; skipped_rules == 14 in scan_summary.
- **Setup:** Pack headed by `import "cuckoo"` on a cuckoo-less agent, in this source order: 6 rules each carrying their own inline `import "cuckoo"`, then 8 rules that use cuckoo.* and inherit the file-level import, plus 2 valid pe rules so the run does not abort at FINAL_COMPILATION_ERROR.
- **Evidence:** Count of 'SKIP (module unavailable):' lines in <scanner_dir>/logs/yara_processing_<run_id>.log, split by the 'requires' vs 'needs ... (inherited from a file-level import)' suffix; 'Skipped 14 rules due to unavailable modules' in the same log; count of <scanner_dir>/failed_rules/skipped_rule_*.yar; skipped_rules in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** The cap must throttle LOGGING only: all 14 skipped_rule_*.yar dumps must be written and skipped_rules must read 14. A build that also capped the dumps or the counter would look identical on the log line count alone, while silently discarding four rules' worth of diagnostics.

### `RULE-038` First-10 throttle on failed-rule console warnings

*low*

- **Must be true:** On a pack containing more than 10 genuinely broken rules, exactly 10 truncated 'Failed rule <name>: ' WARNING lines are emitted (failures 1 through 10 inclusive, because the counter is incremented inside log_rule_compilation_error before the <= 10 test), while the full per-failure forensics continue for every failure past 10.
- **Threshold:** scan_summary compile_source == "fresh" (a cache hit runs none of this). Count of lines matching 'Failed rule ' in logs/diagnostics_<run_id>.log == 10 exactly (not 9, not 11). logs/yara_processing_<run_id>.log contains '=== RULE COMPILATION FAILURE #25 ===' and does NOT contain '#26'. <scanner_dir>/failed_rules/ contains a failed_rule_<name>.yar for each of this pack's 25 named broken rules, every one with mtime >= the run_id's YYYYMMDD_HHMMSS timestamp (an absolute directory count is meaningless — failed_rules is never wiped between runs). scan_summary failed_rules == 25.
- **Setup:** Round 3 pack of 25 rules each with a distinct syntax error plus 5 well-formed rules, so the run still compiles and completes.
- **Evidence:** logs/diagnostics_<run_id>.log lines 'Failed rule <name>: ' (root-logger WARNING, also mirrored to Action Center stderr as 'WARNING: Failed rule ...'); '=== RULE COMPILATION FAILURE #25 ===' in logs/yara_processing_<run_id>.log; `failed_rules` in logs/scan_summary_<run_id>.json.
- **Negative control:** The throttle must not suppress the durable record: failure #25's '=== RULE COMPILATION FAILURE #25 ===' block AND its <scanner_dir>/failed_rules/failed_rule_<name25>.yar dump must both exist. If those stop at 10 too, the cap has been applied to the wrong stream.

### `RULE-039` Every-50-rules compile progress

*low*

- **Must be true:** The progress tally fires only at multiples of 50 AND only when rule number i itself compiled cleanly, and its running counts end equal to the compilation-complete line.
- **Threshold:** Clean 200-rule pack: exactly 4 lines matching '✓ Compiled ' in logs/diagnostics_<run_id>.log, at i = 50, 100, 150, 200; the last reads '✓ Compiled 200/200 rules (200 valid, 0 failed, 0 skipped)'; bracketed above by 'Starting compilation of 200 YARA rules...' and below by 'Compilation complete: 200 valid, 0 failed, 0 skipped'.
- **Setup:** Two runs: (a) a 200-rule clean pack; (b) the same pack with rule #50 alone made syntactically invalid.
- **Evidence:** logs/diagnostics_<run_id>.log — the '✓ Compiled i/200 rules' lines, plus the 'Starting compilation of N YARA rules...' and 'Compilation complete: ...' brackets.
- **Negative control:** Run (b) must emit only 3 progress lines (i = 100, 150, 200) and none at i = 50, proving the line sits inside the compile success branch rather than at the top of the loop. A 4th line at i = 50 on run (b) is a fail.

### `RULE-040` Rule-health triage counters (valid / failed / skipped)

*core*

- **Must be true:** valid, failed and skipped are three independent counts, they partition every rule block the splitter produced, and the three surfaces that carry them agree.
- **Threshold:** Mixed pack run: scan_summary valid_rules == V > 0, failed_rules == F > 0, skipped_rules == S > 0, and V + F + S equals the 'Found N rule start positions' count in logs/diagnostics_<run_id>.log; the yara_scanner_scans_v3_* row for this run_id has valid_rules == V and failed_rules == F; the Action Center result line reads 'Scan completed: ... | F rules failed compilation | S rules skipped (module unavailable) | ... matches found'.
- **Setup:** Round 3 mixed pack: 20 well-formed rules, 3 rules importing an unavailable module (cuckoo on these agents), 2 rules with syntax errors. Must be a fresh compile (see RULE-050 — a cache hit zeroes S).
- **Evidence:** `valid_rules`/`failed_rules`/`skipped_rules` in logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, valid_rules, failed_rules`; the SCAN_RESULT line on Action Center stdout.
- **Negative control:** Skipped must not be folded into failed: on a variant pack whose only defect is module unavailability, failed_rules == 0 and the result line reads '0 rules failed compilation | S rules skipped (module unavailable)' with S > 0. If S is reported as failures the three-way split has collapsed.

### `RULE-041` skipped_rules is absent from the scans dataset schema

*supporting*

- **Must be true:** A run with skipped rules is indistinguishable from a run with none when read from the tenant, because scans_schema has no skipped column — while the endpoint summary for the same run carries the true value.
- **Threshold:** The run's scan_summary must show compile_source == "fresh" and skipped_rules == S with S >= 3. XQL over yara_scanner_scans_v3_* for that run_id returns rows carrying all 22 declared scans_schema columns, with valid_rules and failed_rules present and non-null, and NO returned column whose name contains 'skip' (neither `skipped` nor `skipped_rules`). XDR-internal columns may also be present and are ignored.
- **Setup:** The RULE-040 mixed pack, fresh compile, on any Round 3 endpoint.
- **Evidence:** XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>"` with no fields stage — read the column list off the returned rows; logs/scan_summary_<run_id>.json fields `skipped_rules` and `compile_source`; the scans_schema literal in LookupDatasetUploader.__init__ is the single declaration of the 22 columns.
- **Negative control:** valid_rules and failed_rules ARE present and non-null on those same rows. The absence must be specific to the skipped count, not a symptom of a row build that dropped all rule-health columns.

### `RULE-042` All-skipped vs all-failed abort messages are distinguished

*core*

- **Must be true:** Two packs that both abort the scan with zero valid rules produce two DIFFERENT operator-facing texts — an agent-capability message for all-skipped and a rule-syntax message for all-failed.
- **Threshold:** Pack A (every rule imports an unavailable module, none malformed): stderr shows 'CRITICAL: YARA rule compilation failed: No rules could run on this endpoint: all S rule(s) need YARA modules this agent's libyara build does not provide' then 'Valid rules: 0, Failed rules: 0, Skipped: S'. Pack B (every rule syntactically broken): 'CRITICAL: YARA rule compilation failed: No valid YARA rules could be compiled out of N rules.' then 'Valid rules: 0, Failed rules: N, Skipped: 0'. The two message strings must not be equal.
- **Setup:** Two dedicated Round 3 deliveries — pack A of 6 all-cuckoo rules, pack B of 6 rules each missing its condition block.
- **Evidence:** logs/yara_processing_<run_id>.log line 'FINAL_COMPILATION_ERROR: ...' on each run; the same text plus the counts pair on Action Center action stderr.
- **Negative control:** Neither text may appear on the healthy Round 3 run — a build that emits the abort message on every compile would pass a presence-only check.

### `RULE-043` Combined-ruleset compile failure path

*supporting*

- **Must be true:** Per-rule namespacing (ns_<index>_<rulename>) keeps two same-named rules as TWO distinct compiled units through the final combined compile: the combined compile succeeds, no COMBINED_COMPILATION_ERROR is written, and both Dup_Rule units fire independently on the planted decoy.
- **Threshold:** logs/yara_processing_<run_id>.log contains 'Valid rules compiled: N' in its COMPILATION SUMMARY block with N == (authored rule count − 1 broken rule), i.e. BOTH Dup_Rule copies were counted, and contains zero occurrences of the substring 'COMBINED_COMPILATION_ERROR:'. The scan proceeds (scan_summary files_scanned > 0) and the decoy yields exactly 2 dataset rows for ("Dup_Rule", <planted file>) and exactly 2 "YARA rule 'Dup_Rule' matched file:" blocks in <scanner_dir>/alert/Dup_Rule.txt.
- **Setup:** Round 3 pack containing two rules both literally named `Dup_Rule` with different string sets, plus one genuinely broken rule.
- **Evidence:** logs/yara_processing_<run_id>.log — the 'Valid rules compiled: N' summary line and the absence of 'COMBINED_COMPILATION_ERROR:'; XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" | comp count() by rule, filename` showing 2 for (Dup_Rule, planted file); <scanner_dir>/alert/Dup_Rule.txt block count; `files_scanned` in logs/scan_summary_<run_id>.json.
- **Negative control:** The same run's genuinely broken rule must still appear as a '=== RULE COMPILATION FAILURE #1 ===' block, so the absence of COMBINED_COMPILATION_ERROR is not simply because nothing was exercised.
- **Why this round:** The catalogued line only fires when every per-rule compile succeeded yet the combined compile did not; no rule input delivered through Action Center provokes that deliberately, so the criterion is the negative assertion. Round 3's duplicate-rule-name pack is the exact input that would fire it if the ns_<i>_<name> namespace keying ever stopped disambiguating — which is what makes the negative falsifiable rather than vacuous.

### `RULE-044` Rule-compilation disk cache

*core*

- **Must be true:** A second run of a byte-identical rule pack on the same endpoint loads the compiled bundle from disk instead of recompiling, and the switch that disables the cache actually disables it.
- **Threshold:** Run 1: scan_summary compile_source == "fresh"; <scanner_dir>/rule_cache/rules_<40-hex>.yarac and its .meta.json exist afterwards. Run 2 (same pack): compile_source == "cache", compile_seconds < 0.25 × run 1's compile_seconds and < 5.0s absolute, and logs/system_<run_id>.log carries 'Rule cache HIT rules_<key>.yarac load='.
- **Setup:** Two identical SSH-launched runs on xdr-agent with a 200-rule pack (fresh compile of that size is the ~90s path the cache exists to skip); a third run with YARA_RULE_CACHE=0 exported.
- **Evidence:** `compile_source` and `compile_seconds` in logs/scan_summary_<run_id>.json; 'Rule cache HIT' / 'Rule compile FRESH' in logs/system_<run_id>.log; `ls -l <scanner_dir>/rule_cache/`.
- **Negative control:** Run 3 with YARA_RULE_CACHE=0 must report compile_source == "fresh" and must NOT add a new rules_*.yarac, while the entry from run 1 is left untouched on disk. This separates 'the cache was consulted' from 'no cache file existed'.

### `RULE-045` Rule cache key composition

*supporting*

- **Must be true:** The 40-hex cache filename is a pure function of the compile inputs: identical pack gives the identical name, one changed byte gives a different name, and bumping RULE_CACHE_FORMAT gives a different name again.
- **Threshold:** name(A) == name(B) for a byte-identical pack run twice; name(C) != name(A) after appending a single space to the pack; name(D) != name(A) and != name(C) with YARA_RULE_CACHE_FORMAT=2 and the original pack. All four basenames match `^rules_[0-9a-f]{40}\.yarac$`.
- **Setup:** Four SSH-launched runs on one endpoint: A and B with the same pack, C with the same pack plus one trailing space, D with the original pack and YARA_RULE_CACHE_FORMAT=2.
- **Evidence:** `ls <scanner_dir>/rule_cache/rules_*.yarac` immediately BEFORE and AFTER each of the four runs — the basename that appears is the key that run used (the fresh path logs only a duration, never the filename). For the two cache-HIT runs (B, and the repeat of D) the key is named directly in logs/system_<run_id>.log as 'Rule cache HIT rules_<key>.yarac load='. `compile_source` in logs/scan_summary_<run_id>.json identifies which runs were fresh and which hit.
- **Negative control:** A repeat of run D (still with YARA_RULE_CACHE_FORMAT=2) must produce compile_source == "cache" against name(D). A changed key must invalidate the cache, not disable it — if D never hits on repeat, the key is unstable rather than input-derived.

### `RULE-046` yara engine identity tag in the cache key (_yara_version_tag)

*supporting*

- **Must be true:** The .meta.json sidecar records libyara's own identity (binding version / YARA_VERSION / system / machine) and it differs between the two agents, so one rule pack cannot collide on a single cache key across engines.
- **Threshold:** On xdr-agent the sidecar `yara` value matches `^[0-9.]+/[0-9.]+/Linux/[a-z0-9_]+$`; on xdragent2 it matches `^[0-9.]+/[0-9.]+/Windows/[A-Za-z0-9]+$`; the two YARA_VERSION components differ (3.x vs 4.x); the rules_*.yarac basenames produced by the identical pack on the two hosts differ.
- **Setup:** Deliver the same rule pack to xdr-agent and xdragent2 in the same Round 3 pass; read both sidecars.
- **Evidence:** <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json field `yara` on each host; the rules_*.yarac basenames on each host.
- **Negative control:** Two runs of the same pack on the SAME endpoint must produce the identical basename and an identical `yara` value — otherwise the cross-host difference proves nothing about engine identity.
- **Why this round:** Needs two endpoints carrying different libyara builds. Round 3 is the round that already runs both hosts for the match-API and skip-predicate work, so no extra endpoint is provisioned for it.

### `RULE-047` Cache-hit usability validation (load + externals probe)

*supporting*

- **Must be true:** An unusable .yarac is caught at load/probe time and the run falls back to a fresh compile, rather than failing part-way through the scan.
- **Threshold:** After truncating an existing rules_<key>.yarac to 100 bytes: the next run's scan_summary compile_source == "fresh", logs/system_<run_id>.log carries 'Rule cache miss/unusable, compiling fresh: ' followed later by 'Rule compile FRESH ', and the scan still reaches outcome == "completed" with files_scanned > 0.
- **Setup:** Run the pack once to populate the cache; over SSH `truncate -s 100 <scanner_dir>/rule_cache/rules_<key>.yarac`; re-run the same pack.
- **Evidence:** 'Rule cache miss/unusable, compiling fresh:' and 'Rule compile FRESH' in logs/system_<run_id>.log; `compile_source` and `outcome` in logs/scan_summary_<run_id>.json.
- **Negative control:** Three runs in sequence on one endpoint: (1) populate — compile_source == "fresh", .yarac and .meta.json written; (2) an untouched repeat — compile_source == "cache", 'Rule cache HIT rules_<key>.yarac load=' present and NO 'Rule cache miss/unusable' line; (3) truncate to 100 bytes and repeat — compile_source == "fresh" with the 'Rule cache miss/unusable, compiling fresh:' line. Run 2 is the control: the fallback is triggered by the damage, not taken on every run.

### `RULE-048` Corrupt/unusable cache entries are deleted on the failing load

*supporting*

- **Must be true:** The failing entry and its sidecar are both removed on the failing load, and the freshly compiled bundle is written back in their place.
- **Threshold:** Record size + mtime of rules_<key>.yarac and rules_<key>.yarac.meta.json before truncation. After the fallback run: both files exist again, both mtimes are >= the run's start time (from the run_id's YYYYMMDD_HHMMSS prefix), and the .yarac size equals its pre-truncation size (not 100 bytes).
- **Setup:** Same truncation setup as RULE-047, with at least two other packs' entries already present in rule_cache/.
- **Evidence:** `stat` output for <scanner_dir>/rule_cache/rules_*.yarac and rules_*.yarac.meta.json before and after; 'Rule cache miss/unusable' in logs/system_<run_id>.log naming the reason.
- **Negative control:** The other packs' rules_*.yarac and .meta.json entries in the same directory must keep their original mtimes and sizes. Deletion must be scoped to the failing key, not a wipe of the cache directory.

### `RULE-049` Cache LRU touch on hit (os.utime)

*low*

- **Must be true:** A cache hit advances the .yarac mtime to the run time while leaving the sidecar's mtime and both files' contents untouched — the asymmetry is what proves the touch is an LRU marker and not a rewrite.
- **Threshold:** After a hit run: mtime(rules_<key>.yarac) >= that run's start time (run_id prefix); mtime(rules_<key>.yarac.meta.json) unchanged from the fresh run to the second; sha256 of both files identical across the two runs.
- **Setup:** Fresh run then an immediate identical repeat on the same endpoint; capture `stat -c '%Y %s %n'` and sha256 of both files between runs.
- **Evidence:** `stat -c '%Y %n'` and `sha256sum` on <scanner_dir>/rule_cache/rules_<key>.yarac and its .meta.json across the two runs; 'Rule cache HIT rules_<key>.yarac load=' in logs/system_<run_id>.log confirming which key was hit.
- **Negative control:** A third run with a DIFFERENT pack (a cache miss for this key) must leave the first key's .yarac mtime where the hit run left it. If every run touches every entry the timestamp carries no LRU information and pruning (RULE-053) evicts arbitrarily.

### `RULE-050` Counts sidecar (.meta.json) restored on a cache hit — and the skipped count lost there

*core*

- **Must be true:** On a cache hit valid_rules and failed_rules are restored from the sidecar, but skipped_rules is not: the summary reports 0 while the system log's HIT line still carries the true value read from the same sidecar. That disagreement, on one run, is the confirmation.
- **Threshold:** Fresh run of the mixed pack: valid_rules == V > 0, failed_rules == F > 0, skipped_rules == S > 0. Cache run of the same pack: valid_rules == V and failed_rules == F (both exactly equal to the fresh run), skipped_rules == 0, while logs/system_<run_id>.log reads 'Rule cache HIT rules_<key>.yarac load=..s (valid=V failed=F skipped=S)' with the same non-zero S. Corroborating: the cache run's SCAN_RESULT line omits the '| S rules skipped (module unavailable)' clause the fresh run's line carried.
- **Setup:** Mixed pack — 20 compiling rules, 3 rules importing cuckoo (unavailable on these agents, so skipped), 2 broken rules — run twice on one endpoint with the cache enabled. The pack must be mixed, not all-skipped: an all-skipped pack aborts before anything is cached.
- **Evidence:** `valid_rules`/`failed_rules`/`skipped_rules` in logs/scan_summary_<run_id>.json for both runs; the 'Rule cache HIT ... skipped=' line in logs/system_<run_id>.log for the cache run; the SCAN_RESULT line on Action Center stdout for both runs.
- **Negative control:** valid_rules and failed_rules must NOT be zeroed on the cache run. If all three read 0 the sidecar restore failed wholesale, which is a different defect; the catalogued loss is specific to skipped, which _restore_cache_meta returns but no caller assigns.

### `RULE-051` Sidecar-missing fallback: recount from the loaded bundle

*supporting*

- **Must be true:** With the .yarac present and its .meta.json deleted, the run still takes the cache path and recovers a correct valid count by iterating the loaded bundle — but reports failed_rules as 0, losing the fresh run's failure count.
- **Threshold:** compile_source == "cache"; valid_rules == V (identical to the fresh run of the same pack); failed_rules == 0 even though the fresh run reported F >= 2; logs/system_<run_id>.log reads 'Rule cache HIT rules_<key>.yarac load=..s (valid=V failed=0 skipped=0)'; no rules_<key>.yarac.meta.json exists after the run (the hit path returns before any save).
- **Setup:** Run the RULE-050 mixed pack fresh, then delete ONLY <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json (leaving the .yarac intact — deleting the .yarac instead takes the RULE-048 path), then re-run the same pack.
- **Evidence:** `compile_source`, `valid_rules`, `failed_rules` in logs/scan_summary_<run_id>.json; the 'Rule cache HIT ... (valid=.. failed=.. skipped=..)' line in logs/system_<run_id>.log; `ls <scanner_dir>/rule_cache/` showing the .yarac without its sidecar.
- **Negative control:** skipped_rules == 0 on this run is NOT the diagnostic — it reads 0 on every cache hit (RULE-050). The falsifiable claim is failed_rules collapsing from F to 0 while valid_rules is recovered correctly as V. valid_rules reading 1 instead of V means the bundle iteration raised and the hard-coded fallback fired.

### `RULE-052` Atomic cache save under a process-wide lock

*supporting*

- **Must be true:** A successful save leaves exactly the .yarac + .meta.json pair and no temp file behind; a save that cannot write leaves no temp and no partial bundle, and never fails the scan.
- **Threshold:** After a normal fresh-compile run: `ls <scanner_dir>/rule_cache/` contains zero files matching `rules_*.tmp`, and the rules_<key>.yarac / .meta.json pair both carry mtimes inside the run window. After a run with the rule_cache directory made unwritable: logs/system_<run_id>.log carries 'Rule cache save failed (non-fatal): ', zero rules_*.tmp remain, no new rules_*.yarac appears, and scan_summary outcome == "completed".
- **Setup:** Two SSH-launched runs on xdr-agent with a not-yet-cached pack. For the second, `chattr +i <scanner_dir>/rule_cache` before the run (defeats root, which the Action Center payload runs as) and `chattr -i` afterwards.
- **Evidence:** `ls -a <scanner_dir>/rule_cache/`; 'Rule cache save failed (non-fatal):' in logs/system_<run_id>.log; `outcome` and `files_scanned` in logs/scan_summary_<run_id>.json.
- **Negative control:** The unwritable run must still SCAN — files_scanned > 0 and its matches present in yara_scanner_matches_v3_* — proving the save failure is non-fatal rather than aborting the run. And the writable run must leave no .tmp, so 'zero temps' is not an artefact of the save never having run.

### `RULE-055` compile_source / compile_seconds telemetry

*supporting*

- **Must be true:** Both fields track the path actually taken and agree numerically with the system-log line for the same run, on both the fresh and the cache path.
- **Threshold:** Fresh run: compile_source == "fresh" and |compile_seconds − the value in 'Rule compile FRESH <n>s'| <= 0.01, with compile_seconds > 1.0 on a 200-rule pack. Cache run: compile_source == "cache" and |compile_seconds − the load= value in 'Rule cache HIT ... load=<n>s'| <= 0.01, with compile_seconds < 1.0. Both summary values carry 2 decimal places.
- **Setup:** The RULE-044 pair of runs (fresh then cache) plus one run with YARA_RULE_CACHE=0.
- **Evidence:** `compile_source` and `compile_seconds` in logs/scan_summary_<run_id>.json; 'Rule compile FRESH <n>s' and 'Rule cache HIT ... load=<n>s' in logs/system_<run_id>.log.
- **Negative control:** The YARA_RULE_CACHE=0 run must read "fresh" with compile_seconds > 1.0. A compile_seconds pinned at its 0.0 initial value, or a compile_source that never leaves "fresh" when the HIT line was written, means the fields are decorative rather than wired to the path taken.

### `RULE-057` failed_rules directory accumulates across runs

*supporting*

- **Must be true:** With host cleanup off, failed-rule dumps from an earlier run are still on disk after a later run with a different pack — nothing wipes failed_rules at scan start, unlike alert and evidence.
- **Threshold:** After run A (pack A, 3 failing rules) then run B (pack B, 2 different failing rules): <scanner_dir>/failed_rules/ contains all 5 failed_rule_*.yar files; the 3 from A have mtimes strictly before run B's run_id timestamp and the 2 from B strictly after it. No other discriminator exists — the dumps carry no run_id.
- **Setup:** Two consecutive Round 3 runs on one endpoint with different malformed packs, CONFIG_HOST_CLEANUP left at its "off" default.
- **Evidence:** `ls -l --time-style=full-iso <scanner_dir>/failed_rules/ <scanner_dir>/alert/`; the YYYYMMDD_HHMMSS prefixes of both run_ids taken from logs/scan_summary_<run_id>.json.
- **Negative control:** <scanner_dir>/alert/ after run B must contain ONLY run B's .txt files — initial_cleanup does wipe alert_dir and evidence_dir. The accumulation must be specific to failed_rules, not evidence that initial cleanup never ran at all.

### `RULE-058` Rule counts logged to the system log at initialisation

*low*

- **Must be true:** The initialisation line reports an unanchored regex count of `rule\s+\w+` occurrences over the whole submitted rule text, not the number of rules that will actually be compiled — so text containing the token inside comments inflates it.
- **Threshold:** Pack with 20 authored rules plus 3 comment lines of the form '// this rule detects X' (the token mid-line): logs/system_<run_id>.log reads 'YARA Rules loaded: 23 rules, M imports' with a data payload where total_rules_found == 23, import_statements == M (occurrences of `import\s+`, case-insensitive, unanchored) and rule_content_length == the CHARACTER length of the decoded rule text (len() of the str, not its UTF-8 byte count). In the same run logs/diagnostics_<run_id>.log reads 'Found 20 rule start positions' — the line-anchored splitter is blind to the mid-line mentions — and scan_summary valid_rules + failed_rules + skipped_rules == 20, i.e. exactly 3 fewer than total_rules_found.
- **Setup:** Round 3 pack carrying 3 planted comment lines containing 'rule <word>' mid-line (mid-line, so they do not also trip the line-anchored splitter — that is RULE-070's case).
- **Evidence:** logs/system_<run_id>.log line 'YARA Rules loaded: N rules, M imports | data={"import_statements":..,"rule_content_length":..,"total_rules_found":..}'; `valid_rules`/`failed_rules`/`skipped_rules` in logs/scan_summary_<run_id>.json.
- **Negative control:** On a control pack with no such comment text, total_rules_found must equal valid_rules + failed_rules + skipped_rules exactly. The divergence must be caused by the planted text, not be a permanent off-by-N.

### `RULE-059` Per-rule metadata (meta and tags) parsed then discarded

*supporting*

- **Must be true:** A rule carrying meta and tags produces a finding in both channels with no trace of either value anywhere — the absence is the evidence.
- **Threshold:** For rule `rule Meta_Probe : tagalpha tagbeta { meta: author = "ACCEPTANCE_MARKER_7731" ... }` firing on a planted file: `grep -R -c ACCEPTANCE_MARKER_7731` over <scanner_dir>/alert/, <scanner_dir>/logs/ and <scanner_dir>/evidence/ returns 0 (excluding <scanner_dir>/failed_rules/, which may echo raw rule text); 'tagalpha' likewise 0; XQL for that scan_id and rule returns the row with no `meta` or `tags` field and no field whose value contains the marker.
- **Setup:** Round 3 crafted rule with both a meta block carrying a unique marker string and two tags, matching a planted decoy file whose own bytes do not contain the marker.
- **Evidence:** `grep -R ACCEPTANCE_MARKER_7731 <scanner_dir>/alert <scanner_dir>/logs <scanner_dir>/evidence`; XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "Meta_Probe" | fields *`.
- **Negative control:** The same run must show the rule NAME everywhere it belongs — the row's `rule` column == "Meta_Probe", <scanner_dir>/alert/Meta_Probe.txt exists with a match block, and the alert_name contains 'Meta_Probe'. Without that, a zero grep count would just mean the rule never fired.

### `RULE-062` _debug_rule_analysis — rule-file structure analysis and brace-mismatch check

*supporting*

- **Must be true:** On every run that performs a FRESH compile the analysis block is written in full and its brace counts localise the imbalance, with the mismatch warning firing only when the counts actually differ; on a cache-hit run the block is absent entirely, because its only call site is inside _compile_yara_rules.
- **Threshold:** On a run with scan_summary compile_source == "fresh", logs/diagnostics_<run_id>.log contains, in order: '=== YARA FILE ANALYSIS ===', 'Total lines: L' where L equals the decoded pack's line count, 'Found D rule declarations', 'First few rules:' followed by min(5, D) lines of the form '  Line n: rule <name>', and when D > 10 also '  ...', 'Last few rules:' and 5 more such lines, then 'Import statements: I', 'Total braces: O opening, C closing' and '=== END ANALYSIS ==='. On the unbalanced pack O != C and 'BRACE MISMATCH DETECTED!' appears in that file and on Action Center stderr (as 'WARNING: BRACE MISMATCH DETECTED!').
- **Setup:** Two Round 3 packs of >10 rules each: one balanced, one with a single closing brace deleted from the middle rule.
- **Evidence:** logs/diagnostics_<run_id>.log between '=== YARA FILE ANALYSIS ===' and '=== END ANALYSIS ==='; Action Center action stderr for the 'BRACE MISMATCH DETECTED!' warning.
- **Negative control:** Two controls, both required. (a) On the balanced pack O == C exactly and 'BRACE MISMATCH DETECTED!' appears nowhere — neither in diagnostics_<run_id>.log nor on stderr; a warning that fires on every run tells an operator nothing. (b) A repeat run of the balanced pack with the cache warm (compile_source == "cache") must contain NO '=== YARA FILE ANALYSIS ===' line at all — that separates 'the analysis block is written on every fresh compile' from the untrue 'written on every run'.

### `RULE-068` Zero-valid-rules suppresses scheduled cleanup (diagnostic preservation)

*core*

- **Must be true:** A run that yields zero usable rules schedules NO cleanup unit and leaves its diagnostics on the host.
- **Threshold:** After the all-broken pack run: on xdr-agent, /etc/systemd/system/yara-cleanup.service does not exist and `systemctl list-unit-files 'yara-cleanup*'` returns no rows; on xdragent2, `schtasks /query /tn CleanupScript` reports the task cannot be found. <scanner_dir>/failed_rules/ contains one failed_rule_*.yar per broken rule (N of N) and logs/yara_processing_<run_id>.log is present with its FINAL_COMPILATION_ERROR line. Action Center stderr carries 'CRITICAL: YARA rule compilation failed:'.
- **Setup:** Round 3 delivery of a pack in which every rule is syntactically broken, on a host where no cleanup unit already exists (remove any left by an earlier run first).
- **Evidence:** `systemctl list-unit-files 'yara-cleanup*'` / `schtasks /query /tn CleanupScript`; `ls <scanner_dir>/failed_rules/`; logs/yara_processing_<run_id>.log 'FINAL_COMPILATION_ERROR:'; Action Center action stderr.
- **Negative control:** A healthy Round 3 run that produces at least one .txt in <scanner_dir>/alert MUST create the unit (yara-cleanup.service present / CleanupScript task present). Without that, the absence proves nothing — _check_for_alerts also suppresses scheduling on any run with no alerts at all.
- **Why this round:** Round 3 is the only round that submits a pack producing zero valid rules. Reachability finding, which is why the criterion is written against host state rather than the catalogued log line: 'Cleanup skipped due to critical YARA processing errors' in run() cannot be produced on any live run. Reaching that gate requires the YaraScanner object to have been constructed, which requires _compile_yara_rules to have returned; it only returns when valid_sources is non-empty, i.e. valid_rules_count >= 1, so has_critical_errors (has_errors AND valid_rules_count == 0) is always False there. With zero valid rules the ValueError is raised first and the run aborts. The customer promise still holds — via the abort — and that is what this criterion tests. CleanupManager.schedule_final_cleanup's own identical gate is likewise unreachable, being guarded by the same condition one call downstream.

### `RULE-069` yara-python match-API normalisation (libyara 3.x vs 4.x offset shim)

*core*

- **Must be true:** One rule against one byte-identical file yields identical offsets, string identifiers and rendered data on the libyara 3.x Linux agent and the 4.x Windows agent, and neither run shows the fallback sentinels.
- **Threshold:** On both endpoints, <scanner_dir>/alert/<rule>.txt for the planted file contains the same number of 'Offset: ' lines with the same offset values in the same order, an identical 'Hits per string ID: ' line, and zero lines reading 'Offset: -1' or 'String ID: unknown'. The matches rows for the two hosts have equal match_count and byte-identical `offsets` and `string_ids` JSON.
- **Setup:** Same planted file bytes and same pack delivered to xdr-agent (Linux, yara-python 3.11.0) and xdragent2 (Windows, 4.1.0). The rule must declare 2 string identifiers with several instances of each, so the 4.x StringMatch fan-out over `.instances[]` is actually exercised rather than the single-instance case.
- **Evidence:** <scanner_dir>/alert/<rule>.txt on both hosts; XQL `dataset = yara_scanner_matches_v3_* | filter rule = "<rule>" and filename contains "<planted>" | fields hostname, match_count, offsets, string_ids`.
- **Negative control:** The two endpoints must be confirmed to actually differ, or the comparison is vacuous: the `yara` field of <scanner_dir>/rule_cache/rules_*.yarac.meta.json on the two hosts must show different YARA_VERSION components (3.x vs 4.x). Equal engines would make identical output prove nothing about the shim.

### `RULE-070` Rule splitter is comment-blind, string-blind and case-insensitive

*core*

- **Must be true:** A single prose line whose first non-space token is the word 'rule' in any case starts a new rule unit wherever it appears — including INSIDE an existing rule's body. Placed between `rule R1 {` and its closing `}`, it truncates R1 at that line (R1's dump keeps the opening brace and loses the closing one) and keeps the bogus remainder as its own unit (which keeps the closing brace and has no opening one), so one stray line costs two rules.
- **Threshold:** Pack in which a block comment sits INSIDE R1's body — between `rule R1 {` and its closing `}` — with its middle line reading '   Rule Description: detects X', followed by a well-formed R2, and no rule authored broken. On a run with compile_source == "fresh": <scanner_dir>/failed_rules/failed_rule_R1.yar exists and its rule body has strictly MORE '{' than '}'; <scanner_dir>/failed_rules/failed_rule_Description.yar exists and its rule body has strictly more '}' than '{'; both carry the '// FAILED RULE - Compilation Error' header and the resolved preamble; scan_summary failed_rules == 2; logs/diagnostics_<run_id>.log 'Found N rule start positions' reads exactly one MORE than the number of authored `rule` declarations.
- **Setup:** Two Round 3 packs: the probe pack above, and a control identical except the prose line reads '   Detects: X'.
- **Evidence:** <scanner_dir>/failed_rules/failed_rule_R1.yar and failed_rule_Description.yar; logs/diagnostics_<run_id>.log lines 'Found N rule start positions' and 'Found N unique import statements'; `failed_rules` in logs/scan_summary_<run_id>.json.
- **Negative control:** A control pack identical in every way except that the same in-body comment line reads '   Detects: X' must give failed_rules == 0, no failed_rule_R1.yar and no failed_rule_Description.yar, and 'Found N rule start positions' equal to the authored declaration count. Keeping the comment and changing only its leading token is what attributes the split to the `rule` keyword rather than to the presence of a comment or to its position inside the rule body.
- **Why this round:** At the RULE prior. Worth flagging: the catalogue's 'UNOBSERVABLE: Found N rule start positions is a bare logging.info ... setup_logging pins to WARNING' is stale for this build. setup_logging now attaches a FileHandler at INFO for logs/diagnostics_<run_id>.log and sets the root logger to INFO, so that line — and the whole splitter trail — does land on disk. That is what upgrades this entry from a two-file inference to a directly counted assertion.

### `RULE-071` Duplicate rule names and overlapping scan targets split the books asymmetrically (one alert, two dataset rows)

*core*

- **Must be true:** Two rules sharing a name both compile and both fire on one file: the dataset gets two rows and the local counters count it twice, while the alert channel's (rule, filename) dedup collapses it to a single alert.
- **Threshold:** XQL for this scan_id grouped by (rule, filename) shows exactly 2 rows for ("Dup_Rule", <planted file>); the tenant shows exactly 1 alert named 'YARA Match: Dup_Rule | <basename> (#<tag>) | Host: <host>'; alert_delivery.findings counts that finding once; <scanner_dir>/alert/Dup_Rule.txt contains the block "YARA rule 'Dup_Rule' matched file: <path>" exactly twice; scan_summary `matches` exceeds the count of distinct (rule, file) findings by exactly 1 for this decoy.
- **Setup:** Round 3 pack with two rules both named `Dup_Rule` carrying different string sets, both matching one planted decoy. Separately, a second run with scan_folder set to two deliberately overlapping targets (e.g. '/opt/acc,/opt/acc/inner') and a uniquely-named rule, to reproduce the same asymmetry without duplicate names — target validation dedups only on exact absolute path, and track_real_paths is hard-coded False so no cross-target visited set exists.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" | comp count() by rule, filename`; alert_name search on the tenant for this host and scan window; <scanner_dir>/alert/Dup_Rule.txt; `matches` and `alert_delivery.findings` in logs/scan_summary_<run_id>.json.
- **Negative control:** A uniquely-named rule matching the same file in the same run must produce exactly 1 dataset row, 1 alert and 1 block in its .txt. Without it, 'two rows' is indistinguishable from a delivery path that double-writes every finding.
- **Why this round:** Stays at the RULE prior rather than moving to Round 2, even though the claim is about the delivery books that are Round 2's spine. Only Round 3's material — a duplicate-rule-name pack and deliberately overlapping scan targets — creates the divergence at all; Round 2's flood cannot produce it at any volume, because a flood of distinct (rule, file) findings never trips either the namespace-index case or the overlapping-target case.

### `RULE-072` Per-agent YARA/Python runtime banner in yara_processing_<run_id>.log — and its silent-failure mode

*supporting*

- **Must be true:** logs/yara_processing_<run_id>.log exists and opens with the runtime banner, and its YARA Version value agrees with the yara_version reported independently in the system log's init payload.
- **Threshold:** Within the first 8 physical lines of logs/yara_processing_<run_id>.log, in this order: a line ending '=== YARA Processing Log ===', a line containing 'Python Version: ', a line containing 'Platform: ', a line containing 'YARA Version: ', and a line whose message is a 50-character run of '=' (each carries the '[YYYY-MM-DD HH:MM:SS.mmm] [INFO] ' formatter prefix; sys.version may itself wrap onto a second line). The 'YARA Version:' value string-equals the `yara_version` value inside the data payload of the 'YARA Scanner initialized successfully' record in logs/system_<run_id>.log. The assertion is that equality on each host, not a fixed number (3.11.0 on xdr-agent, 4.1.0 on xdragent2).
- **Setup:** Standard Round 3 run on each of xdr-agent and xdragent2.
- **Evidence:** `head -5 <scanner_dir>/logs/yara_processing_<run_id>.log`; logs/system_<run_id>.log record 'YARA Scanner initialized successfully | data={..."yara_version":"..","python_version":"..","platform":".."}'.
- **Negative control:** The fallback must be shown NOT to have fired: yara_processing_<run_id>.log must be present and non-empty while system_<run_id>.log also exists, and Action Center action STDERR must contain no 'Failed to setup error logger: ' line — that print goes to sys.stderr, not stdout. That combination (file absent, system log present, that line on stderr) is the only signature of _setup_error_logger returning the bare root logger, and it must be ruled out before the banner assertion means anything.

### `RULE-073` Matched-byte rendering for human and wire output (UTF-16 wide → UTF-8 → hex)

*core*

- **Must be true:** The same rendering ladder is applied in both channels: a UTF-16LE wide hit renders as readable text, a non-printable hit renders as lowercase hex, and the alert file and the dataset row agree character for character.
- **Threshold:** Planted file carries the UTF-16LE encoding of 'PowerShellMarker' and a 16-byte non-printable blob. Wide hit: the 'Data: ' line in <scanner_dir>/alert/<rule>.txt reads exactly 'PowerShellMarker' with no interleaved NUL or '\x00' sequences, and the aligned element of the row's `strings` JSON array is the identical string. Binary hit: both the 'Data: ' line and the aligned `strings` element are the same 32-character string matching `^[0-9a-f]{32}$`.
- **Setup:** Round 3 crafted rule with `$w = "PowerShellMarker" wide` and `$b = { DE AD BE EF ... }` (16 non-printable bytes), matching one planted decoy that contains both.
- **Evidence:** 'Data: ' lines in <scanner_dir>/alert/<rule>.txt for the two string IDs; XQL `dataset = yara_scanner_matches_v3_* | filter scan_id = "<scan_id>" and rule = "<rule>" | fields offsets, strings, string_ids`.
- **Negative control:** The binary hit is the control for the wide branch and vice versa. If the UTF-16 detector fired unconditionally the binary hit would come back as mojibake instead of 32 hex characters; if it never fired the wide hit would come back as 'P.o.w.e.r...' or as hex. Both must hold in the same run, in both channels.

### `RULE-074` Post-compile rule-health telemetry, with a third success-rate denominator

*supporting*

- **Must be true:** The post-compile block is emitted whenever valid rules exist, and its compilation_success_rate denominator is valid + failed only — so a pack with skipped rules reports a rate that ignores them.
- **Threshold:** Fresh run of the mixed pack (V valid, F failed, S skipped, all > 0): logs/system_<run_id>.log carries 'Scanner initialized with V valid rules' with a data payload containing valid_rules_compiled == V, failed_rules_skipped == F and compilation_success_rate == V/(V+F)*100 to within 0.01 — and that value differs from V/(V+F+S)*100 by more than 0.5 percentage points; logs/scan_errors_<run_id>.log carries 'Skipped F failed rules'. On an all-skipped-but-some-valid variant (F == 0, S > 0): compilation_success_rate == 100.0 exactly while scan_summary skipped_rules == S.
- **Setup:** The RULE-050 mixed pack, fresh compile; plus a variant with no broken rules but several cuckoo-importing rules.
- **Evidence:** logs/system_<run_id>.log line 'Scanner initialized with N valid rules | data={"compilation_success_rate":..,"failed_rules_skipped":..,"valid_rules_compiled":..}'; logs/scan_errors_<run_id>.log line 'Skipped N failed rules'; `valid_rules`/`failed_rules`/`skipped_rules` in logs/scan_summary_<run_id>.json.
- **Negative control:** On a clean pack (F == 0 and S == 0) the 'Skipped N failed rules' line must be ABSENT from scan_errors_<run_id>.log — it is gated on failed_rules_count > 0 — while 'Scanner initialized with N valid rules' is still present in system_<run_id>.log with compilation_success_rate == 100.0.

## Scan Targeting, Traversal & Skipping

### `TRAV-001` Explicit scan scope via the scan_folder parameter (comma-separated multi-target)

*core*

- **Must be true:** A scan_folder other than the literal 'default' confines the run to exactly the listed targets, and every downstream artefact records the RAW comma-joined string — never a per-target path; a run with scan_folder left EMPTY (None) records the literal 'system' on its rows, while scan_folder='default' records 'default' verbatim. scan_folder is not an options-string key: passing it in the options string raises out of run() before any scan machinery exists, so the run produces no scan result line at all rather than a scan that silently ignores it.
- **Threshold:** Leg A (scan_folder='/opt/decoy_a,/opt/decoy_b'): system_<run_id>.log contains "SCAN SCOPE: Limited to specified targets: ['/opt/decoy_a', '/opt/decoy_b']" and 0 occurrences of 'SCAN SCOPE: Full system scan'; scan_summary_<run_id>.json "scan_folder" == '/opt/decoy_a,/opt/decoy_b' character-for-character (NOT a list, NOT a single path); 100% of paths on 'YARA matches found in ' lines in alerts_<run_id>.log are under one of the two; every yara_scanner_matches_v3_* row for this run_id carries scan_folder == that same raw string, 0 rows carrying a single target path. Leg B1 (scan_folder left EMPTY/None): every yara_scanner_scans_v3_* row for that run_id carries scan_folder == 'system'. Leg B2 (scan_folder='default'): every yara_scanner_scans_v3_* row carries scan_folder == 'default' (NOT 'system' — the `or` fallback only fires on a falsy value). Leg C (options='scan_folder=/opt/decoy_a', run over SSH as `python3 xdr_yara_scanner.py <rules> "" low "" scan_folder=/opt/decoy_a`): exit code == 1; stderr contains "Critical startup error: Unknown option 'scan_folder'. Valid keys:" followed by the sorted 10-key list; stdout contains ZERO occurrences of 'SCAN_RESULT:' and zero occurrences of 'Scan failed:'; no logs/scan_summary_*.json and no logs/yara_processing_*.log are created for this invocation (ScanConfig is never entered).
- **Setup:** Plant /opt/decoy_a and /opt/decoy_b on xdr-agent, each with exactly one file carrying a unique rule marker. Three legs as above; Leg B may be cancelled via control/cancel.flag once the 'Scan configuration established' entry lands.
- **Evidence:** logs/system_<run_id>.log 'SCAN SCOPE: Limited to specified targets:' vs 'SCAN SCOPE: Full system scan (light profile throttling enabled)'; "scan_folder" in logs/scan_summary_<run_id>.json; logs/alerts_<run_id>.log 'YARA matches found in <path>'; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields scan_folder, filename`; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields scan_folder`; Leg C: process exit status plus stderr/stdout of the direct CLI invocation.

### `TRAV-002` Per-target directory validation with partial-failure tolerance

*supporting*

- **Must be true:** An entry that fails os.path.isdir is named in a warning and dropped, while every valid sibling in the same comma list is still walked and still reports its findings — one typo does not kill the run.
- **Threshold:** scan_folder='/opt/decoy_a,/opt/does_not_exist,/opt/decoy_b': yara_processing_<run_id>.log contains exactly one line "Ignoring 1 specified scan folder(s) that are not valid directories on this endpoint: ['/opt/does_not_exist']", immediately followed by "Scan limited to 2 folder(s): ['/opt/decoy_a', '/opt/decoy_b']"; scan_summary_<run_id>.json "outcome" == 'completed' and "matches" == 2.
- **Setup:** Same two planted decoys as TRAV-001 plus one deliberately non-existent path in the middle of the list.
- **Evidence:** logs/yara_processing_<run_id>.log 'Ignoring N specified scan folder(s) that are not valid directories on this endpoint:' and 'Scan limited to N folder(s):' (ErrorLogger owns its own INFO FileHandler with propagate=False, so both land on disk); "outcome" and "matches" in logs/scan_summary_<run_id>.json.
- **Negative control:** Both valid siblings must still be scanned: each decoy's marker file appears in alert/<rule>.txt and produces its own yara_scanner_matches_v3_* row. A control leg in which all three entries are valid directories must produce 0 occurrences of 'Ignoring' in yara_processing_<run_id>.log.

### `TRAV-003` Hard failure when no requested scan folder is a valid directory

*core*

- **Must be true:** When no comma-separated entry passes the isdir test the constructor raises before any walk begins: no scan_summary JSON is produced at all, the returned result line is the generic critical-error line that does NOT name the bad folder, and the reason appears only on stderr/stdout — not in yara_processing_<run_id>.log, which exists but never learns it.
- **Threshold:** Run over SSH as `python3 xdr_yara_scanner.py <rules> '/opt/nope,/srv/also-nope'`. Process exits with status 1 within 30s (the except path sleeps 2s at line 7907). stdout contains the line 'SCAN_RESULT: Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred'. stderr contains both 'SCAN_STATUS: ERROR' and "Critical scanner error: No valid scan directory among the specified scan folder(s): ['/opt/nope', '/srv/also-nope']". Recover run_id from the one artefact that names it: exactly one NEW logs/yara_processing_<run_id>.log exists, and it contains 0 occurrences of 'No valid scan directory'. For that same run_id: logs/scan_summary_<run_id>.json does NOT exist, logs/system_<run_id>.log does NOT exist, logs/statistics_<run_id>.log does NOT exist and logs/diagnostics_<run_id>.log does NOT exist (LogManager and setup_logging are both downstream of the raise). alert/ contains no .txt file that was absent before the leg (initial_cleanup, which wipes alert/, is never reached).
- **Setup:** Short round-3 leg on xdr-agent with two non-existent paths.
- **Evidence:** stdout 'SCAN_RESULT: Scan failed: ... Critical error occurred' and process exit status; stderr 'YARA Scanner Critical Error: Critical scanner error: No valid scan directory among the specified scan folder(s):' and 'SCAN_STATUS: ERROR'; directory listing of <scanner_dir>/logs/ before and after the leg (only yara_processing_<run_id>.log is added); presence-but-silence of logs/yara_processing_<run_id>.log; before/after listing of <scanner_dir>/alert/.
- **Negative control:** A list containing ONE valid directory among the same invalid entries must NOT abort: it produces a scan_summary_<run_id>.json with outcome == 'completed' and scans the valid target. This separates 'aborts when nothing is valid' from 'aborts whenever anything is invalid'.

### `TRAV-004` Scan-target quote stripping and whitespace trimming

*supporting*

- **Must be true:** Leading/trailing whitespace and one layer of surrounding single or double quotes are stripped from each comma entry, and empty entries are dropped, so a pasted quoted list resolves to real directories instead of falling into the invalid-folder warning.
- **Threshold:** scan_folder = ` "/opt/decoy_a" , '/opt/decoy b' ,, ` produces in yara_processing_<run_id>.log the line ending exactly `Scan limited to 2 folder(s): ['/opt/decoy_a', '/opt/decoy b']` — asserted as a whole-string match, not by counting quote characters (the list repr legitimately quotes each element); the count is 2, not 3, so both empty entries were dropped; and yara_processing_<run_id>.log contains 0 occurrences of 'Ignoring'. scan_summary_<run_id>.json "matches" == 2. Order matters and must be pinned: whitespace is stripped before quotes, so a control entry ` " /opt/decoy_a " ` (padding INSIDE the quotes) must be reported in the 'Ignoring 1 specified scan folder(s)' warning — it is not a valid directory after cleaning.
- **Setup:** Plant /opt/decoy_a and '/opt/decoy b' (name containing a space) on xdr-agent, each with one marker file; pass the list with mixed quoting, padding whitespace and one empty entry.
- **Evidence:** logs/yara_processing_<run_id>.log 'Scan limited to N folder(s):' (cleaned absolute paths) and absence of 'Ignoring N specified scan folder(s) that are not valid directories on this endpoint:'; "matches" in logs/scan_summary_<run_id>.json.
- **Negative control:** Inner whitespace must survive: '/opt/decoy b' appears in the 'Scan limited to' line with its space intact and is NOT named in the 'Ignoring ...' warning — a stripper that trimmed all whitespace rather than only the ends would push it into that warning. Plus the ordering control above: ` " /opt/decoy_a " ` MUST land in the Ignoring warning, which separates 'strips ends then quotes' from 'strips quotes then ends'.

### `TRAV-005` Scan-target de-duplication and absolute-path normalisation

*supporting*

- **Must be true:** Entries that normalise to the same absolute path collapse to a single target, so a directory named three ways is walked once and its findings are not multiplied.
- **Threshold:** scan_folder='/opt/decoy_a,/opt/decoy_a/,/opt/decoy_a/./': yara_processing_<run_id>.log shows "Scan limited to 1 folder(s): ['/opt/decoy_a']"; 'Scan configuration established' data 'target_count' == 1 and 'targets' == ['/opt/decoy_a']; exactly one 'Scanning target 1/1: /opt/decoy_a' line; exactly 1 yara_scanner_matches_v3_* row for the single planted marker file.
- **Setup:** Plant /opt/decoy_a with exactly one marker file; pass it three times in three spellings that abspath collapses.
- **Evidence:** logs/yara_processing_<run_id>.log 'Scan limited to N folder(s):'; logs/statistics_<run_id>.log 'Scan configuration established' data keys 'targets'/'target_count'; logs/system_<run_id>.log 'Scanning target i/N:' lines; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | count`.
- **Negative control:** Two genuinely distinct directories must NOT collapse: scan_folder='/opt/decoy_a,/opt/decoy_b' yields target_count == 2, two 'Scanning target i/2' lines and 2 match rows. Dedup is by os.path.abspath only (no normcase), so do not expect case variants to collapse on Windows.

### `TRAV-006` "default" sentinel selects full default-scope discovery

*supporting*

- **Must be true:** Only the exact literal 'default' (case-insensitively) selects full-scope discovery; the raw operator string is still preserved verbatim in the summary even when the sentinel fires.
- **Threshold:** Leg A (scan_folder='DEFAULT', upper case): system_<run_id>.log contains 'SCAN SCOPE: Full system scan (light profile throttling enabled)' and 0 occurrences of 'SCAN SCOPE: Limited to specified targets'; yara_processing_<run_id>.log contains 'Scanning default targets: [' and 0 occurrences of 'Scan limited to'; scan_summary_<run_id>.json "scan_folder" == 'DEFAULT' (raw value, not normalised).
- **Setup:** Two short legs on xdr-agent, both cancelled via control/cancel.flag once 'Scan configuration established' lands. Leg B needs a real directory literally named /opt/default_decoy holding one marker file.
- **Evidence:** logs/system_<run_id>.log 'SCAN SCOPE: ...'; logs/yara_processing_<run_id>.log 'Scanning default targets:' vs 'Scan limited to N folder(s):'; "scan_folder" in logs/scan_summary_<run_id>.json.
- **Negative control:** Leg B (scan_folder='/opt/default_decoy' — a real directory whose name merely BEGINS with 'default'), run to completion with NO cancel flag, must take the LIMITED branch: yara_processing_<run_id>.log contains "Scan limited to 1 folder(s): ['/opt/default_decoy']" and 0 occurrences of 'Scanning default targets'; system_<run_id>.log contains 'SCAN SCOPE: Limited to specified targets' and 0 occurrences of 'SCAN SCOPE: Full system scan'; scan_summary_<run_id>.json "matches" == 1 and "scan_folder" == '/opt/default_decoy'. A prefix or substring test rather than the equality test at line 3139 would send this leg to whole-filesystem discovery. Only Leg A (scan_folder='DEFAULT') is cancelled via control/cancel.flag once 'Scan configuration established' lands.

### `TRAV-007` Config-time warning that a requested target sits under a platform skip path (case-blind, so mostly dormant on Windows and macOS)

*supporting*

- **Must be true:** The config-time skip-path warning fires on Linux, where lin_skip_directory is case-preserved, and is silent on Windows for a genuinely-excluded target because win_skip_folder is lower-cased at construction while the probe path from os.path.abspath is not — yet the run still names that target as excluded on the result line and in the summary, because the runtime check in _is_special_file lower-cases both sides.
- **Threshold:** Linux leg (scan_folder='/proc,/opt/decoy_a'): yara_processing_<run_id>.log contains exactly one line "1 of 2 scan folder(s) sit under a platform skip-path and will yield no files: /proc (excluded by '/proc/')". Windows leg (scan_folder='C:\ProgramData\Cyvera'): 0 occurrences of 'sit under a platform skip-path' in yara_processing_<run_id>.log, while scan_summary_<run_id>.json "excluded_targets" == ['C:\\ProgramData\\Cyvera'] and the returned line contains 'WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned:'.
- **Setup:** Linux leg on xdr-agent with /opt/decoy_a planted; Windows leg on xdragent2 against the real agent directory C:\ProgramData\Cyvera (a win_skip_folder entry).
- **Evidence:** logs/yara_processing_<run_id>.log 'N of M scan folder(s) sit under a platform skip-path and will yield no files:' and 'EVERY requested scan folder is excluded by the platform skip-list'; "excluded_targets" in logs/scan_summary_<run_id>.json; the returned SCAN_RESULT line's 'WARNING: N requested target(s) EXCLUDED by the skip list' clause; logs/scan_errors_<run_id>.log 'Requested scan target is excluded by the skip list, so nothing under it will be scanned:'.
- **Negative control:** /opt/decoy_a in the same Linux list must NOT be named in the warning, and 'EVERY requested scan folder is excluded by the platform skip-list' must be absent from that leg (0 occurrences) while a '/proc'-only Linux leg does emit it exactly once. Otherwise the warning is indistinguishable from one that fires on every target.

### `TRAV-009` Windows default scope = every logical drive returned to this process  <sub>windows</sub>

*supporting*

- **Must be true:** On Windows with scan_folder='default' the discovered target set is exactly the filesystem drive roots visible to the process, each terminated with a backslash, and the same list appears identically in all three artefacts that report it.
- **Threshold:** yara_processing_<run_id>.log "Light profile full-scope targets on Windows: [...]" list equals, as a set, the output of `Get-PSDrive -PSProvider FileSystem | ? {$_.Root -match '^[A-Za-z]:\\$' -and (Test-Path $_.Root)} | % Root` executed IN THE SAME SECURITY CONTEXT as the payload (i.e. delivered through Action Center as a second script, not typed into an RDP session), because drive-letter visibility is per-logon-session; every entry ends with '\'; 'Scan configuration established' data 'target_count' == len(list) and 'targets' == that list; the 'YARA Scanner initialization completed' system entry's data 'scan_targets' (init_data key, line 7648) == that same list.
- **Setup:** Short leg on xdragent2 with scan_folder='default' and a rule pack that cannot match (a 64-byte random string), cancelled by writing <scanner_dir>\control\cancel.flag as soon as 'Scan configuration established' lands — the discovery line is written inside ScanConfig.__init__, seconds in, so a full C:\ walk is not needed.
- **Evidence:** logs\yara_processing_<run_id>.log 'Light profile full-scope targets on Windows:'; logs\statistics_<run_id>.log 'Scan configuration established' data 'targets'/'target_count'; logs\system_<run_id>.log 'YARA Scanner initialization completed' data 'scan_targets'.
- **Negative control:** Discovery must track the machine, not a constant: attach a second volume to xdragent2 (a GCE persistent disk mounted as D:) and re-run the same leg. 'Light profile full-scope targets on Windows:' must then list BOTH 'C:\' and 'D:\', target_count == 2, and both appear in init_data 'scan_targets'. Without this, a single-drive assertion of ['C:\'] is indistinguishable from the hardcoded ['C:\'] last-resort rung at line 3243.
- **Why this round:** Round 3 per ROUNDS.md, which assigns scan-target resolution and its fallback ladder to Round 3. Round 1's clean scan also runs default scope, but the sharp test here is the platform/privilege matrix, and a short cancelled leg reaches the artefact without paying for a whole-drive walk.

### `TRAV-010` Windows drive-root de-duplication via normcase  <sub>windows</sub>

*supporting*

- **Must be true:** A drive found by BOTH discovery passes (psutil.disk_partitions and kernel32.GetLogicalDrives) appears exactly once in the target list — target_count is the number of distinct drives, not the sum of the two passes.
- **Threshold:** 'Scan configuration established' data 'target_count' equals the number of distinct filesystem drive roots on the box; no two entries in 'targets' are equal under os.path.normcase(os.path.normpath(...)); on a single-drive xdragent2 target_count == 1 (not 2), even though both passes independently return C:\.
- **Setup:** The same short cancelled Windows leg as TRAV-009.
- **Evidence:** logs\statistics_<run_id>.log 'Scan configuration established' data 'targets' and 'target_count'; cross-check against `Get-PSDrive -PSProvider FileSystem`.
- **Negative control:** Distinct drives must NOT be collapsed: run the same leg on a Windows box (or after attaching a second volume) with C: and D: present — target_count must be 2 and both roots must appear. Otherwise a dedup that collapsed everything to one entry passes the single-drive assertion.
- **Why this round:** Round 3, same reasoning as TRAV-009.

### `TRAV-012` Linux default scope depends on effective UID (root = whole filesystem)  <sub>linux</sub>

*supporting*

- **Must be true:** The default Linux scope matches the run's effective UID exactly: '/' alone as root, otherwise only the readable subset of the five probe roots — and exactly one of the three branch lines is written per run.
- **Threshold:** Precondition for the non-root leg: export YARA_SCANNER_DIR to a path the unprivileged user owns (e.g. /home/<user>/yara_probe) — ScanConfig's unguarded os.makedirs at lines 2869-2871 otherwise raises before ErrorLogger exists and no yara_processing log is written at all. Root leg (Action Center delivery on xdr-agent, default scanner_dir): yara_processing_<run_id>.log contains 'Light profile default scope on Linux: full filesystem' exactly once and the other two branch lines 0 times; 'Scan configuration established' data 'targets' == ['/'] with target_count == 1; system_<run_id>.log contains 'Running as: root on Linux'. Non-root leg (SSH as an unprivileged user, YARA_SCANNER_DIR set as above, `id -u` captured in the same session): 'Light profile default scope on Linux using accessible full-scan targets: [...]' appears exactly once and the other two branch lines 0 times; 'targets' is a non-empty subset of ['/home','/tmp','/opt','/usr/local','/var/tmp']; every entry independently passes `test -r` as that user and every one of the five that passes `test -r` appears (the filter is exists AND isdir AND R_OK, so the list must be the complete accessible subset, not merely a subset); no path outside those five appears; system_<run_id>.log contains 'Running as: non-root user on Linux'.
- **Setup:** Same scan_folder='default' leg twice on xdr-agent: once via Action Center (root) and once over SSH as an unprivileged user, with `id -u` captured in the same session. Both may be cancelled via control/cancel.flag once 'Scan configuration established' lands.
- **Evidence:** logs/yara_processing_<run_id>.log 'Light profile default scope on Linux: full filesystem' | 'Light profile default scope on Linux using accessible full-scan targets:' | "Light profile default scope fell back to '/' on Linux - many files may be inaccessible"; logs/system_<run_id>.log 'Running as: root on Linux' / 'Running as: non-root user on Linux'; logs/statistics_<run_id>.log 'Scan configuration established' data 'targets'.
- **Why this round:** Round 3 per ROUNDS.md's explicit assignment of scan-target resolution to Round 3; the privilege matrix (two UIDs, same host) is a crafted comparison, not a load property.

### `TRAV-013` Linux non-root fallback to '/' when no probe target is readable  <sub>linux</sub>

*low*

- **Must be true:** When none of the five probe roots is a readable directory, the non-root Linux branch falls back to ['/'] and says so with a WARNING, rather than returning an empty target list and scanning nothing.
- **Threshold:** yara_processing_<run_id>.log contains "Light profile default scope fell back to '/' on Linux - many files may be inaccessible" exactly once and 'Light profile default scope on Linux using accessible full-scan targets:' 0 times; 'Scan configuration established' data 'targets' == ['/'] with target_count == 1. Let the run scan for at least 120s before writing control/cancel.flag (NOT at config time) so the walk actually produces counters: scan_summary_<run_id>.json "outcome" == 'cancelled' (never 'failed'), "files_scanned" > 0, and the 'Skip reasons:' statistics entry exists with skip_breakdown['No read permission'] > 0 — that entry is gated on files_skipped > 0 (line 6903) and is absent entirely on a run cancelled before any file is skipped.
- **Setup:** On xdr-agent, as root: `unshare -m --propagation private` then bind-mount a mode-000 directory over each of /home, /tmp, /opt, /usr/local and /var/tmp that exists, set YARA_SCANNER_DIR to a path outside all five (e.g. /var/lib/yara_probe) so the scanner can still write its own tree, then drop to an unprivileged UID with setpriv and run scan_folder='default'. The namespace is private, so the host outside it is unaffected; exiting the shell restores everything. Cancel via control/cancel.flag once 'Scan configuration established' lands.
- **Evidence:** logs/yara_processing_<run_id>.log "Light profile default scope fell back to '/' on Linux - many files may be inaccessible"; logs/statistics_<run_id>.log 'Scan configuration established' data 'targets'; the 'Skip reasons:' statistics entry data 'skip_breakdown' key 'No read permission' (scan_file's os.access gate — distinct from 'Permission denied', which is a PermissionError out of rules.match).
- **Negative control:** Outside the namespace, the same non-root user on the same host must take the accessible-targets branch instead: 'Light profile default scope on Linux using accessible full-scan targets:' present, the fallback WARNING absent. This separates 'falls back when nothing is readable' from 'always falls back'.
- **Why this round:** Round 3: it is a crafted-environment probe of the resolution ladder, not a resource-discipline measurement, and the setup is destructive to the process's own view of the filesystem — incompatible with Round 1's stop-on-fail baseline run.

### `TRAV-017` Runtime scan-target fallback ladder (_get_scan_targets)

*supporting*

- **Must be true:** On every supported platform the first rung is the one that fires: exactly one 'Using configured scan targets:' line is written to the diagnostics log per run, neither fallback rung is ever taken, and the list on that line is element-for-element equal (same order, same strings) to 'targets' in the 'Scan configuration established' statistics entry — so a run can never silently escalate from a requested folder to a whole-machine walk.
- **Threshold:** For every round-3 leg, in logs/diagnostics_<run_id>.log: count('Using configured scan targets:') == 1, count('Using default Windows targets:') == 0, count('Using default Unix target:') == 0. Parse the Python list repr on that line (f-string, single-quoted elements) and the JSON array under 'targets' in the 'Scan configuration established' data blob (json.dumps, double-quoted) and assert they are EQUAL AS ORDERED LISTS OF STRINGS — not byte-identical; the two serialisers differ by construction. Criterion is void — not passed — if stderr carries 'Diagnostics log unavailable (', the one case in which setup_logging drops the root logger to WARNING and all three lines vanish; assert 0 occurrences of that string.
- **Setup:** None beyond the standard round-3 legs — this is asserted on every one of them, including the scan_folder='default' legs, because ScanConfig always populates config.scan_targets on Windows, Linux and macOS.
- **Evidence:** logs/diagnostics_<run_id>.log 'Using configured scan targets: {targets}' / 'Using default Windows targets: {targets}' / "Using default Unix target: ['/']"; logs/statistics_<run_id>.log 'Scan configuration established' data 'targets'; stderr 'Diagnostics log unavailable ('.
- **Negative control:** The negative half IS the criterion: the two fallback rungs must produce zero lines. A build in which config.scan_targets came back empty or unset would take rung 2 or 3 and walk the whole machine while the operator asked for one folder — the exact failure this catches. The rungs themselves are reachable only in the unknown-platform state of TRAV-016, which no available endpoint can produce.

### `TRAV-018` Non-root system-path advisory for requested targets  <sub>linux, darwin</sub>

*supporting*

- **Must be true:** A non-root POSIX run whose requested scan_folder begins with a privileged system root emits the advisory through log_system (so it lands in the system log at INFO, not in the error log, despite reading 'ERROR:') and still proceeds to scan rather than aborting.
- **Threshold:** Precondition for every non-root leg: export YARA_SCANNER_DIR to a path that user owns; ScanConfig's unguarded os.makedirs at line 2869 otherwise raises before LogManager is constructed and no system_<run_id>.log is written. Non-root SSH leg on xdr-agent with scan_folder='/etc': system_<run_id>.log contains 'ERROR: System path scan requires elevated privileges' and 'Either run as root or choose a different scan path', each exactly once; scan_errors_<run_id>.log contains 0 occurrences of either string; scan_summary_<run_id>.json "outcome" == 'completed' with "files_scanned" > 0. Root control leg, same target, delivered via Action Center: 0 occurrences of the advisory in system_<run_id>.log (the whole block is inside `if not is_root`). macOS leg on OfficeiMac as the console user with scan_folder='/Library': 'ERROR: System path scan requires elevated privileges' plus 'Either run as root (sudo) or grant Full Disk Access', each exactly once.
- **Setup:** SSH into xdr-agent as an unprivileged user and run with scan_folder='/etc'; repeat via Action Center as root. On OfficeiMac run as the console user with scan_folder='/Library'. Note the check reads the RAW scan_folder string (split on commas, quotes stripped), not the resolved targets.
- **Evidence:** logs/system_<run_id>.log 'ERROR: System path scan requires elevated privileges', 'Either run as root or choose a different scan path', 'Either run as root (sudo) or grant Full Disk Access'; absence of those strings in logs/scan_errors_<run_id>.log; "outcome" and "files_scanned" in logs/scan_summary_<run_id>.json.
- **Negative control:** A non-root leg on the same host with scan_folder='/opt/decoy_a' (not under /etc, /boot, /var/log or /root) must emit 0 occurrences of the advisory. Without this, an advisory that fired on every non-root run would be indistinguishable from one that correctly matched the privileged roots.

### `TRAV-019` Cancellable directory walk (_walk_cancellable) replacing os.walk

*core*

- **Must be true:** A cancel flag written mid-walk is honoured within a single scandir: the process reaches a terminal state promptly, the run is reported as cancelled rather than completed, and the terminal lifecycle row names the cancel source.
- **Threshold:** From the log timestamps, not from process exit: (1) system_<run_id>.log 'Cancellation requested (source=action_center)' timestamp minus the control/cancel.flag mtime <= 7s (CANCEL_POLL_SECS defaults to 5, line 393). (2) THE REGRESSION BAR: the 'Target scan completed: <target>' statistics entry — written immediately after the walk generator returns — timestamp minus the 'Cancellation requested (source=' timestamp <= 10s, and system_<run_id>.log '=== ENHANCED CLEANUP AND FINALIZATION ===' lands within 12s of it; the behaviour this replaced left ~50s of walk after the cancel. (3) scan_summary_<run_id>.json "outcome" == 'cancelled' and "cancel_source" == 'action_center'; "files_scanned" strictly less than the true regular-file count under the target. (4) The returned line begins 'Scan cancelled by operator:' and does NOT begin 'Scan completed'. (5) Exactly one yara_scanner_scans_v3_* row for this run_id with status == 'cancelled' and message == 'cancelled by operator (source=action_center)'; its event_timestamp_ms is within 60000 ms of the cancel.flag mtime (it is emitted after up to max_workers x 5s of joins plus a 2s heartbeat join). (6) Process exit within 300s of the flag write — bounded by the uploader drain budgets, not by the walk.
- **Setup:** Long round-3 leg on xdr-agent over a big real tree. At ~60s in, write <scanner_dir>/control/cancel.flag over SSH; capture `date +%s.%N` immediately before the write and again when the payload PID disappears from `ps`. Do NOT use the console Cancel button — it hard-kills the payload and orphans the lifecycle row, which is a different failure mode entirely.
- **Evidence:** Wall time between the control/cancel.flag write and process exit; "outcome", "cancel_source" and "duration_secs" in logs/scan_summary_<run_id>.json; logs/system_<run_id>.log 'Cancellation requested (source=' and 'Scan cancelled by operator (source='; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "cancelled" | fields message, event_timestamp_ms`; mtime of <scanner_dir>/control/cancel.flag.
- **Negative control:** An identical uncancelled twin leg over the same tree must complete: scan_summary "outcome" == 'completed', "cancel_source" null, "files_scanned" == the full regular-file count, the returned line begins 'Scan completed:', and exactly one yara_scanner_scans_v3_* row with status == 'completed' and message == 'scan completed'. Without it, 'cancelled promptly' is indistinguishable from a scan that died or found nothing to walk.

### `TRAV-020` Symlinked directories are enumerated but never descended into

*supporting*

- **Must be true:** A directory symlink is listed in dirnames (so os.walk's topdown contract is preserved) but never pushed onto the traversal stack, so its contents are neither scanned through the link nor able to form a traversal loop.
- **Threshold:** With /opt/decoy_real/hit.bin holding a unique rule marker, /opt/decoy_scope/link -> /opt/decoy_real and the self-referential /opt/decoy_scope/loop -> /opt/decoy_scope, scanning scan_folder='/opt/decoy_scope': alert/<rule>.txt does not exist (0 alert entries); alerts_<run_id>.log contains 0 'YARA matches found in' lines; scan_summary_<run_id>.json "matches" == 0; the 'Target scan completed: /opt/decoy_scope' statistics entry is emitted with scan_time_seconds < 30 (the loop causes no hang) and files_found equal to the number of real regular files directly under /opt/decoy_scope.
- **Setup:** Plant the three paths above on xdr-agent, then run two legs: scan_folder='/opt/decoy_scope' and scan_folder='/opt/decoy_real,/opt/decoy_scope'.
- **Evidence:** Existence/contents of <scanner_dir>/alert/<rule>.txt; logs/alerts_<run_id>.log 'YARA matches found in <path>'; "matches" and "files_scanned" in logs/scan_summary_<run_id>.json; logs/statistics_<run_id>.log 'Target scan completed: /opt/decoy_scope' data 'files_found'/'scan_time_seconds'.
- **Negative control:** The second leg (scan_folder='/opt/decoy_real,/opt/decoy_scope') must produce exactly 1 alert entry, and its path must be '/opt/decoy_real/hit.bin' — never '/opt/decoy_scope/link/hit.bin'. This proves the marker file is matchable and that only the traversal THROUGH the link is refused, not the file itself.

### `TRAV-021` Traversal error tolerance (per-entry and per-directory)

*supporting*

- **Must be true:** Both tolerance arms are silent by design: a scandir entry whose is_dir() raises OSError is dropped outright (XDR's arm does `continue` — it does NOT demote the entry to a file), and a directory whose os.scandir raises is abandoned with its subtree. Neither increments any skip counter, so files_scanned + files_skipped is strictly less than the true file count with no skip_breakdown key explaining the gap — and the scan still completes.
- **Threshold:** Precondition: export YARA_SCANNER_DIR to a path the unprivileged user owns (ScanConfig's os.makedirs at line 2869 otherwise raises). Non-root leg on xdr-agent with scan_folder='/opt/decoy_scope', where /opt/decoy_scope/blocked is mode 000 and holds exactly 5 regular files and /opt/decoy_scope/entry is a symlink to /opt/decoy_scope/blocked/inner (so entry.is_dir() raises PermissionError, caught by the bare `except OSError: continue` at line 6237): scan_summary_<run_id>.json "outcome" == 'completed'; "files_scanned" == (`find /opt/decoy_scope -type f | wc -l` counted as root) minus exactly 5; "files_skipped" == 0; and logs/statistics_<run_id>.log contains ZERO 'Skip reasons:' entries — the entry is gated on files_skipped > 0, so its absence is the proof that neither tolerance arm touched a counter. Root control leg over the identical tree: "files_scanned" higher by exactly 5, "files_skipped" == 0, and likewise zero 'Skip reasons:' entries.
- **Setup:** On xdr-agent as root: `mkdir -p /opt/decoy_scope/blocked/inner`, place 5 files in /opt/decoy_scope/blocked, `chmod 000 /opt/decoy_scope/blocked`, `ln -s /opt/decoy_scope/blocked/inner /opt/decoy_scope/entry`. Run the leg over SSH as an unprivileged user (root bypasses the permission check entirely).
- **Evidence:** "outcome", "files_scanned", "files_skipped" in logs/scan_summary_<run_id>.json; logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' (the human-readable line truncates to the first 5 reasons — read the data dict); `find /opt/decoy_scope -type f | wc -l` executed as root over SSH.
- **Negative control:** The root control leg over the identical tree must scan those same 5 files — files_scanned higher by exactly 5 — while both legs show files_skipped == 0 and no 'Skip reasons:' entry. This proves the shortfall is the unreadable directory and that it was never booked as a skip; 'it tolerated an error' and 'it silently drops files' are otherwise indistinguishable, and a build that DID count them would emit a 'Skip reasons:' entry on the non-root leg.

### `TRAV-022` Caller-side dirnames pruning is honoured

*supporting*

- **Must be true:** A name removed from `dirnames` by the caller between the yield and the stack extension is genuinely never descended into — the generator reads dirnames AFTER the yield, so scan_system's junction filter actually prunes the subtree rather than being silently discarded.
- **Threshold:** On Windows with C:\decoy_scope\My Documents created as a directory junction to C:\decoy_real (junction name contains a problematic-junction substring) and C:\decoy_real\hit.bin holding a unique rule marker, scanning scan_folder='C:\decoy_scope': alert\<rule>.txt contains 0 entries whose path is under 'C:\decoy_scope\My Documents'; 0 yara_scanner_matches_v3_* rows for this run_id with a filename under that junction.
- **Setup:** On xdragent2 as Administrator: `mkdir C:\decoy_real`, plant hit.bin with a unique marker, `mklink /J "C:\decoy_scope\My Documents" C:\decoy_real` and `mklink /J C:\decoy_scope\plain_junction C:\decoy_real`. Windows is the only platform where this is decidable: a junction is a reparse point but NOT a symlink, so entry.is_symlink() is False and _walk_cancellable would descend into it — the caller-side prune is the only thing that stops it. On POSIX the generator already refuses symlinked directories, so pruning there changes no outcome.
- **Evidence:** <scanner_dir>\alert\<rule>.txt entry paths; logs\alerts_<run_id>.log 'YARA matches found in <path>'; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields filename`. Directory-level pruning is counted NOWHERE — 'junction_skips' in the final metrics counts file-level skips only — so a count-based test cannot decide this; the path set is the only evidence.
- **Negative control:** C:\decoy_scope\plain_junction, a junction whose name matches none of the six problematic substrings, must NOT be pruned: hit.bin must appear in alert\<rule>.txt with a path under 'C:\decoy_scope\plain_junction'. Without this, a generator that ignored pruning and a generator that descended into nothing both look the same.

### `TRAV-023` Junction/symlink directory pruning during the walk

*supporting*

- **Must be true:** _should_skip_junction is applied at two grains but counted at only one: file-level redirection skips increment junction_skips and the 'Junction/symlink skip' skip_breakdown key one-for-one, while directory-level pruning increments nothing at all — its only trace is the absence of the pruned subtree's files from the results.
- **Threshold:** Capture the ground truth on the box immediately after the scan: N = `find /tmp -type l ! -xtype d | wc -l` (directory symlinks are pruned by the dirs filter at line 7148 and increment NOTHING, so they must be excluded from the count). Then: final-metrics 'junction_skips' == N and skip_breakdown['Junction/symlink skip'] == N, the two exactly equal to each other; N >= 3 and N minus the pre-plant baseline (`find /tmp -type l ! -xtype d | wc -l` taken before planting) == 3; 'path_deduplication_ratio' == junction_skips / max(files_scanned + files_skipped, 1) * 100 to within 0.01 (the code floors the denominator at 1, line 6872); the Windows leg of TRAV-022 shows 'junction_skips' unchanged by the pruned junction directory, whose files contribute 0 to every skip_breakdown key.
- **Setup:** On OfficeiMac plant /opt/decoy_real/hit.bin with a unique marker, the three symlinks and the real copy under /tmp, then run scan_folder='/tmp'. /tmp is walked on macOS — only '/private/tmp/' is in mac_skip_directory — and _should_skip_junction's Darwin arm returns True for any symlink whose path starts with /etc, /tmp or /var.
- **Evidence:** logs/statistics_<run_id>.log final-metrics entry ('SCAN COMPLETED | ...') data keys 'junction_skips' and 'path_deduplication_ratio'; the 'Skip reasons:' entry data 'skip_breakdown' key 'Junction/symlink skip'; <scanner_dir>/alert/<rule>.txt for the surviving real copy.
- **Negative control:** The byte-identical non-symlinked sibling /tmp/hit_real.bin must be scanned normally: it appears in alert/<rule>.txt, contributes to files_scanned, and does NOT increment junction_skips. Additionally plant a fourth symlink OUTSIDE the Darwin prefix set — /opt/decoy_real/dl4 -> /opt/decoy_real/hit.bin, scanned in a second leg with scan_folder='/opt/decoy_real' — which must be SCANNED (it produces an alert entry) and must NOT increment junction_skips, since the Darwin arm keys on the /etc, /tmp, /var prefixes only. Without both, junction_skips == N is indistinguishable from a predicate that skips every symlink everywhere or every file under /tmp.

### `TRAV-024` Skip lists do NOT prune traversal — excluded subtrees are still fully enumerated

*supporting*

- **Must be true:** A skip-listed directory is still fully walked: every file beneath it is counted into skip_breakdown['Skipped directory'] (because subdirectories are pushed onto the stack after the yield and each arrives as its own root) while files_found for that target stays zero — the cost of the walk is paid, the scanning is not.
- **Threshold:** Let M = `find /media -type f | wc -l` executed as root immediately after the scan (NOT /media/bulk_probe — the walk-root skip at line 7139 counts every file under every skipped root beneath the target). With /media/bulk_probe holding exactly 5,000 regular files and nothing else under /media, M == 5000. Then, with scan_folder='/media' (a lin_skip_directory entry): skip_breakdown['Skipped directory'] == M exactly; scan_summary_<run_id>.json "files_scanned" == 0 and "files_skipped" == M; "excluded_targets" == ['/media']. The cost-was-paid claim must be a comparison, not '> 0': the 'Target scan completed: /media' entry has files_found == 0 while its scan_time_seconds is within a factor of 3 of the /opt/decoy_bulk control leg's scan_time_seconds over the identical 5,000-file tree — the walk was performed, only the matching was not.
- **Setup:** On xdr-agent create /media/bulk_probe with exactly 5,000 small files (/media is in lin_skip_directory and, unlike /opt/yara_scanner, is not written to by the scanner during the run, so the count stays stable). Run one leg with scan_folder='/media' and one with scan_folder='/opt/decoy_bulk' over an identical 5,000-file tree.
- **Evidence:** logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' key 'Skipped directory'; 'Target scan completed: /media' entry data 'files_found'/'scan_time_seconds'; "files_scanned", "files_skipped" and "excluded_targets" in logs/scan_summary_<run_id>.json; `find /media/bulk_probe -type f | wc -l` for the ground truth.
- **Negative control:** The identical 5,000-file tree at /opt/decoy_bulk (on no skip list) must produce files_scanned == 5000, files_skipped == 0, excluded_targets == [], and NO 'Skipped directory' key in skip_breakdown at all — skip_reasons is a defaultdict serialised with dict(), so an unincremented key is absent rather than 0, and asserting '== 0' would raise instead of comparing. Without this control, 'Skipped directory' == M is indistinguishable from a build that skipped every directory it met.

### `TRAV-027` The skip predicate runs at four separate points per scan

*supporting*

- **Must be true:** Three distinguishable grains of the same predicate are all live in one run: the target-level check (populating excluded_targets), the walk-root check (skip_breakdown['Skipped directory'], counted in bulk as len(files) per root) and the per-file check in the walker (skip_breakdown['Special system file']).
- **Threshold:** Let M = `find /media -type f | wc -l` executed as root after the run. One leg with scan_folder='/media,/opt/decoy_mixed', where /opt/decoy_mixed holds a Thumbs.db plus a node_modules/ subdirectory with exactly 3 files plus one ordinary marker file: scan_summary_<run_id>.json "excluded_targets" == ['/media'] (target grain); skip_breakdown['Skipped directory'] == M + 3 EXACTLY — the sum must be pinned, since the key carries no per-path attribution and '>= 3' passes on a build that contributed 0 from node_modules (walk-root grain, '.../node_modules' matching via the tail anchor at line 6516); skip_breakdown['Special system file'] == 1, for Thumbs.db alone (per-file grain); scan_summary "matches" == 1 (only the ordinary marker file); all three keys/fields present in the SAME run.
- **Setup:** Plant /opt/decoy_mixed with Thumbs.db, node_modules/ containing 3 files, and one ordinary file carrying the rule marker; reuse the /media excluded target from TRAV-024.
- **Evidence:** "excluded_targets" in logs/scan_summary_<run_id>.json; logs/scan_errors_<run_id>.log 'Requested scan target is excluded by the skip list, so nothing under it will be scanned:' with data {'reason': 'skip_list'}; logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' keys 'Skipped directory' and 'Special system file'.
- **Negative control:** A control leg with scan_folder='/opt/decoy_plain' (a tree containing none of the three triggers, one ordinary marker file) must produce excluded_targets == [], matches == 1, files_skipped == 0, and therefore NO 'Skip reasons:' statistics entry at all — that entry is gated on files_skipped > 0 (line 6903) and skip_reasons is a defaultdict, so neither 'Skipped directory' nor 'Special system file' exists as a key.
- **Why this round:** The fourth call site — scan_file's own _is_special_file check on a dequeued path — cannot be separated by any artefact: it shares the 'Special system file' key with the walker's per-file site, and every path it sees has already passed that identical predicate in the walker, so it can never be the deciding gate. This criterion therefore asserts the three grains that ARE distinguishable and states the fourth is defence-in-depth with no independent trace.

### `TRAV-029` Filename skip list (OS metadata droppings)

*supporting*

- **Must be true:** A file whose basename is one of the three OS metadata names is skipped case-insensitively and never matched, while a byte-identical file under any other name is scanned and matched.
- **Threshold:** Plant FIVE files in one decoy tree, all carrying the same unique rule marker: Thumbs.db, .DS_Store, desktop.ini (skipped), plus control_thumbs.bin and thumbs.db.bak (both must be scanned). Scan that tree as scan_folder. Then: skip_breakdown['Special system file'] == 3 exactly; alert/<rule>.txt contains exactly 2 entries ('YARA rule ... matched file:' lines), one ending 'control_thumbs.bin' and one ending 'thumbs.db.bak'; scan_summary_<run_id>.json "matches" == 2; exactly 2 yara_scanner_matches_v3_* rows for this run_id (schema v3 writes one row per finding, offsets folded in, so row count == finding count). Set is exactly {'.ds_store','thumbs.db','desktop.ini'} (config.skip_filenames literal, line 3013; no env var, not an options key), compared against os.path.basename of the LOWER-CASED portable path (line 6486), so mixed-case 'Thumbs.db' and '.DS_Store' must both be skipped.
- **Setup:** Plant the four files above in /opt/decoy_names on xdr-agent (or C:\decoy_names on xdragent2) with a rule whose marker string appears in all four.
- **Evidence:** logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' key 'Special system file'; <scanner_dir>/alert/<rule>.txt entry paths; "matches" in logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields filename`.
- **Negative control:** Both controls live in the same leg as the positives and are covered by the threshold above: control_thumbs.bin (identical bytes, different name) and thumbs.db.bak (basename equality, not a prefix test) must BOTH appear in alert/<rule>.txt. Without them, 'it skipped the metadata files' is indistinguishable from 'the rule never matched anything', and a prefix test is indistinguishable from an equality test.

### `TRAV-030` Extension skip list (disk images and VM disks)

*supporting*

- **Must be true:** A file whose lower-cased path ends with one of the nine container extensions is skipped without being opened, while a byte-identical file with a non-listed extension is scanned and matched.
- **Threshold:** Set is exactly {.iso, .img, .dmg, .vmdk, .vhd, .vhdx, .qcow, .qcow2, .sparsebundle} (config.skip_extensions literal, lines 3010-3012; no env var, not an options key), tested as endswith against the full LOWER-CASED portable path (line 6488). Plant ELEVEN files in /opt/decoy_exts on xdr-agent, all carrying the same unique rule marker in their raw bytes: one per extension (9, all skipped), plus payload.bin and archive.img.txt (both must be scanned). Then: skip_breakdown['Special system file'] == 9 exactly; alert/<rule>.txt contains exactly 2 entries, one ending 'payload.bin' and one ending 'archive.img.txt'; scan_summary_<run_id>.json "matches" == 2; exactly 2 yara_scanner_matches_v3_* rows for this run_id.
- **Setup:** Plant the ten files in /opt/decoy_exts on xdr-agent with a rule whose marker string is present in every one of them (the marker must be in the raw bytes — the container files here are plain files with those suffixes, not real images).
- **Evidence:** logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' key 'Special system file'; <scanner_dir>/alert/<rule>.txt entry paths; "matches" in logs/scan_summary_<run_id>.json.
- **Negative control:** Both controls sit in the same leg and are covered by the threshold above: payload.bin (identical bytes, unlisted extension) and archive.img.txt (name CONTAINS '.img' but the path does not END with it) must BOTH be matched. Without archive.img.txt the criterion cannot tell a correct suffix test from a substring test that over-skips.

### `TRAV-032` Cross-platform path-fragment skip list (dev caches, Windows AppData temp/packages)

*supporting*

- **Must be true:** Each of the 15 bounded path fragments excludes its whole subtree from scanning while a sibling whose name merely extends the fragment is scanned normally — the match is on the bounded '/fragment/' form, not a loose substring.
- **Threshold:** Precondition: YARA_EXTRA_SKIP_PATHS unset on both endpoints — line 3029 appends _extra_skip_fragments() to the tuple, so the count is 15 only with that env var absent. Linux leg (scan_folder='/opt/decoy_frags'): tree containing node_modules/, __pycache__/, .git/ and .venv/ subdirectories (2 marker files each), a node_modules_backup/ subdirectory (2 marker files), and one marker file at the tree root: skip_breakdown['Skipped directory'] == 8 exactly (the four fragment subtrees); alert/<rule>.txt contains exactly 3 entries — the root file and the two under node_modules_backup; scan_summary_<run_id>.json "matches" == 3. SEPARATE Windows leg with scan_folder=%LOCALAPPDATA% (the AppData fragments are unreachable from a C:\decoy_frags leg, which makes any assertion about them vacuous): one marker planted in %LOCALAPPDATA%\Temp, one in %LOCALAPPDATA%\Packages and one directly in %LOCALAPPDATA%: alert\<rule>.txt contains exactly 1 entry, whose path is the marker directly in %LOCALAPPDATA%; 0 entries under \AppData\Local\Temp\ and 0 under \AppData\Local\Packages\.
- **Setup:** Plant /opt/decoy_frags on xdr-agent (and C:\decoy_frags plus the two AppData locations on xdragent2) with a single rule whose marker appears in every planted file.
- **Evidence:** logs/statistics_<run_id>.log 'Skip reasons:' entry data 'skip_breakdown' keys 'Skipped directory' and 'Special system file'; <scanner_dir>/alert/<rule>.txt entry paths; "files_scanned" and "matches" in logs/scan_summary_<run_id>.json.
- **Negative control:** node_modules_backup/ must be scanned in full — '/node_modules/' is not a substring of '.../node_modules_backup/x.bin' and the tail anchor does not match it either — and the tree-root marker must be matched. On the Windows leg the marker sitting directly in %LOCALAPPDATA% must be matched: without it, '0 entries under Temp and Packages' is indistinguishable from a leg that scanned nothing, which is exactly the failure the original setup had.

### `TRAV-033` Fragment matching also anchors at the path tail (bare-root fix)

*supporting*

- **Must be true:** When the excluded component IS the walk root — the path the walker yields carries no trailing separator, so the bounded '/fragment/' substring cannot close — the tail anchor still matches, the target is recorded as excluded, and the operator is told rather than being handed a silent clean zero.
- **Threshold:** scan_folder='C:\decoy\node_modules' (a real directory holding 1 marker file): the returned line contains 'WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned: C:\decoy\node_modules'; scan_summary_<run_id>.json "excluded_targets" == ['C:\\decoy\\node_modules'] and "files_scanned" == 0 and "matches" == 0; yara_processing_<run_id>.log contains 0 occurrences of 'sit under a platform skip-path' (skip_path_fragments is deliberately not part of skip_paths, so the config-time warning stays silent here and the result-line warning is the only signal).
- **Setup:** On xdragent2 create C:\decoy\node_modules and C:\decoy\node_modules_backup, each holding one file with the same unique rule marker; run one leg per target.
- **Evidence:** The returned SCAN_RESULT line's 'WARNING: N requested target(s) EXCLUDED by the skip list, nothing under them was scanned:' clause; "excluded_targets", "files_scanned" and "matches" in logs\scan_summary_<run_id>.json; logs\scan_errors_<run_id>.log 'Requested scan target is excluded by the skip list, so nothing under it will be scanned:'; absence of 'sit under a platform skip-path' in logs\yara_processing_<run_id>.log.
- **Negative control:** scan_folder='C:\decoy\node_modules_backup' must produce excluded_targets == [], no WARNING clause on the result line, files_scanned == 1 and matches == 1. Without it, a tail anchor that correctly matched '.../node_modules' is indistinguishable from one that excluded every target whose name contains the fragment.

### `TRAV-035` Windows folder-prefix skip list (vendor agent dirs + scanner's own dir)  <sub>windows</sub>

*core*

- **Must be true:** A path whose normalised lowercase form is prefixed by any win_skip_folder entry is excluded wholesale: passing C:\ProgramData\Cyvera as a scan target records it in excluded_targets and produces zero scanned files under it, while an identical decoy in a sibling directory outside the list is scanned and reported.
- **Threshold:** scan_summary_<run_id>.json "excluded_targets" == ["C:\\ProgramData\\Cyvera"] (exactly one entry); alert/<rule>.txt contains >=1 line naming C:\yara_probe_ctrl\decoy.bin and 0 lines naming any path under C:\ProgramData\Cyvera or under C:\yara_scanner
- **Setup:** On thor: create C:\yara_probe_ctrl\decoy.bin holding the Round-3 decoy string, then run with scan_folder="C:\ProgramData\Cyvera,C:\yara_probe_ctrl".
- **Evidence:** C:\yara_scanner\logs\scan_summary_<run_id>.json field "excluded_targets"; the SCAN_RESULT line fragment "WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned:"; C:\yara_scanner\logs\scan_errors_<run_id>.log line "Requested scan target is excluded by the skip list, so nothing under it will be scanned: C:\ProgramData\Cyvera" with data {'target_path':...,'reason':'skip_list'}; C:\yara_scanner\alert\<rule>.txt
- **Negative control:** C:\yara_probe_ctrl\decoy.bin — byte-identical content, not under any win_skip_folder prefix — must be scanned, must appear in alert/<rule>.txt, and must produce a yara_scanner_matches_v3_<shard> row.

### `TRAV-036` DEAD CODE: Windows wildcard pattern skip list never matches anything  <sub>windows</sub>

*supporting*

- **Must be true:** The win_skip_patterns loop can never return True: a file at C:\yara_probe_ctrl\Cyvera\decoy.bin — nominally covered by pattern "C:\*\cyvera\*" — is scanned and produces a finding, because the pattern retains the "c:" component while the path it is matched against has had its drive stripped by os.path.splitdrive.
- **Threshold:** alert/<rule>.txt contains >=1 line "YARA rule '<rule>' matched file: C:\\yara_probe_ctrl\\Cyvera\\decoy.bin"; an XQL row exists carrying that exact value in the **filename** column (not file_path); and in the same run C:\\yara_scanner appears in scan_summary "excluded_targets" with 0 alert lines naming any path under it and skip_breakdown["Skipped directory"] >= 1.
- **Setup:** On thor: create C:\yara_probe_ctrl\Cyvera\decoy.bin and C:\ProgramData\Cyvera\decoy.bin (if writable) with the same decoy string; run with scan_folder="C:\yara_probe_ctrl".
- **Evidence:** C:\yara_scanner\alert\<rule>.txt; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields filename, rule | filter filename contains "yara_probe_ctrl"` — the column is `filename` and it holds the FULL path (add_match's parameter is named filename but _write_alerts passes file_path into it; matches_schema has no file_path key); C:\yara_scanner\logs\scan_summary_<run_id>.json "excluded_targets"; source: _is_special_file's win_skip_patterns loop matches pattern_parts (which begin "c:") against path_parts taken from os.path.splitdrive(normalized_path)[1], so the first pattern component can never be found and every pattern raises ValueError and continues.
- **Negative control:** Run with scan_folder="C:\\yara_probe_ctrl,C:\\yara_scanner" so the control sits INSIDE the scanned target set. C:\\yara_scanner is excluded by win_skip_folder: it must appear in "excluded_targets", contribute to skip_breakdown["Skipped directory"], and produce 0 alert lines — while C:\\yara_probe_ctrl\\Cyvera\\decoy.bin, nominally covered by pattern "C:\\*\\cyvera\\*", is scanned and matched. That contrast is what separates "only the PATTERN list is inert" from "skipping is broken". Do NOT rely on writing into C:\\ProgramData\\Cyvera — the Cortex agent self-protects that directory and the write will likely be blocked.
- **Why this round:** Marked as an observability gap, but it is decidable by a negative assertion: the artefact's presence (a finding from a path the pattern nominally covers) is the evidence. Round 3 is where planted decoys and targeted paths exist.

### `TRAV-037` Linux directory skip list (pseudo-filesystems, agent root, scanner dir)  <sub>linux</sub>

*core*

- **Must be true:** Every entry of lin_skip_directory that exists as a directory on the endpoint is excluded when named as a scan target, and a control directory outside the list passed in the same comma-separated target list is scanned and yields findings.
- **Threshold:** scan_summary_<run_id>.json "excluded_targets" contains exactly the passed skip-list entries that exist on the host (/proc, /sys, /dev, /run, /var/run, /opt/traps, /opt/yara_scanner on xdr-agent — 7 expected) and does NOT contain /tmp/yara_probe_ctrl; skip_breakdown has no "Skipped directory" attributable to /tmp/yara_probe_ctrl
- **Setup:** On xdr-agent: mkdir /tmp/yara_probe_ctrl and plant decoy.bin there; run with scan_folder="/proc,/sys,/dev,/run,/var/run,/opt/traps,/opt/yara_scanner,/tmp/yara_probe_ctrl". Drop from the list any path that does not exist (it would be reported by the "Ignoring N specified scan folder(s) that are not valid directories" warning instead).
- **Evidence:** /opt/yara_scanner/logs/scan_summary_<run_id>.json field "excluded_targets"; /opt/yara_scanner/logs/scan_errors_<run_id>.log lines "Requested scan target is excluded by the skip list, so nothing under it will be scanned: <target>" (one per excluded target); /opt/yara_scanner/logs/yara_processing_<run_id>.log line "N of M scan folder(s) sit under a platform skip-path and will yield no files:"; /opt/yara_scanner/alert/<rule>.txt
- **Negative control:** /tmp/yara_probe_ctrl/decoy.bin must be scanned and appear in alert/<rule>.txt — otherwise "it skipped /proc" is indistinguishable from "it skipped everything".

### `TRAV-038` Linux bare-root equality match (walk-root fix)  <sub>linux</sub>

*supporting*

- **Must be true:** The bare walk root itself matches its skip entry: scan_folder=/opt/yara_scanner (no trailing separator) is recognised as excluded at target grain, so it is recorded in excluded_targets rather than being walked and having its contents skipped file-by-file.
- **Threshold:** scan_summary_<run_id>.json "excluded_targets" == ["/opt/yara_scanner"]; the "Target scan completed: /opt/yara_scanner" statistics entry has files_found == 0 (there is no per-target files_scanned field); skip_breakdown contains NO "Special system file" key at all for this run, and skip_breakdown["Skipped directory"] >= 1. Rationale: with the equality clause `normalized_path == skip_dir.rstrip("/")` removed, _is_special_file("/opt/yara_scanner") returns False, the bare root is walked, and probe_root.bin is caught only by the per-file check as "Special system file"; with the clause present the root itself matches and every file under it rolls up under "Skipped directory". Note the excluded target is still WALKED (there is no `continue` after excluded_targets.append at line 7123), so "Skipped directory" is the expected bucket, not a zero.
- **Setup:** On xdr-agent: plant /opt/yara_scanner/probe_root.bin (a file at the BARE root, not in a subdirectory) holding the decoy string; run with scan_folder="/opt/yara_scanner,/tmp/yara_probe_ctrl".
- **Evidence:** /opt/yara_scanner/logs/scan_summary_<run_id>.json "excluded_targets"; SCAN_RESULT fragment "requested target(s) EXCLUDED by the skip list"; /opt/yara_scanner/logs/yara_processing_<run_id>.log "scan folder(s) sit under a platform skip-path and will yield no files: /opt/yara_scanner (excluded by '/opt/yara_scanner/')"; source: _is_special_file Linux branch `normalized_path == skip_dir.rstrip("/") or normalized_path.startswith(skip_dir)`
- **Negative control:** /tmp/yara_probe_ctrl/decoy.bin in the same run must produce a finding, and /opt/yara_scanner/probe_root.bin must produce none.

### `TRAV-043` Scanner working-directory self-exclusion (all three platforms)

*core*

- **Must be true:** The scanner never scans its own working directory: on each platform, passing the resolved scanner_dir as a target records it in excluded_targets, and on macOS this is decided solely by the entry derived from scanner_dir (mac_skip_directory carries no literal /usr/local/yara_scanner), so the derived injection is proven rather than a hard-coded string.
- **Threshold:** On OfficeiMac "excluded_targets" == ["/usr/local/yara_scanner"]; on xdr-agent it contains "/opt/yara_scanner"; on thor it contains "C:\\yara_scanner"; on every host alert/<rule>.txt contains 0 lines naming any path under scanner_dir and >=1 line naming the sibling control
- **Setup:** Create a sibling control directory at the same level on each host (/usr/local/yara_control, /opt/yara_control, C:\yara_control) holding decoy.bin, and run with scan_folder="<scanner_dir>,<sibling control>". macOS is the load-bearing host: its skip list has no literal scanner path, only `os.path.normpath(self.scanner_dir).rstrip('/') + '/'`.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "excluded_targets"; <scanner_dir>/logs/scan_errors_<run_id>.log "Requested scan target is excluded by the skip list, so nothing under it will be scanned: <scanner_dir>"; <scanner_dir>/alert/<rule>.txt; source: _default_scanner_dir (YARA_SCANNER_DIR override, else C:\yara_scanner / /usr/local/yara_scanner / /opt/yara_scanner) and the scanner_dir entries injected into win_skip_folder, lin_skip_directory and mac_skip_directory
- **Negative control:** The sibling control directory (e.g. /usr/local/yara_control) sits one component away from scanner_dir and must be scanned and matched — otherwise a prefix bug that swallowed /usr/local entirely would read as a pass.

### `TRAV-044` Per-platform case-folding policy in the skip predicate

*supporting*

- **Must be true:** The platform directory lists are case-SENSITIVE on Linux and case-INSENSITIVE on macOS: on xdr-agent /media/<x> is excluded while /Media/<x> is walked and yields findings; on OfficeiMac a mixed-case /tmp/LIBRARY/Metadata/<x> is skipped because portable_path and mac_skip_directory are both lowercased.
- **Threshold:** Linux run: "excluded_targets" == ["/media/yara_probe"] and alert/<rule>.txt names /Media/yara_probe/decoy.bin exactly once and /media/yara_probe/decoy.bin zero times. macOS run: 0 findings for /tmp/LIBRARY/Metadata/frag.bin, >=1 finding for /tmp/LIBRARYX/Metadata/frag.bin
- **Setup:** xdr-agent: `sudo mkdir -p /media/yara_probe /Media/yara_probe` and plant identical decoy.bin in each; scan_folder="/media/yara_probe,/Media/yara_probe". OfficeiMac: create /tmp/LIBRARY/Metadata/frag.bin and /tmp/LIBRARYX/Metadata/frag.bin; scan_folder="/tmp".
- **Evidence:** scan_summary_<run_id>.json "excluded_targets"; <scanner_dir>/alert/<rule>.txt on both hosts; source: _is_special_file builds normalized_path case-PRESERVED on non-Windows and compares it against lin_skip_directory (also case-preserved), but builds portable_path with `.lower()` and compares it against mac_skip_directory (lowercased at construction) and win_skip_folder (normpath'd + lowercased)
- **Negative control:** /Media/yara_probe/decoy.bin on Linux must be scanned — it is the case-variant control proving the Linux list is not being folded; /tmp/LIBRARYX/Metadata/frag.bin on macOS must be scanned, proving the mac fragment is bounded to the exact component and not a loose substring.

### `TRAV-045` Junction / reparse-point detection (_is_junction_or_symlink)

*supporting*

- **Must be true:** The predicate keys on link/reparse status, not on the path name: a symlink FILE placed under a listed prefix is junction-skipped, while a REGULAR file in the very same directory (identical path prefix, so the name test alone cannot separate them) is scanned and matched.
- **Threshold:** Run with scan_folder="/tmp/yara_probe" (still under the '/tmp' Darwin prefix, so the guard applies, but the population is fully controlled): skip_breakdown["Junction/symlink skip"] == 1 and the "SCAN COMPLETED | Time: ..." entry's data.junction_skips == 1, exactly; alert/<rule>.txt contains 0 lines naming /tmp/yara_probe/probe_link.bin and >=1 line naming /tmp/yara_probe/probe_real.bin.
- **Setup:** On OfficeiMac: `printf '<decoy>' > /tmp/probe_real.bin; ln -s /tmp/probe_real.bin /tmp/probe_link.bin`; run with scan_folder="/tmp". Both paths start with '/tmp', which is one of the Darwin macos_skip_symlinks prefixes, so only the reparse/link test can distinguish them.
- **Evidence:** /usr/local/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown["Junction/symlink skip"], and the "SCAN COMPLETED | Time: ..." entry's data key 'junction_skips'; /usr/local/yara_scanner/alert/<rule>.txt; source: _should_skip_junction returns False immediately unless _is_junction_or_symlink(path) is true
- **Negative control:** /tmp/yara_probe/probe_real.bin — same directory, same listed '/tmp' prefix, regular file not a link — must be scanned and matched. Plant both inside /tmp/yara_probe/ rather than bare /tmp: the guard still fires (path.startswith('/tmp')), but no unrelated system symlink can contaminate the counter, which is what makes the exact ==1 assertion valid instead of a lower bound.
- **Why this round:** Marked as an observability gap because the directory-prune call site increments no counter, but the FILE call site does, and pairing a link with a regular sibling under the same prefix isolates the detection primitive itself. Round 3 is where planted decoys and symlinks live.

### `TRAV-046` Junction/symlink loop guard with narrow, hard-coded per-platform lists

*supporting*

- **Must be true:** The loop guard is narrow by design: a symlink whose path starts with one of the three Darwin prefixes ('/etc', '/tmp', '/var') is skipped and counted, while a symlink outside those prefixes is NOT skipped — it is followed and, when it resolves to matching content, produces a finding.
- **Threshold:** Run with scan_folder="/tmp/yara_probe,/Users/<user>/yara_probe" — /tmp/yara_probe is still under the '/tmp' prefix so the in-list case is genuinely exercised, but the symlink population is fully controlled. skip_breakdown["Junction/symlink skip"] == 1 exactly (the single planted /tmp/yara_probe/probe_link.bin) and final-metrics junction_skips == 1; alert/<rule>.txt contains 0 lines for /tmp/yara_probe/probe_link.bin and >=1 line for /Users/<user>/yara_probe/out_link.bin.
- **Setup:** On OfficeiMac: /tmp/probe_link.bin -> /tmp/probe_real.bin (in-list), and /Users/<user>/yara_probe/out_link.bin -> /Users/<user>/yara_probe/out_real.bin (out-of-list). Run with scan_folder="/tmp,/Users/<user>/yara_probe".
- **Evidence:** /usr/local/yara_scanner/logs/statistics_<run_id>.log skip_breakdown key "Junction/symlink skip" and the 'junction_skips' metric in the "SCAN COMPLETED" statistics entry and in each "Scan Progress | Files: ..." entry's metrics; source: _should_skip_junction's literal lists — Windows ['documents and settings','application data','local settings','my documents','default user','all users'], Darwin ['/etc','/tmp','/var'], Linux ['/proc/self/fd','/proc/self/task']
- **Negative control:** /Users/<user>/yara_probe/out_link.bin is a symlink outside the three Darwin prefixes: _should_skip_junction returns False, the worker's os.path.exists/os.stat follow it, and it must be scanned and appear in alert/<rule>.txt. That is what separates "the guard is narrow" from "the guard skips every symlink". Its target out_real.bin will also be scanned and matched — that is expected and does not weaken the control.

### `TRAV-047` Junction file skip is counted on its own dedicated counter

*low*

- **Must be true:** A junction/symlink file skip increments three books at once and is excluded from discovery counts: junction_skip_count, skip_reasons["Junction/symlink skip"] and files_skipped all move together, and the per-target 'files_found' does NOT include them, so the discovery-versus-accounting identity only closes when junction_skips is subtracted.
- **Threshold:** Run over a single controlled tree /tmp/yara_probe containing: probe_real.bin + probe_link.bin (symlink), ._payload.bin (AppleDouble), big.bin (65 MB), and a node_modules/ subtree. Then: final-metrics 'junction_skips' == skip_breakdown["Junction/symlink skip"] == 1 exactly; skip_breakdown["Special system file"] >= 1 and skip_breakdown["File too large"] == 1, neither reflected in junction_skips; and SUM('files_found' over all "Target scan completed" entries) == files_scanned + files_skipped − skip_breakdown["Skipped directory"] − skip_breakdown["Junction/symlink skip"], delta 0.
- **Setup:** Same planted symlinks as TRAV-045/046; the run must complete uncancelled and the targets must not overlap, or the identity is not expected to close.
- **Evidence:** /usr/local/yara_scanner/logs/statistics_<run_id>.log: the "SCAN COMPLETED | Time: ... | Files: N scanned, M skipped | ..." entry data keys 'junction_skips' and 'skip_rate'; the "Skip reasons: ..." entry data.skip_breakdown; each "Target scan completed: <target>" entry data key 'files_found'; files_scanned/files_skipped in scan_summary_<run_id>.json
- **Negative control:** The same run must plant an ordinary special-system-file skip (/tmp/yara_probe/._payload.bin -> "Special system file") and an oversize file (/tmp/yara_probe/big.bin at 65 MB -> "File too large"), and both counts must be non-zero while junction_skips stays at exactly 1. Without those two planted in the SAME run the control is unevaluable — the stated symlink-only setup produces neither.

### `TRAV-048` Real-path resolution with platform case normalisation (_get_real_path)

*supporting*

- **Must be true:** Every alert log entry for a matched file carries a real_path that is the symlink-resolved, platform-case-normalised form of file_path — on macOS's case-insensitive volume a mixed-case file reached through the /tmp symlink reports file_path with its original case and real_path fully lowercased under /private/tmp.
- **Threshold:** First establish the volume's case sensitivity (`diskutil info / | grep -i 'Case-Sensitive'`). On the default case-INSENSITIVE APFS: the alerts_<run_id>.log entry "YARA matches found in /tmp/yara_probe/Probe_CaSe.BIN" has data.file_path == "/tmp/yara_probe/Probe_CaSe.BIN" (original case, unresolved) and data.real_path == "/private/tmp/yara_probe/probe_case.bin" (symlink-resolved AND fully lowercased) — both transforms, exactly. On a case-SENSITIVE volume the same entry must read real_path == "/private/tmp/yara_probe/Probe_CaSe.BIN" (resolved, case preserved); asserting the lowercased form there would fail a correct build.
- **Setup:** On OfficeiMac: write /tmp/Probe_ReaL.BIN with the decoy string (/tmp is itself a symlink to /private/tmp); run with scan_folder="/tmp".
- **Evidence:** /usr/local/yara_scanner/logs/alerts_<run_id>.log entry "YARA matches found in /tmp/Probe_ReaL.BIN" with data fields 'file_path' and 'real_path'; on an error path the same 'real_path' appears in the scan_errors_<run_id>.log data blob for "Error scanning file ..."; source: _get_real_path (os.path.realpath, then .lower() on Windows and on Darwin when _is_case_sensitive_fs() is False)
- **Negative control:** Add a control OUTSIDE the /tmp symlink in the same run — e.g. /Users/<user>/yara_probe/Probe_CaSe2.BIN with the same decoy — and pass scan_folder="/tmp/yara_probe,/Users/<user>/yara_probe". Its alerts entry must show real_path == the same path with no component rewritten (only the case fold on a case-insensitive volume), proving _get_real_path applies case normalisation independently of symlink resolution rather than the two being confounded. Use a distinct basename from TRAV-045's probe_real.bin: on a case-insensitive volume Probe_ReaL.BIN and probe_real.bin are the same file.

### `TRAV-050` File-existence gate at dequeue time

*supporting*

- **Must be true:** A path that is enqueued during the walk but no longer resolves when a worker dequeues it is skipped under "File does not exist" rather than raising or being counted as scanned, and the run still completes.
- **Threshold:** skip_breakdown["File does not exist"] >= 1 and equals the number of planted dangling symlinks; scan_summary_<run_id>.json "outcome" == "completed"; the same total rolls into files_skipped
- **Setup:** On xdr-agent: `mkdir -p /tmp/yara_probe && ln -s /tmp/definitely_absent_target /tmp/yara_probe/dangling.bin` plus a live symlink `ln -s /tmp/yara_probe/real.bin /tmp/yara_probe/live.bin` where real.bin holds the decoy string. A dangling symlink is classified as a file by the walk (entry.is_dir() is False), survives _should_skip_junction on Linux, and then fails os.path.exists at dequeue — deterministic, no race needed. Run with scan_folder="/tmp/yara_probe".
- **Evidence:** /opt/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown key "File does not exist"; files_skipped in scan_summary_<run_id>.json; source: scan_file `if not os.path.exists(file_path): return False, "File does not exist"` as the first gate after _maybe_sample_fds
- **Negative control:** /tmp/yara_probe/live.bin — also a symlink, but resolving — must be scanned and matched, so the gate is proven to reject non-resolving paths rather than all symlinks.

### `TRAV-052` Regular-file gate (devices, FIFOs, sockets never scanned)

*supporting*

- **Must be true:** A non-regular file that reaches a worker is rejected by the S_ISREG test under "Not a regular file" before rules.match is called, and the scan still completes rather than blocking on the open.
- **Threshold:** skip_breakdown["Not a regular file"] == number of planted FIFOs (1); scan_summary_<run_id>.json "outcome" == "completed"; the planted FIFO appears in no alert/<rule>.txt and in no yara_scanner_matches_v3_<shard> row
- **Setup:** On xdr-agent: `mkdir -p /tmp/yara_probe && mkfifo /tmp/yara_probe/pipe` and place a regular decoy.bin beside it; run with scan_folder="/tmp/yara_probe". Note /dev is already excluded by lin_skip_directory, so the FIFO must be planted inside a scanned target.
- **Evidence:** /opt/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown key "Not a regular file"; scan_summary_<run_id>.json "outcome" and "files_skipped"; source: scan_file `st = os.stat(file_path); if not stat.S_ISREG(st.st_mode): return False, "Not a regular file"`
- **Negative control:** /tmp/yara_probe/decoy.bin — a regular file in the same directory — must be scanned and matched, so the gate is proven to reject the FIFO specifically rather than the whole directory.

### `TRAV-053` Maximum scanned file size cap

*core*

- **Must be true:** Files larger than max_file_bytes are rejected before rules.match under "File too large", the configured cap is echoed as 64 MB on both config entries, and a file just under the cap holding the same decoy string is scanned and matched.
- **Threshold:** 'max_file_size_mb' == 64 in the "Scan configuration established" statistics entry and 'max_file_mb' == 64 in the "YARA Scanner initialization completed" system entry; skip_breakdown["File too large"] == number of planted oversize files (1); alert/<rule>.txt contains 0 lines for big.bin and >=1 for small.bin
- **Setup:** On xdr-agent: create /tmp/yara_probe/big.bin at 65 MB and /tmp/yara_probe/small.bin at 1 MB, both containing the decoy string in the first block; run with scan_folder="/tmp/yara_probe". Optional second run with YARA_MAX_MB=-1 set in the agent's environment: stderr must carry "Ignoring out-of-range YARA_MAX_MB='-1' (minimum 0) - using default 64" and max_file_size_mb must still read 64 — that warning is emitted from _env_number during ScanConfig, before setup_logging installs the diagnostics handler, so it reaches the Action Center's stderr and no scanner log file.
- **Evidence:** /opt/yara_scanner/logs/statistics_<run_id>.log "Scan configuration established" data.max_file_size_mb and "Skip reasons: ..." data.skip_breakdown["File too large"]; /opt/yara_scanner/logs/system_<run_id>.log "YARA Scanner initialization completed" data.max_file_mb; source: `self.max_file_mb = _env_number("YARA_MAX_MB", 64, cast=int, minimum=0)` and scan_file `if max_bytes and st.st_size > max_bytes: return False, "File too large"`
- **Negative control:** /tmp/yara_probe/small.bin must be scanned and matched — otherwise a cap of 0 bytes (or a negative max_file_bytes, the exact bug _env_number's `minimum=0` exists to prevent) would read as a pass.

### `TRAV-054` Bounded skip-reason labels for per-file scan errors

*supporting*

- **Must be true:** Per-file scan errors collapse to one label per exception TYPE, not one per file: with hundreds of errored files the number of distinct "Scan error (...)" keys stays in single digits and no key contains a path, an errno or a digit, while genuinely different exception types still occupy distinct keys.
- **Threshold:** count of distinct skip_breakdown keys matching ^Scan error \( is >= 2 AND <= 4; total bytes of those keys < 200; no such key contains a path separator, an errno or a digit; the aggregate error count (sum of skip_breakdown values whose key contains 'error') is >= 20 and equals error_summary.scan_errors in the "Scan completed successfully in ..." system entry, delta 0. If the run yields fewer than 5 errored files, record the capability UNEXERCISED rather than passing on the bound — the bound only discriminates once enough files have errored that a per-file label would have produced more keys than the cap allows.
- **Setup:** On xdr-agent: build /tmp/yara_probe/churn/ with 5,000 small files, start the scan, and delete the tree ~2 s in while the workers are still draining the queue. Files that vanish after enqueue produce a mix of "File does not exist" and "Scan error (FileNotFoundError)" / "Scan error (Error)" (yara.Error's type name is Error).
- **Evidence:** /opt/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown; /opt/yara_scanner/logs/system_<run_id>.log "Scan completed successfully in ..." data.error_summary.scan_errors (summed by the substring 'error' in the reason, line 7808-7809); per-file detail in scan_errors_<run_id>.log "Error scanning file <path>: <msg>"; source: `_scan_error_reason` returns f"Scan error ({type(exc).__name__})". To reach the floor DETERMINISTICALLY instead of racing the walk, plant a directory of files whose names are invalid UTF-8 (e.g. `python3 -c 'open(b"/tmp/yara_probe/bad\xff\xfe_%d.bin"%i,"wb")...'`): they pass os.path.exists/os.access/os.stat but rules.match(filepath=...) raises on the surrogate-escaped name, giving one bounded key for N files. Keep the churn tree alongside it so a second, different exception type also appears.
- **Negative control:** At least two DIFFERENT exception types must appear as separate keys in the same run — a collapse to a single "Scan error" bucket would also satisfy the cardinality bound while destroying the information the label exists to keep. The per-file paths must still be recoverable from scan_errors_<run_id>.log.

### `TRAV-055` Bulk skip accounting for an excluded directory root

*supporting*

- **Must be true:** Every file under an excluded walk root is counted exactly once under "Skipped directory" — including files in subdirectories, which are not pruned and arrive as their own roots — so files_scanned + files_skipped reconciles with the tree on disk and skip_rate becomes non-zero.
- **Threshold:** skip_breakdown["Skipped directory"] == the independent `find <excluded tree> -type f | wc -l` census, exactly (no double-count: the value must never exceed the census); final-metrics 'skip_rate' > 0; the same total is included in files_skipped in scan_summary_<run_id>.json
- **Setup:** On xdr-agent: build /tmp/yara_probe/node_modules/{a,b,c}/ with a known file count (say 40 files across 3 levels, matching the '/node_modules/' skip fragment) plus /tmp/yara_probe/keep/ with 10 matching files; run with scan_folder="/tmp/yara_probe" and take the find census at the same time.
- **Evidence:** /opt/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown["Skipped directory"] and the "SCAN COMPLETED | Time: ..." entry's data.skip_rate; files_skipped in scan_summary_<run_id>.json; source: scan_system's walk `if self._is_special_file(root): if files: files_skipped += len(files); skip_reasons["Skipped directory"] += len(files); continue` (no dirs pruning)
- **Negative control:** /tmp/yara_probe/keep/ must contribute 0 to "Skipped directory" and its 10 files must all appear in files_scanned and in alert/<rule>.txt — a bulk counter that swallowed the sibling tree would inflate the same key.

### `TRAV-056` Excluded-target recording: a requested target that the skip list swallows whole

*core*

- **Must be true:** A target the operator asked for that the skip list excludes wholesale is named in three places rather than reported as a clean zero, and a non-excluded target in the same comma-separated list is absent from all three and still produces findings.
- **Threshold:** scan_summary_<run_id>.json "excluded_targets" has exactly the excluded targets and not the control; the SCAN_RESULT line contains "| WARNING: N requested target(s) EXCLUDED by the skip list, nothing under them was scanned: " with N == len(excluded_targets) and the first three named; scan_errors_<run_id>.log has exactly N "Requested scan target is excluded by the skip list" lines
- **Setup:** Run with a mixed target list on each host, e.g. on xdr-agent scan_folder="/proc,/opt/yara_scanner,/tmp/yara_probe_ctrl" where the last holds a matching decoy. Note the SCAN_RESULT warning is built on the SUCCESS path only — a failed run will not carry it, so the run must complete.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json field "excluded_targets"; the Action Center SCAN_RESULT line; <scanner_dir>/logs/scan_errors_<run_id>.log lines "Requested scan target is excluded by the skip list, so nothing under it will be scanned: <target>" with data {'target_path':...,'reason':'skip_list'}
- **Negative control:** /tmp/yara_probe_ctrl must NOT appear in excluded_targets, must not appear in the warning, and must produce findings — otherwise a predicate that marked every target excluded would satisfy the positive half.

### `TRAV-058` Skip-reason breakdown in the final statistics entry

*supporting*

- **Must be true:** The dedicated "Skip reasons" statistics entry is emitted whenever files were skipped, its total_skipped equals the sum of its own breakdown and equals scan_summary's files_skipped, and the breakdown exists nowhere else — neither in scan_summary_<run_id>.json nor on any lifecycle dataset row, which carry only the total.
- **Threshold:** data.total_skipped == sum(data.skip_breakdown.values()) == scan_summary_<run_id>.json files_skipped, delta 0; the entry is present iff files_skipped > 0; scan_summary_<run_id>.json contains no skip_breakdown key and yara_scanner_scans_v3_* has no such column; the data blob is either < 4000 chars or ends with "...(truncated)"
- **Setup:** Round 3's crafted run, which plants a file for as many gates as possible (dangling symlink, FIFO, oversize file, ._ AppleDouble, excluded tree, in-list symlink, churned tree for scan errors) so the breakdown has many distinct labels.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log line "Skip reasons: reason(count), ..." with data={'total_skipped': N, 'skip_breakdown': {...}}; scan_summary_<run_id>.json field "files_skipped"; source: _log_final_results emits it only under `if self.files_skipped > 0`, and LogManager._log truncates any data blob over 4000 chars
- **Negative control:** files_scanned must be > 0 in the same run — a scan that skipped everything satisfies the sum identity trivially. At least five distinct skip_breakdown keys must be present, so the identity is testing attribution and not a single bucket.

### `TRAV-059` Derived skip metrics in the final results entry

*low*

- **Must be true:** The final results entry carries four derived metrics whose values are reproducible from the raw counts, and it is routed by outcome: labelled "SCAN COMPLETED" into the statistics log on success, and "SCAN FAILED" into the error log with failure_reasons attached on failure.
- **Threshold:** skip_rate == files_skipped/(files_scanned+files_skipped)*100 within 0.01; path_deduplication_ratio == junction_skips/max(files_scanned+files_skipped,1)*100 within 0.01; unique_paths_scanned == 0; average_scan_rate == files_scanned/total_time_seconds within 0.01; and exactly one entry matching the anchored prefix "SCAN COMPLETED | Time: " exists in statistics_<run_id>.log with zero entries matching "SCAN FAILED | Time: " in scan_errors_<run_id>.log (or the mirror image on a failed run). Do not count the bare substring "SCAN COMPLETED": the separate success banner "SCAN COMPLETED SUCCESSFULLY in ..." is written to the same file and would make the count 2.
- **Setup:** Round 3's crafted run supplies the success variant. The failure variant needs a run where scan_failed is set (e.g. the worker-fatal or critical-scan-error path) — if no Round 3 run fails, record the FAILED half as unexercised rather than inferring it.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log entry "SCAN COMPLETED | Time: ... | Files: N scanned, M skipped | Detections: ... | Rate: ... files/sec" with data keys total_time_seconds, files_scanned, files_skipped, total_detections, average_scan_rate, detection_rate, skip_rate, junction_skips, unique_paths_scanned, path_deduplication_ratio; on failure the same message prefixed "SCAN FAILED" in scan_errors_<run_id>.log with an extra 'failure_reasons' list

### `TRAV-060` Skip breakdown in the comprehensive final report and the efficiency score

*low*

- **Must be true:** The comprehensive report entry is emitted once per successful run with the full final_report_data attached, and its efficiency score is exactly the documented deduction from 100 for skip rate and rule-failure rate — not a constant 100.
- **Threshold:** efficiency_score == 100 − (total_files_skipped/total_files_processed)*20 − (failed_rules_skipped/total_rules_processed)*30, within 0.05, and < 100 because the crafted pack contains at least one broken rule and the run skips files; file_processing.skip_breakdown equals the "Skip reasons" entry's skip_breakdown key-for-key unless the blob was truncated
- **Setup:** Round 3's crafted pack must contain at least one syntactically broken rule (so failed_rules_count > 0) and the run must skip files, or both deduction terms are 0 and the score is a constant 100.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log entry "COMPREHENSIVE SCAN REPORT | Efficiency Score: NN.N/100" with the whole final_report_data dict attached (scan_metadata, file_processing.skip_breakdown, detection_results, rule_compilation, system_info, efficiency_score); the blob is truncated by LogManager._log at 4000 chars with the suffix "...(truncated)", so on a full-system scan expect the tail to be lost — that is a reportable finding, not a failure

### `TRAV-061` Per-target discovery statistics

*supporting*

- **Must be true:** Exactly one "Target scan completed" statistics entry is emitted per requested target on a healthy run, each carrying a files_found and a positive files_per_second for targets that found files; a target whose walk raised produces an "Error scanning target" line in the error log and NO statistics entry.
- **Threshold:** count("Target scan completed:") == 'target_count' in the "Scan configuration established" entry, exactly; every entry with files_found > 0 has files_per_second > 0; count("Error scanning target") == target_count − count("Target scan completed:")
- **Setup:** A multi-target Round 3 run — at least three targets of differing size, e.g. scan_folder="/tmp/yara_probe,/tmp/yara_probe_ctrl,/opt/yara_control". The scan must not be cancelled: `if not self.scan_active: break` at the top of the target loop also drops remaining targets and would produce the same shortfall.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log entries "Target scan completed: <target>" with data {'target','files_found','scan_time_seconds','files_per_second'}, and the "Scan configuration established" entry's data.targets / data.target_count; <scanner_dir>/logs/scan_errors_<run_id>.log "Error scanning target <target>: <exception>"

### `TRAV-062` DEAD: total_files_found and files_per_target are computed then discarded

*low*

- **Must be true:** The discovery aggregate reaches no artefact — it is computed in scan_system, handed to _perform_enhanced_cleanup and never read — so it is recoverable only by summing the per-target entries, and that sum reconciles exactly against the final counters.
- **Threshold:** No file under <scanner_dir> and no column of yara_scanner_scans_v3_* / yara_scanner_matches_v3_* carries a discovery-aggregate field (grep for total_files_found and files_per_target over <scanner_dir>/logs/* and scan_summary_<run_id>.json returns 0 hits); and SUM('files_found' over all "Target scan completed" entries) == files_scanned + files_skipped − skip_breakdown["Skipped directory"] − skip_breakdown["Junction/symlink skip"], delta 0
- **Setup:** The same multi-target Round 3 run as TRAV-061, with non-overlapping targets and no cancellation — an enqueue abandoned by a cancel would leave files counted in files_found that never reached a worker and would break the identity legitimately.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log "Target scan completed: <target>" data.files_found (per target) and the "SCAN COMPLETED" entry's data.files_scanned / data.files_skipped; the "Skip reasons: ..." entry's data.skip_breakdown; scan_summary_<run_id>.json files_scanned/files_skipped; source: total_files_found and files_per_target are assigned in scan_system, passed as parameters to _perform_enhanced_cleanup, and referenced nowhere in its body
- **Why this round:** Marked as an observability gap, but decidable by a two-sided assertion: the aggregate's ABSENCE from every artefact is one half, and the reconciliation identity proves the per-target counters that would compose it are themselves correct — so "dead" is distinguished from "broken".

### `TRAV-063` Skip counting happens in the worker, under lock_counts, at dequeue grain

*supporting*

- **Must be true:** Every skipped file is attributed to exactly one label under lock_counts with no lost updates across concurrent workers: the breakdown sums to the total and to scan_summary's files_skipped, and both grains are represented — the two walk-time keys alongside at least one dequeue-time key that only a worker can produce.
- **Threshold:** sum(skip_breakdown.values()) == data.total_skipped == scan_summary_<run_id>.json files_skipped, delta 0, on a run with max_workers >= 4 and files_skipped >= 500; skip_breakdown contains both walk-grain keys ("Skipped directory", "Junction/symlink skip") and at least two dequeue-grain keys from {"File does not exist","No read permission","Not a regular file","File too large","Scan error (...)"}
- **Setup:** Round 3's crafted run with all gates planted (see TRAV-050/052/053/055 setups) and workers left at the default or raised via options workers=8, so the lock is actually contended.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log "Skip reasons: ..." data.total_skipped and data.skip_breakdown; scan_summary_<run_id>.json files_skipped; source: _worker's `with self.lock_counts:` block increments files_skipped and skip_reasons[reason] from scan_file's return value; the walk-time sites increment "Skipped directory" (at whole-directory grain) and "Junction/symlink skip" under the same lock
- **Negative control:** A file planted purely to trip the size gate must land under "File too large" ONLY and must not also inflate "Skipped directory" or "Junction/symlink skip"; and files_scanned must be > 0, so the identity is not satisfied by skipping everything.

### `TRAV-065` Mid-walk exception on a scan target silently abandons the rest of that tree and erases its per-target row

*core*

- **Must be true:** On a healthy uncancelled run every requested target produces its own "Target scan completed" entry — a per-target row count below target_count with the run still reporting success is the signature of a swallowed mid-walk exception, and the comprehensive report's targets_scanned would still list the lost target.
- **Threshold:** count("Target scan completed:") == 'target_count' from the "Scan configuration established" entry, exactly; count("Error scanning target") in scan_errors_<run_id>.log == 0; and, for every target named in the comprehensive report's scan_metadata.targets_scanned, a matching "Target scan completed" entry exists
- **Setup:** Multi-target Round 3 run with at least three targets. The bare `except Exception: ... continue` cannot be provoked by file content — _walk_cancellable absorbs PermissionError/NotADirectoryError/FileNotFoundError/OSError per directory and _enqueue_scan_path absorbs its own — so this is asserted as an equality on a healthy run, not by forcing the exception. Rule out a cancel first: `if not self.scan_active: break` at the top of the target loop drops remaining targets the same way, so scan_summary "outcome" must be "completed" and "cancel_source" must be null.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log "Target scan completed: <target>" entries and the "Scan configuration established" entry's data.target_count; <scanner_dir>/logs/scan_errors_<run_id>.log "Error scanning target <path>: <exception>" (the file is scan_errors_<run_id>.log, not errors_<run_id>.log); the "COMPREHENSIVE SCAN REPORT" entry's scan_metadata.targets_scanned, which is assigned from the requested list before the walk and so still names a target that produced no row; scan_summary_<run_id>.json "outcome"

### `TRAV-066` Deployer-supplied extra skip fragments (`YARA_EXTRA_SKIP_PATHS`)

*core*

- **Must be true:** The env var adds bounded, component-anchored skip fragments without replacing the built-ins: the named directory yields zero findings, a sibling directory not named still yields findings, the built-in Cortex agent paths remain excluded, and a lone "/" entry is rejected instead of disabling the scan.
- **Threshold:** With YARA_EXTRA_SKIP_PATHS="yara_excl": alert/<rule>.txt contains 0 lines under /tmp/yara_probe/yara_excl/ and >=1 line under /tmp/yara_probe/yara_incl/; ADDITIVITY is proven against a built-in entry of the SAME list — /tmp/yara_probe/node_modules/decoy.bin must still yield 0 alert lines, because "/node_modules/" is a built-in skip_path_fragments entry and a substitute-rather-append build would have dropped it; a substring-only sibling /tmp/yara_probe/yara_exclusive/decoy.bin is still SCANNED and matched (the fragment is normalised to the bounded "/yara_excl/" form and also tail-tested as "/yara_excl", neither of which closes inside "yara_exclusive"). Test /opt/traps only after confirming `test -d /opt/traps` on the endpoint — it is in lin_skip_directory, not skip_path_fragments, so it is corroboration, not the additivity test.
- **Setup:** Set YARA_EXTRA_SKIP_PATHS on the endpoint (machine environment, agent service restarted so the payload inherits it). Plant identical decoys in /tmp/yara_probe/yara_excl/, /tmp/yara_probe/yara_incl/ and /tmp/yara_probe/yara_exclusive/; run with scan_folder="/tmp/yara_probe,/opt/traps". Second run with YARA_EXTRA_SKIP_PATHS="/" to check the rejection.
- **Evidence:** <scanner_dir>/alert/<rule>.txt; scan_summary_<run_id>.json "excluded_targets"; skip_breakdown["Skipped directory"] in the "Skip reasons: ..." statistics entry. For the lone-"/" case the message is "Ignoring YARA_EXTRA_SKIP_PATHS entry '/' - it matches every path and would disable the scan" — and it appears on the Action Center's STDERR, not in diagnostics_<run_id>.log: _extra_skip_fragments runs inside ScanConfig.__init__, which main() calls before setup_logging() installs the diagnostics FileHandler, so logging.warning falls through to the last-resort stderr handler. The catalogue's Observe field is stale on this point.
- **Negative control:** Three controls in one run: (a) /tmp/yara_probe/yara_incl/ (not named) must be scanned and matched — separates "skipped something" from "skipped everything"; (b) /tmp/yara_probe/yara_exclusive/ must be scanned and matched — proves the bounding to whole components, i.e. that the fragment is not a loose substring evasion vector; (c) /tmp/yara_probe/node_modules/ must still be SKIPPED — proves the env var was appended to skip_path_fragments and not substituted for it. Control (c) is the one the original /opt/traps clause was trying and failing to provide.

### `TRAV-067` Boundary skips the force-scan allowlist may never override (`force_scan_never_under`)

*core*

- **Must be true:** A force-scan allowlist fragment is honoured on this host but is blocked at the mount boundaries: an identical browser-cache path under /mnt/ produces zero findings while the same path outside those roots is force-scanned and matched — and /mnt/ appears in no other skip list, so only force_scan_never_under can explain the difference.
- **Threshold:** alert/<rule>.txt contains >=1 line "YARA rule '<rule>' matched file: /opt/yara_probe/library/caches/google/chrome/decoy.bin" and 0 lines naming any path under /mnt/; an XQL row exists with that /opt path in the **filename** column and none with a /mnt/ path; skip_breakdown["Skipped directory"] >= 1 (the /mnt/ tree is dropped at the .../library/caches root, which matches skip_path_fragments once the boundary guard has disabled the allowlist).
- **Setup:** On xdr-agent: `sudo mkdir -p /opt/yara_probe/library/caches/google/chrome /mnt/yara_probe/library/caches/google/chrome` and plant identical decoy.bin in both; run with scan_folder="/opt/yara_probe,/mnt/yara_probe". Linux is the isolating host: /mnt/ is in force_scan_never_under only — it is absent from lin_skip_directory and from skip_path_fragments — whereas on macOS /Volumes/ is ALSO in mac_skip_directory and so cannot separate the two mechanisms.
- **Evidence:** /opt/yara_scanner/alert/<rule>.txt; /opt/yara_scanner/logs/statistics_<run_id>.log "Skip reasons: ..." data.skip_breakdown["Skipped directory"]; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields filename, rule` — the column is `filename` and it carries the full path (there is no file_path column in matches_schema); source: _is_special_file evaluates `if not any(b in _probe for b in force_scan_never_under)` BEFORE consulting force_scan_fragments, with force_scan_never_under == ('/volumes/','/media/','/mnt/','/net/').
- **Negative control:** /opt/yara_probe/library/caches/google/chrome/decoy.bin must be scanned and matched. Without it the boundary guard is indistinguishable from the '/library/caches/' skip fragment simply excluding both paths — that control is what proves the allowlist itself still works and only the boundary suppressed it.

## Performance & Resource Management

### `PERF-023` Worker queue-get timeout and cooperative exit checks

*supporting*

- **Must be true:** Workers observe the cancel within one queue-get timeout: every worker writes its stop record within ~5s of the cancellation request, and each stop record carries a files_processed count.
- **Threshold:** For every ScanWorker-N: the timestamp of its 'Worker ScanWorker-N stopped' entry minus the timestamp of the 'Cancellation requested (source=...)' entry is <= 6.0s (the 5.0s literal get timeout plus one in-flight file), except for a worker still inside rules.match on a large file. Count of 'Worker ... stopped' entries == max_workers. Each carries data.files_processed and data.errors_encountered as integers. The 'Worker cleanup: N stopped, M timed out in X.Xs' line reports N == max_workers and M == 0.
- **Setup:** Round 3's long crafted scan; write <scanner_dir>/control/cancel.flag mid-walk (never the console Cancel button — it hard-kills the payload and orphans the lifecycle row).
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log — the 'Cancellation requested (source=...)' entry and each 'Worker ScanWorker-N stopped' entry with data.files_processed / data.errors_encountered / data.average_processing_time_ms; <scanner_dir>/logs/performance_<run_id>.log 'Worker cleanup: N stopped, M timed out in X.Xs'. Code: YaraScanner._worker's `self.scan_queue.get(timeout=5.0)` inside `while self.scan_active`, and the finally-block stop record.
- **Why this round:** Departs from the PERF prior. The 5.0s timeout only has an observable consequence when the queue goes quiet while scan_active flips — on a normal completion the sentinels wake workers immediately and the timeout never fires. Cancellation is the only condition that drives this code, and ROUNDS.md settles cancellation into Round 3.

### `PERF-026` Sentinel-based worker shutdown with bounded joins

*supporting*

- **Must be true:** Shutdown puts exactly one sentinel per worker and every worker is accounted for in the cleanup tally; the real join budget is max_workers * 5s, which is not what the log line advertises.
- **Threshold:** 'Worker cleanup: N stopped, M timed out in X.Xs' has N + M == max_workers exactly. On a cooperative cancel M == 0 and no 'Worker thread <name> did not finish - continuing anyway' or 'Threads did not terminate: [...]' lines appear in scan_errors_<run_id>.log. Measured X.X <= max_workers * 5.0 + 1.0. On a run with options `workers=8` the real budget is 40s while the preceding system-log line still reads 'Waiting for workers to terminate (max 30 seconds)' — record the discrepancy as a documentation defect, not a pass/fail.
- **Setup:** Round 3 cancel run (PERF-023 setup), repeated once with options `workers=8` to expose the advertised-vs-real budget mismatch.
- **Evidence:** <scanner_dir>/logs/performance_<run_id>.log 'Worker cleanup: N stopped, M timed out in X.Xs'; <scanner_dir>/logs/system_<run_id>.log 'Initiating worker thread cleanup' and 'Waiting for workers to terminate (max 30 seconds)'; <scanner_dir>/logs/scan_errors_<run_id>.log 'Worker thread <name> did not finish - continuing anyway' and 'Threads did not terminate: [...]'. Code: _perform_enhanced_cleanup — `for _ in range(self.config.max_workers): self.scan_queue.put(None, timeout=1.0)` then `t.join(timeout=5)` per thread.
- **Why this round:** Departs from the PERF prior. On a clean completion the sentinels are consumed instantly and the bounded-join logic never exercises its bound; the tally only becomes discriminating when teardown races live work, which is Round 3's mid-walk cancellation. ROUNDS.md also names 'thread cleanup and shutdown ordering' under Round 3.

### `PERF-038` Cancel-flag watcher poll thread

*core*

- **Must be true:** A cancel flag written during the scan is honoured within one poll interval and named in the outcome, while a flag left over from a previous run is removed instead of cancelling the new scan.
- **Threshold:** Fresh cancel: the 'Cancellation requested (source=...)' entry appears within CANCEL_POLL_SECS + 1 = 6.0s of the flag write (capture `date +%s.%N` at the write); scan_summary.outcome == 'cancelled' and scan_summary.cancel_source equals the `source` value in the flag JSON. Stale flag: a cancel.flag whose mtime is at least 60s older than the 'YaraScanner initialized with N workers' system-log entry produces 'Removed stale cancel flag from a previous run', the file no longer exists, and that run reaches outcome == 'completed' with no 'Cancellation requested' entry. BOUNDARY: the baseline is _process_started_at, set inside YaraScanner.__init__ — NOT process launch, which precedes it by the whole ScanConfig/LogManager/priority/initial-cleanup block. Plant run (c)'s flag AFTER the 'YARA Scanner initialized successfully' entry is written (that record immediately precedes the YaraScanner(...) construction) and BEFORE '=== STARTING ENHANCED SYSTEM SCAN', using a large rule pack to widen that window; such a flag has mtime > _process_started_at - 2.0, must be PRESERVED, and must cancel the scan once the watcher starts. A flag timed only by 'seconds after launch' is undecidable and must not be used.
- **Setup:** Three Round 3 runs: (a) write <scanner_dir>/control/cancel.flag over SSH ~60s into a long scan; (b) pre-plant a cancel.flag, `touch -d '-60 seconds'` it, then start a scan; (c) start a scan with a large rule pack and write the flag ~1s after launch, during compilation. Never use the console Cancel button.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log entries 'Cancellation requested (source=…)' and 'Removed stale cancel flag from a previous run'; <scanner_dir>/logs/scan_summary_<run_id>.json fields outcome and cancel_source; the wall-clock of the flag write vs the log entry. Code: _start_cancellation_watcher (mtime < _process_started_at - CANCEL_STALE_TOLERANCE_SECS), _cancellation_watcher (`time.sleep(CANCEL_POLL_SECS)`), _request_cancel.
- **Negative control:** The staleness test must not eat live flags: run (c)'s flag, written after process start, must survive and cancel the scan. A build that removes every pre-existing flag passes run (b) and fails run (c).
- **Why this round:** Departs from the PERF prior. ROUNDS.md settles cancellation into Round 3, and both the fresh-cancel latency and the stale-flag boundary need a long crafted scan with a deliberately planted flag — Round 1's clean run has nothing to cancel and would only exercise the watcher's idle loop.

### `PERF-039` Stack-driven cancellable directory walk

*core*

- **Must be true:** Cancellation latency is bounded by one scandir, not by an os.walk generator: the process reaches terminal state promptly after the cancel and the liveness marker is removed only after cleanup returns.
- **Threshold:** Use the REPORTED value, not the log-entry delta: the X.X in 'Enhanced cleanup completed in X.X seconds' must be <= max_workers * 5.0 + 12.0 (that figure is computed before the uploaders are stopped, whereas the entry's wall-clock timestamp lands after a drain window of up to ALERT_DRAIN_MAX_SECS = 300s and is not a measure of walk-cancellation latency). Walk latency proper: the wall-clock gap from the cancel.flag write to the 'Cancellation requested (source=…)' entry <= CANCEL_POLL_SECS + 1 = 6.0s, and from that entry to the 'Worker cleanup: N stopped, M timed out' performance line <= max_workers * 5.0 + 6.0 — this is the interval the explicit-stack walk bounds, against the ~50s post-cancel tail the os.walk generator left on C:\. Process exit: <= 90s after the cancel.flag write (poll + joins + drain + summary write), NOT 10s. scan_summary.outcome == 'cancelled' and files_scanned strictly less than the file count under the target. <scanner_dir>/control/running.json still exists at the moment 'Enhanced cleanup completed' is written and is gone within 2s afterwards (_remove_running_marker is called after _perform_enhanced_cleanup returns).
- **Setup:** Round 3 long crafted scan over a deep tree with many directories; write control/cancel.flag mid-walk (well before discovery finishes). Poll for the payload PID's disappearance from `ps` and for running.json's existence once per second over SSH.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log — timestamps of 'Cancellation requested (source=…)' and 'Enhanced cleanup completed in X.X seconds'; <scanner_dir>/logs/scan_summary_<run_id>.json outcome and files_scanned; the per-second `ls <scanner_dir>/control/running.json` and `ps` captures. Code: YaraScanner._walk_cancellable (explicit stack, `if not self.scan_active: return` before every scandir and between entries), its call site in scan_system, and _remove_running_marker called after _perform_enhanced_cleanup returns.
- **Why this round:** Departs from the PERF prior for the reason ROUNDS.md settles: only a long crafted scan can be cancelled mid-walk rather than during teardown, and mid-walk is the only condition under which the explicit-stack traversal differs observably from os.walk.

### `PERF-052` Per-file size cap (bounds YARA memory and time per file)

*supporting*

- **Must be true:** Files strictly larger than max_file_bytes are rejected before rules.match() and counted under exactly the skip reason 'File too large', while a file just under the cap is scanned and can still match.
- **Threshold:** max_file_mb == 64 (YARA_MAX_MB default, minimum=0 guard). skip_breakdown['File too large'] == 2 for the planted 65 MB and 200 MB decoys; the 63 MB decoy is scanned and produces a yara_scanner_matches_v3_* row. Control run with YARA_MAX_MB=0: skip_breakdown has no 'File too large' key and all three decoys match.
- **Setup:** Plant three files containing the pack's match string at 63 MB, 65 MB and 200 MB under the Round 3 target so the boundary is crossed in both directions.
- **Evidence:** files_skipped in <scanner_dir>/logs/scan_summary_<run_id>.json; data.skip_breakdown['File too large'] in the 'Skip reasons: ' record in logs/statistics_<run_id>.log; max_file_mb in the 'YARA Scanner initialization completed' init_data record and in the 'YaraScanner initialized with N workers' record, both in logs/system_<run_id>.log; the 63 MB path present in yara_scanner_matches_v3_* for this scan_id.
- **Negative control:** The 63 MB decoy must be scanned and must produce a match — a build that rejected every large file would also report a non-zero 'File too large' count and pass the positive half alone. The YARA_MAX_MB=0 control must scan all three, proving the gate is the cap and not the files themselves.
- **Why this round:** Dimension prior is Round 1, but ROUNDS.md assigns 'size and special-file gates' to Round 3 and the cap is only decided by planted files straddling 64 MB — a crafted-tree probe, not a footprint measurement. Round 1's clean real tree contains no controlled boundary case.

### `PERF-060` DORMANT: real-path deduplication set

*low*

- **Must be true:** Real-path deduplication stays off for the whole run: unique_real_paths and unique_paths_scanned are 0 in every record and 'Junction/symlink duplicate' never appears in skip_breakdown — even on a run that did traverse and skip reparse points.
- **Threshold:** config.track_real_paths is a hardcoded False (no constant, no env var, no options key). data.metrics.unique_real_paths == 0 in every 'Scan Progress' record; data.unique_paths_scanned == 0 in the final metrics; skip_breakdown has no 'Junction/symlink duplicate' key; junction_skips > 0 on the same run.
- **Setup:** Round 3 tree containing at least one directory symlink/junction and one file reachable through two paths, so the dedup set would be provably non-empty if the flag were live.
- **Evidence:** data.metrics.unique_real_paths in 'Scan Progress | Files:' records and data.unique_paths_scanned in the 'SCAN COMPLETED | Time:' record, both in <scanner_dir>/logs/statistics_<run_id>.log; data.skip_breakdown in the 'Skip reasons: ' record in the same file.
- **Negative control:** junction_skips must be > 0 on the same run, which requires a reparse point the platform list actually matches. On the Windows endpoint (xdragent2): create a junction named 'Application Data' inside the Round 3 target. On the Linux endpoint: include /proc/self among the scan targets so the walk reaches /proc/self/fd and /proc/self/task. A generic symlink named anything else is skipped by NEITHER branch and leaves junction_skips at 0, making 'dormant' and 'never reached' indistinguishable.
- **Why this round:** The flag is dormant in every round; the assertion only has teeth on a run that actually traverses junctions and hardlinks, which is Round 3's planted reparse-point tree, not Round 1's ordinary filesystem walk.

### `PERF-061` Compiled-rule disk cache (XDR edition only)

*core*

- **Must be true:** An identical rule pack re-delivered to the same endpoint loads from disk instead of recompiling, and the run summary names which of the two happened.
- **Threshold:** Run 1: compile_source == 'fresh', one 'Rule compile FRESH <secs>s' line, and a rules_<40hex>.yarac plus its .meta.json appear under <scanner_dir>/rule_cache/. Run 2 with the byte-identical pack: compile_source == 'cache', compile_seconds < 0.25 x run 1's compile_seconds, one 'Rule cache HIT rules_<key>.yarac load=' line and zero 'Rule compile FRESH' lines. RULE_CACHE_ENABLED defaults on (YARA_RULE_CACHE); format tag '1'.
- **Setup:** Round 3: deliver the same large pack (~500 rules, where the fresh compile costs tens of seconds) twice back to back, then a third time with one byte changed.
- **Evidence:** compile_source and compile_seconds in <scanner_dir>/logs/scan_summary_<run_id>.json; the 'Rule cache HIT ', 'Rule cache miss/unusable, compiling fresh: ' and 'Rule compile FRESH ' records in logs/system_<run_id>.log; directory listing of <scanner_dir>/rule_cache/.
- **Negative control:** The third run, with one byte changed in the pack, must come back compile_source == 'fresh' and write a second, differently named rules_*.yarac — the key covers rule text, module set, externals, yara version and format tag, so a cache that hits on a changed pack is worse than no cache.
- **Why this round:** ROUNDS.md assigns the compile cache and its sidecar to Round 3, and a HIT is only reachable by compiling the identical pack twice — which only the crafted-pack round does. Round 1 runs one ruleset once.

### `PERF-062` Rule-cache size bounds and LRU pruning

*supporting*

- **Must be true:** The cache directory never holds more than RULE_CACHE_MAX_FILES compiled bundles or RULE_CACHE_MAX_BYTES in total, the entries deleted are the oldest by mtime, and every surviving .yarac keeps its .meta.json sidecar.
- **Threshold:** 5 files / 268435456 bytes (256 MB), from YARA_RULE_CACHE_MAX and YARA_RULE_CACHE_MAX_MB. After compiling 7 distinct packs in a known order: exactly the 5 newest-by-mtime rules_*.yarac remain, each with its matching .meta.json, total under 256 MB (confirm the sum, since the byte cap would otherwise prune more and the file-count claim would pass for the wrong reason), and the two oldest keys are gone. Temp sweep: before the 7th compile, plant two orphans matching the real shape rules_<40hex>.yarac.<pid>.<8hex>.tmp — one with `touch -d '-2 hours'`, one fresh — and assert the aged one is removed and the fresh one survives. LRU touch: after re-delivering pack #3 (cache HIT, os.utime), compile an 8th distinct pack and assert pack #3 survives that prune while pack #4 is deleted.
- **Setup:** Round 3: seven distinct crafted packs compiled in sequence, then re-deliver pack #3 and confirm its mtime is refreshed by the cache HIT (os.utime LRU touch) so it survives the next prune instead of the newest-compiled entry.
- **Evidence:** `ls -l --time-style=full-iso <scanner_dir>/rule_cache/` before and after the seventh compile and again after the pack #3 re-delivery; the 'Rule cache HIT ' record naming the touched file in <scanner_dir>/logs/system_<run_id>.log.
- **Negative control:** The most recently used pack must still be present after the prune and must still report compile_source == 'cache' — a prune that emptied the directory would also satisfy 'at most 5 files'.
- **Why this round:** Pruning is driven by MANY DISTINCT packs. Round 1 runs a single ruleset and can never exceed the 5-file bound, so only the crafted-pack round reaches this code at all.

### `PERF-063` Rule-cache counts sidecar restore

*supporting*

- **Must be true:** On a cache HIT the valid and failed rule counts come back from the .meta.json sidecar instead of reading zero, because the per-rule compile loop is skipped — but the skipped-rules count does NOT: it is restored only into the 'Rule cache HIT' log line, so scan_summary.skipped_rules reads 0 and the result line loses its 'rules skipped (module unavailable)' segment that the fresh run carried.
- **Threshold:** On the run whose compile_source == 'cache': scan_summary valid_rules and failed_rules each equal the fresh run's values exactly and are both non-zero; the 'Rule cache HIT ... (valid=… failed=… skipped=…)' line reports all three matching the sidecar, with skipped non-zero; but scan_summary.skipped_rules == 0 and the returned result line contains no ' rules skipped (module unavailable)' segment, whereas the fresh run's does. That asymmetry is the assertion — error_logger.skipped_rules_count has no writer on the restore path.
- **Setup:** The cache-HIT run of PERF-061's pack, where the pack deliberately contains at least one rule that fails to compile and at least one skipped for an unavailable module, so all three counts are non-zero and a zero would be unmistakable.
- **Evidence:** valid_rules / failed_rules / skipped_rules alongside compile_source in <scanner_dir>/logs/scan_summary_<run_id>.json for BOTH the fresh and the cache run; the 'Rule cache HIT ' record in logs/system_<run_id>.log; the contents of <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json; and the returned result-line text for both runs (the ' | N rules skipped (module unavailable)' segment).
- **Negative control:** Delete only the .meta.json sidecar and re-run: valid_rules must fall back to the loaded bundle's own rule count (non-zero) while failed_rules and skipped_rules read 0. That distinguishes 'restored from the sidecar' from 'recomputed by re-running the compile loop'.
- **Why this round:** ROUNDS.md places the compile cache and its sidecar in Round 3, and the restore path only exists on a HIT, which requires the same pack compiled twice.

### `PERF-071` Tuning-knob parse guard with minimum validation

*supporting*

- **Must be true:** An unparseable or out-of-range tuning env var is ignored with a named warning and the documented default is used — the scan still runs and does not adopt the bad value.
- **Threshold:** YARA_THREADS=x: stderr carries "Ignoring invalid YARA_THREADS='x' (expected a number) - using default 2" and init_data max_workers == 2. YARA_MAX_MB=-1: stderr carries "Ignoring out-of-range YARA_MAX_MB='-1' (minimum 0) - using default 64", init_data max_file_mb == 64 (not -1) and files_scanned > 0 (the negative value previously made max_file_bytes negative and skipped every file).
- **Setup:** Two short Round 3 runs over SSH with the bad env values exported and stderr captured. These warnings fire before setup_logging() installs the diagnostics handler, so they surface through the root logger's stderr path and are not in any log file.
- **Evidence:** stderr of the run; max_workers, scan_queue_size and max_file_mb in the 'YARA Scanner initialization completed' init_data record in <scanner_dir>/logs/system_<run_id>.log; files_scanned in logs/scan_summary_<run_id>.json.
- **Negative control:** A valid YARA_THREADS=4 run must report max_workers == 4 and emit NO 'Ignoring' line. A guard that rejected every supplied value would also fall back to the default and look identical on the bad-value run alone.
- **Why this round:** Prior is Round 1, but ROUNDS.md assigns 'deliberately bad option strings and env values' to Round 3, and nothing but a deliberately malformed env value drives this branch.

### `PERF-072` CPU percentage inputs are unvalidated (the clamp helper is dead)

*low*

- **Must be true:** An absurd cpu_headroom_pct is accepted verbatim rather than clamped to 1..100 — the echoed config shows the raw value, and it is the governor's floor, not input validation, that keeps the scan moving.
- **Threshold:** Defaults 30 / 25 / 5, unclamped (_clamp_pct and _coerce_float have no call sites). With options="cpu_headroom_pct=200": THROTTLE_CONFIG echoes cpu_headroom_pct 200.0 (not 100.0); every CPU_GOVERNOR record has target == 5.0 (CONFIG_CPU_FLOOR_PCT); cpu_governor.floor_hits equals cpu_governor.samples_taken within 1; files_scanned > 0.
- **Setup:** Short Round 3 scan invoked with options="cpu_headroom_pct=200" on a host with no YARA_CPU_GUARANTEE exported.
- **Evidence:** The 'THROTTLE_CONFIG ' record and the 'CPU_GOVERNOR ' records in <scanner_dir>/logs/performance_<run_id>.log; cpu_governor.floor_hits, cpu_governor.target and cpu_governor.samples_taken in logs/scan_summary_<run_id>.json.
- **Negative control:** A control run at the default headroom of 30 on an idle host must show target ≈ 70 - others and floor_hits == 0 — otherwise 'always floored' is indistinguishable from 'the input was clamped to something sane'.
- **Why this round:** Prior is Round 1, but the code path is driven by a deliberately bad option value, which ROUNDS.md places in Round 3. Running a 200% headroom scan inside Round 1 would also corrupt the very timings that round exists to measure.

### `PERF-073` Retired throttle options are translated, not rejected

*supporting*

- **Must be true:** A retired throttle_* key is accepted and translated to its CPU-governor equivalent, while an unrecognised key is rejected outright with a named error and no scan starts at all.
- **Threshold:** throttle_mode=off -> throttle_mode 'none' and posture 'cpu=none'; throttle_mode=script -> 'headroom'; throttle_mode=os -> 'headroom'; throttle_mode=nonsense -> 'headroom' (unknown maps to headroom). options="frobnicate=1" -> the action fails with the exact text "Unknown option 'frobnicate'. Valid keys: collect_files, cpu_budget_pct, cpu_floor_pct, cpu_guarantee, cpu_headroom_pct, create_alerts, lookup_shard, tenant_id, workers, write_dataset".
- **Setup:** Five short Round 3 invocations differing only in the options string, on a host with no YARA_CPU_GUARANTEE exported (an exported env var would outrank the option — see PERF-085).
- **Evidence:** throttle_mode and posture in <scanner_dir>/logs/scan_summary_<run_id>.json; the throttle_mode and posture columns of the yara_scanner_scans_v3_* row for each run; the returned action result text and stderr for the bogus-key run.
- **Negative control:** The bogus-key run must leave NO new run_id artefacts — _parse_options_string raises before ScanConfig is constructed, so no logs/ files and no scan_summary_<run_id>.json for that run may exist. A build that logged the error and scanned anyway would still print the message but would leave a summary behind.
- **Why this round:** ROUNDS.md gives Round 3 'the options string and its validation and precedence'; nothing about a long resource-discipline scan drives this parser.

### `PERF-077` Scan phase tracking (initializing → … → completed)

*supporting*

- **Must be true:** The phase ladder is a state machine, not a fixed script: a completed run writes initializing, starting_workers, scanning, finishing, completed exactly once each in that order, while a cooperatively cancelled run stops at 'finishing' and never reaches 'completed' — its cancellation is recorded instead by scan_summary.outcome == 'cancelled' with a cancel_source, and by the terminal yara_scanner_scans_v3_* row's status column reading 'cancelled'.
- **Threshold:** Completed run: 'Scan status changed to: ' lines for initializing, starting_workers, scanning, finishing, completed, each exactly once, in that order. Cancelled run: the same ladder through 'finishing' and NO 'Scan status changed to: completed' line — and no 'Scan status changed to: cancelled' line either, because no such call site exists; the cancel is evidenced by scan_summary outcome == 'cancelled' with a non-empty cancel_source and by status == 'cancelled' on the terminal scans row. Do not require 'finishing' to post-date the last Scan Progress record: it is set at the top of _perform_enhanced_cleanup, before the worker join and before the progress heartbeat is stopped, so progress records legitimately follow it.
- **Setup:** Two Round 3 runs — one clean crafted-pack scan, and one long scan cancelled mid-walk by writing <scanner_dir>/control/cancel.flag over SSH. Do NOT use the console Cancel button: it hard-kills the payload and orphans the lifecycle row.
- **Evidence:** 'Scan status changed to: ' lines with timestamps in <scanner_dir>/logs/diagnostics_<run_id>.log; outcome and cancel_source in logs/scan_summary_<run_id>.json; the status column of the terminal yara_scanner_scans_v3_* row (which carries only the coarse lifecycle status — no phase label is written into the dataset row).
- **Negative control:** The completed run must carry 'Scan status changed to: completed' and scan_summary outcome 'completed' with cancel_source null; the cancelled run must carry neither, and its terminal scans row must read 'cancelled' while the completed run's reads 'completed'. The phase ladder alone cannot separate the two outcomes past 'finishing' — that is the finding, and both sides are needed to show it.
- **Why this round:** The normal ladder runs in all three rounds, but only Round 3's mid-walk cancellation exercises the abort transitions that distinguish a real state machine from a hardcoded sequence of log lines.

### `PERF-078` Final efficiency score and comprehensive report

*supporting*

- **Must be true:** The efficiency score is exactly the documented arithmetic applied to this run's own numbers, and it is readable from the message text even when the nested payload is truncated.
- **Threshold:** score == max(0, 100 - 20*(files_skipped/(files_scanned+files_skipped)) - 30*(failed_rules/(failed_rules+valid_rules))), agreeing to +/-0.1 with scan_summary's own values, printed to one decimal as 'Efficiency Score: NN.N/100'. BOTH terms must be non-zero on the run: the Round 3 pack must contain rules that fail to compile (failed_rules > 0) and the crafted tree must produce skips (files_skipped > 0), otherwise the 30 weight and the 20 weight are not separately testable. Weights 20 and 30, base 100.
- **Setup:** Round 1 whole-filesystem scan — a large skip_breakdown drives the score visibly below 100 and simultaneously forces the 4000-char payload truncation this record is the best example of.
- **Evidence:** The 'COMPREHENSIVE SCAN REPORT | Efficiency Score: ' line in <scanner_dir>/logs/statistics_<run_id>.log; files_scanned, files_skipped, valid_rules and failed_rules in logs/scan_summary_<run_id>.json.
- **Negative control:** Run the same crafted tree twice — once with the malformed pack (failed_rules > 0) and once with the same pack's valid rules only (failed_rules == 0) — and confirm the score differs by exactly 30*(failed/(failed+valid)). A single run cannot separate the two weights: a build with the wrong rule-failure weight scores identically whenever failed_rules is 0.

### `PERF-085` Env vars outrank the options string for cpu_guarantee and workers (documented precedence is reversed)

*core*

- **Must be true:** An exported YARA_CPU_GUARANTEE or YARA_THREADS wins over the same key supplied in the options string — the reported effective values are the env ones and the operator's option is silently discarded, contrary to the documented 'options override' precedence.
- **Threshold:** Invoked with options="cpu_guarantee=budget,workers=8" on a host exporting YARA_CPU_GUARANTEE=none and YARA_THREADS=1: scan_summary throttle_mode == 'none' (not 'budget'), posture contains 'cpu=none', cpu_governor.policy == 'none', total_paused_secs == 0.0, the result line contains 'cpu-slept 0s', and init_data max_workers == 1 (not 8). Baselines: CONFIG_CPU_GUARANTEE 'headroom', CONFIG_WORKERS 2.
- **Setup:** One Round 3 run over SSH with both env vars exported and the contradicting options string supplied.
- **Evidence:** throttle_mode, posture, total_paused_secs and cpu_governor in <scanner_dir>/logs/scan_summary_<run_id>.json; max_workers in the 'YARA Scanner initialization completed' init_data record in logs/system_<run_id>.log; the throttle_mode and posture columns on the yara_scanner_scans_v3_* row for this scan_id; the returned result line.
- **Negative control:** The same options string with NO env vars exported must yield throttle_mode 'budget', 'cpu=budget' in posture and max_workers 8 — proving the options path works and that the env var is specifically what overrode it, rather than the options string being ignored altogether.
- **Why this round:** Prior is Round 1, but this is a precedence property of the options string, which ROUNDS.md assigns to Round 3, and it is driven entirely by how the run is invoked rather than by any scan shape.

## Local Storage & Host Footprint

### `STOR-005` yara_processing_<run_id>.log — the rule-compilation audit trail

*supporting*

- **Must be true:** On a fresh compile the audit log opens with its five header RECORDS (the first of which spans two physical lines, because sys.version embeds a newline) and carries exactly one COMPILATION SUMMARY whose Total equals Valid + Failed, reconciling with the scan summary, with the failed_rules pointer present iff Failed > 0 and module-skipped rules counted separately from both Valid and Failed.
- **Threshold:** Header records in order: '=== YARA Processing Log ===', 'Python Version:', 'Platform:', 'YARA Version:', then a 50-'=' rule — five records, with the Python Version record occupying two physical lines. Exactly one 'COMPILATION SUMMARY'. 'Total rules processed: T' == 'Valid rules compiled: V' + 'Failed rules skipped: F'; V == scan_summary.valid_rules and F == scan_summary.failed_rules and V >= 1 and F >= 1 (both non-zero, or the reconciliation is vacuous). 'Failed rules saved to: /opt/yara_scanner/failed_rules' present iff F > 0; with failed_rules/ emptied before the run it then holds exactly F files matching failed_rule_*.yar, one per rule that failed in THIS run (match by name), each opening '// FAILED RULE - Compilation Error'. Module-skipped rules are NOT folded into F or V: the aggregate 'Skipped N rules due to unavailable modules' record has N == scan_summary.skipped_rules, and the same file additionally carries min(N,10) 'SKIP (module unavailable): rule ' records and failed_rules/ carries N skipped_rule_*.yar dumps — neither of which may be counted as failures.
- **Setup:** Round-3 crafted pack with >=1 syntactically broken rule, >=1 rule importing a module this agent's libyara lacks, and >=1 good rule. Vary the rule text so the compile cache misses — scan_summary.compile_source must read 'fresh'. Before delivering, EMPTY failed_rules/ over SSH (`rm -f /opt/yara_scanner/failed_rules/*`): initial_cleanup never prunes that directory (it is not in paths_to_clean), so dumps from earlier Round-3 runs would otherwise still be there and the per-run count assertion could not hold.
- **Evidence:** /opt/yara_scanner/logs/yara_processing_<run_id>.log; valid_rules / failed_rules / skipped_rules in logs/scan_summary_<run_id>.json; `ls /opt/yara_scanner/failed_rules`.
- **Negative control:** On a compile_source=='cache' run the same file must contain the header and NO 'COMPILATION SUMMARY' — its absence there is correct behaviour, not a failure.
- **Why this round:** Dimension prior is storage (Round 1), but the file's content is only produced on a FRESH compile of a pack that actually contains broken and module-dependent rules. On a rule-cache HIT the per-rule loop is skipped and log_compilation_summary is never called at all, so a Round-1 repeat run leaves the file holding only its header — a Round-1 criterion on the summary block would fail a correct build.

### `STOR-006` script_exceptions_<run_id>.log — lazily created, so a clean run leaves no empty file

*supporting*

- **Must be true:** script_exceptions_<run_id>.log is absent entirely on every run whose exception never reached run()'s outer handler, and is created banner-first on the run that does crash there.
- **Threshold:** Crash run: file exists; first record '=== SCRIPT EXCEPTION LOG INITIALIZED ==='; contains 'Context: main_function_critical_error', 'Exception Type: ValueError', and '=== EXCEPTION #1 ===' exactly once; scan_errors_<run_id>.log contains 'CRITICAL_ERROR: Critical scanner error: No valid YARA rules could be compiled out of'; NO scan_summary_<run_id>.json exists for that run_id (the finally block needs a constructed scanner, and YaraScanner.__init__ is where the raise happened). Every other Round-3 run: `ls logs/script_exceptions_*` returns nothing for their run_ids.
- **Setup:** One extra Round-3 run with a pack in which every rule body is uncompilable but at least one 'rule X {' declaration is present, so decode_yara_rules passes inside ScanConfig and the ValueError is raised later out of YaraScanner.__init__, after run() has bound its exception_logger local (a failure inside ScanConfig itself leaves that local None and produces no file).
- **Evidence:** `ls /opt/yara_scanner/logs/script_exceptions_*.log`; the file's first four records; the CRITICAL_ERROR line in scan_errors_<run_id>.log; absence of logs/scan_summary_<run_id>.json.
- **Negative control:** A pack with SOME broken rules and at least one good one must produce NO script_exceptions file — per-rule compile failures are handled, not exceptional.
- **Why this round:** Dimension prior is storage (Round 1), but the file only exists when an exception reaches run()'s outer handler, and only Round 3's malformed rule packs drive the scanner there without inventing an artificial crash.

### `STOR-007` scan_summary_<run_id>.json — the machine-readable per-run record, written atomically

*core*

- **Must be true:** Every run that constructs a scanner writes exactly one parseable scan_summary_<run_id>.json carrying schema 'yara_scan_summary/v1', the full documented key set, and an outcome that matches what actually happened — and no .tmp survives at any point.
- **Threshold:** json.load succeeds; schema == 'yara_scan_summary/v1'; keys include all of {schema, run_id, scan_id, tenant_id, hostname, os_info, ip_address, matches_dataset, scans_dataset, posture, outcome, scan_folder, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, alert_bytes_written, alert_detail_suppressed, alert_dir_max_bytes, scan_rate_fps, total_paused_secs, throttle_mode, cpu_governor, compile_source, compile_seconds, scanner_version, cancel_source, alert_delivery, dataset_delivery, delivery_shortfall, top_rules}; outcome == 'cancelled' with a non-null cancel_source on the cancelled run, 'failed' on the fatal run, 'completed' otherwise; compile_source in {'cache','fresh'}; alert_dir_max_bytes == 268435456 (256 MB default); zero scan_summary_*.tmp files at every 1 Hz poll and after exit; system_<run_id>.log contains 'Scan summary written: scan_summary_<run_id>.json'.
- **Setup:** All Round-3 runs, including the cancelled one and the fatal one. Poll logs/ at 1 Hz over SSH from scan start through process exit.
- **Evidence:** /opt/yara_scanner/logs/scan_summary_<run_id>.json; 'Scan summary written:' in system_<run_id>.log; 1 Hz `ls /opt/yara_scanner/logs/*.tmp` and a json.load attempt on each poll; 'Failed to write scan summary JSON:' in scan_errors_<run_id>.log must be absent.
- **Negative control:** The all-rules-broken run of STOR-006 must produce NO summary at all — the finally block requires a constructed scanner, so its absence there is correct and must not be scored as a miss.
- **Why this round:** ROUNDS.md assigns the final report and scan_summary to Round 3, and only Round 3 exercises all three outcomes (completed / cancelled / failed) in one evidence bundle.

### `STOR-017` failed_rules/ is NOT wiped by initial_cleanup — asymmetry with alert/ and evidence/

*low*

- **Must be true:** failed_rules/ is never pruned: a dump written by an earlier run survives a later run whose pack no longer contains that rule, while alert/ and evidence/ from the same earlier run are wiped by the same startup pass.
- **Threshold:** Run A (pack with broken rule BadRuleA) leaves failed_rules/failed_rule_BadRuleA.yar. After run B (pack with broken rule BadRuleB and no BadRuleA), BOTH failed_rule_BadRuleA.yar and failed_rule_BadRuleB.yar exist; count(failed_rules/*.yar) after B >= count after A; evidence/ holds exactly two entries after run B — file_mapping.txt (rewritten every run) and evidence_<host>_<run_id_B>.zip — and run A's ZIP path no longer exists. Both runs report compile_source == 'fresh' in scan_summary_<run_id>.json; a 'cache' value voids the result, because a HIT skips the per-rule loop entirely and refreshes no dumps at all.
- **Setup:** Two Round-3 runs with disjoint broken-rule names, each with at least one good rule so the scan reaches completion, and with rule text differing enough to MISS the compile cache — a cache HIT skips the per-rule loop entirely and refreshes no dumps at all, which would make this look like retention when it is just a skipped loop.
- **Evidence:** `ls /opt/yara_scanner/failed_rules` after each run; first line of each dump is '// FAILED RULE - Compilation Error'; failed_rules count in logs/scan_summary_<run_id>.json.
- **Negative control:** alert/ and evidence/ must be shown WIPED by the same run-B startup — the asymmetry is the claim, so the pruned half has to be demonstrated alongside the unpruned one.
- **Why this round:** Dimension prior is cleanup/storage (Round 1), but failed_rules/ is only populated by a rule that fails to COMPILE, which only Round 3's malformed packs produce; Round 1's clean pack leaves the directory empty and the asymmetry untestable there.

### `STOR-022` Content-addressed evidence entries: matched_files/<sha256>

*supporting*

- **Must be true:** With collect_files=true the ZIP carries one member per distinct matched CONTENT, named matched_files/<sha256>; with the shipped default it carries none.
- **Threshold:** collect_files=true run over the decoy directory: `unzip -l` shows exactly one matched_files/<64-lowercase-hex> entry per distinct content hash in file_mapping.txt, each entry name equal to that file's sha256sum; entry count == number of distinct hashes, NOT the number of distinct paths. Default run in the same round: zero entries whose name starts with matched_files/.
- **Setup:** Round-3 run delivered with options 'collect_files=true' (the key is in _VALID_OPTION_KEYS and the snippet path passes options straight into run(); the Action Center `main` entry point exposes only yarafile/scan_folder/alert_severity, so this cannot be done through `main`) and scan_folder pointed at the planted decoy directory only.
- **Evidence:** `unzip -l /opt/yara_scanner/evidence/evidence_<host>_<run_id>.zip`; /opt/yara_scanner/evidence/file_mapping.txt; `sha256sum` of each decoy.
- **Negative control:** The default collect_files=false run in the same round must show zero matched_files/ entries while still shipping file_mapping.txt and the alerts/ members — the gate must remove file copies only, not the metadata.
- **Why this round:** Needs collect_files=true, which on Round 2's flood would copy tens of thousands of matched files into the ZIP and materially change the delivery round's I/O profile. Round 3's planted decoys give a small, enumerable matched set on a narrow target, which is exactly what the content-addressing claim needs.

### `STOR-023` Evidence ZIP de-duplicates identical content across paths

*supporting*

- **Must be true:** Identical content reached through several paths is packaged once, and the collapse is reported with counts that match the plant.
- **Threshold:** With 3 paths holding byte-identical content plus 2 paths with unique content, all matching: `unzip -l` shows exactly 3 matched_files/ entries; file_mapping.txt shows 5 data rows (the path→hash relation stays complete, which is what makes the collapse lossless); system_<run_id>.log contains 'Evidence ZIP: 3 unique file(s) packaged, 2 duplicate copy(ies) skipped' with data {"duplicate_copies_skipped": 2, "unique_files_packaged": 3}.
- **Setup:** The same collect_files=true Round-3 run; plant the identical trio and the two unique files under the decoy directory and make sure the pack matches all five.
- **Evidence:** `unzip -l` on the ZIP; the 'Evidence ZIP:' line and its data blob in system_<run_id>.log; the row count in evidence/file_mapping.txt.
- **Negative control:** A collect_files=true run in which every matched file has distinct content must emit NO 'Evidence ZIP: ... duplicate copy(ies) skipped' line at all — the line is gated on duplicates_skipped > 0, so its absence there is correct and must not be scored as missing telemetry.
- **Why this round:** Same reason as STOR-022 — it requires collect_files=true, and the dedup predicate needs planted byte-identical files at distinct paths, which is a Round-3 control, not a flood artefact.

### `STOR-026` Evidence is collected on the fatal-failure path too

*supporting*

- **Must be true:** A run that ends in the fatal-failure branch still collects evidence and still records itself: the ZIP exists, the failure is logged, and the summary reads failed.
- **Threshold:** After the forced fatal run: evidence/evidence_<host>_<run_id>.zip exists and contains file_mapping.txt plus alerts/<rule>.txt for the rules that had already matched; system_<run_id>.log contains 'Evidence collected from failed scan'; logs/scan_summary_<run_id>.json outcome == 'failed'; scan_errors_<run_id>.log contains 'Scan stopped due to fatal failures' with data.failure_count >= 1; the returned result line begins 'Scan failed: '; NO cleanup_script.* was written or refreshed for that run (the failure branch returns before scheduling).
- **Setup:** A Round-3 run that matches at least one planted decoy and is then driven into the scan_failed branch. If the crafted round produces a natural worker fatal error, use it; otherwise inject deterministically in the snippet prelude by wrapping _perform_enhanced_cleanup so it calls self._mark_scan_failed(...) before delegating — that marks failure before the terminal lifecycle row is emitted, so the dataset row and the summary agree. Never use the console Cancel button, which hard-kills the payload and produces no artefacts at all.
- **Evidence:** `ls -l /opt/yara_scanner/evidence/`; `unzip -l` on the ZIP; 'Evidence collected from failed scan' in system_<run_id>.log; outcome in logs/scan_summary_<run_id>.json; `stat -c %Y /opt/yara_scanner/cleanup_script.sh`.
- **Negative control:** The outer-except crash path (STOR-006's all-broken-pack run) collects NO evidence — only the scan_failed branch does. Both must be shown, or 'evidence on failure' is untested.

### `STOR-027` Cancelled scans produce NO evidence ZIP and NO cleanup scheduling — surprising asymmetry

*core*

- **Must be true:** A cancelled scan produces no evidence ZIP and schedules no cleanup, yet still writes its summary with outcome cancelled and a cancel_source, and leaves the alert texts unrotated.
- **Threshold:** After a mid-walk cancel of a scan that had already matched: evidence/ contains no ZIP carrying that run_id (and, since initial_cleanup wiped it at start, is empty — file_mapping.txt is absent too); alert/ holds the already-written <rule>.txt files, still with .txt extensions; /opt/yara_scanner/cleanup_script.sh is absent or has an mtime PREDATING this run's start; `systemctl show -p ExecMainStartTimestamp yara-cleanup.service` is unchanged across the run; logs/scan_summary_<run_id>.json outcome == 'cancelled' and cancel_source == 'xdr_action'; the returned result line begins 'Scan cancelled by operator: '.
- **Setup:** Round-3 long crafted scan with planted decoys. Deliver the cancel from a SECOND Action Center invocation (the `cancel` entry point, or a mode=cancel snippet) once files_scanned > 0 and at least one match exists. Never the console Cancel button — it hard-kills the payload and orphans the lifecycle row.
- **Evidence:** `ls -la /opt/yara_scanner/evidence /opt/yara_scanner/alert`; `stat -c %Y /opt/yara_scanner/cleanup_script.sh`; outcome and cancel_source in logs/scan_summary_<run_id>.json; the invocation's SCAN_RESULT line.
- **Negative control:** The fatal-failure run of STOR-026, in the same round, DOES produce a ZIP. The asymmetry is the claim, so both outcomes must come out of the same evidence bundle.

### `STOR-034` Cleanup scheduling is also skipped when diagnostics must be preserved

*low*

- **Must be true:** Cleanup is suppressed on exactly one condition — has_errors AND valid_rules_count == 0 — and a merely NOISY run is never suppressed. The catalogue's Control field is stale: there is no 0.5 error-ratio predicate and no 'Critical errors detected - skipping cleanup to preserve diagnostic data' message anywhere in the source; the real message is 'No valid YARA rules compiled - skipping cleanup to preserve diagnostics'.
- **Threshold:** On the many-broken-but-healthy run, first prove the removed predicate WOULD have fired: in the 'Logging Summary | Total Logs: N' data blob, logs_by_type['error'] / data.total_logs_generated > 0.5. Given that, neither 'No valid YARA rules compiled - skipping cleanup to preserve diagnostics' nor 'Cleanup skipped due to critical YARA processing errors' appears in system_<run_id>.log; 'Cleanup task/service scheduled successfully' does; and the cleanup script AND the scheduled unit ARE created (cleanup_script.sh mtime inside the run window, yara-cleanup.service ExecMainStartTimestamp advanced). All-rules-broken run: the process aborts with CRITICAL_ERROR before scheduling, so neither message appears there either and no cleanup_script.* is written or refreshed. Across all logs of every Round-3 run: 0 occurrences of 'Critical errors detected' and 0 of 'preserve_logs' (the latter is the data key on the one surviving suppressor at 4898-4899, so a single occurrence means the unreachable branch became reachable).
- **Setup:** Deliver a normal Action Center Round-3 run (SYSTEM/root, as every payload runs) with a pack of >=300 syntactically broken rules plus >=1 good rule, so error records dominate by construction: ErrorLogger.log_rule_compilation_error emits one log_manager.log_error per failed rule, which is what moves logs_by_type['error'] past half of total_logs_generated. Do NOT rely on scanning a locked-down target as a non-root user — Action Center payloads run as SYSTEM/root and that run cannot be delivered. Plus the all-broken-pack run from STOR-006.
- **Evidence:** system_<run_id>.log; per-category record counts from the 'Logging Summary | Total Logs:' data blob; `stat -c %Y /opt/yara_scanner/cleanup_script.sh`; `systemctl show -p ExecMainStartTimestamp yara-cleanup.service`.
- **Negative control:** The noisy-but-healthy run must still schedule cleanup. Reinstating a ratio-based suppressor — which would preserve diagnostics forever on every locked-down host — is exactly the regression this catches.
- **Why this round:** Driven by rule-compilation outcomes, which Round 3's malformed packs own. Written as a NEGATIVE criterion because the positive branch is unreachable on a live run: has_critical_errors requires valid_rules_count == 0, which only happens when every rule fails, and that path raises ValueError out of _compile_yara_rules before either the method-internal check or the caller's pre-check is ever evaluated.

### `STOR-035` control/cancel.flag — cooperative cancel signal written by mode=cancel

*core*

- **Must be true:** mode=cancel writes control/cancel.flag with the documented payload without initializing the scan machinery, reports whether a scan is live, and the running scan honours it within the poll interval.
- **Threshold:** The cancel invocation returns a line matching 'Cancel signal delivered (/opt/yara_scanner/control/cancel.flag) | scanner running: yes | scan_id=<the running scan's scan_id>'. The file parses as JSON with exactly the keys requested_at_ms (int, within 5s of the call), source == 'xdr_action', tenant_id_override == ''. The running scan's system_<run_id>.log contains 'Cancellation requested (source=xdr_action)' at a timestamp no earlier than the flag's mtime and no more than CANCEL_POLL_SECS + 1s (6s) after it — the watcher sleeps a full CANCEL_POLL_SECS after each miss, so a bar of exactly 5s has no slack for sleep overshoot and fails a correct build. scan_summary.cancel_source == 'xdr_action' and outcome == 'cancelled'. The flag file is STILL present after the run — it is cleared by the next run's stale sweep, not by the run it cancelled. The cancel invocation itself writes no logs/ files of its own (run() returns from _handle_cancel_request before ScanConfig is constructed, so no run_id and no LogManager exist for it).
- **Setup:** Round-3 long crafted scan. Fire the `cancel` Action Center entry point (or a mode=cancel snippet) from a second invocation while control/running.json is fresh (within SCANS_HEARTBEAT_SECS*3+60 = 1860s of its updated_at at defaults).
- **Evidence:** The cancel invocation's returned string; `cat /opt/yara_scanner/control/cancel.flag`; 'Cancellation requested (source=' in system_<run_id>.log; cancel_source and outcome in logs/scan_summary_<run_id>.json.
- **Negative control:** With no scan running, the same invocation must return '... | scanner running: no | scan_id=n/a' AND still write the flag — the write must not be conditional on liveness. That orphaned flag must then be removed by the next scan's stale sweep ('Removed stale cancel flag from a previous run' in the next run's system log), not honoured.

### `STOR-037` Stale cancel-flag disambiguation by mtime, with coarse-filesystem tolerance

*supporting*

- **Must be true:** A cancel.flag whose mtime predates the watcher's baseline (_process_started_at, captured at the END of YaraScanner.__init__, i.e. AFTER rule compilation) by more than CANCEL_STALE_TOLERANCE_SECS is deleted at scan start and the scan runs to completion; a flag written after that baseline — once 'Rule compile FRESH'/'Rule cache HIT' has been logged and the walk has begun — is preserved and honoured, ending the run as cancelled. A flag delivered DURING the pre-scan compile is NOT preserved on this build: it is swept as stale, contradicting _start_cancellation_watcher's own docstring, and must be recorded as a defect rather than asserted as correct behaviour.
- **Threshold:** CANCEL_STALE_TOLERANCE_SECS = 2.0 (bare module literal, line 401, no env knob). Run A: exactly 1 'Removed stale cancel flag from a previous run' record; <scanner_dir>/control/cancel.flag absent once the walk begins; scan_summary_<run_id>.json outcome == 'completed' and cancel_source == '' (empty string, not null). Run B: 0 such records; outcome == 'cancelled'; cancel_source == 'xdr_action'. Run C: exactly 1 'Removed stale cancel flag from a previous run' record and outcome == 'completed' — this is the CURRENT behaviour and is a FAIL against the documented intent; record it, do not pass it silently.
- **Setup:** Run A — invoke the `cancel` entry point to write <scanner_dir>/control/cancel.flag, wait >= 10 s, then start a Round 3 crafted-pack scan. Run B — start the scan, wait until BOTH 'Rule compile FRESH' (or 'Rule cache HIT') appears in system_<run_id>.log AND the first 'Scan Progress |' record appears in statistics_<run_id>.log, then invoke `cancel`. Run C (defect probe) — empty rule_cache so the compile is FRESH and long, and invoke `cancel` while the compile is still running (before 'Rule compile FRESH' appears).
- **Evidence:** logs/system_<run_id>.log records 'Removed stale cancel flag from a previous run' and 'Could not evaluate pre-existing cancel flag: ' (both log_system calls in _start_cancellation_watcher) and 'Cancellation requested (source=xdr_action)' (_request_cancel); outcome and cancel_source in logs/scan_summary_<run_id>.json; presence/absence of <scanner_dir>/control/cancel.flag polled over SSH.
- **Negative control:** Run B's flag must NOT be removed — a build that clears the flag unconditionally at scan start makes run B complete instead of cancel. Run A's stale flag must not be honoured (a 'cancelled' outcome there is the fail). Run C is the discriminating control for the ordering defect: moving `self._process_started_at = time.time()` ABOVE the `self.rules = self._load_or_compile_rules(...)` call must flip run C to outcome == 'cancelled' with 0 'Removed stale' records, while leaving runs A and B unchanged.
- **Why this round:** Dimension prior is lifecycle/control-directory (Round 1's 'everything the scanner writes'), but the predicate is only decidable by delivering a cancel flag at two different times relative to process start — and cancellation is settled to Round 3, where a long crafted-pack scan gives a ~90s fresh-compile window wide enough to place the second flag inside.

### `STOR-038` An HONOURED cancel flag is left on disk — dead-comment hazard

*low*

- **Must be true:** After a flag-cancelled scan has fully exited, <scanner_dir>/control/cancel.flag is STILL on disk (the watcher never removes the flag it acted on) while <scanner_dir>/control/running.json is gone.
- **Threshold:** Immediately after the payload PID leaves the process table: exactly 1 file <scanner_dir>/control/cancel.flag, with mtime unchanged from when the cancel entry point wrote it (delta < 1 s); exactly 0 files named running.json in that directory; scan_summary_<run_id>.json outcome == 'cancelled'.
- **Setup:** Round 3's cancellation run — cancel delivered mid-walk via the `cancel` entry point. Inspect <scanner_dir>/control BEFORE starting any subsequent scan.
- **Evidence:** `ls -l <scanner_dir>/control` over SSH after the payload PID has disappeared from ps/tasklist; outcome in logs/scan_summary_<run_id>.json; the _cancellation_watcher body contains no os.remove — the only removal of cancel_flag_path in the file is the stale sweep inside _start_cancellation_watcher.
- **Negative control:** The persistence must be a watcher gap, not a permanent leak: starting the NEXT scan afterwards must remove that same flag through the stale sweep ('Removed stale cancel flag from a previous run' in the new run's system_<run_id>.log) and that new run must complete, not cancel. Do NOT try to show the flag surviving CONFIG_HOST_CLEANUP='always' on the same run — host cleanup is gated on outcome=='completed' and never runs on a cancelled scan, so that arrangement cannot distinguish 'control/ is exempt' from 'cleanup did not run'.
- **Why this round:** Cancellation is settled to Round 3, and the only run that can leave an honoured flag behind is one actually cancelled mid-walk.

### `STOR-040` Rule-cache key composition (why a stale bundle can never load)

*supporting*

- **Must be true:** The cache filename is a pure function of the compile inputs: identical rule text reuses exactly one filename and hits; a single changed byte of rule text yields a different filename and a fresh compile; bumping YARA_RULE_CACHE_FORMAT yields a third distinct filename and another fresh compile.
- **Threshold:** 3 distinct basenames under <scanner_dir>/rule_cache after the three runs, every one matching ^rules_[0-9a-f]{40}\.yarac$ (the key is truncated to its first 40 hex chars). Runs B and C both report compile_source == 'fresh'. Re-running pack A afterwards reports compile_source == 'cache' with pack A's original basename.
- **Setup:** Empty rule_cache. Run A: Round 3 pack A. Run B: pack A with exactly one literal byte changed inside a string. Run C: pack A again, SSH-launched with YARA_RULE_CACHE_FORMAT=2 exported. Run D: pack A again, no env override.
- **Evidence:** `ls <scanner_dir>/rule_cache` after each run; compile_source in logs/scan_summary_<run_id>.json; 'Rule cache HIT rules_<key>.yarac' / 'Rule compile FRESH' in logs/system_<run_id>.log; the MODS: component is read back from the 'Available YARA modules: ...' record in logs/yara_processing_<run_id>.log, and the YARA: component from the "yara" field of <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json.
- **Negative control:** Run D (pack A, unchanged, no env change) must NOT create a fourth file — a key that mixed in run_id, scan_id or wall-clock time would produce a new basename every run and the cache would never hit. Equally, run B must not overwrite run A's entry: both basenames coexist.
- **Why this round:** Departs from the Round 1 disk-artefact prior: the key's discriminating power is only observable when the RULE TEXT actually varies, and Round 3 is the only round that ships multiple distinct and mutated packs. Round 1 runs one fixed pack, so the key never moves and the claim is vacuous there.

### `STOR-041` Rule-cache LRU pruning by file count AND total bytes

*supporting*

- **Must be true:** After six fresh compiles of six distinct packs, rule_cache retains at most RULE_CACHE_MAX_FILES .yarac bundles, the evicted one is the oldest by mtime, its .meta.json sidecar is removed with it, and the retained set's total bytes stay within the byte ceiling.
- **Threshold:** RULE_CACHE_MAX_FILES = 5, RULE_CACHE_MAX_BYTES = 256 MB (268435456). Arm 1, after run 6: count of rules_*.yarac == 5; pack 1's basename absent, pack 6's present; the set of *.yarac.meta.json basenames is exactly the retained .yarac basenames + '.meta.json', with no sidecar left for the evicted entry. Arm 2, with the byte ceiling between B and 2*B: count of rules_*.yarac == 1 (well under the 5-file ceiling, so the eviction can only be byte-driven), sum of sizes <= the configured ceiling, and the two older entries plus their sidecars are gone.
- **Setup:** Arm 1 (count): empty <scanner_dir>/rule_cache, then six Round 3 runs with six distinct packs, each a MISS so each triggers a save. Arm 2 (bytes): empty rule_cache again, measure one bundle's size B from a first run, then SSH-launch the next runs with YARA_RULE_CACHE_MAX_MB exported to a value between B and 2*B (module-scope constant at line 382 — an Action Center snippet body has already evaluated it, so this arm must be SSH-launched or must assign RULE_CACHE_MAX_BYTES in a snippet prelude). Run three distinct packs.
- **Evidence:** `ls -l <scanner_dir>/rule_cache` after run 6; 'Rule compile FRESH' in each of the six logs/system_<run_id>.log files (confirming six saves, hence six prune passes); a seventh run with pack 6 reporting compile_source == 'cache' in logs/scan_summary_<run_id>.json.
- **Negative control:** Pruning must evict, not empty: in arm 1 pack 6 (newest mtime) must survive and HIT on run 7, and a re-run of pack 5 must also HIT — at six entries exactly one is evicted. A build that deleted the whole directory, or that sorted oldest-first, fails both. Arm 2's own control: repeat the identical three packs with YARA_RULE_CACHE_MAX_MB back at its 256 default and all three entries must coexist — that is what separates 'byte ceiling enforced' from 'saves are failing'.
- **Why this round:** Pruning runs only on the SAVE path, so it needs six consecutive cache MISSES — i.e. six distinct packs. Only Round 3 supplies those; Round 1's single fixed pack saves once and never prunes.

### `STOR-044` Rule-cache sidecar rules_<key>.yarac.meta.json restores rule counts on a HIT

*supporting*

- **Must be true:** On a cache HIT the valid/failed/skipped counts come back from the sidecar identical to the compiling run's; with the sidecar deleted by hand, valid_rules is still recovered by iterating the loaded bundle while failed_rules and skipped_rules both fall to 0.
- **Threshold:** Run A (fresh, mixed pack): valid_rules == V > 0, failed_rules == F > 0, skipped_rules == S > 0. Run B (HIT, sidecar intact): compile_source == 'cache' with exactly the same V, F, S. Run C (HIT, sidecar deleted): compile_source == 'cache', valid_rules == V, failed_rules == 0, skipped_rules == 0.
- **Setup:** Round 3 mixed pack containing at least one rule that fails to compile and at least one requiring a module this agent's libyara lacks. Between B and C delete only <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json, leaving the .yarac in place.
- **Evidence:** valid_rules / failed_rules / skipped_rules and compile_source in logs/scan_summary_<run_id>.json for all three runs; the echoed triple in the 'Rule cache HIT rules_<key>.yarac load=<s>s (valid=V failed=F skipped=S)' record in logs/system_<run_id>.log.
- **Negative control:** Empty <scanner_dir>/failed_rules before run B: a HIT must write NO new failed_rule_*.yar and NO new skipped_rule_*.yar, because the per-rule loop is skipped entirely. Non-zero counts with an empty failed_rules directory is exactly the proof that the numbers came from the sidecar rather than from the work being redone.
- **Why this round:** Departs from the Round 1 disk prior: the restore is only distinguishable from zero when the pack actually produced failures and module-skips, which only Round 3's malformed/module-dependent packs supply. Round 1's clean pack gives failed=0/skipped=0, where 'restored' and 'never set' look identical.

### `STOR-045` Corrupt / cross-version cache entries are self-healing (and probe-validated)

*supporting*

- **Must be true:** A corrupted cache bundle is caught at load (or by the empty-data externals probe), both it and its sidecar are deleted, and the run falls back to a fresh compile that succeeds and re-saves under the same key.
- **Threshold:** Exactly 1 'Rule cache miss/unusable, compiling fresh: ' record in logs/system_<run_id>.log; compile_source == 'fresh' and outcome == 'completed' in logs/scan_summary_<run_id>.json; the corrupted rules_<key>.yarac has a NEW size and mtime after the run (deleted then rewritten by the fresh save) and rules_<key>.yarac.meta.json likewise; 0 'Rule cache HIT' records on that run.
- **Setup:** Produce a valid entry first with a fresh Round 3 run, then truncate that rules_<key>.yarac to its first 512 bytes (or flip a byte in the middle), then re-run the identical pack.
- **Evidence:** 'Rule cache miss/unusable, compiling fresh: <error>' in logs/system_<run_id>.log; `ls -l <scanner_dir>/rule_cache` captured before and after (size and mtime of the .yarac and its sidecar both change); compile_source in logs/scan_summary_<run_id>.json.
- **Negative control:** The same message text is also the generic except-branch message, so pair it with the file actually being replaced. And the control run — the identical pack against the UNcorrupted entry — must produce 'Rule cache HIT' with zero 'Rule cache miss/unusable' records and an unchanged .yarac size, proving the self-heal fires on damage rather than on every run.
- **Why this round:** Departs from the Round 1 disk prior: reaching this path requires a deliberately damaged artefact planted before the run, which is Round 3's crafted-input character; nothing in a healthy Round 1 run corrupts a bundle.

### `STOR-047` failed_rules/failed_rule_<name>.yar — full source dump per compilation failure

*supporting*

- **Must be true:** Every rule that fails to compile is dumped in full to failed_rules/failed_rule_<name>.yar under the fixed error header with the file-level preamble prepended, and the dump count equals the reported failed-rule count — uncapped, unlike the log warnings.
- **Threshold:** With a pack containing exactly 12 distinctly-named rules that fail to compile: count of <scanner_dir>/failed_rules/failed_rule_*.yar == 12 == failed_rules in scan_summary_<run_id>.json == the N in 'Failed rules skipped: N' in yara_processing_<run_id>.log. Every dump's first line is exactly '// FAILED RULE - Compilation Error'; every dump contains the file-level `import` line before its `rule` keyword. logs/diagnostics_<run_id>.log carries exactly 10 'Failed rule ' warning lines (the <=10 log cap) against those 12 dumps.
- **Setup:** Round 3 malformed pack: a file-level `import "pe"` preamble, 12 distinctly-named rules with real syntax errors, and at least 3 rules that compile cleanly. Empty <scanner_dir>/failed_rules first — initial_cleanup wipes alert/ and evidence/ but deliberately NOT failed_rules/, so dumps accumulate across runs and an unemptied directory makes the count meaningless.
- **Evidence:** `ls <scanner_dir>/failed_rules` and `head -1` of each failed_rule_*.yar; failed_rules field in logs/scan_summary_<run_id>.json; 'Failed rules skipped: N' and 'Failed rules saved to: <dir>' in logs/yara_processing_<run_id>.log; 'Failed rule <name>: ' lines in logs/diagnostics_<run_id>.log.
- **Negative control:** No failed_rule_<name>.yar exists for any of the 3 rules that compiled cleanly, and none exists for a rule skipped for an unavailable module (those go to skipped_rule_*.yar and are counted as skipped, never failed). The 10-vs-12 split is the second control: the log warning is capped, the dumps are not.

### `STOR-048` failed_rules/skipped_rule_<name>_<module>.yar — module-unavailable dumps (two distinct write sites)

*supporting*

- **Must be true:** Both module-unavailable dump sites fire and are distinguishable by header — the pre-compile static check for an inline `import` of a missing module, and the post-compile error classifier for an import inherited from a stripped file-level preamble — and both count as SKIPPED, never as failed.
- **Threshold:** With one rule of each shape against a module this agent's libyara lacks: exactly 2 files matching skipped_rule_*_<module>.yar; exactly 1 begins '// SKIPPED RULE - Module '<mod>' not available' with no following '// (import inherited...' line; exactly 1 begins '// SKIPPED RULE - Module '<mod>' not available on this agent' followed by '// (import inherited from the file-level preamble)'. scan_summary_<run_id>.json skipped_rules == 2 and failed_rules is unchanged by these two. yara_processing_<run_id>.log carries 'Skipped 2 rules due to unavailable modules'. The SCAN_RESULT line contains '2 rules skipped (module unavailable)'.
- **Setup:** Round 3 module-dependent pack on an endpoint whose libyara lacks the module — confirm from the 'Available YARA modules: ' record in yara_processing_<run_id>.log (Linux agents on yara 3.11.0 lack cuckoo). Rule 1 carries `import "cuckoo"` inside its own block; rule 2 carries no import but references cuckoo.* and relies on a file-level `import "cuckoo"` preamble. Empty <scanner_dir>/failed_rules first.
- **Evidence:** `ls <scanner_dir>/failed_rules` plus `head -4` of each skipped_rule_*.yar; skipped_rules in logs/scan_summary_<run_id>.json; 'Skipped N rules due to unavailable modules' in logs/yara_processing_<run_id>.log; the '| N rules skipped (module unavailable) |' segment of the SCAN_RESULT line printed to Action Center stdout.
- **Negative control:** Add a third rule whose ONLY mention of the module is a literal hunt string (`$s = "cuckoo.conf"`) with no import of its own. It must compile, must produce NO skipped_rule_*.yar, must be counted valid, and must be able to match a planted file containing that text — even though the pack imports cuckoo elsewhere. That is the case the retired usage-regex classifier silently dropped, and it is the control that separates 'needs the module' from 'mentions its name'.

### `STOR-049` failed_rules/raw_yara_content.yar — whole-input dump when rule splitting yields nothing

*supporting*

- **Must be true:** A rule payload containing no `rule <name>` declaration produces failed_rules/raw_yara_content.yar holding the whole decoded input under its fixed header, and the run aborts before any file is scanned — with NO scan_summary written for that run, because the ValueError escapes YaraScanner.__init__ before `scanner` is bound in run().
- **Threshold:** Exactly 1 file <scanner_dir>/failed_rules/raw_yara_content.yar; its first line is exactly '// RAW YARA CONTENT - Failed to split into individual rules'; its byte length >= the decoded input length. yara_processing_<run_id>.log contains exactly 1 'COMPILATION_ERROR: No YARA rules found in provided content'. The SCAN_RESULT line begins 'Scan failed: 0 files scanned'. logs/scan_summary_<run_id>.json does NOT exist for that run_id.
- **Setup:** Deliver as `yarafile` a base64 payload whose decoded text puts the `rule` keyword and the rule NAME on separate physical lines, e.g.\n\n    import "pe"\n    rule\n       OrphanName\n    {\n        condition: false\n    }\n\ndecode_yara_rules' `(?m)^\s*rule\s+\w+` matches across the newline and lets the payload through, while _split_yara_rules' per-line `re.match` finds 0 rule starts, so individual_rules is empty and the raw dump fires. Verify the payload first by running both regexes locally before shipping it.
- **Evidence:** <scanner_dir>/failed_rules/raw_yara_content.yar (first line and size); logs/yara_processing_<run_id>.log for 'COMPILATION_ERROR: No YARA rules found in provided content' AND for the absence of 'VALIDATION_ERROR: Decoded content does not contain any YARA' (its presence means the payload died in decode_yara_rules and this criterion was never exercised); identify the run by the newest yara_processing_*.log since no summary is written; the 'SCAN_RESULT: Scan failed: 0 files scanned | ...' line on Action Center stdout — note the except branch at 7904-7907 also dumps a full traceback to stdout ahead of it, so read SCAN_RESULT from the tail of the 10,240-char window; `ls <scanner_dir>/logs/scan_summary_<run_id>.json` returning not-found.
- **Negative control:** The name is fixed, so it is overwritten rather than accumulated: a second such run must still leave exactly one raw_yara_content.yar. And after deleting it, a normal Round 3 pack must leave none — its absence on a healthy run is what makes its presence meaningful. Do NOT assert outcome=='failed' here: no summary file is produced on this path at all.

### `STOR-054` HostCleanup runs only on outcome=='completed'

*core*

- **Must be true:** 'always' does not mean always: a cancelled run keeps every log file this run wrote and every alert file it produced, the summary survives, and the skip is entirely silent because both the removal line and the skip reason sit inside the completed-only branch. Evidence/ is empty on this path for an independent reason — collect_evidence is never reached on the cancel return — so its emptiness is not evidence about cleanup either way.
- **Threshold:** scan_summary_<run_id>.json outcome == 'cancelled' and cancel_source == 'xdr_action'; all 8 files carrying this run_id remain in logs/ (alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_, diagnostics_) plus scan_summary_<run_id>.json; <scanner_dir>/alert holds >= 1 <rule>.txt from the decoy matched before the cancel; <scanner_dir>/evidence holds 0 entries and no evidence_<hostname>_<run_id>.zip — expected, and NOT counted as cleanup having run; logs/diagnostics_<run_id>.log contains 0 lines matching 'Host cleanup' — neither the removal line nor a skip reason.
- **Setup:** Round 3's cancellation run, launched with CONFIG_HOST_CLEANUP='always' and CONFIG_HOST_CLEANUP_KEEP='nothing' (module globals set via a snippet prelude — both are read at runtime in run()'s finally). Plant an always-matching decoy EARLY in the walk order so at least one alert/<rule>.txt exists before the cancel lands, and deliver the cancel mid-walk via the `cancel` entry point only after the first 'Scan Progress |' record appears.
- **Evidence:** outcome in logs/scan_summary_<run_id>.json; `ls <scanner_dir>/logs <scanner_dir>/alert <scanner_dir>/evidence`; `grep -c 'Host cleanup' logs/diagnostics_<run_id>.log` == 0. The diagnostics handler is still open on this path — close_diagnostics_handler() is inside the same completed-only branch — so its silence is real evidence rather than a closed sink.
- **Negative control:** An otherwise identical COMPLETED run with the same settings must wipe everything down to the run_id disappearing from logs/ AND alert/ coming back empty — without that pair, 'kept because cancelled' is indistinguishable from 'cleanup misconfigured'. A fatally-failed run (outcome == 'failed') must be kept for the same reason, and it DOES produce an evidence ZIP (collect_evidence is called on the fatal-failure path at line 7784), which is the control that separates 'cancel skipped evidence collection' from 'evidence collection is broken'.
- **Why this round:** Departs from the Round 1 host-cleanup prior: the claim can only be falsified by a NON-completed outcome, and cancellation is settled to Round 3 — a long crafted scan is the only run that can be cancelled mid-walk.

### `STOR-058` Scanner directory self-exclusion from the scan walk (per platform)

*core*

- **Must be true:** The scanner never scans its own working directory, and when the operator explicitly targets it the run says so instead of reporting a clean zero: the target is recorded as excluded, the result line carries the warning, and no alert or dataset row ever names a path under scanner_dir.
- **Threshold:** Broad-scan arm: 0 alert/<rule>.txt blocks whose 'YARA rule ... matched file:' path is under <scanner_dir>, and 0 rows in yara_scanner_matches_v3_* for this run_id whose filename starts with <scanner_dir>. Targeted arm (scan_folder = <scanner_dir>): excluded_targets in scan_summary_<run_id>.json == [<scanner_dir>]; files_scanned == 0; the SCAN_RESULT line contains 'WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned: <scanner_dir>'; scan_errors_<run_id>.log carries exactly 1 'Requested scan target is excluded by the skip list, so nothing under it will be scanned: <scanner_dir>'; the statistics 'Skip reasons: ' record's skip_breakdown carries a non-zero 'Skipped directory' bucket.
- **Setup:** Two Round 3 runs. (a) A broad scan of a parent that CONTAINS scanner_dir, with the always-matching decoy planted at <scanner_dir>/failed_rules/decoy_selfexclude.txt (or as a bare file <scanner_dir>/decoy_selfexclude.txt) — NOT under <scanner_dir>/alert or <scanner_dir>/evidence, both of which initial_cleanup rmtree's at scan start, which would silently remove the probe. Confirm the decoy is still on disk after the run before reading the result. (b) A scan whose scan_folder is <scanner_dir> itself.
- **Evidence:** excluded_targets and files_scanned in logs/scan_summary_<run_id>.json; the SCAN_RESULT line on Action Center stdout; 'Requested scan target is excluded by the skip list' in logs/scan_errors_<run_id>.log; the 'Skip reasons: ' record and its skip_breakdown data in logs/statistics_<run_id>.log; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | filter filename contains "<scanner_dir>"` returning 0 rows; the ScanConfig validation warnings 'sit under a platform skip-path and will yield no files' and 'EVERY requested scan folder is excluded by the platform skip-list' in logs/yara_processing_<run_id>.log.
- **Negative control:** A sibling directory must NOT be swept up. On Linux the entry is '/opt/yara_scanner/' with an equality test on the bare root (line 6584), so '/opt/probe_tree' is unaffected. On WINDOWS the test is a bare startswith against normpath('c:\\yara_scanner') (line 6525), so 'C:\\yara_scanner_probe' WOULD be excluded — do not use a prefix-sharing name as the control. Use 'C:\\probe_tree' (Windows) or '/opt/probe_tree' (Linux), planted with the same always-matching decoy: it must be scanned and must produce a finding in both the alert file and the matches dataset. Second control: the in-scanner_dir decoy must still EXIST on disk when the run ends — if it is missing, initial_cleanup ate it and arm (a) is void, not passing.
- **Why this round:** This is a skip predicate with a targeting arm; Round 3 owns the skip lists and target resolution, and only a deliberately targeted scan of scanner_dir exercises the excluded-target reporting path.

### `STOR-060` Per-file size ceiling bounds how much the scanner reads off the disk

*supporting*

- **Must be true:** A file larger than the configured ceiling is skipped without being read and is booked under the 'File too large' skip reason, while a file just under the ceiling is scanned and can match; an out-of-range YARA_MAX_MB is rejected back to the 64 MB default rather than disabling the scan.
- **Threshold:** Ceiling = YARA_MAX_MB, default 64 (max_file_bytes = 67108864). Planted 65 MB file: contributes exactly 1 to the 'File too large' bucket of skip_breakdown and produces 0 alert blocks and 0 matches-dataset rows. Planted 63 MB file with identical content trigger: produces exactly 1 alert block and 1 dataset row. init_data.max_file_mb == 64 and the 'Scan configuration established' record's max_file_size_mb == 64. Control run with YARA_MAX_MB=-1 exported: both fields still read 64 and files_scanned > 0 (the negative is rejected by _env_number's minimum=0 rather than making every file oversized).
- **Setup:** Round 3 crafted tree containing a 65 MB and a 63 MB file that both carry the same trigger string. For the control run, set YARA_MAX_MB=-1 EITHER by SSH-launching with it exported OR via an Action Center snippet prelude doing `import os; os.environ['YARA_MAX_MB'] = '-1'` — ScanConfig reads this env var per run (line 2962), not at module import, so the prelude route works and is the cheaper of the two.
- **Evidence:** The 'Skip reasons: ' record in logs/statistics_<run_id>.log and its structured skip_breakdown data (the message text lists only the top 5 reasons — read the data blob); the same bucket under file_processing.skip_breakdown in the 'COMPREHENSIVE SCAN REPORT' record in the SAME statistics log; files_skipped in logs/scan_summary_<run_id>.json (the summary has NO skip_reasons field, so the per-reason number must come from the statistics record); the 'Scan configuration established' record — also in logs/statistics_<run_id>.log, not yara_processing — and its max_file_size_mb field; init_data.max_file_mb in the 'YARA Scanner initialization completed' record in logs/system_<run_id>.log; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>"` for the two planted filenames. Note _env_number's 'Ignoring out-of-range YARA_MAX_MB=...' warning goes through the root logger from inside ScanConfig, which is constructed BEFORE setup_logging installs the diagnostics FileHandler — so it lands on stderr only and must not be used as evidence.
- **Negative control:** The 63 MB file is the control: it must be scanned and must match, proving the ceiling discriminates by size rather than skipping large files wholesale. Second control: the YARA_MAX_MB=-1 run must still scan files — the regression this guard exists for reported 'completed' having scanned nothing.

### `STOR-067` Resolved tenant/credential/posture block and scan-target validation warnings — written to yara_processing_<run_id>.log and nowhere else

*supporting*

- **Must be true:** yara_processing_<run_id>.log is the sole artefact carrying the scan-target validation warnings that explain a zero-coverage run, and the resolved posture it reports agrees with the summary and the result line.
- **Threshold:** Run with scan_folder = '<a real dir>,<a nonexistent dir>,<scanner_dir>': logs/yara_processing_<run_id>.log contains exactly 1 'Ignoring 1 specified scan folder(s) that are not valid directories on this endpoint: ', exactly 1 '1 of 2 scan folder(s) sit under a platform skip-path and will yield no files: ' and exactly 1 'Scan limited to 2 folder(s): '. Those three strings appear 0 times across every other file in logs/, 0 times in scan_summary_<run_id>.json and 0 times on the SCAN_RESULT line. The 'Runtime posture: ' value equals scan_summary_<run_id>.json's posture field and the posture segment of the SCAN_RESULT line. The 'Scan ID: <scan_id> (rule hash: <12hex>...)' record's scan_id equals scan_summary's scan_id. The config block ('XDR API URL: ', 'Tenant ID: ', 'Runtime posture: ') is written before the first 'Available YARA modules: ' record.
- **Setup:** Round 3 run with a comma-separated scan_folder mixing one valid directory, one path that does not exist, and <scanner_dir> itself. Run a second variant whose ONLY target is <scanner_dir> to also produce the 'EVERY requested scan folder is excluded by the platform skip-list - this scan will scan 0 files.' warning.
- **Evidence:** logs/yara_processing_<run_id>.log grepped for 'XDR API URL', 'Tenant ID', 'Runtime posture', 'Scan ID:', 'Ignoring ', 'sit under a platform skip-path', 'EVERY requested scan folder is excluded' and 'Scan limited to '; posture, scan_id and scan_folder fields in logs/scan_summary_<run_id>.json; the SCAN_RESULT line on Action Center stdout.
- **Negative control:** Do NOT assert that posture or tenant_id are unique to this file — both are also written to scan_summary_<run_id>.json, to the yara_scanner_scans_v3_* lifecycle rows and (posture) to the SCAN_RESULT line; only the three validation warnings are single-sourced. Also do not assert 'no quote characters' on 'Scan limited to N folder(s): ' — the value is a Python list repr, so quoted elements are the correct output. Positive control: a run with a single valid target must produce 'Scan limited to 1 folder(s): ' and ZERO occurrences of the other two warnings.
- **Why this round:** Departs from the Round 1 log-layout prior: the config block is written on every run, but the discriminating half — the three scan-target validation warnings that explain a 0-file scan — only fires on deliberately bad or skip-listed targets, which is Round 3's target-resolution material.

## Delivery, Aggregation & Telemetry

### `DELI-037` running.json liveness marker for cross-process cancel

*core*

- **Must be true:** While a scan runs, control/running.json exists, names that scan's identity and is refreshed inside the freshness window; the cancel entry point reads it without starting the scan machinery and reports the scan as running; after the scan ends the marker is removed and the same call reports no scan running.
- **Threshold:** During the scan: <scanner_dir>/control/running.json parses and carries scan_id, run_id, pid equal to the live payload PID, hostname, started_at, updated_at, status='running', files_scanned, detections; (now - updated_at) < 1860s (SCANS_HEARTBEAT_SECS*3+60). A `cancel` Action Center invocation mid-scan returns exactly 'Cancel signal delivered (<scanner_dir>/control/cancel.flag) | scanner running: yes | scan_id=<the running scan's scan_id>'. After the run terminates: os.path.exists(running.json) is False and a second `cancel` invocation returns '... | scanner running: no | scan_id=n/a'.
- **Setup:** Round 3 long crafted scan; issue the dedicated `cancel()` Action Center entry point roughly 60s into the walk, then again after the scan has ended.
- **Evidence:** <scanner_dir>/control/running.json read over SSH during the scan; the string returned by the `cancel` entry point on the Action Center action result (short, well inside the 10,240-character stdout cap); <scanner_dir>/control/cancel.flag; scan_summary_<run_id>.json cancel_source and outcome=='cancelled'.
- **Negative control:** The post-run 'scanner running: no' answer is the load-bearing negative — a build that leaves the marker behind reports a phantom running scan forever, and only the removal check catches it. Do NOT use the console Cancel button: it hard-kills the payload, skipping the marker removal, and would fail a correct build.
- **Why this round:** Departs from the delivery prior. ROUNDS.md settles cancellation into Round 3, and this marker exists solely to let a separate cancel invocation report on a live scan — its only sharp test is a real cancel delivered against a running scan and again against a finished one.

### `DELI-055` scan_summary_<run_id>.json — the machine-readable delivery record

*core*

- **Must be true:** Every terminated run leaves exactly one scan_summary_<run_id>.json, written atomically AFTER both uploaders have drained, so its delivery blocks are the final numbers: alert_delivery.successful_uploads equals the ok= value on the uploads log's 'Alert delivery final:' line and dataset_delivery's five overlapping counters equal the 'Lookup dataset worker stopped' line's, on all three outcomes.
- **Threshold:** Exactly 1 scan_summary_<run_id>.json per run_id; schema == "yara_scan_summary/v1"; outcome in {completed, cancelled, failed} and matches the run; zero files matching scan_summary_*.tmp in logs_dir; alert_delivery.successful_uploads == the log line's ok= integer, exactly.
- **Setup:** The Round 3 crafted run, plus the mid-walk cancellation (write <scanner_dir>/control/cancel.flag; do NOT use the console Cancel button, which hard-kills the payload) for the cancelled outcome. For the failed outcome, force an exception AFTER YaraScanner is constructed — e.g. a snippet prelude that rebinds upload_final_comprehensive_report (called from run() after the scan, with `scanner` already bound) to a function that raises — so run()'s outer except sets scanner.scan_failed = True and the finally derives outcome == "failed". Do NOT use a non-compiling ruleset: that path leaves scanner None and writes no summary.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json; system_<run_id>.log 'Scan summary written: scan_summary_<run_id>.json'; uploads_<run_id>.log 'Alert delivery final:' and 'Lookup dataset worker stopped'.
- **Negative control:** Two arms, both asserting absence. (1) The pre-flight abort path (DELI-059) constructs no scanner and must write NO summary. (2) A run whose ruleset fails to compile likewise constructs no scanner and must write NO summary. The file's presence must mean a scan actually ran — which is exactly what HostCleanup.run's summary-exists guard relies on before deleting anything.
- **Why this round:** ROUNDS.md assigns scan_summary_<run_id>.json to Round 3, and rightly: what distinguishes this capability is that the file is produced for cancelled and failed runs too, and only Round 3 delivers a mid-walk cancel. Its delivery blocks are cross-checked in Round 2 by DELI-051/056/083.

### `DELI-059` Placeholder-credential pre-flight abort

*core*

- **Must be true:** With the shipped placeholder credentials and any delivery channel enabled, the run ABORTS before any scanning: the result line begins with the abort message, both the error log and the processing log record it, and no scan artefacts are produced.
- **Threshold:** The returned text begins exactly 'SCAN ABORTED — XDR API credentials are not set' (em dash). scan_errors_<run_id>.log carries the same full message; yara_processing_<run_id>.log carries 'XDR API CREDENTIALS NOT SET —'. No scan_summary_<run_id>.json is written for that run (the finally block requires a constructed scanner). Zero matches rows and zero scans rows for that run_id.
- **Setup:** Deliver through the Action Center with a snippet prelude restoring the three placeholders — DEFAULT_XDR_API_KEY = "replace_with_xdr_standard_api_key", DEFAULT_XDR_API_ID = "replace_with_xdr_standard_api_id", DEFAULT_XDR_API_URL = "replace_with_xdr_standard_api_url" — because build_scanner_snippet substitutes real credentials into those exact literals by default. Do NOT assert on the __main__ exit code: the snippet rewrites that guard to `if False:`.
- **Evidence:** The action's stdout SCAN_RESULT line; <scanner_dir>/logs/scan_errors_<run_id>.log; <scanner_dir>/logs/yara_processing_<run_id>.log; absence of <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** With the same placeholders but options="create_alerts=false,write_dataset=false", the abort must NOT fire and the scan must run to completion — the gate is creds_placeholder AND (create_alerts OR write_dataset), so a deliberately delivery-free local scan is unaffected.
- **Why this round:** Catalogued under delivery, but the code path is driven by a deliberately bad configuration rather than by delivery volume — Round 3's 'deliberately bad option strings and env values' shape is what reaches it, and Round 2's flood must run with real credentials.

### `DELI-071` Comprehensive final report (statistics log only, never uploaded)

*low*

- **Must be true:** The comprehensive report is written once to the statistics log and never reaches the wire, and its efficiency score is exactly the documented arithmetic over this run's own counters.
- **Threshold:** statistics_<run_id>.log contains exactly 1 line matching 'COMPREHENSIVE SCAN REPORT | Efficiency Score: NN.N/100 | data={'. The score equals 100 - 20*(files_skipped/(files_scanned+files_skipped)) - 30*(failed_rules/(valid_rules+failed_rules)) computed from scan_summary_<run_id>.json, within 0.05. The serialized data blob is <= 4000 characters, and IF and only if it is exactly 4000 characters it is followed by '...(truncated)' — do not require that truncation occurred; _log truncates only when len(blob) > 4000, so a mandatory marker fails on a small crafted run. alert_delivery.alerts_queued == findings + rollups (the report never becomes an alert).
- **Setup:** The Round 3 crafted run, which produces both skips and failed-rule compilations so both penalty terms are non-zero.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log; scan_summary_<run_id>.json {files_scanned, files_skipped, valid_rules, failed_rules, alert_delivery}; corroborating 'Comprehensive final report generated - Efficiency Score: NN.N/100' in diagnostics_<run_id>.log.
- **Negative control:** A run whose ruleset compiles cleanly (failed_rules == 0) must show the rule-compilation penalty at exactly 0, i.e. score == 100 - 20*skip_rate — the two penalties must be independent, not a single blended fudge.
- **Why this round:** ROUNDS.md places the final report in Round 3, and that is where its inputs vary: the efficiency arithmetic is only falsifiable on a run with real skips and real compile failures, which is Round 3's crafted ruleset, not Round 2's flood.

### `DELI-072` Options-string surface for delivery knobs (and what is deliberately excluded)

*core*

- **Must be true:** An unknown option key is rejected BEFORE any scan state exists — no LogManager, no logs, no run_id — while a valid key is applied and a retired key is accepted and translated.
- **Threshold:** options="lookup_rotation=none": the run adds ZERO files to <scanner_dir>/logs, and the action's stdout contains 'SNIPPET_ERROR:' followed by a traceback ending "ValueError: Unknown option 'lookup_rotation'. Valid keys: collect_files, cpu_budget_pct, cpu_floor_pct, cpu_guarantee, cpu_headroom_pct, create_alerts, lookup_shard, tenant_id, workers, write_dataset" — ten names, comma-space separated and UNQUOTED (it is a ', '.join(sorted(...)), not a list repr). options="lookup_shard=wave1": scan_summary_<run_id>.json matches_dataset == 'yara_scanner_matches_v3_wave1_713163_<YYYYMM>'.
- **Setup:** Three Action Center runs: options="lookup_rotation=none", options="lookup_shard=wave1", options="throttle_mode=os". Do NOT assert on the __main__ traceback or exit 1 — build_scanner_snippet rewrites `if __name__ == "__main__":` to `if False:`, so the exception surfaces through the footer's own except branch as 'SNIPPET_ERROR:' instead.
- **Evidence:** The action's returned stdout; `ls <scanner_dir>/logs` immediately before and after the rejected run (identical listings); scan_summary_<run_id>.json matches_dataset and throttle_mode for the two accepted runs.
- **Negative control:** Retired keys must NOT be rejected: options="throttle_mode=os" must run to completion with scan_summary throttle_mode == "headroom" (translated by migrate_throttle_option), so existing scripts and scheduled jobs keep working while typos still fail loudly.
- **Why this round:** Catalogued as a delivery surface, but what drives the code path is a deliberately malformed option string — Round 3's stated shape ('deliberately bad option strings and env values'). Round 2 must run with valid options for its books to mean anything.

### `DELI-075` Endpoint IP identity resolved by NAME lookup — and its failure text is shipped as the IP

*supporting*

- **Must be true:** ip_address is the first non-loopback address returned by getaddrinfo on the HOSTNAME — not the interface used to reach the tenant — and when that lookup fails the failure sentence itself is shipped verbatim as the value everywhere the address appears.
- **Threshold:** Healthy run: scan_summary_<run_id>.json ip_address equals the first non-'127.' entry from socket.getaddrinfo(socket.gethostname(), None) computed independently over SSH at the same moment; no shipped value begins '127.'. Broken-resolution run: scan_summary ip_address, the matches rows' ip_address and the scans rows' ip_address all begin exactly 'Unable to determine IP address: ', and evidence/file_mapping.txt's 'IP Addresses: ' header carries that whole sentence (the list is joined, so it appears in full).
- **Setup:** Two runs on xdr-agent over SSH: one normal, one where socket.getaddrinfo(socket.gethostname(), None) genuinely raises. Do not rely on editing /etc/hosts — on a GCE VM the short hostname still resolves via the internal DNS search domains. Instead set an unresolvable hostname for the run (`sudo hostname yara-noresolve-$$`), verify first that `python3 -c 'import socket; socket.getaddrinfo(socket.gethostname(), None)'` actually raises, then run the scan and restore the original hostname immediately afterwards.
- **Evidence:** `jq -r .ip_address <scanner_dir>/logs/scan_summary_<run_id>.json`; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields ip_address` and the same column on yara_scanner_matches_v3_*; the 'IP Addresses: ' line in <scanner_dir>/evidence/file_mapping.txt.
- **Negative control:** The resolution failure must NOT be logged as an error and must NOT fail the scan — the broken-resolution run still reaches outcome "completed", and scan_errors_<run_id>.log carries no line about IP resolution. The failure surfaces as prose in a data field, nowhere else.
- **Why this round:** Catalogued under delivery because the value rides on every row, but the code path is only exercised by a deliberately broken host environment — Round 3's crafted/targeted shape. Round 1 and 2 both run on healthy hosts where only the positive arm is reachable.

### `DELI-076` file_creation_time is empty on every Linux match, by design  <sub>windows, darwin</sub>

*low*

- **Must be true:** For the SAME planted file and rule, the matches row's file_creation_time is an empty string on the Linux endpoint and a parseable ISO-8601 UTC timestamp on the Windows endpoint, while file_sha256 and file_size are populated on both.
- **Threshold:** Linux row: file_creation_time == "" (empty string, not null), <scanner_dir>/alert/<rule>.txt has NO 'File Creation Time:' line, and the alerts_<run_id>.log detection entry carries file_creation_time null. Windows row (xdragent2): file_creation_time matches ^\d{4}-\d{2}-\d{2}T.*\+00:00$ (st_ctime rendered UTC) and alert/<rule>.txt carries 'File Creation Time: <iso>'. file_sha256 non-empty and file_size > 0 on both.
- **Setup:** Plant a byte-identical decoy file and the same rule on xdr-agent (Linux) and xdragent2 (Windows, ssh as user `ayman`), and run the Round 3 crafted scan on both.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter run_id in ("<linux_run_id>", "<win_run_id>") | fields hostname, filename, file_creation_time, file_sha256, file_size`; <scanner_dir>/alert/<rule>.txt on each host; alerts_<run_id>.log detection entry.
- **Negative control:** The emptiness must be platform-specific and not a dead field: the Windows row for the SAME planted file must be populated, and the Linux row's other stat-derived fields (file_size, file_sha256) must be populated too.
- **Why this round:** Its distinguishing behaviour is a platform difference on a controlled, planted file — Round 3 is the round that plants decoys and runs the crafted multi-endpoint set. Delivery volume is irrelevant to it.

### `DELI-077` os_info is a hand-maintained string whose macOS name table stops at Darwin 24

*low*

- **Must be true:** os_info is one hand-built string that appears identically in every place a run reports it, its macOS name comes from a fixed four-entry table, and os_type is the coarse companion dashboards must segment on.
- **Threshold:** macOS 15.1 endpoint: os_info == 'macOS 15 (Sequoia) [arm64]' exactly — the mac_names table value, NOT the 'macOS (Darwin <release>) [<arch>]' unknown-major fallback — and os_type == 'macos'. Ubuntu VM: os_info == 'Linux ' + `uname -r` + ' [' + `uname -m` + ']' with both read over SSH at the same moment; additionally os_info must contain neither 'Ubuntu' nor the distro version string (kernel release only, no distro name); os_type == 'linux'. xdragent2: os_info matches ^Windows \S+ \[AMD64\]$, os_type == 'windows'. On each host, scan_summary_<run_id>.json os_info, the matches rows' os_info, the scans rows' os_info and the 'OS: ' header in evidence/file_mapping.txt are all byte-identical.
- **Setup:** Round 3 crafted run on all three endpoints.
- **Evidence:** scan_summary_<run_id>.json os_info; XQL over yara_scanner_matches_v3_* and yara_scanner_scans_v3_* fields os_info, os_type for each run_id; the 'OS: ' line in <scanner_dir>/evidence/file_mapping.txt.
- **Negative control:** A macOS major beyond the table (Darwin 25+) renders 'macOS (Darwin <release>) [<arch>]' and no lab host reaches it — so the criterion asserts only that os_type is correct on every host. os_type must never be derived from os_info; a broken os_info must leave os_type intact.
- **Why this round:** Nothing about delivery drives this string; what makes it falsifiable is running the same build on three different operating systems, which is Round 3's endpoint set.

### `DELI-078` scan_folder column carries the operator's RAW input string, or the literal "system"

*supporting*

- **Must be true:** The scan_folder value on both datasets and in the scan summary is the operator's input string verbatim — not the resolved target list — and reads the literal 'system' only when no scan_folder was supplied.
- **Threshold:** With scan_folder = '/opt/decoys, /opt/controls, /opt/nope' (note the spaces), every matches row and every scans row for the run carries scan_folder byte-identical to that string, spaces included, and scan_summary_<run_id>.json scan_folder is the same. The RESOLVED list appears only in yara_processing_<run_id>.log as "Scan limited to 2 folder(s): ['/opt/decoys', '/opt/controls']" (a Python list repr, so its elements ARE quoted) and in system_<run_id>.log's init_data.scan_targets. With scan_folder=None the column reads exactly 'system'.
- **Setup:** Two Round 3 runs — one with the comma-and-space multi-target string above, whose third entry does not exist so the ignore warning also fires; one passing scan_folder=None through the snippet footer.
- **Evidence:** XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | fields scan_folder` and the same over yara_scanner_scans_v3_*; scan_summary_<run_id>.json scan_folder; yara_processing_<run_id>.log 'Scan limited to N folder(s):' and 'Ignoring 1 specified scan folder(s) that are not valid directories on this endpoint:'; system_<run_id>.log 'SCAN SCOPE: Limited to specified targets:'.
- **Negative control:** scan_folder="default" must render as the literal 'default' on the wire while still selecting full scope — the 'system' literal is reserved for a None/empty input, and the two must not be collapsed.
- **Why this round:** The column is a delivery field, but what makes it falsifiable is scan-target resolution and its fallback ladder — a multi-target string with an invalid entry and a None case. ROUNDS.md assigns targeting to Round 3.

### `DELI-081` Condition-only (no-strings) rule matches reach NEITHER delivery channel

*core*

- **Must be true:** A rule that matches on its condition alone is counted as a detection locally but produces NO dataset row and NO alert, because both channels are gated on match_count > 0 in add_match — so scan_summary's match totals and the tenant's row/alert counts legitimately diverge.
- **Threshold:** scan_summary_<run_id>.json top_rules contains the condition-only rule with a count equal to the number of scanned files in the scoped target (>= 3), and matches / unique_rules_triggered include it. XQL count for that rule and run_id == 0. Zero XDR alerts whose alert_name contains that rule. <scanner_dir>/alert/cond_only.txt exists and contains the "YARA rule '<r>' matched file: <path>" header and the 80-character '=' separator, but NO 'Total string hits:' and no 'Matched Strings (showing'. In alerts_<run_id>.log, the 'YARA detection event' entry for a planted file carries, inside its detections list, an entry whose rule_name is the condition-only rule with match_count == 0. Do NOT assert total_string_matches == 0 on a file the control rule also matched — that field is summed across all rules that hit the file and is legitimately > 0 there; assert it == 0 only on the cond_only-exclusive file below.
- **Setup:** Round 3 crafted pack containing `rule cond_only { condition: filesize > 0 }` plus a control rule with strings that matches the SAME planted files, PLUS one extra planted file that only cond_only matches (so the total_string_matches == 0 form of the detection event is also exercised). Scope the run with scan_folder to the planted directory, so cond_only's top_rules count is the planted-file count rather than every non-empty file on the endpoint.
- **Evidence:** scan_summary_<run_id>.json {matches, unique_rules_triggered, top_rules}; XQL `dataset = yara_scanner_matches_v3_* | filter run_id = "<run_id>" | comp count() by rule`; <scanner_dir>/alert/cond_only.txt; <scanner_dir>/logs/alerts_<run_id>.log.
- **Negative control:** The string-bearing control rule on the SAME files must produce one dataset row and one alert per file — the silence must be caused by match_count == 0, not by the files being unreachable or the channels being down.
- **Why this round:** Catalogued as a delivery gap, but it is a detection-precision property: it needs a purpose-built condition-only rule and a planted string-bearing control on the same files, which is Round 3's crafted-pack shape. A flood of ordinary string rules never reaches the zero-match-count branch.

## Scan Lifecycle, Control & Error Handling

### `LIFE-002` Action Center cancel entry point (cancel, zero inputs)

*core*

- **Must be true:** The zero-input `cancel` entry point returns a single result string beginning `Cancel signal delivered (` that names the absolute flag path, and the file it names exists on disk immediately after the action reports success — the entry point never raises and never returns an empty result.
- **Threshold:** The returned text matches `^Cancel signal delivered \(<scanner_dir>/control/cancel.flag\) \| scanner running: (yes|no) \| scan_id=.+$` — exactly one `|`-separated triple, no traceback; `test -f <scanner_dir>/control/cancel.flag` succeeds and its mtime is within 30s of the action's completion; the Action Center action status is COMPLETED_SUCCESSFULLY.
- **Setup:** Invoke the `cancel` entry point (Action Center 'Run by entry point' → cancel, or the snippet built with mode="cancel") while the Round 3 crafted scan is walking. Do NOT use the console Cancel button on the running scan's action — that hard-kills the payload rather than exercising this entry point.
- **Evidence:** The action's stdout line `SCAN_RESULT: Cancel signal delivered (…)`; <scanner_dir>/control/cancel.flag on the endpoint (fetched over SSH).
- **Negative control:** Invoked on an endpoint with NO scan running, the same entry point must still return `Cancel signal delivered (` with `scanner running: no` — flag delivery is unconditional and must never degrade to an error just because nothing is running.

### `LIFE-003` CLI entry point — five ordered positional arguments

*supporting*

- **Must be true:** argv positions 1..5 map to yarafile / scan_folder / alert_severity / mode / options in that order, and an empty or whitespace-only argument selects the CONFIG_* default rather than being passed through as an empty value.
- **Threshold:** Run with argv = (<rules_b64>, /opt/round3tree, "   ", "", "cpu_guarantee=budget"): scan_summary_<run_id>.json "posture" ends `cpu=budget mode=scan` (mode came from CONFIG_MODE because argv[4] was blank) and yara_processing_<run_id>.log carries `Default XDR alert severity: low` (the blank argv[3] took the "low" default, not an empty string). A second run with argv[3]="high" must show `Default XDR alert severity: high` with everything else unchanged.
- **Setup:** Direct SSH invocation of the raw scanner on xdr-agent: `gcloud compute ssh xdr-agent --zone=us-central1-f --command="sudo python3 /opt/yara_scanner/xdr_yara_scanner.py <b64> /opt/round3tree '   ' '' 'cpu_guarantee=budget'"`. NOT via Action Center — build_scanner_snippet rewrites `if __name__ == "__main__":` to `if False:  # snippet-neutralized`, so the argv block never executes on that delivery.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "posture" and "throttle_mode"; <scanner_dir>/logs/yara_processing_<run_id>.log lines `Runtime posture: …` and `Default XDR alert severity: …`.
- **Negative control:** The same command with argv[4]="cancel" must short-circuit to the cancel handler — returning `Cancel signal delivered (` and creating no per-run logs — proving position 4 is mode and not the options string.
- **Why this round:** Round 3 owns option-string resolution and deliberately bad/blank inputs; the five-position argv mapping is the same resolution surface reached from the command line.

### `LIFE-004` SCAN_RESULT stdout line on the CLI path

*supporting*

- **Must be true:** The direct-execution path prints exactly one line beginning `SCAN_RESULT: ` on stdout and flushes it, and the text after the prefix equals run()'s return string character-for-character.
- **Threshold:** `grep -c '^SCAN_RESULT: ' <captured stdout>` == 1; the remainder of that line begins `Scan completed: ` and its trailing posture field equals scan_summary_<run_id>.json "posture" exactly; stdout contains no other line starting with `SCAN_RESULT`.
- **Setup:** The same SSH direct invocation as LIFE-003, with stdout captured to a file.
- **Evidence:** Captured stdout of the SSH command; <scanner_dir>/logs/scan_summary_<run_id>.json "posture".
- **Negative control:** The same scanner delivered through the Action Center snippet must also print the line exactly once (from the footer, with the __main__ block neutralized) — two `SCAN_RESULT: ` lines on that delivery would mean the guard was lost.
- **Why this round:** Only reachable on a direct-execution run, which Round 3 already stages over SSH for the argv and bad-option cases; folding it there avoids a second delivery just for one print.

### `LIFE-005` Exit code derived by string-matching the result line

*supporting*

- **Must be true:** The process exit code is derived solely by lower-cased prefix match on the result text: exit 1 iff the line starts with `scan failed`, `cancel failed`, or `scan aborted`; exit 0 otherwise — including a CANCELLED scan, whose line starts `Scan cancelled by operator:`.
- **Threshold:** Run A (normal completion, line starts `Scan completed:`) -> exit 0. Run B (cancelled mid-walk, line starts `Scan cancelled by operator:`) -> exit 0. Run C (credentials left as the shipped `replace_with_*` placeholders with delivery on, line starts `SCAN ABORTED — XDR API credentials are not set`) -> exit 1. Run D (mode=cancel against a read-only control dir, line starts `Cancel failed: `) -> exit 1. Run E (argv[1] is a base64 blob that decodes to text containing no YARA rule, so ScanConfig raises inside run()'s try and run()'s outer except returns `Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred`) -> exit 1. Run E is mandatory: without it the `scan failed` prefix is never exercised and the criterion cannot fail a build that dropped it from the prefix list.
- **Setup:** Five SSH direct invocations on xdr-agent — the exit code exists only on the `__main__` path, so none of these may be delivered through the Action Center snippet. Run C uses the unmodified repo copy of xdr_yara_scanner.py (creds never injected); Run D reuses LIFE-014's chmod 555 setup; Run E passes `$(printf 'this is not yara' | base64 -w0)` as argv[1].
- **Evidence:** `echo $?` captured immediately after each SSH command, paired with the captured `SCAN_RESULT: ` line from the same run.
- **Negative control:** Runs A and B are the controls: a completed scan and a CANCELLED scan must both exit 0. A build that treated cancellation as a failure passes A, C, D and E and fails only on B; a build that treated every non-empty result as success fails C, D and E.
- **Why this round:** The negative cases (aborted credentials, failed cancel) are deliberately-bad inputs, which is Round 3's shape; and the cancelled run whose exit code must be 0 exists only in Round 3.

### `LIFE-006` Startup-exception exit path (exit 1 with traceback)

*supporting*

- **Must be true:** An exception raised before run()'s try block — alert-severity parsing at the argv assignment, or options parsing at the _parse_options_string call — exits 1 with the two stderr markers and creates NO run artefacts at all: no per-run log files and no scan_summary JSON, because no ScanConfig was ever constructed.
- **Threshold:** Exit code == 1; stderr contains both `Critical startup error: Invalid alert_severity 'critical'. Use low, medium, or high.` and `Full traceback:`; `ls -1 <scanner_dir>/logs | wc -l` is identical before and after the invocation; zero new files matching `scan_summary_*.json`.
- **Setup:** SSH direct invocation on xdr-agent with argv[3]="critical": `python3 /opt/yara_scanner/xdr_yara_scanner.py <b64> /opt/round3tree critical`. Snapshot the logs directory listing immediately before and after.
- **Evidence:** Captured stderr; the before/after `ls -1 <scanner_dir>/logs` listings.
- **Negative control:** The identical command with argv[3]="high" must exit 0 and add the seven per-run log files (alerts_, statistics_, scan_errors_, performance_, uploads_, system_, yara_processing_) plus diagnostics_ and scan_summary_ — otherwise the zero-delta assertion is vacuous.

### `LIFE-007` run() — the full internal API with every behaviour knob

*supporting*

- **Must be true:** Every keyword parameter on run() is honoured, and any parameter left None falls back to its CONFIG_* constant within the SAME call — the fallback is per-parameter, not all-or-nothing.
- **Threshold:** A call with workers=4, cpu_guarantee='budget', collect_files=True and all other knobs left None yields scan_summary "posture" == `alerts=on dataset=on files=on cpu=budget mode=scan` exactly, "throttle_mode" == "budget", and a system-log init blob with max_workers == 4 and scan_queue_size == 8.
- **Setup:** SSH on xdr-agent: `python3 -c "import sys; sys.path.insert(0,'/opt/yara_scanner'); import xdr_yara_scanner as s; print(s.run(RULES_B64, '/opt/round3tree', 'low', workers=4, cpu_guarantee='budget', collect_files=True))"`. The Action Center snippet footer only passes five of run()'s fifteen parameters, so the full API needs this wrapper or a snippet `prelude`.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "posture" and "throttle_mode"; <scanner_dir>/logs/system_<run_id>.log `YARA Scanner initialization completed | data={...}` keys max_workers and scan_queue_size.
- **Negative control:** create_alerts and write_dataset, left as None in the same call, must stay `on` (their CONFIG constants are True) — a build that coerced None to False would flip both off while still honouring the three explicit knobs.

### `LIFE-008` Options string parsing with loud rejection of unknown keys

*core*

- **Must be true:** An unrecognised options key aborts the run before any ScanConfig exists: the ValueError propagates out of run(), the message names the offending key and lists exactly the ten valid keys, and the invocation leaves no per-run log files and no scan_summary JSON behind.
- **Threshold:** Message text is exactly `Unknown option 'foo'. Valid keys: collect_files, cpu_budget_pct, cpu_floor_pct, cpu_guarantee, cpu_headroom_pct, create_alerts, lookup_shard, tenant_id, workers, write_dataset` — ten names, comma-space separated, rendered as bare strings by `', '.join(sorted(_VALID_OPTION_KEYS))` (no quote characters, no brackets, unlike a list repr); CLI exit code 1; `ls -1 <scanner_dir>/logs | wc -l` unchanged across the invocation.
- **Setup:** Two deliveries of options="foo=1": (a) SSH direct invocation, where the __main__ handler writes `Critical startup error: Unknown option 'foo'. …` + `Full traceback:` to stderr; (b) the Action Center snippet, whose footer `except Exception` prints `SNIPPET_ERROR:` followed by a traceback ending in that same ValueError.
- **Evidence:** Captured stderr from (a); the action's stdout beginning `SNIPPET_ERROR:` from (b); the before/after `ls -1 <scanner_dir>/logs` listings.
- **Negative control:** options="throttle_mode=os" — a RETIRED key — must NOT raise; it is accepted at the parser and translated later (LIFE-009). A run with options="cpu_guarantee=budget" must also complete normally, so the rejection is specific to unknown keys and not to having an options string at all.

### `LIFE-009` Retired throttle_* options accepted and translated, not rejected

*supporting*

- **Must be true:** Retired throttle_* keys are accepted and translated rather than rejected or echoed: the resolved value is always one of headroom / budget / none, and the word passed in never appears as the resolved value anywhere.
- **Threshold:** throttle_mode=off -> "none"; throttle_mode=script -> "headroom"; throttle_mode=os -> "headroom"; throttle_mode=aggressive (unmapped) -> "headroom". In every case scan_summary "throttle_mode" equals the translated word EXACTLY and is one of {headroom, budget, none}; the scans-dataset row's throttle_mode column carries the same word; and the cpu token of "posture" — re.search(r'cpu=(\S+) mode=', posture).group(1) — equals it. Assert the untranslated word never survives by testing those two EXTRACTED VALUES against {off, script, os, aggressive, throttle_mode}, never by grepping the posture string: posture always contains the literal `off` in its `files=off` segment (CONFIG_COLLECT_FILES defaults False), so a substring search for `off` fails a correct build on every run.
- **Setup:** Four short Round 3 runs against /opt/round3tree, one per value, each with options="throttle_mode=<v>" and no cpu_guarantee kwarg.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "throttle_mode" and the `cpu=` token parsed out of "posture"; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, throttle_mode, posture`.
- **Negative control:** options="throttle_mode=os,cpu_guarantee=budget" must resolve to "budget" — migrate_throttle_option only sets cpu_guarantee when it is absent, so the explicit key must win. The other three retired keys (cpu_high_threshold, cpu_critical_threshold, max_pause_secs) must be dropped silently, changing neither posture nor throttle_mode.

### `LIFE-010` Options string overrides explicit kwargs and CONFIG constants

*supporting*

- **Must be true:** The options string wins over both the explicit kwarg and the CONFIG_* constant, and its raw string values are coerced by ScanConfig — so `create_alerts=false` genuinely disables the alert channel rather than being read as a truthy non-empty string.
- **Threshold:** A single call passing kwarg cpu_guarantee='none' together with options='cpu_guarantee=budget,create_alerts=false' yields scan_summary "posture" == `alerts=off dataset=on files=off cpu=budget mode=scan` exactly and "throttle_mode" == "budget"; scan_summary "matches" > 0 and dataset_delivery.records_added > 0 (proving the tree really did produce findings on the still-enabled channel) while "alert_delivery" shows findings == 0, alerts_queued == 0 and successful_uploads == 0; uploads_<run_id>.log contains zero `Queued finding alert: ` lines and zero `Alert batch ok (` lines — both are written through _throttled_log, whose log_manager IS bound by scan time, so their absence is a real suppression signal.
- **Setup:** SSH `python3 -c` wrapper on xdr-agent passing both the kwarg and the options string, against a tree that does produce matches (so alerts_queued == 0 is a real suppression, not an empty scan).
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "posture", "throttle_mode", "matches", "alert_delivery", "dataset_delivery"; <scanner_dir>/logs/yara_processing_<run_id>.log line `Runtime posture: alerts=off dataset=on files=off cpu=budget mode=scan`; <scanner_dir>/logs/uploads_<run_id>.log. Do NOT look for `Parsed-alerts upload disabled (create_alerts=false)` OR for `Upload worker thread started (batch=` / `Real-time upload thread started successfully` — ResultsUploader.log_manager is None at all of those points on every build, so none of those lines is ever written and their absence discriminates nothing.
- **Negative control:** The same kwarg with NO options string must produce `alerts=on … cpu=none` — proving the override actually flipped both values rather than the run having been hard-coded.

### `LIFE-011` mode=cancel short-circuit before any scanner initialisation

*supporting*

- **Must be true:** mode="cancel" short-circuits inside run() before ScanConfig is constructed: it writes the flag and returns, so no LogManager exists and the invocation produces no per-run log files and no scan_summary JSON.
- **Threshold:** The cancel invocation adds ZERO files to <scanner_dir>/logs/ (`ls -1 … | wc -l` unchanged) and no diagnostics_*.log; <scanner_dir>/control/cancel.flag parses as JSON with exactly the three keys {requested_at_ms, source, tenant_id_override}, source == "xdr_action", requested_at_ms within 30s of the invocation.
- **Setup:** Invoke the `cancel` entry point on an endpoint with no scan running, snapshotting `ls -1 <scanner_dir>/logs` before and after.
- **Evidence:** <scanner_dir>/control/cancel.flag contents; the before/after logs-directory listings.
- **Negative control:** A `main`/mode=scan invocation on the same endpoint must add the seven per-run log files plus diagnostics_ and scan_summary_ — without that, the zero-delta assertion proves nothing about the short-circuit.

### `LIFE-012` Cancel flag file — cooperative cross-process cancellation

*core*

- **Must be true:** A cancel flag dropped by a SEPARATE process stops the running scan: the scan-side watcher reads that flag's own `source` value into cancel_source, the run ends with outcome cancelled, and it stops early — fewer files scanned than the target holds.
- **Threshold:** scan_summary_<run_id>.json "outcome" == "cancelled" AND "cancel_source" == "xdr_action" (the value _handle_cancel_request writes — the watcher's "action_center" fallback would mean the flag body was unreadable); "files_scanned" strictly less than `find <target> -type f | wc -l` measured on the same tree.
- **Setup:** Round 3's long crafted scan; at ~90s in, deliver the `cancel` entry point (or write the same JSON over SSH). Both sides derive the path from _default_scanner_dir(), so if YARA_SCANNER_DIR was exported for the scan it must be exported identically for the cancel invocation.
- **Evidence:** <scanner_dir>/control/cancel.flag; <scanner_dir>/logs/scan_summary_<run_id>.json "outcome" and "cancel_source"; <scanner_dir>/logs/system_<run_id>.log line `Cancellation requested (source=xdr_action)`.
- **Negative control:** A flag written under a DIFFERENT YARA_SCANNER_DIR (e.g. /tmp/other_scanner/control/cancel.flag) must not stop the scan — that run must finish with outcome "completed" and cancel_source null, proving the watcher is bound to its own control dir and not to any cancel.flag on the host.

### `LIFE-013` Cancel reports liveness from running.json rather than the process table, on a window scaled to the heartbeat

*supporting*

- **Must be true:** Liveness is decided from control/running.json's `updated_at` field on a window of SCANS_HEARTBEAT_SECS*3+60 seconds — not from the process table — and the reported scan_id is whatever that file holds, including a stale file's scan_id, which must still be printed rather than replaced by n/a.
- **Threshold:** Window == 1860s at the 600s heartbeat default. Case A (scan actively running): returned text has `scanner running: yes` and `scan_id=<hostname>_<run_id>_yara_<12 hex chars>` matching the live run's config.scan_id. Case B (no scan; running.json rewritten with updated_at = now-7200 but its scan_id left intact): `scanner running: no` and `scan_id=<that same id>` — NOT `n/a`. Case C (running.json absent): `scanner running: no | scan_id=n/a`.
- **Setup:** Three cancel invocations on xdr-agent. Case B must edit the JSON's `updated_at` value (the code reads the field, not the file mtime) — `touch`-ing the file changes nothing.
- **Evidence:** The three returned `Cancel signal delivered (…) | scanner running: … | scan_id=…` strings; <scanner_dir>/control/running.json in each case.
- **Negative control:** In all three cases <scanner_dir>/control/cancel.flag must be (re)written — liveness reporting must never gate flag delivery, so a 'no' answer that also skipped the write is a failure.

### `LIFE-014` Cancel failure modes return an error string (never raise)

*supporting*

- **Must be true:** Cancel failures are returned as text, never raised: with the control directory present but not writable, the entry point returns a string starting `Cancel failed: cannot write ` and the process exits 1 via the result-prefix rule, with no Python traceback on stderr.
- **Threshold:** Returned line matches `^Cancel failed: cannot write <scanner_dir>/control/cancel.flag: `; CLI exit code == 1 (`cancel failed` is one of the three exit-1 prefixes); stderr contains no `Traceback (most recent call last)`; no cancel.flag is created.
- **Setup:** On xdr-agent: `sudo chmod 555 /opt/yara_scanner/control`, then invoke mode=cancel as a non-root user; restore `sudo chmod 755` afterwards. For the `Cancel failed: cannot create control dir ` variant, export YARA_SCANNER_DIR to a path under a read-only mount so os.makedirs itself fails.
- **Evidence:** Captured stdout (`SCAN_RESULT: Cancel failed: …`), captured stderr, and `echo $?`.
- **Negative control:** With 755 restored, the identical invocation must return `Cancel signal delivered (` and exit 0 — proving the failure text came from the permission state and not from a broken cancel path.

### `LIFE-015` Stale cancel-flag eviction at scan start (with compile-phase preservation)

*supporting*

- **Must be true:** A cancel flag whose mtime predates the YaraScanner-construction timestamp by more than the tolerance is deleted at scan start and does not cancel the run; a flag whose mtime is at or after that timestamp (minus the tolerance) survives to the watcher and is honoured. The baseline is `_process_started_at`, stamped at the END of YaraScanner.__init__ — i.e. AFTER _load_or_compile_rules returns — so a flag delivered DURING rule compilation is evicted as stale, contrary to _start_cancellation_watcher's docstring. Assert the code's behaviour, not the docstring's.
- **Threshold:** CANCEL_STALE_TOLERANCE_SECS == 2.0 (a bare literal, not env-reachable; its only reader is the staleness test). Case A (flag written, scanner started >=10s later): system_<run_id>.log contains `Removed stale cancel flag from a previous run`, the flag file is gone, scan_summary "outcome" == "completed" and "cancel_source" == null. Case B (flag written the instant `YaraScanner initialized with 2 workers` appears in system_<run_id>.log — that line is emitted microseconds after the baseline is stamped): `Removed stale cancel flag from a previous run` is ABSENT, the flag survives to the watcher, "outcome" == "cancelled", "cancel_source" == "xdr_action". Case C (compile-phase delivery: flag written 3s after launch while `YaraScanner initialized with` has NOT yet appeared): the flag IS evicted, `Removed stale cancel flag from a previous run` IS present, "outcome" == "completed" — the shape the docstring promises to preserve and the code does not.
- **Setup:** Three SSH runs on xdr-agent. Case B polls system_<run_id>.log at 0.2s cadence for `YaraScanner initialized with` and writes the flag on the first match. Case C uses a ~500-rule pack with YARA_RULE_CACHE=0 exported so the compile is genuinely paid (~90s of window) and writes the flag 3s after launch.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log; <scanner_dir>/logs/scan_summary_<run_id>.json "outcome" and "cancel_source"; presence/absence of <scanner_dir>/control/cancel.flag sampled just after `=== ENHANCED SYSTEM SCAN INITIATED ===`.
- **Negative control:** Case B is the control the eviction predicate must NOT touch: a flag newer than the construction baseline must survive. Additionally `Could not evaluate pre-existing cancel flag:` must appear in none of the three cases — that line means the staleness test itself threw.

### `LIFE-016` Cancel watcher polling thread

*supporting*

- **Must be true:** The cancel flag is noticed by a dedicated polling thread within one poll interval, exactly once, and the watcher itself never errors.
- **Threshold:** (timestamp of the `Cancellation requested (source=xdr_action)` line in system_<run_id>.log) − (mtime of control/cancel.flag) ≤ 2 × CANCEL_POLL_SECS = 10s at the 5s default; exactly one such line in the file; zero `Cancel watcher error: ` lines in scan_errors_<run_id>.log.
- **Setup:** Round 3's cancelled run; capture the flag mtime with `stat -c %y /opt/yara_scanner/control/cancel.flag` immediately after the cancel invocation.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log line and its `[YYYY-MM-DD HH:MM:SS.mmm]` prefix; `stat` output for control/cancel.flag; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** A repeat run with YARA_CANCEL_POLL_SECS=1 must bring the same latency to ≤ 2s — proving the constant really is the poll cadence and the 10s figure is a bound, not a coincidence of scan timing.

### `LIFE-017` Idempotent cancel request — first source wins

*low*

- **Must be true:** The cancellation is recorded exactly once: a second cancel delivery after the first has been observed adds no further `Cancellation requested` line and does not change cancel_source, which stays a single scalar value.
- **Threshold:** The SECOND delivery must carry a DIFFERENT source. Then: `grep -c 'Cancellation requested (source=' <scanner_dir>/logs/system_<run_id>.log` == 1 and that single line reads `source=xdr_action`; `grep -c 'second_operator' <scanner_dir>/logs/*_<run_id>.log <scanner_dir>/logs/scan_summary_<run_id>.json` == 0; scan_summary "cancel_source" == "xdr_action" as a single JSON string (not an array, not a comma-joined pair); the terminal scans row's message == `cancelled by operator (source=xdr_action)`, containing exactly one `source=`.
- **Setup:** Deliver the `cancel` entry point once during the walk of the Round 3 crafted scan. ~15s later, overwrite <scanner_dir>/control/cancel.flag over SSH with the same three-key JSON shape but `"source": "second_operator"`. Two identical `cancel` invocations cannot decide this criterion.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log grep count; scan_summary_<run_id>.json "cancel_source"; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "cancelled" | fields message`.
- **Negative control:** The `second_operator` string is itself the control: it must appear in no per-run log, in no summary field and in no dataset row — a last-wins build surfaces it in cancel_source and in the terminal row's message. Do NOT mix a POSIX signal into this run: the SIGTERM/SIGINT handler sets cancel_source BARE — outside _cancel_lock and without the idempotence guard, to stay async-signal-safe — so it legitimately overwrites an earlier value.

### `LIFE-018` SIGTERM/SIGINT routed into the graceful cancel path

*supporting*

- **Must be true:** SIGTERM and SIGINT are routed into the graceful cancel path rather than killing the process: the run ends cancelled with cancel_source `signal:<signum>`, and it still emits its terminal lifecycle row and writes its scan_summary.
- **Threshold:** After `kill -TERM <pid>` during the walk: scan_summary "cancel_source" == "signal:15", "outcome" == "cancelled", and exactly one yara_scanner_scans_v3_* row for that run_id with status == "cancelled" and message == `cancelled by operator (source=signal:15)`. Repeating with `kill -INT` gives "signal:2" and the same shape.
- **Setup:** SSH-launched foreground run on xdr-agent; send the signal only after `=== ACTIVE SCANNING PHASE STARTED ===` appears in system_<run_id>.log. Handlers install on the main thread only (the install loop swallows the ValueError otherwise), so this must be the direct-execution delivery — not the Action Center console Cancel button, which hard-kills the payload and orphans the lifecycle row.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" | fields status, message`.
- **Negative control:** A signal delivered BEFORE the handler install (during rule compilation) must not be counted against this criterion — at that point SIGTERM still has its default disposition and the process dies with no summary at all.

### `LIFE-019` Cancellation is a SUCCESS outcome, and returns early from run()

*core*

- **Must be true:** Cancellation is a success outcome delivered by an early return: the result line begins `Scan cancelled by operator: `, outcome is cancelled, and none of the completed-path work after the return (evidence collection, comprehensive report, cleanup scheduling, the success banner) runs — yet a terminal lifecycle row with status cancelled still exists.
- **Threshold:** Result line matches `^Scan cancelled by operator: \d+ files scanned \| \d+ matches found \| alerts=`; scan_summary "outcome" == "cancelled"; `<scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` does NOT exist; system_<run_id>.log has zero `Evidence collection completed successfully` and zero `=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===`; statistics_<run_id>.log has zero `COMPREHENSIVE SCAN REPORT | Efficiency Score:`; exactly one scans_v3 row with status "cancelled"; CLI exit code 0.
- **Setup:** Round 3's cancelled run (cancel flag delivered mid-walk).
- **Evidence:** The `SCAN_RESULT: ` text; scan_summary_<run_id>.json "outcome"; `ls <scanner_dir>/evidence/`; <scanner_dir>/logs/system_<run_id>.log; <scanner_dir>/logs/statistics_<run_id>.log; XQL over yara_scanner_scans_v3_* for the run_id.
- **Negative control:** The completed Round 3 run must contain the ZIP, both system lines and the COMPREHENSIVE SCAN REPORT line for its own run_id — otherwise the four absences above prove nothing.

### `LIFE-020` Delivery-shortfall reporting on the cancelled path

*supporting*

- **Must be true:** The cancelled path reports its delivery shortfall too: when the cancelled run's books show losses, the same _delivery_shortfall text is appended to the result line, written to scan_summary.delivery_shortfall, and logged to scan_errors with the ASCII-hyphen prefix `DELIVERY INCOMPLETE - ` — the completed path's em-dash prefix must not appear in that run.
- **Threshold:** scan_summary "delivery_shortfall" != "" and starts `alerts: `; the SCAN_RESULT tail and the text after `DELIVERY INCOMPLETE - ` in scan_errors_<run_id>.log are byte-identical (the same _cancel_shortfall string) and both end with `— findings are complete in the local logs on this endpoint`; scan_summary.delivery_shortfall is byte-identical to them too — valid only because the lookup drain budgets are left at their defaults, so uploads_<run_id>.log shows `Lookup dataset worker stopped (` and NO `Lookup uploader thread did not stop within`, proving the second computation saw settled counters; `grep -c 'DELIVERY INCOMPLETE - ' scan_errors_<run_id>.log` == 1 and `grep -c 'DELIVERY INCOMPLETE — ' scan_errors_<run_id>.log` == 0.
- **Setup:** Round 3 crafted scan against a subtree planted with >=3,000 matching files, with ONLY YARA_ALERT_DRAIN_MAX_SECS=0 exported (drain_secs collapses to 0, so the alert backlog is booked undelivered) and the lookup drain budgets left at their defaults, cancel flag delivered while the alert queue backlog is still growing. Do NOT zero YARA_LOOKUP_DRAIN_MAX_SECS: it leaves the lookup worker thread alive past stop() and makes the three texts legitimately differ.
- **Evidence:** The `SCAN_RESULT: Scan cancelled by operator: … | alerts: X of Y NOT delivered; dataset rows: N of M NOT confirmed …` text; scan_summary_<run_id>.json "delivery_shortfall"; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** A cancelled run with the drain budgets at their defaults and a small match count must yield delivery_shortfall == "" and zero `DELIVERY INCOMPLETE` lines of either dash — the report must not fire merely because the run was cancelled.
- **Why this round:** The shortfall text itself is Round 2's spine, but THIS capability is the cancelled branch's own copy of it — reachable only on a run that is cancelled, which exists only in Round 3. The forcing setup supplies the delivery deficit that Round 2 would otherwise provide.

### `LIFE-022` CANCEL_DRAIN_DEADLINE_SECS — dead constant

*low*

- **Must be true:** CANCEL_DRAIN_DEADLINE_SECS has no reader anywhere in the scanner: setting YARA_CANCEL_DEADLINE_SECS changes nothing observable, and in particular does not clip the post-cancel uploader drain. Note that `Enhanced cleanup completed in` is NOT the probe for this — cleanup_total_time is captured before the terminal row is emitted and before the uploaders are stopped, so it excludes both drains on every build.
- **Threshold:** Static: `grep -c CANCEL_DRAIN_DEADLINE_SECS <scanner source>` == 1 (the definition line is its only occurrence). Live, two cancelled runs against the same planted match-heavy subtree cancelled at the same point, one with YARA_CANCEL_DEADLINE_SECS=1 and one with =900: (a) the wall clock from the `Alert delivery final: ` line in uploads_<run_id>.log to the `Enhanced cleanup completed in` line in system_<run_id>.log — the window that actually contains the lookup drain — is > 5.0s on BOTH runs and within +/-20% between them; (b) scan_summary alert_delivery.successful_uploads and alert_delivery.undelivered agree between the two runs to within +/-5% (a build that wired the constant in as a drain deadline would strand alerts on the =1 run and not on the =900 run); (c) `grep -ci 'cancel_deadline\|CANCEL_DRAIN_DEADLINE' <scanner_dir>/logs/*_<run_id>.log <scanner_dir>/logs/scan_summary_<run_id>.json` == 0.
- **Setup:** Repeat Round 3's cancelled run twice: once with YARA_CANCEL_DEADLINE_SECS=1, once with =900, both cancelled at the same point with the same planted match-heavy subtree.
- **Evidence:** Timestamps of `Alert delivery final: ` (uploads_<run_id>.log) and `Enhanced cleanup completed in` (system_<run_id>.log) on both runs; scan_summary_<run_id>.json "alert_delivery" on both runs; the grep across the seven per-run logs and the summary JSON; `grep -c` over the scanner source for the symbol.
- **Negative control:** The =900 run's Alert-delivery-final -> cleanup-completed window and its alert_delivery books must match the =1 run's within the bands above — the value must not matter in either direction, so a build that made the drain LONGER with a larger value also fails.
- **Why this round:** Nominally a cancellation budget, so the only meaningful place to prove it is inert is a cancelled run. Kept as a criterion rather than not_covered because it is decidable by a negative assertion: a build that started reading the constant would clip the post-cancel drain and fail the threshold below.

### `LIFE-031` scan_summary_<run_id>.json — the machine-readable per-run record

*core*

- **Must be true:** Exactly one scan_summary_<run_id>.json is written per run, atomically, and only AFTER both uploaders have drained — so its delivery blocks are final and no temp file survives.
- **Threshold:** Exactly one <scanner_dir>/logs/scan_summary_<run_id>.json per run_id; it parses as JSON with "schema" == "yara_scan_summary/v1" and carries run_id, scan_id, tenant_id, hostname, matches_dataset, scans_dataset and posture from the base record plus outcome/duration_secs/files_scanned/alert_delivery/dataset_delivery/delivery_shortfall; zero files matching `scan_summary_*.tmp` in logs/; system_<run_id>.log has exactly one `Scan summary written: scan_summary_<run_id>.json`; zero `Failed to write scan summary JSON: ` in scan_errors_<run_id>.log and zero `scan summary write failed: `; the JSON's alert_delivery.successful_uploads equals the `ok=` value in the single `Alert delivery final:` line of uploads_<run_id>.log.
- **Setup:** Check on all three Round 3 runs — completed, cancelled, and the fault-injected failure — the file must exist and satisfy the above on every outcome.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json; `ls -1 <scanner_dir>/logs/scan_summary_*`; <scanner_dir>/logs/system_<run_id>.log; <scanner_dir>/logs/uploads_<run_id>.log; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** The credentials-placeholder abort must produce NO scan_summary at all — it returns from run() before a scanner object exists and the summary block is guarded on `scanner is not None`. Its absence there is correct behaviour, not a failure of this criterion.

### `LIFE-032` Outcome derivation for the summary (cancelled > failed > completed)

*supporting*

- **Must be true:** outcome is derived by strict precedence cancelled > failed > completed, and it agrees with the terminal lifecycle row's independently-derived status on every run whose crash (if any) happened before cleanup.
- **Threshold:** Three Round 3 runs, each checked as a pair. Completed run: scan_summary "outcome" == "completed" AND terminal scans row status == "completed". Cancelled run: both == "cancelled", even when that run's scan_errors log also carries failure text — cancellation outranks failure. Fault-injected fatal run: both == "failed". No run may show "completed" in the summary while its terminal row says otherwise.
- **Setup:** The three Round 3 runs. The fatal run needs fault injection — no external stimulus reaches _mark_scan_failed — delivered through the Action Center snippet's `prelude` (or an SSH `python3 -c` wrapper) that wraps LogManager.log_system to raise when the message is `=== ACTIVE SCANNING PHASE STARTED ===`; that call sits inside scan_system's outer try but outside the per-target try, so it lands on the `_mark_scan_failed("Critical error during scan execution: …")` arm.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "outcome" for each run; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status in ("completed","cancelled","failed") | fields status` for each.
- **Negative control:** A crash occurring AFTER _perform_enhanced_cleanup has returned is the one permitted disagreement — the terminal row will already read "completed" while the summary derives "failed". Do not score that shape as a failure of this criterion.

### `LIFE-033` Duration fallback chain in the summary

*low*

- **Must be true:** duration_secs is never null on a run that reached the scan phase: the cancelled and failed paths return from run() before scan_total_time is ever assigned, so the fallback to (now − scan_start_time) must supply it, and scan_rate_fps is exactly round(files_scanned / duration_secs, 2).
- **Threshold:** On all three Round 3 runs, "duration_secs" is a number > 0; |duration_secs - (process exit wall clock - the timestamp of `=== STARTING ENHANCED SYSTEM SCAN (STANDARDIZED) ===`)| <= 5s on the cancelled and failed runs (whose value is taken in the finally, after cleanup); "scan_rate_fps" == round(files_scanned / duration_secs, 2) to 2 decimal places on every run with a positive duration_secs; scan_rate_fps == 0 exactly when duration_secs is null or 0 OR files_scanned == 0 — do NOT state it as an iff on duration alone, because the fault-injected failed run reports files_scanned == 0 with duration_secs > 0 on a correct build.
- **Setup:** The three Round 3 runs; the cancelled and failed ones are what exercise the fallback, since scan_total_time is only bound on the success path.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "duration_secs", "scan_rate_fps", "files_scanned"; the `=== STARTING ENHANCED SYSTEM SCAN (STANDARDIZED) ===` timestamp in system_<run_id>.log.
- **Negative control:** On the COMPLETED run, duration_secs is captured at scan end (before evidence collection and cleanup scheduling), so it is legitimately SMALLER than the cancelled run's wall-clock-to-summary measure. Do not require the two branches to include the same phases — only that both are non-null and > 0.

### `LIFE-035` Success result line composition (skipped rules, excluded targets, cpu-slept, posture)

*core*

- **Must be true:** The success result line is composed of exactly the documented fields in order, the two optional segments are present if and only if their counts are non-zero, and every number on the line equals the corresponding scan_summary field.
- **Threshold:** The line matches `^Scan completed: <files_scanned> files scanned \| <failed_rules> rules failed compilation( \| <skipped_rules> rules skipped \(module unavailable\))? \| <matches> matches found \| cpu-slept <N>s \| <posture>( \| WARNING: <K> requested target\(s\) EXCLUDED by the skip list, nothing under them was scanned: .*?)?( \| .+ — findings are complete in the local logs on this endpoint)?$`, where the final optional group is present if and only if scan_summary "delivery_shortfall" != "" and its text equals that field exactly. Each number equals scan_summary files_scanned / failed_rules / skipped_rules / matches; `cpu-slept <N>s` is total_paused_secs rendered with %.0f; the excluded segment lists min(3, K) bare paths joined by `, ` — plain strings, no quotes and no brackets, because the code joins the list elements rather than printing the list — and ends with the literal ` ...` if and only if K > 3; K == len(scan_summary "excluded_targets").
- **Setup:** A Round 3 run whose scan_folder names four Linux platform-skip targets (/proc,/sys,/dev,/run) plus /opt/round3tree, with a rule pack containing at least one rule importing an unavailable module (skipped_rules > 0) and at least one malformed rule (failed_rules > 0). Read scan_summary "delivery_shortfall" first and apply the matching branch of the regex — the field, not an assumption, decides which form the line takes.
- **Evidence:** The `SCAN_RESULT: Scan completed: …` text; <scanner_dir>/logs/scan_summary_<run_id>.json fields excluded_targets, files_scanned, failed_rules, skipped_rules, matches, total_paused_secs.
- **Negative control:** A run with zero skipped rules and zero excluded targets must OMIT both optional segments entirely — no ` | 0 rules skipped (module unavailable)` and no ` | WARNING:` fragment — so their presence is genuinely conditional and not a constant.

### `LIFE-036` Excluded-target detection at two different layers

*core*

- **Must be true:** A requested target that sits under a platform skip path is named at BOTH layers — once at config time from skip_paths, once at walk time from _is_special_file — and a requested sibling that is not under any skip path is scanned normally and named at neither.
- **Threshold:** With scan_folder = "/proc,/sys,/opt/round3tree" on Linux: yara_processing_<run_id>.log contains `2 of 3 scan folder(s) sit under a platform skip-path and will yield no files: /proc (excluded by '/proc/'), /sys (excluded by '/sys/')`; scan_errors_<run_id>.log contains exactly two `Requested scan target is excluded by the skip list, so nothing under it will be scanned: ` lines, one naming /proc and one naming /sys; scan_summary "excluded_targets" has length 2 and contains /proc and /sys only; files_scanned > 0, all attributable to /opt/round3tree.
- **Setup:** xdr-agent, with /opt/round3tree planted with ≥200 files. Note /opt/yara_scanner/ is itself a Linux skip path — the tree must NOT be placed inside the scanner directory.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log; <scanner_dir>/logs/scan_errors_<run_id>.log; <scanner_dir>/logs/scan_summary_<run_id>.json "excluded_targets"; <scanner_dir>/logs/statistics_<run_id>.log line `Target scan completed: /opt/round3tree` with files_found > 0.
- **Negative control:** /opt/round3tree — a real directory not under any skip path — must appear in neither log line, must be absent from excluded_targets, and must yield files_found > 0. Separately, a run with scan_folder = "/proc,/sys" (all targets excluded) must ALSO emit `EVERY requested scan folder is excluded by the platform skip-list - this scan will scan 0 files.`, while the mixed run above must NOT.

### `LIFE-037` Fatal-failure path — status, evidence, and result line

*core*

- **Must be true:** A fatal failure still tells the story: the failure branch logs its reasons with a bounded failure_reasons array, emits a terminal `failed` status, collects the evidence ZIP, and returns a `Scan failed:` result line carrying the fatal-failure count.
- **Threshold:** scan_errors_<run_id>.log contains `Scan stopped due to fatal failures | data={…}` whose blob carries failure_count and a failure_reasons array of length min(failure_count, 20); `<scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` EXISTS; system_<run_id>.log contains `Evidence collected from failed scan` and NOT `Evidence collection failed after fatal failure: `; the result line matches `^Scan failed: \d+ files scanned \| \d+ rules failed compilation \| \d+ matches found \| Fatal failures: \d+$` with the trailing number equal to failure_count; scan_summary "outcome" == "failed". Do NOT assert a process exit code here — reaching _mark_scan_failed requires the fault-injection prelude, deliverable only through the Action Center snippet (no exit code surfaces) or an SSH `python3 -c` wrapper (module import, so the `__main__` exit-code block never executes). The `Scan failed:` -> exit 1 mapping is decided by LIFE-005's Run E.
- **Setup:** Fault injection is required — no external stimulus reaches _mark_scan_failed, because scan_file absorbs per-file errors and the per-target try absorbs walk errors. Deliver via the Action Center snippet's `prelude` (or an SSH `python3 -c` wrapper) that wraps LogManager.log_system to raise on the `=== ACTIVE SCANNING PHASE STARTED ===` message; that call is inside scan_system's outer try but outside the per-target try, so it reaches _mark_scan_failed. Both deliveries forgo the process exit code.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log; `ls <scanner_dir>/evidence/`; <scanner_dir>/logs/system_<run_id>.log; the `SCAN_RESULT: ` text; <scanner_dir>/logs/scan_summary_<run_id>.json "outcome".
- **Negative control:** The completed Round 3 run must contain neither `Scan stopped due to fatal failures` nor `Evidence collected from failed scan`, and its ZIP must be accompanied by `Evidence collection completed successfully` instead — proving the ZIP on the failed run came from the failure branch, not from the success path.

### `LIFE-038` _mark_scan_failed — the only way scan_failed becomes true mid-scan

*supporting*

- **Must be true:** _mark_scan_failed is the only mid-scan route to scan_failed, and every call leaves three consistent traces: a failure_reasons entry naming the cause, a `SCAN FAILED | ` final-results line instead of the `SCAN COMPLETED | ` one (the label is derived from scan_failed, so the two can never both appear for one run_id), and a terminal `failed` lifecycle row whose message is the joined reasons.
- **Threshold:** On the fault-injected run: scan_errors_<run_id>.log contains exactly one `SCAN FAILED | Time: … | Files: … scanned, … skipped | Detections: … | Rate: … files/sec` line whose data blob carries a non-empty failure_reasons array whose first entry starts `Critical error during scan execution: `; statistics_<run_id>.log contains ZERO `SCAN COMPLETED | Time: ` lines for that run_id; the terminal scans_v3 row has status == "failed" and message == the first up-to-three reasons joined by `; `; scan_summary "outcome" == "failed", "files_scanned" == 0, and that 0 equals the terminal row's files_scanned. Do NOT assert files_scanned < `find <target> -type f | wc -l` as evidence that scan_active was cleared — the only reachable injection point precedes the target loop, so no file is ever enqueued and the inequality is vacuously true on every build.
- **Setup:** The same prelude-based fault injection as LIFE-037.
- **Evidence:** <scanner_dir>/logs/scan_errors_<run_id>.log `SCAN FAILED | `; XQL `dataset = yara_scanner_scans_v3_* | filter run_id = "<run_id>" and status = "failed" | fields message`; <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** On the completed run, statistics_<run_id>.log must carry the same builder's other label — `SCAN COMPLETED | Time: …` — and scan_errors_<run_id>.log must carry neither `SCAN FAILED | ` nor any failure_reasons blob. The label is derived from scan_failed, so exactly one of the two must appear per run_id, and never both.

### `LIFE-039` Per-file error classification with a BOUNDED skip-reason key

*supporting*

- **Must be true:** Per-file scan errors collapse into a bounded set of type-labelled skip reasons: no skip_breakdown key contains a filesystem path, an errno or an exception message, and the number of distinct keys does not grow with the number of errored files — while the per-file path and message are still recorded once per file in scan_errors.
- **Threshold:** With >=2,000 files erroring, the final skip_breakdown has <=12 distinct keys; no key contains `Errno`, `: `, a drive-letter prefix (`C:`), or any component of the scanned tree's path (`round3tree`, `/opt/`, `/tmp/`), and no key exceeds 40 characters; every error key reads exactly `Scan error (<ExceptionTypeName>)`; the sum of the `Scan error (…)` counts equals the number of `Error scanning file ` lines in scan_errors_<run_id>.log; PermissionError files land under the separate fixed labels `Permission denied` / `No read permission`, never under a `Scan error (…)` key. Do NOT assert 'zero keys contain `/`': `Junction/symlink duplicate` and `Junction/symlink skip` are legitimate fixed labels containing a forward slash.
- **Setup:** A completed Round 3 run against a tree with a churn generator (a shell loop creating and deleting files under the target throughout the walk) so files vanish between scan_file's existence check and rules.match — yara.Error then yields `Scan error (Error)` — plus a directory of chmod-000 files scanned as a non-root user for the permission labels.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log line `Skip reasons: …` with its `skip_breakdown` data blob, and the same dict inside the `COMPREHENSIVE SCAN REPORT | Efficiency Score: ` line's `file_processing.skip_breakdown`. Note LogManager caps every data blob at 4,000 characters and appends `...(truncated)` — a skip_breakdown large enough to truncate is itself a failure of this criterion. Per-file detail: `Error scanning file <path>: ` in scan_errors_<run_id>.log.
- **Negative control:** Genuinely different failure types must stay distinguishable: the run must show at least two SEPARATE `Scan error (…)` keys for two different exception types, not one merged generic bucket — bounding the key set must not come from collapsing everything into one label.

### `LIFE-040` Worker error tiers — per-file error vs fatal worker error

*low*

- **Must be true:** The two worker error tiers are distinct and only the file tier fires in practice: scan_file absorbs per-file exceptions and returns a skip reason, so on an error-rich run the worker emits neither `Worker ScanWorker-N error:` nor `Worker ScanWorker-N fatal error:`, every worker's `stopped` record reports errors_encountered == 0, and the run still completes.
- **Threshold:** On the LIFE-039 churn run: `grep -cE 'Worker ScanWorker-[0-9]+ error: ' scan_errors_<run_id>.log` == 0 and `grep -c 'fatal error: ' scan_errors_<run_id>.log` == 0; system_<run_id>.log has exactly one `Worker ScanWorker-N started` and one `Worker ScanWorker-N stopped` line per worker (2 of each at CONFIG_WORKERS=2); each `stopped` record's data blob has errors_encountered == 0 while the run's skip_breakdown `Scan error (…)` counts total > 0; scan_summary "outcome" == "completed".
- **Setup:** The LIFE-039 churn run, reused — no separate scan needed.
- **Evidence:** <scanner_dir>/logs/system_<run_id>.log `Worker ScanWorker-N started` / `Worker ScanWorker-N stopped | data={…}`; <scanner_dir>/logs/scan_errors_<run_id>.log; <scanner_dir>/logs/statistics_<run_id>.log skip_breakdown.
- **Negative control:** The counters must not be dead: the sum of files_processed across the `stopped` records must equal scan_summary "files_scanned" — proving the same finally block that reports errors_encountered == 0 is reporting live numbers, not zeros from a path that never ran.
- **Why this round:** Per-file and fatal error handling is a Round 3 subject. Written as a negative assertion because both of the worker's own except arms sit outside everything scan_file already catches: scan_file returns (False, reason) for PermissionError and for every other exception, so on a live run neither the worker's non-fatal nor its fatal branch is reachable by external stimulus.

### `LIFE-041` KeyboardInterrupt during the scan is a FAILURE, not a cancel

*low*

- **Must be true:** KeyboardInterrupt cannot reach the scan phase: SIGINT is trapped by the cancel handler installed immediately after scanner construction, so an interrupt during the walk produces cancel_source `signal:2` with outcome `cancelled`, and the `Scan interrupted by user (Ctrl+C)` branch never fires.
- **Threshold:** After `kill -INT <pid>` delivered during the walk: scan_summary "cancel_source" == "signal:2", "outcome" == "cancelled", CLI exit code 0; `grep -c 'Scan interrupted by user (Ctrl+C)' system_<run_id>.log` == 0; the terminal scans_v3 row status == "cancelled", not "failed"; `status_uploader` never reaches "interrupted" (diagnostics_<run_id>.log has no `Scan status changed to: interrupted`).
- **Setup:** SSH foreground run on xdr-agent; send `kill -INT` only after `=== ACTIVE SCANNING PHASE STARTED ===` has appeared in system_<run_id>.log.
- **Evidence:** <scanner_dir>/logs/scan_summary_<run_id>.json "cancel_source" and "outcome"; <scanner_dir>/logs/system_<run_id>.log; <scanner_dir>/logs/diagnostics_<run_id>.log; XQL terminal row for the run_id.
- **Negative control:** An interrupt delivered BEFORE the handler install — during rule compilation, with YARA_RULE_CACHE=0 and a large pack — kills the process with a KeyboardInterrupt traceback and no scan_summary at all. That shape is outside this criterion's scope and must not be scored against it.
- **Why this round:** Kept as a criterion rather than not_covered because it is decidable by a negative assertion. The positive branch is unreachable on any delivery: SIGINT is trapped by _sig_cancel before scan_system() is entered, so no KeyboardInterrupt can be raised inside the guarded block. A build that dropped the handler install would fail this criterion by producing outcome "failed" with cancel_source null.

### `LIFE-042` Critical-error handler — stderr/stdout dump, 2-second sleep, and marker

*core*

- **Must be true:** A crash inside run()'s try block never escapes to the caller: run() RETURNS the 'Scan failed: … | Critical error occurred' line, and the CRITICAL_ERROR record lands in exactly those channels that already existed at crash time and in EVERY one of them — scan_errors_ only if LogManager was built (run() line 7518), yara_processing_ only if ScanConfig got past ErrorLogger construction (line 2882), script_exceptions_ only if exception_logger had been bound (run() line 7553) — and never in a channel that did not exist. When the crash precedes all three (a ScanConfig raise), it correctly reaches none of them, and the only artefacts are the returned line and stderr.
- **Threshold:** Crash A (pack whose single rule has a syntax error, so LogManager and exception_logger exist but `scanner` is still None because YaraScanner.__init__ raises at line 5198): exactly 1 line containing 'CRITICAL_ERROR: Critical scanner error: ' in logs/scan_errors_<run_id>.log AND exactly 1 in logs/yara_processing_<run_id>.log; logs/script_exceptions_<run_id>.log exists and contains 'Context: main_function_critical_error'; NO logs/scan_summary_<run_id>.json for that run_id (the finally-block guard requires log_manager AND config AND scanner all non-None, and scanner is None); returned line matches ^Scan failed: 0 files scanned \| [1-9][0-9]* rules failed compilation \| 0 matches found \| Critical error occurred$. Crash B (ScanConfig raises — see LIFE-080): ZERO new files appear under <scanner_dir>/logs between a listing taken immediately BEFORE and immediately AFTER the delivery — the run_id is never surfaced for this crash so a glob-by-run_id is impossible — and the returned line is exactly 'Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred' (config is None at the handler, so failed_rules is 0).
- **Setup:** Two crafted Round-3 deliveries. A: base64 pack = a single rule with a deliberate syntax error (e.g. `rule Bad { condition: $undefined }`); delete <scanner_dir>/rule_cache first so the compile is fresh. B: alert_severity='bogus'. Deliver via Action Center and keep the printed SCAN_RESULT; pull logs/ back compressed. Re-run A over SSH on xdr-agent with `2> err.txt` to also capture the stderr triple.
- **Evidence:** The snippet footer's stdout line 'SCAN_RESULT: Scan failed: …'; <scanner_dir>/logs/scan_errors_<run_id>.log line 'CRITICAL_ERROR: Critical scanner error: …'; <scanner_dir>/logs/yara_processing_<run_id>.log line 'CRITICAL_ERROR: Critical scanner error: …'; <scanner_dir>/logs/script_exceptions_<run_id>.log lines '=== EXCEPTION #1 ===' / 'Context: main_function_critical_error'; absence of <scanner_dir>/logs/scan_summary_<run_id>.json; for crash B, before/after `ls <scanner_dir>/logs` listings; on the SSH run, stderr lines 'YARA Scanner Critical Error: Critical scanner error: …', 'Error Type: ValueError' and 'SCAN_STATUS: ERROR', and stdout 'Process failed with critical error'.
- **Negative control:** The round's clean completed run: grep -c 'CRITICAL_ERROR:' across every <scanner_dir>/logs/*_<run_id>.log == 0, no logs/script_exceptions_<run_id>.log, and logs/scan_summary_<run_id>.json present with outcome 'completed'.
- **Why this round:** Round 3 owns fatal error handling; only a crafted broken pack reaches the handler at a point where the channel-by-channel guard is actually discriminating.

### `LIFE-043` Rule-decode failure aborts before any scanning

*core*

- **Must be true:** A pack that fails decode or validation aborts before a single file is opened, and the yara_processing log names WHICH of the three checks rejected it (INPUT_ERROR vs DECODE_ERROR vs VALIDATION_ERROR) rather than one undifferentiated failure.
- **Threshold:** Three deliveries produce, respectively, exactly one 'INPUT_ERROR: Empty YARA rules content provided', one 'DECODE_ERROR: Base64 decode failed: ', one "VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations" in logs/yara_processing_<run_id>.log, each followed by exactly one 'CRITICAL: Failed to decode YARA rules: ' line in the same file. For all three: the returned line is exactly 'Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred'; yara_processing_<run_id>.log is the ONLY file under logs/ carrying that run_id (decode runs inside ScanConfig.__init__, before LogManager exists), and no logs/scan_summary_<run_id>.json is written.
- **Setup:** Three Round-3 deliveries on the same endpoint: (a) yarafile='   ' (whitespace-only but truthy, so the empty-YARA_RULE branch is bypassed and decode_yara_rules' own empty check fires); (b) yarafile='A' (one base64-alphabet char — length ≡ 1 mod 4, which binascii rejects after the module's own padding); (c) yarafile=base64('hello world') — decodable text with no 'rule' declaration. Record the logs/ directory listing per run_id. The 50_000_000-char input cap is NOT exercised: no Action Center script_input can carry a 50 MB argument.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log (the three classified codes plus 'CRITICAL: Failed to decode YARA rules: '); `ls <scanner_dir>/logs/*_<run_id>.*` for each run_id; the SCAN_RESULT line returned by each delivery.
- **Negative control:** A valid pack in the same round decodes with none of the three codes present, and produces the full six-category log set plus scan_summary_<run_id>.json.
- **Why this round:** Round 3 explicitly drives rule decoding and validation with malformed packs.

### `LIFE-044` Invalid scan_folder handling — per-entry validation, whole-run abort only if nothing is valid

*core*

- **Must be true:** One bad entry in a comma-separated scan_folder degrades to the remaining valid entries and says so; only an all-invalid list aborts the run — and the abort happens before LogManager exists, so the run leaves no summary at all.
- **Threshold:** Run A (scan_folder='<valid decoy dir>,/definitely/not/here'): yara_processing_<run_id>.log carries exactly one 'Ignoring 1 specified scan folder(s) that are not valid directories on this endpoint: ' line whose trailing value is the Python list repr of the rejected entries (quoted elements — do NOT assert unquoted), and exactly one 'Scan limited to 1 folder(s): ' line; the run completes, and system_<run_id>.log's 'YARA Scanner initialization completed' data blob has scan_targets == [abspath of the valid decoy dir] (one element, not two). Run B (scan_folder='/definitely/not/here,/also/not/here'): the returned line is exactly 'Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred', logs/yara_processing_<run_id>.log is the only file for that run_id, and no logs/scan_summary_<run_id>.json exists.
- **Setup:** Two Round-3 deliveries against a planted decoy tree (e.g. /opt/yara_lab/decoys) with the same pack. Note scan_summary has NO scan_targets field in this edition — read the resolved list from init_data in system_<run_id>.log, not from the summary.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log lines 'Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]' and 'Scan limited to N folder(s): [...]'; the data blob of the 'YARA Scanner initialization completed' record in <scanner_dir>/logs/system_<run_id>.log (key scan_targets); `ls <scanner_dir>/logs/*_<run_id>.*` for run B; both SCAN_RESULT lines.
- **Negative control:** A single fully-valid scan_folder produces zero 'Ignoring ' lines while still producing the 'Scan limited to 1 folder(s): ' line — the degradation notice must not fire on a clean target list.
- **Why this round:** Round 3 drives scan-target resolution and its fallback ladder with targeted and deliberately bad paths.

### `LIFE-045` Rule-compilation failure classification (split / none-found / all-failed / all-skipped / combined)

*core*

- **Must be true:** A ruleset that yields no usable rules is classified by CAUSE, not lumped into one failure: 'no rules extracted', 'all rules failed to compile' and 'all rules need modules this agent lacks' each produce a distinct, differently-worded terminal error, and the all-skipped wording must not accuse the operator of a syntax error.
- **Threshold:** Pack N (text whose only 'rule' token is split across a newline, e.g. 'rule\nMyRule { condition: true }' — passes decode's (?m)^\s*rule\s+\w+ but yields zero per-line rule starts): yara_processing_<run_id>.log contains 'COMPILATION_ERROR: No YARA rules found in provided content' and <scanner_dir>/failed_rules/raw_yara_content.yar exists holding the raw pack. Pack F (one rule, syntax error): exactly one 'FINAL_COMPILATION_ERROR: No valid YARA rules could be compiled out of 1 rules.' and stderr 'CRITICAL: YARA rule compilation failed: ' plus 'Valid rules: 0, Failed rules: 1, Skipped: 0'. Pack S (one rule importing and using an unavailable module, e.g. cuckoo): exactly one 'FINAL_COMPILATION_ERROR: No rules could run on this endpoint: all 1 rule(s) need YARA modules this agent's libyara build does not provide' and stderr 'Valid rules: 0, Failed rules: 0, Skipped: 1'; that message must NOT contain 'could be compiled out of'. All three: no logs/scan_summary_<run_id>.json (YaraScanner.__init__ raised, so scanner is None).
- **Setup:** Three Round-3 deliveries; delete <scanner_dir>/rule_cache before each so _compile_yara_rules actually runs (a cache HIT bypasses every branch here). Run at least pack F over SSH on xdr-agent with `2> err.txt` to capture the two stderr lines. SPLIT_ERROR and COMBINED_COMPILATION_ERROR are not reachable from a text pack — _split_yara_rules is defensive and per-rule namespacing (ns_i_<name>) prevents a duplicate-name collision at the combined compile — so they are asserted only as absences.
- **Evidence:** <scanner_dir>/logs/yara_processing_<run_id>.log lines 'COMPILATION_ERROR: …' / 'FINAL_COMPILATION_ERROR: …'; <scanner_dir>/failed_rules/raw_yara_content.yar; stderr 'CRITICAL: YARA rule compilation failed: …' and 'Valid rules: X, Failed rules: Y, Skipped: Z'; absence of logs/scan_summary_<run_id>.json.
- **Negative control:** A mixed pack (some rules valid, one broken, one module-dependent) must produce ZERO 'FINAL_COMPILATION_ERROR' / 'COMPILATION_ERROR' / 'SPLIT_ERROR' / 'COMBINED_COMPILATION_ERROR' lines and complete normally — the classification fires only when valid_sources is empty.
- **Why this round:** Round 3 drives compile error classification with malformed and module-dependent packs.

### `LIFE-046` Per-rule compile artefacts written to failed_rules/

*supporting*

- **Must be true:** Every rule the compiler rejects and every rule it skips for a missing module is written out individually under <scanner_dir>/failed_rules/, under a filename that names the rule (and, for a skip, the module), and the counts in scan_summary_<run_id>.json agree with the number of files written.
- **Threshold:** For a mixed pack containing V valid, F syntactically-broken and S module-dependent rules with distinct rule names: count of failed_rule_*.yar == F and count of skipped_rule_*_<module>.yar == S under <scanner_dir>/failed_rules/; scan_summary_<run_id>.json failed_rules == F, skipped_rules == S, valid_rules == V; yara_processing_<run_id>.log contains 'Failed rules saved to: <scanner_dir>/failed_rules' exactly once (emitted only when F > 0) and F blocks headed '=== RULE COMPILATION FAILURE #n ===' numbered 1..F. Each failed_rule_<name>.yar begins '// FAILED RULE - Compilation Error'; each skipped_rule_<name>_<module>.yar begins '// SKIPPED RULE - Module'.
- **Setup:** Round-3 delivery of a crafted pack with, e.g., 3 valid rules, 2 broken rules and 2 rules importing+using an unavailable module (cuckoo/magic on this agent's libyara). Wipe <scanner_dir>/failed_rules and <scanner_dir>/rule_cache first: the directory is not per-run partitioned, and a cache HIT skips the per-rule loop entirely so nothing would be written.
- **Evidence:** `ls <scanner_dir>/failed_rules/`; the failed_rules / skipped_rules / valid_rules fields in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/logs/yara_processing_<run_id>.log ('=== RULE COMPILATION FAILURE #n ===', 'Failed rules saved to: …', 'COMPILATION SUMMARY' block).
- **Negative control:** An all-valid pack on the same host leaves <scanner_dir>/failed_rules empty, writes no 'Failed rules saved to:' line, and reports failed_rules == 0 and skipped_rules == 0 — the directory must not accumulate artefacts from a clean compile.
- **Why this round:** Round 3 drives compile-error classification; these are its per-rule artefacts.

### `LIFE-047` Rule-cache hit restores counts from a sidecar (and validates before trusting)

*supporting*

- **Must be true:** A second run of an identical pack on the same agent loads the cached bundle instead of recompiling, and the restored rule counts equal the first run's — a cache HIT must not report a scan that ran 0 rules; a bundle that no longer loads or no longer accepts the per-file externals is discarded and recompiled rather than used.
- **Threshold:** Run 1 (cold, after `rm -rf <scanner_dir>/rule_cache`): scan_summary.compile_source == 'fresh', system_<run_id>.log has 'Rule compile FRESH <secs>' and no 'Rule cache HIT'; afterwards exactly one rules_<key>.yarac plus its rules_<key>.yarac.meta.json exist. Run 2 (same pack, same agent): scan_summary.compile_source == 'cache', compile_seconds strictly less than run 1's, system_<run_id>.log has exactly one 'Rule cache HIT rules_<key>.yarac load=…s (valid=V failed=F skipped=S)' and no 'Rule compile FRESH'; V and F equal run 1's scan_summary.valid_rules and failed_rules exactly, and S equals the sidecar's "skipped" value. Run 3 (cache file truncated to 100 bytes beforehand): 'Rule cache miss/unusable, compiling fresh: ' appears, compile_source == 'fresh', the corrupt .yarac and its .meta.json are gone and a fresh pair replaces them. After repeated runs with distinct packs the cache dir holds at most RULE_CACHE_MAX_FILES=5 files matching rules_*.yarac (each with its own .meta.json sidecar, so up to 10 files in total — do NOT assert 5 files in the directory), and the summed size of the rules_*.yarac files ALONE stays <= RULE_CACHE_MAX_BYTES=268435456.
- **Setup:** Three sequential Round-3 deliveries with the identical pack, which must contain at least one rule that COMPILES plus one broken rule and one module-dependent rule (V/F/S all non-zero) — a pack with no valid rules raises out of _compile_yara_rules before _save_rule_cache and never populates the cache at all. Then a fourth after `truncate -s 100 <scanner_dir>/rule_cache/rules_*.yarac`. Do NOT assert scan_summary.skipped_rules across runs: _restore_cache_meta restores valid/failed onto the error logger but returns skipped without assigning skipped_rules_count, so the HIT run legitimately reports skipped_rules 0 — compare S from the HIT log line against the sidecar instead.
- **Evidence:** compile_source and compile_seconds in <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/logs/system_<run_id>.log lines 'Rule cache HIT …', 'Rule cache miss/unusable, compiling fresh: …', 'Rule compile FRESH …'; `ls -l <scanner_dir>/rule_cache/` and the contents of rules_<key>.yarac.meta.json (keys valid_rules, failed_rules, skipped, yara, format).
- **Negative control:** A pack differing by one byte, or the same pack after RULE_CACHE_FORMAT changes, must miss the cache (compile_source 'fresh') — the key must not collapse distinct packs onto one bundle.
- **Why this round:** Round 3 names the compile cache and its sidecar explicitly; Round 1's 'rule cache on disk' covers only its footprint, while the behaviour under test is the restore/validate path that varied packs probe.

### `LIFE-049` ScanStatusUploader.set_status — a lifecycle state machine that emits nothing

*supporting*

- **Must be true:** The local status trail is an ordered, complete phase sequence ending in a terminal value that matches the run's outcome, and no scan_status record is ever transmitted to the tenant — set_status only writes locally, and upload_scan_status has no caller and is gated off by UPLOAD_NON_MATCH_DATA=False.
- **Threshold:** Completed run: diagnostics_<run_id>.log contains 'Scan status changed to: ' lines forming the ordered subsequence initializing → starting_workers → scanning → finishing → completed, with 'completed' the LAST such line. Cancelled run (cancel.flag mid-walk): the last such line is 'finishing' — no 'cancelled' value exists in this edition, so a trailing 'completed' on a cancelled run is a failure. Fatal-failure run: last line 'failed'. Every run: zero occurrences of '✓ Scan status uploaded successfully' and '⚠ Scan status upload failed' anywhere under logs/, and an XQL query for alerts carrying log_type 'scan_status' for this scan_id returns 0 rows.
- **Setup:** Three Round-3 variants on the crafted host: clean completed, a long scan cancelled mid-walk by writing <scanner_dir>/control/cancel.flag over SSH, and the fatal-failure variant. Read diagnostics_<run_id>.log for each — the trail is root-logger INFO, which setup_logging now file-backs (the catalogue's 'UNOBSERVABLE' note predates that sink).
- **Evidence:** <scanner_dir>/logs/diagnostics_<run_id>.log lines 'Scan status changed to: <value>'; the outcome field in <scanner_dir>/logs/scan_summary_<run_id>.json; absence of the two upload_scan_status log lines; XQL over the tenant's alert side for scan_status records tied to this scan_id.
- **Negative control:** The status trail must not be truncated by the shutdown path: even on the completed run where close_diagnostics_handler() fires in the finally block, 'completed' (set before run() returns) is present — its absence would mean the terminal transition was moved after the sink was closed.
- **Why this round:** The state machine's terminal values only diverge across completed / cancelled / failed, and Round 3 is the only round that produces a mid-walk cancellation and a fatal failure.

### `LIFE-053` Unreachable branches: ScanConfig mode=cancel and _discover_all_targets

*low*

- **Must be true:** mode='cancel' never constructs a ScanConfig — it short-circuits in run() to the flag-drop path and creates no per-run artefacts at all — and default-target discovery always goes through _default_discover_targets, never through the absent _discover_all_targets.
- **Threshold:** Cancel delivery: the returned line matches ^Cancel signal delivered \(<scanner_dir>/control/cancel\.flag\) \| scanner running: (yes|no) \| scan_id=; <scanner_dir>/control/cancel.flag exists with a fresh requested_at_ms; and `ls <scanner_dir>/logs/` gains ZERO new files (no new run_id appears, no yara_processing_, no scan_summary_) between the listing taken immediately before and immediately after the delivery. Default-target scan (scan_folder blank/'default'): yara_processing_<run_id>.log contains exactly one 'Scanning default targets: [' line and diagnostics_<run_id>.log contains 'Using configured scan targets: '.
- **Setup:** Two Round-3 deliveries against the same endpoint: one with mode='cancel' (entry point `cancel`), one full scan with scan_folder left blank. Snapshot `ls <scanner_dir>/logs` immediately before and after the cancel delivery.
- **Evidence:** The SCAN_RESULT line of the cancel delivery; <scanner_dir>/control/cancel.flag; before/after listings of <scanner_dir>/logs; <scanner_dir>/logs/yara_processing_<run_id>.log line 'Scanning default targets: [...]'.
- **Negative control:** A scan delivered with an explicit scan_folder must log 'Scan limited to N folder(s): ' and NOT 'Scanning default targets: ' — the discovery line is not unconditional, so asserting it on every run would fail a correct build.
- **Why this round:** Round 3 drives scan-target resolution and the options/mode surface; the negative assertions here ride the same deliveries.

### `LIFE-055` upload_final_comprehensive_report and the efficiency score

*supporting*

- **Must be true:** Every completed run emits exactly one comprehensive report whose sections are internally consistent with the same run's summary, and whose efficiency score is the documented formula recomputed from the report's own numbers — and cancelled and failed runs emit none.
- **Threshold:** Completed run: exactly 1 'COMPREHENSIVE SCAN REPORT | Efficiency Score: ' line in logs/statistics_<run_id>.log; its data blob's file_processing.total_files_scanned == scan_summary.files_scanned and total_files_skipped == scan_summary.files_skipped; rule_compilation.valid_rules_loaded + failed_rules_skipped == total_rules_processed; data.efficiency_score == max(0, 100 − (skipped/(scanned+skipped))*20 − (failed/(valid+failed))*30) recomputed from those same fields within 0.1, equals the number printed in the message text, and lies in [50.0, 100.0] (the two deductions cap at 20 and 30, so it can never clamp); 0 occurrences of 'Error generating comprehensive final report: ' in scan_errors_<run_id>.log; data.resource_summary present iff YARA_ENABLE_RESOURCE_MONITOR was true. Cancelled run and fatal-failure run: 0 occurrences of 'COMPREHENSIVE SCAN REPORT' (both return before the call).
- **Setup:** Round-3 variants: the clean completed run (with a pack that fails some rules, so the rule-failure deduction is non-zero and the score is not trivially 100), the mid-walk cancelled run, and the fatal-failure run. One extra completed run with YARA_ENABLE_RESOURCE_MONITOR=true set in the snippet prelude for the resource_summary half.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log line 'COMPREHENSIVE SCAN REPORT | Efficiency Score: NN.N/100' with the full report as its `| data={…}` blob (sections scan_metadata / file_processing / detection_results / rule_compilation / system_info / performance_summary / [resource_summary] / efficiency_score); <scanner_dir>/logs/scan_summary_<run_id>.json; <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** The cancelled and failed runs must still produce their scan_summary and their final-results record — the missing report must be the only thing missing, otherwise the absence proves nothing about this code path.
- **Why this round:** Round 3 owns the final report; the score only becomes discriminating when a crafted pack drives a non-zero rule-failure rate.

### `LIFE-056` _log_final_results — terminal statistics record and its failure variant

*supporting*

- **Must be true:** The terminal statistics record carries the label the run's outcome earns — 'SCAN COMPLETED' into the statistics log, 'SCAN FAILED' into the error log with the failure reasons attached — and its totals and breakdowns agree with the scan summary.
- **Threshold:** Completed run: exactly 1 line matching 'SCAN COMPLETED \| Time: .* \| Files: N scanned, M skipped \| Detections: D \| Rate: R files/sec' in logs/statistics_<run_id>.log with N/M/D equal to scan_summary files_scanned/files_skipped/matches, and R == round(N / data.total_time_seconds, 2) within 0.01 taking total_time_seconds from the SAME record's `| data={…}` blob (NOT scan_summary.duration_secs, which run() measures over a wider window); 0 occurrences of 'SCAN FAILED | Time:' anywhere. Failed run: exactly 1 'SCAN FAILED | Time: ' line in logs/scan_errors_<run_id>.log whose data blob has failure_reasons with len >= 1 (scan_summary has NO failure_reasons field in this edition — read it from the log record), and 0 'SCAN COMPLETED | Time:' lines. Both runs: exactly 1 'Worker performance summary: N workers processed files' in performance_<run_id>.log with N <= init_data.max_workers; 'Skip reasons: ' present in statistics_<run_id>.log iff files_skipped > 0; 'Top detection rules: ' present in alerts_<run_id>.log iff matches > 0.
- **Setup:** The Round-3 clean completed run, plus a fatal-failure run produced by fault injection — an unreadable/permission-denied target does NOT do it. Concrete recipe: a snippet prelude that makes the worker's INNER exception handler itself raise, so the exception escapes to the worker's outer handler and calls _mark_scan_failed. e.g. define `class _Evil(Exception):\n    def __str__(self): raise RuntimeError('injected fatal')` and patch YaraScanner.scan_file to raise _Evil(); the inner `except Exception as e: error_str = str(e)` (line 6108) then blows up and line 6119 marks the scan failed. Do not confuse this line with run()'s separate 'SCAN COMPLETED SUCCESSFULLY in …' statistics record — match on the ' | Time: ' segment.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log 'SCAN COMPLETED | Time: …' / <scanner_dir>/logs/scan_errors_<run_id>.log 'SCAN FAILED | Time: …' with data.failure_reasons; <scanner_dir>/logs/alerts_<run_id>.log 'Top detection rules: …'; <scanner_dir>/logs/statistics_<run_id>.log 'Skip reasons: …'; <scanner_dir>/logs/performance_<run_id>.log 'Worker performance summary: N workers processed files'; <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** On the completed run with zero detections, 'Top detection rules: ' must be ABSENT (it is gated on total_detections > 0) — asserting its presence unconditionally would fail a correct clean build.
- **Why this round:** The label switch is only exercised by a run that actually fails, which Round 3 is the round that produces.

### `LIFE-068` Non-root privilege advisories and system-path warning  <sub>linux, darwin</sub>

*low*

- **Must be true:** On POSIX the run states which privilege level it is running at, and when a non-root run is pointed at a system path it says the scan will be short of privilege — and the resulting inaccessible files show up as a bounded 'No read permission' skip reason rather than as scanned files.
- **Threshold:** Non-root SSH run with scan_folder='/etc': system_<run_id>.log contains 'Running as: non-root user on Linux', 'WARNING: Not running as root - some system files may be inaccessible', exactly 1 'ERROR: System path scan requires elevated privileges' and exactly 1 'Either run as root or choose a different scan path'; the final 'Skip reasons: ' record's data.skip_breakdown['No read permission'] > 0 and files_scanned + files_skipped > 0. Root run (Action Center delivery) over the same path: 'Running as: root on Linux' present, and 0 occurrences of the two ERROR/TIP lines and of the 'Not running as root' warning.
- **Setup:** Two Round-3 deliveries on xdr-agent against scan_folder='/etc': one over SSH as the ordinary gcloud SSH user with `YARA_SCANNER_DIR=$HOME/yara_scanner_nonroot` exported (read by _default_scanner_dir, so the non-root process has a writable logs dir and actually produces system_<run_id>.log), and one through Action Center (which runs as root) against the default /opt/yara_scanner. The system-path branch is matched on the REQUESTED scan_folder string prefix, so the target must be given explicitly — a default-scope run cannot reach it.
- **Evidence:** $YARA_SCANNER_DIR/logs/system_<run_id>.log ('Running as: …', 'WARNING: Not running as root …', 'ERROR: System path scan requires elevated privileges', 'Either run as root or choose a different scan path'); $YARA_SCANNER_DIR/logs/statistics_<run_id>.log 'Skip reasons: …' record's data.skip_breakdown; the same two files under /opt/yara_scanner/logs for the root run.
- **Negative control:** The root run over the same /etc must log 'Running as: root on Linux' and produce ZERO occurrences of 'WARNING: Not running as root - some system files may be inaccessible', 'ERROR: System path scan requires elevated privileges' and 'Either run as root or choose a different scan path', with NO 'No read permission' key in the final 'Skip reasons: ' record's skip_breakdown — root reads every file under /etc, so the bar is absent, not 'lower'. The advisory must track actual privilege, not fire on every POSIX run.
- **Why this round:** Departs from Round 1: the discriminating half is the requested-path predicate, which only a targeted system path reaches, and targeted paths are Round 3's shape.

### `LIFE-069` Invalid numeric env var falls back to the documented default with a warning

*core*

- **Must be true:** A malformed or out-of-range numeric knob never crashes the run and never takes effect: the documented default is used, the effective value is visible in the init record, and the operator is warned on stderr about which variable was rejected and why.
- **Threshold:** Run with YARA_MAX_MB='abc', YARA_THREADS='-4', YARA_QUEUE_SIZE='0' and YARA_PROGRESS_LOG_SECS='0' exported: the 'YARA Scanner initialization completed' data blob shows max_file_mb == 64, max_workers == the CONFIG_WORKERS default, scan_queue_size == max_workers*2 (>= 2); stderr contains exactly one "Ignoring invalid YARA_MAX_MB='abc' (expected a number) - using default 64", one "Ignoring out-of-range YARA_THREADS='-4' (minimum 1) - using default …", one "Ignoring out-of-range YARA_QUEUE_SIZE='0' (minimum 2) - using default …" and one "Ignoring out-of-range YARA_PROGRESS_LOG_SECS='0' (minimum 1) - using default 30"; the run completes with files_scanned > 0. YARA_PROGRESS_LOG_SECS='0' is REJECTED by the minimum=1 guard and falls back to the documented default 30 — the trailing max(1, …) is a no-op, not a clamp to 1 — and no artefact carries log_interval, so the stderr warning is the whole evidence for that knob: do not assert an effective value for it.
- **Setup:** Round-3 delivery launched over SSH on xdr-agent with the four variables exported and `2> err.txt`. These four are read at ScanConfig scope, so an Action Center prelude reaches them too — but the warnings are emitted through logging's lastResort handler (setup_logging has not run yet), which writes to stderr only, so the Action Center path can decide the effective-value half and not the warning half.
- **Evidence:** err.txt lines 'Ignoring invalid <VAR>=… (expected a number) - using default …' and 'Ignoring out-of-range <VAR>=… (minimum …) - using default …' for all four variables; the max_file_mb / max_workers / scan_queue_size fields in the 'YARA Scanner initialization completed' data blob in <scanner_dir>/logs/system_<run_id>.log; scan_summary.files_scanned. No artefact reports log_interval.
- **Negative control:** A run with YARA_MAX_MB='128' (valid) must show max_file_mb == 128 in the same record and emit zero 'Ignoring ' lines — the guard must not swallow legitimate values.
- **Why this round:** Round 3 explicitly drives deliberately bad option strings and env values.

### `LIFE-070` ExceptionLogger — lazily created, so a clean run leaves no empty file

*low*

- **Must be true:** script_exceptions_<run_id>.log exists only for runs that actually threw past the point where exception_logger is bound: a clean run leaves no zero-byte file, and a crashing run leaves one containing the banner, the context and the traceback.
- **Threshold:** Clean completed run: 0 files matching logs/script_exceptions_<run_id>.log. Crash-after-binding run (all rules fail to compile): the file exists, is non-empty, its first record is '=== SCRIPT EXCEPTION LOG INITIALIZED ===' and it contains '=== EXCEPTION #1 ===', 'Context: main_function_critical_error', 'Exception Type: ValueError' and a 'Full Traceback:' block; exception count is 1 (no '=== EXCEPTION #2 ==='). Crash-before-binding run (alert_severity='bogus', which raises inside ScanConfig): 0 files matching logs/script_exceptions_*.log for that run_id.
- **Setup:** Three Round-3 deliveries (the clean run, the broken-pack run from LIFE-042 crash A, and the alert_severity='bogus' run). Clear <scanner_dir>/rule_cache before the broken-pack run so the compile actually runs.
- **Evidence:** `ls <scanner_dir>/logs/script_exceptions_*.log` per run_id and the file's contents.
- **Negative control:** The clean run must produce the other eight per-run files while producing no script_exceptions file — absence alone is not evidence unless the run demonstrably logged everything else.
- **Why this round:** Round 3 owns fatal error handling; only a crafted pack reaches the single call site.

### `LIFE-072` Evidence collection on the successful path (and what a metadata-only ZIP contains)

*supporting*

- **Must be true:** The evidence ZIP is written on every completed run that produced matches, and with collect_files at its default false it carries the alert texts and the path→SHA256 map but no copies of matched files; with collect_files true it carries one content-addressed copy per distinct hash, not one per path.
- **Threshold:** Default run (collect_files=false) over a planted match set: evidence/evidence_<hostname>_<run_id>.zip exists; its member list is exactly {file_mapping.txt} ∪ {alerts/<rule>.txt for each rule that fired}, with 0 members under matched_files/; system_<run_id>.log contains exactly 1 'Evidence: collect_files=false - packaging metadata only (no matched file copies)' and 1 'Evidence collection completed successfully'; scan_errors_<run_id>.log has 0 'Error collecting evidence: '. collect_files=true run over the same set, where P planted paths hold D distinct byte-contents (P > D): the ZIP has exactly D members under matched_files/, each named with the file's sha256, file_mapping.txt still lists all P paths, and system_<run_id>.log carries exactly 1 'Evidence ZIP: D unique file(s) packaged, (P-D) duplicate copy(ies) skipped'.
- **Setup:** Two Round-3 deliveries over a planted directory holding, e.g., 6 matching files of which 2 pairs are byte-identical (P=6, D=4); the second with options='collect_files=true'. The dedup line is gated on at least one duplicate being skipped, so the planted set must contain one.
- **Evidence:** <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip member list (`unzip -l`); <scanner_dir>/evidence/file_mapping.txt (header block plus 'Original Path | SHA256 Hash' rows); <scanner_dir>/logs/system_<run_id>.log ('Evidence: collect_files=false …', 'Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped', 'Evidence collection completed successfully'); <scanner_dir>/logs/scan_errors_<run_id>.log.
- **Negative control:** On the collect_files=false run the 'Evidence ZIP: … duplicate copy(ies) skipped' line must be ABSENT (the dedup branch is inside the copy_files arm), and on the collect_files=true run with no duplicates it must also be absent — asserting it unconditionally would fail a correct build.
- **Why this round:** Departs from Round 2: the discriminating cases are the option value and a planted duplicate-content set, both crafted inputs, and Round 3 is the round that plants decoys and drives the options string.

### `LIFE-077` "Scan configuration established" — resolved target list logged under a non-canonical scan_id

*low*

- **Must be true:** The scan-configuration record carries the run's fully resolved target list, but its inline scan_id is a locally-built string that does NOT match the canonical scan_id used everywhere else — so this record can never be joined to a run by scan_id.
- **Threshold:** Exactly 1 'Scan configuration established' record in statistics_<run_id>.log; its data.targets equals, element for element, the resolved target list in init_data.scan_targets in system_<run_id>.log; data.target_count == len(data.targets); data.max_workers and data.yara_rules_count equal init_data.max_workers and scan_summary.valid_rules; and data.scan_id != scan_summary.scan_id — specifically data.scan_id matches ^<hostname>_\d{8}_\d{6}$ and lacks the '_yara_<12hex>' suffix and the microsecond field the canonical id carries.
- **Setup:** Any Round-3 delivery with an explicit multi-entry scan_folder, so the resolved list is non-trivial. The data blob is capped at 4000 chars by LogManager._log, but sort_keys puts scan_id fifth and targets last, so scan_id is always readable — check for a trailing '...(truncated)' before concluding targets is complete.
- **Evidence:** <scanner_dir>/logs/statistics_<run_id>.log record 'Scan configuration established | data={…}' (keys scan_id, targets, target_count, max_workers, max_file_size_mb, yara_rules_count, failed_rules_count); init_data.scan_targets in <scanner_dir>/logs/system_<run_id>.log; scan_id in <scanner_dir>/logs/scan_summary_<run_id>.json.
- **Negative control:** Every other record that names a scan_id (the dataset rows, the summary, running.json) must carry the canonical form — the divergence must be confined to this one inline f-string, not a global identity break.
- **Why this round:** Round 3 drives scan-target resolution; the resolved-list half of this record is only discriminating when explicit targets are supplied.

### `LIFE-079` Boolean environment toggles fail in opposite directions and have no shared parser

*supporting*

- **Must be true:** The two boolean styles behave as documented and in OPPOSITE directions: a garbage value for a permissive toggle (YARA_RULE_CACHE, YARA_ALERT_REQUEUE) leaves the feature ON, while the same garbage for a strict toggle (YARA_ENABLE_*) leaves the feature OFF — no shared parser normalises them.
- **Threshold:** Permissive: with YARA_RULE_CACHE='maybe' exported before python starts, <scanner_dir>/rule_cache/rules_<key>.yarac exists after the run (the cache dir is only ever created from inside a RULE_CACHE_ENABLED branch); with YARA_RULE_CACHE='0' the rule_cache directory is absent/unchanged after a run started from a clean state, and compile_source == 'fresh' on every repeat. Strict: with YARA_ENABLE_PERF_MONITOR='maybe' the init record's performance_monitoring_enabled == false and 'Performance monitoring disabled in light profile' is present; with 'true' it is true. Cross-check both against the 'All monitoring systems activated' record. Do not use 'Rule compile FRESH' alone as the cache signal — a cold cache logs FRESH either way.
- **Setup:** Four short Round-3 deliveries on xdr-agent, all over SSH with the variables exported in the process environment: RULE_CACHE_ENABLED and ALERT_REQUEUE_ENABLED are read at MODULE scope, so a snippet prelude runs too late for them (the YARA_ENABLE_* pair is ScanConfig-scope and is prelude-reachable). Remove <scanner_dir>/rule_cache before each cache run.
- **Evidence:** Presence/absence of <scanner_dir>/rule_cache/rules_*.yarac and its .meta.json; compile_source in <scanner_dir>/logs/scan_summary_<run_id>.json; 'Rule cache HIT …' / 'Rule compile FRESH …' in <scanner_dir>/logs/system_<run_id>.log; performance_monitoring_enabled / resource_monitoring_enabled in the 'YARA Scanner initialization completed' data blob; the 'All monitoring systems activated' record.
- **Negative control:** No artefact reports the raw env string, so the assertion must be on the resulting behaviour: a valid 'true'/'1' run for each toggle is the control proving the toggle is wired at all, not merely defaulting.
- **Why this round:** Round 3 explicitly drives deliberately bad option strings and env values.

### `LIFE-080` Strictly validated operator inputs that abort the run by raising (alert_severity, mode, cpu_guarantee)

*core*

- **Must be true:** A bad value for any of the three strictly-validated inputs stops the run in ScanConfig — before any directory is created or any file is written — and reports which argument and which value were rejected, rather than silently falling back to a default and scanning with the wrong posture.
- **Threshold:** For each of alert_severity='bogus', mode='bogus', options='cpu_guarantee=bogus': the returned line is exactly 'Scan failed: 0 files scanned | 0 rules failed compilation | 0 matches found | Critical error occurred'; NO new file appears anywhere under <scanner_dir>/logs for a new run_id (all three raises precede the logs_dir creation and ErrorLogger construction), and therefore no scan_summary_<run_id>.json; on the SSH variant stderr carries "YARA Scanner Critical Error: Critical scanner error: Invalid <arg> '<value>'. Use …", 'Error Type: ValueError' and 'SCAN_STATUS: ERROR'. The '__main__' CLI exit code is NOT asserted — build_scanner_snippet neutralises that block, so no Action Center delivery can produce it.
- **Setup:** Three Round-3 deliveries plus one SSH repeat for stderr; snapshot `ls <scanner_dir>/logs` immediately before and after each. Note options='cpu_guarantee=bogus' passes the option parser (cpu_guarantee is a valid key) and is rejected by ScanConfig, whereas an unknown KEY raises out of run() entirely and surfaces as the snippet's 'SNIPPET_ERROR:' traceback instead — that is a different path, not this one.
- **Evidence:** The SCAN_RESULT (or SNIPPET_ERROR) line printed by the snippet footer; before/after listings of <scanner_dir>/logs; captured stderr from the SSH run.
- **Negative control:** alert_severity='high', mode='scan' and options='cpu_guarantee=budget' must all run to completion and be reflected in scan_summary (throttle_mode == 'budget', posture string containing 'cpu=budget') — the validator must reject only genuinely invalid values.
- **Why this round:** Round 3 explicitly drives the options string, its validation and precedence.

---

# Not covered

23 capabilities carry no live criterion. Each reason is concrete and names
what would be needed instead.

| ID | Capability | Reason |
|---|---|---|
| `RULE-003` | Rule input size cap (50 MB of base64) | NOT COVERED — the rejection branch requires a yarafile argument longer than 50,000,000 characters, which no XDR delivery path can carry: run_snippet_code_script embeds the base64 rules inside the snippet source and then base64s the whole snippet for the API body (~67 MB request), and a library-script run_script passes yarafile as a JSON parameter value in the same single request body. Both are orders of magnitude below the cap. The cap is a bare literal (`50_000_000` in decode_yara_rules) with no env or options override, so it cannot be lowered from the delivery side either. To decide it: invoke decode_yara_rules off-endpoint with a synthesized 50,000,001-character string, or temporarily edit the literal in a build-time-patched snippet and assert the CRITICAL line. |
| `RULE-021` | Per-block re-validation before compile (_clean_rule_content) | NOT COVERED — the guard cannot fire. _split_yara_rules builds rule_starts only from lines that already match `^\s*rule\s+\w+`, then slices each block STARTING at that line; _clean_rule_content joins those lines and strips, so its `re.match(r'^\s*rule\s+\w+', content)` test is re-applied to a string that begins with the very line that satisfied it. It can never return None. Its logging.warning ("doesn't start with 'rule' keyword") and the failed_extractions counter it feeds are therefore both unreachable on any input, and failed_extractions is only ever logged, never persisted. Its one live effect — joining and stripping the block — is implicit in every accepted rule body and produces no distinguishing artefact. To decide it: a unit test calling _clean_rule_content directly with a hand-built block whose first line is not a rule declaration. |
| `RULE-022` | _is_valid_rule_structure — DEAD CODE | NOT COVERED — dead code. The symbol has exactly one occurrence in the file (its own `def`), so it is never invoked on any input and produces no artefact; its four internal messages are logging.debug, below the root logger's INFO level, so they would not reach diagnostics_<run_id>.log even if it ran. Decidable only statically. |
| `RULE-060` | Cached-hit dict ingestion path — REMOVED | Not decidable on a live run: the code and its only possible producer no longer exist in xdr_yara_scanner.py. `_serialize_matches` survives only as a sentence in the `_iter_hit_fields` docstring, and `_iter_hit_fields` now handles exactly one shape (a live yara.Match). There is no scan input, env var, option or delivery path that can present the removed dict shape, so no scan artefact can distinguish a build that still has the branch from one that does not. What would be needed instead: running `tests/test_hit_field_extraction.py` under pytest in CI — specifically `test_dict_input_is_no_longer_silently_accepted` (a dict must raise) and `test_the_dict_producer_is_gone` (`assert not hasattr(mod, "_serialize_matches")`). An Action Center scan never executes that file. |
| `RULE-061` | _yara_callback — inert match callback | Not decidable on a live run: both arms of `_yara_callback` return `yara.CALLBACK_CONTINUE`, so the `if data.get("matches")` test changes nothing. It writes no log line, increments no counter, sets no flag and appears in no artefact; a build with the callback and a build without it produce byte-identical logs, alert files, dataset rows and scan summaries. Its only measurable effect is one Python call per rule evaluation per file, which is far below the run-to-run variance of scan duration on a shared lab host and so cannot be separated from noise. What would be needed instead: source inspection, or an instrumented build that increments a counter inside the callback and emits it. |
| `TRAV-008` | Dead hook: _discover_all_targets override branch | Not decidable on a live run. `_discover_all_targets` has no `def` anywhere in xdr_yara_scanner.py — it appears only in the `hasattr(self, "_discover_all_targets")` guard in ScanConfig.__init__ and in the call inside that guard's True arm. The guard is therefore permanently False, the branch never executes, and it emits no log line, no counter and no summary field, so no artefact distinguishes a build with the branch from one without it. Deciding it needs a source-level assertion (`grep -c 'def _discover_all_targets'` == 0) or a unit test that injects the attribute onto a ScanConfig instance — neither is reachable through any Action Center input, options key or environment variable. |
| `TRAV-011` | Windows discovery fallbacks (A–Z probe, then C:\)  <sub>windows</sub> | Not decidable on a live run. The A–Z probe rung in _default_discover_targets executes only when psutil.disk_partitions(all=False) AND ctypes.windll.kernel32.GetLogicalDrives BOTH yield nothing (each is wrapped in a bare `except Exception: pass`), and the hardcoded ['C:\\'] rung only when the A–Z probe also finds nothing. No scan_folder value, options key or environment variable can induce either failure on a functioning Windows agent. Worse, neither rung writes a distinguishing log line: all three paths converge on the same 'Light profile full-scope targets on Windows: [...]' message, and on a box where C:\ exists the A–Z probe produces a list identical to the primary path's — so even if a rung did fire, no artefact would show it. Deciding it needs a fault-injected build that monkey-patches psutil.disk_partitions and GetLogicalDrives to raise. |
| `TRAV-014` | macOS default scope depends on effective UID (root = whole filesystem, SIP still applies)  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-015` | macOS non-root fallback to the home directory only  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-016` | Unknown platform yields an empty default target list | Not decidable on a live run. The else-arm of _default_discover_targets is selected purely by platform.system() returning something other than 'Windows', 'Linux' or 'Darwin'. Nothing the scanner accepts — scan_folder, alert_severity, mode, any of the ten _VALID_OPTION_KEYS, or any YARA_* environment variable — influences platform.system(), and the Cortex XDR agent (the only delivery path in scope) ships for exactly those three families, so no endpoint in either tenant can reach it. Deciding it needs an endpoint whose platform.system() is e.g. 'FreeBSD' or 'SunOS' running the scanner outside Action Center. |
| `TRAV-028` | The scanner's own output log path is excluded from scanning | Not decidable on a live run. config.output_log is always <scanner_dir>/logs/scanner_<run_id>.log, and ScanConfig unconditionally appends the scanner_dir itself to the platform skip list on all three platforms (lin_skip_directory and mac_skip_directory each get `os.path.normpath(scanner_dir).rstrip('/') + '/'`, win_skip_folder gets scanner_dir directly). Any walk that reaches <scanner_dir>/logs is therefore rejected at the walk-ROOT grain as 'Skipped directory' before a single file under it is tested, so the identity check can never be the deciding predicate and deleting it would change no artefact in any run. Targeting the file directly is impossible too: run_id is generated per run, and a file path fails ScanConfig's isdir test (TRAV-003). Deciding it needs a build with the scanner_dir entry removed from the platform skip list. |
| `TRAV-031` | Force-scan allowlist for browser caches (overrides all path-based skips)  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-039` | macOS skip list with three distinct match semantics  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-040` | macOS /Volumes/ exclusion removes all mounted external and network volumes  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-041` | macOS AppleDouble resource-fork file skip  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `TRAV-042` | Unknown platform has no directory skip list at all | Not decidable on a live run. The empty-skip-list branch is guarded by `platform.system()` not being Windows, Linux or Darwin; every Cortex XDR endpoint reports one of those three, and no env var, option key or delivery parameter can change what platform.system() returns. The two artefacts the catalogue proposes are also unavailable: the 'Unknown platform - manual target specification required' warning sits in ScanConfig._default_discover_targets' else-branch which the same condition guards, and scan_config_data (the 'Scan configuration established' statistics entry) contains no skip-list-size field — its keys are scan_id, os_info, targets, target_count, max_workers, max_file_size_mb, yara_rules_count, failed_rules_count. Closing it needs the source change the catalogue describes ('platform_skip_paths': len(getattr(self.config,'skip_paths',())) added to scan_config_data), after which a run on any supported platform would prove the non-zero half and only a non-supported platform could prove the zero half. |
| `PERF-024` | DEAD CONSTANT: WORKER_GET_TIMEOUT_SECS | Not decidable on a live run. WORKER_GET_TIMEOUT_SECS is defined once and never read — grep over xdr_yara_scanner.py returns exactly one hit, its definition — while the timeout actually in force is the 5.0 literal in _worker's scan_queue.get(). It has no env var and no options key, so no delivery path can carry a value for it, and changing it would alter no artefact. Deciding it requires static inspection of the source, not a scan: a source-level assertion that the symbol has exactly one reference, or the PERF-023 measurement (worker stop within ~5s, not ~2s) which decides the real timeout rather than this constant. |
| `PERF-025` | DEAD CONSTANT: CANCEL_DRAIN_DEADLINE_SECS | Not decidable on a live run. CANCEL_DRAIN_DEADLINE_SECS / YARA_CANCEL_DEADLINE_SECS is defined and never referenced again — setting the env var to any value changes no timing, no log line and no summary field, so no run can distinguish it being honoured from it being ignored. Deciding it would need either a source-level single-reference assertion, or a build that wires it into the cleanup budget. The real cancel-to-exit timing is a separate, live-decidable property (see PERF-039). |
| `PERF-032` | Per-tick disk I/O guarded for macOS  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `PERF-037` | Vestigial lock_throttle | Not decidable on a live run. threading.Lock lock_throttle is created in YaraScanner.__init__ and acquired in exactly one place — _emit_scan_row's paused snapshot — which runs at most once per lifecycle row (a handful of times per scan) and has no other contender. A lock with a single acquirer can never contend, so its only possible observable (blocking) cannot occur, and removing it would produce byte-identical artefacts. Deciding it needs a source-level assertion that the symbol has exactly two references (creation and the one `with`), not a scan. |
| `STOR-032` | macOS LaunchDaemon /Library/LaunchDaemons/com.yarascanner.cleanup.plist  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `STOR-059` | macOS case-sensitivity probe, answered once per process  <sub>darwin</sub> | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path is Darwin-only, so no live run on this tenant can reach it. To cover it would need a macOS host enrolled in this XDR tenant; the sibling XSIAM tenant's macOS endpoint cannot decide it, because the two editions are separate codebases. |
| `LIFE-051` | CircuitBreaker class — defined, never instantiated | Not decidable on a live run. |

---

*Generated from the capability catalogue plus the criteria inventory. Every count
above is computed, never typed — hand-maintained totals in this project have drifted
twice, once inside a single working session.*
