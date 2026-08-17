# XSIAM Live Test Tracking

Status of every catalogued XSIAM capability against live endpoints. Regenerated
after each round; `TEST_PLAN.md` holds the criteria themselves.

**Status values:** `not_run` · `pass` · `fail` · `blocked` · `not_covered`

## Progress

| Round | Total | pass | fail | blocked | not_run |
|---|---|---|---|---|---|
| 1 | 55 | 0 | 0 | 0 | 55 |
| 2 | 109 | 0 | 0 | 0 | 109 |
| 3 | 127 | 0 | 0 | 0 | 127 |

**0 of 291 executed.**

## All capabilities

| ID | Capability | Rnd | Pri | Status | Evidence | Notes |
|---|---|---|---|---|---|---|
| `RULE-001` | Base64-only rule input | 3 | core | · not_run | — | — |
| `RULE-002` | Rule input size cap | 3 | supporting | · not_run | — | — |
| `RULE-003` | Typed rule-input rejection codes | 3 | supporting | · not_run | — | — |
| `RULE-004` | Empty embedded ruleset guard | 3 | supporting | · not_run | — | — |
| `RULE-005` | Comment- and string-aware pack parser | 3 | supporting | · not_run | — | — |
| `RULE-006` | private / global rule modifier capture | 3 | supporting | · not_run | — | — |
| `RULE-007` | Pack splitting into preamble + individual rules | 3 | supporting | · not_run | — | — |
| `RULE-008` | Duplicate import de-duplication in the preamble | 3 | supporting | · not_run | — | — |
| `RULE-009` | include statements passed through verbatim | 3 | supporting | · not_run | — | — |
| `RULE-010` | Rule block sanity check | 3 | supporting | · not_run | — | — |
| `RULE-011` | Unnamed-rule fallback naming | 3 | low | · not_run | — | — |
| `RULE-012` | Agent module-availability probe | 3 | supporting | · not_run | — | — |
| `RULE-013` | cuckoo-availability callout | 3 | supporting | · not_run | — | — |
| `RULE-014` | Unavailable preamble imports stripped | 3 | supporting | · not_run | — | — |
| `RULE-015` | Pre-compile skip for rules importing missing modules | 3 | supporting | · not_run | — | — |
| `RULE-016` | Post-compile reclassification of inherited-import failures | 3 | supporting | · not_run | — | — |
| `RULE-017` | Automatic import injection from module usage | 3 | supporting | · not_run | — | — |
| `RULE-018` | Per-rule trial compile then namespaced whole-pack compile | 3 | supporting | · not_run | — | — |
| `RULE-019` | Duplicate rule names survive | 3 | supporting | · not_run | — | — |
| `RULE-020` | Duplicate-name caveat in the rule-source map | 3 | supporting | · not_run | — | — |
| `RULE-021` | Compile-time externals declaration | 3 | supporting | · not_run | — | — |
| `RULE-022` | Per-file externals at match time | 3 | supporting | · not_run | — | — |
| `RULE-023` | Non-short-circuiting match callback | 3 | supporting | · not_run | — | — |
| `RULE-024` | Condition-only (no-strings) rule support | 3 | supporting | · not_run | — | — |
| `RULE-025` | Per-rule compilation-failure diagnostics | 3 | supporting | · not_run | — | — |
| `RULE-026` | failed_rules/ artifact directory | 3 | supporting | · not_run | — | — |
| `RULE-027` | failed_rules/ is never pruned | 3 | supporting | · not_run | — | — |
| `RULE-028` | Un-splittable pack forensics | 3 | supporting | · not_run | — | — |
| `RULE-029` | Split-stage failure isolation | 3 | supporting | · not_run | — | — |
| `RULE-030` | Three-way valid / failed / skipped accounting | 3 | supporting | · not_run | — | — |
| `RULE-031` | Compilation summary block | 3 | supporting | · not_run | — | — |
| `RULE-032` | All-skipped vs all-failed fatal distinction | 3 | supporting | · not_run | — | — |
| `RULE-033` | Combined-compile failure reporting | 3 | supporting | · not_run | — | — |
| `RULE-034` | Rule-pack hash and scan_id derivation | 3 | supporting | · not_run | — | — |
| `RULE-035` | Rule/import census at initialization | 3 | supporting | · not_run | — | — |
| `RULE-036` | Brace-balance sanity check | 3 | supporting | · not_run | — | — |
| `RULE-037` | Console-noise caps on rule diagnostics | 3 | supporting | · not_run | — | — |
| `RULE-038` | Rule-count propagation into scan telemetry | 3 | low | · not_run | — | — |
| `RULE-039` | Diagnostic-preserving cleanup suppression | 3 | low | · not_run | — | — |
| `RULE-040` | YARA runtime version banner | 3 | supporting | · not_run | — | — |
| `RULE-041` | Lenient base64 rule-payload decoding (b64: prefix, URL-safe, unpadded) | 3 | supporting | · not_run | — | — |
| `RULE-042` | Condition-only match explanation mined from the rule's own source text | 3 | supporting | · not_run | — | — |
| `RULE-043` | yara-python version shim for match strings (3.x tuples vs 4.x StringMatch instances) | 3 | supporting | · not_run | — | — |
| `RULE-044` | Dead cached-hit dict ingestion path in match-field extraction | not_covered | low | — not_covered | — | — |
| `TRAV-001` | Explicit scan folder parameter | 3 | core | · not_run | — | — |
| `TRAV-002` | Comma-separated multi-target list | 3 | supporting | · not_run | — | — |
| `TRAV-003` | Per-target validation with independent rejection | 3 | supporting | · not_run | — | — |
| `TRAV-004` | Hard failure when no requested target is valid | 3 | core | · not_run | — | — |
| `TRAV-005` | Windows whole-machine default target discovery | 3 | supporting | · not_run | — | — |
| `TRAV-006` | Linux default target discovery (privilege-aware) | 3 | supporting | · not_run | — | — |
| `TRAV-007` | macOS default target discovery (privilege-aware) | 3 | supporting | · not_run | — | — |
| `TRAV-008` | Unknown-platform target fallback | 3 | supporting | · not_run | — | — |
| `TRAV-009` | Excluded-target warning (requested target wholly skipped) | 3 | supporting | · not_run | — | — |
| `TRAV-010` | Non-root system-path pre-flight advisory | 3 | supporting | · not_run | — | — |
| `TRAV-011` | Cancellable explicit-stack directory walk | 1 | supporting | · not_run | — | — |
| `TRAV-012` | Symlinked directories listed but never recursed | 3 | supporting | · not_run | — | — |
| `TRAV-013` | Unreadable directory entry demoted to a file | 3 | supporting | · not_run | — | — |
| `TRAV-014` | Unreadable directory tolerated, subtree abandoned | 3 | supporting | · not_run | — | — |
| `TRAV-015` | Junction / reparse-point detection | 3 | supporting | · not_run | — | — |
| `TRAV-016` | Per-platform problematic-junction skip list | 3 | supporting | · not_run | — | — |
| `TRAV-017` | Directory-level junction pruning during the walk | 3 | supporting | · not_run | — | — |
| `TRAV-018` | File-level junction skip, counted | 3 | supporting | · not_run | — | — |
| `TRAV-019` | Real-path deduplication (present but disabled) | 3 | supporting | · not_run | — | — |
| `TRAV-020` | Skip by file extension (disk-image containers) | 3 | supporting | · not_run | — | — |
| `TRAV-021` | Skip by exact filename | 3 | supporting | · not_run | — | — |
| `TRAV-022` | Skip by bounded path fragment | 3 | core | · not_run | — | — |
| `TRAV-023` | Browser caches deliberately NOT skipped | 3 | supporting | · not_run | — | — |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | 3 | supporting | · not_run | — | — |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | 3 | supporting | · not_run | — | — |
| `TRAV-026` | Windows skip folders with component-boundary matching | 3 | supporting | · not_run | — | — |
| `TRAV-027` | Windows skip-drive mechanism | 3 | supporting | · not_run | — | — |
| `TRAV-028` | Linux skip directories | 3 | supporting | · not_run | — | — |
| `TRAV-029` | macOS skip directories with three matching semantics | 3 | supporting | · not_run | — | — |
| `TRAV-030` | macOS AppleDouble and .DS_Store file skip | 3 | supporting | · not_run | — | — |
| `TRAV-031` | No directory skipping on unrecognised platforms | 3 | supporting | · not_run | — | — |
| `TRAV-032` | Self-skip of the scanner's own directory and log file | 3 | core | · not_run | — | — |
| `TRAV-033` | Vendor security-agent path exclusions | 3 | core | · not_run | — | — |
| `TRAV-034` | Maximum file size cap | 3 | core | · not_run | — | — |
| `TRAV-035` | Non-regular-file rejection | 3 | supporting | · not_run | — | — |
| `TRAV-036` | Existence and read-access pre-checks | 3 | supporting | · not_run | — | — |
| `TRAV-037` | Second-line skip check inside the worker | 3 | supporting | · not_run | — | — |
| `TRAV-038` | Bulk attribution of a skipped directory's files | 2 | supporting | · not_run | — | — |
| `TRAV-039` | Skip accounting and breakdown reporting | 2 | core | · not_run | — | — |
| `TRAV-040` | Bounded per-file error labels in the skip breakdown | 3 | supporting | · not_run | — | — |
| `TRAV-041` | Per-target progress and throughput reporting | 1 | supporting | · not_run | — | — |
| `TRAV-042` | Scan-configuration disclosure event | 3 | supporting | · not_run | — | — |
| `TRAV-043` | No-drop enqueue under backpressure | 1 | core | · not_run | — | — |
| `TRAV-044` | Case-folding policy for path matching | 3 | supporting | · not_run | — | — |
| `TRAV-045` | macOS case-sensitivity probe file written to /tmp for every file that reaches the scan body | not_covered | low | — not_covered | — | — |
| `TRAV-046` | Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink duplicate" | 3 | low | · not_run | — | — |
| `TRAV-047` | Windows default scan scope is every mounted volume, including network and removable drives | 3 | core | · not_run | — | — |
| `PERF-001` | CPU governor policy selection | 1 | core | · not_run | — | — |
| `PERF-002` | Headroom policy target computation | 1 | core | · not_run | — | — |
| `PERF-003` | Budget policy fixed ceiling | 1 | core | · not_run | — | — |
| `PERF-004` | CPU floor and floor_hits counter | 1 | supporting | · not_run | — | — |
| `PERF-005` | Own-CPU normalisation across cores | 1 | supporting | · not_run | — | — |
| `PERF-006` | Proportional sleep-ratio controller (GAIN, RATIO_MAX) | 1 | supporting | · not_run | — | — |
| `PERF-007` | pace() — post-work proportional sleeping with a per-call cap | 1 | supporting | · not_run | — | — |
| `PERF-008` | pace() call site is AFTER the YARA match, not before | 1 | supporting | · not_run | — | — |
| `PERF-009` | Governor sampling cadence (rate limit) | not_covered | low | — not_covered | — | — |
| `PERF-010` | Governor fail-open when CPU cannot be read | 1 | supporting | · not_run | — | — |
| `PERF-011` | psutil CPU-reading priming | 1 | supporting | · not_run | — | — |
| `PERF-012` | Governor telemetry emission policy (change threshold + heartbeat) | 1 | supporting | · not_run | — | — |
| `PERF-013` | Governor sampling during producer backpressure | 1 | supporting | · not_run | — | — |
| `PERF-014` | Worker thread pool, default 2 and operator-raisable | 1 | supporting | · not_run | — | — |
| `PERF-015` | Worker startup timing event | 1 | supporting | · not_run | — | — |
| `PERF-016` | Bounded scan queue | 1 | supporting | · not_run | — | — |
| `PERF-017` | Producer backpressure on a full queue (never drops files) | 1 | supporting | · not_run | — | — |
| `PERF-018` | Worker get timeout / graceful exit checks | 1 | supporting | · not_run | — | — |
| `PERF-019` | Sentinel-based worker shutdown with bounded joins | 1 | supporting | · not_run | — | — |
| `PERF-020` | Per-worker throughput reporting every 100 files | 1 | supporting | · not_run | — | — |
| `PERF-021` | Per-worker processing-time ring buffer | 1 | supporting | · not_run | — | — |
| `PERF-022` | Process priority lowering (CPU and I/O) | 1 | supporting | · not_run | — | — |
| `PERF-023` | Optional performance monitor (StatisticsManager background thread) | 1 | supporting | · not_run | — | — |
| `PERF-024` | Optional system resource monitor (SystemResourceMonitor) | 1 | supporting | · not_run | — | — |
| `PERF-025` | Optional file-descriptor monitor | 1 | supporting | · not_run | — | — |
| `PERF-026` | Progress heartbeat thread | 1 | supporting | · not_run | — | — |
| `PERF-027` | Progress heartbeat interval and its clamp | 1 | supporting | · not_run | — | — |
| `PERF-028` | Progress heartbeat lifetime spans the worker drain | 1 | supporting | · not_run | — | — |
| `PERF-029` | Progress snapshot contents (capacity/backpressure telemetry) | 1 | supporting | · not_run | — | — |
| `PERF-030` | Long-lived primed handle for progress metrics | 1 | supporting | · not_run | — | — |
| `PERF-031` | Liveness-marker refresh from the heartbeat thread | 1 | supporting | · not_run | — | — |
| `PERF-032` | ETA and rate estimation | 1 | supporting | · not_run | — | — |
| `PERF-033` | Scan-rate reporting in the terminal artefacts | 1 | supporting | · not_run | — | — |
| `PERF-034` | No per-offset retention in memory (uploader) | 1 | supporting | · not_run | — | — |
| `PERF-035` | Per-finding network payload cap | 1 | supporting | · not_run | — | — |
| `PERF-036` | On-disk alert offset sampling (host disk footprint) | 1 | supporting | · not_run | — | — |
| `PERF-037` | Matched-file copying off by default (disk write amplification) | 1 | supporting | · not_run | — | — |
| `PERF-038` | Chunked hashing, matched files only | 1 | supporting | · not_run | — | — |
| `PERF-039` | Maximum scanned file size | 1 | supporting | · not_run | — | — |
| `PERF-040` | Bounded in-memory metric histories | 1 | supporting | · not_run | — | — |
| `PERF-041` | Opportunistic upload batching (network cost control) | 1 | supporting | · not_run | — | — |
| `PERF-042` | Backlog-proportional shutdown drain budget | 1 | supporting | · not_run | — | — |
| `PERF-043` | Per-run log/summary retention on the endpoint | 1 | supporting | · not_run | — | — |
| `PERF-044` | Uploader/log threads are all daemon threads with bounded joins | 1 | supporting | · not_run | — | — |
| `PERF-045` | File-descriptor leak sampling (skipped on every matched file, and on every skipped file) | not_covered | low | — not_covered | — | — |
| `PERF-046` | macOS disk-I/O telemetry is structurally zero | 1 | supporting | · not_run | — | — |
| `PERF-047` | monitoring_duration_minutes reports host uptime, not scan duration | 1 | supporting | · not_run | — | — |
| `PERF-048` | Light-profile priority tuning: outer failure emits a message with no data payload | 1 | supporting | · not_run | — | — |
| `STOR-001` | Scanner working directory (platform default + override) | 3 | supporting | · not_run | — | — |
| `STOR-002` | Four fixed subdirectories: logs/, alert/, evidence/, failed_rules/ | 2 | supporting | · not_run | — | — |
| `STOR-003` | control/ subdirectory for cooperative-cancel state | 3 | supporting | · not_run | — | — |
| `STOR-004` | Six per-category run logs in logs/ | 2 | supporting | · not_run | — | — |
| `STOR-005` | YARA-processing audit log (rule compilation trail) | 2 | supporting | · not_run | — | — |
| `STOR-006` | Lazy script-exception log (no zero-byte file on clean runs) | 2 | supporting | · not_run | — | — |
| `STOR-007` | Per-run log files, truncating, no rotation and no size cap | 2 | supporting | · not_run | — | — |
| `STOR-008` | Reserved scanner_<run_id>.log path, self-excluded from scanning | 2 | supporting | · not_run | — | — |
| `STOR-009` | Per-rule alert text file (alert/<rule>.txt) | 2 | supporting | · not_run | — | — |
| `STOR-010` | Uncapped per-string-ID census in the alert text | 2 | supporting | · not_run | — | — |
| `STOR-011` | Offset cap in the alert text (MAX_ALERT_OFFSETS_PER_FINDING) | 2 | supporting | · not_run | — | — |
| `STOR-012` | Condition-only match detail in the alert text | 2 | supporting | · not_run | — | — |
| `STOR-013` | Matched-bytes rendering (UTF-16 LE / UTF-8 / hex fallback) | 2 | supporting | · not_run | — | — |
| `STOR-014` | evidence/file_mapping.txt (path -> SHA256 manifest) | 2 | supporting | · not_run | — | — |
| `STOR-015` | Evidence ZIP (evidence_<hostname>_<run_id>.zip) | 2 | supporting | · not_run | — | — |
| `STOR-016` | Matched-file copy toggle (COLLECT_MATCHED_FILES) | 2 | supporting | · not_run | — | — |
| `STOR-017` | Content-addressed dedupe of packaged matched files | 2 | supporting | · not_run | — | — |
| `STOR-018` | scan_summary_<run_id>.json — machine-readable per-run summary | 2 | supporting | · not_run | — | — |
| `STOR-019` | Atomic summary write with temp cleanup | 2 | supporting | · not_run | — | — |
| `STOR-020` | Log/summary retention across runs (keep last 2 scans) | 2 | supporting | · not_run | — | — |
| `STOR-021` | Initial cleanup at scan start (alert/ and evidence/ wiped) | 2 | supporting | · not_run | — | — |
| `STOR-022` | failed_rules/ artefacts are never retention-managed | 2 | supporting | · not_run | — | — |
| `STOR-023` | Cleanup script generated on disk (.bat / .sh) | 2 | supporting | · not_run | — | — |
| `STOR-024` | .txt -> .alert rotation performed by the scheduled cleanup | 2 | supporting | · not_run | — | — |
| `STOR-025` | Windows scheduled cleanup task (CleanupScript) | 2 | supporting | · not_run | — | — |
| `STOR-026` | Linux systemd cleanup unit (yara-cleanup.service) | 2 | supporting | · not_run | — | — |
| `STOR-027` | macOS has no working scheduled-cleanup path | 2 | supporting | · not_run | — | — |
| `STOR-028` | Cleanup scheduling is suppressed on critical errors or zero alerts | 2 | supporting | · not_run | — | — |
| `STOR-029` | control/cancel.flag — cooperative cancel signal file | 2 | supporting | · not_run | — | — |
| `STOR-030` | Stale cancel-flag detection and removal | 2 | supporting | · not_run | — | — |
| `STOR-031` | control/running.json liveness marker (atomic, refreshed) | 2 | supporting | · not_run | — | — |
| `STOR-032` | Control-file teardown at end of scan | 2 | supporting | · not_run | — | — |
| `STOR-033` | Scanner never quarantines, moves or deletes scanned files | 2 | supporting | · not_run | — | — |
| `STOR-034` | Scanner working directory is excluded from its own scan | 2 | supporting | · not_run | — | — |
| `STOR-035` | End-of-run "COMPREHENSIVE STATISTICS SUMMARY" block in statistics_<run_id>.log | 2 | supporting | · not_run | — | — |
| `DELI-001` | HTTP Collector NDJSON transport | 2 | core | · not_run | — | — |
| `DELI-002` | NDJSON-only multi-event encoding (JSON array is unsafe) | 2 | core | · not_run | — | — |
| `DELI-003` | Opportunistic (non-timer) batching with event and byte caps | 2 | supporting | · not_run | — | — |
| `DELI-004` | Approximate byte accounting for batch sizing | 2 | supporting | · not_run | — | — |
| `DELI-005` | Bounded retry with jittered exponential backoff | 2 | supporting | · not_run | — | — |
| `DELI-006` | Circuit breaker on the telemetry channel | not_covered | low | — not_covered | — | — |
| `DELI-007` | Match finding grain: one upload item per (rule, file) | 2 | supporting | · not_run | — | — |
| `DELI-008` | match_count vs sampled offsets/strings and the truncated flag | 2 | supporting | · not_run | — | — |
| `DELI-009` | Uncapped per-string-ID census in the finding (match_ids) | 2 | supporting | · not_run | — | — |
| `DELI-010` | yara_match event payload shape (incl. dashboard-flattened aliases) | 2 | supporting | · not_run | — | — |
| `DELI-011` | Condition-only match representation | 2 | supporting | · not_run | — | — |
| `DELI-012` | One merged alert event per matched file | 2 | supporting | · not_run | — | — |
| `DELI-013` | Six categorized event types from the log channel | 2 | supporting | · not_run | — | — |
| `DELI-014` | StandardLogEntry envelope on every event | 2 | supporting | · not_run | — | — |
| `DELI-015` | Per-run scan_id correlation key | 2 | supporting | · not_run | — | — |
| `DELI-016` | Critical-path synchronous send with async fallback | 2 | supporting | · not_run | — | — |
| `DELI-017` | scan_status lifecycle events | 2 | supporting | · not_run | — | — |
| `DELI-018` | scanner_initialization event | 2 | supporting | · not_run | — | — |
| `DELI-019` | statistics_summary checkpoints with per-type rate limiting | 2 | supporting | · not_run | — | — |
| `DELI-020` | scan_completion_summary event with honest outcome | 2 | supporting | · not_run | — | — |
| `DELI-021` | comprehensive_final_report event and efficiency score | 2 | supporting | · not_run | — | — |
| `DELI-022` | Scan-progress telemetry on a whole-scan heartbeat | 2 | supporting | · not_run | — | — |
| `DELI-023` | Time-estimate telemetry | 2 | supporting | · not_run | — | — |
| `DELI-024` | Worker performance telemetry | 2 | supporting | · not_run | — | — |
| `DELI-025` | CPU governor telemetry | 2 | supporting | · not_run | — | — |
| `DELI-026` | system_resource_snapshot and resource_monitoring_summary events | 2 | supporting | · not_run | — | — |
| `DELI-027` | Resource threshold alerts as error events | 2 | supporting | · not_run | — | — |
| `DELI-028` | privilege_status event | 2 | supporting | · not_run | — | — |
| `DELI-029` | resource_limit_warning event | 2 | supporting | · not_run | — | — |
| `DELI-030` | Match-channel delivery accounting (successful / failed / undelivered) | 2 | supporting | · not_run | — | — |
| `DELI-031` | Telemetry-channel delivery accounting (per type + undelivered) | 2 | supporting | · not_run | — | — |
| `DELI-032` | Log-channel delivery accounting | 2 | supporting | · not_run | — | — |
| `DELI-033` | Backlog-proportional shutdown drain window | 2 | supporting | · not_run | — | — |
| `DELI-034` | Shutdown ordering that protects end-of-run events | 2 | supporting | · not_run | — | — |
| `DELI-035` | Delivery shortfall surfaced on the operator's result line | 2 | supporting | · not_run | — | — |
| `DELI-036` | Result line honesty: cancelled verb, skipped rules, excluded targets | 2 | supporting | · not_run | — | — |
| `DELI-037` | scan_summary_<run_id>.json with both delivery books | 2 | supporting | · not_run | — | — |
| `DELI-038` | Credential placeholder detection and early abort | 2 | supporting | · not_run | — | — |
| `DELI-039` | Result printing and exit-code contract | 2 | supporting | · not_run | — | — |
| `DELI-040` | Cancel entry point and its delivery guarantee | 2 | supporting | · not_run | — | — |
| `DELI-041` | Throttled upload logging | 2 | supporting | · not_run | — | — |
| `DELI-042` | Bounded skip-reason labels in shipped aggregates | 2 | supporting | · not_run | — | — |
| `DELI-043` | Matched-data rendering for the wire | 2 | supporting | · not_run | — | — |
| `DELI-044` | Local alert file as the uncapped offset record | 2 | supporting | · not_run | — | — |
| `DELI-045` | No in-memory retention of per-offset detail | 2 | supporting | · not_run | — | — |
| `DELI-046` | Six per-category log files as the local delivery record | 2 | supporting | · not_run | — | — |
| `DELI-047` | Upload channels can be disabled independently | not_covered | low | — not_covered | — | — |
| `DELI-048` | Queue-full handling on the findings channel | 2 | supporting | · not_run | — | — |
| `DELI-049` | Host identity (hostname / os_info / ipAddress) stamped on every uploaded event | 2 | supporting | · not_run | — | — |
| `DELI-050` | Second, non-canonical scan_id inside the "Scan configuration established" payload | 2 | supporting | · not_run | — | — |
| `DELI-051` | Uncapped per-rule detection breakdown in comprehensive_final_report | 2 | supporting | · not_run | — | — |
| `DELI-052` | efficiency_score formula (what the 0-100 number in the final report actually means) | 2 | supporting | · not_run | — | — |
| `DELI-053` | Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the collector sees | 2 | supporting | · not_run | — | — |
| `DELI-054` | LogManager's telemetry books over-count: total_logs increments before the upload gate | 2 | supporting | · not_run | — | — |
| `DELI-055` | Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-bounce) | 2 | supporting | · not_run | — | — |
| `DELI-056` | file_creation_time is null on most Linux filesystems (platform-asymmetric derivation) | 2 | supporting | · not_run | — | — |
| `DELI-057` | Per-finding "Queued finding for upload" receipt in the uploads log (only local view of the truncated flag) | 2 | supporting | · not_run | — | — |
| `DELI-058` | performance_summary / performance_metrics blocks in the two terminal events | 2 | supporting | · not_run | — | — |
| `LIFE-001` | Scan entry point main(yarafile, scan_folder, alert_severity) | 3 | core | · not_run | — | — |
| `LIFE-002` | Cancel entry point cancel() — zero inputs | 3 | core | · not_run | — | — |
| `LIFE-003` | CLI dispatch and exit-code contract | 3 | supporting | · not_run | — | — |
| `LIFE-004` | Cancel flag file (control/cancel.flag) | 3 | core | · not_run | — | — |
| `LIFE-005` | Running marker (control/running.json) and liveness reporting | 1 | supporting | · not_run | — | — |
| `LIFE-006` | Running-marker refresh from two independent sites | 1 | supporting | · not_run | — | — |
| `LIFE-007` | Stale cancel-flag protection anchored at module import | 3 | supporting | · not_run | — | — |
| `LIFE-008` | Cancellation watcher thread and poll cadence | 3 | supporting | · not_run | — | — |
| `LIFE-009` | _request_cancel — idempotent, first-source-wins, thread-safe | 3 | supporting | · not_run | — | — |
| `LIFE-010` | Bounded cancellation latency in directory traversal (_walk_cancellable) | 3 | core | · not_run | — | — |
| `LIFE-011` | Worker-side cancellation and drain | 3 | core | · not_run | — | — |
| `LIFE-012` | Worker join with bounded timeout | 3 | supporting | · not_run | — | — |
| `LIFE-013` | Cancel-flag consumption and marker removal at shutdown | 3 | supporting | · not_run | — | — |
| `LIFE-014` | Backlog-proportional shutdown drain | 3 | supporting | · not_run | — | — |
| `LIFE-015` | Honest undelivered accounting after the drain window | 2 | core | · not_run | — | — |
| `LIFE-016` | Idempotent uploader stop | 2 | supporting | · not_run | — | — |
| `LIFE-017` | scan_status lifecycle values and the terminal status | 2 | supporting | · not_run | — | — |
| `LIFE-018` | scan_status event payload | 2 | supporting | · not_run | — | — |
| `LIFE-019` | Outcome classification (completed / cancelled / failed) | 3 | core | · not_run | — | — |
| `LIFE-020` | Outcome agreement in end-of-scan telemetry | 3 | supporting | · not_run | — | — |
| `LIFE-021` | scan_completion_summary metrics block | 2 | supporting | · not_run | — | — |
| `LIFE-022` | Fatal worker failure path | 3 | supporting | · not_run | — | — |
| `LIFE-023` | Evidence and terminal telemetry survive a fatal failure | 3 | supporting | · not_run | — | — |
| `LIFE-024` | Critical-error path in main() | 3 | supporting | · not_run | — | — |
| `LIFE-025` | KeyboardInterrupt handling | 3 | supporting | · not_run | — | — |
| `LIFE-026` | Guaranteed finalisation order in main()'s finally block | 3 | supporting | · not_run | — | — |
| `LIFE-027` | scan_summary_<run_id>.json artefact | 2 | core | · not_run | — | — |
| `LIFE-028` | scan_summary field contract | 2 | core | · not_run | — | — |
| `LIFE-029` | Duration derivation for the summary | 2 | supporting | · not_run | — | — |
| `LIFE-030` | Operator result line composition | 2 | supporting | · not_run | — | — |
| `LIFE-031` | Cancelled runs never report 'Scan completed' | 3 | core | · not_run | — | — |
| `LIFE-032` | Match-channel delivery shortfall on the result line | 2 | core | · not_run | — | — |
| `LIFE-033` | Telemetry upload-error surfacing | 2 | supporting | · not_run | — | — |
| `LIFE-034` | Excluded-target detection | 3 | supporting | · not_run | — | — |
| `LIFE-035` | Per-file outcome classification and skip reasons | 3 | supporting | · not_run | — | — |
| `LIFE-036` | Bounded skip reason for per-file scan errors | 3 | supporting | · not_run | — | — |
| `LIFE-037` | Per-file error tolerance in the worker loop | 3 | supporting | · not_run | — | — |
| `LIFE-038` | Permission-denied diagnostics | 3 | supporting | · not_run | — | — |
| `LIFE-039` | Env-var guard: numeric tuning knobs fail safe | 3 | supporting | · not_run | — | — |
| `LIFE-040` | Env-var guard: boolean toggles fail safe | 3 | supporting | · not_run | — | — |
| `LIFE-041` | Post-parse clamping of lifecycle knobs | 3 | supporting | · not_run | — | — |
| `LIFE-042` | alert_severity input validation | 3 | supporting | · not_run | — | — |
| `LIFE-043` | scan_folder validation and multi-target contract | 3 | supporting | · not_run | — | — |
| `LIFE-044` | Placeholder-collector-credential abort | 3 | core | · not_run | — | — |
| `LIFE-045` | Rule-compilation fatal errors terminate the run before scanning | 3 | core | · not_run | — | — |
| `LIFE-046` | Module-skipped rules counted separately from failures | 3 | core | · not_run | — | — |
| `LIFE-047` | Privilege detection and privilege_status telemetry | 3 | supporting | · not_run | — | — |
| `LIFE-048` | File-descriptor limit preflight and FD monitoring | 1 | supporting | · not_run | — | — |
| `LIFE-049` | Light-profile process priority tuning at startup | 1 | supporting | · not_run | — | — |
| `LIFE-050` | Progress heartbeat spanning the whole scan | 1 | core | · not_run | — | — |
| `LIFE-051` | Producer backpressure instead of dropping files | 1 | core | · not_run | — | — |
| `LIFE-052` | Final results log with failure-aware label | 2 | supporting | · not_run | — | — |
| `LIFE-053` | scan_system finally-block guarantee | 3 | supporting | · not_run | — | — |
| `LIFE-054` | Comprehensive final report event | 2 | supporting | · not_run | — | — |
| `LIFE-055` | Cleanup scheduling gated on rule-processing health | 3 | supporting | · not_run | — | — |
| `LIFE-056` | Per-run identity: run_id, scan_id, rule_hash | 2 | supporting | · not_run | — | — |
| `LIFE-057` | Six per-run category logs plus two lazy diagnostic logs | 2 | supporting | · not_run | — | — |
| `LIFE-058` | Logging summary at shutdown | 2 | supporting | · not_run | — | — |
| `LIFE-059` | Artefact retention across runs (bounded observability window) | 2 | supporting | · not_run | — | — |
| `LIFE-060` | Root-logger quieting during a scan | 2 | supporting | · not_run | — | — |
| `LIFE-061` | Scanner working-directory selection (shared by both entry points) | 3 | supporting | · not_run | — | — |
| `LIFE-062` | `cancel` as the first CLI argument (cancel keyword dispatch) | 3 | supporting | · not_run | — | — |
| `LIFE-063` | Critical-error handler prints the Python traceback to STDOUT before the result line | 3 | supporting | · not_run | — | — |
| `LIFE-064` | Placeholder-credential abort still wipes alert/, evidence/ and old run logs first — and writes no scan summary | 3 | supporting | · not_run | — | — |
| `LIFE-065` | One failing scan target is abandoned mid-walk; the rest of the scan continues and still reports success | 3 | supporting | · not_run | — | — |
