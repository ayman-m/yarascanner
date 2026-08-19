# XDR Live Test Tracking

Status of every catalogued XDR capability against live endpoints. Regenerated after
each round; `TEST_PLAN.md` holds the criteria themselves.

**Status values:** `not_run` · `pass` · `fail` · `blocked` · `not_covered`

## Progress

| Round | Total | pass | fail | blocked | not_run |
|---|---|---|---|---|---|
| 1 | 134 | 0 | 0 | 0 | 134 |
| 2 | 106 | 0 | 0 | 0 | 106 |
| 3 | 204 | 0 | 0 | 0 | 204 |

**0 of 444 executed.**

## All capabilities

| ID | Capability | Rnd | Pri | Status | Evidence | Notes |
|---|---|---|---|---|---|---|
| `RULE-001` | Base64 YARA rule input decoding (yarafile parameter) | 3 | core | not_run | — | — |
| `RULE-002` | Base64 tolerance: b64: prefix, URL-safe alphabet, whitespace, auto-padding | 3 | core | not_run | — | — |
| `RULE-003` | Rule input size cap (50 MB of base64) | not_covered | low | — not_covered | — | NOT COVERED — the rejection branch requires a yarafile argument longer than 50,000,000 characters, which no XDR delivery path can carry: run_snippet_code_script |
| `RULE-004` | Empty / whitespace-only rule input rejection | 3 | supporting | not_run | — | — |
| `RULE-005` | Decoded-content validation: must contain a 'rule' declaration | 3 | supporting | not_run | — | — |
| `RULE-006` | Rule text encoding fallback (UTF-8 then Latin-1 then replace) | 3 | supporting | not_run | — | — |
| `RULE-007` | Embedded YARA_RULE fallback (empty by default = hard abort) | 3 | core | not_run | — | — |
| `RULE-008` | rule_hash — SHA-256 of the decoded rule text | 3 | core | not_run | — | — |
| `RULE-009` | yara_processing_<run_id>.log — the rule-handling audit trail | 3 | supporting | not_run | — | — |
| `RULE-010` | ErrorLogger.close() — Windows file-handle release before cleanup | 1 | supporting | blocked | no Windows run exists: every leg A-I ran on xdr-agent (Linux 6.8.0-1063-gcp [x86_64]). The Linux analogue is c | — |
| `RULE-011` | YARA module availability probe (per-agent libyara capability detection) | 3 | core | not_run | — | — |
| `RULE-012` | Probe candidate set extended from the submitted rules' own imports | 3 | supporting | not_run | — | — |
| `RULE-013` | Duplicate module probe on a fresh compile (wasted work) | 3 | low | not_run | — | — |
| `RULE-014` | Cuckoo-module absence warning | 3 | low | not_run | — | — |
| `RULE-015` | Preamble extraction and de-duplication (import/include hoisting) | 3 | supporting | not_run | — | — |
| `RULE-016` | Unavailable preamble imports are stripped from the shared preamble | 3 | core | not_run | — | — |
| `RULE-017` | `include` directives hoisted verbatim and never filtered | 3 | supporting | not_run | — | — |
| `RULE-018` | Rule boundary splitting into individually-compiled units | 3 | core | not_run | — | — |
| `RULE-019` | `private rule` / `global rule` are not recognised as rule starts | 3 | core | not_run | — | — |
| `RULE-020` | Everything before the first rule declaration is discarded (except imports) | 3 | supporting | not_run | — | — |
| `RULE-021` | Per-block re-validation before compile (_clean_rule_content) | not_covered | low | — not_covered | — | NOT COVERED — the guard cannot fire. _split_yara_rules builds rule_starts only from lines that already match `^\s*rule\s+\w+`, then slices each block STARTING a |
| `RULE-022` | _is_valid_rule_structure — DEAD CODE | not_covered | low | — not_covered | — | NOT COVERED — dead code. The symbol has exactly one occurrence in the file (its own `def`), so it is never invoked on any input and produces no artefact; its fo |
| `RULE-023` | Per-rule namespace assignment (ns_<index>_<rulename>) | 3 | core | not_run | — | — |
| `RULE-024` | Every rule is compiled twice on a fresh compile | 3 | supporting | not_run | — | — |
| `RULE-025` | Compile-time external variables (filepath, filename) | 3 | core | not_run | — | — |
| `RULE-026` | Per-file external population at match time | 3 | core | not_run | — | — |
| `RULE-027` | Automatic injection of missing module imports per rule (MODULE_USAGE_PATTERNS) | 3 | supporting | not_run | — | — |
| `RULE-028` | Skip classification case 1 — explicit inline import of an unavailable module | 3 | core | not_run | — | — |
| `RULE-029` | Skip classification case 2 — REMOVED usage-regex heuristic (documented dead path) | 3 | core | not_run | — | — |
| `RULE-030` | Post-hoc module-missing reclassification from the compile error | 3 | core | not_run | — | — |
| `RULE-031` | Skipped-rule source dumps | 3 | supporting | not_run | — | — |
| `RULE-032` | Failed-rule source dumps (with resolved preamble) | 3 | supporting | not_run | — | — |
| `RULE-033` | raw_yara_content.yar dump when the split yields zero rules | 3 | supporting | not_run | — | — |
| `RULE-034` | Compilation-error forensics (_analyze_compilation_error) | 3 | supporting | not_run | — | — |
| `RULE-035` | Full failed-rule body echoed into the processing log with an error-line marker | 3 | low | not_run | — | — |
| `RULE-036` | Compilation summary block with success rate | 3 | supporting | not_run | — | — |
| `RULE-037` | First-10 throttle on skipped-rule warnings | 3 | low | not_run | — | — |
| `RULE-038` | First-10 throttle on failed-rule console warnings | 3 | low | not_run | — | — |
| `RULE-039` | Every-50-rules compile progress | 3 | low | not_run | — | — |
| `RULE-040` | Rule-health triage counters (valid / failed / skipped) | 3 | core | not_run | — | — |
| `RULE-041` | skipped_rules is absent from the scans dataset schema | 3 | supporting | not_run | — | — |
| `RULE-042` | All-skipped vs all-failed abort messages are distinguished | 3 | core | not_run | — | — |
| `RULE-043` | Combined-ruleset compile failure path | 3 | supporting | not_run | — | — |
| `RULE-044` | Rule-compilation disk cache | 3 | core | not_run | — | — |
| `RULE-045` | Rule cache key composition | 3 | supporting | not_run | — | — |
| `RULE-046` | yara engine identity tag in the cache key (_yara_version_tag) | 3 | supporting | not_run | — | — |
| `RULE-047` | Cache-hit usability validation (load + externals probe) | 3 | supporting | not_run | — | — |
| `RULE-048` | Corrupt/unusable cache entries are deleted on the failing load | 3 | supporting | not_run | — | — |
| `RULE-049` | Cache LRU touch on hit (os.utime) | 3 | low | not_run | — | — |
| `RULE-050` | Counts sidecar (.meta.json) restored on a cache hit — and the skipped count lost there | 3 | core | not_run | — | — |
| `RULE-051` | Sidecar-missing fallback: recount from the loaded bundle | 3 | supporting | not_run | — | — |
| `RULE-052` | Atomic cache save under a process-wide lock | 3 | supporting | not_run | — | — |
| `RULE-053` | Cache pruning by file count and total bytes (LRU) | 1 | supporting | blocked | cache sits at 5/5 entries, 5 sidecars, 0 orphans, 448,472/268,435,456 bytes — consistent with the cap but not  | — |
| `RULE-054` | Orphaned cache temp sweep with a 1-hour age gate | 1 | low | blocked | no save-temp was ever planted, so the gate was exercised in neither direction: the sweep ran on leg A's save ( | — |
| `RULE-055` | compile_source / compile_seconds telemetry | 3 | supporting | not_run | — | — |
| `RULE-056` | rule_cache survives end-of-run host cleanup | 1 | core | pass | 5 compiled ruleset(s) survived host cleanup in rule_cache/ | — |
| `RULE-057` | failed_rules directory accumulates across runs | 3 | supporting | not_run | — | — |
| `RULE-058` | Rule counts logged to the system log at initialisation | 3 | low | not_run | — | — |
| `RULE-059` | Per-rule metadata (meta and tags) parsed then discarded | 3 | supporting | not_run | — | — |
| `RULE-060` | Cached-hit dict ingestion path — REMOVED | not_covered | low | — not_covered | — | Not decidable on a live run: the code and its only possible producer no longer exist in xdr_yara_scanner.py. `_serialize_matches` survives only as a sentence in |
| `RULE-061` | _yara_callback — inert match callback | not_covered | low | — not_covered | — | Not decidable on a live run: both arms of `_yara_callback` return `yara.CALLBACK_CONTINUE`, so the `if data.get("matches")` test changes nothing. It writes no l |
| `RULE-062` | _debug_rule_analysis — rule-file structure analysis and brace-mismatch check | 3 | supporting | not_run | — | — |
| `RULE-063` | Rule identity in the delivered alert name | 2 | core | not_run | — | — |
| `RULE-064` | Per-rule storm rollup alert | 2 | core | not_run | — | — |
| `RULE-065` | Rule name as a first-class dataset column | 2 | core | not_run | — | — |
| `RULE-066` | Per-rule detection tally and top_rules ranking | 2 | supporting | not_run | — | — |
| `RULE-067` | Per-rule alert text files in alert_dir | 2 | core | not_run | — | — |
| `RULE-068` | Zero-valid-rules suppresses scheduled cleanup (diagnostic preservation) | 3 | core | not_run | — | — |
| `RULE-069` | yara-python match-API normalisation (libyara 3.x vs 4.x offset shim) | 3 | core | not_run | — | — |
| `RULE-070` | Rule splitter is comment-blind, string-blind and case-insensitive | 3 | core | not_run | — | — |
| `RULE-071` | Duplicate rule names and overlapping scan targets split the books asymmetrically (one alert, two dataset rows) | 3 | core | not_run | — | — |
| `RULE-072` | Per-agent YARA/Python runtime banner in yara_processing_<run_id>.log — and its silent-failure mode | 3 | supporting | not_run | — | — |
| `RULE-073` | Matched-byte rendering for human and wire output (UTF-16 wide → UTF-8 → hex) | 3 | core | not_run | — | — |
| `RULE-074` | Post-compile rule-health telemetry, with a third success-rate denominator | 3 | supporting | not_run | — | — |
| `TRAV-001` | Explicit scan scope via the scan_folder parameter (comma-separated multi-target) | 3 | core | not_run | — | — |
| `TRAV-002` | Per-target directory validation with partial-failure tolerance | 3 | supporting | not_run | — | — |
| `TRAV-003` | Hard failure when no requested scan folder is a valid directory | 3 | core | not_run | — | — |
| `TRAV-004` | Scan-target quote stripping and whitespace trimming | 3 | supporting | not_run | — | — |
| `TRAV-005` | Scan-target de-duplication and absolute-path normalisation | 3 | supporting | not_run | — | — |
| `TRAV-006` | "default" sentinel selects full default-scope discovery | 3 | supporting | not_run | — | — |
| `TRAV-007` | Config-time warning that a requested target sits under a platform skip path (case-blind, so mostly dormant on Windows and macOS) | 3 | supporting | not_run | — | — |
| `TRAV-008` | Dead hook: _discover_all_targets override branch | not_covered | low | — not_covered | — | Not decidable on a live run. `_discover_all_targets` has no `def` anywhere in xdr_yara_scanner.py — it appears only in the `hasattr(self, "_discover_all_targets |
| `TRAV-009` | Windows default scope = every logical drive returned to this process  <sub>windows</sub> | 3 | supporting | not_run | — | — |
| `TRAV-010` | Windows drive-root de-duplication via normcase  <sub>windows</sub> | 3 | supporting | not_run | — | — |
| `TRAV-011` | Windows discovery fallbacks (A–Z probe, then C:\)  <sub>windows</sub> | not_covered | low | — not_covered | — | Not decidable on a live run. The A–Z probe rung in _default_discover_targets executes only when psutil.disk_partitions(all=False) AND ctypes.windll.kernel32.Get |
| `TRAV-012` | Linux default scope depends on effective UID (root = whole filesystem)  <sub>linux</sub> | 3 | supporting | not_run | — | — |
| `TRAV-013` | Linux non-root fallback to '/' when no probe target is readable  <sub>linux</sub> | 3 | low | not_run | — | — |
| `TRAV-014` | macOS default scope depends on effective UID (root = whole filesystem, SIP still applies)  <sub>darwin</sub> | not_covered | supporting | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-015` | macOS non-root fallback to the home directory only  <sub>darwin</sub> | not_covered | low | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-016` | Unknown platform yields an empty default target list | not_covered | low | — not_covered | — | Not decidable on a live run. The else-arm of _default_discover_targets is selected purely by platform.system() returning something other than 'Windows', 'Linux' |
| `TRAV-017` | Runtime scan-target fallback ladder (_get_scan_targets) | 3 | supporting | not_run | — | — |
| `TRAV-018` | Non-root system-path advisory for requested targets  <sub>linux, darwin</sub> | 3 | supporting | not_run | — | — |
| `TRAV-019` | Cancellable directory walk (_walk_cancellable) replacing os.walk | 3 | core | not_run | — | — |
| `TRAV-020` | Symlinked directories are enumerated but never descended into | 3 | supporting | not_run | — | — |
| `TRAV-021` | Traversal error tolerance (per-entry and per-directory) | 3 | supporting | not_run | — | — |
| `TRAV-022` | Caller-side dirnames pruning is honoured | 3 | supporting | not_run | — | — |
| `TRAV-023` | Junction/symlink directory pruning during the walk | 3 | supporting | not_run | — | — |
| `TRAV-024` | Skip lists do NOT prune traversal — excluded subtrees are still fully enumerated | 3 | supporting | not_run | — | — |
| `TRAV-025` | Producer backpressure: files are blocked on, never dropped | 1 | core | pass | 97,430 paths reconcile identically across every leg including queue=8, 0 enqueue failures | — |
| `TRAV-026` | Per-directory heartbeat call during the walk (rate-limited to YARA_HEARTBEAT_SECS) | 1 | supporting | blocked | control/ captured and empty after the run (marker removed), but the cadence is undecidable: longest leg is A a | — |
| `TRAV-027` | The skip predicate runs at four separate points per scan | 3 | supporting | not_run | — | — |
| `TRAV-028` | The scanner's own output log path is excluded from scanning | not_covered | low | — not_covered | — | Not decidable on a live run. config.output_log is always <scanner_dir>/logs/scanner_<run_id>.log, and ScanConfig unconditionally appends the scanner_dir itself  |
| `TRAV-029` | Filename skip list (OS metadata droppings) | 3 | supporting | not_run | — | — |
| `TRAV-030` | Extension skip list (disk images and VM disks) | 3 | supporting | not_run | — | — |
| `TRAV-031` | Force-scan allowlist for browser caches (overrides all path-based skips)  <sub>darwin</sub> | not_covered | core | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-032` | Cross-platform path-fragment skip list (dev caches, Windows AppData temp/packages) | 3 | supporting | not_run | — | — |
| `TRAV-033` | Fragment matching also anchors at the path tail (bare-root fix) | 3 | supporting | not_run | — | — |
| `TRAV-034` | Windows drive-letter exclusion list (present but permanently empty)  <sub>windows</sub> | 1 | low | blocked | the constant half holds in the delivered payload (1 initialiser(s), all [], 0 later writes, absent from _VALID | — |
| `TRAV-035` | Windows folder-prefix skip list (vendor agent dirs + scanner's own dir)  <sub>windows</sub> | 3 | core | not_run | — | — |
| `TRAV-036` | DEAD CODE: Windows wildcard pattern skip list never matches anything  <sub>windows</sub> | 3 | supporting | not_run | — | — |
| `TRAV-037` | Linux directory skip list (pseudo-filesystems, agent root, scanner dir)  <sub>linux</sub> | 3 | core | not_run | — | — |
| `TRAV-038` | Linux bare-root equality match (walk-root fix)  <sub>linux</sub> | 3 | supporting | not_run | — | — |
| `TRAV-039` | macOS skip list with three distinct match semantics  <sub>darwin</sub> | not_covered | core | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-040` | macOS /Volumes/ exclusion removes all mounted external and network volumes  <sub>darwin</sub> | not_covered | core | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-041` | macOS AppleDouble resource-fork file skip  <sub>darwin</sub> | not_covered | supporting | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `TRAV-042` | Unknown platform has no directory skip list at all | not_covered | low | — not_covered | — | Not decidable on a live run. The empty-skip-list branch is guarded by `platform.system()` not being Windows, Linux or Darwin; every Cortex XDR endpoint reports  |
| `TRAV-043` | Scanner working-directory self-exclusion (all three platforms) | 3 | core | not_run | — | — |
| `TRAV-044` | Per-platform case-folding policy in the skip predicate | 3 | supporting | not_run | — | — |
| `TRAV-045` | Junction / reparse-point detection (_is_junction_or_symlink) | 3 | supporting | not_run | — | — |
| `TRAV-046` | Junction/symlink loop guard with narrow, hard-coded per-platform lists | 3 | supporting | not_run | — | — |
| `TRAV-047` | Junction file skip is counted on its own dedicated counter | 3 | low | not_run | — | — |
| `TRAV-048` | Real-path resolution with platform case normalisation (_get_real_path) | 3 | supporting | not_run | — | — |
| `TRAV-049` | DORMANT: real-path de-duplication across junctions (track_real_paths is hard-wired off) | 1 | low | pass | dormant on 7 legs: unique_paths_scanned=0, path_deduplication_ratio=0.0 with junction_skips=0, unique_real_pat | — |
| `TRAV-050` | File-existence gate at dequeue time | 3 | supporting | not_run | — | — |
| `TRAV-051` | Read-permission gate with per-file permission diagnostics (unbounded, unthrottled) | 1 | supporting | blocked | UNEXERCISED: 0 read-permission denials on all 7 legs (lines/skips per leg: A:0/0 B:0/0 C:0/0 E:0/0 F:0/0 G:0/0 | — |
| `TRAV-052` | Regular-file gate (devices, FIFOs, sockets never scanned) | 3 | supporting | not_run | — | — |
| `TRAV-053` | Maximum scanned file size cap | 3 | core | not_run | — | — |
| `TRAV-054` | Bounded skip-reason labels for per-file scan errors | 3 | supporting | not_run | — | — |
| `TRAV-055` | Bulk skip accounting for an excluded directory root | 3 | supporting | not_run | — | — |
| `TRAV-056` | Excluded-target recording: a requested target that the skip list swallows whole | 3 | core | not_run | — | — |
| `TRAV-057` | files_skipped on the wire: every scan-lifecycle row carries the skip count | 1 | core | pass | non-decreasing across 9 rows [0, 0, 0, 0, 0, 1621, 4215, 4253, 4303], terminal matches the local counter (4303 | — |
| `TRAV-058` | Skip-reason breakdown in the final statistics entry | 3 | supporting | not_run | — | — |
| `TRAV-059` | Derived skip metrics in the final results entry | 3 | low | not_run | — | — |
| `TRAV-060` | Skip breakdown in the comprehensive final report and the efficiency score | 3 | low | not_run | — | — |
| `TRAV-061` | Per-target discovery statistics | 3 | supporting | not_run | — | — |
| `TRAV-062` | DEAD: total_files_found and files_per_target are computed then discarded | 3 | low | not_run | — | — |
| `TRAV-063` | Skip counting happens in the worker, under lock_counts, at dequeue grain | 3 | supporting | not_run | — | — |
| `TRAV-064` | Scan status transitions are effectively unobservable (and their uploader is never called) | 1 | low | pass | leg A recorded 5 states in order ['initializing', 'starting_workers', 'scanning', 'finishing', 'completed'], 0 | — |
| `TRAV-065` | Mid-walk exception on a scan target silently abandons the rest of that tree and erases its per-target row | 3 | core | not_run | — | — |
| `TRAV-066` | Deployer-supplied extra skip fragments (`YARA_EXTRA_SKIP_PATHS`) | 3 | core | not_run | — | — |
| `TRAV-067` | Boundary skips the force-scan allowlist may never override (`force_scan_never_under`) | 3 | core | not_run | — | — |
| `PERF-001` | CPU governor policy selector (headroom / budget / none) | 1 | core | pass | A=headroom B=none(samples 0, paused 0) C=budget; D aborted on bogus | — |
| `PERF-002` | Headroom policy — always leave N% of the host free | 1 | core | pass | headroom=30.0, identity holds on 8/8 above-floor samples (max dev 0.00<=0.2); leg F others 0.0->25.7 (+25.7 pt | — |
| `PERF-003` | Budget policy — fixed cap on the scanner's share | 1 | core | pass | target=25.0 constant across 2 samples, floor_hits=0 | — |
| `PERF-004` | CPU floor — the anti-stall guarantee (headroom policy only) | 1 | supporting | pass | others=75.5% drove the unclamped target to -35.5; floor held it at 5.0 on 116/118 samples; own fell to 3.5% an | — |
| `PERF-005` | Process-CPU normalisation to a whole-machine share | 1 | supporting | pass | host_cores=8 on every leg; own vs raw_process_cpu/8 median gap 2.5 pts vs 141 pts if un-normalised, over 6 pai | — |
| `PERF-006` | Sleep-ratio controller (proportional gain and runaway clamp) | 1 | supporting | pass | ratio wound to 6.749 under load, within the 20.0 clamp, while every idle leg stayed at 0.0 [0.0, 0.0, 0.0] | — |
| `PERF-007` | Per-file proportional pacing (the actuator) | 1 | core | pass | paced 170.86s across workers over a 129.81s run at ratio 6.749; slept_secs, total_paused_secs and the SCAN_RES | — |
| `PERF-008` | Governor sampling rate limit | 1 | supporting | pass | mean measured sample gap vs configured interval per leg {'A': (1.001, 1.0), 'C': (1.004, 1.0), 'E': (1.001, 1. | — |
| `PERF-009` | Governor fail-open on unreadable CPU | 1 | supporting | pass | 0 'CPU governor disabled' lines on any leg; A: 101 samples/101s working (of 108s run), last line 0.1s from las | — |
| `PERF-010` | Governor telemetry: change-triggered plus heartbeat emission | 1 | supporting | blocked | decidable half HOLDS on leg A: 4 lines / 101 samples (25x decoupling, <= samples/4), gaps [30.02, 30.04, 30.04 | — |
| `PERF-011` | psutil CPU sampler priming | 1 | supporting | pass | first CPU_GOVERNOR own per leg {'A': 22.2, 'C': 14.8, 'E': 11.6, 'F': 18.2} (all > 0); first progress cpu_perc | — |
| `PERF-012` | THROTTLE_CONFIG startup header in the performance log | 1 | supporting | pass | 1 header on each of 5 legs, all 11 keys, defaults on A (standard/1.0s/headroom/30.0/25.0/5.0, host_cores=8); A | — |
| `PERF-013` | Below-normal process priority and I/O priority demotion | 1 | core | blocked | the scanner's CLAIM is consistent and correct on all 5 Linux legs (A:nice=10/best_effort:7, B:nice=10/best_eff | — |
| `PERF-014` | DEAD CODE: idle-tier ("os") priority branch | 1 | low | blocked | the idle tier is unreachable on all 5 collected runs (priority_tier {'A': 'standard', 'B': 'standard', 'C': 's | — |
| `PERF-015` | CPU affinity capture (Cortex agent core pinning) | 1 | supporting | blocked | negative control verified on Linux: A: 8/8 cores, B: 8/8 cores, C: 8/8 cores, E: 8/8 cores, F: 8/8 cores — ful | — |
| `PERF-016` | host_cores recorded outside the affinity try-block | 1 | supporting | blocked | Linux arm HOLDS on all 5 legs (A:host_cores=8, B:host_cores=8, C:host_cores=8, E:host_cores=8, F:host_cores=8; | — |
| `PERF-017` | Worker thread count and the auto (cores // 2) mode | 1 | core | pass | workers=2 honoured: declared=2, distinct workers started=2 | — |
| `PERF-018` | Worker pool startup and naming | 1 | supporting | pass | (workers_started, max_workers, startup_secs) per leg {'A': (2, 2, 0.0026), 'B': (2, 2, 0.0026), 'C': (2, 2, 0. | — |
| `PERF-019` | Bounded scan queue (the memory ceiling for file discovery) | 1 | supporting | blocked | bound and derivation verified: A: workers=2 queue=4 depths=[4]; B: workers=2 queue=4 depths=[4]; C: workers=2  | — |
| `PERF-020` | Producer backpressure — block, never drop | 1 | core | pass | queue forced to 8: 93127+4303=97430 identical to the default run, 0 enqueue failures | — |
| `PERF-021` | Queue-saturation event counter with 1-in-25 log sampling | 1 | low | pass | queue_full_events=0 now readable in the summary (was absent on the identically-configured pre-fix leg G); 0 sa | — |
| `PERF-022` | Governor sampling from the blocked producer | 1 | supporting | blocked | the queue was never driven to Full: 0 'Scan queue saturated' lines across legs A/B/C/E/F, and every leg ran to | — |
| `PERF-023` | Worker queue-get timeout and cooperative exit checks | 3 | supporting | not_run | — | — |
| `PERF-024` | DEAD CONSTANT: WORKER_GET_TIMEOUT_SECS | not_covered | low | — not_covered | — | Not decidable on a live run. WORKER_GET_TIMEOUT_SECS is defined once and never read — grep over xdr_yara_scanner.py returns exactly one hit, its definition — wh |
| `PERF-025` | DEAD CONSTANT: CANCEL_DRAIN_DEADLINE_SECS | not_covered | low | — not_covered | — | Not decidable on a live run. CANCEL_DRAIN_DEADLINE_SECS / YARA_CANCEL_DEADLINE_SECS is defined and never referenced again — setting the env var to any value cha |
| `PERF-026` | Sentinel-based worker shutdown with bounded joins | 3 | supporting | not_run | — | — |
| `PERF-027` | Per-worker throughput logging every 100 files — and why its Error Rate is structurally 0.0% | 1 | low | pass | leg A: all 8 Worker Performance lines report Error Rate 0.0% (files_processed all exact multiples of 100, per- | — |
| `PERF-028` | Per-worker timing ring buffer capped at 100 samples — and the end-of-run summary that reports its length as a file count | 1 | supporting | pass | leg A: 'Worker performance summary' reports {'ScanWorker-1': 100, 'ScanWorker-2': 100} against stop-record tru | — |
| `PERF-029` | Progress heartbeat thread (whole-scan progress telemetry) | 1 | core | pass | leg A: 3 lines in 108s (~30s cadence); leg F at 5s: 8 lines in 51s | — |
| `PERF-030` | Progress snapshot holds lock_counts across psutil calls | 1 | supporting | pass | 14/14 paired ticks satisfy files_remaining == files_skipped + 2*queue_size exactly, 0 mismatches (A:3 ticks/2  | — |
| `PERF-031` | Progress sampler reuses the primed psutil handle | 1 | supporting | pass | A: 3 ticks, first cpu=118.5%, min=118.5%, max=155.3%, min mem=57.4609375MB, 0 metric errors; F: 8 ticks, first | — |
| `PERF-032` | Per-tick disk I/O guarded for macOS  <sub>darwin</sub> | not_covered | supporting | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `PERF-033` | ETA and completion-time estimation | 1 | supporting | pass | 14 'Time Estimates' records across all legs, every one internally consistent (worst \|eta - remaining/rate\| = | — |
| `PERF-034` | Scan-lifecycle heartbeat thread (dataset 'running' rows) | 1 | core | pass | 7 running rows, gaps [5.0, 5.0, 6.89, 5.0, 5.06, 5.0] against a 5s setting, counters advancing 13361->84011; t | — |
| `PERF-035` | Heartbeat gate is lock-protected against duplicate rows | 1 | supporting | blocked | the only decidable bound HOLDS: leg F added 9 rows on a 50.8s scan with YARA_HEARTBEAT_SECS=5, i.e. 7 running  | — |
| `PERF-036` | Paused-seconds accounting on every lifecycle row | 1 | supporting | pass | leg K paused 170.86s and the summary records it; leg H independently carried 0.18s to its terminal row. Reachi | — |
| `PERF-037` | Vestigial lock_throttle | not_covered | low | — not_covered | — | Not decidable on a live run. threading.Lock lock_throttle is created in YaraScanner.__init__ and acquired in exactly one place — _emit_scan_row's paused snapsho |
| `PERF-038` | Cancel-flag watcher poll thread | 3 | core | not_run | — | — |
| `PERF-039` | Stack-driven cancellable directory walk | 3 | core | not_run | — | — |
| `PERF-040` | StatisticsManager background performance sampler | 1 | supporting | blocked | default half verified on every leg (A: off x2, started 0, snapshots 0; B: off x2, started 0, snapshots 0; C: o | — |
| `PERF-041` | Performance history ring buffer and peak/average metrics | 1 | low | blocked | the ZERO CONTROL holds on every leg (5 of them: A: monitor off, samples_collected=0, all four metrics 0.0, no  | — |
| `PERF-042` | Sampled performance-detail logging (1 in 6 snapshots) | 1 | low | blocked | no leg ran with the performance monitor on — (perf_monitoring_enabled, snapshot lines, worker-start lines) per | — |
| `PERF-043` | Snapshot enrichment with live scanner counters | 1 | low | blocked | default half verified (A: null/null, 0 snapshots, scan_errors 0 lines; B: null/null, 0 snapshots, scan_errors  | — |
| `PERF-044` | SystemResourceMonitor thread (host-level resource sampling) | 1 | supporting | blocked | the OFF arm is proved POSITIVELY (not by absence) on all 5 legs — 'All monitoring systems activated' carries r | — |
| `PERF-045` | Resource alert thresholds (CPU / memory / disk) | 1 | supporting | blocked | no leg ran with YARA_ENABLE_RESOURCE_MONITOR=true — (resource_monitoring_enabled, RESOURCE ALERT entries, 'Res | — |
| `PERF-046` | Resource and alert history ring buffers | 1 | supporting | blocked | SystemResourceMonitor was never constructed — resource_monitoring is false on every leg (A:False, B:False, C:F | — |
| `PERF-047` | Resource trend classification | 1 | low | blocked | UNREACHED: no 'System resources - CPU:' record exists on any leg, because no leg ran with YARA_ENABLE_RESOURCE | — |
| `PERF-048` | Resource monitor stopped AFTER worker join, not at discovery end | 1 | supporting | blocked | no leg emitted a 'Resource monitoring completed:' record — the resource monitor was off on every run — so the  | — |
| `PERF-049` | File-descriptor sampling every 1000 CLEAN scanned files  <sub>linux, darwin</sub> | 1 | low | blocked | leg E ran with YARA_ENABLE_FD_MONITOR=true and emitted 0 'WARNING: High FD usage: ' and 0 'FD usage increased  | — |
| `PERF-050` | Startup file-descriptor limit probe  <sub>linux, darwin</sub> | 1 | supporting | blocked | the HEALTHY-HOST arm holds on leg E: exactly 1 'Current file descriptor limit: 16384', exactly 1 'Initial file | — |
| `PERF-051` | FD monitoring flag plumbing (two-name handoff)  <sub>linux, darwin</sub> | 1 | supporting | blocked | the enabled run's probe fired exactly once ('Current file descriptor limit: 16384', 'Initial file descriptors  | — |
| `PERF-052` | Per-file size cap (bounds YARA memory and time per file) | 3 | supporting | not_run | — | — |
| `PERF-053` | Chunked hashing of matched files | 2 | supporting | not_run | — | — |
| `PERF-054` | Hash only on match (no full read per scanned file) | 2 | supporting | not_run | — | — |
| `PERF-055` | Per-offset match detail is never retained in memory | 2 | supporting | not_run | — | — |
| `PERF-056` | Finding-dedup set bounded at 150,000 entries | 2 | supporting | not_run | — | — |
| `PERF-057` | Local alert-file offset sampling | 2 | supporting | not_run | — | — |
| `PERF-058` | Dataset row payload sampling per finding | 2 | supporting | not_run | — | — |
| `PERF-059` | Structured log payload truncation | 2 | low | not_run | — | — |
| `PERF-060` | DORMANT: real-path deduplication set | 3 | low | not_run | — | — |
| `PERF-061` | Compiled-rule disk cache (XDR edition only) | 3 | core | not_run | — | — |
| `PERF-062` | Rule-cache size bounds and LRU pruning | 3 | supporting | not_run | — | — |
| `PERF-063` | Rule-cache counts sidecar restore | 3 | supporting | not_run | — | — |
| `PERF-064` | Alert POST pacing against the shared rate limit | 2 | core | not_run | — | — |
| `PERF-065` | Backlog-scaled alert drain window | 2 | core | not_run | — | — |
| `PERF-066` | Rate-limit requeue with a global wall-clock budget | 2 | supporting | not_run | — | — |
| `PERF-067` | Backlog-scaled lookup drain budget and per-batch deadline | 2 | core | not_run | — | — |
| `PERF-068` | Lookup write jitter and per-target batch timers | 2 | supporting | not_run | — | — |
| `PERF-069` | Concurrent final flush of the two lookup datasets | 2 | supporting | not_run | — | — |
| `PERF-070` | Uploader threads are daemons with bounded joins | 2 | supporting | not_run | — | — |
| `PERF-071` | Tuning-knob parse guard with minimum validation | 3 | supporting | not_run | — | — |
| `PERF-072` | CPU percentage inputs are unvalidated (the clamp helper is dead) | 3 | low | not_run | — | — |
| `PERF-073` | Retired throttle options are translated, not rejected | 3 | supporting | not_run | — | — |
| `PERF-074` | DEAD CONFIG: batch_size / performance_log_interval / statistics_upload_interval | 2 | low | not_run | — | — |
| `PERF-075` | DEAD CODE: _get_scanner_stats aggregate | 1 | low | blocked | 0 occurrences of 'performance_snapshots' and 'resource_alerts' across all 45 log artefacts and scan_summaries  | — |
| `PERF-076` | DEAD CODE: periodic scan-status upload | 1 | low | blocked | on all 5 legs the two upload lines are absent while 'Scan status changed to: ' is present, so the sink is demo | — |
| `PERF-077` | Scan phase tracking (initializing → … → completed) | 3 | supporting | not_run | — | — |
| `PERF-078` | Final efficiency score and comprehensive report | 3 | supporting | not_run | — | — |
| `PERF-079` | End-of-run performance summary lines | 1 | core | pass | 1 SCAN COMPLETED, 0 SCAN FAILED, 1 worker summary | — |
| `PERF-080` | Both psutil monitors are OFF by default — every performance figure in the final report is structurally zero | 1 | core | pass | no psutil monitor started by default; samples_collected=0 | — |
| `PERF-081` | Per-file permission denials accumulate in an unbounded list that nothing ever reads | 1 | supporting | blocked | no leg encountered a single unreadable file ({'A': 0, 'B': 0, 'C': 0, 'E': 0, 'F': 0}) — every run executed as | — |
| `PERF-082` | Unthrottled 'Permission denied' system-log line — one record per unreadable file | 1 | supporting | blocked | negative control verified — A: 35 system-log lines total, skip_breakdown={'Skipped directory': 4221, 'Special  | — |
| `PERF-083` | Mislabelled resource-monitor telemetry: monitoring_duration_minutes is host uptime | 1 | low | blocked | UNREACHED: no 'System resources - CPU:' record and no 'Resource monitoring completed:' record exists on any le | — |
| `PERF-084` | Per-tick 'Network: X MB' is the whole host's traffic since boot, not the scanner's uploads | 1 | low | pass | first heartbeat of each separate scanner process, in delivery order: [('A', 3696.9), ('B', 3698.2), ('C', 3698 | — |
| `PERF-085` | Env vars outrank the options string for cpu_guarantee and workers (documented precedence is reversed) | 3 | core | not_run | — | — |
| `PERF-086` | Governor final state persisted as a structured cpu_governor block in the run summary | 1 | core | pass | cpu_governor block complete and slept totals agree on every leg | — |
| `PERF-087` | Per-worker throughput reports are time-gated, not file-count-gated | 1 | supporting | pass | leg A: 8 lines for 93,127 files (ungated ~931, 116x fewer); leg E with the gate disabled: 932 lines | — |
| `PERF-088` | Governor sampling-cadence counters (`samples_taken`, `secs_since_last_sample`) | 1 | supporting | pass | samples_taken=101 vs 4 emitted line(s) (25x divergence), last gap 1.001s | — |
| `PERF-089` | FD sampling runs once per file PROCESSED, before every early return | 2 | supporting | not_run | — | — |
| `STOR-001` | Scanner working directory root (scanner_dir) and its platform defaults | 1 | supporting | pass | A 6/6 paths under /opt/yara_scanner (Linux literal), E 6/6 under /opt/yara_lab and 0 under the default, F (nex | — |
| `STOR-002` | Fixed subdirectory layout under scanner_dir (logs, control, alert, evidence, failed_rules — plus rule_cache) | 1 | supporting | pass | 6/6 dirs present; alert/ 0 entries, failed_rules/ 0 entries, evidence/ exactly 2 (evidence_xdr-agent_20260819_ | — |
| `STOR-003` | run_id — microsecond timestamp that names every per-run file | 1 | supporting | blocked | disk half VERIFIED: 9 artefacts (8 .log + scan_summary) all on token 20260819_035240_307745; scan_id=xdr-agent | — |
| `STOR-004` | Six per-category structured log files (alerts / statistics / errors / performance / uploads / system) | 1 | supporting | pass | 6/6 files present (alerts_ and scan_errors_ zero-byte, not absent); Total Logs: 76 == sum(0, 0, 19, 12, 34, 11 | — |
| `STOR-005` | yara_processing_<run_id>.log — the rule-compilation audit trail | 3 | supporting | not_run | — | — |
| `STOR-006` | script_exceptions_<run_id>.log — lazily created, so a clean run leaves no empty file | 3 | supporting | not_run | — | — |
| `STOR-007` | scan_summary_<run_id>.json — the machine-readable per-run record, written atomically | 3 | core | not_run | — | — |
| `STOR-008` | Orphaned scan_summary *.tmp sweep at scan start | 1 | low | blocked | no .tmp was ever planted. All six legs ran back-to-back on a shared /opt/yara_scanner/logs with no pre-seeded  | — |
| `STOR-009` | Log retention — keep only the last N scans' logs and summaries | 1 | supporting | blocked | not collected: retention needs a whole-directory listing of logs/ before and after a run, and the collector pu | — |
| `STOR-010` | Current run is force-protected from retention | 1 | supporting | blocked | the discriminating setup was never run. Every leg used the default LOG_KEEP_SCANS and the current run_id sorte | — |
| `STOR-011` | Log-file deletion failures are tolerated, not fatal | 1 | low | blocked | not collected: no undeletable entry was ever planted, so the OSError branch in _prune_old_scan_logs never exec | — |
| `STOR-012` | Structured log `data` payload capped at 4000 characters per line | 2 | low | not_run | — | — |
| `STOR-013` | Upload-log volume suppression (_throttled_log buckets) | 2 | supporting | not_run | — | — |
| `STOR-014` | Progress-heartbeat writes to statistics AND performance logs on a fixed cadence for the whole scan | 1 | supporting | pass | leg A: 3 Scan Progress records in 108.5s (floor(D/30)-2 = 1), max consecutive gap 30.005s <= 45s, System Resou | — |
| `STOR-015` | config.output_log (scanner_<run_id>.log) — DEAD as a log file, but load-bearing as a path | 1 | low | pass | 0 scanner_*.log across 5 completed legs (A/B/C/E/F); each lists exactly the 8 real logs including system_ and  | — |
| `STOR-016` | initial_cleanup wipes the previous run's alert/ and evidence/ directories wholesale | 1 | supporting | blocked | the alert/ half is undecidable and the two-run design was not run. Verified after leg A: evidence/ holds exact | — |
| `STOR-017` | failed_rules/ is NOT wiped by initial_cleanup — asymmetry with alert/ and evidence/ | 3 | low | not_run | — | — |
| `STOR-018` | alert/<rule>.txt — one append-only text file per matching rule, uncapped in file count | 2 | core | not_run | — | — |
| `STOR-019` | Alert offsets sampled per finding; per-string-ID census kept complete | 2 | core | not_run | — | — |
| `STOR-020` | evidence/file_mapping.txt — path→SHA256 manifest with a host header, silently lossy on both edges | 2 | supporting | not_run | — | — |
| `STOR-021` | Evidence ZIP creation and naming | 1 | core | pass | evidence_xdr-agent_20260819_035240_307745.zip produced on a zero-match run | — |
| `STOR-022` | Content-addressed evidence entries: matched_files/<sha256> | 3 | supporting | not_run | — | — |
| `STOR-023` | Evidence ZIP de-duplicates identical content across paths | 3 | supporting | not_run | — | — |
| `STOR-024` | Metadata-only evidence ZIP is the default (collect_files=false) | 1 | supporting | pass | 1 decision record with data collect_files=false; ZIP has 1 member(s) (file_mapping.txt) and 0 matched_files/;  | — |
| `STOR-025` | Evidence ZIP bundles only alert/*.txt — .alert files are excluded by design | 1 | low | blocked | decidable only on a run that produces an alert. Verified: evidence_xdr-agent_20260819_035240_307745.zip holds  | — |
| `STOR-026` | Evidence is collected on the fatal-failure path too | 3 | supporting | not_run | — | — |
| `STOR-027` | Cancelled scans produce NO evidence ZIP and NO cleanup scheduling — surprising asymmetry | 3 | core | not_run | — | — |
| `STOR-028` | Runtime-generated cleanup script (cleanup_script.sh / .bat) in scanner_dir root | 1 | supporting | blocked | not collected: the script only exists once alert/ holds a .txt, and all six legs matched 0 (leg A matches=0),  | — |
| `STOR-029` | Alert rotation: .txt → .alert, executed by the scheduled task, not by the scan | 1 | supporting | blocked | no alert file ever existed to rotate. Leg A matched 0 files, alert/ is empty in the post-run tarball, and syst | — |
| `STOR-030` | Windows scheduled task 'CleanupScript' registered as SYSTEM  <sub>windows</sub> | 1 | supporting | blocked | not collected: every leg ran on the Linux endpoint xdr-agent (Linux 6.8.0-1063-gcp [x86_64]), where _schedule_ | — |
| `STOR-031` | Linux (and any non-Windows/non-Darwin) systemd unit /etc/systemd/system/yara-cleanup.service — written, ENABLED, never removed  <sub>linux</sub> | 1 | supporting | blocked | Observed on leg A, and it is exactly what this criterion's negative control warns about: system log emits 'Cle | — |
| `STOR-032` | macOS LaunchDaemon /Library/LaunchDaemons/com.yarascanner.cleanup.plist  <sub>darwin</sub> | not_covered | low | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `STOR-033` | Cleanup scheduling is gated on at least one alert .txt existing | 1 | supporting | pass | gate line present once; 0 'decoded'/'scheduled successfully' discriminators; alert/ 0 entries; no cleanup_scri | — |
| `STOR-034` | Cleanup scheduling is also skipped when diagnostics must be preserved | 3 | low | not_run | — | — |
| `STOR-035` | control/cancel.flag — cooperative cancel signal written by mode=cancel | 3 | core | not_run | — | — |
| `STOR-036` | control/running.json — atomically-refreshed liveness marker | 1 | supporting | blocked | only the end-state half was captured. Verified: leg A finished outcome=completed and control/ is present but E | — |
| `STOR-037` | Stale cancel-flag disambiguation by mtime, with coarse-filesystem tolerance | 3 | supporting | not_run | — | — |
| `STOR-038` | An HONOURED cancel flag is left on disk — dead-comment hazard | 3 | low | not_run | — | — |
| `STOR-039` | rule_cache/ — compiled-ruleset disk cache (XDR-only; the XSIAM twin has none) | 1 | core | pass | A fresh (0.01s) -> B cache (0.0s) | — |
| `STOR-040` | Rule-cache key composition (why a stale bundle can never load) | 3 | supporting | not_run | — | — |
| `STOR-041` | Rule-cache LRU pruning by file count AND total bytes | 3 | supporting | not_run | — | — |
| `STOR-042` | Rule-cache atomic save with PID+random temp naming | 1 | supporting | pass | compile_source=fresh (0.01s) -> 1 new bundle rules_5a5629abcbe3f9409361d3587b2a2ee4f4c61bfa.yarac + its .meta. | — |
| `STOR-043` | Rule-cache orphan .tmp sweep, age-gated at 1 hour | 1 | low | blocked | the age gate was never exercised. Verified after leg A's FRESH compile: rule_cache holds 5 rules_<40hex>.yarac | — |
| `STOR-044` | Rule-cache sidecar rules_<key>.yarac.meta.json restores rule counts on a HIT | 3 | supporting | not_run | — | — |
| `STOR-045` | Corrupt / cross-version cache entries are self-healing (and probe-validated) | 3 | supporting | not_run | — | — |
| `STOR-046` | rule_cache is deliberately exempt from HostCleanup | 1 | supporting | blocked | not collected: all 9 artefacts carrying run_id 20260819_035240_307745 survive, and the evidence ZIP is still o | — |
| `STOR-047` | failed_rules/failed_rule_<name>.yar — full source dump per compilation failure | 3 | supporting | not_run | — | — |
| `STOR-048` | failed_rules/skipped_rule_<name>_<module>.yar — module-unavailable dumps (two distinct write sites) | 3 | supporting | not_run | — | — |
| `STOR-049` | failed_rules/raw_yara_content.yar — whole-input dump when rule splitting yields nothing | 3 | supporting | not_run | — | — |
| `STOR-050` | HostCleanup — opt-in end-of-run removal of this run's on-host working files | 1 | core | pass | cleanup OFF kept 9 artefacts, cleanup ALWAYS kept 1 (the summary) — opt-in and effective | — |
| `STOR-051` | HostCleanup KEEP tiers (nothing / summary / evidence) | 1 | supporting | blocked | not collected: all 9 artefacts carrying run_id 20260819_035240_307745 survive, and the evidence ZIP is still o | — |
| `STOR-052` | HostCleanup refuses to delete unless the summary JSON durably exists | 1 | core | blocked | the failure was never induced. Across all 5 completed legs the summary write succeeded (0 'Failed to write sca | — |
| `STOR-053` | HostCleanup on_delivery gate — refuses when there is no delivery channel to verify | 1 | core | blocked | not collected on two counts: all 9 artefacts carrying run_id 20260819_035240_307745 survive, and the evidence  | — |
| `STOR-054` | HostCleanup runs only on outcome=='completed' | 3 | core | not_run | — | — |
| `STOR-055` | HostCleanup closes log FileHandlers before deleting (Windows WinError 32) | 1 | supporting | blocked | no Windows leg and no cleaned run. All 5 completed legs report os_info=['Linux 6.8.0-1063-gcp [x86_64]'] on xd | — |
| `STOR-056` | HostCleanup recreates alert/evidence/failed_rules empty after wiping | 1 | supporting | blocked | not collected: all 9 artefacts carrying run_id 20260819_035240_307745 survive, and the evidence ZIP is still o | — |
| `STOR-057` | HostCleanup identifies this run's logs the same way retention does | 1 | supporting | blocked | no cleaned run, so nothing was removed and 'only THIS run's files' has no subject. The round did produce the n | — |
| `STOR-058` | Scanner directory self-exclusion from the scan walk (per platform) | 3 | core | not_run | — | — |
| `STOR-059` | macOS case-sensitivity probe, answered once per process  <sub>darwin</sub> | not_covered | low | — not_covered | — | No macOS endpoint exists on the XDR lab tenant — it has two GCP VMs, xdr-agent (Ubuntu 22.04) and xdragent2 (Windows Server 2022). This capability's code path i |
| `STOR-060` | Per-file size ceiling bounds how much the scanner reads off the disk | 3 | supporting | not_run | — | — |
| `STOR-061` | Matched files are hashed once: SHA256 computed per match, reused by evidence | 2 | supporting | not_run | — | — |
| `STOR-062` | Per-offset match detail is deliberately NOT retained in memory | 2 | core | not_run | — | — |
| `STOR-063` | Resource-monitor sampling histories are ring-buffered (memory, not disk) | 1 | supporting | blocked | the ring-buffer CAP was never exercised: no leg turned the monitors ON, and the longest run was 108s against t | — |
| `STOR-064` | Final comprehensive report lands only in statistics_<run_id>.log — and is cut at 4000 chars, losing scan_metadata / system_info / rule_compilation first | 2 | supporting | not_run | — | — |
| `STOR-065` | alerts_<run_id>.log carries TWO structured records per matched file, and is the only artefact holding the junction-resolved real_path | 2 | supporting | not_run | — | — |
| `STOR-066` | Runtime fingerprint (embedded Python, platform, yara binding version) written at the head of yara_processing_<run_id>.log before any rule work | 1 | supporting | pass | yara_processing offsets [33, 94, 203, 289] in order, all before 'Available YARA modules: ' at 1380; Python='3. | — |
| `STOR-067` | Resolved tenant/credential/posture block and scan-target validation warnings — written to yara_processing_<run_id>.log and nowhere else | 3 | supporting | not_run | — | — |
| `STOR-068` | StatisticsManager bypasses LogManager and writes raw, multi-line blocks into statistics_/performance_<run_id>.log | 1 | low | pass | 1 COMPREHENSIVE STATISTICS SUMMARY; line after 'Worker Summary: {' is '  "ScanWorker-2": {' (indent=2, not a n | — |
| `STOR-069` | Logging counters under-report by construction, and yara_processing_<run_id>.log is missing from log_files_created | 1 | low | blocked | check raised NameError: name 'need' is not defined | — |
| `STOR-070` | Evidence ZIP is produced on every completed scan, including zero-match runs — its existence proves nothing | 1 | core | pass | outcome=completed, matches=0, unique_rules_triggered=0 -> evidence_xdr-agent_20260819_035240_307745.zip still  | — |
| `STOR-071` | Alert-directory byte ceiling degrades detail, never counts (`YARA_ALERT_DIR_MAX_MB`) | 2 | core | not_run | — | — |
| `STOR-072` | The root diagnostics handler is closed before host cleanup | 1 | supporting | blocked | the off-run control exists, the cleaned run does not, and neither is on Windows. Verified: with CONFIG_HOST_CL | — |
| `DELI-001` | Master upload kill-switch (UPLOAD_RESULTS) | 2 | core | not_run | — | — |
| `DELI-002` | Insert Parsed Alerts channel enable (create_alerts) | 2 | core | not_run | — | — |
| `DELI-003` | Lookup dataset channel enable (write_dataset) | 2 | core | not_run | — | — |
| `DELI-004` | Alert batching into one insert_parsed_alerts POST | 2 | core | not_run | — | — |
| `DELI-005` | Partial alert batch idle flush | 2 | supporting | not_run | — | — |
| `DELI-006` | Alert POST pacing against the ~600 alerts/min ceiling | 2 | core | not_run | — | — |
| `DELI-007` | Alert batch retry ladder with exponential backoff + jitter | 2 | supporting | not_run | — | — |
| `DELI-008` | Retry-After header honoured on alert throttling | 2 | supporting | not_run | — | — |
| `DELI-009` | Rate-limit classification from status code OR response body | 2 | supporting | not_run | — | — |
| `DELI-010` | Requeue rate-limited alert batches for a later window | 2 | core | not_run | — | — |
| `DELI-011` | HTTP 2xx with a JSON `false` body counted as a failure | 2 | supporting | not_run | — | — |
| `DELI-012` | Backlog-scaled end-of-scan alert drain | 2 | supporting | not_run | — | — |
| `DELI-013` | Alert thread join timeout | 2 | supporting | not_run | — | — |
| `DELI-014` | Honest leftover accounting for undelivered alerts | 2 | core | not_run | — | — |
| `DELI-015` | Alert delivery books (upload_stats fields) | 2 | core | not_run | — | — |
| `DELI-016` | Alert grain is one alert per (rule, file) finding, deduped within scan | 2 | core | not_run | — | — |
| `DELI-017` | Alert storm cap per scan | 2 | core | not_run | — | — |
| `DELI-018` | Per-rule storm rollup alerts at scan end | 2 | core | not_run | — | — |
| `DELI-019` | Alert identity: rule + basename + 8-char path hash + host | 2 | supporting | not_run | — | — |
| `DELI-020` | Alert wire payload shape and placeholder network fields | 2 | supporting | not_run | — | — |
| `DELI-021` | alert_description JSON envelope | 2 | supporting | not_run | — | — |
| `DELI-022` | Alert severity mapping | 2 | supporting | not_run | — | — |
| `DELI-023` | Throttled upload logging buckets | 2 | supporting | not_run | — | — |
| `DELI-024` | Lookup dataset naming: prefix + schema version + shard + monthly rotation | 2 | core | not_run | — | — |
| `DELI-025` | Per-writer lookup dataset sharding | 2 | core | not_run | — | — |
| `DELI-026` | Shard label slugification with collision-proof hash | 2 | supporting | not_run | — | — |
| `DELI-027` | Monthly lookup dataset rotation | 2 | supporting | not_run | — | — |
| `DELI-028` | Lookup schema version tag in the dataset name | 2 | core | not_run | — | — |
| `DELI-029` | Explicit dataset pre-creation (get_datasets probe then add_dataset) | 2 | supporting | not_run | — | — |
| `DELI-030` | add_dataset 'already exists' error body treated as success | 2 | supporting | not_run | — | — |
| `DELI-031` | Matches dataset row schema (22 fields on the wire) | 2 | core | not_run | — | — |
| `DELI-032` | Scans lifecycle row schema (22 fields on the wire) | 2 | supporting | not_run | — | — |
| `DELI-033` | Scan lifecycle row emission (initiated / running / completed / cancelled / failed) | 2 | core | not_run | — | — |
| `DELI-034` | Terminal lifecycle row emitted BEFORE the uploaders are stopped | 2 | core | not_run | — | — |
| `DELI-035` | Scans-dataset heartbeat cadence | 1 | supporting | blocked | cadence BOUND undecidable: the criterion needs consecutive event_timestamp_ms deltas in 600-635s, but the long | — |
| `DELI-036` | Independent heartbeat thread (decoupled from the directory walker) | 1 | supporting | blocked | the parked-walker window was never produced: no leg's performance log contains a 'Scan queue saturated (<n> it | — |
| `DELI-037` | running.json liveness marker for cross-process cancel | 3 | core | not_run | — | — |
| `DELI-038` | Lookup batch size (rows per add_data POST) | 2 | core | not_run | — | — |
| `DELI-039` | Per-target lookup flush timers | 2 | supporting | not_run | — | — |
| `DELI-040` | Pre-write jitter before every add_data POST | 2 | low | not_run | — | — |
| `DELI-041` | Full-jitter backoff for add_data retries (distinct from the alert ladder) | 2 | supporting | not_run | — | — |
| `DELI-042` | add_data retry cap | 2 | supporting | not_run | — | — |
| `DELI-043` | Split connect/read timeouts for add_data | 2 | supporting | not_run | — | — |
| `DELI-044` | Read-timeout attempt cap and the 'rows_unconfirmed' verdict | 2 | core | not_run | — | — |
| `DELI-045` | Per-batch wall-clock deadline so the drain cannot be killed mid-POST | 2 | supporting | not_run | — | — |
| `DELI-046` | add_data response row accounting with dual key names | 2 | core | not_run | — | — |
| `DELI-047` | Concurrent final drain of the two lookup datasets | 2 | supporting | not_run | — | — |
| `DELI-048` | Backlog-scaled lookup drain budget | 2 | core | not_run | — | — |
| `DELI-049` | Honest leftover accounting for undelivered dataset rows | 2 | core | not_run | — | — |
| `DELI-050` | Dropped-row accounting when the lookup worker is not alive | 2 | supporting | not_run | — | — |
| `DELI-051` | Lookup delivery books (upload_stats fields) | 2 | core | not_run | — | — |
| `DELI-052` | Per-finding dataset row cap and the `truncated` flag | 2 | core | not_run | — | — |
| `DELI-053` | Uncapped per-string-ID census on the wire | 2 | supporting | not_run | — | — |
| `DELI-054` | Local alert-file offset sampling (mirrors the dataset sample) | 2 | supporting | not_run | — | — |
| `DELI-055` | scan_summary_<run_id>.json — the machine-readable delivery record | 3 | core | not_run | — | — |
| `DELI-056` | delivery_shortfall — the single 'did this land?' verdict | 2 | core | not_run | — | — |
| `DELI-057` | Delivery shortfall surfaced on the Action Center result line | 2 | core | not_run | — | — |
| `DELI-058` | Host cleanup gated on confirmed delivery | 2 | core | not_run | — | — |
| `DELI-059` | Placeholder-credential pre-flight abort | 3 | core | not_run | — | — |
| `DELI-060` | XDR auth mode: per-request HMAC (Advanced) or plain key (Standard), auto-probed | 2 | supporting | not_run | — | — |
| `DELI-061` | Tenant identity tagging on every alert and every row | 2 | supporting | not_run | — | — |
| `DELI-062` | Idempotent endpoint URL construction | 2 | supporting | not_run | — | — |
| `DELI-063` | uploads_<run_id>.log — the delivery observability artefact | 2 | core | not_run | — | — |
| `DELI-064` | CPU governor telemetry heartbeat (CPU_GOVERNOR lines) | 1 | supporting | pass | leg A: 4 CPU_GOVERNOR lines over a 90.1s span (>= 3 required), max gap 30.042s <= 31.5s, gaps=[30.02, 30.035,  | — |
| `DELI-065` | DEAD CODE: CircuitBreaker class is never instantiated | 2 | low | not_run | — | — |
| `DELI-066` | DEAD CODE: ResultsUploader.upload_results() is never called | 2 | low | not_run | — | — |
| `DELI-067` | DEAD CODE: ScanStatusUploader.upload_scan_status() is never called and is double-gated off | 2 | low | not_run | — | — |
| `DELI-068` | DORMANT: _build_xdr_parsed_alert single-alert payload builder | 2 | low | not_run | — | — |
| `DELI-069` | DEAD BRANCH: 'Upload queue full' / 'Lookup dataset queue full' handlers | 2 | low | not_run | — | — |
| `DELI-070` | Log retention across runs (delivery diagnostics window) | 1 | supporting | pass | YARA_LOG_KEEP=2 honoured exactly: 6 run_ids existed in /opt/yara_scanner/logs when leg H pruned, the 4 oldest  | — |
| `DELI-071` | Comprehensive final report (statistics log only, never uploaded) | 3 | low | not_run | — | — |
| `DELI-072` | Options-string surface for delivery knobs (and what is deliberately excluded) | 3 | core | not_run | — | — |
| `DELI-073` | records_skipped counted as DELIVERED in the delivery verdict | 2 | core | not_run | — | — |
| `DELI-074` | Lookup dataset re-created mid-scan when it disappears under the writer | 2 | supporting | not_run | — | — |
| `DELI-075` | Endpoint IP identity resolved by NAME lookup — and its failure text is shipped as the IP | 3 | supporting | not_run | — | — |
| `DELI-076` | file_creation_time is empty on every Linux match, by design  <sub>windows, darwin</sub> | 3 | low | not_run | — | — |
| `DELI-077` | os_info is a hand-maintained string whose macOS name table stops at Darwin 24 | 3 | low | not_run | — | — |
| `DELI-078` | scan_folder column carries the operator's RAW input string, or the literal "system" | 3 | supporting | not_run | — | — |
| `DELI-079` | Alert channel's startup narration is unreachable — uploads log never records whether alerts are on | 2 | supporting | not_run | — | — |
| `DELI-080` | Both uploader worker loops swallow unexpected exceptions and keep running | 2 | supporting | not_run | — | — |
| `DELI-081` | Condition-only (no-strings) rule matches reach NEITHER delivery channel | 3 | core | not_run | — | — |
| `DELI-082` | An exception while building one alert dict silently shrinks the batch | 2 | supporting | not_run | — | — |
| `DELI-083` | The alert worker honours the stop flag before dequeuing | 2 | core | not_run | — | — |
| `LIFE-001` | Action Center scan entry point (main) — only 3 operator inputs | 1 | core | pass | no options string; posture resolved to 'alerts=on dataset=on files=off cpu=headroom mode=scan' | — |
| `LIFE-002` | Action Center cancel entry point (cancel, zero inputs) | 3 | core | not_run | — | — |
| `LIFE-003` | CLI entry point — five ordered positional arguments | 3 | supporting | not_run | — | — |
| `LIFE-004` | SCAN_RESULT stdout line on the CLI path | 3 | supporting | not_run | — | — |
| `LIFE-005` | Exit code derived by string-matching the result line | 3 | supporting | not_run | — | — |
| `LIFE-006` | Startup-exception exit path (exit 1 with traceback) | 3 | supporting | not_run | — | — |
| `LIFE-007` | run() — the full internal API with every behaviour knob | 3 | supporting | not_run | — | — |
| `LIFE-008` | Options string parsing with loud rejection of unknown keys | 3 | core | not_run | — | — |
| `LIFE-009` | Retired throttle_* options accepted and translated, not rejected | 3 | supporting | not_run | — | — |
| `LIFE-010` | Options string overrides explicit kwargs and CONFIG constants | 3 | supporting | not_run | — | — |
| `LIFE-011` | mode=cancel short-circuit before any scanner initialisation | 3 | supporting | not_run | — | — |
| `LIFE-012` | Cancel flag file — cooperative cross-process cancellation | 3 | core | not_run | — | — |
| `LIFE-013` | Cancel reports liveness from running.json rather than the process table, on a window scaled to the heartbeat | 3 | supporting | not_run | — | — |
| `LIFE-014` | Cancel failure modes return an error string (never raise) | 3 | supporting | not_run | — | — |
| `LIFE-015` | Stale cancel-flag eviction at scan start (with compile-phase preservation) | 3 | supporting | not_run | — | — |
| `LIFE-016` | Cancel watcher polling thread | 3 | supporting | not_run | — | — |
| `LIFE-017` | Idempotent cancel request — first source wins | 3 | low | not_run | — | — |
| `LIFE-018` | SIGTERM/SIGINT routed into the graceful cancel path | 3 | supporting | not_run | — | — |
| `LIFE-019` | Cancellation is a SUCCESS outcome, and returns early from run() | 3 | core | not_run | — | — |
| `LIFE-020` | Delivery-shortfall reporting on the cancelled path | 3 | supporting | not_run | — | — |
| `LIFE-021` | running.json liveness marker — write, heartbeat refresh, removal | 1 | supporting | blocked | post-exit half PROVEN: leg A's scanner_dir snapshot holds control/ with 0 entries (no running.json, no running | — |
| `LIFE-022` | CANCEL_DRAIN_DEADLINE_SECS — dead constant | 3 | low | not_run | — | — |
| `LIFE-023` | Scan phase ordering in scan_system | 1 | supporting | blocked | log half verified on 7 completed legs (leg A offsets [12, 15, 19, 21, 26], compile at 11, each banner exactly  | — |
| `LIFE-024` | Scan-lifecycle rows in the yara_scanner_scans dataset | 1 | core | pass | 9 rows: 1 initiated, 7 running, 1 terminal; single host xdr-agent | — |
| `LIFE-025` | Terminal lifecycle row emitted after workers drain but before uploaders stop | 1 | core | pass | terminal row scanned=93127 skipped=4303 matches the local summary exactly, and is >= every running row | — |
| `LIFE-026` | Heartbeat lifecycle row and its independent thread | 1 | supporting | blocked | the cadence itself is undecidable here: per-row event_timestamp_ms lives only in yara_scanner_scans_v3_xdr_age | — |
| `LIFE-027` | Progress-heartbeat thread spanning the whole scan | 1 | supporting | blocked | cadence half verified on leg A: 3 progress lines in 108s (>= floor(dur/30)-2 = 1), gaps [30.004, 30.005] all < | — |
| `LIFE-028` | Shutdown sequence in _perform_enhanced_cleanup | 1 | supporting | pass | order banner<initiate<waiting<Worker cleanup<Alert delivery final<Enhanced cleanup completed held on every leg | — |
| `LIFE-029` | Worker-thread join timeout is non-fatal | 1 | supporting | pass | stopped/timed_out/elapsed per leg -- A:2/0/0.0s(<= 10.0), B:2/0/0.0s(<= 10.0), C:2/0/0.0s(<= 10.0), E:2/0/0.0s | — |
| `LIFE-030` | Second, idempotent uploader stop in run()'s finally block | 2 | supporting | not_run | — | — |
| `LIFE-031` | scan_summary_<run_id>.json — the machine-readable per-run record | 3 | core | not_run | — | — |
| `LIFE-032` | Outcome derivation for the summary (cancelled > failed > completed) | 3 | supporting | not_run | — | — |
| `LIFE-033` | Duration fallback chain in the summary | 3 | low | not_run | — | — |
| `LIFE-034` | _delivery_shortfall — the single "did the findings land?" answer | 2 | core | not_run | — | — |
| `LIFE-035` | Success result line composition (skipped rules, excluded targets, cpu-slept, posture) | 3 | core | not_run | — | — |
| `LIFE-036` | Excluded-target detection at two different layers | 3 | core | not_run | — | — |
| `LIFE-037` | Fatal-failure path — status, evidence, and result line | 3 | core | not_run | — | — |
| `LIFE-038` | _mark_scan_failed — the only way scan_failed becomes true mid-scan | 3 | supporting | not_run | — | — |
| `LIFE-039` | Per-file error classification with a BOUNDED skip-reason key | 3 | supporting | not_run | — | — |
| `LIFE-040` | Worker error tiers — per-file error vs fatal worker error | 3 | low | not_run | — | — |
| `LIFE-041` | KeyboardInterrupt during the scan is a FAILURE, not a cancel | 3 | low | not_run | — | — |
| `LIFE-042` | Critical-error handler — stderr/stdout dump, 2-second sleep, and marker | 3 | core | not_run | — | — |
| `LIFE-043` | Rule-decode failure aborts before any scanning | 3 | core | not_run | — | — |
| `LIFE-044` | Invalid scan_folder handling — per-entry validation, whole-run abort only if nothing is valid | 3 | core | not_run | — | — |
| `LIFE-045` | Rule-compilation failure classification (split / none-found / all-failed / all-skipped / combined) | 3 | core | not_run | — | — |
| `LIFE-046` | Per-rule compile artefacts written to failed_rules/ | 3 | supporting | not_run | — | — |
| `LIFE-047` | Rule-cache hit restores counts from a sidecar (and validates before trusting) | 3 | supporting | not_run | — | — |
| `LIFE-048` | Root-logger INFO records land in diagnostics_<run_id>.log | 1 | supporting | blocked | the diagnostics half is PROVEN: diagnostics_<run_id>.log is 2142 bytes and carries both root INFO probes, whil | — |
| `LIFE-049` | ScanStatusUploader.set_status — a lifecycle state machine that emits nothing | 3 | supporting | not_run | — | — |
| `LIFE-050` | ResultsUploader.upload_results — dead finalisation path | 2 | low | not_run | — | — |
| `LIFE-051` | CircuitBreaker class — defined, never instantiated | not_covered | low | — not_covered | — | Not decidable on a live run. |
| `LIFE-052` | Dead/unused lifecycle constants and config attributes | 1 | low | pass | leg A: unique_real_paths=0 across all 3 progress records, unique_paths_scanned=0, junction_skips=0, 'Junction/ | — |
| `LIFE-053` | Unreachable branches: ScanConfig mode=cancel and _discover_all_targets | 3 | low | not_run | — | — |
| `LIFE-054` | logs/scanner_<run_id>.log — declared, cleaned, self-excluded, never written | 1 | low | pass | scanner_<run_id>.log never created on any of the 5 completed legs; each has exactly one of the 8 per-run files | — |
| `LIFE-055` | upload_final_comprehensive_report and the efficiency score | 3 | supporting | not_run | — | — |
| `LIFE-056` | _log_final_results — terminal statistics record and its failure variant | 3 | supporting | not_run | — | — |
| `LIFE-057` | Log retention across runs (keep last N scans) plus orphan-temp sweep | 1 | core | pass | kept the current run 20260819_043954_736239; pruned 4 older run(s) (['20260819_035240_307745', '20260819_04184 | — |
| `LIFE-058` | initial_cleanup — previous run's alert/evidence wiped at scan start | 1 | supporting | blocked | the scoping half is PROVEN on leg A's post-run snapshot: evidence/ holds exactly ['evidence/evidence_xdr-agent | — |
| `LIFE-059` | schedule_final_cleanup gating (critical errors / error ratio / no alerts) | 1 | supporting | blocked | Run-A half verified on all 7 zero-alert legs (A, B, C, E, F, G, H): exactly 1 'No alerts found, skipping clean | — |
| `LIFE-060` | Cleanup script generated from the real alert dir (path-drift fix) | 1 | supporting | blocked | no alert-producing run exists: every completed leg matched nothing ({'A': 0, 'B': 0, 'C': 0, 'E': 0, 'F': 0}), | — |
| `LIFE-061` | Platform-specific cleanup scheduling and its non-fatal failure modes | 1 | supporting | blocked | the redirected-scanner-dir half is verified: leg E wrote all 8 logs ['alerts', 'diagnostics', 'performance', ' | — |
| `LIFE-062` | End-of-run host cleanup — opt-in deletion of this run's working files | 1 | core | pass | cleanup left exactly scan_summary_20260819_044103_799557.json — the other 8 per-run artefacts removed | — |
| `LIFE-063` | Host cleanup refuses to run without a durable summary, and when there is no delivery channel | 2 | core | not_run | — | — |
| `LIFE-064` | Log handlers closed BEFORE host cleanup because Windows refuses to delete open files | 1 | supporting | blocked | the Linux half is verified on leg I (CONFIG_HOST_CLEANUP='always', keep='summary'): 0 of 8 per-run logs left i | — |
| `LIFE-065` | stop_logging idempotence and the final logging summary | 1 | supporting | pass | exactly 1 Logging Summary per leg, each the final non-empty line of system_<run_id>.log, 6 log_files_created e | — |
| `LIFE-066` | Monitoring lifecycle and its stop-once guards | 1 | supporting | blocked | default half verified on all 7 completed legs (disabled/thread-started/res-started/res-disabled/stats-stopped/ | — |
| `LIFE-067` | File-descriptor monitoring setup block (POSIX only, off by default)  <sub>linux, darwin</sub> | 1 | supporting | pass | leg E (YARA_ENABLE_FD_MONITOR=true, 93,127 files > the 1000-file sampler interval): limit=16384 recorded once, | — |
| `LIFE-068` | Non-root privilege advisories and system-path warning  <sub>linux, darwin</sub> | 3 | low | not_run | — | — |
| `LIFE-069` | Invalid numeric env var falls back to the documented default with a warning | 3 | core | not_run | — | — |
| `LIFE-070` | ExceptionLogger — lazily created, so a clean run leaves no empty file | 3 | low | not_run | — | — |
| `LIFE-071` | XDR auth-type probe on first use (auto), with caching and no-cache-on-network-error | 2 | supporting | not_run | — | — |
| `LIFE-072` | Evidence collection on the successful path (and what a metadata-only ZIP contains) | 3 | supporting | not_run | — | — |
| `LIFE-073` | Remaining-thread join in the successful path | 1 | low | pass | terminal banner exactly 1x on each of 7 completed legs, always after both 'Evidence collection completed succe | — |
| `LIFE-074` | Terminal "completed" status emission is best-effort and last | 2 | core | not_run | — | — |
| `LIFE-075` | Run identity: run_id, scan_id and their propagation | 1 | core | pass | run_id=20260819_035240_307745 scan_id=xdr-agent_20260819_035240_307745_yara_ed2487d26819; 9 artefacts all carr | — |
| `LIFE-076` | Scanner version self-identification | 1 | low | pass | scanner_version 3.3.0 agrees with the single yara_processing header line on every completed leg: A: summary=3. | — |
| `LIFE-077` | "Scan configuration established" — resolved target list logged under a non-canonical scan_id | 3 | low | not_run | — | — |
| `LIFE-078` | "All monitoring systems activated" — the run's monitoring and delivery switch record (and why performance_metrics is all zeros) | 1 | supporting | blocked | monitor-OFF half verified on all 7 completed legs (A:workers=2,cpu=headroom, B:workers=2,cpu=none, C:workers=2 | — |
| `LIFE-079` | Boolean environment toggles fail in opposite directions and have no shared parser | 3 | supporting | not_run | — | — |
| `LIFE-080` | Strictly validated operator inputs that abort the run by raising (alert_severity, mode, cpu_guarantee) | 3 | core | not_run | — | — |
| `LIFE-081` | init_data initialisation disclosure record — emitted twice, includes the tenant API URL | 1 | low | pass | both records present exactly once with a byte-identical, untruncated payload on every leg; xdr_api_url names t | — |
| `LIFE-082` | A failed category logger silently falls back to the root logger | 1 | supporting | pass | all 6 named channels exist on each of 7 completed legs (A, B, C, E, F, G, H), basenames == ['alerts', 'perform | — |
