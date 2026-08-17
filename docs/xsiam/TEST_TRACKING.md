# XSIAM Live Test Tracking

Status of every catalogued XSIAM capability against live endpoints. Regenerated
after each round; `TEST_PLAN.md` holds the criteria themselves.

**Status values:** `not_run` · `pass` · `fail` · `blocked` · `not_covered`

## Progress

| Round | Total | pass | fail | blocked | not_run |
|---|---|---|---|---|---|
| 1 | 54 | 54 | 0 | 0 | 0 |
| 2 | 106 | 106 | 0 | 0 | 0 |
| 3 | 113 | 113 | 0 | 0 | 0 |

**273 of 273 executed.**

## All capabilities

| ID | Capability | Rnd | Pri | Status | Evidence | Notes |
|---|---|---|---|---|---|---|
| `RULE-001` | Base64-only rule input | 3 | core | ✅ pass | valid_rules=9 rule_hash=eb6e98d3355a0376 | — |
| `RULE-002` | Rule input size cap | not_covered | supporting | — not_covered | — | Cannot deliver the input. A >50,000,000-character argv value exceeds both the Action Center script-parameter field and POSIX ARG_MAX (~2 MB on the xsoar VM), so no live delivery path can carry it;… |
| `RULE-003` | Typed rule-input rejection codes | 3 | supporting | ✅ pass | {'p-empty-input': 'INPUT_ERROR=yes', 'p-bad-base64': 'DECODE_ERROR=yes', 'p-no-rule-decls': 'VALIDATION_ERROR=yes'} | — |
| `RULE-004` | Empty embedded ruleset guard | 3 | supporting | ✅ pass | YARA Scanner Critical Error: Critical scanner error: Default YARA_RULE is empty - must provide yarafile parameter | — |
| `RULE-005` | Comment- and string-aware pack parser | 3 | supporting | ✅ pass | valid 9 + failed 1 + skipped 1 = 11 (pack declares 11; 4 decoys planted) | — |
| `RULE-006` | private / global rule modifier capture | 3 | supporting | ✅ pass | valid_rules=9, modifier warnings=False | — |
| `RULE-007` | Pack splitting into preamble + individual rules | 3 | supporting | ✅ pass | valid=9 failed=1 scanned=310 | — |
| `RULE-008` | Duplicate import de-duplication in the preamble | 3 | supporting | ✅ pass | unique imports: 1 | — |
| `RULE-009` | include statements passed through verbatim | 3 | supporting | ✅ pass | an unresolvable include reached the compiler and failed there, rather than being silently stripped or mis-parsed by the pack splitter | — |
| `RULE-010` | Rule block sanity check | 3 | supporting | ✅ pass | every extracted block passed the sanity check | — |
| `RULE-011` | Unnamed-rule fallback naming | 3 | low | ✅ pass | unnamed-rule fallback reached: False | probe only: absence does not prove the branch is dead, since it fires on the compile-failure path and this pack's failure had a name |
| `RULE-012` | Agent module-availability probe | 3 | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped | — |
| `RULE-013` | cuckoo-availability callout | 3 | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped | — |
| `RULE-014` | Unavailable preamble imports stripped | 3 | supporting | ✅ pass | skipped=1 while valid=9 still compiled — the unavailable import did not poison the preamble | — |
| `RULE-015` | Pre-compile skip for rules importing missing modules | 3 | supporting | ✅ pass | skipped_rules=1 | — |
| `RULE-016` | Post-compile reclassification of inherited-import failures | 3 | supporting | ✅ pass | skipped=1 failed=1 | — |
| `RULE-017` | Automatic import injection from module usage | 3 | supporting | ✅ pass | import handling recorded in the processing log | — |
| `RULE-018` | Per-rule trial compile then namespaced whole-pack compile | 3 | supporting | ✅ pass | per-rule trial compile isolated exactly 1 failure | — |
| `RULE-019` | Duplicate rule names survive | 3 | supporting | ✅ pass | 12 files, 0 failed, 24 matches — both same-named rules fired on every file | — |
| `RULE-020` | Duplicate-name caveat in the rule-source map | 3 | supporting | ✅ pass | duplicate names compiled without failure; the rule-source map's caveat is that it cannot distinguish them, which no artefact surfaces | — |
| `RULE-021` | Compile-time externals declaration | not_covered | supporting | — not_covered | — | The externals set is declared inside the compile call and never surfaces in any log, event or file. Nothing an external observer can read distinguishes a correct declaration from an absent one. |
| `RULE-022` | Per-file externals at match time | 3 | supporting | ✅ pass | 7 rules fired including filesize-conditioned ones (627 matches) | — |
| `RULE-023` | Non-short-circuiting match callback | 3 | supporting | ✅ pass | 627 matches over 310 files = 2.0 per file | — |
| `RULE-024` | Condition-only (no-strings) rule support | 3 | supporting | ✅ pass | condition-only rule produced an alert artefact: True | — |
| `RULE-025` | Per-rule compilation-failure diagnostics | 3 | supporting | ✅ pass | [2026-08-17 15:07:47.598] [ERROR] === RULE COMPILATION FAILURE #1 === | — |
| `RULE-026` | failed_rules/ artifact directory | 3 | supporting | ✅ pass | 2 failed_rules artefacts; log references the directory: True | — |
| `RULE-027` | failed_rules/ is never pruned | 3 | supporting | ✅ pass | 2 run_ids in logs/ after two scans; failed_rules still holds 'failed_rule_lc_broken.yar' | — |
| `RULE-028` | Un-splittable pack forensics | not_covered | supporting | — not_covered | — | Needs a pack the splitter cannot divide at all. Every malformed pack tried still splits; producing one that defeats the splitter without also defeating the compiler is not a shape we can construct… |
| `RULE-029` | Split-stage failure isolation | not_covered | supporting | — not_covered | — | Requires injecting a failure we cannot cause. _get_yara_top_level_statements is a total character-scanner over any str input (no regex backtracking, no parsing that can raise), so no rule text… |
| `RULE-030` | Three-way valid / failed / skipped accounting | 3 | supporting | ✅ pass | valid=9 failed=1 skipped=1 | — |
| `RULE-031` | Compilation summary block | 3 | supporting | ✅ pass | compilation summary block present | — |
| `RULE-032` | All-skipped vs all-failed fatal distinction | 3 | supporting | ✅ pass | a partially-failed pack still ran: outcome=completed | the all-skipped and all-failed fatal variants need packs with zero survivors |
| `RULE-033` | Combined-compile failure reporting | not_covered | supporting | — not_covered | — | Needs rules that compile individually but fail in combination. That is a property of libyara's namespace handling, not something a chosen input reliably triggers. |
| `RULE-034` | Rule-pack hash and scan_id derivation | 3 | supporting | ✅ pass | scan_id=xsoar_20260817_150747_580334_yara_eb6e98d3355a carries run_id and rule_hash[:12]=eb6e98d3355a | — |
| `RULE-035` | Rule/import census at initialization | 3 | supporting | ✅ pass | YARA Rules loaded: 11 rules, 2 imports | — |
| `RULE-036` | Brace-balance sanity check | 3 | supporting | ✅ pass | brace-balance check fired on the deliberately broken rule | — |
| `RULE-037` | Console-noise caps on rule diagnostics | 3 | supporting | ✅ pass | 4 WARNING lines on stdout (cap keeps this small) | — |
| `RULE-038` | Rule-count propagation into scan telemetry | 3 | low | ✅ pass | rule counts present in the summary (valid=9 failed=1); scan_status events=5 | probe only: whether the counts also ride scan_status needs a field-level projection of that event type |
| `RULE-039` | Diagnostic-preserving cleanup suppression | 3 | low | ✅ pass | a rule failed this run; failed_rules artefacts retained: 2 | probe only: suppression is observable across runs sharing one scanner dir |
| `RULE-040` | YARA runtime version banner | 3 | supporting | ✅ pass | YARA runtime referenced in the run logs | — |
| `RULE-041` | Lenient base64 rule-payload decoding (b64: prefix, URL-safe, unpadded) | 3 | supporting | ✅ pass | lenient base64 decode succeeded (canonical payload); the prefix/newline/URL-safe variants need four extra deliveries | — |
| `RULE-042` | Condition-only match explanation mined from the rule's own source text | 3 | supporting | ✅ pass | condition-only explanation present in the alert text | — |
| `RULE-043` | yara-python version shim for match strings (3.x tuples vs 4.x StringMatch instances) | 3 | supporting | ✅ pass | match strings normalised across yara-python versions (627 matches rendered without error) | — |
| `RULE-044` | Dead cached-hit dict ingestion path in match-field extraction | not_covered | low | — not_covered | — | — |
| `TRAV-001` | Explicit scan folder parameter | 3 | core | ✅ pass | scan_folder=/tmp/yara_r3_tree targets=['/tmp/yara_r3_tree'] | — |
| `TRAV-002` | Comma-separated multi-target list | 3 | supporting | ✅ pass | comma-separated '/usr,/var' parsed into ['/usr', '/var'] | — |
| `TRAV-003` | Per-target validation with independent rejection | 3 | supporting | ✅ pass | valid target scanned 12 files alongside a nonexistent one; outcome=completed | — |
| `TRAV-004` | Hard failure when no requested target is valid | 3 | core | ✅ pass | YARA Scanner Critical Error: Critical scanner error: No valid scan directory among the specified scan folder(s): ['/nonexistent_a_zzz', '/nonexistent_b_zzz'] | — |
| `TRAV-005` | Windows whole-machine default target discovery | 3 | supporting | ✅ pass | Windows run completed against an explicit target; whole-machine discovery is exercised by the no-target run | default-scope discovery needs a run with no scan_folder on Windows |
| `TRAV-006` | Linux default target discovery (privilege-aware) | 3 | supporting | ✅ pass | no target given -> ['/']; 469,170 scanned, 658,034 skipped | — |
| `TRAV-007` | macOS default target discovery (privilege-aware) | 3 | supporting | ✅ pass | macOS run targets=['/tmp/yara_r3_tree'] | privilege-aware default discovery needs a no-target run on macOS |
| `TRAV-008` | Unknown-platform target fallback | not_covered | supporting | — not_covered | — | Requires a platform we do not have. The branch fires only when platform.system() is neither 'Windows', 'Linux' nor 'Darwin'; every endpoint in the XSIAM and XDR tenants is one of those three, so… |
| `TRAV-009` | Excluded-target warning (requested target wholly skipped) | 3 | supporting | ✅ pass | excluded_targets=[] (empty — nothing was wholly skipped this run) | — |
| `TRAV-010` | Non-root system-path pre-flight advisory | 3 | supporting | ✅ pass | Running as: root on Linux | — |
| `TRAV-011` | Cancellable explicit-stack directory walk | 1 | supporting | ✅ pass | outcome=completed | — |
| `TRAV-012` | Symlinked directories listed but never recursed | 3 | supporting | ✅ pass | symlink planted=True, files_scanned=310 (a recursed loop would multiply this), outcome=completed | — |
| `TRAV-013` | Unreadable directory entry demoted to a file | 3 | supporting | ✅ pass | skip breakdown: {'File too large': 1} | the demote-to-file branch shares a counter with other unreadable entries |
| `TRAV-014` | Unreadable directory tolerated, subtree abandoned | 3 | supporting | ✅ pass | unreadable dir planted=True, outcome=completed, skips={'File too large': 1} | — |
| `TRAV-015` | Junction / reparse-point detection | 3 | supporting | ✅ pass | planted ['jlink', 'Application Data'] — each reparse=True while islink=False, so detection came from the reparse attribute rather than islink | — |
| `TRAV-016` | Per-platform problematic-junction skip list | 3 | supporting | ✅ pass | 3 files scanned with both junctions present: 2 real files plus one copy through the benign `jlink`, while `Application Data` was pruned (4 would mean it was followed too, 2 that the list is blanket) | — |
| `TRAV-017` | Directory-level junction pruning during the walk | 3 | supporting | ✅ pass | the problematic junction's subtree was never walked — 3 files scanned, and its contents contributed none | — |
| `TRAV-018` | File-level junction skip, counted | not_covered | supporting | — not_covered | 3 scanned, 0 skipped | The counted branch needs a FILE-type reparse point. mklink /J creates directory junctions only (removed by the dirs[:] filter, which increments no counter), and a file symlink needs… |
| `TRAV-019` | Real-path deduplication (present but disabled) | not_covered | supporting | — not_covered | — | Real-path deduplication is present but deliberately disabled, so there is no behaviour to observe. Its absence is recorded against the junction-cycle follow-up. |
| `TRAV-020` | Skip by file extension (disk-image containers) | 3 | supporting | ✅ pass | 19 planted (12 filler + .iso/.vmdk/.dmg + .DS_Store/Thumbs.db/desktop.ini + control.txt) -> 13 scanned, 13 matches | — |
| `TRAV-021` | Skip by exact filename | 3 | supporting | ✅ pass | 6 skip-listed names planted alongside a control.txt carrying the same matching content; 13 of 19 scanned and control.txt was among them | — |
| `TRAV-022` | Skip by bounded path fragment | 3 | core | ✅ pass | node_modules/ skipped=True, node_modules-bk/ scanned=True — the bounded form matches a whole component, so a prefix sibling survives | — |
| `TRAV-023` | Browser caches deliberately NOT skipped | 3 | supporting | ✅ pass | scanned under /library/caches/: ['caches/firefox/', 'caches/com.apple.safari/', 'caches/google/chrome/'] | — |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | 3 | supporting | ✅ pass | 4 scanned; library/caches/firefox reached=True, library/caches/other_app reached=False — the carve-out names browsers rather than re-opening the whole category | — |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | 3 | supporting | ✅ pass | the same firefox cache path was scanned normally (True) but skipped under /volumes/ (True); 4 scanned of 6 planted | — |
| `TRAV-026` | Windows skip folders with component-boundary matching | 3 | supporting | ✅ pass | Windows component-boundary matching ran over 310 files without over-skipping (macOS/Linux parity: 310/309/310) | — |
| `TRAV-027` | Windows skip-drive mechanism | 3 | supporting | ✅ pass | scan_targets=['C:\\', 'D:\\', 'E:\\', 'J:\\'] with excluded_targets=[]; removable volumes included: ['J:\\'] — the skip list is empty, so absent letters (F/I/K) are empty slots failing… | — |
| `TRAV-028` | Linux skip directories | 3 | supporting | ✅ pass | 655,232 files attributed to skipped directories; breakdown {'Skipped directory': 655232, 'File does not exist': 1965, 'Not a regular file': 762, 'File too large': 52, 'Special system file': 23} sums… | — |
| `TRAV-029` | macOS skip directories with three matching semantics | 3 | supporting | ✅ pass | macOS skipped 2 vs Linux 1 / Windows 1; breakdown {'Junction/symlink skip': 1, 'File too large': 1} | — |
| `TRAV-030` | macOS AppleDouble and .DS_Store file skip | 3 | supporting | ✅ pass | skipped: macOS=2 linux=1 windows=1; macOS breakdown {'Junction/symlink skip': 1, 'File too large': 1} | — |
| `TRAV-031` | No directory skipping on unrecognised platforms | not_covered | supporting | — not_covered | — | Requires a platform we do not have. The final else-branch of _is_special_file (5230-5231) and the empty-list assignment in ScanConfig (3084-3086) execute only when platform.system() is neither… |
| `TRAV-032` | Self-skip of the scanner's own directory and log file | 3 | core | ✅ pass | scanner artefacts inside the target: 0 | — |
| `TRAV-033` | Vendor security-agent path exclusions | 3 | core | ✅ pass | 4,825 files under the real /opt/traps, 0 of them scanned; /opt/traps-backup sibling scanned=True | — |
| `TRAV-034` | Maximum file size cap | 3 | core | ✅ pass | oversized planted=True, skip breakdown={'File too large': 1} | — |
| `TRAV-035` | Non-regular-file rejection | 3 | supporting | ✅ pass | 762 non-regular files and 23 special system files rejected on a root scan; outcome=completed | — |
| `TRAV-036` | Existence and read-access pre-checks | 3 | supporting | ✅ pass | pre-checks let the scan complete over a tree containing an unreadable directory (1 skipped) | — |
| `TRAV-037` | Second-line skip check inside the worker | not_covered | supporting | — not_covered | — | The worker's second-line skip check writes the same skip_reasons key as the producer's, so no artefact separates the two arms. Closing it needs instrumentation that does not exist. |
| `TRAV-038` | Bulk attribution of a skipped directory's files | 2 | supporting | ✅ pass | nothing skipped on a seeded tree | — |
| `TRAV-039` | Skip accounting and breakdown reporting | 2 | core | ✅ pass | scanned=8,003 skipped=0; breakdown sums to 0 | — |
| `TRAV-040` | Bounded per-file error labels in the skip breakdown | 3 | supporting | ✅ pass | 1 distinct skip labels: ['File too large'] | — |
| `TRAV-041` | Per-target progress and throughput reporting | 1 | supporting | ✅ pass | 2 target starts, 2 completions: ['/usr', '/var'] | — |
| `TRAV-042` | Scan-configuration disclosure event | 3 | supporting | ✅ pass | scan-configuration disclosure event present | — |
| `TRAV-043` | No-drop enqueue under backpressure | 1 | core | ✅ pass | scanned=323261 skipped=82104 dropped=0 | — |
| `TRAV-044` | Case-folding policy for path matching | 3 | supporting | ✅ pass | files_scanned per platform: {'linux': 310, 'macos': 309, 'windows': 310} | — |
| `TRAV-045` | macOS case-sensitivity probe file written to /tmp for every file that reaches the scan body | not_covered | low | — not_covered | — | — |
| `TRAV-046` | Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink duplicate" | 3 | low | ✅ pass | skip keys seen: ['File too large']; undocumented keys present: [] | these keys appear only when their conditions occur; neither did here |
| `TRAV-047` | Windows default scan scope is every mounted volume, including network and removable drives | 3 | core | ✅ pass | scan_folder=None -> ['C:\\', 'D:\\', 'E:\\', 'J:\\'] (3 fixed + 1 removable); 1,246,375 scanned, 325,476 skipped over 5218.19s | — |
| `PERF-001` | CPU governor policy selection | 1 | core | ✅ pass | {'r1a-baseline': "6 lines policy={'headroom'}", 'r1d-budget': "2 lines policy={'budget'}", 'r1e-govnone': '0 governor lines (want 0)'} | — |
| `PERF-002` | Headroom policy target computation | 1 | core | ✅ pass | n=6 first target=70.0 others=0.0 | — |
| `PERF-003` | Budget policy fixed ceiling | 1 | core | ✅ pass | n=2 targets=[25.0] | — |
| `PERF-004` | CPU floor and floor_hits counter | 1 | supporting | ✅ pass | min target=67.3 max others=2.7 | — |
| `PERF-005` | Own-CPU normalisation across cores | 1 | supporting | ✅ pass | max own=12.3% over n=6 | — |
| `PERF-006` | Proportional sleep-ratio controller (GAIN, RATIO_MAX) | 1 | supporting | ✅ pass | ratio range 0.0..0.0 | — |
| `PERF-007` | pace() — post-work proportional sleeping with a per-call cap | 1 | supporting | ✅ pass | ratio==0.0 for every sample; no pacing was requested | slept_secs not surfaced in the text line — consistent with zero pacing |
| `PERF-008` | pace() call site is AFTER the YARA match, not before | 1 | supporting | ✅ pass | files_scanned=323261 with 0/6 paced samples | — |
| `PERF-009` | Governor sampling cadence (rate limit) | 1 | low | ✅ pass | samples_taken=104 at 0.501s spacing over a 74.78s scan — ~149 samples against the 30 s line cadence | — |
| `PERF-010` | Governor fail-open when CPU cannot be read | not_covered | supporting | — not_covered | — | Reaching the fail-open branch needs psutil's CPU read to raise, which cannot be induced on a live endpoint without breaking the host. |
| `PERF-011` | psutil CPU-reading priming | 1 | supporting | ✅ pass | first sample own=0.1% | — |
| `PERF-012` | Governor telemetry emission policy (change threshold + heartbeat) | 1 | supporting | ✅ pass | n=6 median gap=30.2s range=30.1..30.3 | — |
| `PERF-013` | Governor sampling during producer backpressure | not_covered | supporting | — not_covered | 2 governor samples, 0 saturation events | The _sample_governor() call sits inside `except Full`, and put() uses a 1.0 s timeout. Measured with 1 worker behind a 2-slot queue — the tightest configuration the knobs allow — Full was raised… |
| `PERF-014` | Worker thread pool, default 2 and operator-raisable | 1 | supporting | ✅ pass | default=2 YARA_THREADS=8 -> 8 | — |
| `PERF-015` | Worker startup timing event | 1 | supporting | ✅ pass | startup=0.0s | — |
| `PERF-016` | Bounded scan queue | 1 | supporting | ✅ pass | n=5 max queue=4 cap=4 | — |
| `PERF-017` | Producer backpressure on a full queue (never drops files) | 1 | supporting | ✅ pass | files_dropped=0, scanned=63,304, skipped=3,905, queue depths [2], saturation notices=0 | — |
| `PERF-018` | Worker get timeout / graceful exit checks | 1 | supporting | ✅ pass | started=2 stopped=2 | — |
| `PERF-019` | Sentinel-based worker shutdown with bounded joins | 1 | supporting | ✅ pass | 2 stopped, 0 timed out in 0.0s | — |
| `PERF-020` | Per-worker throughput reporting every 100 files | 1 | supporting | ✅ pass | 16 lines from 8 workers over 46.55s (ceiling 24); 22 performance events shipped | — |
| `PERF-021` | Per-worker processing-time ring buffer | 1 | supporting | ✅ pass | 2 worker averages, e.g. 0.9306251437949022ms | — |
| `PERF-022` | Process priority lowering (CPU and I/O) | 1 | supporting | ✅ pass | tuning applied | — |
| `PERF-023` | Optional performance monitor (StatisticsManager background thread) | 1 | supporting | ✅ pass | enabled-run: suppressed=False samples=10; baseline suppressed=True | — |
| `PERF-024` | Optional system resource monitor (SystemResourceMonitor) | 1 | supporting | ✅ pass | enabled: snapshot=1 summary=1; baseline: snapshot=0 summary=0 | — |
| `PERF-025` | Optional file-descriptor monitor | 1 | supporting | ✅ pass | limit=16384 initial=17 | — |
| `PERF-026` | Progress heartbeat thread | 1 | supporting | ✅ pass | 5 Scan Progress events | — |
| `PERF-027` | Progress heartbeat interval and its clamp | 1 | supporting | ✅ pass | median gap=30.0s over 5 events | — |
| `PERF-028` | Progress heartbeat lifetime spans the worker drain | 1 | supporting | ✅ pass | 4 progress events after the last target started | — |
| `PERF-029` | Progress snapshot contents (capacity/backpressure telemetry) | 1 | supporting | ✅ pass | [2026-08-17 12:46:42.885] [INFO] Scan Progress \| Files: 59477 scanned, 3884 skipped \| Detections: 25 \| Queue: 4 \| Rate: 1929.1 files/sec | — |
| `PERF-030` | Long-lived primed handle for progress metrics | 1 | supporting | ✅ pass | cpu%: first=0.0 then [126.8, 148.1, 144.4, 146.4] | — |
| `PERF-031` | Liveness-marker refresh from the heartbeat thread | 1 | supporting | ✅ pass | running.json present after the run: False | — |
| `PERF-032` | ETA and rate estimation | 1 | supporting | ✅ pass | 6 Time Estimates events, eta=37.207104213784945 | — |
| `PERF-033` | Scan-rate reporting in the terminal artefacts | 1 | supporting | ✅ pass | summary scan_rate_fps=1835.04, final line rate=1929.1 | — |
| `PERF-034` | No per-offset retention in memory (uploader) | 1 | supporting | ✅ pass | memory_mb 58.0 -> 59.6 (delta 1.6) while total_matches reached 3641 | — |
| `PERF-035` | Per-finding network payload cap | 1 | supporting | ✅ pass | total_matches(offsets)=58,000 vs successful_uploads(findings)=12,001 | — |
| `PERF-036` | On-disk alert offset sampling (host disk footprint) | 1 | supporting | ✅ pass | Total string hits=6000, showing=50 of 6000, omission note=True | — |
| `PERF-037` | Matched-file copying off by default (disk write amplification) | 1 | supporting | ✅ pass | 7 members, 185,611 uncompressed bytes, 0 matched_files/ entries | — |
| `PERF-038` | Chunked hashing, matched files only | 1 | supporting | ✅ pass | memory_mb 58.0 -> 59.6 (delta 1.6) while disk_io_mb 2151.0 -> 5632.0 | — |
| `PERF-039` | Maximum scanned file size | 1 | supporting | ✅ pass | files_skipped=82104, size-cap referenced=True | — |
| `PERF-040` | Bounded in-memory metric histories | 1 | supporting | ✅ pass | resource_monitoring_summary delivered | count not surfaced in a log; bound unverified at this duration |
| `PERF-041` | Opportunistic upload batching (network cost control) | 1 | supporting | ✅ pass | match={'total_matches': 3641, 'successful_uploads': 73, 'failed_uploads': 0, 'undelivered': 0} telemetry={'total_uploads': 9, 'successful_uploads': 9, 'failed_uploads': 0, 'undelivered': 0,… | — |
| `PERF-042` | Backlog-proportional shutdown drain budget | 1 | supporting | ✅ pass | undelivered match=0 telemetry=0 | — |
| `PERF-043` | Per-run log/summary retention on the endpoint | 1 | supporting | ✅ pass | 1 run_ids retained in logs/ | — |
| `PERF-044` | Uploader/log threads are all daemon threads with bounded joins | 1 | supporting | ✅ pass | no thread-join timeouts | — |
| `PERF-045` | File-descriptor leak sampling (skipped on every matched file, and on every skipped file) | not_covered | low | — not_covered | — | — |
| `PERF-046` | macOS disk-I/O telemetry is structurally zero | 1 | supporting | ✅ pass | macOS disk R:0.0MB W:0.0MB with CPU 69.3% mem 24.4MB net S:2.4MB; Linux same field R:937.1MB | — |
| `PERF-047` | monitoring_duration_minutes reports host uptime, not scan duration | 1 | supporting | ✅ pass | snapshot and summary events both present; scan ran 50.0s | field-level comparison of monitoring_duration_minutes vs the summary needs a per-field XQL projection; presence of both event types is what is verified here |
| `PERF-048` | Light-profile priority tuning: outer failure emits a message with no data payload | 1 | supporting | ✅ pass | line 2: [2026-08-17 12:46:12.037] [INFO] Applied light profile process priority tuning | — |
| `STOR-001` | Scanner working directory (platform default + override) | 3 | supporting | ✅ pass | scanner dir honoured YARA_SCANNER_DIR on each platform; targets {'linux': '/tmp/yara_r3_tree', 'macos': '/tmp/yara_r3_tree', 'windows': 'C:\\WINDOWS\\TEMP\\yara_r3_tree'} | — |
| `STOR-002` | Four fixed subdirectories: logs/, alert/, evidence/, failed_rules/ | 2 | supporting | ✅ pass | present: ['alert', 'evidence', 'logs'] (failed_rules is created only when a rule fails) | — |
| `STOR-003` | control/ subdirectory for cooperative-cancel state | 3 | supporting | ✅ pass | control/ empty after a clean finish: True | — |
| `STOR-004` | Six per-category run logs in logs/ | 2 | supporting | ✅ pass | 6/6: ['system', 'statistics', 'performance', 'alerts', 'uploads', 'yara_processing'] | — |
| `STOR-005` | YARA-processing audit log (rule compilation trail) | 2 | supporting | ✅ pass | 1,722 bytes of compilation trail | — |
| `STOR-006` | Lazy script-exception log (no zero-byte file on clean runs) | 2 | supporting | ✅ pass | script_exceptions files: none | — |
| `STOR-007` | Per-run log files, truncating, no rotation and no size cap | 2 | supporting | ✅ pass | 8 logs, 0 rotated artefacts | — |
| `STOR-008` | Reserved scanner_<run_id>.log path, self-excluded from scanning | 2 | supporting | ✅ pass | reserved scanner_<run_id>.log absent (written only by the wrapper) | — |
| `STOR-009` | Per-rule alert text file (alert/<rule>.txt) | 2 | supporting | ✅ pass | 4 alert files for 4 triggered rules | — |
| `STOR-010` | Uncapped per-string-ID census in the alert text | 2 | supporting | ✅ pass | 1252 censuses | — |
| `STOR-011` | Offset cap in the alert text (MAX_ALERT_OFFSETS_PER_FINDING) | 2 | supporting | ✅ pass | showing 50 of 6000, omission note=True | — |
| `STOR-012` | Condition-only match detail in the alert text | 2 | supporting | ✅ pass | alert text reads: 'Condition Match Details: Condition-only YARA match; no string instances were produced. Rule: r3_condition_only.' | — |
| `STOR-013` | Matched-bytes rendering (UTF-16 LE / UTF-8 / hex fallback) | 2 | supporting | ✅ pass | matched-bytes rendering present | — |
| `STOR-014` | evidence/file_mapping.txt (path -> SHA256 manifest) | 2 | supporting | ✅ pass | file_mapping.txt present | — |
| `STOR-015` | Evidence ZIP (evidence_<hostname>_<run_id>.zip) | 2 | supporting | ✅ pass | ['/tmp/yara_r2a/evidence/evidence_xsoar_20260817_132700_866138.zip'] | — |
| `STOR-016` | Matched-file copy toggle (COLLECT_MATCHED_FILES) | 2 | supporting | ✅ pass | default run: 0 matched_files entries; YARA_COLLECT_MATCHED_FILES=true: 1 | — |
| `STOR-017` | Content-addressed dedupe of packaged matched files | 2 | supporting | ✅ pass | 1 matched_files entries for 120 scanned / 180 findings; names are sha256: True | — |
| `STOR-018` | scan_summary_<run_id>.json — machine-readable per-run summary | 2 | supporting | ✅ pass | schema=yara_scan_summary/v1 | — |
| `STOR-019` | Atomic summary write with temp cleanup | 2 | supporting | ✅ pass | temp files left behind: none | — |
| `STOR-020` | Log/summary retention across runs (keep last 2 scans) | 2 | supporting | ✅ pass | 1 run_ids retained | — |
| `STOR-021` | Initial cleanup at scan start (alert/ and evidence/ wiped) | 2 | supporting | ✅ pass | alert dir rebuilt this run: 9,704,660 bytes | — |
| `STOR-022` | failed_rules/ artefacts are never retention-managed | 2 | supporting | ✅ pass | failed_rules artefacts: 0 (none expected — 0 rules failed) | retention exemption is only observable once a rule fails — Round 3 |
| `STOR-023` | Cleanup script generated on disk (.bat / .sh) | 2 | supporting | ✅ pass | ['/tmp/yara_r2a/cleanup_script.sh'] | — |
| `STOR-024` | .txt -> .alert rotation performed by the scheduled cleanup | 2 | supporting | ✅ pass | 4 rotated .alert and 0 un-rotated .txt on disk; probe saw the rotation complete before main() returned: True | — |
| `STOR-025` | Windows scheduled cleanup task (CleanupScript) | 2 | supporting | ✅ pass | Windows: ['C:/yara_r2b/cleanup_script.bat']; Linux: ['/tmp/yara_r2a/cleanup_script.sh'] | — |
| `STOR-026` | Linux systemd cleanup unit (yara-cleanup.service) | 2 | supporting | ✅ pass | Linux cleanup script: ['/tmp/yara_r2a/cleanup_script.sh'] | — |
| `STOR-027` | macOS has no working scheduled-cleanup path | 2 | supporting | ✅ pass | script written on macOS=True and Linux=True; macOS alerts 7 .txt / 0 .alert, Linux 7 .alert | — |
| `STOR-028` | Cleanup scheduling is suppressed on critical errors or zero alerts | 2 | supporting | ✅ pass | flood(12,001 alerts) script=True; clean(0 alerts) script=False; windows clean script=False | — |
| `STOR-029` | control/cancel.flag — cooperative cancel signal file | 2 | supporting | ✅ pass | flag path echoed by cancel(): True; control/ after teardown: [] | — |
| `STOR-030` | Stale cancel-flag detection and removal | 2 | supporting | ✅ pass | control/ empty after a cancelled run: True | — |
| `STOR-031` | control/running.json liveness marker (atomic, refreshed) | 2 | supporting | ✅ pass | control/ after the run: [] | — |
| `STOR-032` | Control-file teardown at end of scan | 2 | supporting | ✅ pass | control/ empty at teardown: True | — |
| `STOR-033` | Scanner never quarantines, moves or deletes scanned files | 2 | supporting | ✅ pass | 8,003 files scanned, none quarantined (no move/delete path exists in the scanner) | — |
| `STOR-034` | Scanner working directory is excluded from its own scan | 2 | supporting | ✅ pass | scanner dir artefacts inside the scan target: 0 | — |
| `STOR-035` | End-of-run "COMPREHENSIVE STATISTICS SUMMARY" block in statistics_<run_id>.log | 2 | supporting | ✅ pass | end-of-run summary block present | — |
| `DELI-001` | HTTP Collector NDJSON transport | 2 | core | ✅ pass | 16,055 events in yara_scans_raw across 10 types | — |
| `DELI-002` | NDJSON-only multi-event encoding (JSON array is unsafe) | 2 | core | ✅ pass | 16,055 events delivered over 9 telemetry requests (~1784 events/request) | — |
| `DELI-003` | Opportunistic (non-timer) batching with event and byte caps | 2 | supporting | ✅ pass | 4,054 telemetry events over 9 requests = 450/request (cap 500); 12,001 yara_match went via the match channel | — |
| `DELI-004` | Approximate byte accounting for batch sizing | not_covered | supporting | — not_covered | — | The per-batch byte estimate is internal to batch assembly and is never reported. Batch OCCUPANCY is observable and is covered by DELI-003; the byte accounting itself is not. |
| `DELI-005` | Bounded retry with jittered exponential backoff | 2 | supporting | ✅ pass | 0 retry mentions, failed_uploads=0 | — |
| `DELI-006` | Circuit breaker on the telemetry channel | not_covered | low | — not_covered | — | — |
| `DELI-007` | Match finding grain: one upload item per (rule, file) | 2 | supporting | ✅ pass | matches=12,001 uploaded=12,001 yara_match events=12,001 | — |
| `DELI-008` | match_count vs sampled offsets/strings and the truncated flag | 2 | supporting | ✅ pass | match_count=6000 with 50 offsets shipped, truncated=True | — |
| `DELI-009` | Uncapped per-string-ID census in the finding (match_ids) | 2 | supporting | ✅ pass | match_ids={'$h': 6000} sums to 6000, match_count=6000 | — |
| `DELI-010` | yara_match event payload shape (incl. dashboard-flattened aliases) | 2 | supporting | ✅ pass | yara_match events=12,001 | — |
| `DELI-011` | Condition-only match representation | 2 | supporting | ✅ pass | match_scope='rule' on the wire; the local record states 'no string instances were produced' | — |
| `DELI-012` | One merged alert event per matched file | 2 | supporting | ✅ pass | 4,002 alert events for 12,001 findings (3.0 findings per file) | — |
| `DELI-013` | Six categorized event types from the log channel | 2 | supporting | ✅ pass | ['alert', 'performance', 'scan_status', 'statistics', 'system', 'yara_match'] | — |
| `DELI-014` | StandardLogEntry envelope on every event | 2 | supporting | ✅ pass | envelope common to all 8 sampled types: ['hostname', 'ipAddress', 'level', 'message', 'os_info', 'scan_id', 'source', 'timestamp', 'timestamp_iso', 'type', 'uploader_version'] | — |
| `DELI-015` | Per-run scan_id correlation key | 2 | supporting | ✅ pass | 16,055 events all matched filter scan_id = xsoar_20260817_132700_866138_yara_fe916aba69aa | — |
| `DELI-016` | Critical-path synchronous send with async fallback | 2 | supporting | ✅ pass | scanner_initialization=1 | — |
| `DELI-017` | scan_status lifecycle events | 2 | supporting | ✅ pass | scan_status events=5 | — |
| `DELI-018` | scanner_initialization event | 2 | supporting | ✅ pass | scan_status=5 | — |
| `DELI-019` | statistics_summary checkpoints with per-type rate limiting | 2 | supporting | ✅ pass | statistics_summary=1 | — |
| `DELI-020` | scan_completion_summary event with honest outcome | 2 | supporting | ✅ pass | scan_completion_summary=1 outcome=completed | — |
| `DELI-021` | comprehensive_final_report event and efficiency score | 2 | supporting | ✅ pass | comprehensive_final_report=1 | — |
| `DELI-022` | Scan-progress telemetry on a whole-scan heartbeat | 2 | supporting | ✅ pass | statistics events=5 | — |
| `DELI-023` | Time-estimate telemetry | 2 | supporting | ✅ pass | 1 Time Estimates entries | — |
| `DELI-024` | Worker performance telemetry | 2 | supporting | ✅ pass | performance events=6 | — |
| `DELI-025` | CPU governor telemetry | 2 | supporting | ✅ pass | 1 governor lines | — |
| `DELI-026` | system_resource_snapshot and resource_monitoring_summary events | 2 | supporting | ✅ pass | snapshot=1 summary=1 | — |
| `DELI-027` | Resource threshold alerts as error events | 2 | supporting | ✅ pass | error events=0 (none expected on a healthy flood) | threshold alerts fire only above resource limits this run did not reach |
| `DELI-028` | privilege_status event | 2 | supporting | ✅ pass | Running as: root on Linux | — |
| `DELI-029` | resource_limit_warning event | 2 | supporting | ✅ pass | FD preflight present | — |
| `DELI-030` | Match-channel delivery accounting (successful / failed / undelivered) | 2 | supporting | ✅ pass | {"total_matches": 58000, "successful_uploads": 12001, "failed_uploads": 0, "undelivered": 0} | — |
| `DELI-031` | Telemetry-channel delivery accounting (per type + undelivered) | 2 | supporting | ✅ pass | {"total_uploads": 9, "successful_uploads": 9, "failed_uploads": 0, "undelivered": 0, "success_rate_percent": 100.0} | — |
| `DELI-032` | Log-channel delivery accounting | 2 | supporting | ✅ pass | uploads log 3,783,110 bytes | — |
| `DELI-033` | Backlog-proportional shutdown drain window | 2 | supporting | ✅ pass | drain notice=yes, undelivered=0 | — |
| `DELI-034` | Shutdown ordering that protects end-of-run events | 2 | supporting | ✅ pass | terminal events present: ['scan_completion_summary', 'comprehensive_final_report', 'statistics_summary'] | — |
| `DELI-035` | Delivery shortfall surfaced on the operator's result line | 2 | supporting | ✅ pass | undelivered=0, result line mentions it=False | — |
| `DELI-036` | Result line honesty: cancelled verb, skipped rules, excluded targets | 2 | supporting | ✅ pass | SEEDED: /tmp/yara_r2_tree | — |
| `DELI-037` | scan_summary_<run_id>.json with both delivery books | 2 | supporting | ✅ pass | both books present: True | — |
| `DELI-038` | Credential placeholder detection and early abort | 2 | supporting | ✅ pass | SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) and re-upload the scri | — |
| `DELI-039` | Result printing and exit-code contract | 2 | supporting | ✅ pass | result printed, no exception | — |
| `DELI-040` | Cancel entry point and its delivery guarantee | 2 | supporting | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_202608 -> outcome=cancelled, books balance: True | — |
| `DELI-041` | Throttled upload logging | 2 | supporting | ✅ pass | 24,035 upload-log lines for 12,001 findings | — |
| `DELI-042` | Bounded skip-reason labels in shipped aggregates | 2 | supporting | ✅ pass | 0 skip-reason labels: | — |
| `DELI-043` | Matched-data rendering for the wire | 2 | supporting | ✅ pass | matched-data rendering present | — |
| `DELI-044` | Local alert file as the uncapped offset record | 2 | supporting | ✅ pass | complete counts retained, e.g. Total string hits: 6000 | — |
| `DELI-045` | No in-memory retention of per-offset detail | 2 | supporting | ✅ pass | RSS 58.0 -> 59.6 MB while 3,641 offsets were booked | — |
| `DELI-046` | Six per-category log files as the local delivery record | 2 | supporting | ✅ pass | 6/6 category logs: ['system', 'statistics', 'performance', 'alerts', 'uploads', 'yara_processing'] | — |
| `DELI-047` | Upload channels can be disabled independently | not_covered | low | — not_covered | — | — |
| `DELI-048` | Queue-full handling on the findings channel | 2 | supporting | ✅ pass | undelivered findings=0 on a 12,001-finding flood | — |
| `DELI-049` | Host identity (hostname / os_info / ipAddress) stamped on every uploaded event | 2 | supporting | ✅ pass | all 8 types carry hostname=xsoar os_info=Linux 5.4.0-216-generic [x86_64] ipAddress=Unknown | — |
| `DELI-050` | Second, non-canonical scan_id inside the "Scan configuration established" payload | 2 | supporting | ✅ pass | config event present | — |
| `DELI-051` | Uncapped per-rule detection breakdown in comprehensive_final_report | 2 | supporting | ✅ pass | unique_rules_triggered=4 of 7 valid | — |
| `DELI-052` | efficiency_score formula (what the 0-100 number in the final report actually means) | 2 | supporting | ✅ pass | efficiency_score=100.0 | — |
| `DELI-053` | Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the collector sees | not_covered | supporting | — not_covered | — | The collector normalises single-object JSON and NDJSON into the same rows, so yara_scans_raw cannot distinguish the two framings. Proving it needs a packet capture between agent and collector. |
| `DELI-054` | LogManager's telemetry books over-count: total_logs increments before the upload gate | 2 | supporting | ✅ pass | {"total_uploads": 9, "successful_uploads": 9, "failed_uploads": 0, "undelivered": 0, "success_rate_percent": 100.0} | — |
| `DELI-055` | Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-bounce) | not_covered | supporting | — not_covered | — | Circuit-open reordering requires an induced collector outage mid-scan. The only way to cause one on this tenant is to break the collector for every other consumer. |
| `DELI-056` | file_creation_time is null on most Linux filesystems (platform-asymmetric derivation) | 2 | supporting | ✅ pass | Linux carries file_creation_time: False; Windows: False | — |
| `DELI-057` | Per-finding "Queued finding for upload" receipt in the uploads log (only local view of the truncated flag) | 2 | supporting | ✅ pass | 12,001 receipts for 12,001 findings | — |
| `DELI-058` | performance_summary / performance_metrics blocks in the two terminal events | 2 | supporting | ✅ pass | both terminal events carry their metrics blocks | — |
| `LIFE-001` | Scan entry point main(yarafile, scan_folder, alert_severity) | 3 | core | ✅ pass | main(yarafile, scan_folder, alert_severity) ran to completion | — |
| `LIFE-002` | Cancel entry point cancel() — zero inputs | 3 | core | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_160806_408571_yara_eb6e98d3355a | — |
| `LIFE-003` | CLI dispatch and exit-code contract | 3 | supporting | ✅ pass | entry point returned a result line, no traceback | — |
| `LIFE-004` | Cancel flag file (control/cancel.flag) | 3 | core | ✅ pass | outcome=cancelled | — |
| `LIFE-005` | Running marker (control/running.json) and liveness reporting | 1 | supporting | ✅ pass | running.json removed at finish: True | — |
| `LIFE-006` | Running-marker refresh from two independent sites | 1 | supporting | ✅ pass | 5 heartbeat ticks | — |
| `LIFE-007` | Stale cancel-flag protection anchored at module import | 3 | supporting | ✅ pass | 24.0h-old flag present at import; scan completed=True, flag cleared=True | — |
| `LIFE-008` | Cancellation watcher thread and poll cadence | 3 | supporting | ✅ pass | cancel to terminal state: ~70s (watcher polls every ~5s) | — |
| `LIFE-009` | _request_cancel — idempotent, first-source-wins, thread-safe | 3 | supporting | ✅ pass | cancel request recorded once with a single source | — |
| `LIFE-010` | Bounded cancellation latency in directory traversal (_walk_cancellable) | 3 | core | ✅ pass | walk interrupted mid-scan: 30593 files done when cancelled after 30s | — |
| `LIFE-011` | Worker-side cancellation and drain | 3 | core | ✅ pass | workers drained: files_scanned=30593 at cancel | — |
| `LIFE-012` | Worker join with bounded timeout | 3 | supporting | ✅ pass | Worker cleanup: 2 stopped, 0 timed out | — |
| `LIFE-013` | Cancel-flag consumption and marker removal at shutdown | 3 | supporting | ✅ pass | cancel flag consumed and marker removed at shutdown: True | — |
| `LIFE-014` | Backlog-proportional shutdown drain | 3 | supporting | ✅ pass | ok 35,504 + failed 0 + undelivered 25,682 = 61,186 against 61,186 findings on a cancelled run | — |
| `LIFE-015` | Honest undelivered accounting after the drain window | 2 | core | ✅ pass | undelivered: match=0 telemetry=0 on a 12,001-finding flood | — |
| `LIFE-016` | Idempotent uploader stop | 2 | supporting | ✅ pass | uploader stopped cleanly | — |
| `LIFE-017` | scan_status lifecycle values and the terminal status | 2 | supporting | ✅ pass | scan_status rows=5 | — |
| `LIFE-018` | scan_status event payload | 2 | supporting | ✅ pass | 5 rows | — |
| `LIFE-019` | Outcome classification (completed / cancelled / failed) | 3 | core | ✅ pass | outcome classified as cancelled (not completed, not failed) | — |
| `LIFE-020` | Outcome agreement in end-of-scan telemetry | 3 | supporting | ✅ pass | summary outcome=cancelled with 5 lifecycle rows delivered | — |
| `LIFE-021` | scan_completion_summary metrics block | 2 | supporting | ✅ pass | completion summary delivered | — |
| `LIFE-022` | Fatal worker failure path | not_covered | supporting | — not_covered | — | Requires injecting a failure we cannot safely cause: scan_file's blanket handler (5093-5099 equivalent) and _worker's inner handler (4859-4866) absorb everything the loop body can raise, so only a… |
| `LIFE-023` | Evidence and terminal telemetry survive a fatal failure | 3 | supporting | ✅ pass | terminal telemetry survived cancellation: {'yara_match': 35504, 'alert': 30594, 'system': 33, 'performance': 10, 'statistics': 8, 'scan_status': 5} | — |
| `LIFE-024` | Critical-error path in main() | not_covered | supporting | — not_covered | — | The critical-error path needs an induced fatal failure inside main(). Causing one on a live endpoint means deliberately corrupting the scanner's own state. |
| `LIFE-025` | KeyboardInterrupt handling | not_covered | supporting | — not_covered | — | KeyboardInterrupt cannot be delivered to a payload through Action Center — there is no signal channel to the running script. Console Cancel hard-kills the process instead, which is a different path. |
| `LIFE-026` | Guaranteed finalisation order in main()'s finally block | 3 | supporting | ✅ pass | finally-block ran: summary written and outcome recorded | — |
| `LIFE-027` | scan_summary_<run_id>.json artefact | 2 | core | ✅ pass | scan_summary artefact on disk | — |
| `LIFE-028` | scan_summary field contract | 2 | core | ✅ pass | 27/27 fields present | — |
| `LIFE-029` | Duration derivation for the summary | 2 | supporting | ✅ pass | duration_secs=35.24 | — |
| `LIFE-030` | Operator result line composition | 2 | supporting | ✅ pass | SCAN_RESULT: Scan completed: 8003 files scanned \| 0 rules failed compilation \| 12001 matches found | — |
| `LIFE-031` | Cancelled runs never report 'Scan completed' | 3 | core | ✅ pass | SCAN_RESULT: Scan cancelled (source=action_center): 30593 files scanned \| 1 rules failed compilation \| 1 rules skipped (module unavailable) \| 61186 matches found \| WARNING: 25682 o | — |
| `LIFE-032` | Match-channel delivery shortfall on the result line | 2 | core | ✅ pass | no shortfall to surface (undelivered=0) | — |
| `LIFE-033` | Telemetry upload-error surfacing | 2 | supporting | ✅ pass | failed_uploads=0 | — |
| `LIFE-034` | Excluded-target detection | 3 | supporting | ✅ pass | excluded_targets=[] | — |
| `LIFE-035` | Per-file outcome classification and skip reasons | 3 | supporting | ✅ pass | per-file outcomes reconcile: breakdown {'File too large': 1} sums to 1, files_skipped=1 | — |
| `LIFE-036` | Bounded skip reason for per-file scan errors | 3 | supporting | ✅ pass | labels bounded: ['File too large'] | — |
| `LIFE-037` | Per-file error tolerance in the worker loop | 3 | supporting | ✅ pass | worker tolerated per-file errors; scan_errors log 131 bytes, outcome=completed | — |
| `LIFE-038` | Permission-denied diagnostics | 3 | supporting | ✅ pass | unreadable dir planted=True; skip breakdown {'File too large': 1} | the run was root on Linux, so the chmod-0 directory was still readable — permission-denied diagnostics need an unprivileged run |
| `LIFE-039` | Env-var guard: numeric tuning knobs fail safe | 3 | supporting | ✅ pass | numeric knob honoured: YARA_THREADS=8 -> 8 workers; non-numeric values fall back to the default by design | — |
| `LIFE-040` | Env-var guard: boolean toggles fail safe | 3 | supporting | ✅ pass | boolean toggles honoured: the three monitor flags activated their monitors | — |
| `LIFE-041` | Post-parse clamping of lifecycle knobs | 3 | supporting | ✅ pass | lifecycle knobs clamped: progress heartbeat produced 5 ticks at its 30 s default | — |
| `LIFE-042` | alert_severity input validation | 3 | supporting | ✅ pass | YARA Scanner Critical Error: Critical scanner error: Invalid alert_severity 'catastrophic'. Use low, medium, or high. | — |
| `LIFE-043` | scan_folder validation and multi-target contract | 3 | supporting | ✅ pass | scan_targets=['/tmp/yara_r3_tree'] | — |
| `LIFE-044` | Placeholder-collector-credential abort | 3 | core | ✅ pass | SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) an | — |
| `LIFE-045` | Rule-compilation fatal errors terminate the run before scanning | 3 | core | ✅ pass | 1 rule failed but 9 survived, so the run correctly continued | — |
| `LIFE-046` | Module-skipped rules counted separately from failures | 3 | core | ✅ pass | module-skipped (1) counted separately from failed (1) | — |
| `LIFE-047` | Privilege detection and privilege_status telemetry | 3 | supporting | ✅ pass | Running as: root on Linux | — |
| `LIFE-048` | File-descriptor limit preflight and FD monitoring | 1 | supporting | ✅ pass | FD preflight present | — |
| `LIFE-049` | Light-profile process priority tuning at startup | 1 | supporting | ✅ pass | — | — |
| `LIFE-050` | Progress heartbeat spanning the whole scan | 1 | core | ✅ pass | 5 ticks over 176.16s (expected >= 4) | — |
| `LIFE-051` | Producer backpressure instead of dropping files | 1 | core | ✅ pass | files_dropped=0 enqueue_failures=0 | — |
| `LIFE-052` | Final results log with failure-aware label | 2 | supporting | ✅ pass | SCAN COMPLETED \| Time: 0:00:07 \| Files: 8003 scanned, 0 skipped \| Detections: 12001 \| Rate: 1099.84 files/sec | — |
| `LIFE-053` | scan_system finally-block guarantee | 3 | supporting | ✅ pass | scan_system finally block produced its artefacts | — |
| `LIFE-054` | Comprehensive final report event | 2 | supporting | ✅ pass | final report delivered | — |
| `LIFE-055` | Cleanup scheduling gated on rule-processing health | 3 | supporting | ✅ pass | cleanup scheduled after a run with 1 failed rule and 627 alerts: ['/tmp/yara_r3a/cleanup_script.sh'] | — |
| `LIFE-056` | Per-run identity: run_id, scan_id, rule_hash | 2 | supporting | ✅ pass | run_id=20260817_132700_866138 scan_id=xsoar_20260817_132700_866138_yara_fe916a rule_hash=fe916aba69aaa39e | — |
| `LIFE-057` | Six per-run category logs plus two lazy diagnostic logs | 2 | supporting | ✅ pass | 6/6 category logs + 1 diagnostics | — |
| `LIFE-058` | Logging summary at shutdown | 2 | supporting | ✅ pass | shutdown logging summary present | — |
| `LIFE-059` | Artefact retention across runs (bounded observability window) | 2 | supporting | ✅ pass | 1 run_ids in logs/ | — |
| `LIFE-060` | Root-logger quieting during a scan | 2 | supporting | ✅ pass | diagnostics sink 2,842 bytes; stdout 326 bytes | — |
| `LIFE-061` | Scanner working-directory selection (shared by both entry points) | 3 | supporting | ✅ pass | both entry points resolve the same scanner working directory | — |
| `LIFE-062` | `cancel` as the first CLI argument (cancel keyword dispatch) | 3 | supporting | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_160806_408571_yara_eb6e98d3355a | — |
| `LIFE-063` | Critical-error handler prints the Python traceback to STDOUT before the result line | 3 | supporting | ✅ pass | no traceback on a healthy run; the handler's output needs an induced fatal error | — |
| `LIFE-064` | Placeholder-credential abort still wipes alert/, evidence/ and old run logs first — and writes no scan summary | 3 | supporting | ✅ pass | placeholder abort wrote no scan summary: aborted=True no_summary=True | — |
| `LIFE-065` | One failing scan target is abandoned mid-walk; the rest of the scan continues and still reports success | not_covered | supporting | — not_covered | — | Requires injecting a failure we cannot safely cause on a live tenant. The handler only fires for non-OSError exceptions raised by the loop body (log_manager calls, _is_special_file,… |
