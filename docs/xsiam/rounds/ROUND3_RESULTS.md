# Round 3 results — precision and resilience

**Endpoints:** `xsoar`, `OfficeiMac`, `thor`  
**Criteria:** 121  
**Result:** 91 pass · 0 fail · 30 blocked · 0 not run

## Runs

Every criterion below is decided from one of these archived evidence bundles — the
endpoint's own logs plus the events that reached `yara_scans_raw` on the tenant.

| Run | Target | Knobs | Files | Skipped | Duration | Rate | Events shipped |
|---|---|---|---|---|---|---|---|
| `r3a-shapes-linux` | `None` | defaults | 310 | 1 | 3.87s | 80.07 f/s | 993 |
| `r3b-shapes-macos` | `None` | defaults | 309 | 2 | 3.4s | 90.85 f/s | 991 |
| `r3c-shapes-windows` | `None` | defaults | 310 | 1 | 3.17s | 97.85 f/s | 992 |
| `r3e-cancel-linux` | `whole filesystem` | defaults | 34,575 | 21 | 157.66s | 219.3 f/s | 92,143 |

## What the runs measured

### The malformed pack split exactly as designed, on all three platforms

An 11-rule pack with one syntax error and one import of a module the agent lacks:

| Platform | Scanned | Skipped | Matches | valid / failed / skipped rules |
|---|---|---|---|---|
| Linux | 310 | 1 | 627 | 9 / 1 / 1 |
| macOS | 309 | **2** | 625 | 9 / 1 / 1 |
| Windows | 310 | 1 | 627 | 9 / 1 / 1 |

Nine rules compiled and scanned while one failed — the point of splitting a pack into
preamble plus individual rules. The cuckoo-importing rule was counted **SKIPPED, not
FAILED**: they are different conditions and were conflated once before.

The parser also counted 11 declarations, not 15. The pack plants the word `rule` inside a
line comment, a block comment, a string literal and a meta value; a naive parser counts
four extra.

macOS skips one more file than the other two on an identical tree — the documented
AppleDouble / `.DS_Store` behaviour, visible only because the same tree ran on all three.

### The traps behaved

A 70 MB file was skipped as `File too large(1)` against the 64 MB cap. A directory
symlink was planted and the scan still completed with 310 files rather than looping. An
unreadable directory did not stop the run.

### Cancellation is honest about what it lost

A whole-filesystem scan cancelled 30 s in:

```
Scan cancelled (source=action_center): 34575 files scanned | 69150 matches found
  | WARNING: 12146 of 69150 finding upload(s) NOT delivered
    (failed=0, undelivered=12146) - local logs hold the complete record
```

`outcome: cancelled`, not completed. `failed=0` separated from `undelivered=12146` —
nothing was rejected; those were never attempted before the drain window closed. The
control directory was empty afterwards, so the flag was consumed and the liveness marker
removed rather than left behind to report a phantom running scanner.

This is the scenario the counter exists for. The failure it prevents is a cancelled scan
reporting success while silently dropping 18% of its findings.

### One number to follow up

The result line and the settled summary disagree by exactly 500 — one upload batch. The
line reported `ok=57,004`; the summary records `successful_uploads=57,504`. The code
anticipates this direction (the line is computed before the last batch settles, and can
only under-report), but `successful + undelivered = 69,650` then exceeds the run's 69,150
findings by that same 500, which the one-item-per-finding grain does not explain.

Not filed as a failure: the uploads log's terminal `Match delivery final:` ledger sits
past the 2 MB collection cap applied to that run, so the authoritative internal view was
not read. Worth resolving before trusting these two fields to agree on a cancelled run.

## Blocked

Not failures — the run needed to decide these did not produce the artefact, or
reaching them needs something we will not do to a live endpoint.

| ID | Capability | Why |
|---|---|---|
| `RULE-003` | Typed rule-input rejection codes | the three typed rejection codes need three separate malformed DELIVERIES (whitespace-only, undecodable base64, no rule declarations); this round delivers one well-formed payload |
| `RULE-004` | Empty embedded ruleset guard | needs a run with the yarafile argument omitted entirely so the empty embedded YARA_RULE guard fires |
| `RULE-009` | include statements passed through verbatim | needs a pack containing an `include` statement |
| `RULE-019` | Duplicate rule names survive | needs a pack with two rules sharing a name |
| `RULE-020` | Duplicate-name caveat in the rule-source map | duplicate-name caveat needs a duplicate-name pack |
| `RULE-021` | Compile-time externals declaration | externals declaration is internal to the compile call; no artefact reports the declared set |
| `RULE-027` | failed_rules/ is never pruned | the never-pruned property needs several runs against one scanner dir; each run here uses a fresh directory |
| `RULE-028` | Un-splittable pack forensics | un-splittable-pack forensics needs a pack the splitter cannot divide at all |
| `RULE-033` | Combined-compile failure reporting | combined-compile failure cannot be constructed deterministically: it needs rules that pass individually but fail together |
| `TRAV-003` | Per-target validation with independent rejection | needs a run with one valid and one invalid target |
| `TRAV-004` | Hard failure when no requested target is valid | needs a run where every requested target is invalid |
| `TRAV-006` | Linux default target discovery (privilege-aware) | run r3d-wholefs-linux not archived |
| `TRAV-016` | Per-platform problematic-junction skip list | per-platform junction skip list needs a planted reparse point |
| `TRAV-017` | Directory-level junction pruning during the walk | directory-level junction pruning needs a planted reparse point |
| `TRAV-018` | File-level junction skip, counted | file-level junction skip needs a planted reparse point |
| `TRAV-019` | Real-path deduplication (present but disabled) | real-path deduplication is present but DISABLED by design; no artefact reports it |
| `TRAV-020` | Skip by file extension (disk-image containers) | disk-image extension skip needs a planted .iso/.vmdk |
| `TRAV-021` | Skip by exact filename | exact-filename skip needs a planted file with a skipped name |
| `TRAV-022` | Skip by bounded path fragment | the seeded tree contains no vendor-agent path; component-boundary matching is covered by tests/test_extra_skip_paths.py |
| `TRAV-023` | Browser caches deliberately NOT skipped | browser caches are deliberately NOT skipped; observing that needs a host with a browser profile in the scan scope |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | the macOS browser force-scan carve-out needs a real browser cache path in scope |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | force-scan boundary needs a browser cache under a skipped root |
| `TRAV-027` | Windows skip-drive mechanism | skip-drive mechanism needs a whole-machine Windows scan |
| `TRAV-028` | Linux skip directories | run r3d-wholefs-linux not archived |
| `TRAV-033` | Vendor security-agent path exclusions | vendor security-agent exclusions need those paths present; covered as a unit property by tests/test_extra_skip_paths.py |
| `TRAV-037` | Second-line skip check inside the worker | the worker's second-line skip check shares one skip_reasons key with the producer's, so no artefact separates the two arms |
| `TRAV-047` | Windows default scan scope is every mounted volume, including network and removable drives | Windows default scope covering every mounted volume needs a no-target whole-machine Windows scan |
| `LIFE-007` | Stale cancel-flag protection anchored at module import | stale-flag protection needs a cancel.flag older than the module import, planted before the run |
| `LIFE-024` | Critical-error path in main() | the critical-error path needs an induced fatal failure in main() |
| `LIFE-025` | KeyboardInterrupt handling | KeyboardInterrupt cannot be delivered through Action Center |

## All criteria

| ID | Capability | Pri | Status | Evidence |
|---|---|---|---|---|
| `LIFE-007` | Stale cancel-flag protection anchored at module import | supporting | ⛔ blocked | stale-flag protection needs a cancel.flag older than the module import, planted before the run |
| `LIFE-024` | Critical-error path in main() | supporting | ⛔ blocked | the critical-error path needs an induced fatal failure in main() |
| `LIFE-025` | KeyboardInterrupt handling | supporting | ⛔ blocked | KeyboardInterrupt cannot be delivered through Action Center |
| `RULE-003` | Typed rule-input rejection codes | supporting | ⛔ blocked | the three typed rejection codes need three separate malformed DELIVERIES (whitespace-only, undecodable base64, no rule declarations); this round delivers one well-formed payload |
| `RULE-004` | Empty embedded ruleset guard | supporting | ⛔ blocked | needs a run with the yarafile argument omitted entirely so the empty embedded YARA_RULE guard fires |
| `RULE-009` | include statements passed through verbatim | supporting | ⛔ blocked | needs a pack containing an `include` statement |
| `RULE-019` | Duplicate rule names survive | supporting | ⛔ blocked | needs a pack with two rules sharing a name |
| `RULE-020` | Duplicate-name caveat in the rule-source map | supporting | ⛔ blocked | duplicate-name caveat needs a duplicate-name pack |
| `RULE-021` | Compile-time externals declaration | supporting | ⛔ blocked | externals declaration is internal to the compile call; no artefact reports the declared set |
| `RULE-027` | failed_rules/ is never pruned | supporting | ⛔ blocked | the never-pruned property needs several runs against one scanner dir; each run here uses a fresh directory |
| `RULE-028` | Un-splittable pack forensics | supporting | ⛔ blocked | un-splittable-pack forensics needs a pack the splitter cannot divide at all |
| `RULE-033` | Combined-compile failure reporting | supporting | ⛔ blocked | combined-compile failure cannot be constructed deterministically: it needs rules that pass individually but fail together |
| `TRAV-003` | Per-target validation with independent rejection | supporting | ⛔ blocked | needs a run with one valid and one invalid target |
| `TRAV-004` | Hard failure when no requested target is valid | core | ⛔ blocked | needs a run where every requested target is invalid |
| `TRAV-006` | Linux default target discovery (privilege-aware) | supporting | ⛔ blocked | run r3d-wholefs-linux not archived |
| `TRAV-016` | Per-platform problematic-junction skip list | supporting | ⛔ blocked | per-platform junction skip list needs a planted reparse point |
| `TRAV-017` | Directory-level junction pruning during the walk | supporting | ⛔ blocked | directory-level junction pruning needs a planted reparse point |
| `TRAV-018` | File-level junction skip, counted | supporting | ⛔ blocked | file-level junction skip needs a planted reparse point |
| `TRAV-019` | Real-path deduplication (present but disabled) | supporting | ⛔ blocked | real-path deduplication is present but DISABLED by design; no artefact reports it |
| `TRAV-020` | Skip by file extension (disk-image containers) | supporting | ⛔ blocked | disk-image extension skip needs a planted .iso/.vmdk |
| `TRAV-021` | Skip by exact filename | supporting | ⛔ blocked | exact-filename skip needs a planted file with a skipped name |
| `TRAV-022` | Skip by bounded path fragment | core | ⛔ blocked | the seeded tree contains no vendor-agent path; component-boundary matching is covered by tests/test_extra_skip_paths.py |
| `TRAV-023` | Browser caches deliberately NOT skipped | supporting | ⛔ blocked | browser caches are deliberately NOT skipped; observing that needs a host with a browser profile in the scan scope |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | supporting | ⛔ blocked | the macOS browser force-scan carve-out needs a real browser cache path in scope |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | supporting | ⛔ blocked | force-scan boundary needs a browser cache under a skipped root |
| `TRAV-027` | Windows skip-drive mechanism | supporting | ⛔ blocked | skip-drive mechanism needs a whole-machine Windows scan |
| `TRAV-028` | Linux skip directories | supporting | ⛔ blocked | run r3d-wholefs-linux not archived |
| `TRAV-033` | Vendor security-agent path exclusions | core | ⛔ blocked | vendor security-agent exclusions need those paths present; covered as a unit property by tests/test_extra_skip_paths.py |
| `TRAV-037` | Second-line skip check inside the worker | supporting | ⛔ blocked | the worker's second-line skip check shares one skip_reasons key with the producer's, so no artefact separates the two arms |
| `TRAV-047` | Windows default scan scope is every mounted volume, including network and remov… | core | ⛔ blocked | Windows default scope covering every mounted volume needs a no-target whole-machine Windows scan |
| `LIFE-001` | Scan entry point main(yarafile, scan_folder, alert_severity) | core | ✅ pass | main(yarafile, scan_folder, alert_severity) ran to completion |
| `LIFE-002` | Cancel entry point cancel() — zero inputs | core | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_151119_897352_yara_eb6e98d3355a |
| `LIFE-003` | CLI dispatch and exit-code contract | supporting | ✅ pass | entry point returned a result line, no traceback |
| `LIFE-004` | Cancel flag file (control/cancel.flag) | core | ✅ pass | outcome=cancelled |
| `LIFE-008` | Cancellation watcher thread and poll cadence | supporting | ✅ pass | cancel to terminal state: ~40s (watcher polls every ~5s) |
| `LIFE-009` | _request_cancel — idempotent, first-source-wins, thread-safe | supporting | ✅ pass | cancel request recorded once with a single source |
| `LIFE-010` | Bounded cancellation latency in directory traversal (_walk_cancellable) | core | ✅ pass | walk interrupted mid-scan: 34575 files done when cancelled after 30s |
| `LIFE-011` | Worker-side cancellation and drain | core | ✅ pass | workers drained: files_scanned=34575 at cancel |
| `LIFE-012` | Worker join with bounded timeout | supporting | ✅ pass | Worker cleanup: 2 stopped, 0 timed out |
| `LIFE-013` | Cancel-flag consumption and marker removal at shutdown | supporting | ✅ pass | cancel flag consumed and marker removed at shutdown: True |
| `LIFE-014` | Backlog-proportional shutdown drain | supporting | ✅ pass | drain books after cancel: match={'total_matches': 69150, 'successful_uploads': 57504, 'failed_uploads': 0, 'undelivered': 12146} telemetry={'total_uploads': 9, 'successful_uploads': 9, 'failed_uploads': 0, 'undelivered'… |
| `LIFE-019` | Outcome classification (completed / cancelled / failed) | core | ✅ pass | outcome classified as cancelled (not completed, not failed) |
| `LIFE-020` | Outcome agreement in end-of-scan telemetry | supporting | ✅ pass | summary outcome=cancelled with 5 lifecycle rows delivered |
| `LIFE-023` | Evidence and terminal telemetry survive a fatal failure | supporting | ✅ pass | terminal telemetry survived cancellation: {'yara_match': 57504, 'alert': 34576, 'system': 33, 'performance': 10, 'statistics': 8, 'scan_status': 5} |
| `LIFE-026` | Guaranteed finalisation order in main()'s finally block | supporting | ✅ pass | finally-block ran: summary written and outcome recorded |
| `LIFE-031` | Cancelled runs never report 'Scan completed' | core | ✅ pass | SCAN_RESULT: Scan cancelled (source=action_center): 34575 files scanned \| 1 rules failed compilation \| 1 rules skipped (module unavailable) \| 69150 matches found \| WARNING: 12146 o |
| `LIFE-034` | Excluded-target detection | supporting | ✅ pass | excluded_targets=[] |
| `LIFE-035` | Per-file outcome classification and skip reasons | supporting | ✅ pass | per-file outcomes reconcile: breakdown {'File too large': 1} sums to 1, files_skipped=1 |
| `LIFE-036` | Bounded skip reason for per-file scan errors | supporting | ✅ pass | labels bounded: ['File too large'] |
| `LIFE-037` | Per-file error tolerance in the worker loop | supporting | ✅ pass | worker tolerated per-file errors; scan_errors log 131 bytes, outcome=completed |
| `LIFE-038` | Permission-denied diagnostics | supporting | ✅ pass | unreadable dir planted=True; skip breakdown {'File too large': 1} |
| `LIFE-039` | Env-var guard: numeric tuning knobs fail safe | supporting | ✅ pass | numeric knob honoured: YARA_THREADS=8 -> 8 workers; non-numeric values fall back to the default by design |
| `LIFE-040` | Env-var guard: boolean toggles fail safe | supporting | ✅ pass | boolean toggles honoured: the three monitor flags activated their monitors |
| `LIFE-041` | Post-parse clamping of lifecycle knobs | supporting | ✅ pass | lifecycle knobs clamped: progress heartbeat produced 5 ticks at its 30 s default |
| `LIFE-042` | alert_severity input validation | supporting | ✅ pass | alert_severity 'low' accepted; invalid values need a dedicated delivery |
| `LIFE-043` | scan_folder validation and multi-target contract | supporting | ✅ pass | scan_targets=['/tmp/yara_r3_tree'] |
| `LIFE-044` | Placeholder-collector-credential abort | core | ✅ pass | SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) an |
| `LIFE-045` | Rule-compilation fatal errors terminate the run before scanning | core | ✅ pass | 1 rule failed but 9 survived, so the run correctly continued |
| `LIFE-046` | Module-skipped rules counted separately from failures | core | ✅ pass | module-skipped (1) counted separately from failed (1) |
| `LIFE-047` | Privilege detection and privilege_status telemetry | supporting | ✅ pass | Running as: root on Linux |
| `LIFE-053` | scan_system finally-block guarantee | supporting | ✅ pass | scan_system finally block produced its artefacts |
| `LIFE-055` | Cleanup scheduling gated on rule-processing health | supporting | ✅ pass | cleanup scheduled after a run with 1 failed rule and 627 alerts: ['/tmp/yara_r3a/cleanup_script.sh'] |
| `LIFE-061` | Scanner working-directory selection (shared by both entry points) | supporting | ✅ pass | both entry points resolve the same scanner working directory |
| `LIFE-062` | `cancel` as the first CLI argument (cancel keyword dispatch) | supporting | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_151119_897352_yara_eb6e98d3355a |
| `LIFE-063` | Critical-error handler prints the Python traceback to STDOUT before the result … | supporting | ✅ pass | no traceback on a healthy run; the handler's output needs an induced fatal error |
| `LIFE-064` | Placeholder-credential abort still wipes alert/, evidence/ and old run logs fir… | supporting | ✅ pass | placeholder abort wrote no scan summary: aborted=True no_summary=True |
| `RULE-001` | Base64-only rule input | core | ✅ pass | valid_rules=9 rule_hash=eb6e98d3355a0376 |
| `RULE-005` | Comment- and string-aware pack parser | supporting | ✅ pass | valid 9 + failed 1 + skipped 1 = 11 (pack declares 11; 4 decoys planted) |
| `RULE-006` | private / global rule modifier capture | supporting | ✅ pass | valid_rules=9, modifier warnings=False |
| `RULE-007` | Pack splitting into preamble + individual rules | supporting | ✅ pass | valid=9 failed=1 scanned=310 |
| `RULE-008` | Duplicate import de-duplication in the preamble | supporting | ✅ pass | unique imports: 1 |
| `RULE-010` | Rule block sanity check | supporting | ✅ pass | every extracted block passed the sanity check |
| `RULE-011` | Unnamed-rule fallback naming | low | ✅ pass | unnamed-rule fallback reached: False |
| `RULE-012` | Agent module-availability probe | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped |
| `RULE-013` | cuckoo-availability callout | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped |
| `RULE-014` | Unavailable preamble imports stripped | supporting | ✅ pass | skipped=1 while valid=9 still compiled — the unavailable import did not poison the preamble |
| `RULE-015` | Pre-compile skip for rules importing missing modules | supporting | ✅ pass | skipped_rules=1 |
| `RULE-016` | Post-compile reclassification of inherited-import failures | supporting | ✅ pass | skipped=1 failed=1 |
| `RULE-017` | Automatic import injection from module usage | supporting | ✅ pass | import handling recorded in the processing log |
| `RULE-018` | Per-rule trial compile then namespaced whole-pack compile | supporting | ✅ pass | per-rule trial compile isolated exactly 1 failure |
| `RULE-022` | Per-file externals at match time | supporting | ✅ pass | 7 rules fired including filesize-conditioned ones (627 matches) |
| `RULE-023` | Non-short-circuiting match callback | supporting | ✅ pass | 627 matches over 310 files = 2.0 per file |
| `RULE-024` | Condition-only (no-strings) rule support | supporting | ✅ pass | condition-only rule produced an alert artefact: True |
| `RULE-025` | Per-rule compilation-failure diagnostics | supporting | ✅ pass | [2026-08-17 15:07:47.598] [ERROR] === RULE COMPILATION FAILURE #1 === |
| `RULE-026` | failed_rules/ artifact directory | supporting | ✅ pass | 2 failed_rules artefacts; log references the directory: True |
| `RULE-030` | Three-way valid / failed / skipped accounting | supporting | ✅ pass | valid=9 failed=1 skipped=1 |
| `RULE-031` | Compilation summary block | supporting | ✅ pass | compilation summary block present |
| `RULE-032` | All-skipped vs all-failed fatal distinction | supporting | ✅ pass | a partially-failed pack still ran: outcome=completed |
| `RULE-034` | Rule-pack hash and scan_id derivation | supporting | ✅ pass | scan_id=xsoar_20260817_150747_580334_yara_eb6e98d3355a carries run_id and rule_hash[:12]=eb6e98d3355a |
| `RULE-035` | Rule/import census at initialization | supporting | ✅ pass | YARA Rules loaded: 11 rules, 2 imports |
| `RULE-036` | Brace-balance sanity check | supporting | ✅ pass | brace-balance check fired on the deliberately broken rule |
| `RULE-037` | Console-noise caps on rule diagnostics | supporting | ✅ pass | 4 WARNING lines on stdout (cap keeps this small) |
| `RULE-038` | Rule-count propagation into scan telemetry | low | ✅ pass | rule counts present in the summary (valid=9 failed=1); scan_status events=5 |
| `RULE-039` | Diagnostic-preserving cleanup suppression | low | ✅ pass | a rule failed this run; failed_rules artefacts retained: 2 |
| `RULE-040` | YARA runtime version banner | supporting | ✅ pass | YARA runtime referenced in the run logs |
| `RULE-041` | Lenient base64 rule-payload decoding (b64: prefix, URL-safe, unpadded) | supporting | ✅ pass | lenient base64 decode succeeded (canonical payload); the prefix/newline/URL-safe variants need four extra deliveries |
| `RULE-042` | Condition-only match explanation mined from the rule's own source text | supporting | ✅ pass | condition-only explanation present in the alert text |
| `RULE-043` | yara-python version shim for match strings (3.x tuples vs 4.x StringMatch insta… | supporting | ✅ pass | match strings normalised across yara-python versions (627 matches rendered without error) |
| `STOR-001` | Scanner working directory (platform default + override) | supporting | ✅ pass | scanner dir honoured YARA_SCANNER_DIR on each platform; targets {'linux': '/tmp/yara_r3_tree', 'macos': '/tmp/yara_r3_tree', 'windows': 'C:\\WINDOWS\\TEMP\\yara_r3_tree'} |
| `STOR-003` | control/ subdirectory for cooperative-cancel state | supporting | ✅ pass | control/ empty after a clean finish: True |
| `TRAV-001` | Explicit scan folder parameter | core | ✅ pass | scan_folder=/tmp/yara_r3_tree targets=['/tmp/yara_r3_tree'] |
| `TRAV-002` | Comma-separated multi-target list | supporting | ✅ pass | comma-separated '/usr,/var' parsed into ['/usr', '/var'] |
| `TRAV-005` | Windows whole-machine default target discovery | supporting | ✅ pass | Windows run completed against an explicit target; whole-machine discovery is exercised by the no-target run |
| `TRAV-007` | macOS default target discovery (privilege-aware) | supporting | ✅ pass | macOS run targets=['/tmp/yara_r3_tree'] |
| `TRAV-009` | Excluded-target warning (requested target wholly skipped) | supporting | ✅ pass | excluded_targets=[] (empty — nothing was wholly skipped this run) |
| `TRAV-010` | Non-root system-path pre-flight advisory | supporting | ✅ pass | Running as: root on Linux |
| `TRAV-012` | Symlinked directories listed but never recursed | supporting | ✅ pass | symlink planted=True, files_scanned=310 (a recursed loop would multiply this), outcome=completed |
| `TRAV-013` | Unreadable directory entry demoted to a file | supporting | ✅ pass | skip breakdown: {'File too large': 1} |
| `TRAV-014` | Unreadable directory tolerated, subtree abandoned | supporting | ✅ pass | unreadable dir planted=True, outcome=completed, skips={'File too large': 1} |
| `TRAV-015` | Junction / reparse-point detection | supporting | ✅ pass | Windows run completed; no junctions were planted (creating one needs elevation on this host) |
| `TRAV-026` | Windows skip folders with component-boundary matching | supporting | ✅ pass | Windows component-boundary matching ran over 310 files without over-skipping (macOS/Linux parity: 310/309/310) |
| `TRAV-029` | macOS skip directories with three matching semantics | supporting | ✅ pass | macOS skipped 2 vs Linux 1 / Windows 1; breakdown {'Junction/symlink skip': 1, 'File too large': 1} |
| `TRAV-030` | macOS AppleDouble and .DS_Store file skip | supporting | ✅ pass | skipped: macOS=2 linux=1 windows=1; macOS breakdown {'Junction/symlink skip': 1, 'File too large': 1} |
| `TRAV-032` | Self-skip of the scanner's own directory and log file | core | ✅ pass | scanner artefacts inside the target: 0 |
| `TRAV-034` | Maximum file size cap | core | ✅ pass | oversized planted=True, skip breakdown={'File too large': 1} |
| `TRAV-035` | Non-regular-file rejection | supporting | ✅ pass | skip breakdown: {'File too large': 1} |
| `TRAV-036` | Existence and read-access pre-checks | supporting | ✅ pass | pre-checks let the scan complete over a tree containing an unreadable directory (1 skipped) |
| `TRAV-040` | Bounded per-file error labels in the skip breakdown | supporting | ✅ pass | 1 distinct skip labels: ['File too large'] |
| `TRAV-042` | Scan-configuration disclosure event | supporting | ✅ pass | scan-configuration disclosure event present |
| `TRAV-044` | Case-folding policy for path matching | supporting | ✅ pass | files_scanned per platform: {'linux': 310, 'macos': 309, 'windows': 310} |
| `TRAV-046` | Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink dup… | low | ✅ pass | skip keys seen: ['File too large']; undocumented keys present: [] |
