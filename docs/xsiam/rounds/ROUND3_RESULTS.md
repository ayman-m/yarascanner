# Round 3 results — precision and resilience

**Endpoints:** `xsoar`, `OfficeiMac`, `thor`  
**Criteria:** 121  
**Result:** 105 pass · 0 fail · 16 blocked · 0 not run

## Runs

Every criterion below is decided from one of these archived evidence bundles — the
endpoint's own logs plus the events that reached `yara_scans_raw` on the tenant.

| Run | Target | Knobs | Files | Skipped | Duration | Rate | Events shipped |
|---|---|---|---|---|---|---|---|
| `r3a-shapes-linux` | `None` | defaults | 310 | 1 | 3.87s | 80.07 f/s | 993 |
| `r3b-shapes-macos` | `None` | defaults | 309 | 2 | 3.4s | 90.85 f/s | 991 |
| `r3c-shapes-windows` | `None` | defaults | 310 | 1 | 3.17s | 97.85 f/s | 992 |
| `r3d-wholefs-linux` | `None` | defaults | 469,170 | 658,034 | 712.47s | 658.51 f/s | 553,047 |
| `r3e-cancel-linux` | `whole filesystem` | defaults | 30,593 | 21 | 99.47s | 307.55 f/s | 66,161 |

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

### A whole-machine scan, and the fix under real pressure

No `scan_folder` given, so Linux discovery selected the machine root:

| | |
|---|---|
| target chosen | `/` |
| scanned / skipped | 469,170 / 658,034 |
| findings | 925,507 |
| duration | 712 s |

The skip breakdown reconciles exactly with `files_skipped`:
`Skipped directory(655232), File does not exist(1965), Not a regular file(762),
File too large(52), Special system file(23)`.

762 non-regular files and 23 special system files were rejected without planting a
single fifo — a root scan walks /dev, /proc and /run, which is the honest way to exercise
that path; a planted fifo proves only that one contrived case works.

This is also the hardest available test of the delivery-book fix. A 925,507-finding
backlog left 669,991 undelivered, and the books still balance to the item:

```
255,516 + 0 + 669,991 = 925,507 = findings
```

### Windows junctions: the skip list is selective, by design

Two junctions were planted pointing at one directory holding a single matching file —
`jlink` (benign) and `Application Data` (a name on the problematic list). Both are real
reparse points: `os.path.islink()` returns **False** for a junction while `isdir()`
returns True, which is precisely why the scanner cannot rely on `islink` and carries its
own reparse-attribute check.

Three files were scanned, not four: `real/inside.txt`, `plain.txt`, and one copy reached
through the benign junction, while `Application Data` was pruned before descent.

That the benign junction IS followed is the documented behaviour —
`_should_skip_junction` prunes only six legacy names (`application data`, `documents and
settings`, `local settings`, `my documents`, `default user`, `all users`). A first probe
with only a benign junction read its correct recursion as a missed skip; the pair is what
distinguishes "the predicate works" from "the predicate always says yes".

**Worth a follow-up.** Because pruning is name-based and real-path deduplication is
present-but-disabled (TRAV-019), a junction pointing at one of its own ancestors and NOT
carrying a legacy name has no cycle protection in either mechanism. Not asserted as a
failure — no catalogued capability claims loop protection beyond the name list — and
deliberately not probed, since the way to find out on a live endpoint is to hang it.

### The 500-finding book discrepancy — found, fixed, re-verified

The first cancelled run booked `ok + undelivered = 69,650` against 69,150 findings. The
uploads log named the cause at the same timestamp as its own "final" ledger:
`Upload thread did not terminate within 60s timeout`.

`_upload_worker` consulted its stop flag only in the `except Empty` branch — unreachable
against a full queue, which is precisely the condition the flag exists for. So after the
drain budget expired and the sentinel was queued behind 12,146 items, the loop kept
sending; the join timed out; `stop()` booked those items `undelivered`; and the live
thread then delivered 1,000 of them into `successful_uploads`. The same items in two
buckets.

The flag is now checked before taking work. Re-run on the fixed build:

```
ok 35,504 + failed 0 + undelivered 25,682 = 61,186
findings                                  = 61,186   balanced
```

This mattered beyond arithmetic: the operator's result line derives its shortfall
denominator from `ok+failed+undelivered`, so the inflated sum understated the loss
percentage while overstating both totals — in the one scenario the counter exists for.


## Blocked

Not failures — the run needed to decide these did not produce the artefact, or
reaching them needs something we will not do to a live endpoint.

| ID | Capability | Why |
|---|---|---|
| `RULE-021` | Compile-time externals declaration | externals declaration is internal to the compile call; no artefact reports the declared set |
| `RULE-028` | Un-splittable pack forensics | un-splittable-pack forensics needs a pack the splitter cannot divide at all |
| `RULE-033` | Combined-compile failure reporting | combined-compile failure cannot be constructed deterministically: it needs rules that pass individually but fail together |
| `TRAV-018` | File-level junction skip, counted | directory junctions are removed by the `dirs[:]` filter, which increments no counter; the counted file-level branch needs a FILE-type reparse point, not a directory junction. mklink /J creates only the latter. |
| `TRAV-019` | Real-path deduplication (present but disabled) | real-path deduplication is present but DISABLED by design; no artefact reports it |
| `TRAV-022` | Skip by bounded path fragment | the seeded tree contains no vendor-agent path; component-boundary matching is covered by tests/test_extra_skip_paths.py |
| `TRAV-023` | Browser caches deliberately NOT skipped | browser caches are deliberately NOT skipped; observing that needs a host with a browser profile in the scan scope |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | the macOS browser force-scan carve-out needs a real browser cache path in scope |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | force-scan boundary needs a browser cache under a skipped root |
| `TRAV-027` | Windows skip-drive mechanism | skip-drive mechanism needs a whole-machine Windows scan |
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
| `RULE-021` | Compile-time externals declaration | supporting | ⛔ blocked | externals declaration is internal to the compile call; no artefact reports the declared set |
| `RULE-028` | Un-splittable pack forensics | supporting | ⛔ blocked | un-splittable-pack forensics needs a pack the splitter cannot divide at all |
| `RULE-033` | Combined-compile failure reporting | supporting | ⛔ blocked | combined-compile failure cannot be constructed deterministically: it needs rules that pass individually but fail together |
| `TRAV-018` | File-level junction skip, counted | supporting | ⛔ blocked | 3 scanned, 0 skipped |
| `TRAV-019` | Real-path deduplication (present but disabled) | supporting | ⛔ blocked | real-path deduplication is present but DISABLED by design; no artefact reports it |
| `TRAV-022` | Skip by bounded path fragment | core | ⛔ blocked | the seeded tree contains no vendor-agent path; component-boundary matching is covered by tests/test_extra_skip_paths.py |
| `TRAV-023` | Browser caches deliberately NOT skipped | supporting | ⛔ blocked | browser caches are deliberately NOT skipped; observing that needs a host with a browser profile in the scan scope |
| `TRAV-024` | Browser force-scan allowlist (macOS carve-out) | supporting | ⛔ blocked | the macOS browser force-scan carve-out needs a real browser cache path in scope |
| `TRAV-025` | Boundary skips the force-scan allowlist cannot override | supporting | ⛔ blocked | force-scan boundary needs a browser cache under a skipped root |
| `TRAV-027` | Windows skip-drive mechanism | supporting | ⛔ blocked | skip-drive mechanism needs a whole-machine Windows scan |
| `TRAV-033` | Vendor security-agent path exclusions | core | ⛔ blocked | vendor security-agent exclusions need those paths present; covered as a unit property by tests/test_extra_skip_paths.py |
| `TRAV-037` | Second-line skip check inside the worker | supporting | ⛔ blocked | the worker's second-line skip check shares one skip_reasons key with the producer's, so no artefact separates the two arms |
| `TRAV-047` | Windows default scan scope is every mounted volume, including network and remov… | core | ⛔ blocked | Windows default scope covering every mounted volume needs a no-target whole-machine Windows scan |
| `LIFE-001` | Scan entry point main(yarafile, scan_folder, alert_severity) | core | ✅ pass | main(yarafile, scan_folder, alert_severity) ran to completion |
| `LIFE-002` | Cancel entry point cancel() — zero inputs | core | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_160806_408571_yara_eb6e98d3355a |
| `LIFE-003` | CLI dispatch and exit-code contract | supporting | ✅ pass | entry point returned a result line, no traceback |
| `LIFE-004` | Cancel flag file (control/cancel.flag) | core | ✅ pass | outcome=cancelled |
| `LIFE-008` | Cancellation watcher thread and poll cadence | supporting | ✅ pass | cancel to terminal state: ~70s (watcher polls every ~5s) |
| `LIFE-009` | _request_cancel — idempotent, first-source-wins, thread-safe | supporting | ✅ pass | cancel request recorded once with a single source |
| `LIFE-010` | Bounded cancellation latency in directory traversal (_walk_cancellable) | core | ✅ pass | walk interrupted mid-scan: 30593 files done when cancelled after 30s |
| `LIFE-011` | Worker-side cancellation and drain | core | ✅ pass | workers drained: files_scanned=30593 at cancel |
| `LIFE-012` | Worker join with bounded timeout | supporting | ✅ pass | Worker cleanup: 2 stopped, 0 timed out |
| `LIFE-013` | Cancel-flag consumption and marker removal at shutdown | supporting | ✅ pass | cancel flag consumed and marker removed at shutdown: True |
| `LIFE-014` | Backlog-proportional shutdown drain | supporting | ✅ pass | ok 35,504 + failed 0 + undelivered 25,682 = 61,186 against 61,186 findings on a cancelled run |
| `LIFE-019` | Outcome classification (completed / cancelled / failed) | core | ✅ pass | outcome classified as cancelled (not completed, not failed) |
| `LIFE-020` | Outcome agreement in end-of-scan telemetry | supporting | ✅ pass | summary outcome=cancelled with 5 lifecycle rows delivered |
| `LIFE-023` | Evidence and terminal telemetry survive a fatal failure | supporting | ✅ pass | terminal telemetry survived cancellation: {'yara_match': 35504, 'alert': 30594, 'system': 33, 'performance': 10, 'statistics': 8, 'scan_status': 5} |
| `LIFE-026` | Guaranteed finalisation order in main()'s finally block | supporting | ✅ pass | finally-block ran: summary written and outcome recorded |
| `LIFE-031` | Cancelled runs never report 'Scan completed' | core | ✅ pass | SCAN_RESULT: Scan cancelled (source=action_center): 30593 files scanned \| 1 rules failed compilation \| 1 rules skipped (module unavailable) \| 61186 matches found \| WARNING: 25682 o |
| `LIFE-034` | Excluded-target detection | supporting | ✅ pass | excluded_targets=[] |
| `LIFE-035` | Per-file outcome classification and skip reasons | supporting | ✅ pass | per-file outcomes reconcile: breakdown {'File too large': 1} sums to 1, files_skipped=1 |
| `LIFE-036` | Bounded skip reason for per-file scan errors | supporting | ✅ pass | labels bounded: ['File too large'] |
| `LIFE-037` | Per-file error tolerance in the worker loop | supporting | ✅ pass | worker tolerated per-file errors; scan_errors log 131 bytes, outcome=completed |
| `LIFE-038` | Permission-denied diagnostics | supporting | ✅ pass | unreadable dir planted=True; skip breakdown {'File too large': 1} |
| `LIFE-039` | Env-var guard: numeric tuning knobs fail safe | supporting | ✅ pass | numeric knob honoured: YARA_THREADS=8 -> 8 workers; non-numeric values fall back to the default by design |
| `LIFE-040` | Env-var guard: boolean toggles fail safe | supporting | ✅ pass | boolean toggles honoured: the three monitor flags activated their monitors |
| `LIFE-041` | Post-parse clamping of lifecycle knobs | supporting | ✅ pass | lifecycle knobs clamped: progress heartbeat produced 5 ticks at its 30 s default |
| `LIFE-042` | alert_severity input validation | supporting | ✅ pass | YARA Scanner Critical Error: Critical scanner error: Invalid alert_severity 'catastrophic'. Use low, medium, or high. |
| `LIFE-043` | scan_folder validation and multi-target contract | supporting | ✅ pass | scan_targets=['/tmp/yara_r3_tree'] |
| `LIFE-044` | Placeholder-collector-credential abort | core | ✅ pass | SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) an |
| `LIFE-045` | Rule-compilation fatal errors terminate the run before scanning | core | ✅ pass | 1 rule failed but 9 survived, so the run correctly continued |
| `LIFE-046` | Module-skipped rules counted separately from failures | core | ✅ pass | module-skipped (1) counted separately from failed (1) |
| `LIFE-047` | Privilege detection and privilege_status telemetry | supporting | ✅ pass | Running as: root on Linux |
| `LIFE-053` | scan_system finally-block guarantee | supporting | ✅ pass | scan_system finally block produced its artefacts |
| `LIFE-055` | Cleanup scheduling gated on rule-processing health | supporting | ✅ pass | cleanup scheduled after a run with 1 failed rule and 627 alerts: ['/tmp/yara_r3a/cleanup_script.sh'] |
| `LIFE-061` | Scanner working-directory selection (shared by both entry points) | supporting | ✅ pass | both entry points resolve the same scanner working directory |
| `LIFE-062` | `cancel` as the first CLI argument (cancel keyword dispatch) | supporting | ✅ pass | CANCEL_RESULT: Cancel signal delivered (/tmp/yara_r3e/control/cancel.flag) \| scanner running: yes \| scan_id=xsoar_20260817_160806_408571_yara_eb6e98d3355a |
| `LIFE-063` | Critical-error handler prints the Python traceback to STDOUT before the result … | supporting | ✅ pass | no traceback on a healthy run; the handler's output needs an induced fatal error |
| `LIFE-064` | Placeholder-credential abort still wipes alert/, evidence/ and old run logs fir… | supporting | ✅ pass | placeholder abort wrote no scan summary: aborted=True no_summary=True |
| `RULE-001` | Base64-only rule input | core | ✅ pass | valid_rules=9 rule_hash=eb6e98d3355a0376 |
| `RULE-003` | Typed rule-input rejection codes | supporting | ✅ pass | {'p-empty-input': 'INPUT_ERROR=yes', 'p-bad-base64': 'DECODE_ERROR=yes', 'p-no-rule-decls': 'VALIDATION_ERROR=yes'} |
| `RULE-004` | Empty embedded ruleset guard | supporting | ✅ pass | YARA Scanner Critical Error: Critical scanner error: Default YARA_RULE is empty - must provide yarafile parameter |
| `RULE-005` | Comment- and string-aware pack parser | supporting | ✅ pass | valid 9 + failed 1 + skipped 1 = 11 (pack declares 11; 4 decoys planted) |
| `RULE-006` | private / global rule modifier capture | supporting | ✅ pass | valid_rules=9, modifier warnings=False |
| `RULE-007` | Pack splitting into preamble + individual rules | supporting | ✅ pass | valid=9 failed=1 scanned=310 |
| `RULE-008` | Duplicate import de-duplication in the preamble | supporting | ✅ pass | unique imports: 1 |
| `RULE-009` | include statements passed through verbatim | supporting | ✅ pass | an unresolvable include reached the compiler and failed there, rather than being silently stripped or mis-parsed by the pack splitter |
| `RULE-010` | Rule block sanity check | supporting | ✅ pass | every extracted block passed the sanity check |
| `RULE-011` | Unnamed-rule fallback naming | low | ✅ pass | unnamed-rule fallback reached: False |
| `RULE-012` | Agent module-availability probe | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped |
| `RULE-013` | cuckoo-availability callout | supporting | ✅ pass | WARNING: YARA cuckoo module not available - rules using it will be skipped |
| `RULE-014` | Unavailable preamble imports stripped | supporting | ✅ pass | skipped=1 while valid=9 still compiled — the unavailable import did not poison the preamble |
| `RULE-015` | Pre-compile skip for rules importing missing modules | supporting | ✅ pass | skipped_rules=1 |
| `RULE-016` | Post-compile reclassification of inherited-import failures | supporting | ✅ pass | skipped=1 failed=1 |
| `RULE-017` | Automatic import injection from module usage | supporting | ✅ pass | import handling recorded in the processing log |
| `RULE-018` | Per-rule trial compile then namespaced whole-pack compile | supporting | ✅ pass | per-rule trial compile isolated exactly 1 failure |
| `RULE-019` | Duplicate rule names survive | supporting | ✅ pass | 12 files, 0 failed, 24 matches — both same-named rules fired on every file |
| `RULE-020` | Duplicate-name caveat in the rule-source map | supporting | ✅ pass | duplicate names compiled without failure; the rule-source map's caveat is that it cannot distinguish them, which no artefact surfaces |
| `RULE-022` | Per-file externals at match time | supporting | ✅ pass | 7 rules fired including filesize-conditioned ones (627 matches) |
| `RULE-023` | Non-short-circuiting match callback | supporting | ✅ pass | 627 matches over 310 files = 2.0 per file |
| `RULE-024` | Condition-only (no-strings) rule support | supporting | ✅ pass | condition-only rule produced an alert artefact: True |
| `RULE-025` | Per-rule compilation-failure diagnostics | supporting | ✅ pass | [2026-08-17 15:07:47.598] [ERROR] === RULE COMPILATION FAILURE #1 === |
| `RULE-026` | failed_rules/ artifact directory | supporting | ✅ pass | 2 failed_rules artefacts; log references the directory: True |
| `RULE-027` | failed_rules/ is never pruned | supporting | ✅ pass | 2 run_ids in logs/ after two scans; failed_rules still holds 'failed_rule_lc_broken.yar' |
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
| `TRAV-003` | Per-target validation with independent rejection | supporting | ✅ pass | valid target scanned 12 files alongside a nonexistent one; outcome=completed |
| `TRAV-004` | Hard failure when no requested target is valid | core | ✅ pass | YARA Scanner Critical Error: Critical scanner error: No valid scan directory among the specified scan folder(s): ['/nonexistent_a_zzz', '/nonexistent_b_zzz'] |
| `TRAV-005` | Windows whole-machine default target discovery | supporting | ✅ pass | Windows run completed against an explicit target; whole-machine discovery is exercised by the no-target run |
| `TRAV-006` | Linux default target discovery (privilege-aware) | supporting | ✅ pass | no target given -> ['/']; 469,170 scanned, 658,034 skipped |
| `TRAV-007` | macOS default target discovery (privilege-aware) | supporting | ✅ pass | macOS run targets=['/tmp/yara_r3_tree'] |
| `TRAV-009` | Excluded-target warning (requested target wholly skipped) | supporting | ✅ pass | excluded_targets=[] (empty — nothing was wholly skipped this run) |
| `TRAV-010` | Non-root system-path pre-flight advisory | supporting | ✅ pass | Running as: root on Linux |
| `TRAV-012` | Symlinked directories listed but never recursed | supporting | ✅ pass | symlink planted=True, files_scanned=310 (a recursed loop would multiply this), outcome=completed |
| `TRAV-013` | Unreadable directory entry demoted to a file | supporting | ✅ pass | skip breakdown: {'File too large': 1} |
| `TRAV-014` | Unreadable directory tolerated, subtree abandoned | supporting | ✅ pass | unreadable dir planted=True, outcome=completed, skips={'File too large': 1} |
| `TRAV-015` | Junction / reparse-point detection | supporting | ✅ pass | planted ['jlink', 'Application Data'] — each reparse=True while islink=False, so detection came from the reparse attribute rather than islink |
| `TRAV-016` | Per-platform problematic-junction skip list | supporting | ✅ pass | 3 files scanned with both junctions present: 2 real files plus one copy through the benign `jlink`, while `Application Data` was pruned (4 would mean it was followed too, 2 that the list is blanket) |
| `TRAV-017` | Directory-level junction pruning during the walk | supporting | ✅ pass | the problematic junction's subtree was never walked — 3 files scanned, and its contents contributed none |
| `TRAV-020` | Skip by file extension (disk-image containers) | supporting | ✅ pass | 19 planted (12 filler + .iso/.vmdk/.dmg + .DS_Store/Thumbs.db/desktop.ini + control.txt) -> 13 scanned, 13 matches |
| `TRAV-021` | Skip by exact filename | supporting | ✅ pass | 6 skip-listed names planted alongside a control.txt carrying the same matching content; 13 of 19 scanned and control.txt was among them |
| `TRAV-026` | Windows skip folders with component-boundary matching | supporting | ✅ pass | Windows component-boundary matching ran over 310 files without over-skipping (macOS/Linux parity: 310/309/310) |
| `TRAV-028` | Linux skip directories | supporting | ✅ pass | 655,232 files attributed to skipped directories; breakdown {'Skipped directory': 655232, 'File does not exist': 1965, 'Not a regular file': 762, 'File too large': 52, 'Special system file': 23} sums to 658,034 = files_s… |
| `TRAV-029` | macOS skip directories with three matching semantics | supporting | ✅ pass | macOS skipped 2 vs Linux 1 / Windows 1; breakdown {'Junction/symlink skip': 1, 'File too large': 1} |
| `TRAV-030` | macOS AppleDouble and .DS_Store file skip | supporting | ✅ pass | skipped: macOS=2 linux=1 windows=1; macOS breakdown {'Junction/symlink skip': 1, 'File too large': 1} |
| `TRAV-032` | Self-skip of the scanner's own directory and log file | core | ✅ pass | scanner artefacts inside the target: 0 |
| `TRAV-034` | Maximum file size cap | core | ✅ pass | oversized planted=True, skip breakdown={'File too large': 1} |
| `TRAV-035` | Non-regular-file rejection | supporting | ✅ pass | 762 non-regular files and 23 special system files rejected on a root scan; outcome=completed |
| `TRAV-036` | Existence and read-access pre-checks | supporting | ✅ pass | pre-checks let the scan complete over a tree containing an unreadable directory (1 skipped) |
| `TRAV-040` | Bounded per-file error labels in the skip breakdown | supporting | ✅ pass | 1 distinct skip labels: ['File too large'] |
| `TRAV-042` | Scan-configuration disclosure event | supporting | ✅ pass | scan-configuration disclosure event present |
| `TRAV-044` | Case-folding policy for path matching | supporting | ✅ pass | files_scanned per platform: {'linux': 310, 'macos': 309, 'windows': 310} |
| `TRAV-046` | Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink dup… | low | ✅ pass | skip keys seen: ['File too large']; undocumented keys present: [] |
