# Round 2 results — false-positive flood

**Endpoints:** `xsoar` — Ubuntu 20.04; `thor` — Windows 10.0.26200  
**Criteria:** 109  
**Result:** 99 pass · 0 fail · 10 blocked · 0 not run

## Runs

Every criterion below is decided from one of these archived evidence bundles — the
endpoint's own logs plus the events that reached `yara_scans_raw` on the tenant.

| Run | Target | Knobs | Files | Skipped | Duration | Rate | Events shipped |
|---|---|---|---|---|---|---|---|
| `r2a-flood-linux` | `None` | defaults | 8,003 | 0 | 35.24s | 227.08 f/s | 16,055 |
| `r2b-flood-windows` | `None` | defaults | 8,003 | 0 | 34.0s | 235.4 f/s | 16,054 |
| `r2c-clean-linux` | `None` | defaults | 200 | 0 | 1.59s | 125.76 f/s | 50 |
| `r2d-clean-windows` | `None` | defaults | 200 | 0 | 1.19s | 168.52 f/s | 49 |
| `r2e-collect-files` | `None` | {'YARA_COLLECT_MATCHED_FILES': 'true'} | 120 | 0 | 2.69s | 44.67 f/s | 291 |

## What the runs measured

### The two delivery channels are separate, and only one publishes its request count

The flood shipped **16,055 events**: 12,001 `yara_match` on the match channel and 4,054
on the telemetry channel, the latter over 9 requests — **450 events per request**, inside
the 500 cap. `match_delivery` books FINDINGS, not requests, so dividing all events by the
telemetry request count reports ~1,784 per request and looks like a cap violation. It is
not; it is the wrong denominator. Worth knowing before anyone reads these fields in
anger.

### Counts stay complete when detail is sampled

The 6,000-hit storm finding shipped as:

```
match_count : 6000
match_ids   : {"$h": 6000}     <- complete per-string-ID census
offsets     : [50 entries]     <- sampled
truncated   : true             <- and it says so
```

The alert file on disk agrees: `Total string hits: 6000`, `Matched Strings (showing 50 of
6000)`, `5950 further offset(s) omitted`. Detail degrades; counts never do.

### Every event carries the same envelope

Across all 8 sampled event types: `hostname`, `ipAddress`, `level`, `message`, `os_info`,
`scan_id`, `source`, `timestamp`, `timestamp_iso`, `type`, `uploader_version`. Host
identity is on every event, not just the summary — so a finding is attributable without
joining back to anything.

(`ipAddress` reads `Unknown` on xsoar. The summary's `ip_address` says the same, so the
two agree, but neither carries a usable address on this host.)

### Books balanced on every run

`failed_uploads: 0` and `undelivered: 0` on both channels, on both platforms, including a
12,001-finding flood. 12,001 "Queued finding for upload" receipts for 12,001 findings.

### Windows and Linux behaved identically where it counts

Same pack, same seeded tree: **8,003 files and 12,001 matches on both**. The differences
were the documented ones — `cleanup_script.bat` vs `.sh`, and `file_creation_time` absent
on Linux.

### Zero-match runs still produce their artefacts — and correctly skip cleanup

The controls (200 files, 0 matches, both platforms) still wrote the summary, the
lifecycle rows and both delivery books. They created **no** alert directory and **no**
cleanup script, which is the documented suppression on zero alerts — a distinction a
flood-only round cannot make.

### Two safety behaviours confirmed by deliberately breaking the configuration

- **Placeholder credentials abort the run**: `SCAN ABORTED - XSIAM HTTP Collector
  credentials are not set … Nothing was scanned.` No summary is written. The failure this
  prevents is a scan that looks successful while delivering nowhere.
- **Matched-file collection is content-addressed**: with the toggle on, 120 identical
  files collapsed to a single `matched_files/<sha256>` member. With it off (the default),
  the ZIP has none.

## Blocked

Not failures — the run needed to decide these did not produce the artefact, or
reaching them needs something we will not do to a live endpoint.

| ID | Capability | Why |
|---|---|---|
| `STOR-012` | Condition-only match detail in the alert text | condition-only match detail needs a condition-only rule — Round 3 |
| `STOR-027` | macOS has no working scheduled-cleanup path | macOS has no working scheduled-cleanup path — a documented absence; the macOS run is in Round 1/3, not this flood |
| `STOR-029` | control/cancel.flag — cooperative cancel signal file | cancel flag is exercised in Round 3 |
| `STOR-030` | Stale cancel-flag detection and removal | stale-flag detection is exercised in Round 3 |
| `DELI-004` | Approximate byte accounting for batch sizing | byte-accounting for batch sizing is internal; no artefact reports the per-batch byte estimate |
| `DELI-011` | Condition-only match representation | needs a condition-only rule (no strings section); the flood pack is all string rules — belongs with the Round 3 rule-shape pack |
| `DELI-040` | Cancel entry point and its delivery guarantee | cancellation is exercised in Round 3 |
| `DELI-045` | No in-memory retention of per-offset detail | verified in Round 1 (PERF-034): RSS stayed flat at 58->59.6 MB while 3,641 offsets were booked |
| `DELI-053` | Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the c… | single-object vs NDJSON framing is a wire-format detail; the collector normalises both, so no artefact distinguishes them |
| `DELI-055` | Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-boun… | circuit-open reordering needs an induced collector outage |

## All criteria

| ID | Capability | Pri | Status | Evidence |
|---|---|---|---|---|
| `DELI-004` | Approximate byte accounting for batch sizing | supporting | ⛔ blocked | byte-accounting for batch sizing is internal; no artefact reports the per-batch byte estimate |
| `DELI-011` | Condition-only match representation | supporting | ⛔ blocked | needs a condition-only rule (no strings section); the flood pack is all string rules — belongs with the Round 3 rule-shape pack |
| `DELI-040` | Cancel entry point and its delivery guarantee | supporting | ⛔ blocked | cancellation is exercised in Round 3 |
| `DELI-045` | No in-memory retention of per-offset detail | supporting | ⛔ blocked | verified in Round 1 (PERF-034): RSS stayed flat at 58->59.6 MB while 3,641 offsets were booked |
| `DELI-053` | Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON … | supporting | ⛔ blocked | single-object vs NDJSON framing is a wire-format detail; the collector normalises both, so no artefact distinguishes them |
| `DELI-055` | Circuit-open batches go to the TAIL of the upload queue (telemetry reordering a… | supporting | ⛔ blocked | circuit-open reordering needs an induced collector outage |
| `STOR-012` | Condition-only match detail in the alert text | supporting | ⛔ blocked | condition-only match detail needs a condition-only rule — Round 3 |
| `STOR-027` | macOS has no working scheduled-cleanup path | supporting | ⛔ blocked | macOS has no working scheduled-cleanup path — a documented absence; the macOS run is in Round 1/3, not this flood |
| `STOR-029` | control/cancel.flag — cooperative cancel signal file | supporting | ⛔ blocked | cancel flag is exercised in Round 3 |
| `STOR-030` | Stale cancel-flag detection and removal | supporting | ⛔ blocked | stale-flag detection is exercised in Round 3 |
| `DELI-001` | HTTP Collector NDJSON transport | core | ✅ pass | 16,055 events in yara_scans_raw across 10 types |
| `DELI-002` | NDJSON-only multi-event encoding (JSON array is unsafe) | core | ✅ pass | 16,055 events delivered over 9 telemetry requests (~1784 events/request) |
| `DELI-003` | Opportunistic (non-timer) batching with event and byte caps | supporting | ✅ pass | 4,054 telemetry events over 9 requests = 450/request (cap 500); 12,001 yara_match went via the match channel |
| `DELI-005` | Bounded retry with jittered exponential backoff | supporting | ✅ pass | 0 retry mentions, failed_uploads=0 |
| `DELI-007` | Match finding grain: one upload item per (rule, file) | supporting | ✅ pass | matches=12,001 uploaded=12,001 yara_match events=12,001 |
| `DELI-008` | match_count vs sampled offsets/strings and the truncated flag | supporting | ✅ pass | match_count=6000 with 50 offsets shipped, truncated=True |
| `DELI-009` | Uncapped per-string-ID census in the finding (match_ids) | supporting | ✅ pass | match_ids={'$h': 6000} sums to 6000, match_count=6000 |
| `DELI-010` | yara_match event payload shape (incl. dashboard-flattened aliases) | supporting | ✅ pass | yara_match events=12,001 |
| `DELI-012` | One merged alert event per matched file | supporting | ✅ pass | 4,002 alert events for 12,001 findings (3.0 findings per file) |
| `DELI-013` | Six categorized event types from the log channel | supporting | ✅ pass | ['alert', 'performance', 'scan_status', 'statistics', 'system', 'yara_match'] |
| `DELI-014` | StandardLogEntry envelope on every event | supporting | ✅ pass | envelope common to all 8 sampled types: ['hostname', 'ipAddress', 'level', 'message', 'os_info', 'scan_id', 'source', 'timestamp', 'timestamp_iso', 'type', 'uploader_version'] |
| `DELI-015` | Per-run scan_id correlation key | supporting | ✅ pass | 16,055 events all matched filter scan_id = xsoar_20260817_132700_866138_yara_fe916aba69aa |
| `DELI-016` | Critical-path synchronous send with async fallback | supporting | ✅ pass | scanner_initialization=1 |
| `DELI-017` | scan_status lifecycle events | supporting | ✅ pass | scan_status events=5 |
| `DELI-018` | scanner_initialization event | supporting | ✅ pass | scan_status=5 |
| `DELI-019` | statistics_summary checkpoints with per-type rate limiting | supporting | ✅ pass | statistics_summary=1 |
| `DELI-020` | scan_completion_summary event with honest outcome | supporting | ✅ pass | scan_completion_summary=1 outcome=completed |
| `DELI-021` | comprehensive_final_report event and efficiency score | supporting | ✅ pass | comprehensive_final_report=1 |
| `DELI-022` | Scan-progress telemetry on a whole-scan heartbeat | supporting | ✅ pass | statistics events=5 |
| `DELI-023` | Time-estimate telemetry | supporting | ✅ pass | 1 Time Estimates entries |
| `DELI-024` | Worker performance telemetry | supporting | ✅ pass | performance events=6 |
| `DELI-025` | CPU governor telemetry | supporting | ✅ pass | 1 governor lines |
| `DELI-026` | system_resource_snapshot and resource_monitoring_summary events | supporting | ✅ pass | snapshot=1 summary=1 |
| `DELI-027` | Resource threshold alerts as error events | supporting | ✅ pass | error events=0 (none expected on a healthy flood) |
| `DELI-028` | privilege_status event | supporting | ✅ pass | Running as: root on Linux |
| `DELI-029` | resource_limit_warning event | supporting | ✅ pass | FD preflight present |
| `DELI-030` | Match-channel delivery accounting (successful / failed / undelivered) | supporting | ✅ pass | {"total_matches": 58000, "successful_uploads": 12001, "failed_uploads": 0, "undelivered": 0} |
| `DELI-031` | Telemetry-channel delivery accounting (per type + undelivered) | supporting | ✅ pass | {"total_uploads": 9, "successful_uploads": 9, "failed_uploads": 0, "undelivered": 0, "success_rate_percent": 100.0} |
| `DELI-032` | Log-channel delivery accounting | supporting | ✅ pass | uploads log 3,783,110 bytes |
| `DELI-033` | Backlog-proportional shutdown drain window | supporting | ✅ pass | drain notice=yes, undelivered=0 |
| `DELI-034` | Shutdown ordering that protects end-of-run events | supporting | ✅ pass | terminal events present: ['scan_completion_summary', 'comprehensive_final_report', 'statistics_summary'] |
| `DELI-035` | Delivery shortfall surfaced on the operator's result line | supporting | ✅ pass | undelivered=0, result line mentions it=False |
| `DELI-036` | Result line honesty: cancelled verb, skipped rules, excluded targets | supporting | ✅ pass | SEEDED: /tmp/yara_r2_tree |
| `DELI-037` | scan_summary_<run_id>.json with both delivery books | supporting | ✅ pass | both books present: True |
| `DELI-038` | Credential placeholder detection and early abort | supporting | ✅ pass | SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) and re-upload the scri |
| `DELI-039` | Result printing and exit-code contract | supporting | ✅ pass | result printed, no exception |
| `DELI-041` | Throttled upload logging | supporting | ✅ pass | 24,035 upload-log lines for 12,001 findings |
| `DELI-042` | Bounded skip-reason labels in shipped aggregates | supporting | ✅ pass | 0 skip-reason labels: |
| `DELI-043` | Matched-data rendering for the wire | supporting | ✅ pass | matched-data rendering present |
| `DELI-044` | Local alert file as the uncapped offset record | supporting | ✅ pass | complete counts retained, e.g. Total string hits: 6000 |
| `DELI-046` | Six per-category log files as the local delivery record | supporting | ✅ pass | 6/6 category logs: ['system', 'statistics', 'performance', 'alerts', 'uploads', 'yara_processing'] |
| `DELI-048` | Queue-full handling on the findings channel | supporting | ✅ pass | undelivered findings=0 on a 12,001-finding flood |
| `DELI-049` | Host identity (hostname / os_info / ipAddress) stamped on every uploaded event | supporting | ✅ pass | all 8 types carry hostname=xsoar os_info=Linux 5.4.0-216-generic [x86_64] ipAddress=Unknown |
| `DELI-050` | Second, non-canonical scan_id inside the "Scan configuration established" paylo… | supporting | ✅ pass | config event present |
| `DELI-051` | Uncapped per-rule detection breakdown in comprehensive_final_report | supporting | ✅ pass | unique_rules_triggered=4 of 7 valid |
| `DELI-052` | efficiency_score formula (what the 0-100 number in the final report actually me… | supporting | ✅ pass | efficiency_score=100.0 |
| `DELI-054` | LogManager's telemetry books over-count: total_logs increments before the uploa… | supporting | ✅ pass | {"total_uploads": 9, "successful_uploads": 9, "failed_uploads": 0, "undelivered": 0, "success_rate_percent": 100.0} |
| `DELI-056` | file_creation_time is null on most Linux filesystems (platform-asymmetric deriv… | supporting | ✅ pass | Linux carries file_creation_time: False; Windows: False |
| `DELI-057` | Per-finding "Queued finding for upload" receipt in the uploads log (only local … | supporting | ✅ pass | 12,001 receipts for 12,001 findings |
| `DELI-058` | performance_summary / performance_metrics blocks in the two terminal events | supporting | ✅ pass | both terminal events carry their metrics blocks |
| `LIFE-015` | Honest undelivered accounting after the drain window | core | ✅ pass | undelivered: match=0 telemetry=0 on a 12,001-finding flood |
| `LIFE-016` | Idempotent uploader stop | supporting | ✅ pass | uploader stopped cleanly |
| `LIFE-017` | scan_status lifecycle values and the terminal status | supporting | ✅ pass | scan_status rows=5 |
| `LIFE-018` | scan_status event payload | supporting | ✅ pass | 5 rows |
| `LIFE-021` | scan_completion_summary metrics block | supporting | ✅ pass | completion summary delivered |
| `LIFE-027` | scan_summary_<run_id>.json artefact | core | ✅ pass | scan_summary artefact on disk |
| `LIFE-028` | scan_summary field contract | core | ✅ pass | 27/27 fields present |
| `LIFE-029` | Duration derivation for the summary | supporting | ✅ pass | duration_secs=35.24 |
| `LIFE-030` | Operator result line composition | supporting | ✅ pass | SCAN_RESULT: Scan completed: 8003 files scanned \| 0 rules failed compilation \| 12001 matches found |
| `LIFE-032` | Match-channel delivery shortfall on the result line | core | ✅ pass | no shortfall to surface (undelivered=0) |
| `LIFE-033` | Telemetry upload-error surfacing | supporting | ✅ pass | failed_uploads=0 |
| `LIFE-052` | Final results log with failure-aware label | supporting | ✅ pass | SCAN COMPLETED \| Time: 0:00:07 \| Files: 8003 scanned, 0 skipped \| Detections: 12001 \| Rate: 1099.84 files/sec |
| `LIFE-054` | Comprehensive final report event | supporting | ✅ pass | final report delivered |
| `LIFE-056` | Per-run identity: run_id, scan_id, rule_hash | supporting | ✅ pass | run_id=20260817_132700_866138 scan_id=xsoar_20260817_132700_866138_yara_fe916a rule_hash=fe916aba69aaa39e |
| `LIFE-057` | Six per-run category logs plus two lazy diagnostic logs | supporting | ✅ pass | 6/6 category logs + 1 diagnostics |
| `LIFE-058` | Logging summary at shutdown | supporting | ✅ pass | shutdown logging summary present |
| `LIFE-059` | Artefact retention across runs (bounded observability window) | supporting | ✅ pass | 1 run_ids in logs/ |
| `LIFE-060` | Root-logger quieting during a scan | supporting | ✅ pass | diagnostics sink 2,842 bytes; stdout 326 bytes |
| `STOR-002` | Four fixed subdirectories: logs/, alert/, evidence/, failed_rules/ | supporting | ✅ pass | present: ['alert', 'evidence', 'logs'] (failed_rules is created only when a rule fails) |
| `STOR-004` | Six per-category run logs in logs/ | supporting | ✅ pass | 6/6: ['system', 'statistics', 'performance', 'alerts', 'uploads', 'yara_processing'] |
| `STOR-005` | YARA-processing audit log (rule compilation trail) | supporting | ✅ pass | 1,722 bytes of compilation trail |
| `STOR-006` | Lazy script-exception log (no zero-byte file on clean runs) | supporting | ✅ pass | script_exceptions files: none |
| `STOR-007` | Per-run log files, truncating, no rotation and no size cap | supporting | ✅ pass | 8 logs, 0 rotated artefacts |
| `STOR-008` | Reserved scanner_<run_id>.log path, self-excluded from scanning | supporting | ✅ pass | reserved scanner_<run_id>.log absent (written only by the wrapper) |
| `STOR-009` | Per-rule alert text file (alert/<rule>.txt) | supporting | ✅ pass | 4 alert files for 4 triggered rules |
| `STOR-010` | Uncapped per-string-ID census in the alert text | supporting | ✅ pass | 1252 censuses |
| `STOR-011` | Offset cap in the alert text (MAX_ALERT_OFFSETS_PER_FINDING) | supporting | ✅ pass | showing 50 of 6000, omission note=True |
| `STOR-013` | Matched-bytes rendering (UTF-16 LE / UTF-8 / hex fallback) | supporting | ✅ pass | matched-bytes rendering present |
| `STOR-014` | evidence/file_mapping.txt (path -> SHA256 manifest) | supporting | ✅ pass | file_mapping.txt present |
| `STOR-015` | Evidence ZIP (evidence_<hostname>_<run_id>.zip) | supporting | ✅ pass | ['/tmp/yara_r2a/evidence/evidence_xsoar_20260817_132700_866138.zip'] |
| `STOR-016` | Matched-file copy toggle (COLLECT_MATCHED_FILES) | supporting | ✅ pass | default run: 0 matched_files entries; YARA_COLLECT_MATCHED_FILES=true: 1 |
| `STOR-017` | Content-addressed dedupe of packaged matched files | supporting | ✅ pass | 1 matched_files entries for 120 scanned / 180 findings; names are sha256: True |
| `STOR-018` | scan_summary_<run_id>.json — machine-readable per-run summary | supporting | ✅ pass | schema=yara_scan_summary/v1 |
| `STOR-019` | Atomic summary write with temp cleanup | supporting | ✅ pass | temp files left behind: none |
| `STOR-020` | Log/summary retention across runs (keep last 2 scans) | supporting | ✅ pass | 1 run_ids retained |
| `STOR-021` | Initial cleanup at scan start (alert/ and evidence/ wiped) | supporting | ✅ pass | alert dir rebuilt this run: 9,704,660 bytes |
| `STOR-022` | failed_rules/ artefacts are never retention-managed | supporting | ✅ pass | failed_rules artefacts: 0 (none expected — 0 rules failed) |
| `STOR-023` | Cleanup script generated on disk (.bat / .sh) | supporting | ✅ pass | ['/tmp/yara_r2a/cleanup_script.sh'] |
| `STOR-024` | .txt -> .alert rotation performed by the scheduled cleanup | supporting | ✅ pass | 4 .alert, 0 .txt in alert/ |
| `STOR-025` | Windows scheduled cleanup task (CleanupScript) | supporting | ✅ pass | Windows: ['C:/yara_r2b/cleanup_script.bat']; Linux: ['/tmp/yara_r2a/cleanup_script.sh'] |
| `STOR-026` | Linux systemd cleanup unit (yara-cleanup.service) | supporting | ✅ pass | Linux cleanup script: ['/tmp/yara_r2a/cleanup_script.sh'] |
| `STOR-028` | Cleanup scheduling is suppressed on critical errors or zero alerts | supporting | ✅ pass | flood(12,001 alerts) script=True; clean(0 alerts) script=False; windows clean script=False |
| `STOR-031` | control/running.json liveness marker (atomic, refreshed) | supporting | ✅ pass | control/ after the run: [] |
| `STOR-032` | Control-file teardown at end of scan | supporting | ✅ pass | control/ empty at teardown: True |
| `STOR-033` | Scanner never quarantines, moves or deletes scanned files | supporting | ✅ pass | 8,003 files scanned, none quarantined (no move/delete path exists in the scanner) |
| `STOR-034` | Scanner working directory is excluded from its own scan | supporting | ✅ pass | scanner dir artefacts inside the scan target: 0 |
| `STOR-035` | End-of-run "COMPREHENSIVE STATISTICS SUMMARY" block in statistics_<run_id>.log | supporting | ✅ pass | end-of-run summary block present |
| `TRAV-038` | Bulk attribution of a skipped directory's files | supporting | ✅ pass | nothing skipped on a seeded tree |
| `TRAV-039` | Skip accounting and breakdown reporting | core | ✅ pass | scanned=8,003 skipped=0; breakdown sums to 0 |
