# Release Notes

Every released version of `xdr_yara_scanner.py`, `xsiam_yara_scanner.py`, and their
companion scripts. Each entry records what changed and **why**, so you can decide whether
a release is worth taking.

The guides in `docs/xdr/` and `docs/xsiam/` describe the **current** version only. Anything about how a
behaviour used to work, or the testing behind a change, lives here.

**Which version am I running?** Read `scanner_version` in `scan_summary_<run_id>.json`, or
the `VERSION` line at the top of `yara_processing_<run_id>.log`.

Versioning is semantic: **MAJOR** breaks something, **MINOR** adds capability, **PATCH**
fixes without changing behaviour you rely on.

---

## xsiam_yara_scanner.py v4.2.0 — 2026-08-14

Endpoint footprint release. A scan was writing **2.8 GB to the disk of the machine it was
scanning**, unconditionally and with no way to turn it off. This release stops that by
default and fixes a packaging bug found alongside it. Numbers below are measured on the
same live Windows endpoint as v4.1.0 (26,312 files, 22,918 findings).

> **Behaviour change:** the evidence ZIP no longer contains copies of matched files by
> default. Nothing else about scanning, alerting, or delivery changes. See below for how
> to restore the old behaviour and what you give up by leaving it off.

### Changed — matched files are no longer copied into the evidence ZIP by default

The evidence collector read every matched file and wrote it into a local archive. That
work is charged entirely to the **scanned host**: on the lab endpoint it read **7,244 MB**
of file data and left a **2,867 MB** ZIP behind, for a scan that ran 455 seconds. Because
the archive is named per run and only cleared at the *start* of the next scan, a host
scanned once keeps that 2.8 GB indefinitely.

`xdr_yara_scanner.py` already defaults its equivalent `collect_files` option **off, at the
customer's request**. XSIAM had no such option at all — the copy was unconditional. This
release closes that gap.

The new top-of-file knob mirrors the XDR default:

```python
COLLECT_MATCHED_FILES = _env_bool("YARA_COLLECT_MATCHED_FILES", False)
```

Set it to `True` (or export `YARA_COLLECT_MATCHED_FILES=true`) to restore pre-4.2.0
behaviour.

**What you still get with it off.** The ZIP keeps `file_mapping.txt` — every matched path
with its SHA256 — and the per-rule alert texts with every offset. A responder can still
identify exactly which files matched and fetch any of them on demand. What is dropped is
only the bulk, up-front copy of files that are by definition already sitting on the host.

### Fixed — duplicate files were stored multiple times in the evidence ZIP

Archive entries are content-addressed (`matched_files/<sha256>`), but the writer iterated
by *path*, so several paths holding identical bytes each wrote a full copy under the same
entry name. `zipfile` only emits a warning for a repeated name and stores the member
anyway, so the archive silently carried N copies while a reader could still only ever
extract the first.

Measured on the lab endpoint: 22,918 matched paths held **22,213 distinct files**, so
**705 redundant copies** were being written — **506 MB**, or 7% of the bytes copied. The
worst single case was `c_usb.inf_loc`, stored **34 times**.

This only affects scans that opt back in via `COLLECT_MATCHED_FILES=true`, but it is fixed
so that opting in is no longer needlessly expensive.

### Known limitation — alert text files are still unbounded

The per-rule `alert/<rule>.txt` files record every matched offset and are packaged into the
ZIP regardless of this setting. On the lab endpoint's 2,653,415 offsets they came to
**240 MB**. With file copying off they are now the largest thing in the archive. Bounding
them is deferred to a later release; it needs a decision about which offsets to keep.

### Tests

`tests/test_evidence_collector.py` — 6 new tests covering dedupe by content, distinct
content surviving, mapping completeness after dedupe, resilience to a file deleted
mid-scan, metadata-only packaging when collection is off, and archive size staying
independent of matched-file size. Suite total: 234 → 240.

---

## xsiam_yara_scanner.py v4.1.0 — 2026-08-13

Delivery and footprint release. Fixes a case where **97% of a scan's findings never
reached the tenant**, removes a multi-gigabyte memory cost on match-heavy endpoints, and
cuts total ingested rows by roughly a third. Every number below was measured on a live
Windows endpoint (26,312 files, 22,918 findings, 2,653,417 matched offsets), not estimated.

### Fixed — findings were being lost in bulk on match-heavy scans

Each event was sent as its own HTTP request. At ~756 ms per round trip, a scan producing
23,223 findings needed **~4.9 hours** of serial requests but finished in 455 seconds, so
**22,621 findings (97%) were still queued when the shutdown drain expired and were dropped.**

All three channels — matches, telemetry/monitoring, and logs — now send many events per
request. On the same endpoint and ruleset:

| | Before | After |
|---|---|---|
| Findings delivered | 602 (2.6%) | **22,918 (100%)** |
| Undelivered | 22,621 | **0** |
| Scan duration | 161.7 s | **63.1 s** |
| Scan rate | 162.7 files/s | **417.2 files/s** |

The scan itself got 2.6× faster as a side effect: the upload thread had been contending
heavily with the scan workers.

Batching is **opportunistic, not timer-based** — a worker takes whatever is already queued
behind the first event and sends immediately. Batch size self-adjusts to load: 500 under a
storm, 3 on a scan with 3 matches, with no added latency either way. Tunable at the top of
the script via `UPLOAD_BATCH_MAX_EVENTS` (default 500) and `UPLOAD_BATCH_MAX_BYTES`
(default 4 MB).

> **If you modify the upload code:** the collector accepts NDJSON (one JSON object per
> line). It *also* accepts a JSON array — answering `HTTP 200 {"error":"false"}` — and then
> **silently discards every event in it.** Verified twice against a live tenant: array 0/5
> landed, NDJSON 5/5. Using the array form would report 100% success while delivering
> nothing.

### Changed — one alert event per matched file instead of two

Two alert events fired for the same file: `"YARA detection event: N rules triggered in
<file>"` and `"YARA matches found in <file>"`. Their payloads overlapped almost entirely
(path, SHA256, creation time, rule list). Measured on the storm scan, alerts were **47,460
of 72,484 ingested rows (65%)** at 2.07 events per finding — the single largest consumer of
ingestion, mostly duplication.

They are now **one** event carrying the union of both payloads, plus rule and string-hit
counts in the message. Expected effect on that scan: ~47,460 alert rows → ~22,918, cutting
total ingestion roughly a third.

**Check any ad-hoc query matching `"YARA detection event"`** — that message no longer
exists. No shipped widget, dashboard, or parsing-rule field used either event, so nothing
in the packaged content breaks, and `rules_triggered` is retained as an alias of
`rules_matched` so queries on either field name still resolve.

### Fixed — multi-gigabyte memory growth on match-heavy endpoints

A record was built for every matched *offset* and held in memory for the whole scan.
Measured: **1,048,035 offsets held ~15 GB RSS and was still climbing.** That endpoint had
160 GB and survived; a normal 8–16 GB endpoint would have been driven into swap by the same
ruleset.

Those records were never written anywhere — the function that would have serialized them is
unreachable, so the data was accumulated and then discarded. They are no longer built at
all. The per-offset detail was already recorded, uncapped, in `alert/<rule>.txt` (String ID
/ Offset / Data), which the evidence ZIP bundles, so **nothing is lost.**

Re-measured on the same endpoint with **2.5× more offsets** (2,653,415): peak RSS **224 MB**.

### Also in this release

- **11 new dashboard widgets**, each live-validated against a tenant: scanner memory growth,
  host load vs scanner CPU share, scan ETA, disk headroom, thread count, disk I/O, agent
  fleet inventory, rule-only vs string matches, truncated findings, detection density, and
  rule compilation health. Of the 84 fields the parsing rule extracts, only 24 were
  previously visualized.
- **Removed the Cache Hit-Rate widget.** Scan caching is a roadmap feature that is hardcoded
  off, so the scanner has never emitted a cache event — the widget could not populate.
- **Documented why the CPU/memory widgets are blank during a running scan** (Deployment
  Guide §12.1): they average samples between a per-host start marker and `Target scan
  completed:`, so a scan with no end marker yet contributes nothing.

### Upgrading

**Re-upload the script and re-import both dashboards.** The parsing rule is unchanged since
v4.0.0 — nothing to re-apply on the tenant. Expect noticeably lower ingested row counts and
complete delivery on match-heavy scans.

---

## xdr_yara_scanner.py v3.2.0 — 2026-08-13

Ports the delivery-agnostic fixes from the XSIAM edition. XDR's own alert/dataset machinery
is untouched.

### Fixed — the same multi-gigabyte memory growth

XDR had this defect in identical form: a record per matched offset, buffered for the whole
scan, serialized by a function that is never called. Removed outright, for the same reason —
`alert_dir/<rule>.txt` already records every offset. See the XSIAM v4.1.0 entry above for
the measurements.

### Fixed — rules were silently dropped for mentioning a module name

Module availability was decided by matching `\b<module>\.` against raw rule text, guarded by
a set of imports computed over the **whole ruleset**. So a single `import "cuckoo"` anywhere
in a pack opened the gate for every other rule in the file — exactly the case the guard
existed for. Demonstrated against the old code: a rule hunting the literal string
`"cuckoo.conf"`, and a rule merely mentioning it in a comment, were both **skipped without
ever being compiled** — silent detection loss.

Classification now happens only after yara itself raises `undefined identifier "<module>"`
for a module imported in the source and absent from the agent. A rule that merely mentions a
module name compiles and runs normally.

> `docs/xdr/topics/Rule_Compatibility.md` stated that a rule containing `"cuckoo.conf"` is
> not wrongly dropped. That was **not true** before this release.

### Fixed — skipped rules were invisible, and cancelled runs under-reported

- `skipped_rules_count` was set but never read by anything operator-facing, so a pack whose
  rules mostly could not run still reported "0 rules failed compilation". Now on the
  `SCAN_RESULT` line and in `scan_summary_<run_id>.json`.
- An all-skipped ruleset reported a compilation failure; it now reports an agent capability
  limit, so the operator is not sent hunting for a syntax error that does not exist.
- The cancel path returned early and **bypassed the delivery-shortfall check entirely** — the
  one outcome where partial results matter most was the one that never reported lost
  findings.

### Upgrading

**Drop-in.** Expect one extra rule compile per host on the first scan after upgrading (the
module-probe fix changes the rule-cache key).

---

## xsiam_yara_scanner.py v4.0.0 — 2026-08-13

**Breaking.** Adds operator-driven scan cancellation — which this edition simply did not
have — plus a per-run machine-readable summary, a scan-coverage fix, and correct
classification of rules the agent cannot run. The major bump is for four contract changes
listed under *Breaking* below, not for the new features; if you parse this scanner's output
or group on its `scan_id`, read that section before upgrading.

### Added — cooperative cancellation (`cancel` entry point)

Until now the only way to stop a running scan was the console's **Cancel** button, which
hard-kills the payload process: queued findings are lost, no summary is written, and no
terminal event is emitted. The scan simply vanishes.

The scanner now exposes a second, **zero-input** Action Center entry point, `cancel`. It
writes a flag file that the running scan polls for (default every 5s) and reports whether a
scan is actually alive. The scan then unwinds cooperatively — workers stop, queues drain,
telemetry flushes, and the run still writes its summary with `outcome: "cancelled"`.

`cancel` is a separate entry point rather than a `mode` input on `main` deliberately: Action
Center derives a script's input list from the function signature, so adding a parameter to
`main` would change its 3-input contract and fail parameter validation on every existing
`run_script` call. **`main`'s inputs are unchanged.**

Supporting pieces: `_walk_cancellable` replaces `os.walk` for discovery so a cancel is
honoured within a single directory read instead of an unbounded wait (traversal verified
byte-identical to `os.walk`, including symlink handling and caller-side pruning); a
`control/running.json` liveness marker, written before rule compilation starts so `cancel`
does not report "scanner running: no" about a scan that is merely still compiling.

Verified live: a cancel truncated a scan at 1,627 of 4,000 files, with the flag consumed and
the marker removed.

### Added — `logs/scan_summary_<run_id>.json`

One machine-readable record per run — outcome, duration, file/match counts, rule stats,
scanner version, and both delivery books — written atomically so a reader never sees a
partial file. This matters most in the case this edition is least protected against: after a
console hard-kill, nothing reaches the collector and this local file is the only surviving
evidence of what the run had done.

### Fixed — browser caches and profiles were never scanned (detection blind spot)

Chrome, Edge and Firefox cache and profile directories were on the skip list on **every**
platform, so a payload staged in one was invisible to this scanner. Those four skip entries
are removed, and a small allowlist re-opens browser caches on macOS where a broader
`/library/caches/` rule would still have excluded them. The allowlist deliberately does not
override *boundary* skips — mounted volumes, removable and network media (`/Volumes/`,
`/media/`, `/mnt/`, `/net/`) stay excluded, so a Time Machine disk's per-snapshot browser
caches cannot turn the carve-out into an unbounded walk.

**This widens what gets scanned.** Expect more files scanned, and potentially new detections,
in user profile directories.

### Fixed — rules needing an unavailable module counted as compilation failures

A rule that inherits `import "cuckoo"` (or any module this agent's libyara lacks) from a
shared file-level preamble had that import stripped, then failed to compile with `undefined
identifier` and was booked as a **failed rule** — inflating the failure count and making a
healthy scan look broken. This is the normal, idiomatic YARA layout, so it affected whole
rule packs at once.

Such rules are now reported as **skipped**, and skipped rules appear on the result line and in
the summary JSON so they cannot silently vanish. Classification is based on the actual compile
error, not on scanning rule text for module names — a rule hunting for the literal string
`"cuckoo.conf"` still compiles and runs normally. If *every* rule is skipped, the error now
says the agent lacks the required modules rather than reporting a compilation failure that
sends you hunting for a syntax error that does not exist.

Relatedly, module availability is no longer probed against a fixed list of eight names —
whatever the submitted rules import is probed too, so a module this agent *does* support is
no longer treated as missing.

### Fixed — progress telemetry was effectively never emitted

Progress logging was checked only inside the file-discovery loop, which almost never runs
long enough to cross the interval; enumeration is fast, and the worker threads matching file
content are what take minutes. Confirmed against the tenant: **zero** "Scan Progress" or
"Cache Performance" events had ever been recorded, on any host. It now runs on a background
heartbeat spanning the whole scan, and the default interval is **30s** (was 120s, which was
longer than many scans' active phase). The value is clamped to a 1s minimum — setting `0`
does not disable progress logging, it would have busy-spun; use a large value instead.

Two long-standing metric bugs surfaced by that fix: CPU was reported as `0.0%` forever (a
fresh psutil handle was created per sample, and psutil's first reading is always zero), and
on macOS an unguarded `io_counters()` call zeroed memory and network too.

### Fixed — other

- Monitoring toggles (`ENABLE_RESOURCE_MONITOR`, `ENABLE_PERF_MONITOR`, `ENABLE_FD_MONITOR`)
  are editable constants at the top of the file. They were previously environment variables
  only, with no constant anywhere — and Action Center cannot set environment variables, so
  they were unreachable in practice.
- Direct CLI runs print their result. Previously `main`'s return value was computed, used for
  the exit code, and discarded, so a direct invocation printed nothing at all.
- A crashed scan records `outcome: "failed"` in the summary instead of `"completed"`.
- Log retention covers the new summary JSONs and sweeps orphaned `.json.tmp` files; it
  previously matched only `*.log`, so summaries would have accumulated indefinitely.

### Breaking

1. **`scan_id` format.** Was `yara_<sha256-of-rules>`; now
   `<hostname>_<run_id>_yara_<hash12>`. The old form was identical across every host running
   the same ruleset and across re-runs, so anything grouping by `scan_id` was silently
   merging an entire fleet into one "scan". The new form is unique per run. **History
   contains both shapes**, and queries grouped on `scan_id` will not error — they will just
   group differently. No shipped widget or dashboard uses `scan_id`.
2. **`SCAN_RESULT` line shape.** It can now begin `Scan cancelled (source=…)` instead of
   `Scan completed`, gains a `| N rules skipped (module unavailable)` segment when relevant,
   and gains a trailing delivery-shortfall warning when findings did not reach the collector.
   Prefix and positional parsers need updating.
3. **Exit codes.** `SCAN ABORTED` (placeholder credentials — nothing scanned or ingested) and
   `Cancel failed` now exit **1**. `SCAN ABORTED` previously exited 0, reporting a total
   failure as success.
4. **Completion telemetry.** For a cancelled run the `scan_completion_summary` message is now
   `Scan cancelled by operator…` rather than `Scan completed successfully in …`, and the event
   carries a new `outcome` field. Saved queries keyed on the old message text will miss
   cancelled runs.

### Upgrading

1. Re-upload the script to the Action Center script library, re-applying your collector
   credentials (`DEFAULT_API_KEY` / `DEFAULT_API_ENDPOINT`) after download.
2. Confirm the console lists **two** entry points: `main` (3 inputs) and `cancel` (0 inputs).
3. Use the `cancel` entry point instead of the console Cancel button — the console button
   still hard-kills and still loses findings.
4. If you want CPU/memory dashboard data, set `ENABLE_RESOURCE_MONITOR = True` before
   uploading. Note `ENABLE_PERF_MONITOR` writes to the endpoint's local log only and sends
   nothing to the collector.
5. Review the four Breaking items against any automation that parses this scanner's output.

**The parsing rule and the XSIAM dashboards/widgets are unchanged in this release — there is
nothing to re-apply on the tenant.**

---

## xdr_yara_scanner.py v3.1.0 — 2026-08-13

Adds optional end-of-run host cleanup, and fixes progress telemetry that was effectively
never emitted. Drop-in: every new behaviour is off by default.

### Added — end-of-run host cleanup (`CONFIG_HOST_CLEANUP`, default `off`)

A one-off fleet sweep previously left every scanned host's full working directory — logs,
evidence ZIP, alert files — on disk forever; the scanner only ever trimmed its footprint
across *repeat* scans, never at the end of a run.

`CONFIG_HOST_CLEANUP` accepts `off` (default), `on_delivery`, or `always`, with
`CONFIG_HOST_CLEANUP_KEEP` (`nothing` / `summary` (default) / `evidence`) controlling what
survives. Because it deletes data, the gate is deliberately conservative:

- Only runs when the scan's outcome is `completed` — a cancelled or failed run keeps
  everything.
- Only when the run's `scan_summary` was actually written (verify-before-delete).
- `on_delivery` additionally requires the run's delivery accounting to show **nothing** lost,
  and refuses outright when both alert and dataset delivery are disabled — "nothing was
  attempted" must never be mistaken for "everything landed."
- Never touches another run's retained logs, or `rule_cache` (a cross-run cache, not this
  run's data).

`always` bypasses the delivery check by design. That is the one setting that can remove a
run's only local copy regardless of whether anything reached the tenant — choose it
deliberately.

**Caveat:** cleanup empties `failed_rules/` wholesale, which includes earlier runs'
compilation diagnostics, not just this run's.

Two Windows-only bugs were found and fixed during live validation: cleanup ran before the
log-file handles were released, and Windows refuses to delete an open file (POSIX tolerates
it, so it never surfaced on Linux). A seventh file owned by a separate logger had no `close()`
method at all. Both are fixed by closing handles immediately before cleanup dispatches.

### Fixed — progress telemetry, module probing, and metrics

The same three fixes described in the XSIAM v4.0.0 entry above, ported to this edition:
progress logging moved to a background heartbeat (it was checked only in the discovery loop
and so effectively never fired); `log_interval` default 120s → 30s with a 1s clamp; module
availability probed against what the rules actually import rather than a fixed list; and the
psutil handle primed and reused so CPU is no longer reported as `0.0%` forever, with
`io_counters()` guarded so macOS does not lose memory and network metrics too.

Note the module-probe fix changes the rule-cache key, so the first scan on each host after
upgrading recompiles rules once.

Separately, the dataset heartbeat now runs on its own thread, so liveness no longer stalls
when the directory walker is blocked on a saturated queue.

### Upgrading

**Drop-in** — `CONFIG_HOST_CLEANUP` defaults to `off`, so behaviour is unchanged until you
opt in. Expect one extra rule compile per host on the first scan (cache-key change), and
roughly 4× more local progress-log lines from the 30s interval.

### Known issue — the bundled XDR dashboard is still on the pre-v3 match grain

The standalone widget files under `widgets/xdr/` were rewritten for the v3.0.0 grain change
(one dataset row per *finding* rather than per matched offset, with the true hit total in
`match_count`). **The bundled `dashboards/xdr/YARA Scanner (Lookup).json` was not.** All 18 of
its match-related queries still use the pre-v3 shape (`count()` over rows,
`matched_length`), and none reference `match_count`.

Consequence: importing that dashboard as-is produces hit counts that **undercount by orders
of magnitude** on any rule with many string hits per file — the queries run and return data,
they are simply wrong. This is the same defect corrected on the XSIAM side in v3.0.0.

Until it is fixed, prefer the individual `.xql` files in `widgets/xdr/`, which are correct.
Note also that `Matched-Length Size Buckets` was replaced by `Match Count Buckets` (the old
`matched_length` column does not exist at the v3 grain).

---

## YARA Dataset Management pack v1.1.0 — 2026-08-12

The pack now ships all four automations its own shared-library header always claimed it did.
`YaraConsolidateCommon.py`'s first paragraph has said since v1.0.0 that "the four thin
automations (`YaraConsolidateStatus`, `YaraConsolidateApply`, `YaraReport`, `YaraCleanup`)
import from this module" — the last two did not exist. Both are added here, as verbatim
ports of `xdr_data_management.py`'s report and retention-pruning logic, in the same
hand-kept-copy style the consolidation logic was ported in (XSOAR automations cannot import
arbitrary repo files at runtime, so the pack carries its own copy and a test gate keeps the
two honest). Nothing about the consolidation playbook, its schedule, or its behaviour
changes; neither new automation is a task in it.

Suite is **217 tests, all passing** (was 125) — 83 in the new
`tests/test_pack_data_management.py` and 9 added to `tests/test_data_management.py` for the
canonical-side changes below.

### Added — `YaraReport`: read-only dataset inventory in the console

Wraps the CLI's `--report`. Lists every `yara_scanner_*` lookup dataset with kind, host and
age in whole months, and splits out the legacy, newer-schema and per-scan-consolidated
buckets. It makes exactly one API call (the dataset listing), writes nothing and deletes
nothing, so it is safe to run at any time — from a poll loop, or alongside a running
consolidation or cleanup pass. Outputs to `Yara.Report.*`, with the rendered fixed-width
table in a code fence so the War Room does not reflow its columns.

It preserves the one distinction `render_report` already drew and a raw dataset listing
cannot: an unsuffixed dataset with rotated siblings is **frozen** (a pre-rotation leftover —
rotation is on, writes moved to the dated names, nothing to do), while an unsuffixed dataset
with *no* rotated siblings is **not rotated** (rotation is genuinely off for that deployment
and the dataset grows without bound). Same shape in a listing, opposite advice.

### Added — `YaraCleanup`: retention pruning, dry run by default

Wraps the CLI's `--older-than-months` / `--delete-legacy` deletion path. **This automation
deletes whole lookup datasets and the platform has no undelete**, so the properties that
make it hard to run by accident are the feature, not the pruning:

* **Dry run by default.** The CLI's `--yes` is inverted into an `execute` argument that
  defaults to false: a bare invocation reports what it *would* delete and deletes nothing.
  Only an explicit affirmative enables deletion — an unrecognised value raises and is
  reported as a rejected argument rather than being guessed in either direction, and the
  readable output opens with `DRY RUN — nothing was deleted.` or `EXECUTED — N dataset(s)
  deleted` so the mode is never ambiguous in Job history.
* **No implicit retention window.** `older_than_months` keeps the CLI's deliberate lack of a
  default. With neither it nor `delete_legacy`, the run selects nothing, deletes nothing,
  says so, and returns before making a single API call.
* **All seven rails, on both selection paths.** Never the current month, never a
  future-dated month, never an unsuffixed dataset, never a newer schema version, never a
  name outside the `yara_scanner_*` contract, never a dataset written to within
  `min_quiet_hours`, never a dataset still holding a scan consolidation has not verified
  into a per-scan target. Rails 6 and 7 are live XQL and both **keep** the dataset on query
  error, matching the skip-to-be-safe posture of every other rail.
* **Takes the consolidation lock before deleting, in a `try`/`finally`, exactly as
  `consolidate_all` does** — same `yara_scanner_consolidation_lock` marker. Pruning and
  consolidation mutate the same shards and rails 6/7 are point-in-time checks, so a
  consolidation pass starting between the checks and the deletes would race them. A held
  lock means this pass deletes nothing and reports `lock_held_by_other_run`, mirroring how
  `YaraConsolidateApply` surfaces it. **A dry run never takes the lock** — it mutates
  nothing and must stay safe to run concurrently with anything.
* **Every skipped candidate's reason reaches the operator**, uncapped, in both the War Room
  entry and `Yara.Cleanup.skipped` — including the buckets that were never candidates at all
  (newer-schema always; legacy when `delete_legacy` is off). A dataset silently not deleted
  is indistinguishable from a bug, and "0 selected, 0 skipped" must never be how the tenant
  reports "rail 4 vetoed everything".
* **`min_quiet_hours` cannot be used to switch rail 6 off.** `0` does not relax the rail, it
  disables it — `filter_recently_written`'s `(now − newest) < 0` is false even for a row
  written a second ago. The CLI is typed by a human who can see what they typed; an XSOAR
  argument is one field on a scheduled Job, so anything below a 1h floor
  (`MIN_ALLOWED_QUIET_HOURS`, pack-only) is raised to the floor and the run says so.
* **A stricter lock-takeover posture than consolidation's.** A wrong takeover during a merge
  costs a redundant merge; during a prune it deletes data mid-copy. So on this path an
  existing marker whose row cannot be read counts as **held** rather than stale (that is
  precisely the `add_data` create-lag window right after another run took it), staleness is
  judged on a 6h window (`PRUNE_LOCK_STALE_SECS`) instead of consolidation's 2h, and any
  takeover that does happen is reported in `Yara.Cleanup.lock_taken_over` and called out in
  the War Room entry rather than passing for an ordinary uncontended pass.

### Added — `yara_scanner_cleanup_runs`, deliberately separate from the consolidation record

Neither new automation writes to `yara_scanner_consolidation_runs`. That dataset's schema
and status vocabulary (`consolidated_count`, `failed_scan_ids`,
`success`/`partial_failure`/`crashed`) describe a *consolidation* pass, and the
`Consolidation Run Health` widget reads "a row in the last ~24h" as proof the twice-daily
merge Job is alive — a report or prune row would both skew its counts and satisfy that
liveness check, masking a dead merge Job. `record_consolidation_run()` was read and judged a
bad fit rather than forced.

`YaraReport` therefore records nothing at all (writing nothing is the point of it), and each
**executed** prune writes one row to its own `yara_scanner_cleanup_runs` dataset instead:
mode, schema version, window, `delete_legacy`, `min_quiet_hours`, the selected/deleted/
failed/skipped counts, the deleted names, every skip reason, and `lock_taken_over`. The
write is best-effort — a failure to record is logged and never changes the run's outcome.
A War Room entry and XSOAR investigation context are per-run and not queryable across runs,
so without this row there is no way to answer "which datasets did we prune last month, and
why were the rest kept" for the one action in this pack that cannot be undone. No widget
ships for it; `Packs/YaraDatasetManagement/README.md` carries the XQL to read it directly.

### Fixed — `xdr_data_management.py`: `--delete-legacy` now takes the same rails as the age path

`select_legacy_for_deletion()` previously returned `list(legacy_names)` unchanged — the
"legacy" bucket went straight to deletion with none of the name-derived rails the
`--older-than-months` path applies, and without the two live-query gates. But "legacy" is
not observed, it is *derived* from `YARA_LOOKUP_SCHEMA_VER`: set that one version too high —
a typo, or automation bumping it ahead of the fleet rollout — and every live,
actively-written dataset on the tenant reclassifies as legacy. The classification alone is
no longer allowed to authorise a delete. `--delete-legacy` is now **refused outright while
any newer-schema dataset exists** (that proves the assumed version is stale — the keep-guard
`xdr_action_center.py prune-datasets` already carried, now shared), unsuffixed datasets and
per-scan consolidated targets are never blanket candidates, the current and future-month
rails apply, and `main()` runs the survivors through `filter_recently_written` and
`filter_unconsolidated` just as it does the rotated path. The signature gained
`newer_names`/`now_yyyymm` and the return became `(candidates, skip_reasons)` to match
`select_rotated_for_deletion`'s shape.

### Fixed — `MONTH_RE`'s bare `\d{6}` resolved two ambiguities the wrong way

The rotation-month regex was `^(?:(?P<host>.*?)_)?(?P<month>\d{6})$`, so *any* six trailing
digits read as a month. The comment above it claimed the ambiguous reading was the
conservative one; for two real shapes it was the opposite. A host segment like `110501`
parsed as year 1105 — an age of roughly 11,000 months, older than every retention window, so
the ambiguity resolved towards **deleting**. A trailing `HHMMSS` timestamp such as `143025`
raised `ValueError` out of `months_between`, crashing the read-only `--report` as well as the
prune. The pattern now requires a plausible `YYYYMM` (`20\d{2}` plus month `01`–`12`), so
every implausible group falls back to "this is part of the host name" — which reads as
unrotated and is therefore never a deletion candidate.

### Fixed — a per-scan consolidated target could be read as an ancient rotation shard

`parse_dataset_name()` now marks `yara_scanner_<kind>_v<N>_scan_<slug>` as `scan_target`,
using the same discriminator `xdr_consolidate.parse_shard` already applies from the other
side. Such a dataset is not a rotation shard: it has no month by design, it is immutable once
verified, and once consolidation deleted the source shards it is the **only** copy of that
scan. Marking it explicitly keeps a scan slug that happens to end in six month-shaped digits
from being aged like a rotation month, keeps consolidation's own output out of `--report`'s
"not rotated — will grow without bound" advice (it is finished, not leaking), and makes it a
permanent non-candidate on both deletion paths.

### Fixed — `acquire_consolidation_lock` gained two knobs for irreversible callers

`xdr_consolidate.py` (and the pack's copy) take `unreadable_is_held` and `on_takeover`.
The first treats an existing lock dataset whose row cannot be read as **held** instead of
stale — that state is not exotic, it is the window right after another run created the
marker, since `add_lookup_data` tolerates up to ~60s of create-lag with its retries, so the
dataset exists before its row does. The second reports a takeover to the caller so it can say
"I proceeded while another run's marker was in place" instead of logging an ordinary pass.
Consolidation's defaults are unchanged (`unreadable_is_held=False`, no callback): its cost of
a wrong takeover is a redundant merge, and parking the pipeline forever on an unreadable row
would be the worse failure. `YaraCleanup` sets both.

### Fixed — `YaraConsolidateApply` surfaces lock events in its War Room entry

Lock events exist only in the library's log stream, never in the structured result:
`acquire_consolidation_lock`'s "stale or unreadable — taking over" (which precedes
force-deleting another run's marker) and `release_consolidation_lock`'s "could not release"
(which parks every following pass until the marker goes stale). Both were invisible to
anyone reading Job history. `YaraConsolidateApply.py` now appends a `lock events:` block to
its readable output, as `YaraCleanup` does.

### Docs

`Packs/YaraDatasetManagement/README.md` gains a `YaraReport` section, a rewritten
`YaraCleanup` section opening with an unmissable statement that it deletes whole datasets and
that **the platform has no undelete**, a full argument table for each automation, the seven
rails as a numbered table, the recommended report → dry-run → `execute=true` sequence, five
new Troubleshooting rows (nothing-requested, stale-LOW `schema_version`, rail 6/7 skips, held
lock, lock takeover), and a `yara_scanner_cleanup_runs` subsection under Monitoring with the
XQL to query it. It also states that neither new automation is a task in the consolidation
playbook and that scheduling `YaraCleanup` with `execute=true` is a standing authorisation.
The root `README.md` §2 records that the rails now cover `--delete-legacy`, and §7 and the
repository-layout tree name both new automations. Pack version `1.0.0` → `1.1.0`
(`pack_metadata.json` does not enumerate content items, so nothing else in it changed).

---

## Tier 3 edge-case fixes — 2026-08-12

Ten confirmed Tier-3 gaps fixed in this pass, found through systematic edge-case review of
the consolidation pipeline's operator-facing failure modes (API key rotation, playbook
failure visibility, Action Center's full terminal-state vocabulary, heartbeat liveness under
throttling, endpoint clock skew in the consolidation time gates) — not through a live incident.
The tenth, edge case #6, was recorded as still-open in an earlier draft of this entry and is
now fixed; its section below is the authoritative account, including what it deliberately
leaves open.

### Fixed — `xdr_consolidate.py` v2.6.0: two more Action Center states recognized as terminal (edge case #2)

`TERMINAL_ACTION` (`xdr_consolidate.py:55`, was `{"COMPLETED_SUCCESSFULLY", "FAILED",
"ABORTED", "EXPIRED", "TIMEOUT", "CANCELED", "CANCELLED"}`) was missing
`COMPLETED_WITH_ERRORS` and `COMPLETED_PARTIAL` — two Action Center statuses this repo's own
`xdr_action_center.py` and the `xdr-yara-scan-test` skill's `xdr_lib.py` already treat as
terminal, confirmed from live polling. A scan whose Action Center action ended in either state
(Gate B, `action_state_for`) was invisible to `shard_is_terminal()`, which returned `False` for
it forever — it could never consolidate on its own, only get swept up later by the 24h
abandoned-scan cutoff, and only if nothing else about it looked more broken along the way.
Both states are now in the set, mirrored into
`Packs/YaraDatasetManagement/Scripts/YaraConsolidateCommon/YaraConsolidateCommon.py`'s own
copy of `TERMINAL_ACTION` so the console automations get the same fix. Verified with a new
unit test, `test_terminal_action_includes_partial_and_with_errors_states`.

### Fixed — independent heartbeat thread decouples dataset liveness from walker progress (edge case #8)

Distinct from v3.0.1's self-healing dataset recreation below (that fixed the *consequence* of
an abandoned-cutoff misjudgment; this fixes a different way a scan can go quiet in the first
place, and is the follow-up that entry's own last line pointed to). `_maybe_heartbeat()` was
previously called only from the directory-walker loop, once per directory finished.
`_enqueue_scan_path()` blocks — retrying on `queue_backoff_secs` — rather than dropping files
when the scan queue is saturated, so a large single directory on a heavily CPU-governor-
throttled host could leave the walker parked there, and the heartbeat unsent, well past the
consolidation tool's quiet period — making a scan that is still genuinely running look
abandoned or finished to the consolidation gates for no reason but throttling pressure.
`xdr_yara_scanner.py` now runs a dedicated daemon thread (`_start_heartbeat_thread` /
`_heartbeat_worker`, polling every `YARA_HEARTBEAT_POLL_SECS` seconds, default 30) that calls
`_maybe_heartbeat()` on a fixed cadence independent of walker progress. The check-and-set on
`_last_heartbeat` is now guarded by a new `_heartbeat_lock` so the walker thread and the
heartbeat thread can't both pass the interval gate and emit a duplicate `running` row.

### Fixed — `CoreApiClient` fails fast on a rotated/expired API key, and says so (edge case #47)

A revoked/rotated/expired `DEFAULT_XDR_API_KEY` previously produced a bare `HTTP 401` that
`CoreApiClient.add_lookup_data`/`delete_dataset` retried into several pointless backoff sleeps
before finally surfacing, with nothing in the repo telling an operator that a 401 here means
"check the key" rather than "transient API/network blip" — the twice-daily Job's first task
would just fail, unexplained. Both methods
(`YaraConsolidateCommon.py:706` / `:734`) now re-raise immediately on `HTTP 401` instead of
retrying. `Packs/YaraDatasetManagement/README.md` gets a new Troubleshooting table row mapping
the exact symptom (`... failed: ... HTTP 401 ...` in the Job's task error) to cause
(rotated/revoked/expired/mistyped key, or a Standard/Advanced type mismatch — the response body
alone can't distinguish these) and fix (regenerate an Advanced-type key, edit the three
`DEFAULT_XDR_*` constants, re-deliver the pack — editing the repo file alone does nothing until
it's re-imported/re-installed).

### Fixed — Task 8's placeholder is no longer the only signal, and a whole-playbook crash now leaves a record (edge case #36/#53, parts 1 and 3)

Task 8 ("Flag failures for attention") still only writes a flag into its own run's ephemeral
XSOAR context — turning that into a real push notification is a product decision, see the
next entry — but the two structural gaps under it are closed. `YaraConsolidateCommon.py`
adds `record_consolidation_run()` (`:143`), which writes one row per `YaraConsolidateApply`
pass to a new `yara_scanner_consolidation_runs` lookup dataset: `status`
(`success`/`partial_failure`/`crashed`), plus counts, failed scan IDs/reasons, and — for a
crash — the exception text. `YaraConsolidateApply.py` calls it on *both* the normal-completion
path and inside the `except` block wrapping `consolidate_all()`, writing the `"crashed"` row
*before* calling `return_error()` — which is exactly the failure mode task 8 can never record,
since `return_error` halts the whole playbook run before task 8's condition is ever evaluated.
Task 8's own `description` field in `playbook-YARA_Dataset_Consolidation.yml` now points at
this dataset and the new widget below instead of just calling itself a placeholder with nowhere
else to point.

### Documented, not fixed — no independent Job-failure alerting is provisioned (edge case #36/#53, part 4) — needs_decision

Still true, and left that way deliberately: this repo provisions no push-style alert
(Slack/email/incident) for a failed or missing Job run — no `Jobs/*.json` ships in the pack,
and task 8 remains an unwired placeholder by design, since which channel to wire it to is a
product decision, not something to invent a default for. What changed is visibility:
`Packs/YaraDatasetManagement/README.md`'s new Monitoring section says this explicitly instead
of the gap being silently undocumented, and points at the `yara_scanner_consolidation_runs`
dataset/widget as the closest thing to a health signal available today — still pull-based, an
operator has to know to look, not push.

### Fixed — new "Consolidation Run Health" dashboard widget (edge case #36/#53, part 5)

Every existing widget in this repo was scan-result-focused (matches, detections, throughput);
nothing showed whether the consolidation/maintenance pipeline itself was healthy or running at
all. New `widgets/xdr/Consolidation Run Health.xql`, added as a row on the
`YARA Scanner (Lookup)` dashboard, reads the last 20 rows of `yara_scanner_consolidation_runs`
(run time, status, consolidated/failed counts, failed scan IDs, error message). No row in
roughly the last 24h (2x the twice-daily schedule interval) means the Job did not complete a
pass recently, independent of whether task 8 flagged anything.

### Fixed — `lock_held_by_other_run` is now visible in the Job's readable output (edge case 37c)

`YaraConsolidateApply.py` previously flattened a lock collision into the same generic
`"0 scan(s) consolidated"` message as a genuinely empty pass, so an operator scanning Job run
history for the exact CLI/Job collision scenario this case investigates would see nothing
distinctive. It now branches on `result.get("lock_held_by_other_run")` and reports
`"Skipped this pass — consolidation lock is held by another concurrent run (CLI or another Job
execution)."` instead, and the pack's README Troubleshooting table documents the symptom.

### Fixed — pack-specific deployment documentation (edge case #56 part 3)

Nothing in the repo previously told an operator that `Packs/YaraDatasetManagement` needs
console Import or a pack-zip install to become Job-selectable — a raw item-level
`demisto-sdk upload` of just the playbook registers it as an invisible private draft, runnable
directly but absent from the Job-creation picker, so it looks deployed right up until someone
tries to attach it to a scheduled Job and can't find it. New
`Packs/YaraDatasetManagement/README.md` covers this (plus credentials, troubleshooting, and
monitoring); the top-level `README.md` §7 now links to it and the repo layout tree lists the
pack.

### Fixed — `xdr_consolidate.py` v2.7.0: the time gates no longer trust the endpoint's clock (edge case #6)

Recorded in an earlier draft of this section as a known gap; now closed. Both time gates —
the quiet period (`newest_row_age_ok`) and the abandoned-scan cutoff (`_gate_scan`) — measured
a scan's age as `now_ms` (server-side) minus `event_timestamp_ms`, which is stamped **on the
endpoint**. At fleet scale a wrong endpoint clock is routine, and one direction loses data: a
clock running *behind* makes a live scan's rows look hours or days old, so the cutoff sweeps
the scan as abandoned and the quiet period waves it through — and this tool then consolidates
and **deletes the shard the scanner is still uploading into**.

New `_newest_ms()` measures against the later of `event_timestamp_ms` and `_insert_time`, the
platform's own server-side ingest stamp, which stays ~"now" for as long as a scan is actually
uploading no matter what the endpoint's clock says. `_scan_stats()` gets it from
`max(_insert_time)` riding along in the existing `comp ... by scan_id` stage (measured working
on the live tenant); `_stats_from_rows()` reads it as a system column off the rows it already
pulled. New `_as_ms()` coerces whatever shape XQL returns a stamp in (int, float, numeric or
exponent string, ISO-8601) and degrades to "no signal" rather than raising — the same
type-fidelity problem `_coerce_row` exists for.

**Why `max()` and not simply replacing one stamp with the other:** `_insert_time` is a
freshness signal *only on a source shard*. Consolidation reads a shard's rows and re-writes
them into the per-scan target, which resets `_insert_time` while `event_timestamp_ms` keeps
the original scan time — measured on a real target, the gap was ~**31 days**, against 3.2s /
3.7s / 5.2s / 5.4s / 66.8s (ordinary upload latency) on real shards. Both stats helpers are
therefore fed source shards only, which `parse_shard` enforces structurally by refusing to
recognise a `…_scan_<id>` target as a shard.

Two guards keep the correction from creating a worse failure than the one it fixes, since a
value that is too *new* is unbounded rather than merely inconvenient (`now_ms - newest` goes
negative, so the quiet period can never be satisfied **and** the abandoned cutoff can never
fire — the scan is stuck and its shard undeletable forever):

- an endpoint stamp more than `SKEW_TOLERANCE_MS` (5 min) ahead of the ingest stamp is
  discarded, not maxed in — a row cannot be authored after the platform received it, so that
  is a clock running ahead, and the trustworthy stamp is used instead;
- a server stamp implausibly far in the future of `now_ms` (the tell for a unit mismatch, e.g.
  microseconds) is dropped in favour of the endpoint stamp, so an unexpected platform
  representation degrades to pre-fix behaviour instead of stalling every scan on the tenant.

`_gate_scan` also gains a **backstop** (`DEFAULT_SKEW_BACKSTOP_SECS`, 7 days) measured on the
endpoint stamp alone, which nothing but the endpoint itself can re-arm. The cutoff's whole
purpose is to guarantee nothing blocks cleanup forever, and `_insert_time` only means "when
this row was ingested" as long as nothing rewrites the shard — this tool's own
`_cleanup_verified_scan_rows` rewrites shards that may still hold other scans' rows. Whether
the platform implements that removal as a rewrite (which would re-stamp the survivors) is
**not verified** — settling it needs a destructive `remove_lookup_data` against a real shard —
so the backstop makes the answer not matter: past a week of endpoint silence, a non-terminal
scan is abandoned and the quiet period is satisfied regardless. The trade is explicit: skew
protection is given back only for a clock wrong by more than a week, which is far rarer than
one wrong by hours.

Mirrored verbatim into
`Packs/YaraDatasetManagement/Scripts/YaraConsolidateCommon/YaraConsolidateCommon.py` — that
copy, not `xdr_consolidate.py`, is what the scheduled `YaraConsolidateApply` Job actually runs,
so a fix landing only in the standalone module would leave the data-loss window fully open in
production. New `test_pack_copy_gate_logic_matches_xdr_consolidate` now compares the two files'
whole ported core statement-by-statement (docstrings and comments stripped), so the copies
cannot silently drift again. As with every pack change, it only takes effect once the pack is
re-delivered (console Import or pack-zip install) — editing the repo file changes nothing on
the tenant.

Also in this change: `build_terminal_map`'s `newest_ms` goes through the same skew-proof path
(and through `_as_ms`, so a non-numeric stamp no longer raises `ValueError` and aborts a whole
pass), so the value sitting next to `terminal` cannot silently reintroduce this bug if a future
caller reaches for it; `_scan_stats`/`_stats_from_rows` log when a shard returns no usable
`_insert_time`, so a silently-inactive protection is visible in the run log; and the fake
client's aggregation in `tests/test_consolidation.py` now derives its response from the query
text instead of hardcoded output keys — previously, reverting the query to its pre-fix form or
renaming the alias disabled the fix completely with the suite still green.

**Residual, deliberately open:** an endpoint whose clock runs *ahead* on a platform that
returns no usable `_insert_time` still defers indefinitely, because there is then no
trustworthy stamp to correct against (clamping to `now_ms` would reset the age to zero every
pass and livelock the same way). `_gate_scan` logs that case distinctly so it is diagnosable
rather than silently permanent.

### Upgrading

**Mostly drop-in.** `xdr_consolidate.py` ships from this pass as **v2.7.0**. Its
`TERMINAL_ACTION` change only widens what already counts as terminal — no config or dataset
changes. The edge-case-#6 gate change is also
drop-in but is a **behavioural** change to when a scan is consolidated: a scan whose endpoint
clock is wrong now waits longer (and, in the ahead direction, is no longer stuck forever),
which is why the module version moves to 2.7.0 — a tenant can tell a skew-protected
consolidator from an unprotected one by that number. `xdr_yara_scanner.py`'s heartbeat thread
is internal; the new `YARA_HEARTBEAT_POLL_SECS` env var (default 30s) is optional. The
`Packs/YaraDatasetManagement` changes (the mirrored gate fix, `record_consolidation_run`, the
new `yara_scanner_consolidation_runs` dataset, the new widget, `CoreApiClient`'s fail-fast 401)
only take effect once the pack is re-delivered via console Import or pack-zip install (see its
README's Deployment section) — editing the repo files alone changes nothing on the tenant.

Verified with the full suite: **125/125** passing (`python3 -m pytest tests/ -q`).

---

## xdr_consolidate.py v2.5.0 — 2026-08-12

### New — immediate per-scan row cleanup closes the double-counting window (edge case #51)

Root-cause half of edge case #51 (the dashboards' `dedup` clause from a prior pass was the
defense-in-depth half, and stays as-is — not touched here).

`run_consolidation` only ever deleted a per-host *shard* once **every** `scan_id` it had ever
held was verified into its own per-scan target (the "Deletion pass" at the end of the
function). A shard can hold many `scan_id`s — a host re-scanned repeatedly within the same
month shares one dataset — so a scan whose own target had already been written and verified
could still sit duplicated inside its source shard for a long time, waiting on every *other*
scan sharing that shard to also finish. Any dashboard querying the `yara_scanner_matches*`
wildcard during that window double-counted that scan's findings: once from the still-live
shard, once from the already-complete per-scan target.

`run_consolidation` now calls the already-existing `client.remove_lookup_data(shard, [{"scan_id":
scan_id}])` against every source shard the instant a scan's target verifies — on **both** the
idempotent already-complete short-circuit (a re-run finding the target already holds exactly
this scan's rows) and the fresh-write-verified path, so a scan's rows never wait around in a
shard it's already been safely copied out of. This is deliberately the idempotent path that
matters most: it's exactly where a *retry* of a previously-failed cleanup call naturally
lands — run 1 writes and verifies the target but the cleanup call throws (network blip), the
source rows survive; run 2 sees the target already complete and, without this, would never
retry the cleanup that failed last time. A follow-on case surfaced in testing: a scan whose
rows span two source shards (a run straddling a monthly-rotation boundary) where cleanup
succeeds on one shard but fails transiently on the other — the next run recomputes the source
row total from whatever shards are *currently* live, which would now be permanently smaller
than the target's fixed, correct count. Rather than misreport that forever as a data-integrity
`count_mismatch` and give up retrying, this shape is now recognized as "cleanup already landed
on some sources" and stays verified, retrying cleanup on what's left.

This is **complementary to, not a replacement for**, the existing whole-shard `delete_dataset()`
call at the end of the function, which is unchanged: row-level removal shrinks the
double-counting window immediately; the shard-level delete still eventually removes the
dataset object itself once every scan sharing it is also done. A `remove_lookup_data` failure
is caught, logged, and otherwise ignored — it never crashes the run, never flips a scan's
`plan["ok"]` (the scan's data is already safely verified in its target; only the redundant
source-row cleanup failed), and never blocks the eventual whole-shard delete. Purely a
dashboard-accuracy improvement — data safety is unaffected either way. Scoped to
`kind=="matches"` only: a `"scans"` shard's rows are the sole source of `build_terminal_map`'s
per-`(scan_id, host)` lifecycle signal, and stripping a verified scan's status row out early
would make a still-pending sibling scan sharing that shard lose its terminal signal and get
misclassified as stuck. Stays strictly sequential, matching `remove_lookup_data`'s own
"NOT concurrency-safe — the caller must serialize" contract and `run_consolidation`'s existing
single-sequential-writer design (the unrelated `_delete_many` concurrency at the very end, for
different *datasets*, is untouched).

Mirrored into `Packs/YaraDatasetManagement/Scripts/YaraConsolidateCommon/YaraConsolidateCommon.py`
(the XSOAR-side hand-kept port of this same logic, including its own `CoreApiClient.
remove_lookup_data`), so the console automations (`YaraConsolidateStatus`/`YaraConsolidateApply`)
get the same fix.

Verified with 8 new unit tests covering same-run cleanup on a fresh write, a shard holding a
second still-pending scan keeping the shard but losing only the ready scan's rows, dry runs
touching nothing, a cleanup failure not crashing or flipping `ok`, the idempotent path
retrying a previously-failed cleanup, a scan spanning two source shards getting cleanup on
both, `kind=="scans"` never stripping a lifecycle row out from under a pending sibling, and
the transient-partial-failure case above resolving cleanly over three simulated runs — full
suite now **101/101** passing.

### Upgrading

**Drop-in.** No config or dataset changes. The client already exposes `remove_lookup_data`
(already live and used elsewhere in this repo, e.g. `xdr_action_center.py`'s pruning tooling);
`run_consolidation` now just calls it automatically as an extra step after each scan verifies.

---

## xsiam_yara_scanner.py v3.0.0 — 2026-08-12

**Breaking.** First versioned release of the XSIAM edition since v2.0.0 (2026-08-03) — this
edition had never had a changelog entry before. Redesigns the `yara_match` webhook event's
grain, fixes several dashboard widgets that were silently empty, and tunes shutdown
behaviour. Everything below was found and fixed in the course of investigating one customer
report of an undercounted dashboard, then verified independently by a second, adversarial
code-review pass after the first round of live testing.

### Changed — one `yara_match` event per (rule, file) finding, not per matched-string offset

The original design queued one webhook event per matched STRING OFFSET. One loosely-written
rule matching one large file (a growing Windows event log, in the case that surfaced this)
can produce tens of thousands of offsets, and each one became its own HTTP POST — measured
live on the sandbox tenant: 36,213 upload items backlogged in one scan's delivery queue, the
large majority from one rule matching one file. `xdr_yara_scanner.py`'s companion lookup
dataset had the identical bug (also one row per offset) and is fixed in the same commit —
this is not a case of porting an already-proven fix from one edition to the other; both
editions had the same design flaw and both are corrected together here.

`add_match()` now folds every offset for a given (rule, file) into **one** event, adding:
- `match_count` — the TRUE total offsets matched for that finding, never sampled or capped.
- `truncated` — `true` when the samples below hold fewer entries than `match_count`.
- `offsets` / `strings` — JSON arrays, a sample of up to `MAX_MATCH_SAMPLES_PER_FINDING`
  (default 50, override via `YARA_MAX_MATCH_SAMPLES`) offsets and their matched strings,
  aligned 1:1.
- `match_ids` — JSON object of TRUE, uncapped counts per YARA string identifier (e.g.
  `{"$ps": 20649, "$enc": 55}`) — exact, but keyed by the rule's internal identifier, not the
  literal matched text.
- `match_scope` — `"rule"` or `"string"`, distinguishing a condition-only match from one with
  actual string hits.
- `file_name` / `rule_id` — aliases of the existing `filename`/`rule` fields, added so the
  dashboard widgets below can query stable, self-explanatory column names.

**Removed:** the old `match` field (one specific string identifier per row) no longer exists
in the event payload — it only ever meant something at the old per-offset grain. Any ad-hoc
query built directly against the raw `match` field (rather than through the shipped
dashboards) will need to move to `match_ids` instead.

**Requires updating the XSIAM parsing rule** to extract these fields — now at
[`parsing_rules/xsiam/parsing_rule.xql`](parsing_rules/xsiam/parsing_rule.xql) (moved out of
`docs/xsiam/`, see below). This is a manual console step; there is no parsing-rule API.
Updated the 5 affected dashboard widgets and `dashboards/xsiam/YARA Matches.json` to
`sum(to_integer(match_count))` instead of `count()`, and to explode the sampled `strings`
array where a per-string breakdown is needed.

**Live-verified against the sandbox tenant on 2026-08-12, after the parsing rule was
updated**, including the pathological case reproducing naturally rather than being
re-staged: a fresh scan of the same event-log directory that originally surfaced the bug
landed exactly 3 dataset rows for 3 findings, two of them genuinely truncated (20,759 and
13,013 true offsets each) with `match_ids` summing EXACTLY to `match_count` in every case —
the hardest correctness bar for this design, since the per-string counts are uncapped while
the offset/string samples are not. All 5 widget queries then ran live against that data with
correct numbers (Hot Hosts: 33,784 = 12 + 13,013 + 20,759, matching the sum of the 3
findings exactly).

**Caveat:** parsing rules are not retroactively applied to already-ingested raw logs, so any
`yara_match` row ingested before you update the tenant's parsing rule permanently shows `null`
for these fields. Widgets will show gaps for old hosts/data until fresh scans run under the
new rule — this is an XSIAM platform behaviour, not something this fix can work around.

### Fixed — three dashboard widgets that were silently empty

Found and fixed alongside the grain-split work above, all three because the widget's filter
referenced a column the scanner never actually populated at that level:

- **"Capacity vs Backpressure"** filters on a top-level `active_workers` column;
  `log_scan_progress()` only ever nested it under `metrics.active_workers`. Now also emitted
  at the top level.
- **CPU/memory widgets** filter on top-level `proc_cpu_percent`, `proc_memory_mb`,
  `sys_cpu_percent`, `sys_memory_used_percent`; `SystemResourceMonitor` only nested these
  under `resource_data['process']`/`['system']`. Now also flattened to the top level.
- **Resource monitoring stopped after file discovery, not after scanning finished.**
  `_perform_enhanced_cleanup()` stopped `resource_monitor`/`stats_manager` as soon as file
  discovery completed — a different, earlier moment than when the worker threads actually
  finish matching everything still queued, which on a large scan can be minutes apart. Moved
  both `stop_monitoring()` calls to fire after the worker-thread join loop instead, so
  resource telemetry now covers the scan's real duration. Same fix ported to
  `xdr_yara_scanner.py` (same bug, same root cause, XDR explicitly authorized).

### Fixed — critical lifecycle events could take minutes to actually deliver

The delivery queue backlogs during a heavy scan, and "Target scan completed"/"Worker thread
startup completed" were previously queued behind that same backlog like any other telemetry
log — measured live: a 12s scan's own completion event took ~246s to actually land. Added
`LogManager._log_critical()`: an immediate synchronous send attempt for these two dashboard-
critical, once-per-scan(-target) signals, falling back to the normal async queue only if the
direct send fails. Verified live: 246s → 1s.

### Changed — shutdown drain budget scales with backlog instead of a flat timeout

Ported XDR's proportional drain-budget design (`DRAIN_MIN_SECS`/`DRAIN_PER_ITEM_SECS`/
`DRAIN_MAX_SECS`, env-overridable) to all 4 of this edition's independent drain sites
(`LogManager.stop_logging` + 3 uploader classes) — a flat timeout was either too short for a
heavy backlog (events dropped, not delayed) or wastefully long for a light one. Tuned down
from an initial, too-generous `DRAIN_MAX_SECS=300` after a live 4-host concurrent test showed
3 of 4 hosts hit Action Center `TIMEOUT` (each of the 4 drain sites approaching 300s
sequentially exceeded the snippet's own timeout) — final values (15 / 0.3 / 60) re-verified
live with all 4 hosts completing cleanly.

### Fixed — placeholder-credential abort check was a tautology

`main()`'s abort guard compared `API_ENDPOINT`/`API_KEY` against `DEFAULT_API_ENDPOINT`/
`DEFAULT_API_KEY` after both had already been reset TO those same defaults a few lines
earlier — always true either way, so a scanner shipped with un-edited placeholder
credentials never aborted and instead failed every single upload silently. Added fixed
sentinel literals to compare against instead.

### Fixed — second-round hardening (independent adversarial code review)

An exhaustive, independently-verified review pass over this release's diff surfaced more
real issues, all fixed here:

- `_log_critical()`'s synchronous send never updated `upload_stats['successful_uploads'/
  'failed_uploads']` in any outcome, undercounting the final accounting, and swallowed a
  non-2xx response or a send exception with no logged error before silently falling back to
  the queue — including the case where the fallback queue itself wasn't available (thread not
  alive, or the queue put failing), which previously dropped the log with zero trace at all.
  Every outcome now updates stats and logs something before the method returns.
- The same method could double-deliver a critical event on an ambiguous outcome (e.g. a read
  timeout after the collector already processed the request) — no idempotency key exists to
  dedupe this, so rather than pretend to solve it, the ambiguous case is now logged explicitly
  instead of disappearing silently, consistent with this scanner's existing "honest books over
  exact-once delivery" philosophy elsewhere.
- `MAX_MATCH_SAMPLES_PER_FINDING` and the 3 `DRAIN_*` env-var overrides were parsed with bare
  `int()`/`float()` at module import time — a deployer typo (e.g. `YARA_DRAIN_MAX_SECS=60s`)
  crashed the entire scanner before `main()` ever ran, with zero telemetry. Added `_env_number()`:
  falls back to the default and logs a warning on a malformed value instead of crashing.
- `dashboards/xsiam/YARA Matches.json`'s `widgets_data[]` catalog copies of the 5 grain-
  affected widgets were never patched — only the `dashboards_data[].layout[]` copies were,
  earlier in this same release. Anyone editing/reusing a widget from the widget library (not
  just viewing the dashboard) would have silently gotten the old, wrong query. Patched to
  match.

### Known gap (not fixed here)

`widgets/xsiam/Matches Over Time.xql`'s "by Severity" breakdown can never show more than one
series: `add_match()` hardcodes `level="INFO"` on every `yara_match` event and never surfaces
the rule's actual `threat_level` as a queryable column. Pre-existing, not introduced by this
release — left as a follow-up since fixing it changes `level` semantics for every log type,
not just matches.

### Also available, not yet wired into a widget

`add_match()` also emits `string_match_count`, `threat_level`, `dateOfScan`, `file_sha256`,
and `file_creation_time` into every `yara_match` event, but the parsing rule doesn't promote
any of them to a bare column and no shipped widget queries them. They're reachable today via
`json_extract_scalar(data, "$.file_sha256")` etc. for custom queries; promoting them to real
columns is a natural follow-up if you build on top of this dashboard.

### Upgrading

1. Update the tenant's XSIAM parsing rule from
   [`parsing_rules/xsiam/parsing_rule.xql`](parsing_rules/xsiam/parsing_rule.xql) (console
   step, no API).
2. Re-import or re-add the 5 affected widgets/`YARA Matches.json` dashboard if you've
   customized them locally.
3. If you have any custom query referencing the old `match` field directly, move it to
   `match_ids`.
4. Expect a gap for historical data — old rows won't retroactively gain the new fields.

No other config or dataset changes required.

---

## Docs — 2026-08-12

### Clarified — verify-before-delete is row-count parity, not content verification (edge case #52)

`README.md`, `docs/xdr/topics/Datasets_and_Maintenance.md`, and the
`playbook-YARA_Dataset_Consolidation.yml` description now say explicitly what
"verify before delete" checks and doesn't: a per-scan target's row count matching its
sources' combined count is treated as fully consolidated, but that is parity, not a
content comparison — a corrupted or duplicated write with a matching count would still
pass. Combined with the platform having no undelete or dataset versioning, a bad delete
from either `xdr_data_management.py --older-than-months` or `--consolidate` cannot be
recovered after the fact. No code changed; this is documentation only, prompted by the
same edge-case review that produced the two new pre-delete gates below.

---

## xdr_consolidate.py v2.4.0 — 2026-08-12

### New — per-scan failure/block reasons surfaced, not just counted (edge case #19)

`consolidate_all()` and `check_consolidation_status()` previously returned only
`failed_scan_ids`/`blocked_scan_ids` — a bare list of which scans need attention, with no
indication of *why*. An operator (or the XSOAR playbook) seeing `blocked_count: 3` had to
re-run the tool by hand with logging cranked up just to learn whether the cause was a row
ceiling worth raising, a genuine count mismatch worth investigating, or something else
entirely — three very different next actions collapsed into one undifferentiated signal.

Both functions now also return `failed_reasons`/`blocked_reasons`: a `{scan_id: reason}`
map built from the same per-scan `reason` field `run_consolidation()` was already
producing internally but discarding at the aggregation step. No new failure modes are
introduced or classified differently — this is pure visibility, not a behavior change.

`YaraConsolidateStatus`/`YaraConsolidateApply` (the XSOAR automations wrapping this
module) now cite the specific reason per scan_id in their human-readable output instead of
a generic "row ceiling or count mismatch" message, and declare the new context paths in
their `.yml` output specs.

Verified with 2 new unit tests (`test_consolidate_all_reports_why_a_scan_failed`,
`test_check_consolidation_status_reports_why_a_scan_is_blocked`) plus the one existing test
whose exact-dict assertion needed the new key added — 93/93 total passing.

### Upgrading

**Drop-in.** Both new fields are additive keys on the existing return dicts; nothing that
previously read `failed_count`/`failed_scan_ids`/`blocked_count`/`blocked_scan_ids` needs
to change.

---

## xdr_data_management.py v2.1.1 — 2026-08-12

### New — two extra safety gates before deleting a rotated shard (edge cases #16, #19)

`--older-than-months` selected purely on the dataset's name (its `_YYYYMM` suffix) and the
current calendar month. Found through systematic edge-case review, not a live incident:
two ways that selection could still delete a dataset a scan or the consolidation tool
actively needed.

- **`filter_recently_written`** (edge case #16): a shard's rotation suffix reflects when it
  was *created*, not when it was last *written*. A long-running scan against a host whose
  shard rotated months ago keeps writing to that same (now "old-looking") dataset name
  until the scan finishes — `--older-than-months` had no way to tell "old name" from
  "actively being written right now." This function queries each candidate's newest row
  via XQL and drops it from the delete list if that row is younger than `--min-quiet-hours`
  (default 24h), regardless of how old its calendar label is.
- **`filter_unconsolidated`** (edge case #19): a shard can still hold a scan_id that
  `xdr_consolidate.py` has not yet folded into a per-scan target — most often because that
  scan tripped the row ceiling, or was never run through consolidation at all. Deleting
  such a shard on a pure age basis would permanently lose that scan's findings with no
  warning. This function checks, per scan_id in the candidate shard, whether a matching
  per-scan target exists with an equal row count, and drops the shard from the delete list
  if any scan_id inside it isn't fully, verifiably consolidated yet.

Both functions default to **skipping (keeping) the dataset** on any XQL error rather than
deleting — "skip to be safe," the same posture every other guard in this module already
takes. Wired into the `--older-than-months` path in `main()`, after
`select_rotated_for_deletion` and before deletion; each skip reason is included in the
existing report output alongside the other rails (current-month, future-clock-skew,
not-rotated).

Verified with 8 new unit tests against an in-memory fake XQL client (still writing,
genuinely quiet, no rows at all, query-error-skips-safe for the first function;
never-verified, fully-verified, already-empty, foreign-name-passthrough for the second) —
32/32 in `test_data_management.py`, 93/93 across the full suite.

### Upgrading

**Drop-in for `--report`/dry runs** (nothing deletes by default). For scheduled
`--older-than-months --yes` runs: the new gates only make deletion *more* conservative, so
existing automation keeps working, just with fewer false-positive deletions. New optional
flag: `--min-quiet-hours` (default `24.0`) — raise it if your scans can legitimately run
longer than a day against a single host.

---

## xdr_consolidate.py v2.3.0 — 2026-08-12

### New — overlap guard against concurrent consolidation runs (edge case #31)

`consolidate_all`'s intended protection against two runs overlapping is the XSOAR Job's own
"don't trigger a new instance" queue-handling setting — a deployment-time console setting
this code cannot verify is actually configured. If it's missing or fails, two overlapping
runs would both write to the *same* per-scan target dataset concurrently — exactly the
collision per-host sharding exists to prevent (measured elsewhere in this project: 87% row
loss at 8 concurrent writers to one dataset).

`consolidate_all` (and the `xdr_data_management.py --consolidate` CLI) now takes a
best-effort lock before any write pass: `acquire_consolidation_lock` creates a marker
dataset and relies on `create_lookup_dataset` distinguishing a fresh create from an
already-exists response (confirmed live against the real API — `{"dataset_name": ...}` vs
`{"status": "exists"}`). A second concurrent call sees the marker already exists, backs off
immediately (`lock_held_by_other_run: true` in its return value, nothing touched), and the
first call releases the lock in a `finally` block when it's done. A stale lock (holder
crashed without releasing, default 2h) is detected by age and taken over rather than
blocking forever.

This is explicitly **not** a true distributed lock — there's an inherent check-then-act
window between one caller's create call and another's. It's defense in depth for the common
failure (a stuck or misconfigured scheduler), not a correctness guarantee under a genuine
simultaneous race. Dry runs (`check_consolidation_status`, `--consolidate` without `--yes`)
never touch the lock — they don't write or delete anything, so they're safe to run
concurrently with anything.

Verified with 7 new unit tests (fresh acquire, blocked-when-held, stale-lock takeover,
release-then-reacquire, `consolidate_all` skipping cleanly when locked, dry runs ignoring
the lock entirely, and the lock releasing after a normal run completes — 83/83 total
passing) and live against the real tenant: manually held the lock, confirmed a concurrent
`consolidate_all` call backed off with `lock_held_by_other_run: true` and touched nothing,
released it, and confirmed the next call proceeded normally.

### Upgrading

**Drop-in.** No config or dataset changes — the lock is entirely internal, self-cleaning,
and only engages on write passes.

---

## v3.0.1 — 2026-08-12

Fixes a data-loss bug in the lookup-dataset write path, found through systematic edge-case
testing of the consolidation tool's abandoned-scan cutoff (not through customer reports).
No config or dataset changes required to upgrade.

### Fixed — recreate the lookup dataset when a write finds it missing mid-scan

`LookupDatasetUploader._ensure_datasets()` runs once, at scan startup. If the dataset it
created is deleted *after* that — most plausibly by `xdr_consolidate.py`'s abandoned-scan
cutoff misjudging a still-running scan as abandoned (its gate only looks at row age, not
whether the scan is actually still executing), but equally by any operator or tool deleting
it by hand — every subsequent `add_data` call failed with `HTTP 400 "Dataset not found"`
and was silently dropped for the rest of the scan's lifetime. No retry, no recreation,
findings gone.

`_send_batch()` now recognizes this specific failure (`HTTP 400` + `"not found"`), calls
`_ensure_one()` to recreate the dataset, and retries the batch once. Bounded to a single
recreate attempt per batch so a genuinely broken create call can't loop forever.

**Live-reproduced and fixed, not just code-traced.** Deliberately deleted a running scan's
own lookup dataset mid-flight (twice — once via the abandoned-cutoff race on `xdragent2`,
once by deleting the dataset directly on `xdr-agent` while tailing its log over SSH) and
confirmed both halves:

- **Pre-fix:** the dataset never reappeared; the scanner kept running but its per-host
  matches dataset stayed gone for the rest of the scan.
- **Post-fix**, from the scanner's own log:
  ```
  Lookup batch failed (HTTP 400, dataset not found) - '...' appears to have been deleted
  mid-scan; recreating and retrying this batch once.
  Lookup batch ok (55 rows): added=55, updated=0, skipped=0
  ```
  12 seconds from failure to recovery; every batch after that succeeded normally for the
  rest of the scan.

Verified locally first with mocked HTTP responses (recreate-once-then-succeed, and
recreate-once-then-still-fails-cleanly, both asserted) before the live reproduction —
76/76 unit tests passing throughout.

The abandoned-cutoff misjudgment itself (`xdr_consolidate.py`'s gate not checking whether
the scan's Action Center action is actually still running before applying its age-based
cutoff) is not fixed by this change — this is a scanner-side safety net that makes the
*consequence* non-destructive, not a fix to the gate's own precision. That remains a
follow-up.

---

## v3.0.0 — 2026-08-11

**Breaking.** Redesigns the matches lookup dataset's row grain. Supersedes v2.1.1's row-cap
fix (same day) with a fix at the root instead of a cap on the symptom.

### Changed — matches dataset is now one row per (rule, file) finding, not per offset

v2.1.1 addressed the pathological-row-explosion bug (see its entry below) by capping how
many *rows* one finding could emit. Further discussion of the tradeoffs that cap carried —
sampling order, no queryable truncation flag, dataset row count still unrelated to finding
count — led to a better fix: stop writing one row per matched offset at all.

`yara_scanner_matches_v3_<host>_<YYYYMM>` now writes exactly one row per (rule, filename)
match — the same grain the alert channel has always used. Every matched offset for that
finding folds into the row instead of becoming its own row:

- `match_count` — the TRUE total offsets matched, always accurate, never sampled
- `truncated` — true when the embedded sample below is less than `match_count`
- `offsets` / `strings` — JSON arrays, a sample of up to `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX`
  (default 50) offsets and their rendered matched strings, aligned 1:1
- `string_ids` — JSON object of TRUE, uncapped per-string-identifier counts (e.g.
  `{"$ext2": 12, "$note1": 3}`), for rules with multiple string variables

The old per-offset columns (`offset`, `match`, `matched_length`, `string` as a single value)
are gone from `_v3`; `_v2` data keeps them and remains queryable at its old grain. This is
why it's a major bump: any dashboard or saved query built against `_v2`'s flat `offset`
column will not find that column on `_v3` rows.

Re-verified live against the same tenant and the same pathological file
(`Microsoft-Windows-PowerShell%4Operational.evtx`, one rule, now 19,537 offsets — the file
grew between test runs since it's a live event log): the finding is one row, `match_count`
correctly reports 19,537, `truncated=true`, and `string_ids` sums back exactly to
`match_count` (`{"$ps": 3501, "$enc": 424, "$hide": 14, "$np": 475}` = 4,414 on the
`Diagtrack-Listener.etl.004` finding in the same run). Total dataset rows for the full
53-match scan: **53** — one row per finding, matching the scan summary exactly.

### Fixed — `xdr_consolidate.py` now schema-version-aware (2.1.0 → 2.2.0)

Consolidation (`run_consolidation`) selected its shards by matching only `kind`
(`matches`/`scans`), not schema version — on a tenant with both `_v2` and `_v3` matches
shards (any tenant mid-rollout of this scanner version), a `ver="2"` consolidation run would
have picked up `_v3` shards too and mis-projected their aggregated `match_count`/`offsets`/
`string_ids` fields onto the `_v2` schema's per-offset columns, silently corrupting the
merge. Shard selection now filters by `(kind, ver)` together, and `check_consolidation_status`
/`consolidate_all` fan out across every known version by default
(`KNOWN_MATCHES_SCHEMA_VERSIONS = ("2", "3")`) — `run_consolidation` itself still handles one
version per call (breaking change: its `ver`/`vers` split is new; existing callers that never
passed `ver=` explicitly are unaffected). The XSOAR automations
(`YaraConsolidateStatus`/`YaraConsolidateApply`, via `YaraConsolidateCommon.py`, kept in sync
with this file by hand) and the `xdr_data_management.py --consolidate` CLI both pick this up
automatically — no argument changes needed on either.

Verified with 5 new unit tests (mixed-version shard isolation, correct per-version target
naming/schema, both wrapper functions covering both versions by default — 75/75 total passing).

### Fixed — `consolidate_all`/`check_consolidation_status` now process matches before scans

A second bug, found live while testing the fix above: both functions default to
`kinds=("scans", "matches")`. Consolidating "scans" first deletes the per-host scans shard
once verified — but that shard is the ONLY source of terminal-lifecycle truth
(`build_terminal_map` rebuilds it fresh from whatever scans shards still exist on every
`run_consolidation` call). By the time the separate "matches" pass ran moments later in the
same `consolidate_all` call, the scans evidence was already gone, so a scan that had
genuinely finished got deferred as `host_not_terminal ("no lifecycle row")` — a false
negative caused by the tool's own ordering, not a real gate failure. Reproduced with a
minimal single-host/single-scan unit test (`test_consolidate_all_processes_matches_before_scans`,
76/76 total passing) and fixed by reordering the default to `("matches", "scans")` everywhere
it appears (both wrapper functions here, `YaraConsolidateCommon.py`, and the
`xdr_data_management.py --consolidate` CLI loop). This predates `_v3` entirely — it affects
any consolidation run that processes both kinds together, so it would eventually have hit a
`_v2`-only tenant too, just less easily reproduced (needs a host+scan combination where
nothing else keeps the scans shard alive past that one scan).

Verified end-to-end against the tenant's actual `_v3` data (scan `xdragent_..._104813_...`,
the real scan this session's `_v3` testing produced — an earlier live-verification attempt
targeted the wrong scan_id by mistake, which is what surfaced this ordering bug in the first
place): matches (53 rows) and scans (2 rows) both consolidated cleanly into
`yara_scanner_{matches,scans}_v3_scan_<scan_id>` in one pass, zero deferrals, sources
verified and deleted. Row shape confirmed correct — `match_count`, `offsets`, `strings`,
`string_ids`, `truncated` all present and internally consistent (`string_ids` sums to
`match_count` on every row checked).

### Upgrading

**Not drop-in — dashboards/queries built on `_v2`'s per-offset columns need updating** before
relying on `_v3` data (§3.2 README covers the caveats: JSON-encoded fields aren't natively
XQL-filterable per-offset the way the old flat `offset` column was). Consolidation is
drop-in: `xdr_consolidate.py` 2.2.0 handles `_v2` and `_v3` shards correctly and
automatically in the same pass.

---

## v2.1.1 — 2026-08-11

Fixes a dataset-upload starvation bug found during live fleet testing. No config or
dataset changes required to upgrade.

### Fixed — per-finding lookup-dataset row cap

An unanchored or short string pattern (a bare word, a common byte pair) can occur
thousands of times inside *one* file. Measured live: one test rule's `"powershell"`
substring against a single `Microsoft-Windows-PowerShell%4Operational.evtx` produced
**33,118 offsets from that one (rule, file) pair alone**, on a fleet scan where 3 of 8
concurrently-scanned endpoints lost data — including one host that lost **100% of its
matches and alerts** — because the pathological finding consumed the entire upload
retry budget before the scan's other, legitimate findings ever got a turn. The alert
channel already had a storm cap (`CONFIG_ALERT_MAX_PER_SCAN`, since day one); the
lookup-dataset write loop had none.

`CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` (default `50`, `≤0` disables) now bounds dataset
rows per (rule, file) finding the same way the alert cap bounds per-scan alert volume.
Local artifacts (the JSON results file, the per-rule alert `.txt` log) are unaffected —
only the network upload is capped. Truncation is logged locally
(`Rule '<rule>' matched <file> at <N> offsets; capped lookup-dataset upload to the
first 50`); see the README §3.2 caveats section for what this does and does not
guarantee (sampling order, no queryable truncation flag, per-file not per-scan scope).

Re-verified against the same live tenant after the fix: the three previously-affected
files now cap at exactly 50 rows each, and all three previously-degraded endpoints
delivered cleanly. A fourth endpoint's total delivery failure in the same test turned
out to be an unrelated, pre-existing network-reachability issue (that host's outbound
HTTPS to the XDR API times out at the TCP-connect stage) — confirmed via its local
upload log, not something this or any scanner-side fix can address.

### Upgrading

**Drop-in.** No config or dataset changes. `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` ships
with a sensible default; tune it only if you have rules that legitimately need more
than 50 samples per file (see README §3.2 for the tradeoffs).

---

## v2.1.0 — 2026-08-06

Adds dataset consolidation and a macOS telemetry fix. The scanner's scan/deliver
behaviour is unchanged — nothing about running scans differs from v2.0.0.

### Upgrading

**Drop-in.** No config or dataset changes. `xdr_consolidate.py` is a new companion file;
`xdr_data_management.py` gains a `--consolidate` action. If you never run consolidation,
nothing changes.

### New — dataset consolidation (`xdr_data_management.py --consolidate`)

Folds the per-host lookup datasets a scan produces into **one dataset per scan**
(`yara_scanner_<kind>_v2_scan_<scan_id>`) and deletes the per-host shards, so a large fleet
no longer leaves two datasets per host accumulating on the tenant. The scanner still writes
per-host (that is what avoids the `add_data` write collision); consolidation is a separate,
optional maintenance pass. Dry run unless `--yes`.

Safety, because it deletes datasets:

- **One sequential writer** to each target, so consolidation is never exposed to the
  concurrent-write collision it is cleaning up after.
- **Verify before delete** — a shard is deleted only after the target's row count equals the
  sum of the sources. Every failure mode found in testing tripped this and preserved the
  data rather than losing it.
- **A shard is deleted only when every scan in it is consolidated** — a host re-scanned in
  the same month shares one dataset, so deleting after a single scan would destroy the
  others. Re-runs are idempotent.
- **Abandoned-scan cutoff** — a console-cancelled scan leaves its lifecycle row stuck at
  `running`/`initiated` forever (see the known limitation in v2.0.0), which would block its
  shard from ever being cleaned. A non-terminal scan whose newest row is older than 24 h
  (`--abandoned-after-hours`, comfortably past the 6 h action timeout) is treated as
  abandoned so it stops blocking cleanup; its partial matches are still consolidated, not
  dropped.
- **Row ceiling** refuses a consolidation too large to finish rather than half-building it.

Operational notes measured on a live tenant: a single dataset delete is ~60 s server-side,
but deletes of *different* datasets do not race, so the cleanup runs them concurrently
(12 at a time) — turning a fleet's days of serial deletion into hours. Reporting is
unaffected throughout: dashboards already query `yara_scanner_*` wildcards, so query results
are identical whether the data sits in per-host or per-scan datasets.

### Fixed — macOS runs recorded no CPU core count

`psutil.Process.cpu_affinity()` does not exist on macOS, and `host_cores` was assigned
inside the same try block, so every macOS run logged `"host_cores": null` — the denominator
behind every CPU-governor percentage. macOS now reports it (and an equal
`cpu_affinity_count`, since macOS applies no affinity cap).

### Validation

Consolidation was validated end-to-end against a live tenant, not just unit-mocked: the
collision that justifies per-host sharding was measured directly (8 concurrent writers to
one dataset lost 87 % of rows), both a happy-path and a finished-scan-gate scenario passed
end to end, and a dry run plus a scoped real consolidation ran against genuine scanner data
(72/65 scans across the per-host shards) with the orphaned scans correctly deferred. Six
issues that only appear against a real tenant were found and fixed in the process — dataset
enumeration key, create→write schema lag, read-back system columns, read-back type
round-tripping, terminality source, and results-poll timeouts.

---

## v2.0.0 — 2026-08-03

First formally released version. Everything below is relative to the unversioned builds
shared before this date.

### Upgrading

**Drop-in.** Edit the three credential lines and the `CUSTOMER CONFIG` block, re-upload to
the script library, done. Retired options are still accepted and translated, so existing
playbooks and scheduled jobs keep running unchanged:

| Old option | Now |
|---|---|
| `throttle_mode=off` | `cpu_guarantee=none` |
| `throttle_mode=script` or `os` | `cpu_guarantee=headroom` |
| `cpu_high_threshold`, `cpu_critical_threshold`, `max_pause_secs` | accepted, value ignored |

Existing lookup datasets are unaffected — the `_v2` schema is unchanged.

### New — CPU impact control that can be stated and verified

Replaces the previous `throttle_mode = script | os | off` design. You now choose a
guarantee rather than a threshold:

- **`headroom`** (default) — always leave N% of the host free; the scan's share adapts to
  whatever else is running.
- **`budget`** — never exceed N% of the host, whatever else is running.
- **`none`** — no governing.

Constants: `CONFIG_CPU_GUARANTEE`, `CONFIG_CPU_HEADROOM_PCT` (30), `CONFIG_CPU_BUDGET_PCT`
(25), `CONFIG_CPU_FLOOR_PCT` (5).

**Why the old design went.** It watched *system-wide* CPU and paused the scan above a
threshold, which meant it punished itself for load it did not cause and kept pausing while
that load persisted. Measured on 8-core Linux: **285 s of a 347 s scan spent parked**, worst
case **65.9× slower** than unthrottled — operators experienced a scan that never finished.
It also bought nothing: across 2, 4 and 8 cores under saturating load, every mode protected
the competing workload to within **−3% to +1%** of no throttling at all. The `os` tier was
worse still, starving on a busy host (**252 s vs 77 s** for the same work).

The new design does not claim to protect the host either — no self-governed throttle
meaningfully can. What it adds is a share you can state before the scan, a floor that
guarantees the scan finishes, and telemetry proving the bound held.

### New — `xdr_data_management.py`

Standalone script to stop lookup datasets accumulating forever. Reports an inventory, and
deletes rotated months or legacy-schema datasets on an age you choose. Dry run unless
`--yes`; five safety rails including never touching the current month.

**No scan depends on it.** The scanner creates and writes its own datasets; if this never
runs, datasets grow but every scan still succeeds.

### Changed — worker default stays at 2

`CONFIG_WORKERS` is configurable and the old hard cap of 2 is gone, but 2 remains the
default because that is what the measurements support: on 8-core Linux over 93k files,
**2 workers = 71 s, 4 = 93 s, 8 = 101 s**. Scanning is disk-bound, so more concurrent
readers cause seek contention rather than useful overlap. Raise it only if you measure a
gain on your storage.

### Fixed — cancellation exited up to 55 s after it stopped scanning

A cancelled scan stopped its workers promptly but then took up to 55 s to exit, because the
directory walk used `os.walk`, which yields a whole directory tree level at a time and could
not be interrupted mid-level. Replaced with an explicit cancellable walk.

Measured on the same `C:\` scan: workers stopped in the **same millisecond** as the request
(was +4.45 s), cleanup started the same millisecond (was +55.0 s), process exited **+2.02 s**
(was +55.0 s). A 46-directory regression corpus with symlinks produced identical results
before and after.

### Fixed — a scan that delivered nothing reported success

If every alert failed to upload — revoked key, missing permission, unreachable tenant — the
scan reported `outcome: completed`, `undelivered: 0`, and wrote no error log. The only trace
was one line in the upload log, so an operator would reasonably conclude the alerts landed.

Cause was a naming trap: `undelivered` counts only items **never attempted**, while items
attempted and rejected went to `failed_uploads`. Both are real loss; only one was named like
it.

Scans now report the shortfall in three places — the `SCAN_RESULT` line, an ERROR in
`scan_errors_<run_id>.log`, and a `delivery_shortfall` field in the summary JSON. Read-timeout
batches count as *not* delivered: the server may have committed them, but "may have" is not
evidence.

### Fixed — macOS runs recorded no CPU core count

Every macOS run logged `"host_cores": null` in its `THROTTLE_CONFIG` header.
`psutil.Process.cpu_affinity()` does not exist on Darwin, and `host_cores` was assigned
inside the same try block, so it was never reached.

That field is the denominator behind every `own` percentage the governor reports
(`process_cpu / cpu_count`), so a macOS performance log could not be interpreted — there was
no way to verify the promised CPU share had been held. macOS now reports `host_cores` and,
because the platform imposes no affinity cap, an equal `cpu_affinity_count`.

### Fixed — running the script directly printed nothing

The CLI path exited 0 having reported nothing at all. Anyone validating the scanner outside
Action Center — a scheduled task, CI, a customer smoke test — got silence. Now prints
`SCAN_RESULT: ...`, the same prefix the Action Center path uses.

### Fixed — scanning a path under a platform skip-list failed silently

A scan targeting a directory beneath an excluded path (`/tmp`, `/proc`, `/private/tmp`)
reported "0 files scanned" with no reason. It now warns explicitly, naming the path and the
exclusion that caught it.

### Added — versioning

The script carries `__version__`, reports it in `scan_summary_<run_id>.json` as
`scanner_version`, and logs it at the start of every run. A shared copy of the file now
identifies itself.

### Known limitations

These are platform behaviours, not defects in the scanner. They are documented so you are
not surprised by them.

- **The console's Cancel hard-kills the payload.** A scan stopped that way writes no terminal
  row and no summary, so dashboards show it as running indefinitely. Use the `cancel` entry
  point to stop a scan and keep its findings. The scanner cannot fix this: the agent runs
  scripts off the main thread, so no signal handler can be installed.
- **One lookup dataset per endpoint, not one for the estate.** `lookups/add_data` is not
  concurrency-safe — two endpoints writing one dataset lose rows silently (~2 of 8 batches at
  8-way concurrency). Per-writer sharding is the workaround. Bucket hosts with a literal
  `CONFIG_LOOKUP_SHARD` label to reduce the count.
- **Windows agents cap payloads at 2 CPU cores**, so on an 8-core host the scanner cannot
  exceed ~25% regardless of configuration.
- **Rule compatibility is set by the agent's libyara build**, not by the agent version.
  Modules beyond `pe`, `elf`, `math`, `hash` and `time` are unavailable, and Windows and
  Linux agents differ. A rule compiling on your workstation proves nothing about the agent.
- **There is no public API to upload a script to the library.** The initial upload is a
  one-time console action; everything after it is API-drivable.
