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
