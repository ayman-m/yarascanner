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
