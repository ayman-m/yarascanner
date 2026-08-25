# YARA Scanner for Cortex XDR — Operations Deep Dive

*Scanner **3.4.0** · pack automations v16/v24/v24/v12/v14 · playbook v4*

Everything an operator needs to know that isn't obvious from the config file: what the
platform does that you can't change, what the scanner does about it, what it costs, and
where it will surprise you.

**Every number in this document was measured on a live tenant**, not estimated. Where
something is unverified or unresolved it says so explicitly.

---

## Contents

1. [Read this first — the five things that bite people](#1-read-this-first)
2. [Platform constraints you cannot change](#2-platform-constraints-you-cannot-change)
3. [What a scan actually does](#3-what-a-scan-actually-does)
4. [The dataset model](#4-the-dataset-model)
5. [Sizing the run timeout — the drain problem](#5-sizing-the-run-timeout--the-drain-problem)
6. [Delivery accounting — did my data land?](#6-delivery-accounting--did-my-data-land)
7. [Dataset management: the five automations](#7-dataset-management-the-five-automations)
8. [Consolidation mechanics and safety rails](#8-consolidation-mechanics-and-safety-rails)
9. [The consolidation lock](#9-the-consolidation-lock)
10. [Cancellation](#10-cancellation)
11. [Capacity planning](#11-capacity-planning)
12. [Credentials and permissions](#12-credentials-and-permissions)
13. [Failure modes catalogue](#13-failure-modes-catalogue)
14. [Known limitations and open questions](#14-known-limitations-and-open-questions)
15. [Pre-flight checklist](#15-pre-flight-checklist)

---

## 1. Read this first

Five things account for most of the operational pain. If you read nothing else:

**1. The run timeout must cover upload drain, not just scan time.** A scan reports "done"
when the last file is checked, but queued match rows keep uploading afterwards — measured
at **169s of scanning followed by 6m41s of draining**. Size the Action Center timeout for
both or you lose queued rows. → [§5](#5-sizing-the-run-timeout--the-drain-problem)

**2. `YaraConsolidateApply` has no dry-run mode and deletes on its first run.** There is no
`execute` argument. A bare invocation with no arguments merges and deletes source shards
immediately. `YaraConsolidateStatus` is the read-only equivalent — check with it first.
→ [§7](#7-dataset-management-the-five-automations)

**3. One consolidation pass is bounded and does not self-drain.** Default `max_scans` is
**4**. A larger backlog needs the automation re-run, or the cap raised. The playbook does
not loop. → [§8](#8-consolidation-mechanics-and-safety-rails)

**4. The matches dataset is permanent and overwritten, not rotated.** One per host, no month
suffix, replaced wholesale at the start of every scan. It is the deep-dive source. Anything
that tells you to "turn on rotation" for it is out of date. → [§4](#4-the-dataset-model)

**5. A timed-out API call does not mean the script stopped.** Observed live: a consolidation
run whose caller timed out kept executing server-side for roughly two hours afterwards.
Treat a caller timeout as *unknown*, never *dead*. → [§9](#9-the-consolidation-lock)

---

## 2. Platform constraints you cannot change

These are properties of Cortex XDR's APIs. Every design decision downstream exists because
of one of them.

| Constraint | Measured | Consequence |
|---|---|---|
| `lookups/add_data` is **not concurrency-safe** | 8 endpoints writing one dataset: **~2 of 8 batches landed**. Client-side jitter did not help. | One writer per dataset, enforced by per-host sharding. Rows are lost *silently* — the retry returns HTTP 200. |
| `add_data` merge time scales with **dataset size**, not payload size | 15,000 rows → ~13s/write · 77,000 rows → ~31s/write | An unbounded append-only dataset eventually goes **write-dead**. Observed at ~77k rows. |
| Lookup dataset hard cap | **50 MB** per dataset | Caps rows per dataset. See [§11](#11-capacity-planning). |
| XQL result truncation | Silent at **1,000,000 rows** | A query over a very large dataset can return partial results with no error. |
| `delete_dataset` is slow | **~60s** server-side per dataset | Bulk cleanup is an hours-scale background job. Different-dataset deletes don't race, so they run 12-wide. |
| Action Center **script timeout is not a hard kill** | A run continued ~2h past its 900s timeout | See [§9](#9-the-consolidation-lock) and [§14](#14-known-limitations-and-open-questions). |
| No public API to upload a library script | — | Scanner upload is a one-time manual console step. |
| Alert ingestion budget | ~600 alerts/min **per API key**, shared across all endpoints using it | Stagger large fleets; use a separate key per wave. |

> **The silent-loss point is the important one.** Concurrent `add_data` writes don't error —
> they return success and drop rows. Per-host sharding isn't a preference, it's the only
> configuration where delivery is provably complete (verified 8/8).

---

## 3. What a scan actually does

### Sequence

1. **Resolve dataset names** — `yara_scanner_matches_v4_<host>_<6hex>` and
   `yara_scanner_scans_v4_<host>_<6hex>_<YYYYMM>`.
2. **Ensure datasets exist** — creates them if absent; a first scan on a host is a no-op here.
3. **Overwrite the matches dataset** — enumerates `scan_id`s already present and removes every
   row belonging to a *previous* scan. The current scan's own ID is never a removal target.
4. **Write the `initiated` lifecycle row.**
5. **Compile rules**, then walk and scan, with the CPU governor throttling throughout.
6. **Heartbeat** — a `running` lifecycle row every **600s**.
7. **Write the terminal lifecycle row** (`completed` / `cancelled` / `failed`) — sent
   **inline, ahead of the upload queue**, so it lands even if the queue never drains.
8. **Drain the upload queue** — this can take minutes. See [§5](#5-sizing-the-run-timeout--the-drain-problem).
9. **Write `scan_summary_<run_id>.json`** with full delivery accounting.

### Key defaults

| Setting | Default | Notes |
|---|---|---|
| `CONFIG_CPU_GUARANTEE` | `headroom` | Leaves `CONFIG_CPU_HEADROOM_PCT` = **30%** of the host free |
| `CONFIG_CPU_FLOOR_PCT` | `5` | Never targets below this — guarantees progress |
| `CONFIG_WORKERS` | `2` | Scanning is disk-bound too; more workers is not reliably faster |
| `CONFIG_ALERT_MAX_PER_SCAN` | `500` | Beyond this, one rollup alert per rule |
| `CONFIG_ALERT_OFFSETS_PER_FINDING_MAX` | `50` | Offsets rendered per finding in local alert files |
| `CONFIG_COLLECT_FILES` | `False` | Metadata only; `True` copies matched files into an evidence ZIP |
| `CONFIG_HOST_CLEANUP` | `off` | End-of-run local log/artifact cleanup |
| `SCANS_HEARTBEAT_SECS` | `600` | `running` row cadence |
| `LOOKUP_DATASET_BATCH_SIZE` | `500` | Rows per POST — stays under gateway 502s |

### Measured scan performance

| Host | Target | Files | Detections | Scan time | Rate |
|---|---|---|---|---|---|
| Windows Server 2022 | full `C:\` | 935,824 | 2,574 | 1,912s (~32 min) | 490 files/s |
| Windows Server 2022 | full `C:\` | 636,743 | 2,643 | 1,622s (~27 min) | 393 files/s |
| Linux (GCP e2) | `/usr` | 93,137 | 19,447 | 169s | 551 files/s |
| Linux (GCP e2) | `/etc` | 1,449 | 164 | 2.5s | 580 files/s |

Rates cluster around **400–580 files/s** with the default 2 workers and headroom governor.

---

## 4. The dataset model

### The two datasets have different lifecycles

```
yara_scanner_matches_v4_<host>_<6hex>            PERMANENT — one per host, no month suffix.
                                                 Overwritten at the start of every scan.
                                                 Holds exactly the newest scan. Never rotates.

yara_scanner_scans_v4_<host>_<6hex>_<YYYYMM>     APPEND-ONLY — rotates monthly.
                                                 Lifecycle events only, a few rows per scan.
```

**This asymmetry is deliberate and is the single most misunderstood part of the system.**

- **Matches** is bounded by the *overwrite*: it can only ever hold one scan's worth of rows,
  so it never needs rotation to stay small. Its name must stay stable because dashboards and
  the consolidation automations reference it, and it is the deep-dive source — the only place
  the per-file detail behind a consolidated summary row still lives.
- **Scans** is bounded by *rotation*: it's append-only (a handful of rows per scan) so it
  genuinely grows, and `CONFIG_LOOKUP_ROTATION = "monthly"` bounds it.

`CONFIG_LOOKUP_ROTATION` **only affects the scans dataset.** Setting it has no effect on
matches whatsoever.

### Why the overwrite is a row-flush, not delete-and-recreate

| Operation | Measured | Why it matters |
|---|---|---|
| `remove_data` filter flush | **10.0s** (~550 rows) | What the scanner does. Keeps the dataset object and schema alive. |
| `delete_dataset` + recreate | **190.2s** (delete alone: 187s) | **19× slower**, and drops the schema. Never used. |
| `add_lookup_data` write | 44.7s for 1,097 rows (3 batches) | At fleet scale the *write* dominates, not the flush. |

**The flush fails safe.** Every failure is logged and swallowed — stale rows surviving is
recoverable, a scan refusing to run because it couldn't tidy up is not. The current scan's
`scan_id` is filtered out before any delete, so the worst case of a wrong enumeration is that
too *few* rows are removed.

> **Two concurrent scans on one host are not supported** under the overwrite model. The
> second scan's flush would delete the first's rows — from the dataset's point of view they
> *are* a previous scan.
>
> **Sequential re-scans destroy the previous scan's file detail too — and consolidation does
> not prevent it.** The flush does not check whether the previous scan was archived, because on
> v4 nothing archives it: `YaraConsolidateApply` is deliberately blocked from consuming the
> live v4 matches dataset (doing so would recreate the unbounded per-scan growth the overwrite
> model removed), and `YaraConsolidateSummary` reads it but keeps only `scan_id`, `hostname`,
> `rule`, `event_timestamp_ms` — no filenames, no offsets. So a host's file-level findings live
> in exactly one place and the next scan on that host replaces them, at any interval, whatever
> your consolidation cadence. Alerts already raised are unaffected. Treat each scan's file
> detail as valid until that host is scanned again.

### Schema v4 — one row per file

v2 wrote one row per matched **string**. v3 wrote one per **(rule, file)** finding. v4 writes
one per **file**, folding every rule that hit it into a `rules` JSON array.

**Fields:** `tenant_id`, `scan_id`, `hostname`, `os_info`, `os_type`, `ip_address`,
`filename`, `file_size`, `file_sha256`, `file_creation_time`, `rules` (JSON array),
`rule_count`, `match_total`, `severity` (highest across the file's rules), `truncated`,
`event_timestamp_ms`.

Each `rules` entry: `rule`, `match_count`, `offsets`, `strings`, `string_ids`, `truncated`,
`severity`.

**Measured reduction**, same underlying findings:

| Scan | (rule, file) pairs | v4 rows | Reduction |
|---|---|---|---|
| Windows full `C:\` | 2,574 | 1,485 | **42%** |
| Linux `/etc` | 5,241 | 2,714 | **48%** |

> **Why `string_ids` is an array, not an object.** YARA string identifiers begin with `$`,
> and `json_extract_scalar(x, "$.$ip")` is not valid JSONPath — an object keyed by identifier
> could be stored but never queried. It's `[{id, count}]` for that reason.

### Querying

Dashboards match `yara_scanner_matches*` / `yara_scanner_scans*` wildcards, so shards fan
back in automatically. Filtering by `scan_id` or `hostname` behaves exactly as it would
against one dataset.

Expanding v4's `rules` array in XQL:

```
dataset = yara_scanner_matches_v4_<host>_<6hex>
| alter r = json_extract_array(rules, "$")
| arrayexpand r
| alter rule = json_extract_scalar(r, "$.rule")
| comp count() as n by scan_id, hostname, rule
```

---

## 5. Sizing the run timeout — the drain problem

**This is the most likely thing to cost you data on a first large scan.**

Match rows upload on a background queue that keeps working after scanning finishes. The scan
reports "completed" as soon as the last file is checked — the queue may still hold thousands
of rows.

**Measured, on a 93,137-file scan:**

```
scan time:   169 seconds
drain time:  6 minutes 41 seconds     ← 2.4× longer than the scan itself
```

If the Action Center action's timeout expires mid-drain, the platform kills the payload and
**queued rows are never sent**. In that measured run, 13,845 rows were still pending when the
timeout hit.

### What survives a mid-drain kill

| Data | Survives? | Why |
|---|---|---|
| Terminal lifecycle row | **Yes** | Sent inline, ahead of the queue, specifically for this case |
| Already-uploaded match rows | Yes | Already committed |
| Queued match rows | **No** | Never sent; counted in `dataset_delivery.undelivered` |
| `scan_summary_<run_id>.json` | **No** | Written after the drain completes |

> A missing summary file is itself a signal: the run was killed before finishing.

### Guidance

Budget **scan time + 10 minutes** as a starting point. Very large scans on slow links need
more. Drain budget internals: minimum **150s**, scaled by backlog at **45s per batch**,
capped at **600s**.

There is no external signal to poll for "drain finished" — the summary file only appears once
the whole run, drain included, is done.

---

## 6. Delivery accounting — did my data land?

Every run writes `scan_summary_<run_id>.json` to the scanner's `logs/` directory. The
delivery counters **always balance**, by design:

```
queued == added + updated + skipped + unconfirmed + undelivered (+ failures × batch)
```

### The one field to check

**`delivery_shortfall`** — empty string means everything queued arrived. Non-empty means
findings exist only in the endpoint's local logs. Example from a real killed run:

```
"delivery_shortfall": "dataset rows: 19 of 1523 NOT confirmed (19 never sent)
                       — findings are complete in the local logs on this endpoint"
```

### Counter meanings

| Counter | Meaning |
|---|---|
| `records_added` | Confirmed written |
| `undelivered` | Still queued when the run ended — **never attempted** |
| `send_failures` | Attempted, failed permanently |
| `rows_unconfirmed` | Read-timed-out; the server may have committed them anyway. Deliberately not retried, to avoid duplicates |
| `dropped` | Queue was full or the uploader thread was dead |

A worked example, reconciled exactly:

```
1,523 queued  =  1,504 delivered  +  19 undelivered
1,504 delivered = 1,501 match rows + initiated + 2 heartbeats
```

> `rows_unconfirmed` is not a bug — a read timeout means the server was mid-merge when the
> connection dropped. Blind retries would duplicate rows, so the scanner counts them as
> *fate unknown* rather than guessing.

---

## 7. Dataset management: the five automations

| Automation | Writes? | Deletes? | Dry run? |
|---|---|---|---|
| `YaraReport` | No | No | n/a — read-only |
| `YaraConsolidateStatus` | No | No | n/a — read-only |
| **`YaraConsolidateApply`** | **Yes** | **Yes** | **NO — none exists** |
| `YaraConsolidateSummary` | Yes | **Never** | Yes, unless `execute=true` |
| `YaraCleanup` | No | **Yes** | Yes, unless `execute=true` |

> ### ⚠ `YaraConsolidateApply` is the exception
> It has **no `execute` argument and no dry-run mode**. `main()` runs with `dry_run=False`
> unconditionally. A bare `!YaraConsolidateApply` with zero arguments merges and deletes on
> its first run. Use `YaraConsolidateStatus` to preview.

### The two consolidation modes

|  | **Full detail** (`Apply`) | **Summary only** (`Summary`) |
|---|---|---|
| Target | `yara_scanner_matches_v4_scan_<id>` | `yara_scanner_summary_v4_scan_<id>` |
| Row grain | Every matched-file row, verbatim | One row per **(host, rule)** |
| Columns | Full v4 schema | `scan_id`, `hostname`, `rule`, `event_timestamp_ms` |
| Per-rule counts | n/a | **Deliberately absent** |
| Source afterwards | **Deleted** once verified | **Untouched** |
| Read cost | Reads the shard's rows | One XQL per shard, aggregated in-engine |
| Default | Writes and deletes | **Dry run** |

**Summary** is the safer default for fleet reporting — the per-host dataset stays in place,
so any summary row can still be drilled into. **Full detail** is right when the per-scan
dataset must answer file-level questions with no second lookup.

> **They are not interchangeable after the fact.** Full mode deletes the per-host shard that
> summary mode preserves. The next scan on that host recreates it, so the loss is bounded —
> but until then that scan's per-file detail is gone.

> **On a tenant with no YARA datasets yet, summary mode is a clean no-op.** Dry run and
> `execute=true` alike report `XQL calls: 0 (+1 dataset listing)`,
> `written: 0 | skipped: 0 | failed: 0 | file-level findings collapsed: 0` and
> `host shards deleted: 0`, with `written`, `skipped` and `query_modes` empty. Zero here is
> the correct result, not a misconfiguration.

### YaraCleanup's safety rails

Nothing is deleted if it is: not a YARA dataset name · a per-scan consolidated target · a
**permanent per-host matches dataset** · an abandoned pre-rotation dataset · genuinely
unrotated · the current month · dated in the future · inside the retention window · written
to more recently than `min_quiet_hours` · still holding an unconsolidated scan.

Plus **dry run unless `execute=true`**, and `older_than_months` has no default.

---

## 8. Consolidation mechanics and safety rails

### The pipeline

```
Status (read-only)  →  eligible scan IDs
                       ↓
Apply               →  create per-scan target
                       copy this scan's rows from each source shard
                       count target rows
                       ↓
                    verify: target_count == sum(source_counts)?
                       ↓ yes                        ↓ no
                    strip this scan's rows       count_mismatch —
                    from sources; delete a       nothing deleted,
                    shard once EVERY scan        reported for review
                    in it is verified
```

### Verify-before-delete

A source shard is deleted **only** when the target's row count equals the sum of its sources
*and* every scan sharing that shard is verified. Any shortfall keeps every source.

> **What verification does not check.** It compares row *counts*, not row *content*. A
> corrupted write landing on the same count would pass. And `delete_dataset` has no undo —
> the platform offers no versioning or restore. Treat consolidation as one-way.

### Gate outcomes

| Outcome | Meaning | Action |
|---|---|---|
| `verified` | Counts match; sources deletable | None — success |
| `host_not_terminal` | Scan has no terminal lifecycle row yet | Deferred; retried next pass |
| `within_quiet_period` | Newest row is younger than `quiet_secs` (900s) | Deferred — the uploader may still be draining |
| `count_mismatch` | Target ≠ sum of sources | **Nothing deleted.** Investigate |
| `row_ceiling_exceeded` | Scan exceeds 2,000,000 rows | Refused before writing, not half-built |

**`count_mismatch` is a safety feature, not an error.** It means the tool refused to delete
data it couldn't prove it had copied.

### The bounded pass

`max_scans` (default **4**) caps how many scans one invocation processes.

**A pass costs fixed overhead plus per-scan work. `~128s` is not a per-scan rate.**

Every pass pays roughly **105s of fixed bookkeeping before the first scan is merged**
— measured on an idle pass: the consolidation lock costs ~75s (its release
`delete_dataset` alone is ~60s, and that price is the same for a one-row lock table as
for a large dataset), the run-log's two writes ~19s, and dataset enumeration ~11s. Only
the remainder scales with the scans.

| Pass size | Time | % of 900s timeout | implied marginal cost/scan |
|---|---|---|---|
| 4 scans | 403s | 45% | ~75s |
| 5 scans | 638s | 71% | ~107s |
| 20 scans | ~1,600–2,240s (projected) | **178–249% — killed between scan 7 and 11** |  |

The two measured passes cannot be fit by one straight line, because per-scan cost depends
on how many rows each scan holds — so read **~75–107s** as the marginal range, not `~128s`
as a rate. Dividing a pass's total by its scan count folds the fixed ~105s into every scan
and overstates the marginal cost by 20–70%; the old `~128s` figure was exactly that
(638 ÷ 5). The conclusion is unchanged under either end of the range: 20 is fatal, 4 is safe.

The default was originally 20. That was wrong and would have reliably reproduced a
stuck-lock failure on a real backlog.

> **A bounded pass does not resume itself.** It reports `stopped_early`; drain a large
> backlog by re-running, or raise the cap after measuring your own per-scan cost. The
> playbook runs Apply exactly once per execution — it does not loop back.

### Run history

`yara_scanner_consolidation_runs` gets a **`started`** row before the merge and a terminal
row (`success` / `partial_failure` / `crashed`) after. A `started` row with **no** matching
terminal row means a pass was killed — or is still running.

---

## 9. The consolidation lock

### How it works

The lock is a dataset (`yara_scanner_consolidation_lock`), not a real mutex primitive.
Acquisition exploits the atomicity of dataset creation: whoever's `create_lookup_dataset`
returns "created" owns it; a second run gets "already exists" and stands down.

Release is `delete_dataset`. **Both are ordinary API calls** — if the process dies, release
never happens.

### Why it exists

Consolidation merges then **deletes**. Two concurrent runs on the same scan could both delete
sources after only one wrote a target. Plus `add_data` isn't concurrency-safe. Passes are
serialised tenant-wide.

### Stale takeover

`DEFAULT_LOCK_STALE_SECS` = **20 minutes**, sized against the 900s task timeout. Past that,
the next run treats the lock as abandoned and takes over.

> ### ⚠ A timed-out caller does not mean a stopped script
> **Observed live:** a consolidation run whose HTTP caller timed out kept executing
> server-side for approximately **two hours**, eventually completing and writing its result —
> using whatever code was deployed when it *started*.
>
> **Consequences:** a caller timeout tells you nothing about whether the run is still going.
> And because the stale window (20 min) is far shorter than that observed overrun, a genuinely
> long-running process *can* have its lock taken by a later run while still mid-write.
>
> **Before intervening manually** — especially before clearing a lock — check
> `yara_scanner_consolidation_runs` for a `started` row with no terminal row, and watch
> whether dataset counts are still changing.

### Clearing a stuck lock

Only after confirming nothing is actually running (no dataset churn over several minutes, no
recent tracker activity). Delete the `yara_scanner_consolidation_lock` dataset — that *is*
what release does. Or wait for the 20-minute stale window.

---

## 10. Cancellation

Two ways to stop a scan; they behave **very differently**.

| Method | Mechanism | Terminal row? | Result |
|---|---|---|---|
| **Scanner `cancel` entry point** | Cooperative flag, detected within ~5s | **Yes** — `cancelled` | Clean. Partial findings preserved and consolidatable |
| **Action Center console Cancel** | Hard-kills the payload | **No** | Lifecycle stuck at `running` forever |

**Always prefer the `cancel` entry point.** Run the same library script with Entry Point =
`cancel` (it takes no inputs).

A console Cancel leaves an orphaned scan that shows as running indefinitely. The 24-hour
abandoned-scan cutoff (`DEFAULT_ABANDONED_SECS`) eventually rescues it — its partial matches
are consolidated rather than dropped — but for those 24 hours it is neither terminal nor
abandoned, and it blocks its shard from cleanup.

---

## 11. Capacity planning

### The binding constraint

**50 MB per lookup dataset.** Everything else follows from it.

| Row type | Measured size | Rows per 50 MB |
|---|---|---|
| v4 match row (one per file) | ~749 B | ~70,000 |
| Summary row (host, rule) | ~163 B | ~321,000 |

### Per-host matches dataset

Because it's overwritten each scan, it only ever holds **one scan's** matched files. A host
would need ~70,000 matched files *in a single scan* to approach the cap. The measured
worst case in testing was 14,500 rows — about 20% of capacity.

### Summary datasets

The fleet limit is **rules-matched-per-host, not host count**. 321,000 (host, rule) pairs is
a very large fleet unless rules are extremely noisy.

### Dataset count

A fleet produces one matches dataset per host (permanent) plus one scans dataset per host per
month. Control it with `CONFIG_LOOKUP_SHARD` — it accepts a literal label (`wave1`, `emea`),
grouping hosts into a fixed number of buckets rather than one per endpoint.

> Choose bucket count so that few endpoints in the same bucket scan concurrently. The
> concurrent-write risk returns as writers-per-dataset rises above one. Set
> `CONFIG_LOOKUP_SHARD = "none"` only for a single scanning endpoint — at fleet scale that's
> the configuration measured at 2/8 delivery.

### The noisy-rule failure mode

A single over-broad rule on a 465,000-file Windows host produced **36,243 string matches
across 401 files**. Alerts absorbed it cleanly (401 alerts — alerts are per *finding*, not
per string). The dataset channel queued ~36,000 rows and 7,719 hit the drain budget.

> That measurement predates v4. Under v4's one-row-per-file grain the same event would write
> **401 rows, not 36,000** — the row explosion is largely gone. What has *not* changed is the
> alert-budget pressure and the scan-time cost of a rule that matches far more than intended,
> so the mitigation below still stands.

**Mitigation is entirely on the rules.** Test every new pack against one directory first and
read `top_rules` in the summary. A rule matching hundreds of files in a small sample will
match tens of thousands fleet-wide.

---

## 12. Credentials and permissions

**Two different keys, two different types.** Mixing them up produces an identical generic 401.

| Component | Key type | Where |
|---|---|---|
| Scanner (`xdr_yara_scanner.py`) | **Standard** | `DEFAULT_XDR_API_KEY` / `_ID` / `_URL`, top of CUSTOMER CONFIG |
| Pack automations (×5) | **Advanced (HMAC)** | Same three constants, top of each automation |

**This is five separate edits for the automations.** Every automation is self-contained —
the tenant resolves no cross-script imports, so there is no shared library to edit once.

### Scanner key permissions

- **External Issues Mapping** (`external_alerts_action`) — for alert insertion
- **Data Management** (`data_management_action`) — for datasets
- **Query Center** (`investigation_query_view`) — **required for the overwrite**

> **Without Query Center, the overwrite fails silently.** The start-of-scan flush enumerates
> stale `scan_id`s with one XQL. Without the permission it 403s, fails safe, and the dataset
> quietly resumes accumulating. The only sign is a line in the scan log.

### Editing deployed automations

Uploading a pack marks its items `system:true`, after which item-level API writes fail
permanently with `Item is system and cannot be modified (100001)`. Re-import the whole pack
rather than patching one script.

---

## 13. Failure modes catalogue

Every one of these was observed live during validation.

| Symptom | Cause | What to do |
|---|---|---|
| Scan "completed" but rows missing | Run timeout expired mid-drain | Check `delivery_shortfall`. Raise the timeout ([§5](#5-sizing-the-run-timeout--the-drain-problem)) |
| Scan shows `running` forever | Console Cancel, or terminal row lost | 24h cutoff rescues it. Use the `cancel` entry point instead |
| No `scan_summary_*.json` | Run killed before completing | Confirms a mid-drain kill |
| Consolidation reports 0 candidates, exits clean | `schema_version` mismatch — datasets classify as "newer" and are correctly left alone | Ensure `schema_version` matches the scanner (**4**) |
| `count_mismatch` on a scan | Target ≠ sum of sources | **Safe** — nothing deleted. Often a prior partial run |
| "Lock held by another run" | Genuine concurrency, **or** a stale lock from a killed pass | Check the runs tracker before clearing ([§9](#9-the-consolidation-lock)) |
| Consolidation stalls indefinitely | Pass killed at the task timeout holding the lock | Fixed by `max_scans` bounding. Clear the lock if confirmed dead |
| Summary mode writes 0 rows | Scan still in progress (correctly skipped), or genuinely no matches | Check the skip reasons in the output |
| 401 on every automation call | Standard key in an Advanced-key slot, or rotated key | Regenerate an **Advanced** key; edit all five |
| Dataset grows despite overwrite | Query Center permission missing on the **scanner's** key | Grant `investigation_query_view` |
| `add_data` rows silently skipped | Row carries a field outside the dataset's schema | Schema can't be altered in place — bump the version tag |

---

## 14. Known limitations and open questions

### Accepted limitations

- **Verification compares counts, not content.** A corrupted write on the right count passes.
- **`delete_dataset` has no undo.** No versioning, no restore.
- **Two concurrent scans on one host are unsupported** — the second's flush deletes the
  first's rows.
- **The CLI path (`xdr_data_management.py --consolidate`) has no `max_scans` bound.** It was
  not updated when the cap was added to the pack automations. Restrict scope with `--scan-id`.
- **A bounded pass doesn't self-resume.** Re-run to drain a backlog.
- **XQL truncates silently at 1,000,000 rows.**

### Open questions — genuinely unresolved

- **Does `remove_data` re-stamp `_insert_time` on surviving rows?** Unverified; settling it
  needs a destructive test against a real shard holding two scans. **Not load-bearing** for
  the overwrite, which flushes every previous `scan_id` so no row survives for a re-stamp to
  touch. It would matter to a partial, filtered removal.
- **Why a run outlived its task timeout by ~8×.** Observed once, mechanism unexplained. The
  20-minute stale-lock window assumes the declared timeout is roughly honoured; that
  assumption is not confirmed.
- **`_insert_time`'s exact shape on a raw row pull** (as opposed to the `max()` aggregation,
  which is verified). Degrades to "no signal" and is logged, so worst case is a logged
  reversion to pre-fix behaviour.

### Environment-specific notes

- Cortex **XDR has no scheduled-Job facility** — the playbook is triggered by a correlation
  rule, not a timer. (XSIAM differs.)
- Incident creation via `/xsoar/incident` is inert on XDR tenants.
- Long-running automations exceed the synchronous-execute gateway timeout; the run continues
  server-side regardless.
- YARA versions differ by agent: **4.5.4** local dev macOS, **4.1.0** Windows/macOS agents,
  **3.11.0** Linux agents. 3.11.0 predates match-API changes the scanner normalises around.

---

## 15. Pre-flight checklist

> Running this yourself? [**Manual Validation Runbook**](Manual_Validation_Runbook.md)
> turns the checks below into an executable procedure — console and XQL only, with
> expected output and a pass/fail line for each step.


**Before the first scan**

- [ ] Scanner uploaded; confirm `scanner_version` in a summary reads **3.4.0**
- [ ] **Standard** key in the scanner's three config constants
- [ ] Scanner key has External Issues Mapping + Data Management + **Query Center**
- [ ] Rules tested against **one directory** first; `top_rules` reviewed for noise
- [ ] Run timeout sized for **scan + drain** (start at scan estimate + 10 min)
- [ ] `CONFIG_LOOKUP_SHARD` decided — per-host, or bucketed for a large fleet

**After the first scan**

- [ ] `delivery_shortfall` is empty in `scan_summary_<run_id>.json`
- [ ] Terminal row present in the scans dataset
- [ ] Matches dataset holds exactly one `scan_id`
- [ ] Row count is sane against the 50 MB / ~70,000-row ceiling

**Before the first consolidation**

- [ ] **Advanced (HMAC)** key in all five automations
- [ ] `YaraReport` run — inventory understood. On a tenant with no YARA datasets yet
      the report is a legitimate empty one — the header reads
      `0 current-schema dataset(s), 0 legacy, 0 newer-schema (never pruned)` and the
      table's only body row is `(none)`. Correct, not a broken deployment
- [ ] `YaraConsolidateStatus` run — eligible scans reviewed
- [ ] Mode decided: **Summary** (safe, non-destructive) or **Full** (destructive)
- [ ] Understood: **`Apply` has no dry run and deletes on first use**
- [ ] `max_scans` left at 4 for the first pass. Before raising it, measure your own
      **marginal** per-scan cost — subtract the fixed ~105s per-pass overhead first, then
      divide by the scan count. Dividing a pass total by its scan count counts that fixed
      cost once per scan and will mislead you into raising the cap too far

**Ongoing**

- [ ] Watch `yara_scanner_consolidation_runs` for `started` rows without terminal rows
- [ ] Re-run consolidation until it stops reporting `stopped_early`
- [ ] Schedule `YaraCleanup` separately from consolidation — never the same window
