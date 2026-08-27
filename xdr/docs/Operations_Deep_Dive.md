# YARA Scanner for Cortex XDR — Operations Deep Dive

*Scanner **3.4.0** · 9 pack automations · playbook v4*

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
7. [Dataset management: the nine automations](#7-dataset-management-the-nine-automations)
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

**2. `YaraConsolidateApply` is dry run by default, and never deletes a source.** Its `execute`
argument defaults to `false`, so a bare invocation reports what it would write and writes
nothing. Even with `execute=true` it only writes its own consolidated dataset — the per-host
matches datasets are never deleted. `YaraConsolidateStatus` previews the same grouping
read-only. → [§7](#7-dataset-management-the-nine-automations)

**3. One consolidation pass is bounded by rows, not by scan count.** There is no `max_scans`
argument. `row_ceiling` (default **60,000**) refuses a ruleset group larger than that rather
than half-filling its target; nothing else caps a pass, so a large backlog is a 900s-timeout
risk. Narrow it with `scan_id`. → [§8](#8-consolidation-mechanics-and-safety-rails)

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
| Linux (`xdr_agent_cd7e9b`) | full (default) | 209,804 | 225 | 236s | 888 files/s |
| Windows (`xdragent_68494d`) | full (default) | 636,780 | 452 | 1,437s (~24 min) | 443 files/s |
| Windows (`xdragent2_2fd370`) | full (default) | 935,868 | 457 | 1,728s (~29 min) | 541 files/s |

The last three rows are the **2026-08-25** round — scanner 3.4.0, 10 rules, three hosts scanned
concurrently; the rows above them are earlier rounds.

Rates span **393–888 files/s** with the default 2 workers and headroom governor. The Linux 888 is
high because the rate counts only the files actually scanned and skipping is cheap — that host
skipped **269,716** files against the **209,804** it scanned.

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
> **Sequential re-scans destroy the previous scan's file detail unless you consolidated it
> first.** The flush does not check whether the previous scan was archived — it has no way to.
> Archiving it is entirely on you: `YaraConsolidateApply` with `execute=true` copies every
> column of every matched-file row into `yara_scanner_full_v4_rules_<hash>`, so a scan's file
> detail survives a later re-scan *if* Apply ran against it in between. `YaraConsolidateSummary`
> reads the same source but keeps only `scan_id`, `hostname`, `rule`, `event_timestamp_ms` — no
> filenames, no offsets. Nothing schedules either, and the scanner does not wait for them. So
> without a consolidation between scans a host's file-level findings live in exactly one place
> and the next scan on that host replaces them, at any interval. Alerts already raised are
> unaffected. Treat each scan's file detail as valid until that host is scanned again.

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

## 7. Dataset management: the nine automations

| Automation | Writes? | Deletes? | Dry run? |
|---|---|---|---|
| `YaraReport` | No | No | n/a — read-only |
| `YaraConsolidateStatus` | No | No | n/a — read-only |
| **`YaraConsolidateApply`** | **Yes** | **Never** | Yes, unless `execute=true` |
| `YaraConsolidateSummary` | Yes | **Never** | Yes, unless `execute=true` |
| `YaraCleanup` | No | **Yes** | Yes, unless `execute=true` |
| **`YaraWipeAllDatasets`** | No | **Yes — every `yara_scanner_*` dataset** | Yes, unless `execute=true` **and** an exact `confirm` phrase |
| `YaraScanVerify` | No | No | n/a — read-only |
| `YaraRulesFromFile` | No | No | n/a — read-only, makes no tenant call |
| `YaraRulesDecode` | No | No | n/a — read-only, makes no tenant call |

The last four are newer than the consolidation set and are the ones most often missed:

- **`YaraWipeAllDatasets`** deletes every `yara_scanner_*` dataset on the tenant. Destructive,
  and confirm-gated — `execute=true` on its own does nothing without the exact `confirm` phrase.
- **`YaraScanVerify`** is a bounded post-dispatch check that a dispatched scan wave actually
  started on its hosts. Read-only, but it queries the tenant, so it needs a key.
- **`YaraRulesFromFile`** validates an operator-uploaded YARA rules file and returns the base64
  the Action Center scanner takes as its `yarafile` input.
- **`YaraRulesDecode`** is the inverse: it decodes that base64 back to readable rules and
  recomputes the ruleset hash, for verification and forensics.

`YaraRulesFromFile` and `YaraRulesDecode` make no tenant API call at all, which is why they are
the two that carry no credentials — see [§12](#12-credentials-and-permissions).

> ### `YaraConsolidateApply` is not the exception — it behaves like the rest
> `YaraConsolidateApply.yml` declares an `execute` argument with `defaultValue: 'false'`, and
> the script defaults it `False` too. A bare `!YaraConsolidateApply` with zero arguments
> reports what it would write and **writes nothing** — it does not even take the consolidation
> lock, which only `execute=true` acquires. And it deletes nothing in either mode: the per-host
> matches datasets are permanent, and the only rows it ever removes are its own, inside its own
> target. Use `YaraConsolidateStatus` for a preview that reads even less.

### The two consolidation modes

Both group the **same** data the **same** way. They differ only in fidelity — which is the
whole choice being offered.

|  | **Full detail** (`Apply`) | **Summary only** (`Summary`) |
|---|---|---|
| Reads | The live `yara_scanner_matches_v4_<host>_<6hex>`, plus any month-suffixed v4 matches shard | Identical |
| Groups by | The ruleset hash trailing every `scan_id` | Identical |
| Target | `yara_scanner_full_v4_rules_<hash>` | `yara_scanner_summary_v4_rules_<hash>` |
| Datasets produced | **One per ruleset**, holding every host scanned with it | Identical |
| Row grain | Every matched-file row, verbatim | One row per **(host, rule)** |
| Columns | Full v4 schema — filenames, offsets, matched strings, hashes | `scan_id`, `hostname`, `rule`, `event_timestamp_ms` |
| Measured, 3 hosts / 1,134 detections | **1,012 rows** | **24 rows** |
| Source afterwards | **Untouched** | **Untouched** |
| Size rail | `row_ceiling`, default **60,000** — refuses rather than half-filling | None needed |
| Default | **Dry run** | **Dry run** |

**Neither mode deletes anything.** The per-host matches datasets are permanent, overwritten by
the next scan on that host, and remain the deep-dive source both targets point back to. The
only rows either automation removes are its own, in its own target, for a scan the source no
longer holds — that is how a re-run reconciles instead of appending.

**Re-running is a verified no-op.** Both compare the `scan_id` set their target already holds
against the set the sources offer now. A re-scanned host mints a new `scan_id`, so a changed
host is detected without reading a single row back: its old rows are dropped, its new ones
written, and untouched hosts are not rewritten at all.

> **Pick `Summary` for a fleet, `Apply` for an investigation.** Full detail is roughly 42× the
> rows on the same data. At fleet scale that is what the 50 MB lookup cap is for, and
> `row_ceiling` will refuse the write rather than half-fill a dataset. `Summary` answers
> "which rules fired where"; `Apply` answers "which files, at which offsets, matching what".

> **`Apply` neither consolidates nor deletes the scans lifecycle shards.** It reads
> `yara_scanner_scans_v4_<host>_<6hex>_<YYYYMM>` for one purpose only — building the terminal
> map that decides which scans are eligible — and writes nothing back to them. It once merged
> those shards into per-scan targets and deleted the sources; that work is deferred to a future
> automation, the functions remain in place and drift-gated, and nothing calls them today.
> **`YaraCleanup` is the only thing in the pack that deletes an aged month-suffixed scans
> shard, and nothing schedules it** — that is a run you have to make yourself.

> **Both modes produce a record that outlives the source scan — but only if you run one.**
> `Apply` archives the findings themselves, every column of every matched-file row; `Summary`
> archives one row per (host, rule). Neither is scheduled, and the per-host matches dataset is
> overwritten by the next scan on that host
> ([§14](#14-known-limitations-and-open-questions)). Run one of them per scan if the findings
> have to outlive the scan — `Summary` if the rule/host list is enough, `Apply` if the file
> detail has to survive.

> **On a tenant with no YARA datasets yet, summary mode is a clean no-op.** Dry run and
> `execute=true` alike report `XQL calls: 0 (+1 dataset listing)`,
> `written: 0 | skipped: 0 | failed: 0 | file-level findings collapsed: 0` and
> `host shards deleted: 0 (source data is never deleted — the host dataset is the deep-dive
> source; only this automation's own summary rows are reconciled)`, with `written`, `skipped`
> and `query_modes` empty. That deletion counter is a constant zero, not a tally — zero here
> is the correct result, not a misconfiguration.

### YaraCleanup's safety rails

Nothing is deleted if it is: not a YARA dataset name · a consolidated target (consolidation
*output*, not a source) · a **permanent per-host matches dataset** · an abandoned pre-rotation
dataset · genuinely unrotated · the current month · dated in the future · inside the retention
window · written to more recently than `min_quiet_hours` · still holding an unconsolidated scan.

Plus **dry run unless `execute=true`**, and `older_than_months` has no default.

---

## 8. Consolidation mechanics and safety rails

### The pipeline

```
Status (read-only)  →  eligible scan IDs, grouped by ruleset hash
                       ↓
Apply               →  read every per-host matches dataset
                       gate each scan: terminal lifecycle row AND newest row
                       older than the 900s quiet period, OR aged past
                       retention_hours (24h)
                       bucket the survivors by the ruleset hash in the scan_id
                       ↓
                    per ruleset group, against ONE target
                    yara_scanner_full_v4_rules_<hash>:
                       ↓
                    rows > row_ceiling?  →  REFUSED, nothing written
                       ↓ no
                    read the scan_ids the target already holds
                    drop the held ones no source still holds   ← its OWN rows
                    write the ones the target does not have
                       ↓
                    sources untouched, in every branch
```

### Reconciliation, not verify-before-delete

An earlier build wrote a per-scan target, compared row counts, and deleted the source shard
once every scan in it verified. **That pipeline is gone.** Full consolidation deletes no source
at all, so there is no delete to gate — what replaced the count check is `scan_id`
reconciliation. Each pass compares the set of `scan_id`s the target already holds against the
set the sources still hold: the ones missing from every source are dropped from the target,
the ones the target lacks are written, and an unchanged group is left alone entirely.

Stale is measured as *held minus observed-in-sources*, never *held minus what this pass was
asked to process* — a scan_id still sitting in a source is valid whether or not `scan_id`
narrowed this pass to it. And if **any** source dataset could not be read, stale-row removal is
skipped for the whole pass: a scan missing from an unreadable source is not evidence it was
superseded.

> **What reconciliation does and does not check.** It compares `scan_id` *sets*, not row
> *content* — a corrupted row carrying a scan_id the target already holds is left alone.
> Consolidation's only `delete_dataset` call is releasing its own lock. The genuinely
> destructive tools are elsewhere: **`YaraCleanup` and `YaraWipeAllDatasets` do call
> `delete_dataset` on real data, and `delete_dataset` has no undo** — the platform offers no
> versioning or restore. Treat *those* as one-way.

### Pass outcomes

| Outcome | Meaning | Action |
|---|---|---|
| `WOULD write …` | Dry run — the default — reporting the write it would perform | Re-run with `execute=true` |
| `target already current … verified, not rewritten` | Held scan_ids already match the sources | None — success |
| `scan still in progress - left alone` | No terminal lifecycle row and not yet past `retention_hours` | Deferred; picked up next pass |
| `finished, but its newest row is inside the 900s quiet period (rows may still be draining) - left alone` | Terminal, but its newest match row is younger than `quiet_secs` (**900s**) | Deferred; picked up once the scan has been quiet that long |
| `no ruleset hash in scan_id - cannot be grouped` | scan_id predates the ruleset-hash suffix | Nothing to group it by; rescan |
| `<dataset>: unreadable` | A source matches dataset could not be read | Its rows are absent this pass, **and stale-row removal is skipped for every group** |
| `exceeds the full-consolidation ceiling` | Group larger than `row_ceiling` (60,000) | **Refused before writing**, not half-built. Use `Summary`, or raise `row_ceiling` deliberately |
| `could not read existing target` | Target exists but its scan_id set could not be read | Nothing written for that group — re-run |

**Refusal is a safety feature, not an error.** In every one of these branches the source
datasets are untouched and the target is either correct or unwritten — never half-filled.

> **A cleanly completed scan does not wait out `retention_hours`.** The terminal-lifecycle gate
> is real: a scan with a terminal row for every host is eligible as soon as its newest match row
> has been quiet for **900s** (`DEFAULT_QUIET_SECS`). That quiet period is the drain guard, not
> ceremony — the scanner writes the terminal row *ahead* of the upload queue
> ([§3](#3-what-a-scan-actually-does)), so consolidating inside that window would copy a partial
> row set, and the damage would be permanent: the `scan_id` would land in the target and never
> be written again. `retention_hours` (24h) is the *fallback* for a scan that never wrote a
> terminal row, not the wait everything serves.

### What a pass costs

There is no scan-count cap. One invocation attempts every eligible scan, so the cost model
below is what decides whether a pass fits inside the 900s task timeout.

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
(638 ÷ 5). The conclusion is unchanged under either end of the range: 20 scans in one pass is
fatal, 4 is safe.

An earlier build enforced that with a scan-count cap — `max_scans`, shipped at 20, then
corrected to 4. **That argument no longer exists.** Nothing now stops a pass attempting the
whole backlog, so the bound has become yours to apply.

> **A pass is not self-limiting — scope it yourself.** There is no cap and no `stopped_early`
> report to tell you one held back. Name the scans with `scan_id`
> (`YaraConsolidateStatus`'s `eligible_scan_ids` is the list to draw from — it is the
> conservative end of what a pass will take, never more) and work a large backlog
> in batches sized against the numbers above. Re-running is a verified no-op, so an overlapping
> batch costs a read, not a rewrite. The playbook runs Apply exactly once per execution — it
> does not loop back.

### Run history

`yara_scanner_consolidation_runs` gets a **`started`** row before the merge and a terminal
row (`success` / `partial_failure` / `crashed` / `skipped_locked`) after. A `started` row with
**no** matching terminal row means a pass was killed — or is still running.

**Only an `execute=true` pass is recorded at all.** A dry run writes no row here, so an absent
row means either "nothing ran" or "only dry runs ran" — it is not evidence of a failure.

---

## 9. The consolidation lock

### How it works

The lock is a dataset (`yara_scanner_consolidation_lock`), not a real mutex primitive.
Acquisition exploits the atomicity of dataset creation: whoever's `create_lookup_dataset`
returns "created" owns it; a second run gets "already exists" and stands down.

Release is `delete_dataset`. **Both are ordinary API calls** — if the process dies, release
never happens.

### Why it exists

Consolidation writes tenant-wide, and `add_data` **isn't concurrency-safe**: two passes writing
the same `yara_scanner_full_v4_rules_<hash>` target would silently drop each other's rows
([§2](#2-platform-constraints-you-cannot-change)), and each would reconcile against a scan_id
set the other was mid-way through changing. Passes are serialised tenant-wide. **A dry run
takes no lock** — only `execute=true` acquires one.

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
| Pack automations (×7) | **Advanced (HMAC)** | Same three constants, under the `CONFIGURATION - the only values in this file you need to edit` banner in each of the seven |

**This is seven separate edits for the automations, not five.** Every automation is
self-contained — the tenant resolves no cross-script imports, so there is no shared library to
edit once. The seven carrying the credential block are `YaraCleanup`, `YaraConsolidateApply`,
`YaraConsolidateStatus`, `YaraConsolidateSummary`, `YaraReport`, **`YaraScanVerify`** and
**`YaraWipeAllDatasets`**. The last two are the ones operators skip, because older guidance said
"five" — leave either on its placeholder values and it fails at client construction the first
time it is run.

**`YaraRulesFromFile` and `YaraRulesDecode` need no credentials.** Neither makes a tenant API
call — one reads an uploaded file, the other decodes a base64 string — so neither carries the
configuration block, and there is nothing in them to edit.

Don't go looking for a line number; find the banner, which appears verbatim in all seven:

```
CONFIGURATION - the only values in this file you need to edit
```

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
| Consolidation reports 0 candidates, exits clean | **The scans were gated, not invisible.** Both modes read the permanent per-host matches dataset deliberately, through a wider read-only inclusion than `parse_shard`'s — so zero here means every scan was skipped: still running, inside the 900s quiet period, no ruleset hash in its `scan_id`, or already reconciled. **A genuine `schema_version` mismatch** also reads as zero — those datasets classify as "newer" and are correctly left alone. (`no matches shards found` belongs to the retired per-scan merge; no live entry point emits it) | Read the `SKIPPED:` lines — they name the gate per scan. `YaraConsolidateStatus` shows whether any scan is eligible at all. Suspect `schema_version` (**4**) only after those check out |
| A ruleset group reported `REFUSED` | The group exceeds `row_ceiling` (60,000 rows) | **Safe** — nothing written for that group, sources untouched. Use `Summary` at that scale, or raise `row_ceiling` deliberately |
| "Lock held by another run" | Genuine concurrency, **or** a stale lock from a killed pass | Check the runs tracker before clearing ([§9](#9-the-consolidation-lock)) |
| Consolidation stalls indefinitely | Pass killed at the task timeout holding the lock | Scope the next pass with `scan_id` ([§8](#8-consolidation-mechanics-and-safety-rails)). The 20-minute stale window releases the lock; clear it only if confirmed dead |
| Summary mode writes 0 rows | Scan still in progress (correctly skipped), genuinely no matches, or the host was re-scanned and its matches dataset overwritten | Check the skip reasons. An overwritten scan produces no skip reason — it is simply absent |
| 401 on every automation call | Standard key in an Advanced-key slot, or rotated key | Regenerate an **Advanced** key; edit all **seven** that carry the CONFIGURATION banner — `YaraScanVerify` and `YaraWipeAllDatasets` included |
| Dataset grows despite overwrite | Query Center permission missing on the **scanner's** key | Grant `investigation_query_view` |
| `add_data` rows silently skipped | Row carries a field outside the dataset's schema | Schema can't be altered in place — bump the version tag |

---

## 14. Known limitations and open questions

### Accepted limitations

- **Reconciliation compares `scan_id` sets, not content.** A corrupted row under a scan_id the
  target already holds is left alone.
- **`delete_dataset` has no undo.** No versioning, no restore — which is why `YaraCleanup` and
  `YaraWipeAllDatasets` are the two automations to be careful with. Consolidation calls it only
  on its own lock dataset, never on a source.
- **Any re-scan of a host destroys the previous scan's file-level matches unless it was
  consolidated first** — concurrent or sequential, at any interval. `Apply` with `execute=true`
  archives that detail into `yara_scanner_full_v4_rules_<hash>`, and summary mode keeps only
  rule/host/timestamp, not filenames or offsets; but nothing runs either automatically and the
  scanner does not wait for one. Alerts already raised are unaffected.
- **Neither the pack automation nor the CLI (`xdr_data_management.py --consolidate`) bounds a
  pass by scan count.** Restrict scope with `scan_id` / `--scan-id`.
- **A pass has no scan-count bound and no `stopped_early` report.** Batch it yourself.
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

- [ ] **Advanced (HMAC)** key in all **seven** automations carrying the
      `CONFIGURATION - the only values in this file you need to edit` banner — including
      **`YaraScanVerify`** and **`YaraWipeAllDatasets`**, the two usually left on placeholders.
      `YaraRulesFromFile` and `YaraRulesDecode` make no API call and need no key
- [ ] `YaraReport` run — inventory understood. On a tenant with no YARA datasets yet
      the report is a legitimate empty one — the header reads
      `0 current-schema dataset(s), 0 legacy, 0 newer-schema (never pruned)` and the
      table's only body row is `(none)`. Correct, not a broken deployment
- [ ] `YaraConsolidateStatus` run — eligible scans reviewed
- [ ] Both modes understood — they read the **same** sources and differ only in fidelity:
      `Summary` keeps one row per (host, rule), `Apply` keeps every column of every
      matched-file row. **Neither deletes a source**
- [ ] Understood: **`Apply` is dry run by default** — nothing is written until `execute=true`,
      and no per-host matches dataset is ever deleted
- [ ] First pass scoped with `scan_id` rather than run open-ended — there is no scan-count cap.
      Size the batch against your own **marginal** per-scan cost: subtract the fixed ~105s
      per-pass overhead first, then divide by the scan count. Dividing a pass total by its scan
      count counts that fixed cost once per scan and will mislead you into batching too far
- [ ] `row_ceiling` left at 60,000. A group above it is refused, not half-written — at that
      scale reach for `Summary` instead of raising it

**Ongoing**

- [ ] Watch `yara_scanner_consolidation_runs` for `started` rows without terminal rows
- [ ] Consolidate after each wave, before those hosts are scanned again — it reconciles on
      `scan_id`, so a pass with nothing changed is a verified no-op
- [ ] Run `YaraCleanup` yourself — nothing in the pack schedules it, and it is the only thing
      that removes an aged scans shard. Never in the same window as consolidation
