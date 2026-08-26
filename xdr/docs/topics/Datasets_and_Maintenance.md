# Datasets and Maintenance — technical detail

*Applies to scanner **v3.4.0**. History of changes: [release notes](../../../CHANGELOG.md).*

Companion to the XDR YARA Scanner Guide. Read this to understand why the dataset names look
the way they do, and how to stop them growing forever.

> **The matches dataset no longer rotates.** Since v4 (scanner 3.4.0+) the *matches* dataset
> is a single **permanent** dataset per host, overwritten at the start of every scan — it is
> not deleted and rewritten each month the way §3 below describes. Only the *scans*
> (lifecycle) dataset still rotates monthly. This is a deliberate, load-bearing change — see
> [the pack README's "overwrite model" section](../../Packs/YaraDatasetManagement/README.md#the-overwrite-model--one-permanent-matches-dataset-per-host)
> for the full mechanism and measured numbers. §1, §3, §5 and §6 below are rewritten for it;
> §2's sharding rationale and §4's cleanup safety rails are unaffected and still current.

---

## 0. Which component does what — a map for reading the code

Three different things run in three different places. Almost every "why did that happen?"
question resolves faster once you know which one you are looking at.

| Runs | Component | What it is |
|---|---|---|
| **On the endpoint** | `xdr_yara_scanner.py` | The scan itself. Uploaded once to Action Center → Scripts, then dispatched per action (or by `playbooks/YARA_Scanner_Runner.yml`). Everything about *writing* data happens here. |
| **In the tenant** | The six `YaraDatasetManagement` automations | `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`, `YaraConsolidateSummary`, `YaraCleanup` — run from the War Room (`!YaraReport`) or by `playbook-YARA_Dataset_Consolidation.yml`. Plus `YaraWipeAllDatasets`, which is **not** wired to that playbook or any other content item — War Room / Playground only, by design (see below). Everything about *reshaping and pruning* data happens here. |
| **On an operator's machine** | `xdr_data_management.py`, `xdr_consolidate.py`, `xdr_action_center.py` | CLI equivalents, never uploaded to the tenant. `xdr_consolidate.py` is the readable source of the consolidation logic. |

> **The automations inline their library rather than importing it.** A tenant cannot resolve
> cross-script imports, so each of the five carries its own copy of the consolidation core.
> Read the logic in **`xdr/xdr_consolidate.py`** — the line numbers below refer to it — then
> regenerate the uploaded YAMLs with `tools/build_pack_unified.py` after any edit.

### Action → component → function

| Action | Component | Function (file:line) |
|---|---|---|
| Pick both dataset names, incl. the `_YYYYMM` suffix | scanner | `LookupDatasetUploader.__init__` — `xdr_yara_scanner.py:3996` |
| Build the collision-safe `_<host>_<6hex>` suffix | scanner | `_dataset_shard_suffix()` — `xdr_yara_scanner.py:614` |
| Create the datasets up front | scanner | `_ensure_datasets` → `_ensure_one` — `:4147`, `:4156` |
| **Overwrite: delete the previous scan's matches** | scanner | `_flush_stale_matches` — `:4260` |
| ↳ list the scan_ids already present | scanner | `_matches_scan_ids` — `:4370` |
| ↳ delete one scan_id's rows | scanner | `_remove_scan_id` — `:4454` |
| Upload this scan's rows | scanner | `_upload_worker` — `:3258` |
| **Refuse to consolidate the live matches dataset** | consolidation core | `parse_shard` — `xdr_consolidate.py:190`; `_is_live_overwrite_dataset` — `:512` |
| Report readiness (read-only) | `YaraConsolidateStatus` | `check_consolidation_status` — `xdr_consolidate.py:829` |
| Decide if one scan may consolidate yet | consolidation core | `_gate_scan` — `:978` |
| **Consolidate for real** (destructive) | `YaraConsolidateApply` | `consolidate_all` → `run_consolidation` — `:876`, `:643` |
| Name the per-scan target | consolidation core | `target_name` — `:184` |
| Summary-only consolidation | `YaraConsolidateSummary` | `_matches_shard_for_read` — `:1629`; `summary_target_name` — `:1584` |
| Inventory every dataset | `YaraReport` | `report_datasets` — `:1217` |
| **Prune old datasets** (destructive) | `YaraCleanup` | `prune_datasets` — `:1300` |
| ↳ pick rotated candidates + rails | cleanup core | `select_rotated_for_deletion` — `xdr_data_management.py:124` |
| ↳ pick legacy candidates + rails | cleanup core | `select_legacy_for_deletion` — `:251` |
| **Delete every dataset, no exceptions** (destructive, hand-run only) | `YaraWipeAllDatasets` | `wipe_all` → `list_all_yara_datasets` — `Scripts/YaraWipeAllDatasets/YaraWipeAllDatasets.py` (self-contained; no canonical CLI copy — see the pack README) |

Line numbers move as the code changes; the **function names are the stable handle** — grep for
those rather than jumping to a line.

## 1. What the scanner writes

```
yara_scanner_matches_v4_<host>_<6hex>       one row per matched FILE (rules folded into a
                                             JSON array) — PERMANENT, no month suffix, one
                                             per host, overwritten at the start of every scan
yara_scanner_scans_v4_<host>_<YYYYMM>       one row per scan lifecycle event — still rotates
                                             monthly, still append-only
```

The two datasets are named differently on purpose now — they have different lifecycles:

| Part | Why |
|---|---|
| `_v4` | schema version — bumped whenever the row shape changes |
| `_<host>_<6hex>` | per-writer sharding (§2); the 6-hex suffix is a short hash of the host identity, not a literal hostname |
| `_<YYYYMM>` (scans only) | monthly rotation (§3) — matches does **not** carry this any more |

The scanner **creates these itself** if they do not exist. It never depends on any other
script having run first.

### Why the 6-hex suffix — it's not a random ID

`_dataset_shard_suffix()` builds it in two steps:

1. **Slugify the hostname** to XDR's dataset-name rules (lowercase `[a-z0-9_]`, capped at 32
   characters): `WEB-SERVER-01.corp.local` → `web_server_01_corp_local`.
2. **Append the first 6 hex characters of a SHA-1 hash of the original, un-slugified
   hostname**: `web_server_01_corp_local_a1b2c3`.

The hash exists because slugifying is **lossy**. `web-server.corp` and `web_server_corp` and
`WEB-SERVER-CORP` all collapse to the identical slug, and two long hostnames can even get
truncated to the same 32-character prefix. Without something to break the tie, those
different hosts would land in the **same** dataset name — which is exactly the concurrent-
write collision the whole per-host sharding model exists to prevent (§2: 87% row loss
measured on shared writes). Hashing the *original* hostname, before slugifying, means two
hosts that collapse to the same slug still get different suffixes.

So `matches_v4_xdragent_68494d`: `xdragent` is the slugified hostname, `68494d` is
`sha1("xdragent")[:6]`. It carries no information on its own — it is not a version, a date,
or anything you configure. It only exists to keep otherwise-identical-looking hostnames from
colliding. Source: `xdr_yara_scanner.py`, function `_dataset_shard_suffix()`.

## 2. Why not one dataset for everything?

**One dataset would be the better design.** One object to manage, one place to query, no
proliferation. Every row already carries `scan_id`, `run_id`, `scan_date`, `hostname` and
`tenant_id`, so a single dataset would give you everything you need by filtering — nothing
about the *data* requires splitting it.

**We chose per-host datasets anyway, because the platform will not support the better
design.** This is a deliberate trade-off forced by a limitation in `lookups/add_data`, and
it is worth being precise about what goes wrong, because the failure is silent.

### What happens if you point a fleet at one dataset

XDR stages every `add_data` write through a per-write clone table. Two endpoints writing the
**same** dataset at the same time collide, the server returns a transient
`HTTP 500 ..._clone was not found`, and **the rows are lost**. Not rejected — lost. The
retry returns HTTP 200 and nothing anywhere reports a problem.

Measured on a live tenant with 8 endpoints writing one shared dataset: roughly **2 of 8
batches landed**. Spreading the writes client-side does not fix it — 45 seconds of jitter
across those 8 writers still lost most of them, because the server holds the dataset through
a slow merge that no amount of client-side politeness can shorten.

It also degrades as it grows. Merge time scales with the **size of the dataset**, not the
size of the write (§3), so a single fleet-wide dataset becomes the largest and slowest
object you have, widening the very window in which collisions happen. The failure mode
compounds.

With one writer per dataset the collision cannot occur by construction. Delivery was
verified at **8/8**.

### The cost we accept in exchange

**Dataset count.** Per-host sharding combined with monthly rotation means a 500-endpoint
fleet creates on the order of **1,000 datasets a month**. That is a real operational cost
and the honest reason it is tolerated is that the alternative loses customer data.

Two levers control it:

- **Bucket instead of per-host.** `CONFIG_LOOKUP_SHARD` accepts a literal label, so you can
  group hosts into a fixed set of shards — `wave1`, `emea`, `site-3` — rather than one per
  endpoint. Ten buckets across 500 hosts is 10 datasets, not 500. Choose a bucket count high
  enough that few endpoints in the same bucket scan concurrently; the risk returns as the
  number of simultaneous writers per dataset rises above one.
- **Delete old months.** `xdr_data_management.py` (§4) removes them on whatever retention
  you choose.

**What you do not lose is the query experience.** Dashboards match
`yara_scanner_matches*` / `yara_scanner_scans*` wildcards, so shards fan back in
automatically and a query spans the whole estate regardless of how many datasets sit behind
it. Filtering by `scan_id`, `scan_date` or `hostname` works exactly as it would against a
single dataset.

> Set `CONFIG_LOOKUP_SHARD = "none"` only for a single scanning endpoint. At fleet scale it
> is the configuration measured above at 2/8 delivery.

## 3. Monthly rotation — why the *scans* name carries a date

`CONFIG_LOOKUP_ROTATION = "monthly"` (the default) appends `_<YYYYMM>` to the **scans**
dataset only, so a fresh one begins each month. It has no effect on matches — see the
callout at the top of this page.

**This exists because `add_data` merge time scales with dataset SIZE, not payload size.**
Measured on a live tenant, writing a single row:

| Dataset size | Time per write |
|---|---|
| 15,000 rows | ~13 s |
| 77,000 rows | ~31 s |

An unrotated append-only dataset therefore gets progressively slower until writes exceed any
client timeout and it goes **write-dead** — observed at ~77k rows, where a host lost the
majority of a scan's rows to read timeouts. That is exactly the failure mode the matches
dataset used to be exposed to before the overwrite model — an append-only dataset with no
bound eventually goes write-dead regardless of *why* it never shrinks. Rotation was the
original fix for scans and matches alike; for matches the overwrite (§1) is now the fix
instead, because a permanent single-scan dataset never grows past one scan's worth of rows in
the first place — it does not need rotation to stay small.

Rotation bounds the scans dataset's size permanently, so write time stays flat forever.

> Rotation **bounds size but deletes nothing.** Old months accumulate on the tenant
> indefinitely. That is what §4 is for. `YaraReport`/`YaraCleanup` correctly treat a live
> matches dataset as a permanent, never-delete candidate rather than as "not rotated" —
> that classification was fixed in the pack; if you are running scanner 3.4.0+ against an
> **older** copy of the pack automations, re-deploy them before relying on this.

### Rotation is passive — a quiet month produces nothing

Nothing schedules rotation, and no job runs on the 1st of the month. The suffix is fixed from
**the scan's own start date** (`_rot = f"_{self.scan_date[:6]}"`, local time, stamped once when
the uploader is constructed). A scan that starts at 23:50 on 31 January and writes rows past
midnight still writes them all to `_202601`.

Datasets are created **eagerly at scan start**, before any file is scanned — so a scan that
finds nothing still creates its datasets for that month. But nothing constructs the uploader
when no scan runs, so a month in which a host is never scanned simply has no dataset. Nothing
is created, nothing rotates, no empty shard appears, and nothing is deleted. Skip August
through October and the tenant just has no `_202608`/`_202609`/`_202610` shard for that host;
the next scan in November writes to `_202611` and the gap is absent rather than empty.

The host's **matches** dataset is likewise untouched by the passage of time. It holds its last
scan's findings indefinitely, with no expiry — a host scanned once and never again keeps that
one scan's results available until someone deletes it deliberately. That permanence is
explicit, not incidental: `YaraCleanup` excludes unsuffixed datasets by safety rail, and
`YaraConsolidateApply` is blocked from consuming the live v4 dataset by two independent guards
(`parse_shard` returns `None` for it; `_is_live_overwrite_dataset` blocks both destructive call
sites), each pinned by tests.

### Why matches is overwritten rather than rotated — the 50 MB cap

**A lookup dataset is capped at 50 MB by the platform.** It is not tunable, and it is the
constraint the whole matches design answers to.

Rotation bounds size only *statistically* — a month is an arbitrary interval, and how much lands
in one depends entirely on scan frequency and ruleset noise. Overwrite makes the bound
structural: because every scan begins by deleting the previous scan's rows
(`_flush_stale_matches`), the dataset holds **one scan's findings**, whether that host is
scanned once a year or six times a day. That is also why the matches dataset needs no month in
its name — there is no accumulation for a month boundary to interrupt.

Two honest caveats:

- **A single host filling 50 MB on its own is not a routine concern.** It needs a pathological
  ruleset, not a large disk — see [CAPACITY.md](../CAPACITY.md), where the measured worst case
  was 2.57 MB and filling the cap extrapolates to millions of matched files on one machine.
- **The ceiling is by design, not by guarantee.** The flush *fails safe*: every failure is
  logged and swallowed, leaving stale rows rather than aborting the scan. If the flush is
  persistently failing (most often a missing **Query Center** permission on the scanner's key),
  the dataset does accumulate. The scanner warns at >1000 distinct `scan_id`s
  (`"the overwrite has not been landing"`), and every run logs a
  `Matches dataset overwrite [outcome]` line. Watch that line — it is the only signal.

> ### ⚠ Re-scanning a host destroys the previous scan's file-level matches — permanently
>
> The flush deletes **every** other `scan_id`'s rows from its host's matches dataset at scan
> start. It does not check whether those rows were archived anywhere first, because on v4
> **nothing archives them.**
>
> This is the part that surprises people: **consolidation does not protect the live matches
> dataset, and no consolidation cadence changes that.** `YaraConsolidateApply` is deliberately
> blocked from consuming the live v4 dataset (consolidating it would recreate exactly the
> unbounded per-scan growth the overwrite model removed). `YaraConsolidateSummary` *does* read
> it, but writes only four columns — `scan_id`, `hostname`, `rule`, `event_timestamp_ms`. No
> filenames, no offsets, no per-rule counts.
>
> So on v4, a host's file-level detail lives in exactly one place — its live matches dataset —
> and the next scan on that host replaces it. Alerts already raised are unaffected (a separate
> delivery channel, untouched by the flush), and summary rows survive if summary mode ran. The
> filenames and offsets do not.
>
> **Practical rule:** treat each scan's file-level findings as valid until that host is scanned
> again. If you need them to outlive the next scan, export or act on them first — or run
> `YaraConsolidateSummary` to keep at least the rule/host/timestamp record. Scheduling
> consolidation more frequently does **not** help here.

## 3b. The run-log datasets — why three `*_runs` datasets exist

Alongside the scan data you will see three small datasets that no scan ever writes:

| Dataset | Written by | One row records |
|---|---|---|
| `yara_scanner_consolidation_runs` | `YaraConsolidateApply` | `status`, `consolidated_count`, `failed_count`, failed scan IDs and their reasons |
| `yara_scanner_cleanup_runs` | `YaraCleanup` | `mode`, `schema_version`, `deleted_count`, and the retention scope the pass ran with |
| `yara_scanner_wipe_runs` | `YaraWipeAllDatasets` | `mode`, `total_found`, `deleted_count`, `failed_count`, `stopped_early` |

They are an **audit trail: one row per run**. Every automation that mutates or deletes
writes one; the read-only ones (`YaraReport`, `YaraConsolidateStatus`) write nothing.

### Why keep them

**A War Room entry scrolls away; a dataset does not.** These answer "did last night's pass
actually run, and what did it do?" days later, from XQL, without hunting through job history.

**They make a killed run detectable.** `YaraConsolidateApply` writes a `started` row *before*
the merge and a terminal row after. The platform kills a task that overruns its ~900 s
timeout, and a kill runs no Python — so the terminal row is unreachable in exactly the case
worth diagnosing. **A `started` row with no matching terminal row is the timeout-kill
signature**, and it is only visible because the first row was written in advance.

**They settle "what actually happened" after an ambiguous failure.** A wipe once surfaced as a
bare `Internal Server Error`. Its `wipe_runs` row showed `total_found=245`,
`deleted_count=195`, `failed_count=48` — and because `195 + 48 = 243` matched the candidate
count, the pass had demonstrably *completed* rather than being killed mid-batch. That
distinction came from the row, not the error message.

**They are the record of a destructive act.** `YaraWipeAllDatasets` logs both dry runs and
executed ones, so "who checked what a full wipe would remove, and when" survives even when
nothing was deleted.

### Why the wipe never deletes them

All three are in `PRESERVED_DATASETS`, so `YaraWipeAllDatasets` skips them even though they
match `yara_scanner_*`. Deleting the record of a wipe defeats the reason it exists.

### Two things that surprise people

**They do not appear in `!YaraReport`.** The inventory classifies `matches`, `scans` and
`summary` datasets; the run logs sit outside that naming contract deliberately, so they are
never mistaken for scan data or considered for retention. Query them directly by name.

**Nothing prunes them.** They grow by a row or two per run, forever. At a few hundred bytes a
row this is immaterial for years, but it is unbounded by design rather than by a rail — worth
knowing before a very high-frequency schedule.

> **`YaraConsolidateSummary` does not write a run log.** It is the one mutating automation
> with no audit row, so a scheduled summarisation cannot be confirmed from the tenant the way
> a consolidation or a cleanup can. Check its War Room output instead.

### Worked example — the two modes are independent

Observed on a live tenant, 2026-08-26, three hosts scanned by one Action Center launch:

```
!YaraConsolidateSummary schema_version="4" retention_hours="24" execute="true"
  EXECUTED.  XQL calls: 6 (+1 dataset listing)  [single-query]
  written: 1 | skipped: 0 | failed: 0 | file-level findings collapsed: 1134
  rules 90149530ddc2: wrote 24 row(s) for 3 new scan(s), dropped 0 stale row(s)
                      -> yara_scanner_summary_v4_rules_90149530ddc2 (3 host(s) total, completed)

!YaraConsolidateStatus
  3 scan(s) eligible to consolidate
  eligible: xdr-agent_20260825_103650..., xdragent2_20260825_103653..., xdragent_20260825_103654...
```

**`Status` still lists all three as eligible, and that is correct.** It reports readiness for
`YaraConsolidateApply`, which had not run. `Summary` writing a rollup does not make a scan
consolidated, because `Apply` merges the *scans* shards and `Summary` never touches them.

Read it as two independent questions:

| Question | Answered by |
|---|---|
| Has this scan's rule/host record been captured? | the `summary_v4_rules_<hash>` dataset exists |
| Have this scan's lifecycle shards been merged and removed? | `YaraConsolidateStatus`, and the presence of `scans_v4_scan_<id>` targets |

`!YaraReport` at the same moment showed all three source shards still present, no per-scan
targets, and the summary dataset alongside them — the state both answers describe.

## 4. Cleanup — `xdr_data_management.py`

A small standalone script that deletes whole old datasets.

**It is deliberately not a prerequisite for anything.** The scanner creates its own datasets
and writes to them self-sufficiently. If this script never runs, datasets get large and
eventually slow, but **every scan still succeeds**. Cleanup is optional work; creation is
not, and coupling them would mean a scan could fail because a different script had not run.

```bash
python3 xdr_data_management.py --report                      # inventory (default action)
python3 xdr_data_management.py --older-than-months 6 --yes   # drop months older than 6
python3 xdr_data_management.py --delete-legacy --yes         # drop older-than-current-schema datasets
```

### Reading the report

`--report` lists every YARA dataset with kind, host and age in months, and flags two
conditions:

| Flag | Meaning |
|---|---|
| **`frozen`** | An unsuffixed dataset that has rotated siblings. It predates rotation, is no longer written to, and is left alone. |
| **not rotated** | An unsuffixed dataset with *no* rotated siblings — rotation is off for that deployment and the dataset really will grow without bound. The report names the config change. |

Neither is ever deleted automatically: an unsuffixed dataset holds **all** pre-rotation
history for a host, so removing one is a bigger decision than dropping a month.

### Safety rails

Nothing is deleted if it is:

1. **the current month** — a scan may be writing to it
2. **a future-dated month** — clock skew must not destroy data
3. **unsuffixed** — see above
4. **on a newer schema version** than this host understands
5. **outside the `yara_scanner_*` naming contract** — unrelated tenant data is unreachable
6. **written to more recently than `--min-quiet-hours`** (default 24h, checked live via
   XQL) — a rotation suffix reflects when a dataset was *created*, not when it was last
   written; a long-running scan against a host whose shard rotated months ago is still
   writing to that "old-looking" name
7. **still holding a scan_id `--consolidate` (§5) hasn't fully verified into a per-scan
   target** — most often a scan that tripped the row ceiling, or was never consolidated at
   all; deleting it would be the only copy of that scan's findings gone for good

Plus: **dry run unless `--yes`**, and `--older-than-months` has no default, so a bare `--yes`
deletes nothing. Rails 6 and 7 each cost one extra XQL query per candidate dataset and, like
every other rail here, skip (keep) the dataset rather than delete it if that query errors.

> **Why the current-month guard matters.** Deleting a dataset a scan is actively writing to
> does not error the scan — the scanner keeps POSTing rows to a name that no longer exists
> and receives HTTP 400 per batch. Across a fleet mid-scan that is silent, partial data loss
> discovered days later as a gap in the dashboards.

A failed delete is reported and the run continues to the next dataset, so one dataset with
dependencies cannot strand the whole cleanup. Exit code is non-zero if any deletion failed.

## 5. Consolidation — one dataset per scan

Deleting old months (§4) bounds *age*. It does not bound *count*: a fleet still produces one
scans dataset per host every month, and — since a single scan can legitimately span many
scan_ids over time — the *matches* side still benefits from being folded down to one dataset
per scan even though it no longer rotates. Consolidation addresses the count directly — it
folds each scan's per-host shards into a **single dataset per scan**, and, in the mode that
does so, deletes the shards.

**Two delivery mechanisms exist for the same underlying logic** (`xdr_consolidate.py`):

- **The pack automations** (`xdr/Packs/YaraDatasetManagement/`) — `YaraConsolidateStatus`
  (read-only check), `YaraConsolidateApply` (writes and **deletes** verified source shards),
  `YaraConsolidateSummary` (writes a lightweight rollup, **deletes nothing**), driven by the
  `YARA Dataset Consolidation` playbook or invoked directly from the console. This is the
  supported day-to-day path — see the
  [pack README](../../Packs/YaraDatasetManagement/README.md) for the full comparison of the
  two modes, arguments, and outputs.
- **The CLI** (`xdr_data_management.py --consolidate`) — the same logic, for scripted/ad-hoc
  use outside XSOAR:

  ```bash
  python3 xdr_data_management.py --consolidate                 # dry run — plan only
  python3 xdr_data_management.py --consolidate --yes           # apply
  python3 xdr_data_management.py --consolidate --scan-id <id>  # one scan (repeatable)
  ```

  > **The CLI path has no per-pass bound.** `--consolidate --yes` calls the same underlying
  > merge logic as the pack's `YaraConsolidateApply`, but without the cap described below —
  > `_run_consolidate` in `xdr_data_management.py` was not updated when that cap was added.
  > A CLI-driven consolidation against a large backlog can run for as long as there is work
  > to do; there is currently no equivalent of `--max-scans` to bound one invocation. Restrict
  > scope with `--scan-id` (repeatable) if you need to control how much one run touches.

The result is `yara_scanner_matches_v4_scan_<scan_id>` / `..._scans_v4_scan_<scan_id>`: all
hosts for one scan, in one place, filterable by the same fields as before.

> **On v4, the matches side of this only applies to *dated* leftovers.** `YaraConsolidateApply`
> is blocked from consuming a host's **live** unsuffixed matches dataset, so it can only produce
> a `matches_v4_scan_*` target from pre-overwrite dated shards (`…_202608`) still on the tenant.
> The scans side is unaffected — scans still rotates monthly at v4 and consolidates normally.
> See §3's overwrite callout for what this means for retaining file-level detail.

**This is a housekeeping step, not a requirement, and not a reporting fix.** Reporting never
needed it — dashboards query `yara_scanner_*` wildcards, so a query spans per-host and
per-scan datasets identically. Consolidation only reduces how many datasets exist.

> **`YaraConsolidateApply` is destructive with no dry-run mode; `YaraConsolidateStatus` is
> read-only.** Check status first if you want to see what a pass *would* do before it does
> it. There is no equivalent "would delete" flag on Apply itself.

### One pass is bounded — it is not "run once and the backlog is gone"

Both the CLI and the pack `YaraConsolidateApply` cap how many scans **one invocation**
processes (`--max-scans` / the `max_scans` argument, default **4**), so a pass finishes
comfortably inside the script/task timeout instead of being killed mid-merge while still
holding the consolidation lock — measured live: a 5-scan pass used 71% of a 900-second
timeout, and 20 would have been killed around scan 7. A bounded pass reports how many scans
it left for next time; a backlog larger than one pass's cap needs to be **re-run**, or the
cap raised, to fully drain — it does not resume itself automatically.

### The consolidation lock

Only one Apply/Summary(execute) pass may write at a time — a second concurrent invocation
finds the lock held and returns immediately, touching nothing. The lock is a dataset
(`yara_scanner_consolidation_lock`) created by whichever run wins the race to create it
first; the second run's `create_lookup_dataset` returns "already exists" instead of failing,
which is the actual mutex. If a run is genuinely dead (crashed, or its host container was
recycled) without releasing the lock, another run treats it as **stale** after 20 minutes and
takes over — sized to roughly the 900-second task timeout, not to how long a healthy run
could conceivably take. **A run can, in practice, keep executing well past its declared
timeout without the platform actually killing it** — treat a caller's request timing out as
"unknown," not "dead," and check `yara_scanner_consolidation_runs` (a `started` row with no
matching terminal row means a pass is still — or was still — running) before assuming it is
safe to intervene manually.

### Why it is safe to run against live data

It deletes datasets, so it is deliberately conservative:

- **One sequential writer** per target — never exposed to the concurrent-write collision
  that per-host sharding exists to avoid (§2).
- **Verify before delete** — a shard is deleted only after the target's row count equals the
  sum of its sources. A mismatch keeps every source and reports it.
- **A shard is deleted only when every scan in it is consolidated.** A host re-scanned in
  the same month shares one dataset; deleting after a single scan would destroy the others.
  Re-running is idempotent — an already-consolidated scan is detected and not rewritten.
- **Abandoned-scan cutoff.** A scan stopped by the console Cancel leaves its lifecycle stuck
  at `running`/`initiated` forever (§5, and the Scan Cancellation guide), which would block
  its shard from ever being cleaned. A non-terminal scan whose newest row is older than
  **24 hours** (`--abandoned-after-hours`, past the 6 h action timeout so a live scan is
  never mistaken for one) is treated as abandoned: it stops blocking cleanup, and its partial
  matches are still consolidated rather than dropped.
- **Row ceiling** (`--row-ceiling`, default 2,000,000) refuses a consolidation too large to
  finish rather than half-building a target.

> **What "verify before delete" does *not* check.** The row-count comparison confirms the
> target has as many rows as its sources combined — it does not compare row *content*. A
> corrupted or duplicated write that happens to land on the same count would still pass and
> the source would still be deleted. And once `delete_dataset` runs, the platform has no
> undelete or dataset versioning to fall back on — a mismatch or bug caught after the fact
> cannot be recovered, only avoided by verifying before you run with `--yes`. Treat
> consolidation, like the pruning in §4, as one-way.

### What it will and will not clean

A scan is consolidated once it is **finished** — a terminal lifecycle row, or abandoned past
the cutoff. Scans still genuinely in progress are deferred to a later run. A per-host shard
is removed only once *all* of its scans are handled, so on a busy host you may see per-scan
targets appear while the shard persists until its last scan clears.

> Deleting a whole dataset takes ~60 seconds server-side on the tenants measured. Deletes of
> different datasets do not conflict, so consolidation runs them concurrently (12 at a time);
> even so, cleaning a large fleet is an hours-scale background job, not instant. Run it off-
> peak.

## 6. Row shapes

**`yara_scanner_matches_v4_*`** — one row per matched **file**, not per matched string or
per rule: host, file path, severity, scan id, timestamps, plus a `rules` field holding a
JSON array of every rule that matched that file (rule name, match count, offsets, matched
strings). This folds v2/v3's one-row-per-finding grain down to one row per file — measured
~47% smaller for the same underlying findings.

**`yara_scanner_scans_v4_*`** — scan lifecycle. Each scan writes `initiated`, then a terminal
row (`completed` / `cancelled` / `failed`), plus periodic `running` rows.

> A scan stopped by the **console Cancel** never writes a terminal row, so its lifecycle
> stays at `initiated` or `running` permanently and dashboards show it as running forever.
> See the Scan Cancellation topic guide.

## 7. Schema changes

The row shape is pinned by the `_v4` tag (currently) for a reason: **`add_data` silently skips rows
carrying fields that are not in the existing dataset's schema.** It returns
`records_skipped=N, records_added=0` with HTTP 200 and no error anywhere.

A schema cannot be altered in place. So any change to the row shape requires bumping the
version tag, which starts new datasets. If you add a field without bumping, scans will
report success while their telemetry silently vanishes.
