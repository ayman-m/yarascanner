# YARA Dataset Management (XSOAR pack)

Consolidates each finished YARA scan's findings out of the per-host lookup datasets and
into one dataset per scan — safely, at fleet scale — reports what needs attention, and prunes
what has aged out. There are **two consolidation modes**, full detail and summary only; which
one you want is the first decision to make and it is answered in
[Two consolidation modes](#two-consolidation-modes--full-detail-or-summary-only) below. This
is the XSOAR-pack delivery of the same logic in [`xdr_consolidate.py`](../../xdr_consolidate.py)
and [`xdr_data_management.py`](../../xdr_data_management.py) (see
[Datasets and Maintenance](../../docs/topics/Datasets_and_Maintenance.md) §5 for the
underlying design and safety rails); this pack runs it as a scheduled Job instead of a
manual CLI invocation.

## What's in the pack

| Item | Type | Role |
|---|---|---|
| `YARA Dataset Consolidation` | Playbook | Orchestrates one pass: check readiness → wait on in-progress scans → **consolidate in the mode `consolidation_mode` selects** → flag failures. Meant to run **twice daily** as a scheduled Job. |
| `YaraConsolidateStatus` | Automation | Read-only readiness check. Never writes or deletes. Shared by both modes. |
| `YaraConsolidateApply` | Automation | **Mode A, full detail.** Creates per-scan targets and deletes fully-verified source shards. On the v4 overwrite model the only shards it can see are the **scans** lifecycle ones — `parse_shard` excludes the permanent per-host matches dataset by design — so its matched-file copy path fires only on a month-suffixed matches shard (v2/v3, or dated v4 debris). |
| `YaraConsolidateSummary` | Automation | **Mode B, summary only.** One row per (host, rule) — which rules fired on which host — into `yara_scanner_summary_v<VER>_scan_<slug>`. Four columns, no filenames, no per-rule counts. **Deletes nothing at all.** Dry run unless `execute=true`. On v4 it is also the **only** automation that writes a durable per-scan record of what matched. |
| `YaraReport` | Automation | Read-only inventory of every `yara_scanner_*` lookup dataset (kind, host, age, plus the legacy / newer-schema / consolidated buckets). One API call, no writes — safe any time. Writes to `Yara.Report.*`. |
| `YaraCleanup` | Automation | Retention pruning — **deletes whole datasets**. Dry run by default; see below. |
| `YaraWipeAllDatasets` | Automation | **Deletes every `yara_scanner_*` dataset on the tenant, unconditionally.** No scoping, no rules. **Not wired to the playbook or any other content item — run it by hand only.** See below. |

## The overwrite model — one permanent matches dataset per host

Everything below depends on this, so it comes first. It changed with the v4 scanner and it
is the reason a second consolidation mode exists at all.

```
yara_scanner_matches_v4_<host>_<6hex>     one per host. No scan_id. No month suffix.
```

The scanner keeps **one matches dataset per host, permanently**, and **overwrites it at the
start of every scan**: after ensuring the dataset exists and *before* the writer thread is
started, it enumerates the `scan_id`s already in there and removes every row belonging to a
**previous** scan (`xdr/xdr_yara_scanner.py:4577` `_flush_stale_matches`, called from
`:4450`; naming at `:4360`). The current scan's own `scan_id` is never a removal target, and
a dataset that did not already exist is skipped entirely. So the dataset never accumulates,
always exists, and always holds exactly the newest scan of that host.

That makes it **the deep-dive source** — the only place the per-file detail behind a
consolidated row still lives — and it is why summary mode never deletes it.

**The overwrite is a `remove_data` filter flush, not a delete-and-recreate.** Measured live
on this tenant:

| Operation | Measured | Notes |
|---|---|---|
| `remove_data` filter flush | **10.0s** for ~550 rows | Keeps the dataset object and its schema alive. What the scanner does. |
| `delete_dataset` + recreate | **190.2s** (the delete alone: 187s) | **19x slower**, and it drops the schema. Never used for the overwrite. |
| `add_lookup_data` write | 44.7s for 1,097 rows, 3 batches of 500 (~15s/batch) | At fleet scale the **write** dominates, not the flush. |

(For scale, the v4 row grain those numbers came from: `/usr`, 93,137 files → 1,836 findings
→ 1,097 rows at 749 B ≈ 0.78 MB.)

Three consequences worth knowing before you run anything:

* **Rotation does not apply to the matches dataset any more.** `CONFIG_LOOKUP_ROTATION`
  governs the *scans* (lifecycle) dataset only — that one is append-only and still grows, so
  bounding its size still means something. Rotation exists to bound size; the overwrite
  already bounds matches to a single scan. Leaving it on would have minted a new dataset
  every month regardless of the overwrite, moved the deep-dive source's name under every
  dashboard pinned to it, and left last month's copy holding its final scan's rows for ever
  with nothing that ever overwrites them. `YaraReport` and `YaraCleanup` classify a live
  matches dataset as a permanent `overwrite` state, distinct from both `frozen` and
  `not rotated` — the report line reads "N permanent per-host matches dataset(s) — replaced
  wholesale at the start of every scan... rotation does not apply", not the old
  "set `CONFIG_LOOKUP_ROTATION="monthly"`" advice. That fix is gated on schema version (v4+
  only); a tenant still pinned to v2/v3 correctly keeps seeing the old advice, because
  matches genuinely still rotated under those versions.
* **The flush needs Query Center on the *scanner's* delivery key**, not this pack's key. It
  enumerates the stale `scan_id`s with one XQL. Without `investigation_query_view` every
  scan 403s on that enumeration, fails safe, and the dataset quietly goes back to
  accumulating — the scan log says so and nothing else will. See
  [API_Permissions.md](../../docs/topics/API_Permissions.md), Key 1.
* **One open question, and it cannot bite here.** Whether `remove_data` re-stamps
  `_insert_time` on *surviving* rows is unresolved (`../../docs/topics/Known_Limitations.md:66`).
  The overwrite is a full flush of every previous `scan_id`, so no row survives it for a
  re-stamp to touch. It would matter to a partial, filtered removal; this is not one.

## Two consolidation modes — full detail or summary only

The host dataset and the scanner behave **identically** under both modes, and on v4 the
host dataset survives both — full mode cannot reach it. What differs is what each mode
reads and what it copies out: only summary mode reads the per-host matches dataset, and
only summary mode records what matched.

| | **A. Full detail** | **B. Summary only** |
|---|---|---|
| Automation | `YaraConsolidateApply` | `YaraConsolidateSummary` |
| Source enumeration | `parse_shard` — which returns `None` for the v4 per-host matches dataset, so on a current-model tenant it sees **no matches shards at all** | `_matches_shard_for_read` — a deliberately wider, read-only inclusion that **does** see the live per-host dataset, because reading it is safe when nothing is ever deleted |
| Target | on v4, `yara_scanner_scans_v<VER>_scan_<slug>` — the lifecycle record. The matches target `yara_scanner_matches_v<VER>_scan_<slug>` is written only for a **month-suffixed** matches shard (v2/v3, or dated v4 debris) | `yara_scanner_summary_v<VER>_scan_<slug>` |
| Row grain | on v4, the scan's lifecycle rows, copied verbatim; every matched-file row, copied verbatim, on a month-suffixed matches shard | **one row per (host, rule)** |
| Columns | on v4, the scans lifecycle schema; the full v4 match schema on a month-suffixed matches shard | `scan_id`, `hostname`, `rule`, `event_timestamp_ms` — and nothing else |
| Records what matched | **no**, not on v4 — with no matches shard in scope, it consolidates lifecycle rows only | **yes.** The only automation that writes a durable per-scan record of which rules fired |
| Per-rule counts | n/a | **deliberately absent.** A count column turns every dashboard query over the summary into an aggregation over numbers instead of a distinct-set lookup. |
| Source shard afterwards | **deleted**, once the target's row count verifies — on v4 that means the *scans* shards. The per-host matches dataset is never deleted: `parse_shard` keeps it out of the list, and `_is_live_overwrite_dataset` re-checks both destructive call sites | **untouched.** No `delete_dataset`, no `remove_lookup_data`, no row removal anywhere in the file. `shards_deleted` is always `0` and is reported so a playbook can assert it. |
| Read cost | reads the shard's rows | **one XQL per host shard**, which expands the v4 `rules` JSON array and groups inside the engine, so the rows never leave the tenant |
| Write verification | required — it must count rows into the target *before* deleting the source | not required — the source outlives the run, so a partial write is fixed by re-running |
| Default | writes (and deletes) | **dry run** unless `execute=true` |

**Which one to use.**

* **Summary** is the right default for fleet-wide reporting: "which rules fired on which
  host, per scan". It is the cheap variant, it is the safe variant, and it composes with the
  overwrite model — the per-host dataset stays in place, so any summary row can still be
  drilled into for the files behind it. Its size limit is `50 MB` per lookup dataset, which
  at ~163 B per (host, rule) row is ~321,649 rows: **the fleet limit is rules-matched-per-host,
  not host count.**
* **Full detail** answers file-level questions from the per-scan dataset alone — an
  investigation workflow that queries only the per-scan target, or a tenant where that
  target is exported elsewhere — but **on v4 it has nothing to build one from.** The only v4
  matches dataset a host has is the permanent per-host one, and `parse_shard` excludes that
  by design, so a v4 full-mode pass consolidates the scans lifecycle shards and writes no
  matches target. It remains the file-level mode on a **v2/v3** fleet, and it still picks up
  a month-suffixed v4 matches dataset left over from before the overwrite model.
* **They are not interchangeable after the fact — and on v4 the reason has inverted.** Full
  mode does not delete the per-host dataset; it cannot reach it. What it does instead is
  record nothing about what matched, so a scan consolidated in full mode leaves a per-scan
  *lifecycle* row and no per-scan record of which rules fired. Summary mode is the only
  thing that writes one. Either way the per-host dataset stays the only place per-file
  detail lives, until the next scan on that host overwrites it — at which point that scan's
  file-level detail is gone and nothing archived it. Pick per deployment, not per run.
* **One pass is bounded, in both modes.** `YaraConsolidateApply` takes `max_scans` (default
  **4**) to cap how many scans one invocation processes, so it finishes comfortably inside
  the script timeout instead of being killed mid-merge while still holding the consolidation
  lock — measured live: a 5-scan pass used 71% of a 900-second timeout, and 20 would have
  been killed around scan 7. A bounded pass reports how many scans it left for the next run;
  the playbook's `max_scans` input passes this through, but a full backlog larger than one
  pass still needs to be **re-run**, or the cap raised, to fully drain — it does not loop on
  its own within a single playbook execution.

### Choosing the mode from the playbook

`YARA Dataset Consolidation` takes a **`consolidation_mode`** input, `full` (default) or
`summary`. Task 11 branches on it: `full` → `YaraConsolidateApply` (exactly the pre-existing
flow, same arguments), `summary` → `YaraConsolidateSummary`. Every pre-existing input still
works unchanged, and an existing scheduled Job that predates this input picks up the `full`
default, i.e. the behaviour it already had.

| Playbook input | Default | Notes |
|---|---|---|
| `consolidation_mode` | `full` | Matched **exactly** against `full` and `summary`. Anything else — a typo, an empty value — reaches neither automation: it lands on a dead-end task that merges, writes and deletes nothing, so an unrecognised mode can never fall through to the branch that deletes shards. |
| `summary_execute` | `true` | Summary mode only. `YaraConsolidateSummary` is a dry run unless `execute=true`, so a scheduled Job with this defaulted the other way would report forever and never write a row. Set it to `false` deliberately to preview a pass. The full-detail branch has no equivalent — `YaraConsolidateApply` always writes, and deletes. |
| `abandoned_after_hours` | *(script default: 24h)* | Reaches summary mode as its `retention_hours`: the same idea (how long a non-terminal scan may be silent before it is consolidated anyway), and in summary mode it is **only** that threshold — it is not a deletion window, because nothing is deleted. |

`schema_version` is deliberately **not** a playbook input. A single-version fleet is served
by the automation's own default; a fleet mid-rollout should be summarised by invoking
`YaraConsolidateSummary` directly per version rather than by giving a scheduled Job a version
number that will go stale. (The automation handles both shapes: v4 expands the `rules` JSON
array, v2/v3 read their scalar `rule` column.)

Summary-mode results land under `Yara.ConsolidateSummary.*`: `written`, `skipped`, `failed`,
`dry_run`, `xql_calls`, `query_modes`, `findings_collapsed` (how much file-level detail the
summary collapsed — reported only, never written into a row), `shards_deleted` (always `0`),
plus the `schema_version` and `retention_hours` the run used. A failure here never destroyed
anything, so it is a flag to read rather than an incident to chase: host shards are untouched
in every failure case and **re-running is always safe**.

**On a tenant with no YARA datasets yet, every one of those counts comes back `0` and every
list comes back empty — that is the correct result, not a broken deployment.** The first line
reads `DRY RUN - nothing was created or written.  XQL calls: 0 (+1 dataset listing)`, with
`EXECUTED.` in place of the dry-run head when `execute=true`, followed by
`written: 0 | skipped: 0 | failed: 0 | file-level findings collapsed: 0`; `written`,
`skipped` and `query_modes` come back empty, while `schema_version` and `retention_hours`
still report what the run used. There is no host shard to read — nothing is misconfigured.
Budget for the wait, though: `execute=true` with nothing to do still takes ~70s in-process
(~100-110s as seen in the War Room), while the dry run returns in about a second.

**Two consequences of summary mode, stated rather than defended against.** Summary targets
are invisible to `YaraCleanup` by construction — the name matches neither the current-dataset
regex nor the shard regex, which is what stops one `delete_legacy=true` pass taking every
summary target with it, and the price is that they accumulate one per scan for ever. They are
also the smallest datasets this pipeline makes. And a scan consolidated by summary mode is
not recorded as consolidated by the merge's own bookkeeping (which keys on the *matches*
per-scan target name), so on a summary-only tenant `YaraCleanup`'s rail 7 will still read
those matches shards as unconsolidated. Under the overwrite model that rail is moot for the
permanent per-host dataset — an unrotated dataset is never a candidate anyway — but know it
before running the two modes side by side.

## Read-only inventory — `YaraReport`

Wraps the CLI's `xdr_data_management.py --report`. It lists every `yara_scanner_*` lookup
dataset with its kind, host and age in whole months, and separates the legacy, newer-schema
and per-scan-consolidated buckets. **It never writes or deletes anything**, and issues
exactly one API call (the dataset listing) — safe to run at any time, from a poll loop, or
alongside a running consolidation or cleanup pass. Start here before running `YaraCleanup`:
this is how you find out what a prune would even be looking at.

| Argument | Default | What it does |
|---|---|---|
| `schema_version` | `2` | The scanner's current lookup schema version (`YARA_LOOKUP_SCHEMA_VER` on the endpoints). Must be a whole number — see the `schema_version` note below. Datasets on a *higher* version are reported under "newer schema"; if this is stale, that is where everything lands. |

It flags two unsuffixed-dataset conditions that look identical in a dataset listing but need
**opposite** advice, which is the main reason to run it:

* **`frozen`** — unsuffixed, but rotated siblings exist. A pre-rotation leftover: rotation
  *is* on for that host, writes moved to the dated names, and this dataset is finished and
  not growing. Nothing to do.
* **`not_rotated`** — unsuffixed with *no* rotated siblings. Rotation is genuinely off for
  that deployment and the dataset will grow without bound until it goes write-dead. Fix it
  at the source: set `CONFIG_LOOKUP_ROTATION="monthly"` in the scanner.

Per-scan consolidated targets (`…_scan_<id>`) are unsuffixed too, but they are consolidation
*output* — finished by design, not a rotation failure — so they get their own
`consolidated` state and are counted in neither bucket.

Outputs land under `Yara.Report.*`: the rendered table as `report`, per-dataset rows as
`datasets` (name / kind / host / month / age_months / state), plus `frozen`, `not_rotated`,
`consolidated`, `legacy`, `newer` and a `*_count` for each. The War Room entry carries the
same table inside a code fence so its fixed-width columns stay aligned.

**A tenant with no YARA datasets yet reports zeros, and that is the correct answer.** The
header line reads `0 current-schema dataset(s), 0 legacy, 0 newer-schema (never pruned)`,
the table's only body row is `(none)`, `datasets` is empty and every `*_count` is `0`, while
`now_yyyymm` and `schema_version` are still populated. Nothing is misconfigured: a listing
that fails — a bad credential included — raises, and the automation returns an error rather
than a table, so a report of zeros is a successful run and not a silent one.

## Retention pruning — `YaraCleanup`

> **`YaraCleanup` DELETES WHOLE LOOKUP DATASETS, and the platform has no undelete.** There
> is no recycle bin, no soft-delete, no retention grace period and no restore-from-snapshot
> for a lookup dataset on this tenant: once `delete_dataset` succeeds, every row that
> dataset held is gone permanently, and for an unconsolidated scan those rows were that
> scan's only copy. **It is a dry run unless you pass `execute=true`** — that single
> argument is the entire difference between a report and irreversible data loss. Everything
> below exists because that call cannot be taken back.

`YaraCleanup` wraps the CLI's `--older-than-months` / `--delete-legacy` pruning. It is the
only item in this pack that deletes anything an operator did not name, so it is built to be
boring to run by accident. Neither `24` nor `2` below is declared in the `.yml` — those are
the values `YaraCleanup.py` applies when the argument is absent.

| Argument | Default | What it does |
|---|---|---|
| `execute` | `false` | **The deletion opt-in — the only argument that can destroy data.** Left `false`, the run reports what it *would* delete and deletes nothing. Set `true` to actually delete. Only an explicit affirmative (`true`/`yes`/`1`) enables deletion; an unrecognised value is *rejected* rather than guessed in either direction. |
| `older_than_months` | *(none)* | Delete rotated datasets older than N whole months. **No default, on purpose** — see "No implicit window" below. `0` means "every month before the current one". A negative value is clamped to `0` and the run says so. |
| `delete_legacy` | `false` | Also put datasets on an older/unversioned schema in scope. Every rail below applies to these identically; refused outright while any newer-schema dataset exists. |
| `min_quiet_hours` | `24` | Rail 6's threshold: never delete a dataset whose newest row is younger than this many hours, whatever its month label says. Cannot be used to switch the rail off — anything under the 1h floor is raised to 1h and the run says so. |
| `force` | `false` | Passed through to `delete_dataset` for datasets that have dependencies. Does **not** relax any rail — it only affects the delete call for datasets that already passed all seven. |
| `schema_version` | `2` | The version treated as current. Must be a whole number. It decides whether the run has any scope at all — see the note below. |

### The seven safety rails

None of them is optional, none can be switched off by an argument, and all seven apply to
**both** selection paths — the `older_than_months` window and `delete_legacy`.

| # | Rail | Why |
|---|---|---|
| 1 | Never the current month | A scan may be writing to it right now. |
| 2 | Never a future-dated month | Endpoint clock/timezone skew must not be able to destroy data; a dataset "from next month" means the clock is wrong, not that the data is disposable. |
| 3 | Never an unsuffixed dataset | It holds *all* pre-rotation history for that host — the same one API call, but a categorically bigger blast radius than dropping one month. Delete it by name yourself if you really want the space. |
| 4 | Never a newer schema version | A stale `schema_version` must never let this code delete a future schema's data. |
| 5 | Never a name outside the `yara_scanner_*` contract | Anything the name parser does not recognise can never become a candidate, so a bug in selection cannot reach unrelated tenant data. |
| 6 | Never a dataset written to within `min_quiet_hours` (live XQL) | A rotation suffix records when a dataset was **created**, not when it was last written. A long scan is still writing to an "old-looking" name. |
| 7 | Never a dataset still holding a scan consolidation has not verified into a per-scan target (live XQL) | Deleting it loses that scan's only copy. |

Rails 6 and 7 are live queries, and both **keep** the dataset on any query error — the same
"skip to be safe" posture every other rail takes. The rails apply identically on the
`delete_legacy` path because "legacy" is a *derived* classification that trusts
`schema_version`: only the two live rails can tell "these really are old-schema leftovers"
from "the assumed version is one too high, so the live tenant now looks legacy". Per-scan
consolidated targets (`…_scan_<id>`) are never candidates on either path — they are
consolidation *output*, and after the source shards were deleted they are a scan's only copy.

### The rest of the safety posture

* **Dry run by default.** Without `execute=true` it reports what it *would* delete and
  deletes nothing. The War Room entry always states which mode the run was in, opening with
  either `DRY RUN — nothing was deleted.` or `EXECUTED — N dataset(s) deleted`.
* **No implicit window.** `older_than_months` has no default. Run it with neither
  `older_than_months` nor `delete_legacy=true` and it selects nothing, deletes nothing, and
  says so — without making a single API call.
* **`min_quiet_hours` cannot switch its rail off.** `0` would not relax rail 6, it would
  disable it (`(now − newest) < 0` is false even for a row written a second ago), so
  anything below a 1h floor is raised to the floor and the run says so.
* **Every kept candidate reports its reason**, uncapped, in both the War Room entry and
  `Yara.Cleanup.skipped` — including the buckets that were never candidates at all
  (newer-schema always; legacy when `delete_legacy` is off). A dataset silently not deleted
  is indistinguishable from a bug, and "0 selected, 0 skipped" must never be the report for
  "rail 4 vetoed the entire tenant".
* **Takes the consolidation lock** (the same `yara_scanner_consolidation_lock` marker
  `YaraConsolidateApply` uses) before evaluating the rails, and releases it in a `finally`.
  Pruning and consolidation mutate the same shards, and the last two rails are point-in-time
  checks. If another run holds the lock this one deletes nothing and reports
  `lock_held_by_other_run`. Because a wrong takeover here is *irreversible* rather than a
  redundant merge, this path is stricter than consolidation's: an existing marker whose row
  cannot be read counts as **held** (that is the `add_data` create-lag window right after
  another run took it), staleness is judged on a much longer window, and any takeover that
  does happen is reported in `Yara.Cleanup.lock_taken_over` and in the War Room entry rather
  than passing for an ordinary pass. A **dry run never takes the lock** — it mutates nothing
  and stays safe to run concurrently with anything.
* **Each executed pass writes one row to `yara_scanner_cleanup_runs`** (best-effort; a write
  failure never changes the run's outcome). A War Room entry and investigation context are
  per-run and not queryable across runs, so without this there is no way to answer "which
  datasets did we prune last month, and why were the rest kept" for the one action in this
  pack that cannot be undone.

Outputs land under `Yara.Cleanup.*`: `dry_run`, `selected` / `selected_count` (passed every
rail), `deleted` / `deleted_count` (always empty on a dry run), `failed` (per-dataset delete
errors — one failure never strands the rest of the pass), `skipped` with every kept
candidate's reason, `newer` (rail 4's veto list), the `nothing_requested` /
`lock_held_by_other_run` / `lock_taken_over` flags, and the scope the run actually used
(`schema_version`, `older_than_months`, `delete_legacy`, `min_quiet_hours`).

**The intended way to run it**, and the reason `execute` exists as a separate argument
rather than a `--dry-run` inverse: run `YaraReport` to see the inventory, run `YaraCleanup`
with your window and **no** `execute` to see exactly which datasets that window selects and
why every other candidate was kept, read that list, and only then re-run the *same*
arguments with `execute=true`. `YaraCleanup`'s `timeout` is deliberately higher than the
rest of the pack's (5400s): the two live rails issue one polled XQL query per candidate, and
a platform kill mid-run skips the `finally` that releases the consolidation lock.

Neither `YaraReport` nor `YaraCleanup` writes a row to `yara_scanner_consolidation_runs`.
That dataset's schema and status vocabulary describe a *consolidation* pass, and the
`Consolidation Run Health` widget reads "a row in the last ~24h" as proof the twice-daily
merge Job is alive — rows from a report or a prune would misreport its counts and mask a
dead merge Job. `YaraCleanup` keeps its own `yara_scanner_cleanup_runs` dataset instead
(see Monitoring below); `YaraReport` records nothing, which is the point of it.

## `schema_version` — it decides the scope of both new automations

The CLI reads the current lookup schema version
from the `YARA_LOOKUP_SCHEMA_VER` environment variable; XSOAR containers have no such
variable, so both automations take it as an argument and assume `"2"` when it is absent.
It must be a whole number — a non-numeric value like `"v3"` is **rejected outright**, because
it would make `CURRENT_RE` match nothing *and* leave rail 4 unable to fire, silently
reclassifying every live dataset on the tenant as "legacy". Two ways to get a valid number
wrong, with different consequences:

* **Stale-LOW** (tenant writes v3, argument left at `"2"`): the v3 datasets classify as
  "newer" and are never pruned. `YaraCleanup` prunes little — but it now lists every
  newer-schema dataset it vetoed, and names `schema_version` as the likely cause, so this is
  no longer indistinguishable from "nothing has aged out".
* **Stale-HIGH** (argument set to `"3"` on a v2 tenant): live datasets classify as *legacy*.
  This cannot be detected from the version alone. `delete_legacy` is refused outright while
  any newer-schema dataset exists, and everything else is caught by the same rails the age
  path uses — the live recency and consolidation checks in particular — each reported as a
  skip.

## Resetting a tenant — `YaraWipeAllDatasets`

`YaraCleanup` and `YaraConsolidateApply` protect a specific set of data on purpose: a live
matches dataset is never a deletion candidate, and a per-scan consolidated target is never
touched. Those protections exist because that data is normally irreplaceable. Occasionally
— most often before a test cycle — you want the opposite: every `yara_scanner_*` dataset on
the tenant gone, no exceptions. `YaraWipeAllDatasets` is that tool, and nothing else in this
pack.

**It is not a task in the playbook, and it never will be.** Import the playbook and it will
never call this automation; the only way it runs is an operator invoking it directly from
the War Room or Playground.

It targets host matches and scan lifecycle datasets, old schema and new, per-scan
consolidated targets, and summary datasets — every kind the other five automations
recognise, plus any the classification patterns above don't (it matches on the bare
`yara_scanner_` prefix, not on `matches`/`scans` specifically). It preserves exactly four
names: the three run-log audit trails this pack's automations keep (including its own,
`yara_scanner_wipe_runs`) and the consolidation lock, which it takes for the duration of an
executed pass the same way `YaraConsolidateApply` does.

| Argument | Default | What it does |
|---|---|---|
| `execute` | `false` | The deletion opt-in. Left `false`, reports what would be deleted and deletes nothing. |
| `confirm` | *(none)* | Required when `execute=true`: must equal, exactly and case-sensitively, `DELETE ALL YARA DATASETS`. There is no scoping argument on this automation — no `older_than_months`, no host filter, no `schema_version` — so this phrase is the only thing standing between `execute=true` and every YARA dataset on the tenant. Get it wrong and nothing is deleted, whatever `execute` says. |

Run the dry run first, read the full list it prints, and only then re-run with both
arguments set.

## Deployment — pack install or console Import, not a bare item push

**Uploading an automation itself (as opposed to the scanner's Action Center script) has a
working API**, unlike the scanner — see the Deployment Guide's callout at "Step 3 — Upload
the Script to the Library" for the distinction. All six of this pack's automations were
delivered as standalone items via `POST /xsoar/automation/import` (multipart, field `file` =
the `unified/<Name>.yml`), using the **same Advanced key, HMAC-signed**, already used for
every `/public_api/*` call in this project — verified live, `/xsoar/automation/search` and
`/xsoar/automation/import` both accept it. This is scriptable end to end; it does not need
the console. `POST /xsoar/automation/search {"query":"name:Yara*"}` lists what is currently
registered.

**A playbook delivered via a raw `POST /playbook/save/yaml` push (e.g. plain
`demisto-sdk upload` of just the single playbook file) is stored and runnable by id, but it
is an invisible private draft** — absent from `/playbook/search` and therefore from every
console picker, including the one used to attach a playbook to a scheduled Job. It will look
deployed (loads fine, runs fine when triggered directly) right up until someone tries to
select it while creating the Job and cannot find it. Deliver this pack via **console Import**
or a **pack-zip install** instead, both of which register the playbook the normal way.
Details: xsoar-content-engineering skill, `SKILL.md`, "Platform quirks that silently corrupt
content" #33.

**Pick ONE delivery mechanism for this pack's items and never mix it with an ad-hoc item-level
push afterwards.** After a pack-zip install, every item the install *writes* is marked
`system:true`, and further item-level API writes to it fail forever with `Item is system and
cannot be modified (100001)` — recovery differs by item type and is not always clean (see
gotcha #16 in the same file). If you need to iterate on one of these scripts after the pack
is installed, either re-import the whole pack or accept the `system:true` constraint; don't
reach for a one-off `demisto-sdk upload` on just that file.

**Upload `unified/`, not the `.py` files.** An XSOAR automation *is* its yml: the tenant
runs whatever sits under that file's `script:` key. `unified/<Name>.yml` carries the whole
Python body inline and is the delivery copy for every automation in this pack;
`Scripts/<Name>/<Name>.py` exists so the code can be reviewed, tested and `py_compile`d.
Those are two copies of one source, and they have already drifted once — a shipped `.yml`
was missing a safety guard its `.py` had, silently shipping the unguarded behaviour to the
tenant while every reviewer, test and `py_compile` run only ever saw the guarded file.
Regenerate rather than hand-edit:

```
python3 tools/build_pack_unified.py            # rewrite every embedded copy from its .py
python3 tools/build_pack_unified.py --check    # exit 1 if any is stale
```

`tests/test_pack_unified_yaml_is_in_sync.py` runs `--check` in CI, and
`tests/test_pack_playbook_consolidation_modes.py` checks the playbook's tasks against the
automations they call. `YaraConsolidateSummary` is self-contained
on the `Scripts/` side too (its `Scripts/<Name>/<Name>.yml` embeds the script); the rest
carry `script: '-'` there and are unified at upload time.

**`YaraReport` and `YaraCleanup` are not tasks in the consolidation playbook**, and nothing
in this pack schedules them. They install as standalone automations, run from the War Room
or their own Job. That is deliberate for `YaraCleanup`: a destructive action attached to the
same twice-daily Job as the merge would delete on a schedule nobody re-reads, and the two
would contend for the consolidation lock every single pass. If you *do* put `YaraCleanup` on
a schedule, give it its own Job at its own cadence (monthly matches the rotation it prunes),
keep it well clear of the merge Job's window, and treat `execute=true` on a recurring Job as
the standing authorisation it is — the operator reading each run's skip reasons after the
fact is the only review it gets.

## Credentials

Each automation's own `CoreApiClient` calls this tenant's own public API directly over
signed Advanced (HMAC) HTTPS — the design-rationale comment above the class explains why (the
originally-planned "Cortex Core - IR" generic REST bridge is not registered on this tenant).

**This is five edits, not one.** Every automation in this pack is self-contained: it inlines
the whole shared library, including its own copy of `CoreApiClient` and its own copy of the
three constants below. That is not duplication for its own sake — the tenant resolves no
cross-script import, so a shared library automation could not be imported at runtime even if
one shipped, and each file must therefore carry everything it needs. Before uploading, edit
the three placeholder constants near the top of **each of the five** automations
(`YaraConsolidateStatus`, `YaraConsolidateApply`, `YaraConsolidateSummary`,
`YaraReport`, `YaraCleanup`) — in `Scripts/<Name>/<Name>.py` if you
are regenerating, or directly in the `unified/<Name>.yml` you import:

```python
DEFAULT_XDR_API_KEY = "replace_with_xdr_advanced_api_key"
DEFAULT_XDR_API_ID = "replace_with_xdr_advanced_api_id"
DEFAULT_XDR_API_URL = "replace_with_xdr_api_url"
```

Use an **Advanced**-type key and set an expiry — see
[API_Permissions.md](../../docs/topics/API_Permissions.md)
for the least-privilege recipe used elsewhere in this project (the automation key needs
script-execution/Action Center/query components; it deliberately should **not** be granted
Data Management, per that doc — but this pack's `CoreApiClient` does need Data Management,
since consolidation itself creates/writes/deletes datasets). There is no separate documented
role recipe scoped to *just* what this pack's key needs (create/read/write/delete lookup
datasets); treat it as needing Data Management at minimum until a narrower recipe is defined.
Use an **Advanced**-type key and set an expiry.

### The role this key needs

Custom role — **Data Management** + **Query Center**, nothing else. No endpoint scope, no
script components, no External Issues Mapping. This is "Key 3" in
[API_Permissions.md](../../docs/topics/API_Permissions.md),
where the full per-API mapping and the machine keys for `POST /platform/iam/v1/role` live.

Three things about this tenant's RBAC that determine the answer, enumerated live from
`permission-config` and the built-in role grants on 2026-08-13:

- **Data Management has no read-only tier** — its component is action-only
  (`view=- action=data_management_action`). There is no way to grant a key that can *read*
  lookup datasets without also being able to `delete_dataset`.
- **No built-in role fits.** Only **Admin** carries Data Management; Privileged Responder,
  Responder and Viewer have Query Center but not Data Management. So it is a custom role or
  an Admin key, and it should not be an Admin key.
- **The narrower-sounding dataset permissions cannot be used.** `Create Datasets`,
  `Dataset Management` and `Datasets Access Control` show up in Admin's grant list but are
  absent from `permission-config`, so a custom role cannot reference them. A finer-grained
  dataset role is not constructible on this platform today.

**What that means for safety.** Because the delete capability cannot be withheld at the RBAC
layer, the protection against a bad delete is not the API key — it is this pack's own code:
`YaraCleanup` is dry-run by default and requires an explicit affirmative to delete, applies
all seven safety rails on both selection paths, and takes the consolidation lock first. Read
the YaraCleanup section above before granting this key to anything.

> **Currently deployed on the lab tenant:** a full-access key, not the scoped role above.
> That is a deliberate, accepted state for lab work — the scoped role is the target for any
> non-lab deployment, and nothing in the pack depends on the broader grant.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `YaraConsolidateStatus failed: ... HTTP 401: ...` or `YaraConsolidateApply failed: ... HTTP 401: ...` in the Job's task error / War Room | The embedded `DEFAULT_XDR_API_KEY`/`DEFAULT_XDR_API_ID` were rotated, revoked, or hit their `expiration` on the tenant. The identical generic 401 also covers a mistyped key/ID and a Standard/Advanced type mismatch — the response body alone cannot tell you which. | Regenerate an Advanced-type key for this pack's role (see Credentials above), edit the three `DEFAULT_XDR_*` constants in **all five** automations — each one carries its own credential block, because the tenant resolves no cross-script import and every automation is therefore self-contained — and re-deliver the pack (editing the repo file alone does nothing until it's re-imported/re-installed — see Deployment above). Confirm with `YaraConsolidateStatus` — it's read-only and safe to run any time. |
| `YaraConsolidateStatus` reports `0 scan(s) eligible to consolidate` and every list in its outputs is empty | A fresh or freshly-wiped tenant holds no host matches or scans datasets at all, so the gate has no scan to evaluate. | Not a failure and not a misconfiguration. `eligible_count` and `blocked_count` are `0`, `any_in_progress` is `False`, `blocked_reasons` is `{}`, and `eligible_scan_ids` / `pending_scan_ids` / `blocked_scan_ids` are empty — that is the correct read-only answer on an empty tenant. Run a scan, wait out the 900-second quiet period (`DEFAULT_QUIET_SECS`), and re-run. |
| `YaraConsolidateStatus` still reports the same `N scan(s) eligible to consolidate` after `YaraConsolidateSummary` has run — even a successful `execute=true` that wrote rows | **Expected.** `Status` reports readiness for **`YaraConsolidateApply`**, not for `Summary`. The two act on different datasets and neither consumes the other's input: `Summary` reads the per-host *matches* datasets and writes a rollup, while `Apply` merges the month-suffixed *scans* shards and deletes them once verified. Nothing `Summary` does marks a scan as consolidated, because from `Apply`'s point of view it is not. | Not a failure. A scan stays eligible until `Apply` actually merges it. Confirm with `!YaraReport`: if no `yara_scanner_scans_v4_scan_<id>` targets exist, the sources are genuinely unconsolidated. Verified live: after a `Summary` run wrote 24 rows across 3 hosts, `Status` correctly still listed all 3 scans as eligible, and `yara_scanner_consolidation_runs` showed no `Apply` pass since the scan. |
| Every scheduled Job run fails at task "Check consolidation status" (or "Apply consolidation") and task 8 ("Flag failures for attention") never lights up | `return_error` halts the whole playbook run at the failing task, before task 8's condition is ever evaluated — task 8 only reports data-level `failed_count` from a *completed* run, not a total execution error. | Watch the Job's own run history, not just the task-8 context flag — a dead key (or any other uncaught exception) is a hard failure, not a soft one. The `yara_scanner_consolidation_runs` dataset (see Monitoring below) also gets a `status="crashed"` row for a mid-run `YaraConsolidateApply` crash specifically (not for a `YaraConsolidateStatus` crash — that one never reaches `YaraConsolidateApply` at all). |
| Job history shows "0 scan(s) consolidated" every run, nothing actually being merged | Consolidation lock held by another concurrent run (the CLI's `xdr_data_management.py --consolidate --yes`, or an overlapping Job execution) | Check `Yara.ConsolidateApply.lock_held_by_other_run` in context, or just read the readable output — it now says "Skipped this pass — consolidation lock is held by another concurrent run" instead of looking identical to a genuinely-empty pass. Confirm the Job's Queue Handling is set to "Don't trigger a new job instance" and that no one is running the CLI `--consolidate --yes` concurrently. |
| The playbook run ends at **"Unrecognised consolidation_mode - nothing done"** and nothing was merged or written | `consolidation_mode` is neither exactly `full` nor exactly `summary` — a typo, a capitalised value, or an empty one. This is the designed fail-safe, not a bug: an unrecognised mode must never fall through to the branch that deletes per-host shards. | Set the input to exactly `full` or exactly `summary` and re-run. If it is already one of those, the `isEqualString` condition in task 11 is the thing to verify against the live tenant (see the playbook description's NOTE ON VERIFICATION) — it has no local precedent in this repo. |
| Summary mode runs every pass, reports rows it "WOULD write", and never writes any | `summary_execute` was set to `false` (or the automation was invoked directly without `execute=true`). `YaraConsolidateSummary` is a dry run by default. | Leave the playbook's `summary_execute` at its default of `true`. The War Room entry names the mode it ran in on its first line — `DRY RUN - nothing was created or written.` vs `EXECUTED.` |
| Summary mode reports failures in `Yara.ConsolidateSummary.failed` | A write or a count query failed for that scan. **Nothing was destroyed** — this automation has no deletion path, and the message says `host shards untouched`. | Re-run; it is idempotent. A target already holding exactly this run's row count is verified and left alone, and one holding a *different* count is refused rather than appended to (appending would duplicate (host, rule) pairs and there is no delete path to undo that). Clear that target by hand if the mismatch is real. |
| `YaraCleanup` reports `Nothing selected and nothing deleted: no retention window was given` | Neither `older_than_months` nor `delete_legacy=true` was passed. This is not a failure — it is the "a bare invocation must never delete" property, and no API call was made at all. | Pass a retention window (`older_than_months=N`) and/or `delete_legacy=true`. There is deliberately no default window to fall back on. |
| `YaraCleanup` ran `EXECUTED` but deleted far less than expected, and `Yara.Cleanup.newer` is non-empty | Rail 4 vetoed those datasets: they are on a **higher** schema version than the `schema_version` argument, i.e. the argument is stale-LOW. | Set `schema_version` to what the fleet actually writes (`YARA_LOOKUP_SCHEMA_VER` on the endpoints). Run `YaraReport` first — its "newer schema" bucket shows the same thing without touching anything. |
| `YaraCleanup` selected almost nothing and every skip reason names the recency or consolidation rail | Working as designed, and usually one of two real conditions: scans are still writing to those shards (rail 6 — the *name*'s month is not when it was last written), or consolidation has not yet verified their `scan_id`s into per-scan targets (rail 7). Both rails also keep a dataset when their live query **errors**, so a flaky query window looks the same. | Read the per-candidate reasons in `Yara.Cleanup.skipped` — they name the specific rail. Let the consolidation Job catch up (`YaraConsolidateStatus` shows readiness) and re-run. Do not lower `min_quiet_hours` to force it through; below 1h it is raised back to the floor anyway. |
| `YaraCleanup` reports `Skipped this pass — the consolidation lock is held by another concurrent run` and deletes nothing | `YaraConsolidateApply`, the CLI, or another `YaraCleanup` run holds `yara_scanner_consolidation_lock`. On this path an existing marker whose row cannot yet be read also counts as held — that is the `add_data` create-lag window right after another run took it. | Expected when a prune overlaps the twice-daily merge Job. Re-run after the merge pass finishes. A **dry run** never takes the lock, so it is always available to see what *would* go. |
| War Room entry contains `WARNING: another run's consolidation lock marker was present and this pass TOOK IT OVER as stale` | A previous lock holder died without releasing the marker (e.g. a platform kill mid-run, which skips the `finally`), and this pass judged it stale and proceeded. | Check `Yara.Cleanup.lock_taken_over` / `lock_takeover_reason` and confirm no consolidation pass was in fact still running — if one was, its shards were pruned concurrently. This is reported rather than silent precisely because it is not an ordinary pass. |

## Monitoring — `yara_scanner_consolidation_runs`

Every `YaraConsolidateApply` pass writes one row to the `yara_scanner_consolidation_runs`
lookup dataset: `run_ts_ms`, `status` (`success` / `partial_failure` / `crashed`),
`consolidated_count`, `failed_count`, `failed_scan_ids`, `failed_reasons`, `error_message`.
This is the one queryable, persistent signal for pipeline health — task 8's own description
in the playbook says plainly that it is a **placeholder**: it only writes a flag into that
one run's ephemeral XSOAR investigation context, which nothing else reads, and it is never
reached at all when a run crashes outright (see the Troubleshooting row above). Use the
`Consolidation Run Health` widget (`widgets/xdr/Consolidation Run Health.xql`, on the
`YARA Scanner (Lookup)` dashboard) to see recent runs at a glance; no row in roughly the last
24h (2x the twice-daily schedule interval) means the Job did not complete a pass recently.

**This repo does not provision any push-style alert on a failed or missing Job run** — no
`Jobs/*.json` content item ships in this pack, so the Job's own schedule and any
Job-level failure notification are entirely a manual, out-of-band console configuration, not
something installing this pack sets up for you. Either configure a platform-level
Job-failure/incident notification rule yourself, or treat the `Consolidation Run Health`
widget and the Job's own run history as something an operator must proactively check —
neither is pushed to you.

### The prune audit trail — `yara_scanner_cleanup_runs`

`YaraCleanup` keeps its record in a **separate** dataset, for the reason given above: a
cleanup row in `yara_scanner_consolidation_runs` would both skew that widget's counts and
satisfy its "a row in the last ~24h" liveness check, masking a merge Job that has stopped.

Every **executed** pass writes one row to `yara_scanner_cleanup_runs`: `run_ts_ms`, `mode`
(`executed` / `dry_run`), `schema_version`, `older_than_months` (`-1` when no window was
given — a numeric column cannot carry null on this API, and "no window" is a meaningful
state), `delete_legacy`, `min_quiet_hours`, the `selected` / `deleted` / `failed` / `skipped`
counts, the deleted dataset names, every skip reason, and `lock_taken_over`. The write is
best-effort: a failure to record is logged and never changes the run's outcome. A dry run
writes no row — it did nothing.

**No widget ships for this dataset**, unlike consolidation's. Query it directly when you
need to answer "what did we prune, when, and why was the rest kept" — the only durable
answer available for the one action in this pack that has no undo:

```
dataset = yara_scanner_cleanup_runs*
| sort desc run_ts_ms
| alter run_time = to_timestamp(run_ts_ms, "MILLIS")
| fields run_time, mode, schema_version, older_than_months, delete_legacy,
         deleted_count, skipped_count, deleted, skipped_reasons, lock_taken_over
| limit 20
```

(Lookup rows carry no `_time` — read `run_ts_ms` and derive `run_time`, same as the
consolidation widget does.)

### The wipe audit trail — `yara_scanner_wipe_runs`

`YaraWipeAllDatasets` keeps its own record too, for the same reason `YaraCleanup` does not
share `yara_scanner_consolidation_runs`. It diverges from `YaraCleanup`'s convention in one
place, deliberately: **it records every invocation, dry run included**, not only executed
passes. For a tool with no scoping argument at all, knowing who checked what a full wipe
would delete, and when, is worth keeping even when nothing was actually deleted.

Every run — `mode` (`dry_run` / `executed`) — writes one row: `run_ts_ms`, `total_found`,
`to_delete_count`, `deleted_count`, `failed_count`, the `deleted` / `failed` dataset name
lists, and `preserved`. Same best-effort write discipline as the other two logs: a failure
to record never changes the run's real outcome.
