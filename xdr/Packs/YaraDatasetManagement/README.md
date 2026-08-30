# YARA Dataset Management (XSOAR pack)

Consolidates every finished YARA scan's findings out of the per-host lookup datasets and
into one dataset per **ruleset** — safely, at fleet scale — reports what needs attention, and
prunes what has aged out when you ask it to. **Neither consolidation mode deletes source
data**: both read the permanent per-host datasets and leave them exactly as they found them,
and the only rows either one ever removes are stale rows inside its own output. There are
**two consolidation modes**, full detail and summary only; which one you want is the first
decision to make and it is answered in
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
| `YaraConsolidateApply` | Automation | **Mode A, full detail.** Groups every column of every matched-file row, across every host scanned with one ruleset, into a single `yara_scanner_full_v<VER>_rules_<hash>` dataset. **Deletes no source dataset:** the only `remove_lookup_data` call it makes is against its *own* output, dropping `scan_id`s the sources no longer hold. **Dry run unless `execute=true`.** |
| `YaraConsolidateSummary` | Automation | **Mode B, summary only.** One row per (host, rule) — which rules fired on which host — into `yara_scanner_summary_v<VER>_rules_<hash>`. Four columns, no filenames, no per-rule counts. **Deletes no source dataset:** exactly like Mode A, its only `remove_lookup_data` call is against its *own* output. Dry run unless `execute=true`. The compact counterpart to Mode A: same sources, same grouping key, roughly a fortieth of the rows. |
| `YaraReport` | Automation | Read-only inventory of every `yara_scanner_*` lookup dataset (kind, host, age, plus the legacy / newer-schema / consolidated buckets). One API call, no writes — safe any time. Writes to `Yara.Report.*`. |
| `YaraCleanup` | Automation | Retention pruning — **deletes whole datasets**. Dry run by default; see below. |
| `YaraWipeAllDatasets` | Automation | **Deletes every `yara_scanner_*` dataset on the tenant, unconditionally.** No scoping, no rules. **Not wired to the playbook or any other content item — run it by hand only.** See below. |
| `YaraScanVerify` | Automation | Bounded post-dispatch check that a dispatched scan wave actually started on its hosts. Read-only — it reads lifecycle rows and reports; it writes and deletes nothing. |
| `YaraRulesFromFile` | Automation | Validates an operator-uploaded YARA rules file and returns the base64 the Action Center scanner takes as its `yarafile` input. Makes **no tenant API call** — no credentials to configure. |
| `YaraRulesDecode` | Automation | The inverse: decodes that base64 back to readable rules and recomputes the ruleset hash, for verification and forensics. Makes **no tenant API call** — no credentials to configure. |

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
consolidated row still lives — and it is why **neither** consolidation mode deletes it.
There is nothing to reclaim by deleting it either: it is overwritten wholesale by the next
scan on that host, so it never accumulates and never grows.

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

The host dataset and the scanner behave **identically** under both modes, and the host
dataset survives both — **both** modes read it and **neither** deletes it. What differs is
**fidelity**: full mode copies every column of every matched-file row, summary mode collapses
the same rows to one per (host, rule). Same sources, same grouping key, same reconciliation.

| | **A. Full detail** | **B. Summary only** |
|---|---|---|
| Automation | `YaraConsolidateApply` | `YaraConsolidateSummary` |
| Source enumeration | `_matches_shard_for_read` — the read-only inclusion that **does** see the live per-host dataset. It also lists the *scans* lifecycle shards, but **only** to build the terminal map that gates eligibility: they are read, never written and never deleted | `_matches_shard_for_read` — the same read-only inclusion, for the same reason: reading the live dataset is safe when nothing is ever deleted |
| Grouping key | the ruleset hash the scanner leaves at the end of every `scan_id` — the only component every host in one Action Center launch shares | the same ruleset hash |
| Target | `yara_scanner_full_v<VER>_rules_<hash>` — **one per ruleset**, holding every host scanned with it | `yara_scanner_summary_v<VER>_rules_<hash>` — one per ruleset, same key |
| Row grain | every matched-file row, copied verbatim | **one row per (host, rule)** |
| Columns | the full match schema, every column | `scan_id`, `hostname`, `rule`, `event_timestamp_ms` — and nothing else |
| Records what matched | **yes**, at file level — which file, where, matched by what | **yes**, at rule level — which rules fired on which host |
| Per-rule counts | derivable: every matched file is its own row | **deliberately absent.** A count column turns every dashboard query over the summary into an aggregation over numbers instead of a distinct-set lookup. |
| Source dataset afterwards | **untouched.** The per-host matches dataset is never deleted: `parse_shard` excludes it at enumeration time, and `_is_live_overwrite_dataset` re-derives the same answer at each destructive call site. The single `remove_lookup_data` call is against **its own output**, dropping `scan_id`s the sources no longer hold | **untouched.** Identical posture, enforced by the same two guards: no `delete_dataset` and no row removal on any path this automation reaches. Its single `remove_lookup_data` call is against **its own output** too, dropping `scan_id`s the sources no longer hold. `shards_deleted` is always `0` and is reported so a playbook can assert it. |
| Read cost | reads every host's matched-file rows in full | **one XQL per host dataset**, which expands the v4 `rules` JSON array and groups inside the engine, so the rows never leave the tenant |
| Write verification | reconciles on `scan_id` sets: unchanged hosts are left alone, a re-scanned host's rows are replaced, and a run with nothing changed is a verified no-op | the same reconciliation on the same `scan_id` sets — unchanged hosts left alone, a re-scanned host's rows replaced, nothing changed a verified no-op. Nothing is deleted either way, so a partial write is fixed by re-running |
| Default | **dry run** unless `execute=true` | **dry run** unless `execute=true` |

**Which one to use.**

* **Summary** is the right default for fleet-wide reporting: "which rules fired on which
  host". It is the cheap variant, it is the safe variant, and it composes with the
  overwrite model — the per-host dataset stays in place, so any summary row can still be
  drilled into for the files behind it. Its size limit is `50 MB` per lookup dataset, which
  at ~163 B per (host, rule) row is ~321,649 rows: **the fleet limit is rules-matched-per-host,
  not host count.**
* **Full detail** answers file-level questions — which file, where, matched by what —
  from one dataset per ruleset instead of host by host: an investigation workflow that
  queries the consolidated target, or a tenant where that target is exported elsewhere. It
  reads exactly the same permanent per-host matches datasets summary mode reads, and leaves
  them exactly as it found them. The price is volume: roughly **40x** the rows of a summary
  for the same scans, which is what `row_ceiling` exists to bound.
* **They are not interchangeable after the fact.** Both modes record what matched, but only
  full mode records the *files*: a scan consolidated in summary mode leaves a (host, rule)
  row and no durable copy of the file-level detail behind it. Either way the per-host
  dataset stays the deep-dive source, until the next scan on that host overwrites it — at
  which point that scan's file-level detail is gone unless full mode archived it first. Pick
  per deployment, not per run.
* **One pass is bounded by rows, not by scans.** The full-consolidation `YaraConsolidateApply`
  has **no `max_scans` argument**; its per-pass bound is **`row_ceiling`**, shipped default
  **60,000**, set below the ~70,000 rows at which lookup writes were measured going dead. A
  ruleset group larger than the ceiling is **refused outright** — reported in
  `Yara.ConsolidateApply.failed` — rather than half-filling the target, because a
  partially-written consolidated dataset is indistinguishable from a complete one. If a group
  is refused, use `YaraConsolidateSummary` for a fleet that size, or raise `row_ceiling`
  deliberately knowing where the write ceiling actually is. (The playbook still carries a
  vestigial `max_scans` input; it is wired to no task and has no effect on this automation.)

### Choosing the mode from the playbook

`YARA Dataset Consolidation` takes a **`consolidation_mode`** input, `full` (default) or
`summary`. Task 11 branches on it: `full` → `YaraConsolidateApply`, `summary` →
`YaraConsolidateSummary`. Every pre-existing input still works unchanged, and an existing
scheduled Job that predates this input picks up the `full` default. Both branches are
non-destructive, and each is gated by its own execute flag.

| Playbook input | Default | Notes |
|---|---|---|
| `consolidation_mode` | `full` | Matched **exactly** against `full` and `summary`. Anything else — a typo, an empty value — reaches neither automation: it lands on a dead-end task that consolidates and writes nothing, so an unrecognised mode can never quietly pick a mode on your behalf. |
| `summary_execute` | `true` | Summary mode only. `YaraConsolidateSummary` is a dry run unless `execute=true`, so a scheduled Job with this defaulted the other way would report forever and never write a row. Set it to `false` deliberately to preview a pass. |
| `full_execute` | `true` | The exact counterpart, full mode only. `YaraConsolidateApply` is **also** a dry run unless `execute=true`; left at `false` the full branch reports what it would write and writes nothing, every run, for ever. Neither flag can cause a deletion of source data — neither branch has a path to one. |
| `row_ceiling` | *(script default: 60000)* | Full mode only. Refuses a ruleset group larger than this many rows rather than half-filling the target. |
| `max_scans` | *(unused)* | Vestigial. It is wired to no task and the full-consolidation `YaraConsolidateApply` has no such argument; the per-pass bound is `row_ceiling`. |
| `abandoned_after_hours` | *(script default: 24h)* | Reaches **both** modes as their `retention_hours`: how long a non-terminal scan may be silent before it is consolidated anyway. In both modes it is **only** that threshold — it is never a deletion window, because neither mode deletes source data. A cleanly completed scan does not wait it out at all: the terminal-lifecycle gate makes it eligible as soon as its rows have settled — the 15-minute quiet window — instead of after `retention_hours`. |

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

**Two consequences of the consolidated targets, stated rather than defended against.** Both
modes' targets are invisible to `YaraCleanup` by construction — `NAME_RE` parses only
`matches` and `scans`, so a `full` or `summary` name returns `None` and can never become a
candidate, which is what stops one `delete_legacy=true` pass taking every consolidated target
with it. The price is that they accumulate for ever; grouping by ruleset rather than by scan
is what keeps that number small — one target per ruleset, not one per scan. And **neither**
mode records a scan as consolidated in the bookkeeping `YaraCleanup`'s rail 7 reads: that
rail still looks for the obsolete per-scan target name, which nothing creates any more, so it
keeps every month-suffixed shard still holding a `scan_id`. For the permanent per-host dataset
that is moot — an unrotated dataset is never a candidate anyway — but for an aged *scans*
shard it means the prune will conservatively decline to delete it.

## Read-only inventory — `YaraReport`

Wraps the CLI's `xdr_data_management.py --report`. It lists every `yara_scanner_*` lookup
dataset with its kind, host and age in whole months, and separates the legacy, newer-schema
and per-scan-consolidated buckets. **It never writes or deletes anything**, and issues
exactly one API call (the dataset listing) — safe to run at any time, from a poll loop, or
alongside a running consolidation or cleanup pass. Start here before running `YaraCleanup`:
this is how you find out what a prune would even be looking at.

| Argument | Default | What it does |
|---|---|---|
| `schema_version` | `4` | The scanner's current lookup schema version (`YARA_LOOKUP_SCHEMA_VER` on the endpoints). Must be a whole number — see the `schema_version` note below. Datasets on a *higher* version are reported under "newer schema"; if this is stale, that is where everything lands. |

It flags two unsuffixed-dataset conditions that look identical in a dataset listing but need
**opposite** advice, which is the main reason to run it:

* **`frozen`** — unsuffixed, but rotated siblings exist. A pre-rotation leftover: rotation
  *is* on for that host, writes moved to the dated names, and this dataset is finished and
  not growing. Nothing to do.
* **`not_rotated`** — unsuffixed with *no* rotated siblings. Rotation is genuinely off for
  that deployment and the dataset will grow without bound until it goes write-dead. Fix it
  at the source: set `CONFIG_LOOKUP_ROTATION="monthly"` in the scanner.

This pack's consolidated output is unsuffixed too, but it is consolidation *output* —
finished by design, not a rotation failure — so it is counted in neither bucket. The current
names, `yara_scanner_full_v<N>_rules_<hash>` and `yara_scanner_summary_v<N>_rules_<hash>`,
are labelled "this pack's own consolidated output, never a candidate"; legacy per-scan targets
(`…_scan_<id>`), which neither mode creates any more, still get their own `consolidated`
state.

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
boring to run by accident. Neither `24` nor `4` below is declared in the `.yml` — those are
the values `YaraCleanup.py` applies when the argument is absent.

| Argument | Default | What it does |
|---|---|---|
| `execute` | `false` | **The deletion opt-in — the only argument that can destroy data.** Left `false`, the run reports what it *would* delete and deletes nothing. Set `true` to actually delete. Only an explicit affirmative (`true`/`yes`/`1`) enables deletion; an unrecognised value is *rejected* rather than guessed in either direction. |
| `older_than_months` | *(none)* | Delete rotated datasets older than N whole months. **No default, on purpose** — see "No implicit window" below. `0` means "every month before the current one". A negative value is clamped to `0` and the run says so. |
| `delete_legacy` | `false` | Also put datasets on an older/unversioned schema in scope. Every rail below applies to these identically; refused outright while any newer-schema dataset exists. |
| `min_quiet_hours` | `24` | Rail 6's threshold: never delete a dataset whose newest row is younger than this many hours, whatever its month label says. Cannot be used to switch the rail off — anything under the 1h floor is raised to 1h and the run says so. |
| `force` | `false` | Passed through to `delete_dataset` for datasets that have dependencies. Does **not** relax any rail — it only affects the delete call for datasets that already passed all seven. |
| `schema_version` | `4` | The version treated as current. Must be a whole number. It decides whether the run has any scope at all — see the note below. |

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
| 7 | Never a dataset still holding a scan consolidation has not verified into a consolidated target (live XQL) | Deleting it loses that scan's only copy. Note that this rail still looks for the **obsolete** per-scan target name (`…_v<N>_scan_<slug>`), which neither consolidation mode creates any more, so on a current tenant it keeps every month-suffixed shard that holds a `scan_id`. It errs in the safe direction, but it is why an aged *scans* shard may never be selected. |

Rails 6 and 7 are live queries, and both **keep** the dataset on any query error — the same
"skip to be safe" posture every other rail takes. The rails apply identically on the
`delete_legacy` path because "legacy" is a *derived* classification that trusts
`schema_version`: only the two live rails can tell "these really are old-schema leftovers"
from "the assumed version is one too high, so the live tenant now looks legacy". This pack's
own consolidated output — `yara_scanner_full_v<N>_rules_<hash>`,
`yara_scanner_summary_v<N>_rules_<hash>`, and any legacy `…_scan_<id>` target — is never a
candidate on either path: `NAME_RE` refuses to parse those names, and that refusal *is* rail
5. They are consolidation *output*, and once `YaraCleanup` has pruned an aged source they can
be the only surviving copy of it.

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
variable, so both automations take it as an argument and assume `"4"` when it is absent.
It must be a whole number — a non-numeric value like `"v3"` is **rejected outright**, because
it would make `CURRENT_RE` match nothing *and* leave rail 4 unable to fire, silently
reclassifying every live dataset on the tenant as "legacy". Two ways to get a valid number
wrong, with different consequences:

* **Stale-LOW** (tenant writes v5, argument left at `"4"`): the v5 datasets classify as
  "newer" and are never pruned. `YaraCleanup` prunes little — but it now lists every
  newer-schema dataset it vetoed, and names `schema_version` as the likely cause, so this is
  no longer indistinguishable from "nothing has aged out".
* **Stale-HIGH** (argument set to `"5"` on a v4 tenant): live datasets classify as *legacy*.
  This cannot be detected from the version alone. `delete_legacy` is refused outright while
  any newer-schema dataset exists, and everything else is caught by the same rails the age
  path uses — the live recency and consolidation checks in particular — each reported as a
  skip.

## Resetting a tenant — `YaraWipeAllDatasets`

`YaraCleanup` and `YaraConsolidateApply` protect a specific set of data on purpose: a live
matches dataset is never a deletion candidate — `YaraConsolidateApply` has no path that
deletes one at all — and a consolidated target is never touched. Those protections exist
because that data is normally irreplaceable. Occasionally
— most often before a test cycle — you want the opposite: every `yara_scanner_*` dataset on
the tenant gone, no exceptions. `YaraWipeAllDatasets` is that tool, and nothing else in this
pack.

**It is not a task in the playbook, and it never will be.** Import the playbook and it will
never call this automation; the only way it runs is an operator invoking it directly from
the War Room or Playground.

It targets host matches and scan lifecycle datasets, old schema and new, legacy per-scan
consolidated targets, and both per-ruleset outputs (`full` and `summary`) — every kind the
other automations recognise, plus any the classification patterns above don't (it matches on
the bare `yara_scanner_` prefix, not on `matches`/`scans` specifically). It preserves exactly four
names: the three run-log audit trails this pack's automations keep (including its own,
`yara_scanner_wipe_runs`) and the consolidation lock, which it takes for the duration of an
executed pass the same way `YaraConsolidateApply` does.

| Argument | Default | What it does |
|---|---|---|
| `execute` | `false` | The deletion opt-in. Left `false`, reports what would be deleted and deletes nothing. |
| `confirm` | *(none)* | Required when `execute=true`: must equal, exactly and case-sensitively, `DELETE ALL YARA DATASETS`. There is no scoping argument on this automation — no `older_than_months`, no host filter, no `schema_version`, and `max_deletes` bounds how many go, never which — so this phrase is the only thing standing between `execute=true` and every YARA dataset on the tenant. Get it wrong and nothing is deleted, whatever `execute` says. |
| `max_deletes` | *(script default: 100)* | Caps how many datasets **one executed pass** deletes, so the pass finishes inside the platform's ~900s task timeout: `delete_dataset` measures ~60s server-side, and 100 at this automation's 12-way concurrency is ~500s. **An executed pass is therefore not necessarily the whole tenant** — a bigger tenant is drained over several re-runs. A dry run is unaffected and always reports the full candidate list. `0` or a negative value disables the cap, and the run logs that as the explicit choice it is. |

Run the dry run first, read the full list it prints, and only then re-run with `execute`
and `confirm` both set.

## Deployment — pack install or console Import, not a bare item push

**Uploading an automation itself (as opposed to the scanner's Action Center script) has a
working API**, unlike the scanner — see the Deployment Guide's callout at "Step 3 — Upload
the Script to the Library" for the distinction. All nine of this pack's automations were
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

### The other drift axis: the same function in nine files

`.py` vs `.yml` is one way a fix goes missing. The other is *across* automations, because
each is standalone and hand-carries its own copy of the shared code. Two gates cover that,
and it matters which functions each one compares:

| Gate | Canonical | Compares | Across |
|---|---|---|---|
| `tests/test_pack_data_management.py` | `xdr/xdr_data_management.py` | `_PORTED_FUNCS` — the eight classify/select functions, plus `_PORTED_CONSTS` | `SHIPPING` (the five carrying the consolidation core) |
| `tests/test_consolidation.py` | `xdr/xdr_consolidate.py` | `_SHARED_GATE_FUNCS` — the full ported core, plus `_SHARED_CONSTS` | `SHIPPING` |
| `tests/test_consolidation.py` (lock gate) | `xdr/xdr_consolidate.py` | the lock surface only — `_read_lock`, `acquire_consolidation_lock`, `release_consolidation_lock`, `_LOCK_DATASET`, `_LOCK_SCHEMA`, `DEFAULT_LOCK_STALE_SECS` | **every automation that defines the lock**, discovered from the filesystem |

`main`, `report_datasets` and `_matches_shard_for_read` are legitimately per-file — never
propagate those by name; doing so overwrites nine distinct `main()`s.

**The consolidation lock is not in that per-file list, despite what its call sites suggest.**
The call sites *do* legitimately differ (`YaraCleanup` passes a longer `stale_after_secs`;
`YaraConsolidateApply` passes `unreadable_is_held=True` at both destructive call sites), but
the function definition is identical everywhere and must stay that way. It drifted once, in
the worst possible file: `YaraWipeAllDatasets` carried a copy missing `unreadable_is_held`
and `on_takeover` — the two knobs `xdr_consolidate.py` documents as existing "for callers
whose cost of a WRONG takeover is irreversible (dataset deletion)", which describes that
automation and no other. It could not even express the guard, so it took over locks it could
not read and deleted every dataset out from under a consolidation pass still in flight. The
whole suite was green throughout, because the older gates only ever looked at `SHIPPING` and
`YaraWipeAllDatasets` is deliberately not in it.

That is why the third gate keys on **who takes the lock** rather than on `SHIPPING`
membership, and discovers lock-bearing automations from the filesystem so a new one is
covered the day it lands. If you add an automation that takes the lock, copy the function
verbatim from `xdr/xdr_consolidate.py` and let the gate confirm it; choose the *call site*
arguments to match the cost of a wrong takeover in that automation.

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

**This is seven edits, not one.** Every automation that talks to the tenant is self-contained:
it carries its own inlined copy of `CoreApiClient` and its own copy of the three constants
below. That is not duplication for its own sake — the tenant resolves no
cross-script import, so a shared library automation could not be imported at runtime even if
one shipped, and each file must therefore carry everything it needs. Before uploading, edit
the three placeholder constants under the banner that reads
`CONFIGURATION - the only values in this file you need to edit` — it appears verbatim in
**each of the seven** automations that need a key (`YaraConsolidateStatus`,
`YaraConsolidateApply`, `YaraConsolidateSummary`, `YaraReport`, `YaraCleanup`,
**`YaraScanVerify`** and **`YaraWipeAllDatasets`**) — in `Scripts/<Name>/<Name>.py` if you
are regenerating, or directly in the `unified/<Name>.yml` you import:

```python
DEFAULT_XDR_API_KEY = "replace_with_xdr_advanced_api_key"
DEFAULT_XDR_API_ID = "replace_with_xdr_advanced_api_id"
DEFAULT_XDR_API_URL = "replace_with_xdr_api_url"
```

**`YaraScanVerify` and `YaraWipeAllDatasets` are the two that get missed.** They were added
after the original five, and an operator working from an older "credential five of them" note
leaves both on placeholders — at which point each one fails at client construction the first
time it is run, not later and not partially. Grep for what actually carries the block rather
than trusting a count:

```
grep -l "replace_with_xdr_api_url" Scripts/*/*.py     # expect seven files
```

The other two automations, **`YaraRulesFromFile`** and **`YaraRulesDecode`**, need **no
credentials at all**: neither makes a tenant API call — one validates an uploaded rules file
and returns base64, the other decodes that base64 back and rehashes it, both entirely
in-process — so neither carries the block and neither has anything to edit. Nine automations
ship; seven of them need this edit.

Use an **Advanced**-type key and set an expiry — see
[API_Permissions.md](../../docs/topics/API_Permissions.md)
for the least-privilege recipe used elsewhere in this project (the automation key needs
script-execution/Action Center/query components; it deliberately should **not** be granted
Data Management, per that doc — but this pack's `CoreApiClient` does need Data Management,
since consolidation itself creates and writes datasets, and `YaraCleanup` /
`YaraWipeAllDatasets` delete them). There is no separate documented
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
| `YaraConsolidateStatus failed: ... HTTP 401: ...` or `YaraConsolidateApply failed: ... HTTP 401: ...` in the Job's task error / War Room | The embedded `DEFAULT_XDR_API_KEY`/`DEFAULT_XDR_API_ID` were rotated, revoked, or hit their `expiration` on the tenant. The identical generic 401 also covers a mistyped key/ID and a Standard/Advanced type mismatch — the response body alone cannot tell you which. | Regenerate an Advanced-type key for this pack's role (see Credentials above), edit the three `DEFAULT_XDR_*` constants in **all seven** automations that carry the `CONFIGURATION - the only values in this file you need to edit` banner — `YaraConsolidateStatus`, `YaraConsolidateApply`, `YaraConsolidateSummary`, `YaraReport`, `YaraCleanup`, **`YaraScanVerify`** and **`YaraWipeAllDatasets`**; each one carries its own credential block, because the tenant resolves no cross-script import and every automation is therefore self-contained. The last two are the ones a rotation usually misses, and each then fails at client construction on its next run. (`YaraRulesFromFile` and `YaraRulesDecode` make no API call, hold no credentials and need nothing done to them.) Then re-deliver the pack (editing the repo file alone does nothing until it's re-imported/re-installed — see Deployment above). Confirm with `YaraConsolidateStatus` — it's read-only and safe to run any time. |
| `YaraConsolidateStatus` reports `0 scan(s) ready to consolidate, in 0 ruleset group(s)` | A fresh or freshly-wiped tenant holds no host matches datasets at all, so the gate has no scan to evaluate. | Not a failure and not a misconfiguration. `eligible_count`, `pending_count` and `group_count` are all `0` and `eligible_scan_ids` / `pending_scan_ids` / `groups` are empty — that is the correct read-only answer on an empty tenant. Run a scan, wait out the settle window, and re-run. |
| `YaraConsolidateStatus` still reports the same `N scan(s) ready to consolidate` after a consolidation run has already written its dataset | **Expected.** "Ready" means the scan is *finished* — terminal lifecycle, or silent past `retention_hours` — not that it is unconsolidated. A finished scan stays ready however many times you group it, because both modes are idempotent: a re-run reconciles on `scan_id` sets rather than appending, so running twice is a verified no-op. | Not a failure, and not a to-do list that empties. Read `Status` as "what would a run group right now". To check whether the work is done, look for the output datasets in `!YaraReport`: `yara_scanner_summary_v4_rules_<hash>` for the compact record, `yara_scanner_full_v4_rules_<hash>` for full detail. |
| Every scheduled Job run fails at task "Check consolidation status" (or "Apply consolidation") and task 8 ("Flag failures for attention") never lights up | `return_error` halts the whole playbook run at the failing task, before task 8's condition is ever evaluated — task 8 only reports data-level `failed_count` from a *completed* run, not a total execution error. | Watch the Job's own run history, not just the task-8 context flag — a dead key (or any other uncaught exception) is a hard failure, not a soft one. The `yara_scanner_consolidation_runs` dataset (see Monitoring below) also gets a `status="crashed"` row for a mid-run `YaraConsolidateApply` crash specifically (not for a `YaraConsolidateStatus` crash — that one never reaches `YaraConsolidateApply` at all). |
| Job history shows "0 scan(s) consolidated" every run, nothing actually being merged | Consolidation lock held by another concurrent run (the CLI's `xdr_data_management.py --consolidate --yes`, or an overlapping Job execution) | Check `Yara.ConsolidateApply.lock_held_by_other_run` in context, or just read the readable output — it now says "Skipped this pass — consolidation lock is held by another concurrent run" instead of looking identical to a genuinely-empty pass. Confirm the Job's Queue Handling is set to "Don't trigger a new job instance" and that no one is running the CLI `--consolidate --yes` concurrently. |
| The playbook run ends at **"Unrecognised consolidation_mode - nothing done"** and nothing was merged or written | `consolidation_mode` is neither exactly `full` nor exactly `summary` — a typo, a capitalised value, or an empty one. This is the designed fail-safe, not a bug: neither branch deletes source data, but an unrecognised mode must never silently pick one for you. | Set the input to exactly `full` or exactly `summary` and re-run. If it is already one of those, the `isEqualString` condition in task 11 is the thing to verify against the live tenant (see the playbook description's NOTE ON VERIFICATION) — it has no local precedent in this repo. |
| Full mode runs every pass, reports rows it "WOULD write", and never writes any | `full_execute` was set to `false` (or the automation was invoked directly without `execute=true`). **`YaraConsolidateApply` is a dry run by default** — a bare `!YaraConsolidateApply` writes nothing and deletes nothing. | Leave the playbook's `full_execute` at its default of `true`. The War Room entry names the mode it ran in on its first line — `DRY RUN - nothing was created or written.` vs `EXECUTED.` |
| Summary mode runs every pass, reports rows it "WOULD write", and never writes any | `summary_execute` was set to `false` (or the automation was invoked directly without `execute=true`). `YaraConsolidateSummary` is a dry run by default. | Leave the playbook's `summary_execute` at its default of `true`. The War Room entry names the mode it ran in on its first line — `DRY RUN - nothing was created or written.` vs `EXECUTED.` |
| Summary mode reports failures in `Yara.ConsolidateSummary.failed` | A write or a count query failed for that scan. **Nothing was destroyed** — this automation touches no source data, and the message says `host shards untouched`. | Re-run; it is idempotent. Reconciliation is on `scan_id` sets, not on row counts: a target already holding exactly this run's `scan_id`s is verified and left alone, `scan_id`s new to it are written, and rows for a `scan_id` no longer present in any source are dropped from the target — the one removal this automation makes, and it is against its own output. If a source dataset could not be read that pass, that removal is skipped entirely and the run says so. |
| `YaraCleanup` reports `Nothing selected and nothing deleted: no retention window was given` | Neither `older_than_months` nor `delete_legacy=true` was passed. This is not a failure — it is the "a bare invocation must never delete" property, and no API call was made at all. | Pass a retention window (`older_than_months=N`) and/or `delete_legacy=true`. There is deliberately no default window to fall back on. |
| `YaraCleanup` ran `EXECUTED` but deleted far less than expected, and `Yara.Cleanup.newer` is non-empty | Rail 4 vetoed those datasets: they are on a **higher** schema version than the `schema_version` argument, i.e. the argument is stale-LOW. | Set `schema_version` to what the fleet actually writes (`YARA_LOOKUP_SCHEMA_VER` on the endpoints). Run `YaraReport` first — its "newer schema" bucket shows the same thing without touching anything. |
| `YaraCleanup` selected almost nothing and every skip reason names the recency or consolidation rail | Working as designed, and usually one of two real conditions: scans are still writing to those shards (rail 6 — the *name*'s month is not when it was last written), or consolidation has not verified their `scan_id`s into a consolidated target (rail 7 — which still looks for the **obsolete** per-scan target name, so on a current tenant it holds back any month-suffixed shard that still carries a `scan_id`, however many consolidation passes have run). Both rails also keep a dataset when their live query **errors**, so a flaky query window looks the same. | Read the per-candidate reasons in `Yara.Cleanup.skipped` — they name the specific rail. For rail 6, let the scans finish and re-run. For rail 7, re-running consolidation will **not** clear it: satisfy yourself from `!YaraReport` and the `…_rules_<hash>` targets that the data is consolidated, then delete the shard by name. Do not lower `min_quiet_hours` to force rail 6 through; below 1h it is raised back to the floor anyway. |
| `YaraCleanup` reports `Skipped this pass — the consolidation lock is held by another concurrent run` and deletes nothing | `YaraConsolidateApply`, the CLI, or another `YaraCleanup` run holds `yara_scanner_consolidation_lock`. On this path an existing marker whose row cannot yet be read also counts as held — that is the `add_data` create-lag window right after another run took it. | Expected when a prune overlaps the twice-daily merge Job. Re-run after the merge pass finishes. A **dry run** never takes the lock, so it is always available to see what *would* go. |
| War Room entry contains `WARNING: another run's consolidation lock marker was present and this pass TOOK IT OVER as stale` | A previous lock holder died without releasing the marker (e.g. a platform kill mid-run, which skips the `finally`), and this pass judged it stale and proceeded. | Check `Yara.Cleanup.lock_taken_over` / `lock_takeover_reason` and confirm no consolidation pass was in fact still running — if one was, its shards were pruned concurrently. This is reported rather than silent precisely because it is not an ordinary pass. |
| `YaraWipeAllDatasets` (or `YaraCleanup`) logs `consolidation lock marker exists but its row is unreadable ... standing down rather than taking over`, and keeps doing so on every re-run | The `yara_scanner_consolidation_lock` dataset exists but holds no readable row. Normally that is the ~60s `add_lookup_data` create-lag window right after another run took the lock, and standing down is correct. If it persists, the marker is orphaned — a run created it and died before its row landed. | First confirm nothing is actually running (`yara_scanner_consolidation_runs`, newest row). Then delete the `yara_scanner_consolidation_lock` dataset by hand; the next acquire recreates it. **Do not** "fix" this by passing `unreadable_is_held=False` for a deleting automation — refusing is the intended direction to fail when the alternative is deleting datasets out from under a live pass. |
| `YaraWipeAllDatasets` reports `Skipped - the consolidation lock is held...` and you want to know whether an earlier run did nothing or never started | Both look identical in `Yara.WipeAll` outputs alone. | Query `yara_scanner_wipe_runs`: a standdown writes `mode = "skipped_locked"`, a real pass that found nothing to delete writes `mode = "executed"` with `deleted_count = 0`, and a dry run writes `mode = "dry_run"`. An **absent** row for a run you know was launched is the platform-timeout-kill signature — a kill runs no Python, so the audit write never executes. |

## Monitoring — `yara_scanner_consolidation_runs`

Every **executed** `YaraConsolidateApply` pass writes to the `yara_scanner_consolidation_runs`
lookup dataset: `run_ts_ms`, `status` (a `started` row before the merge, then one of
`success` / `partial_failure` / `crashed` / `skipped_locked`), `consolidated_count`,
`failed_count`, `failed_scan_ids`, `failed_reasons`, `error_message`. An **executed**
`YaraConsolidateSummary` pass records here too (`success` / `partial_failure` /
`skipped_locked`, and no `started` row), so a summary-mode Job keeps this dataset — and the
widget's liveness check — alive just as a full-mode one does. Otherwise a **dry run writes
no row**: the automation is dry-run by default, so a Job left without `full_execute=true`
leaves this dataset as silent as it leaves the tenant. The single exception is a crash —
`YaraConsolidateApply` records `crashed` whether or not the pass was executing. A `started`
row with no terminal row is the pass the platform killed on timeout.
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
