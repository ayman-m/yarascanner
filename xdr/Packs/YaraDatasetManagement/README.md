# YARA Dataset Management (XSOAR pack)

Merges each finished YARA scan's per-host lookup dataset shards into one dataset per scan
— safely, at fleet scale — reports what needs attention, and prunes what has aged out. This
is the XSOAR-pack delivery of the same logic in [`xdr_consolidate.py`](../../xdr_consolidate.py)
and [`xdr_data_management.py`](../../xdr_data_management.py) (see
[Datasets and Maintenance](../../docs/topics/Datasets_and_Maintenance.md) §5 for the
underlying design and safety rails); this pack runs it as a scheduled Job instead of a
manual CLI invocation.

## What's in the pack

| Item | Type | Role |
|---|---|---|
| `YARA Dataset Consolidation` | Playbook | Orchestrates one pass: check readiness → wait on in-progress scans → apply → flag failures. Meant to run **twice daily** as a scheduled Job. |
| `YaraConsolidateStatus` | Automation | Read-only readiness check. Never writes or deletes. |
| `YaraConsolidateApply` | Automation | The mutating step — creates per-scan targets, writes rows, deletes fully-verified source shards. |
| `YaraReport` | Automation | Read-only inventory of every `yara_scanner_*` lookup dataset (kind, host, age, plus the legacy / newer-schema / consolidated buckets). One API call, no writes — safe any time. Writes to `Yara.Report.*`. |
| `YaraCleanup` | Automation | Retention pruning — **deletes whole datasets**. Dry run by default; see below. |
| `YaraConsolidateCommon` | Automation (library only) | Not invoked directly, but it **must still be delivered as an automation in its own right** — the other four do `from YaraConsolidateCommon import ...`, which XSOAR resolves against an automation of that name on the server, and a directory holding only a `.py` is not a content item and is created by no upload path. A verbatim port of `xdr_consolidate.py`'s core logic and `xdr_data_management.py`'s retention logic, kept in sync by `tests/test_consolidation.py::test_pack_copy_gate_logic_matches_xdr_consolidate` and `tests/test_pack_data_management.py::test_pack_data_management_logic_matches_the_cli` (both compare the two files' ported functions and constants statement-by-statement and fail on any drift), plus `CoreApiClient` — a direct, signed-HTTPS client for this tenant's own public API. |

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

## Deployment — pack install or console Import, not a bare item push

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

`YaraConsolidateCommon.py`'s `CoreApiClient` calls this tenant's own public API directly over
signed Advanced (HMAC) HTTPS — the design-rationale comment above the class explains why (the
originally-planned "Cortex Core - IR" generic REST bridge is not registered on this tenant).
Before uploading, edit the three placeholder constants at the top of the file:

```python
DEFAULT_XDR_API_KEY = "replace_with_xdr_advanced_api_key"
DEFAULT_XDR_API_ID = "replace_with_xdr_advanced_api_id"
DEFAULT_XDR_API_URL = "replace_with_xdr_api_url"
```

Use an **Advanced**-type key and set an expiry — see
[api-permissions.md](../../../.claude/skills/xdr-action-center-api/references/api-permissions.md)
for the least-privilege recipe used elsewhere in this project (the automation key needs
script-execution/Action Center/query components; it deliberately should **not** be granted
Data Management, per that doc — but this pack's `CoreApiClient` does need Data Management,
since consolidation itself creates/writes/deletes datasets). There is no separate documented
role recipe scoped to *just* what this pack's key needs (create/read/write/delete lookup
datasets); treat it as needing Data Management at minimum until a narrower recipe is defined.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `YaraConsolidateStatus failed: ... HTTP 401: ...` or `YaraConsolidateApply failed: ... HTTP 401: ...` in the Job's task error / War Room | The embedded `DEFAULT_XDR_API_KEY`/`DEFAULT_XDR_API_ID` were rotated, revoked, or hit their `expiration` on the tenant. The identical generic 401 also covers a mistyped key/ID and a Standard/Advanced type mismatch — the response body alone cannot tell you which. | Regenerate an Advanced-type key for this pack's role (see Credentials above), edit the three `DEFAULT_XDR_*` constants in `YaraConsolidateCommon.py`, and re-deliver the pack (editing the repo file alone does nothing until it's re-imported/re-installed — see Deployment above). Confirm with `YaraConsolidateStatus` — it's read-only and safe to run any time. |
| Every scheduled Job run fails at task "Check consolidation status" (or "Apply consolidation") and task 8 ("Flag failures for attention") never lights up | `return_error` halts the whole playbook run at the failing task, before task 8's condition is ever evaluated — task 8 only reports data-level `failed_count` from a *completed* run, not a total execution error. | Watch the Job's own run history, not just the task-8 context flag — a dead key (or any other uncaught exception) is a hard failure, not a soft one. The `yara_scanner_consolidation_runs` dataset (see Monitoring below) also gets a `status="crashed"` row for a mid-run `YaraConsolidateApply` crash specifically (not for a `YaraConsolidateStatus` crash — that one never reaches `YaraConsolidateApply` at all). |
| Job history shows "0 scan(s) consolidated" every run, nothing actually being merged | Consolidation lock held by another concurrent run (the CLI's `xdr_data_management.py --consolidate --yes`, or an overlapping Job execution) | Check `Yara.ConsolidateApply.lock_held_by_other_run` in context, or just read the readable output — it now says "Skipped this pass — consolidation lock is held by another concurrent run" instead of looking identical to a genuinely-empty pass. Confirm the Job's Queue Handling is set to "Don't trigger a new job instance" and that no one is running the CLI `--consolidate --yes` concurrently. |
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
