# YARA Dataset Management (XSOAR pack)

Merges each finished YARA scan's per-host lookup dataset shards into one dataset per scan
— safely, at fleet scale — and reports what needs attention. This is the XSOAR-pack
delivery of the same consolidation logic in [`xdr_consolidate.py`](../../xdr_consolidate.py)
(see [Datasets and Maintenance](../../docs/xdr/topics/Datasets_and_Maintenance.md) §5 for
the underlying design and safety rails); this pack runs it as a scheduled Job instead of a
manual CLI invocation.

## What's in the pack

| Item | Type | Role |
|---|---|---|
| `YARA Dataset Consolidation` | Playbook | Orchestrates one pass: check readiness → wait on in-progress scans → apply → flag failures. Meant to run **twice daily** as a scheduled Job. |
| `YaraConsolidateStatus` | Automation | Read-only readiness check. Never writes or deletes. |
| `YaraConsolidateApply` | Automation | The mutating step — creates per-scan targets, writes rows, deletes fully-verified source shards. |
| `YaraConsolidateCommon` | Automation (library only) | Not invoked directly. A verbatim port of `xdr_consolidate.py`'s core logic, hand-kept in sync (see the comment block at the top of the file), plus `CoreApiClient` — a direct, signed-HTTPS client for this tenant's own public API. |

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
[api-permissions.md](../../.claude/skills/xdr-action-center-api/references/api-permissions.md)
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
