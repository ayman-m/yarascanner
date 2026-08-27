# YARA Scanner — Cortex XDR edition

A YARA scanning engine that runs on your endpoints through the **Cortex XDR Action Center**,
delivered as a single Python script rather than installed software. Findings leave the endpoint
on two channels: one alert per matched file × rule (the triage grain, capped per scan) and full
match detail written into **XQL lookup datasets** (the forensic grain). A small set of
automations then rolls those datasets up into a fleet-wide view and prunes the aged ones, because
a fleet scan produces one dataset pair per host and nothing on the platform tidies them for you.

On XSIAM? Go to [`../xsiam/`](../xsiam/) instead — separate codebase, different delivery model.

## Why there is one dataset per host

XDR's `lookups/add_data` is **not concurrency-safe**. Two endpoints writing the same dataset
collide server-side and silently lose rows — measured at **87% row loss with 8 concurrent
writers**, with no error raised to either writer. So every host writes to its own dataset. That
is correct for writing, and everything else on this page follows from it.

## What you upload to the tenant

| File | Where it goes | Key type |
|---|---|---|
| `xdr_yara_scanner.py` | Action Center → Scripts (manual; there is no upload API) | **Standard** |
| The nine YAMLs in `Packs/YaraDatasetManagement/unified/` | Automations | **Advanced (HMAC)** |
| `Packs/YaraDatasetManagement/Playbooks/playbook-YARA_Dataset_Consolidation.yml` | Playbooks → **Import, through the console** | — |

The nine automations are `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`,
`YaraConsolidateSummary`, `YaraCleanup`, `YaraWipeAllDatasets`, `YaraRulesFromFile`,
`YaraRulesDecode` and `YaraScanVerify` — the last three serve the scan-from-issue path
(validate an operator-uploaded rules file, decode a dispatched one back to readable rules,
confirm a dispatched wave actually started). That folder holds those nine and nothing else:
upload all of them, each is self-contained, and none imports any of the others.

Three things that cost people a deployment:

- **The two keys are different types.** The scanner takes a Standard key in
  `xdr_yara_scanner.py` lines 131–133 (`DEFAULT_XDR_API_KEY` / `_API_ID` / `_API_URL`, at the
  top of the CUSTOMER CONFIG block). The
  automations take an Advanced (HMAC) key. A Standard key in an automation 401s.
- **Each automation that calls the API carries its own copy of the credential block** — seven of
  the nine, each under the same `CONFIGURATION - the only values in this file you need to edit`
  banner near the top of the file. (`YaraRulesFromFile` and `YaraRulesDecode` make no API call
  and hold no credentials.) That is **seven separate edits**, not
  one — the tenant resolves no cross-script import, so there is no shared library to edit once.
  (`Scripts/<Name>/<Name>.py` is the repo-side review copy; editing it changes nothing on the
  tenant until `tools/build_pack_unified.py` regenerates the yml that actually gets uploaded.)
- **The scanner key needs Query Center (`investigation_query_view`)** on top of External Issues
  Mapping and Data Management. Without it the start-of-scan overwrite 403s, fails safe, and the
  host dataset quietly resumes accumulating — the only sign is a line in the scan log.

Import the playbook through the console, not by API. An API-pushed playbook runs by id but never
appears in `/playbook/search`, so it shows up in no console picker.

## The data model

| Dataset | Lifetime | Holds |
|---|---|---|
| `yara_scanner_matches_v4_<host>_<6hex>` | **Permanent, overwritten** at the start of every scan | One row per matched file. The deep-dive source. |
| `yara_scanner_scans_v4_<host>_<6hex>[_<YYYYMM>]` | Append-only, rotates monthly | Scan lifecycle only — 2 rows per scan, ~1.2 KB |
| `yara_scanner_full_v4_rules_<rulehash>` or `yara_scanner_summary_v4_rules_<rulehash>` | Written by consolidation | See below |

The matches dataset carries no `scan_id` and no month in its name, so dashboards and automations
can pin it literally. Each scan begins by deleting the previous scan's rows from it, which is why
it never accumulates — and why only the newest scan's file detail exists per host. The scans
dataset still rotates monthly because nothing ever overwrites it.

Consolidation **reads** the per-host datasets and never removes them. It groups by the ruleset
hash the scanner leaves at the end of every `scan_id` — the one component every host in a single
Action Center launch shares — so one ruleset produces one consolidated dataset covering the whole
fleet, not one per scan.

## The two consolidation modes — pick one before you scan a fleet

|  | Full detail | Summary only |
|---|---|---|
| Automation | `YaraConsolidateApply` | `YaraConsolidateSummary` |
| Writes to | `yara_scanner_full_v4_rules_<rulehash>` | `yara_scanner_summary_v4_rules_<rulehash>` |
| Grouped by | ruleset — one dataset per ruleset, all hosts in it | same |
| Row grain | one row per matched file | one row per (host, rule) |
| Per-rule counts | yes | **no** — you see that a rule fired on a host, not on how many files |
| Writes anything at all | only with `execute=true` | only with `execute=true` |
| Host shards afterwards | **kept**, as the deep-dive source | **kept**, as the deep-dive source |
| Shipped dashboards | keep working — but see below | keep working — but see below |

**Choose full detail** when the consolidated dataset is what analysts will actually query, and
you can afford one row per matched file across the fleet. Its per-pass bound is `row_ceiling`
(shipped default 60,000 rows per ruleset group); a group larger than that is refused rather than
half-written.

**Choose summary** when you want a fleet-wide "which rules fired where" view and you are content
to pivot into the per-host dataset for detail. Full detail is roughly 40× the rows, so summary is
what scales to a large fleet.

Neither mode deletes a source dataset. Both read the per-host matches datasets and leave them in
place — those are permanent and overwritten by the next scan on that host, so there is nothing
there to reclaim, and they stay the deep-dive source you pivot into. The two modes write to
different target names, so both can run against the same ruleset without colliding.

**No shipped dashboard reads a consolidated dataset.** Of the 41 widgets in `widgets/`, 37 query
`yara_scanner_matches*` / `yara_scanner_scans*`, three read the alerts channel, and one reads
`yara_scanner_consolidation_runs*`. None query `yara_scanner_full_*` or `yara_scanner_summary_*`.
Because both modes leave the per-host shards in place, all 37 keep working either way — but if
the consolidated dataset is what your analysts are meant to look at, you will need to write those
widgets yourself.

## Sizing

Measured on a live Cortex XDR tenant, 2026-08-20, schema v4. Two scans, same rules, one Linux host:

|  | `/usr` | `/etc` |
|---|---|---|
| files scanned | 93,137 | 2,713 matched |
| findings | 1,836 | 5,240 |
| rows written | 1,097 | 2,713 |
| bytes per row | 749 (measured) | ~994 (modelled) |
| dataset size | 0.78 MB | ~2.57 MB |
| match rate | 1.97% | pathological |

`/etc` produced **more findings from fewer files**. Dataset size does not track how much you
scan — it tracks **how often your rules fire**. A targeted scan with loose string rules costs
more than a filesystem sweep with precise ones. This is the single most useful thing to know
before you size anything.

**Per host:** the platform caps a lookup dataset at **50 MB** — not tunable. At 749 B/row that
is roughly **70,000 matched files** on one host. The `/usr` scan used 1.6% of it.

**Per fleet (arithmetic on the row shape, not measured):** a summary row is ~163 B, so 50 MB
holds 321,649 rows. At 4 rules/host that is 80,412 hosts; at 10, 32,164; at 25, 12,865; at 50,
6,432; at 100, 3,216. **Quote 5,000–10,000 endpoints per consolidated scan** — that stays safe
across realistic rule counts. The per-host numbers above are measured; these fleet figures are not.

**Timing.** The per-scan overwrite is a filtered row delete: 10.0s for ~550 rows, against 190.2s
to delete and recreate the dataset — 19×, which is why it is done that way. Writing took 44.7s
for 1,097 rows (3 batches of 500). At fleet scale the **write** dominates, not the flush.

**XQL truncates silently at 1,000,000 rows** and there is no pagination. Nothing warns you.

## Caveats

- **Only the latest scan's file detail survives per host.** The host matches dataset is
  overwritten. If you need history, consolidate before the next scan.
- **Consolidation must keep pace with scan frequency.** An unconsolidated scan is overwritten by
  the next one on that host and is gone.
- **Summary mode carries no counts.** A rule fired on a host; how many files, you cannot tell.
- **Never run two concurrent scans on the same host.** Each flushes the other's rows.
- **A pathological rule set can still overflow one host** (~70,000 matched files). Loose string
  rules are the usual cause.
- **A missing Query Center permission on the scanner key disables the overwrite silently.** The
  scan still runs and still writes; the dataset just grows.

## Operating it

Every automation that writes or deletes is a **dry run unless `execute=true`**, with no
exceptions — `YaraConsolidateApply` included. A bare `!YaraConsolidateApply` with zero arguments
writes nothing and deletes nothing; it reports what it *would* write and stops. The read-only
`YaraConsolidateStatus` gives you the same preview from the eligibility side.

Whole-dataset deletion of your data lives in exactly two automations, and neither is on the
consolidation path: `YaraCleanup` (retention pruning, dry run by default) and
`YaraWipeAllDatasets` (exactly what its name says). The only dataset a consolidation pass ever
deletes is its own mutex, `yara_scanner_consolidation_lock`, when taking over a stale one.

1. **`YaraReport`** — read-only inventory of every `yara_scanner_*` dataset: kind, host, age,
   state. One API call, safe any time. Start here when asked "why are there so many datasets?"
2. **`YaraConsolidateStatus`** — read-only readiness check: which scans are eligible now, which
   are still running or inside their settle window, which are blocked. Safe in a poll loop.
3. **`YaraConsolidateApply`** or **`YaraConsolidateSummary`** (both dry run unless
   `execute=true`) — the roll-up itself, per the mode you chose above. Neither deletes a source
   dataset; the one removal either performs is against its *own* output, dropping `scan_id`s the
   sources no longer hold so a re-run reconciles instead of duplicating.
4. **`YaraCleanup`** — retention pruning; deletes whole datasets, subject to seven safety rails
   (never the current month, among others). Dry run by default. Short of the indiscriminate
   `YaraWipeAllDatasets`, it is the only thing in the pack that deletes an aged month-suffixed
   scans shard; it is blocked from touching a live per-host matches dataset; and **nothing
   schedules it** — if you never run it, aged shards stay.

The playbook wires steps 2 → 3 together (`YaraConsolidateStatus`, then `YaraConsolidateApply` or
`YaraConsolidateSummary`) and is triggered by a correlation rule. **XDR has no scheduled-Job
facility** — there is no built-in way to run this on a timer.

## Where to read more

- **[docs/Operations_Deep_Dive.md](docs/Operations_Deep_Dive.md)** — **start here before a
  fleet rollout.** Every measured limit, caveat and failure mode: run-timeout sizing, the
  overwrite model, consolidation safety rails, the lock, capacity ceilings, and a pre-flight
  checklist.
- **[docs/Deployment_Guide.md](docs/Deployment_Guide.md)** — install and first scan.
- **[docs/CAPACITY.md](docs/CAPACITY.md)** — the full sizing measurements behind the table above.
- **[docs/Troubleshooting.md](docs/Troubleshooting.md)** — when something looks wrong.
- **[docs/topics/](docs/topics/)** — CPU impact, cancellation, datasets and maintenance, rule
  compatibility, known limitations, API key permissions.
- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — every catalogued capability and how to
  observe it on a live scan.

## What else is in this folder

`xdr_action_center.py` (API toolkit — deliver, track, verify, cancel), `xdr_consolidate.py`
(pure consolidation logic, unit-tested), `xdr_data_management.py` (CLI for consolidation and
retention), `playbooks/` (Action Center runner and canceller), `dashboards/` and `widgets/`.
None of these are uploaded to the tenant.

## Tests

Tests live at the repo root in [`../tests/`](../tests/), deliberately: most exercise **both**
editions through a shared `EDITIONS` list, and they are what stops the two scanners drifting
apart.

```bash
python3 -m pytest tests/ -q      # from the repo root
```
