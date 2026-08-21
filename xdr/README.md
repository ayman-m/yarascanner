# YARA Scanner — Cortex XDR edition

A YARA scanning engine that runs on your endpoints through the **Cortex XDR Action Center**,
delivered as a single Python script rather than installed software. Findings leave the endpoint
on two channels: one alert per matched file × rule (the triage grain, capped per scan) and full
match detail written into **XQL lookup datasets** (the forensic grain). A small set of
automations then keeps those datasets bounded, because a fleet scan produces one dataset pair
per host and nothing on the platform prunes them for you.

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
| The five YAMLs in `Packs/YaraDatasetManagement/unified/` | Automations | **Advanced (HMAC)** |
| `Packs/YaraDatasetManagement/Playbooks/playbook-YARA_Dataset_Consolidation.yml` | Playbooks → **Import, through the console** | — |

The five automations are `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`,
`YaraConsolidateSummary`, `YaraCleanup`. That folder holds those five and
nothing else: upload all of them, each is self-contained, and none imports any of the others.

Three things that cost people a deployment:

- **The two keys are different types.** The scanner takes a Standard key in
  `xdr_yara_scanner.py` lines 131–133 (`DEFAULT_XDR_API_KEY` / `_API_ID` / `_API_URL`, at the
  top of the CUSTOMER CONFIG block). The
  automations take an Advanced (HMAC) key. A Standard key in an automation 401s.
- **Each automation carries its own copy of the credential block** — `YaraReport.yml:1500`,
  `YaraConsolidateStatus.yml:1487`, `YaraConsolidateApply.yml:1490`,
  `YaraConsolidateSummary.yml:1590`, `YaraCleanup.yml:1569`. That is **five separate edits**, not
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
| `yara_scanner_matches_v4_scan_<id>` or `yara_scanner_summary_v4_scan_<id>` | Written by consolidation | See below |

The matches dataset carries no `scan_id` and no month in its name, so dashboards and automations
can pin it literally. Each scan begins by deleting the previous scan's rows from it, which is why
it never accumulates — and why only the newest scan's file detail exists per host. The scans
dataset still rotates monthly because nothing ever overwrites it.

## The two consolidation modes — pick one before you scan a fleet

|  | Full detail | Summary only |
|---|---|---|
| Automation | `YaraConsolidateApply` (verifies row counts before deleting) | `YaraConsolidateSummary` |
| Writes to | `yara_scanner_matches_v4_scan_<id>` | `yara_scanner_summary_v4_scan_<id>` |
| Row grain | one row per matched file | one row per (host, rule) |
| Per-rule counts | yes | **no** — you see that a rule fired on a host, not on how many files |
| Host shards afterwards | **deleted** | **kept**, as the deep-dive source |
| Shipped dashboards | work | **none work** — see below |

**Choose full detail** when the consolidated dataset is what analysts will actually query, and
you can afford one row per matched file across the fleet. Use `Apply` for the verified path and
`Fast` when you have already trusted it and want the run time back.

**Choose summary** when you want a fleet-wide "which rules fired where" view and you are content
to pivot into the per-host dataset for detail. It deletes nothing, so it is the safer first run.

Both write to different target names, so both can run against the same scan without colliding.

**Summary mode has no dashboard coverage.** Of the 41 widgets in `widgets/`, 37 query
`yara_scanner_matches*` / `yara_scanner_scans*`, three read the alerts channel, and one reads
`yara_scanner_consolidation_runs*`. None query `yara_scanner_summary_*`. A summary-only tenant
has zero working widgets over its consolidated data and will need its own.

## Sizing

Measured on `api-emea-cxdrp`, 2026-08-20, schema v4. Two scans, same rules, one Linux host:

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

Most automations that write or delete are a **dry run unless `execute=true`** —
**`YaraConsolidateApply` is the one exception, and it matters.** It always writes and always
deletes verified source shards; there is no `execute` argument, no dry-run mode, and no
equivalent flag. A bare `!YaraConsolidateApply` with zero arguments deletes data on its
first run. Check with the read-only `YaraConsolidateStatus` first if you want to see what a
pass *would* do before committing to it.

1. **`YaraReport`** — read-only inventory of every `yara_scanner_*` dataset: kind, host, age,
   state. One API call, safe any time. Start here when asked "why are there so many datasets?"
2. **`YaraConsolidateStatus`** — read-only readiness check: which scans are eligible now, which
   are still running or inside their settle window, which are blocked. Safe in a poll loop.
3. **`YaraConsolidateApply`** (always writes and deletes — see above) or
   **`YaraConsolidateSummary`** (dry run unless `execute=true`) — the
   merge itself, per the mode you chose above.
4. **`YaraCleanup`** — retention pruning; deletes whole datasets, subject to seven safety rails
   (never the current month, among others). Dry run by default.

The playbook wires steps 2 → 3 together (`YaraConsolidateStatus`, then `YaraConsolidateApply` or
`YaraConsolidateSummary`) and is triggered by a correlation rule. **XDR has no scheduled-Job
facility** — there is no built-in way to run this on a timer.

## Where to read more

- **[docs/Deployment_Guide.md](docs/Deployment_Guide.md)** — install and first scan.
- **[docs/CAPACITY.md](docs/CAPACITY.md)** — the full sizing measurements behind the table above.
- **[docs/Troubleshooting.md](docs/Troubleshooting.md)** — when something looks wrong.
- **[docs/topics/](docs/topics/)** — CPU impact, cancellation, datasets and maintenance, rule
  compatibility, known limitations.
- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — every catalogued capability and how to
  observe it on a live scan. **[docs/TEST_PLAN.md](docs/TEST_PLAN.md)** and
  **[docs/rounds/](docs/rounds/)** — acceptance criteria and what each live round found.
- **[docs/design/Dataset_Management_v2_Design.md](docs/design/Dataset_Management_v2_Design.md)** —
  why the dataset model is shaped this way.

## What else is in this folder

`xdr_action_center.py` (API toolkit — deliver, track, verify, cancel), `xdr_consolidate.py`
(pure consolidation logic, unit-tested), `xdr_data_management.py` (CLI for consolidation and
retention), `playbooks/` (Action Center runner and canceller), `simulation/` (fleet and scan
simulators), `dashboards/` and `widgets/`. None of these are uploaded to the tenant.

## Tests

Tests live at the repo root in [`../tests/`](../tests/), deliberately: most exercise **both**
editions through a shared `EDITIONS` list, and they are what stops the two scanners drifting
apart.

```bash
python3 -m pytest tests/ -q      # from the repo root
```
