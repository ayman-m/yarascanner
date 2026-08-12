# YARA Scanner for Cortex XDR & XSIAM

**Current version: v2.1.0** (2026-08-06) · [Release notes](CHANGELOG.md) · [Deployment guide](docs/xdr/Deployment_Guide.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Fleet-scale YARA scanning delivered through the Cortex agent — alerts sized for triage,
> datasets sized for forensics, and delivery accounting that always balances.

A multi-threaded, resource-aware YARA scanning engine designed to run on endpoints **through the
Cortex agent** (Action Center / automation playbooks / scheduled jobs). Matches flow back into the
Cortex platform as alerts, datasets, and dashboards — no extra infrastructure on the endpoint.

---

## 1. Overview

### Two editions, one engine

| | `xdr_yara_scanner.py` (Cortex XDR) | `xsiam_yara_scanner.py` (Cortex XSIAM) |
|---|---|---|
| **Delivery APIs** | Insert Parsed Alerts + XQL lookup datasets | HTTP Event Collector (webhook) |
| **Auth** | XDR API key — Advanced (HMAC) and Standard, **auto-detected** | Single HTTP Collector key |
| **Alerting model** | One XDR alert per **finding** (file × rule), storm-capped | Raw JSON events; alerting via XSIAM correlation rules |
| **Forensic record** | Sharded + monthly-rotated lookup datasets (one row per matched string) | Collector dataset (one event per matched string) |
| **Telemetry** | Match-focused (`UPLOAD_NON_MATCH_DATA=False`); agent covers general telemetry | Full telemetry: stats, performance, resources |
| **Cancel a running scan** | `cancel` entry point (cooperative, ~5 s) | stop via agent |
| **Dashboards** | `Yara XDR Scanner (Lookup).json` — 40 widgets | `Yara Matches.json`, `Yara Scan Performance.json` |

### Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Cortex XDR / XSIAM                        │
│   ┌────────────┐   ┌───────────┐   ┌────────┐   ┌──────────┐   │
│   │ Dashboards │   │ Playbooks │   │ Alerts │   │ Datasets │   │
│   └────────────┘   └───────────┘   └────────┘   └──────────┘   │
│          ▲               ▲              ▲            ▲         │
│          └───────────────┴──────┬───────┴────────────┘         │
│                                 │  public API / HTTP collector │
└─────────────────────────────────┼──────────────────────────────┘
                                  │ HTTPS (from the endpoint)
                   ┌──────────────┴──────────────┐
              ┌────▼─────┐                  ┌────▼─────┐
              │ Endpoint │                  │ Endpoint │
              │  Cortex  │  Action Center   │  Cortex  │
              │  agent ──┼── runs script ───┼── agent  │
              │  scanner │                  │  scanner │
              └──────────┘                  └──────────┘
```

### Engine capabilities (both editions)

- **Multi-threaded scanning** with a bounded queue and light process priority (agent-friendly)
- **CPU governor** — bounds the scanner's OWN share of the host: `headroom` (leave N% free,
  adaptive), `budget` (never exceed N%), or `none`. Never stalls: under heavy external load it
  shrinks to a floor rather than waiting for room
- **Rule pack handling** — per-rule compile isolation, unavailable-module detection (skips only
  rules that *import* a missing module), condition-only match summaries, `filename`/`filepath`
  externals available to rules
- **Rule-compile disk cache** (XDR edition) — re-runs with an identical pack skip compilation
- **Junction/symlink cycle protection**, special-file skipping, per-file size limits
- **Evidence collection** (optional) — matched files zipped on the endpoint
- **Structured endpoint logs** per run + machine-readable `scan_summary_<run_id>.json`
- **Log retention** — old run logs pruned automatically (last 10 runs kept)

---

## 2. Quick start (XDR edition)

### Step 1 — set the CUSTOMER CONFIG

All deployment-wide behaviour lives in one block at the top of `xdr_yara_scanner.py`. Edit it once,
then upload — operators never type these again:

| Constant | Values | Default | Effect |
|----------|--------|---------|--------|
| `CONFIG_MODE` | scan/cancel | `scan` | Default action for `main` |
| `CONFIG_CREATE_ALERTS` | True/False | `True` | Insert Parsed Alerts (→ incident creation) |
| `CONFIG_WRITE_DATASET` | True/False | `True` | Write the lookup datasets |
| `CONFIG_COLLECT_FILES` | True/False | `False` | Copy matched files into the evidence zip |
| `CONFIG_CPU_GUARANTEE` | headroom/budget/none | `headroom` | CPU impact policy |
| `CONFIG_CPU_HEADROOM_PCT` | int | `30` | *headroom:* % of the host always left free |
| `CONFIG_CPU_BUDGET_PCT` | int | `25` | *budget:* max % of the host we may use |
| `CONFIG_CPU_FLOOR_PCT` | int | `5` | Never target below this — guarantees progress |
| `CONFIG_WORKERS` | int | `2` | Worker threads. More measured SLOWER (disk-bound); leave at 2 |

**Per-run overrides.** The `options` string (`key=value,key=value`) overrides any constant
for a single run, without re-uploading — handy for testing:

```
cpu_guarantee=budget,cpu_budget_pct=20     # hard 20% cap for this run
cpu_guarantee=none                         # no governing
create_alerts=false,write_dataset=false    # scan only, no delivery
```

Valid keys: `create_alerts, write_dataset, collect_files, cpu_guarantee, cpu_headroom_pct,
cpu_budget_pct, cpu_floor_pct, workers, tenant_id, lookup_shard`. Retired `throttle_*` keys
are still accepted and translated, so existing scripts keep running. Unknown keys fail loudly.
| `CONFIG_TENANT_ID` | string | `""` | Tenant tag (`""` = derive from API URL) |
| `CONFIG_LOOKUP_SHARD` | endpoint/none/label | `endpoint` | Per-writer dataset sharding |
| `CONFIG_ALERT_MAX_PER_SCAN` | int | `500` | Storm cap: max per-finding alerts per scan (`≤0` = uncapped) |
| `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` | int | `50` | Max offsets/strings sampled into one (rule, file) finding's row (`≤0` = uncapped) — see §3.2 |
| `CONFIG_LOOKUP_ROTATION` | monthly/none | `monthly` | Monthly dataset rotation (`_YYYYMM`) |
| `CONFIG_OPTIONS` | `key=value,...` | `""` | Extra overrides applied every run (rarely needed) |

Also set the API credentials (`DEFAULT_XDR_API_URL` / `DEFAULT_XDR_API_ID` / `DEFAULT_XDR_API_KEY`).
Both XDR auth models are supported and **auto-detected** (Advanced/HMAC and Standard); override with
`XDR_AUTH_TYPE` if needed. **A scan aborts loudly if delivery is enabled and the credentials are
still placeholders** — a misconfigured deployment can't silently scan into the void.

### Step 2 — upload to the script library

Console → **Action Center → Script Library → Upload**, entry point **`main`**. The signature is the
input list, so operators see exactly **3 inputs**:

1. `yarafile` — base64-encoded YARA rules (`python3 encode_rules.py rules.yar`)
2. `scan_folder` — a target path, a **comma-separated list of paths** (one scan covering multiple locations/partitions, e.g. `C:\Users,D:\Shares`), or `default` for platform defaults. Invalid entries in a list are skipped with a logged warning; the scan fails only if none are valid
3. `alert_severity` — `low` | `medium` | `high`

Upload the same file again with entry point **`cancel`** (no inputs) to get a stop button.

### Step 3 — run

Target endpoints in Action Center and run. Progress, per-run logs, and a `scan_summary_<run_id>.json`
land on the endpoint under the scanner directory (`C:\yara_scanner\` / `/opt/yara_scanner/`);
matches land in XDR as alerts + dataset rows as the scan runs.

To stop a running scan: run the `cancel` entry point on the same endpoint — the scan winds down
within ~5 s, drains its uploaders, and writes a terminal `cancelled` lifecycle row.

---


### Dataset maintenance — `xdr_data_management.py`

Rotation bounds each dataset's size but never deletes anything, so old months accumulate. This small companion script removes them:

```bash
python3 xdr_data_management.py --report                      # inventory (default)
python3 xdr_data_management.py --older-than-months 6 --yes   # drop months older than 6
```

Dry run unless `--yes`. Never deletes the current month, a future-dated month, an unsuffixed dataset, a newer schema version, or anything outside the `yara_scanner_*` naming contract. **No scan depends on it having run** — if it never runs, datasets grow but every scan still succeeds.

Two more gates run before any `--older-than-months` deletion, both checked live against the
tenant and both "skip to be safe" on error: a dataset whose *newest row* is younger than
`--min-quiet-hours` (default 24h) is kept even if its calendar label looks old — its rotation
suffix reflects when it was created, not whether a long-running scan is still writing to it;
and a dataset still holding a scan_id that `xdr_consolidate.py` hasn't fully folded into a
per-scan target (row ceiling hit, or never consolidated) is kept rather than losing that
scan's only copy of its findings. Both checks add their own XQL query per candidate dataset,
so `--report`/`--older-than-months` runs cost more calls against the tenant than name-only
filtering would — expected, not a bug, on a large fleet.

**Verify-before-delete checks row-count parity only, not content correctness** — a target
whose row count happens to match its sources' combined count is treated as fully
consolidated even if the rows differ (a corrupted write with the same count could still slip
through). The platform has no undelete or dataset versioning: once `delete_dataset` runs, a
mismatch or bug caught after the fact cannot be recovered from a backup, only from whatever
copy the API happened to have prior. Treat consolidation and pruning as one-way.

## 3. How results are delivered (XDR edition)

### 3.1 Alerts — sized for triage

**One alert per finding (file × rule).** A SOC triages *"this file matched this rule"*; per-string
evidence belongs in the dataset. Each alert carries the string-hit count and a sample, and its
identity is stable per (rule, file path, host):

- **1:1 with findings** within a scan — a rule with 90 string hits in one file is *one* alert
- **Idempotent across re-scans** — re-scanning updates the existing alert instead of duplicating it
- Severity comes from the `alert_severity` run input

**Storm cap.** Past `CONFIG_ALERT_MAX_PER_SCAN` findings (default 500), per-finding alerts stop and
each affected rule reports the remainder as **one rollup alert** — `YARA Match Storm: <rule> |
Host: <host>` with the suppressed count. Alert volume is bounded by design; nothing goes silent.

**Paced, batched, retried.** Alerts POST in batches (platform cap 60/call), paced under the
platform's shared per-key alert budget, honor `Retry-After`, and requeue rate-limited batches for a
later delivery window. The end-of-scan drain scales with the backlog.

### 3.2 Lookup datasets — sized for forensics

Two datasets per endpoint per month:

- **`yara_scanner_matches_v3_<host>_<YYYYMM>`** — **one row per (rule, file) finding** (same grain
  as the alert channel below): `rule`, `filename`, `file_size`, `file_sha256`, `severity`, `os_type`,
  `scan_folder`, `tenant_id`, `scan_id`/`run_id`, timestamps, plus `match_count` (the TRUE total
  matched offsets, even when the sample below is capped), `truncated` (bool), and three JSON-encoded
  text fields carrying the per-offset detail: `offsets` (sample of matched byte offsets, up to
  `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX`), `strings` (rendered matched strings, aligned 1:1 with
  `offsets`), and `string_ids` (TRUE, uncapped per-string-identifier counts, e.g.
  `{"$ext2": 12, "$note1": 3}` — useful when a rule has several string variables and you need to
  know which ones actually fired)
- **`yara_scanner_scans_v3_<host>_<YYYYMM>`** — scan lifecycle: `initiated` / `running` heartbeat /
  `completed` / `cancelled` / `failed`, with counts, throttle posture, and paused time

Why this shape (both are XDR `add_data` platform characteristics):

- **Sharding (`_<host>`)** — concurrent writers to one dataset collide server-side and lose rows;
  one writer per dataset lands 100% at any fleet scale.
- **Rotation (`_<YYYYMM>`)** — `add_data` merge time grows with the dataset's total size, so a
  bounded dataset keeps bounded write time, permanently.
- **One row per finding, not per offset (`_v3`)** — an earlier schema (`_v2`, still queryable on
  old data) wrote one row per matched *string offset*. That repeats every per-file column
  (hostname, filename, sha256, scan context — ~18 of 20 fields) unchanged on every row, and an
  unanchored/short pattern hitting one large file can multiply that into tens of thousands of
  near-duplicate rows — measured live: **33,118 rows from one rule against one `.evtx` event log**,
  enough to exhaust a scan's whole upload budget before other findings in the same scan got a turn
  (two endpoints in that test lost data entirely as a result). Folding every offset for a finding
  into one row, with `match_count`/`truncated` tracking the true total, fixes that at the root
  instead of just capping row emission. Re-verified live after the change: total dataset rows for a
  53-match scan dropped to exactly 53 (one row per finding, matching the scan summary).

Dashboards and queries fan in with a wildcard (`dataset = yara_scanner_matches*`), but **`_v2` and
`_v3` data have different columns** — a query selecting `offset`/`string`/`match`/`matched_length`
finds those only on `_v2` rows; `_v3` rows carry the aggregated fields instead. Update saved queries
before relying on `_v3` data. Old months/versions are pruned explicitly with
`xdr_action_center.py prune-datasets` / the `delete_dataset` API. The version tag is the row-schema
version — bump it on any row-shape change (datasets can't alter schemas in place).

Caveats worth knowing before you rely on the `_v3` dataset:

- **The embedded sample is still a sample.** `offsets`/`strings` hold the *first* N occurrences
  (effectively file-offset order) up to `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` (default 50), not a
  random or representative selection — check `truncated` before assuming you're seeing everything.
  `match_count` and `string_ids`, however, are always TRUE totals, never sampled.
- **No native XQL filtering on individual offsets/strings.** XDR lookup datasets only support
  scalar columns (`text`/`number`/`datetime`/`bool` — no array/nested type), so `offsets`/`strings`/
  `string_ids` are JSON-encoded text. You can pull a row and parse it (e.g. in a playbook
  enrichment step), but you can no longer `filter`/`comp` across individual offsets the way `_v2`'s
  flat `offset` column allowed.
- **Bounds per finding, not per scan.** A rule matching moderately across thousands of *different*
  files still produces one row per file — this fixes the single-finding explosion, not a scan-wide
  noisy-rule problem (that's what tuning the rule pack, §4.3, is for).
- **Local artifacts are still uncapped.** The local JSON results file and the per-rule local alert
  `.txt` file on the endpoint both retain every offset — only the network upload is aggregated.
- **The embedded sample is uniform, not rule-aware.** Every finding gets the same
  `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` sample size regardless of rule confidence — there's no
  per-rule exemption today.

### 3.3 Delivery accounting — the books always balance

Every run's `scan_summary_<run_id>.json` reports exactly what landed:

```json
"alert_delivery":   {"total_matches": 36243, "findings": 401, "alerts_queued": 401,
                     "successful_uploads": 401, "failed_uploads": 0, "suppressed": 0,
                     "rollups": 0, "undelivered": 0, "requeued": 0},
"dataset_delivery": {"queued": 36246, "batches_sent": 59, "records_added": 27527,
                     "records_skipped": 0, "send_failures": 1, "rows_unconfirmed": 0,
                     "undelivered": 7719, "dropped": 0}
```

- `findings = successful + failed + undelivered` — anything a bounded drain window can't deliver is
  **counted and logged**, never silently discarded
- `suppressed` findings are reported via `rollups`
- `rows_unconfirmed` marks dataset batches whose *read* timed out — the server merge often commits
  after the client hangs up, so these are retried once and then counted (blind retries would
  duplicate rows)
- The uploads log closes with a one-line truth statement, e.g.
  `Alert delivery final: findings=401 queued=401 ok=401 failed=0 undelivered=0 ...`

---

## 4. ⚠️ Limitations & best practices

The scanner rides two hard platform ceilings. Both are **shared-tenant characteristics of the
Cortex APIs, not tunables** — the scanner is engineered to degrade *predictably and visibly*
against them, and well-tuned rule packs never come near them.

### 4.1 The two ceilings

| Ceiling | What it is | What you see at the limit |
|---|---|---|
| **Alert budget** | The Insert Parsed Alerts API allows ~600 alerts/min **per API key, shared across every endpoint using that key** | Batches are paced/retried; a saturated key requeues and, past the delivery budget, counts `undelivered` |
| **Dataset write time** | Each `add_data` POST triggers a server-side merge whose duration **grows with the dataset's total size** (measured: ~13 s/POST at 15k rows → ~31 s at 77k) | Rows queue behind slow merges; at scan end the drain runs up to its budget (10 min), then counts the remainder `undelivered` |

### 4.2 When you would actually hit them

One condition produces both: **a rule pack that matches far more than intended**, either spread
across a large filesystem or concentrated in one file. Both measured cases below predate the `_v3`
per-finding dataset grain (§3.2) — since dataset rows are now bounded by *finding* count rather than
*match* count, both scenarios now produce roughly one dataset row per matched file instead of one
per string hit, which structurally closes most of the dataset-side exposure. They're kept here
because the *alert* budget ceiling (per-key, not per-finding-size) is unaffected by the dataset
schema and can still be hit by either shape:

- **Many files, moderate hits each.** A string common in benign files (a config keyword, a library
  banner, a copyright line) matching tens of thousands of files on a full-drive scan. A measured
  worst case (pre-`_v3`): one over-broad rule on a 465k-file Windows system produced **36,243 string
  matches across 401 files** in a single scan. The finding-grain alert model absorbed it (401
  alerts, all delivered); the pre-`_v3` dataset channel queued 36k rows and 7,719 hit the drain
  budget — under `_v3` this would be ~401 rows, well inside the write-time ceiling.
- **One file, extreme hits.** An unanchored short pattern (a bare word like `"powershell"`) inside a
  single text-dense file — a log, a `.dll`, an event trace. Measured live (pre-`_v3`): one rule
  against one `.evtx` event log produced **33,118 offsets from a single (rule, file) pair**, on a
  host whose other findings then went entirely undelivered — the write budget was spent before they
  got a turn. This is the case that motivated the `_v3` redesign; re-verified after the change, the
  same file now produces exactly one dataset row (`match_count` still reports the true 33k+, via
  `truncated=true` — see §3.2).

A very large fleet scanning concurrently on one API key can also saturate the *alert* budget alone,
even with tuned rules.

### 4.3 How to avoid it

1. **Tune out false-positive-prone rules before fleet rollout.** Test every new pack against a
   small representative folder first (`scan_folder` = one directory, not a drive) and read
   `top_rules` in the scan summary. A rule matching hundreds of files in a small sample will match
   tens of thousands fleet-wide — fix the rule (anchor strings, add `filesize`/path conditions,
   require multiple strings) or drop it. **Prefer fewer, specific rules over broad packs.**
2. **Watch the books.** `alert_delivery.suppressed`, `.undelivered`, and
   `dataset_delivery.undelivered` in the scan summary (and the dashboard's delivery widgets) are
   your early-warning signals — non-zero values mean a rule needs tuning, not that data was lost
   silently.
3. **Stagger fleet scans** (scheduling waves in the Job/playbook) and/or use **separate API keys
   per wave** if you must scan thousands of endpoints in one window — the alert budget is per key.
4. **Let rotation work for you.** Keep `CONFIG_LOOKUP_ROTATION=monthly` (default) so dataset write
   time stays bounded; prune old months periodically with `prune-datasets`.
5. **Storm behaviour is a policy knob.** `CONFIG_ALERT_MAX_PER_SCAN` (default 500) decides how many
   per-finding alerts a runaway scan may emit before rolling up. Raise it only with a tuned pack
   and a dedicated API key.

> **Design position:** past the ceilings, alerts stay complete at *finding* grain (cap + rollups),
> the dataset holds everything the write budget allows, and every shortfall is **counted** in the
> summary. If `undelivered` is consistently non-zero, the fix is in the rules or the schedule — not
> the endpoint.

---

## 5. XSIAM edition (`xsiam_yara_scanner.py`)

The XSIAM edition ships every event as standardized JSON to an **HTTP Event Collector** — matches,
statistics, performance snapshots, and resource telemetry — and leaves alerting to XSIAM
correlation rules over the ingested dataset.

- **Setup:** set `DEFAULT_API_KEY` / `DEFAULT_API_ENDPOINT` to your collector, upload via the
  console, entry point `main(yarafile, scan_folder, alert_severity)`. A scan **aborts loudly** if
  uploads are enabled while the collector credentials are still placeholders.
- **Delivery:** one JSON event per matched string with bounded per-item retries and backoff.
  Repetitive per-item log lines are rate-limited on the endpoint (first 20, then periodic
  summaries), so a sustained failure can't bloat endpoint logs.
- **Accounting:** the uploads log closes with
  `Match delivery final: matches=N ok=A failed=B undelivered=C` — items still queued when the
  shutdown drain expires are counted, never silently dropped.
- **Rule support:** the same engine features as XDR, plus detailed fallback summaries for
  condition-only matches.
- **Dashboards:** `dashboards/Yara Matches.json` and `dashboards/Yara Scan Performance.json` (with
  their editable XQL under `widgets/`).

---

## 6. Dashboards

| Dashboard | Edition | Contents |
|---|---|---|
| `dashboards/Yara XDR Scanner (Lookup).json` | XDR | **40 widgets** over the lookup datasets: detection KPIs, top rules/hosts/files, match timelines, scan throughput, cancellations/failures, alert-vs-dataset delivery health |
| `dashboards/Yara Matches.json` | XSIAM | Threat-detection view over collector events |
| `dashboards/Yara Scan Performance.json` | XSIAM | Scan operations: throughput, workers, cache, resources |

Import via **Dashboards → Import**. Every widget's XQL is in `widgets/` (XSIAM) and
`widgets/xdr/` (XDR) for customization. The XDR queries use wildcard dataset references, so
they span all endpoint shards and months automatically.

Example ad-hoc XQL against the XDR datasets:

```sql
dataset = yara_scanner_matches*
| filter severity in ("High", "Medium")
| comp count() as hits by rule, hostname
| sort desc hits | limit 20
```

---

## 7. Automation & tooling

### Playbooks (`playbooks/`)

`YARA_Scanner_Runner.yml` / `YARA_Scanner_Canceller.yml` — Action Center automation via the
**Cortex Core - IR** integration (`core-get-scripts` → `core-get-endpoints` → `core-script-run`),
plus scheduling guidance for recurring scan Jobs. See `playbooks/README.md` for the required
3-input script upload.

### Dataset consolidation automation (`Packs/YaraDatasetManagement/`)

An XSOAR pack — playbook + automations — that runs `xdr_consolidate.py`'s per-scan
consolidation (§2 above) as a **twice-daily scheduled Job** instead of a manual CLI
invocation. Deployment, credentials, troubleshooting (including the pack-specific HTTP 401
symptom), and the `yara_scanner_consolidation_runs` health dataset/widget:
[Packs/YaraDatasetManagement/README.md](Packs/YaraDatasetManagement/README.md).

### API toolkit (`xdr_action_center.py`)

A single CLI/library for driving the whole lifecycle from anywhere with API access:

```bash
python3 xdr_action_center.py endpoints                    # list agents
python3 xdr_action_center.py run-scanner --hostname H --rules rules.yar --scan-folder /tmp
python3 xdr_action_center.py cancel --hostname H
python3 xdr_action_center.py verify --hostname H          # matches/scans landed?
python3 xdr_action_center.py xql "dataset = yara_scanner_scans* | limit 10"
python3 xdr_action_center.py prune-datasets --dry-run     # retire legacy/old datasets
```

Credentials come from `.env` / environment (`XDR_API_URL`, `XDR_API_ID`, `XDR_API_KEY`); both auth
models are auto-detected. Corporate-proxy TLS is supported via `XDR_CA_BUNDLE`.

### Automation skill (`.claude/skills/xdr-action-center-api/`)

A self-contained bundle documenting **which supported public APIs automate each YARA-scan
operation** (run / cancel / track / results / verify), with a runnable end-to-end example
(`scripts/yara_scan_automation.py`) usable by humans or LLM agents. Includes a full
endpoint map (`references/public-api-map.md`) — including why console-internal
`/api/webapp/*` endpoints must not be scripted, and the supported equivalent for each.

### Test harness (`tests/`)

`gen_rules.py` (rule packs of every shape, 1→500 rules), `seed_corpus.py`, `run_matrix.py`
(multi-host scan matrix), `analyze.py` (results → report tables). The
`.claude/skills/xdr-yara-scan-test` skill packages the same flow for assistant-driven testing.

### Documentation

**Cortex XDR**
- [Deployment Guide](docs/xdr/Deployment_Guide.md) — install, configure, run
- [Troubleshooting](docs/xdr/Troubleshooting.md) — symptom, cause, fix
- Topic guides — [CPU Impact Control](docs/xdr/topics/CPU_Impact_Control.md) ·
  [Scan Cancellation](docs/xdr/topics/Scan_Cancellation.md) ·
  [Rule Compatibility](docs/xdr/topics/Rule_Compatibility.md) ·
  [Datasets and Maintenance](docs/xdr/topics/Datasets_and_Maintenance.md) ·
  [Known Limitations](docs/xdr/topics/Known_Limitations.md)

**Cortex XSIAM**
- [Deployment Guide](docs/xsiam/Deployment_Guide.md) — collector, parsing rule, run
- [Troubleshooting](docs/xsiam/Troubleshooting.md) — symptom, cause, fix

**Both**
- [CHANGELOG.md](CHANGELOG.md) — release notes: what changed in each version, and why

---

## 8. Performance

Measured on 2-worker light profile (agent-friendly defaults), e2-medium-class VMs:

| Scenario | Result |
|---|---|
| Linux full-system scan (133k files, 10 rules) | ~2.6 min wall, ~850 files/s |
| Windows full-drive scan (465k files, 10 rules) | ~25 min wall, ~470–540 files/s |
| 500-rule pack compile | ~0.2 s (then cached on disk for re-runs) |
| Small scan end-to-end (scan + alerts + datasets) | ~30–60 s including delivery drains |
| Finding alerts | delivered 1:1 up to the cap, idempotent across re-scans |

CPU stays under the configured share via the governor; memory footprint is bounded by the scan
queue and batch sizes. All figures come from live tenant runs recorded in the performance report.

---

## 9. Security considerations

- **Credentials live in the script** (uploaded to the console script library) or in environment
  variables for the CLI toolkit — never commit real keys to source control (`.env` is gitignored).
- **Least-privilege key roles**: use two separate XDR keys — a *scanner delivery* key
  (**External Issues Mapping** for alerts + **Data Management** for datasets — verified
  by live smoke test) and an optional *automation* key (script execution + Action Center +
  query, endpoint-scoped). The XSIAM collector key is a write-only ingestion token with no
  RBAC role. Exact per-operation recipes, the create-role/key API flow, and the
  `manage_role_key.py` helper:
  [.claude/skills/xdr-action-center-api/references/api-permissions.md](.claude/skills/xdr-action-center-api/references/api-permissions.md).
- Runs against protected paths degrade gracefully (permission errors are counted + logged, not
  fatal). Evidence collection (`CONFIG_COLLECT_FILES`) copies matched files — leave it off unless
  your handling process requires it.
- All uploads are HTTPS. On TLS-intercepting networks, point `XDR_CA_BUNDLE` /
  `REQUESTS_CA_BUNDLE` at your CA chain for the CLI toolkit (endpoint agents are unaffected).

---

## 10. Troubleshooting

Symptom, cause and fix: **[Troubleshooting](docs/xdr/Troubleshooting.md)**.

Start with `scan_summary_<run_id>.json` on the endpoint — it carries the scanner version,
the outcome, every delivery counter, and the CPU governor result in one file. Report
`scanner_version` with any support request.

## 11. Repository layout

Everything is split by edition — **XDR** and **XSIAM** never share a folder.

```
├── xdr_yara_scanner.py            # XDR edition   (Action Center: main / cancel)
├── xdr_data_management.py         # XDR: lookup-dataset retention + consolidation
├── xdr_consolidate.py             # XDR: per-scan dataset consolidation logic
├── xdr_action_center.py           # XDR: API toolkit — run / cancel / verify / xql
├── xsiam_yara_scanner.py          # XSIAM edition (HTTP Log Collector)
├── encode_rules.py                # rules.yar -> base64 for the yarafile input
├── test_rules.yar                 # sample rules (stock-binary matches for smoke tests)
├── CHANGELOG.md                   # release notes — what changed in each version, and why
│
├── docs/
│   ├── xdr/                       # XDR: deployment guide, troubleshooting, presentation
│   │   └── topics/                #      CPU, cancellation, rule compatibility, datasets, known limitations
│   ├── xsiam/                     # XSIAM: deployment guide, troubleshooting
│   └── RELEASING.md               # internal: release process
│
├── dashboards/{xdr,xsiam}/        # importable dashboards, per edition
├── widgets/{xdr,xsiam}/           # per-widget XQL, per edition
├── playbooks/                     # Runner / Canceller — work on both editions
├── Packs/YaraDatasetManagement/   # XSOAR pack: consolidation as a scheduled Job (§7)
├── images/                        # dashboard screenshots
└── tests/                         # XDR: rule generator, corpus seeder, scan matrix, unit tests
```

**Where things belong.** Product documentation describes the current release only.
Anything historical — why a design changed, what a past version measured, defects and their
fixes — lives in [CHANGELOG.md](CHANGELOG.md). Symptom/cause/fix material lives in each
edition's Troubleshooting guide, not in its deployment guide.

---

## 12. License & support

MIT — see [LICENSE](LICENSE). Issues and contributions via GitHub. For Cortex platform questions,
see the [Cortex XDR](https://docs-cortex.paloaltonetworks.com/p/XDR) and
[Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/p/XSIAM) documentation; for YARA rule
authoring, the [YARA documentation](https://yara.readthedocs.io/).
