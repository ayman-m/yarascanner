# YARA Scanner for Cortex XDR & XSIAM

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
- **CPU throttling** — `script` (pause/resume with hysteresis), `os` (idle-tier priority), or `off`
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
| `CONFIG_THROTTLE_MODE` | script/os/off | `script` | CPU pacing strategy |
| `CONFIG_CPU_HIGH_THRESHOLD` | int/None | `None` | Pause-entry % CPU (None = profile default) |
| `CONFIG_CPU_CRITICAL_THRESHOLD` | int/None | `None` | Critical % CPU (None = profile default) |
| `CONFIG_MAX_PAUSE_SECS` | int/None | `None` | Cap on one continuous CPU pause |
| `CONFIG_TENANT_ID` | string | `""` | Tenant tag (`""` = derive from API URL) |
| `CONFIG_LOOKUP_SHARD` | endpoint/none/label | `endpoint` | Per-writer dataset sharding |
| `CONFIG_ALERT_MAX_PER_SCAN` | int | `500` | Storm cap: max per-finding alerts per scan (`≤0` = uncapped) |
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
2. `scan_folder` — target path, or `default` for platform defaults
3. `alert_severity` — `low` | `medium` | `high`

Upload the same file again with entry point **`cancel`** (no inputs) to get a stop button.

### Step 3 — run

Target endpoints in Action Center and run. Progress, per-run logs, and a `scan_summary_<run_id>.json`
land on the endpoint under the scanner directory (`C:\yara_scanner\` / `/opt/yara_scanner/`);
matches land in XDR as alerts + dataset rows as the scan runs.

To stop a running scan: run the `cancel` entry point on the same endpoint — the scan winds down
within ~5 s, drains its uploaders, and writes a terminal `cancelled` lifecycle row.

---

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

- **`yara_scanner_matches_v2_<host>_<YYYYMM>`** — one row per matched string: `rule`, `filename`,
  `file_size`, `file_sha256`, `offset`, `matched_length`, `string`, `severity`, `os_type`,
  `scan_folder`, `tenant_id`, `scan_id`/`run_id`, timestamps
- **`yara_scanner_scans_v2_<host>_<YYYYMM>`** — scan lifecycle: `initiated` / `running` heartbeat /
  `completed` / `cancelled` / `failed`, with counts, throttle posture, and paused time

Why this shape (both are XDR `add_data` platform characteristics):

- **Sharding (`_<host>`)** — concurrent writers to one dataset collide server-side and lose rows;
  one writer per dataset lands 100% at any fleet scale.
- **Rotation (`_<YYYYMM>`)** — `add_data` merge time grows with the dataset's total size, so a
  bounded dataset keeps bounded write time, permanently.

Dashboards and queries are unaffected by either: they fan in with a wildcard
(`dataset = yara_scanner_matches*`). Old months are pruned explicitly with
`xdr_action_center.py prune-datasets` / the `delete_dataset` API. The `_v2` tag is the row-schema
version — bump it on any row-shape change (datasets can't alter schemas in place).

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

One condition produces both: **a rule pack that matches far more than intended** on a large
filesystem — e.g. a string common in benign files (a config keyword, a library banner, a copyright
line) matching tens of thousands of files on a full-drive scan. A measured worst case: one
over-broad rule on a 465k-file Windows system produced **36,243 string matches across 401 files**
in a single scan. The finding-grain alert model absorbed it (401 alerts, all delivered), but the
dataset channel — which records every string hit — queued 36k rows against write times of ~35 s per
500-row batch, and 7,719 rows hit the drain budget: counted, logged, but absent from the dataset.

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
`widgets/xdr_lookup/` (XDR) for customization. The XDR queries use wildcard dataset references, so
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

### Guides (`docs/guides/`)

- `XDR_YARA_Scanner_Guide.md` / `.docx` — deployment + operations, XDR edition
- `XSIAM_YARA_Scanner_Guide.md` / `.docx` — deployment + operations, XSIAM edition
- `YARA_Scanner_Test_and_Performance_Report.md` / `.docx` — measured performance & test coverage

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

CPU stays under the configured thresholds via throttling; memory footprint is bounded by the scan
queue and batch sizes. All figures come from live tenant runs recorded in the performance report.

---

## 9. Security considerations

- **Credentials live in the script** (uploaded to the console script library) or in environment
  variables for the CLI toolkit — never commit real keys to source control (`.env` is gitignored).
- The XDR key needs only **Insert Parsed Alerts** + **XQL/lookups** permissions; scope it to a
  dedicated role. The XSIAM collector key is write-only ingestion.
- Runs against protected paths degrade gracefully (permission errors are counted + logged, not
  fatal). Evidence collection (`CONFIG_COLLECT_FILES`) copies matched files — leave it off unless
  your handling process requires it.
- All uploads are HTTPS. On TLS-intercepting networks, point `XDR_CA_BUNDLE` /
  `REQUESTS_CA_BUNDLE` at your CA chain for the CLI toolkit (endpoint agents are unaffected).

---

## 10. Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| Result says `SCAN ABORTED — … credentials are not set` | Delivery is enabled but the script still has placeholder creds — edit the `DEFAULT_*` values and re-upload |
| `alert_delivery.undelivered > 0` | Alert budget saturated (fleet too concurrent, or a match storm) — see §4.3 |
| `dataset_delivery.undelivered > 0` | Dataset write budget exhausted by a match storm — tune the offending rule (`top_rules` in the summary) |
| `records_skipped > 0` in dataset delivery | Row shape doesn't match the dataset's schema — bump `LOOKUP_SCHEMA_VERSION` so a fresh dataset is created |
| A rule never matches | Check `rules_failed` + the failed-rules log on the endpoint: unavailable module imports are skipped by design |
| Scan is slow on a busy host | That's the throttler honoring CPU thresholds; use `CONFIG_THROTTLE_MODE=os` or raise thresholds for maintenance windows |
| Alerts don't appear in XDR | Verify the key type/permissions; the scanner auto-detects Advanced (HMAC) vs Standard auth — check `uploads_<run_id>.log` for HTTP status lines |

Per-run logs on the endpoint (`logs/` under the scanner directory): `scanner_`, `uploads_`,
`scan_errors_`, `statistics_`, `performance_`, `system_`, `yara_processing_` + the
`scan_summary_<run_id>.json`.

---

## 11. Repository layout

```
├── xdr_yara_scanner.py            # XDR edition (Action Center: main / cancel)
├── xsiam_yara_scanner.py          # XSIAM edition (HTTP Collector)
├── xdr_action_center.py           # API toolkit: run/cancel/verify/xql/prune
├── encode_rules.py                # rules.yar -> base64 for the yarafile input
├── test_rules.yar                 # sample rules (stock-binary matches for smoke tests)
├── dashboards/                    # 3 importable dashboards (XDR lookup + 2 XSIAM)
├── widgets/                       # per-widget XQL (XSIAM) + xdr_lookup/ (XDR)
├── playbooks/                     # Runner / Canceller + README
├── docs/guides/                   # deployment guides + performance report (md + docx)
└── tests/                         # rule generator, corpus seeder, scan matrix, analyzer
```

---

## 12. License & support

MIT — see [LICENSE](LICENSE). Issues and contributions via GitHub. For Cortex platform questions,
see the [Cortex XDR](https://docs-cortex.paloaltonetworks.com/p/XDR) and
[Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/p/XSIAM) documentation; for YARA rule
authoring, the [YARA documentation](https://yara.readthedocs.io/).
