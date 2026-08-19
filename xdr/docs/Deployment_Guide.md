% YARA Scanner for Cortex XDR — Deployment Guide
% Cortex XDR edition (`xdr_yara_scanner.py`, v2)
% Version 3.3.0 · Released 2026-08-17

---

# 1. Overview

> **Which edition is this?** This guide covers `xdr_yara_scanner.py` for **Cortex XDR**.
> For Cortex XSIAM, see the [XSIAM Deployment Guide](../../xsiam/docs/Deployment_Guide.md).

This guide explains how to deploy `xdr_yara_scanner.py` as a managed response script in
**Cortex XDR Action Center** and land its results in XDR as **alerts** and **lookup
datasets** for hunting, dashboards, and incident response.

This edition uses the **Cortex XDR public API** directly:

| Channel | XDR API | Result |
|---------|---------|--------|
| Alerts | **Insert Parsed Alerts** (`/public_api/v1/alerts/insert_parsed_alerts`) | One alert per **finding** (`rule + file`, offset-free identity; hit count + sample inside) → feeds XDR incident creation. Storm-capped at `CONFIG_ALERT_MAX_PER_SCAN` (default 500) with one rollup alert per rule beyond it |
| Match records | **Lookup dataset** `yara_scanner_matches_v2_<host>_<YYYYMM>` (`/xql/lookups/add_data`) | One row per matched string; per-endpoint shard, **monthly-rotated** (bounds `add_data` merge time, which grows with dataset size), queried via `yara_scanner_matches*` |
| Scan lifecycle | **Lookup dataset** `yara_scanner_scans_v2_<host>_<YYYYMM>` | initiated / running / completed / cancelled / failed rows |

Every row and alert is tagged with a **`tenant_id`** derived from your API URL, so the
data is safe to consolidate across tenants.

> **v2 highlights:** Advanced (HMAC) authentication with auto-detection, per-channel
> output flags, a CPU governor that bounds the scan's share of the host, cooperative scan
> cancellation, per-endpoint rotated lookup datasets, a dedicated dashboard, and automation
> playbooks.

## Topic guides

This guide covers deployment and the capabilities of **v2.1.0** as shipped. What changed
between versions, and why, is in the [release notes](../../CHANGELOG.md). Four companion documents go
deeper where operators usually need it:

| Guide | Answers |
|---|---|
| [CPU Impact Control](topics/CPU_Impact_Control.md) | *"Will this scan slow my machine, and how do you know?"* |
| [Scan Cancellation](topics/Scan_Cancellation.md) | *"How do I stop a scan, and why does a cancelled one still show as running?"* |
| [Rule Compatibility](topics/Rule_Compatibility.md) | *"Which YARA library does each agent ship, and why do my rules work locally but get skipped on the endpoint?"* |
| [Datasets and Maintenance](topics/Datasets_and_Maintenance.md) | *"Why these dataset names, and how do I stop them growing forever?"* |
| [Troubleshooting](Troubleshooting.md) | *"It didn't work — where do I look?"* |

---

# 2. Script Design & Capabilities

## 2.1 Design philosophy

1. **Do no harm to production hosts** — throttled CPU, bounded memory, graceful back-off.
2. **Lose nothing** — matches are written to disk (forensic evidence) *and* delivered to
   XDR; retries + circuit breaker absorb transient network failures.
3. **Operate unattended** — no prompts; a compact parameter surface drives fleet-wide
   execution from the Action Center.

## 2.2 Internal architecture

A producer/consumer pipeline of single-responsibility classes:

| Component | Responsibility |
|-----------|----------------|
| `ScanConfig` | Rules, paths, thresholds, runtime options, tenant identity |
| `YaraScanner` | Orchestrator — work queue, workers, scan loop, throttle + cancellation |
| `ResultsUploader` | Insert Parsed Alerts channel (one alert per file×rule finding; storm cap + per-rule rollups; honest undelivered accounting) |
| `LookupDatasetUploader` | Batched writes to the per-endpoint `yara_scanner_matches_v2_*` / `yara_scanner_scans_v2_*` shards |
| `EvidenceCollector` | Evidence ZIP (metadata always; matched-file copies optional) |
| `CleanupManager` | Post-scan cleanup via Task Scheduler / systemd / launchd |

## 2.3 Output channels & flags

Each delivery channel is independently switchable at runtime (see the `options`
parameter, §7):

| Channel | Flag | Default | When OFF |
|---------|------|---------|----------|
| Insert Parsed Alerts (alerts → incidents) | `create_alerts` | on | Matches still logged locally + written to the dataset |
| Lookup datasets | `write_dataset` | on | No dataset writes |
| Matched-file copies in the evidence ZIP | `collect_files` | **off** | ZIP is metadata-only (`file_mapping.txt` + alert texts + SHA256) |

Local file logging (`logs/`, `alert/`) is always on — it is the forensic baseline and is
not gated by any flag.

---

# 3. Authentication (important)

Cortex XDR issues API keys at two security levels, and the scanner supports **both**,
auto-detecting which your tenant expects:

| Mode | Headers |
|------|---------|
| **Advanced** (default for modern tenants) | `x-xdr-nonce` + `x-xdr-timestamp` + `Authorization = sha256(key + nonce + timestamp)` |
| **Standard** | `Authorization: <key>` + `x-xdr-auth-id: <key-id>` |

Set `XDR_AUTH_TYPE` (`auto` \| `advanced` \| `standard`, default `auto`). In `auto` mode
the scanner probes `get_datasets` once with Advanced then Standard and caches the winner.

> **Why this matters:** an Advanced-key tenant returns **HTTP 401** to Standard-only
> auth. If your earlier YARA scans produced *no* alerts and *no* dataset rows, a
> Standard-only build silently failing against an Advanced key is the usual cause — the
> v2 build fixes this.

---

# 4. Prerequisites

| Item | Value / Notes |
|------|---------------|
| XDR role | A user/API key with permission to run scripts and write lookup datasets |
| API key | Standard or Advanced — the scanner auto-detects (§3) |
| Cortex Agent | Installed and connected on each target endpoint |
| Endpoint OS | Windows, Linux, or macOS. The agent ships its **own** embedded Python with `yara`, `psutil` and `requests` — nothing to install on the endpoint. The YARA library version depends on the **platform**, not the agent version, and decides which rule features compile: see [Rule Compatibility](topics/Rule_Compatibility.md) |
| Privileges | Run as **root / SYSTEM** for full coverage |
| Disk space | ~200 MB on the endpoint for the working directory and evidence ZIP |
| Network | Outbound HTTPS from the endpoint to your XDR API URL |

---

# 5. Step 1 — Configure Credentials

Open `xdr_yara_scanner.py` and set the embedded credential constants near the top:

```python
DEFAULT_XDR_API_KEY = "<your-api-key>"
DEFAULT_XDR_API_ID  = "<your-api-key-id>"
DEFAULT_XDR_API_URL = "https://api-<tenant>.xdr.<region>.paloaltonetworks.com"
```

Leave `XDR_AUTH_TYPE` at `auto` unless you need to force a mode.

> **Security note:** the edited `.py` now contains a live API key — treat it as a secret.
> Never commit it to shared version control; keep credentialed copies in a controlled
> location and rotate the key if the file leaves it.

---

# 6. Step 2 — Prepare Your YARA Rules (Base64)

The `yarafile` argument must be base64-encoded:

```bash
python3 encode_rules.py my_rules.yar -o my_rules.b64     # repo helper
# or: base64 -w0 my_rules.yar > my_rules.b64  (macOS: base64 -i my_rules.yar -o my_rules.b64)
```

The `test_rules.yar` in this repo is a good starting point — its `MatchCalc` /
`MatchNotepad` rules fire on stock Windows binaries for an end-to-end smoke test.

---

# 7. Step 3 — Upload the Script to the Library

Cortex XDR has **no public API to upload a library script**, so this is a one-time UI
step. **Action Center → Scripts → New → Upload Script**, select `xdr_yara_scanner.py`.

Metadata:

| Field | Value |
|-------|-------|
| Script Name | `xdr_yara_scanner_v4` (any name; referenced by the playbooks' `script_name`) |
| Supported OS | Windows, Linux, macOS |
| Timeout | `21600` (6 h) |
| Entry Point | `main` (run a scan) — or `cancel` (stop a running scan, no inputs) |
| Run as | Administrator / root |

**Input parameters — only these 3 string inputs (Entry Point = `main`):**

| Order | Name | Description |
|-------|------|-------------|
| 1 | `yarafile` | Base64-encoded YARA rules |
| 2 | `scan_folder` | Target path, a comma-separated list of paths (multi-location/partition scan; invalid entries skipped with a warning), or `default` |
| 3 | `alert_severity` | `low` \| `medium` \| `high` |

That is the whole per-run input list — operators fill in *which rules, which folder, what
severity*, nothing else. Everything else (alerts on/off, dataset on/off, file collection, CPU
throttling, sharding, tenant tag, …) is set **once** in the CUSTOMER CONFIG block at the top of
the script (§7.1) and travels with the uploaded script. To **cancel** a running scan, run the
same script with Entry Point = `cancel` (it takes no inputs).

## 7.1 CUSTOMER CONFIG — edit once, at the top of the script

Open `xdr_yara_scanner.py` and edit the clearly-marked `CUSTOMER CONFIG` block near the top, then
re-upload. These are the deployment-wide behaviour knobs (no per-run input needed):

| Constant | Values | Default | Effect |
|----------|--------|---------|--------|
| `CONFIG_MODE` | `scan` / `cancel` | `scan` | Default action for the `main` entry point |
| `CONFIG_CREATE_ALERTS` | `True`/`False` | `True` | Insert Parsed Alerts (→ incidents) |
| `CONFIG_WRITE_DATASET` | `True`/`False` | `True` | Write the lookup datasets |
| `CONFIG_COLLECT_FILES` | `True`/`False` | `False` | Copy matched files into the evidence ZIP |
| `CONFIG_CPU_GUARANTEE` | `headroom`/`budget`/`none` | `headroom` | CPU impact policy (§10) |
| `CONFIG_CPU_HEADROOM_PCT` | int | `30` | *headroom:* % of the host always left free |
| `CONFIG_CPU_BUDGET_PCT` | int | `25` | *budget:* max % of the host we may use |
| `CONFIG_CPU_FLOOR_PCT` | int | `5` | Never target below this — guarantees progress (§10) |
| `CONFIG_WORKERS` | int | `2` | Scan worker threads. `0` = auto (`cores // 2`). **Leave at 2** (§10) |
| `CONFIG_TENANT_ID` | string | `""` | Tenant tag (`""` = derive from API URL) |
| `CONFIG_LOOKUP_SHARD` | `endpoint`/`none`/`<label>` | `endpoint` | Dataset sharding (§11) |
| `CONFIG_ALERT_MAX_PER_SCAN` | int | `500` | Max per-finding alerts per scan; beyond → one rollup per rule. **Constant only** |
| `CONFIG_ALERT_OFFSETS_PER_FINDING_MAX` | int | `50` | Offsets **rendered** per finding in the local `alert/<rule>.txt`. **New in v3.3.0** — the file previously listed every offset, which on a noisy rule against event logs grew it to hundreds of MB on the scanned host. The per-string-ID hit census above them is never capped, so which string fired and how often survives in full; only the offsets are sampled. `0` renders everything. **Constant only** |
| `CONFIG_LOOKUP_ROTATION` | `monthly`/`none` | `monthly` | Monthly dataset rotation (§11). **Constant only** |
| `CONFIG_HOST_CLEANUP` | `off`/`on_delivery`/`always` | `off` | Remove this run's working files from the endpoint at end of run. **Constant only** |
| `CONFIG_HOST_CLEANUP_KEEP` | `nothing`/`summary`/`evidence` | `summary` | What to keep when cleanup runs. **Constant only** |
| `CONFIG_OPTIONS` | `key=value,key=value` | `""` | Rarely-needed extra overrides applied every run |

**Upgrading from an earlier build.** The old `throttle_mode` runtime option is still
accepted and translated (`off` → `cpu_guarantee=none`; `script` or `os` →
`cpu_guarantee=headroom`), so existing scheduled jobs and playbooks keep running unchanged.
Unknown keys still fail loudly.

**Host cleanup.** Off by default — nothing about existing deployments changes unless you
turn it on. The scanner already trims its footprint *across repeat scans* (the previous
run's alerts/evidence are cleared at the start of the next one, logs keep the last 10
scans), but does nothing at the *end* of a run — so a host scanned once and never again
keeps its full working directory forever. `on_delivery` removes it only once this run's
findings are confirmed delivered (an empty `delivery_shortfall`); it refuses if neither
`CONFIG_CREATE_ALERTS` nor `CONFIG_WRITE_DATASET` is enabled, since with no delivery
channel there is nothing to verify and the local copy would be the only copy. `always`
skips that check entirely. `CONFIG_HOST_CLEANUP_KEEP` controls what survives: `summary`
(recommended) keeps the tiny machine-readable `scan_summary_<run_id>.json`; `evidence`
also keeps the evidence ZIP; `nothing` removes everything. The rule-compilation cache is
never touched — it is shared across runs, not this run's data.

**Per-run overrides.** A per-run `options` string (`key=value,key=value`) beats the constant
for the ten runtime keys: `create_alerts`, `write_dataset`, `collect_files`, `cpu_guarantee`,
`cpu_headroom_pct`, `cpu_budget_pct`, `cpu_floor_pct`, `workers`, `tenant_id`, `lookup_shard`.
The two marked **constant only** have no options equivalent and are rejected as unknown keys —
both are deployment-wide by nature (rotation decides dataset naming; the alert cap protects a
per-API-key ceiling shared across every concurrent scan). Unknown keys always fail loudly with
the valid list, rather than being silently ignored.

> Advanced / automation only: the internal `run(...)` API and the CLI accept that `options`
> string, but the Action Center `main` entry point deliberately does **not** expose it, so
> operators aren't faced with a long input list.

---

# 8. Step 4 — Run the Script on Endpoints

## 8.1 Ad-hoc run from the UI

**Action Center → Scripts** → select the script → **Run** → pick target endpoints →
supply the three inputs (`yarafile` = your base64, `scan_folder`, `alert_severity`).
Track under **Action Center → All Actions**. To stop a scan, run the same script with
Entry Point = `cancel` (§9).

## 8.2 Programmatic (API)

```bash
# core of the playbook flow — run a library script with parameters
POST /public_api/v1/scripts/run_script/
{"request_data": {"script_uid": "<uid-from-get_scripts>", "timeout": 3600,
  "filters": [{"field": "endpoint_id_list", "operator": "in", "value": ["<endpoint-id>"]}],
  "parameters_values": {"yarafile": "<b64>", "scan_folder": "default",
                        "alert_severity": "low"}}}
```

`parameters_values` must match the library script's inputs **exactly** — the three above
for `main`, and an empty set for the `cancel` entry point. Any extra key is rejected.

Advanced-key tenants must HMAC-sign the request (§3). Poll
`/public_api/v1/actions/get_action_status/` (by `group_action_id`) and read
`/public_api/v1/scripts/get_script_execution_results/` for the per-endpoint summary.

## 8.3 Automation playbooks

`playbooks/YARA_Scanner_Runner.yml` and `playbooks/YARA_Scanner_Canceller.yml` wrap the
flow using the built-in **Cortex Core - IR** integration (`core-get-scripts` →
`core-get-endpoints` → `core-script-run`). Import them via console custom content and
run manually or as a scheduled **Job**. See `playbooks/README.md`.

## 8.4 Testing without a UI upload

The bundled skill `.claude/skills/xdr-yara-scan-test/` runs the scanner on an endpoint
via `run_snippet_code_script` (no library upload) and verifies the datasets — useful for
validating rules/credentials before a production rollout.

---

# 9. Step 5 — Scan Cancellation

There are two ways to stop a running scan, and they behave differently.

**To stop a scan and keep what it has found**, run the script's **`cancel` entry point** as
a second Action Center action against the same endpoints (or use
`YARA_Scanner_Canceller.yml`). The scan stops within ~5 seconds, drains its queued alerts
and dataset rows, writes a terminal `cancelled` row to `yara_scanner_scans`, and returns
`Scan cancelled by operator: …`.

**To stop a scan immediately**, use the console's own **Cancel** in Action Center. This
terminates the payload outright — faster, but the scan writes no terminal row, no summary,
and any findings not yet delivered are lost.

| | Console Cancel | `cancel` entry point |
|---|---|---|
| Stops the scan | immediately | within ~5 s |
| Findings preserved | no | yes |
| Terminal row + summary | no | yes |
| Usable from API / SOAR | no | yes |

> A scan stopped by the console Cancel leaves its lifecycle row at `initiated` or `running`
> permanently, so dashboards will show it as running long after it has stopped. Use the
> `cancel` entry point if that matters to you.

**Detail:** [Scan Cancellation](topics/Scan_Cancellation.md) — the two mechanisms, the
orphaned-lifecycle-row behaviour, fleet-scale considerations, and API limitations.

---

# 10. Resource Management — CPU impact

The scanner bounds **its own share of the host**, so a scan does not degrade the machine it
runs on.

| `CONFIG_CPU_GUARANTEE` | Behaviour |
|---|---|
| `headroom` (default) | Always leave `CONFIG_CPU_HEADROOM_PCT` of the host free. A quiet machine gets a fast scan; a busy one gets a quiet scanner. |
| `budget` | Never exceed `CONFIG_CPU_BUDGET_PCT` of the host, whatever else is running. Predictable, easy to state in a change request. |
| `none` | No CPU governing. Low process priority still applies. |

Under heavy external load the target falls to `CONFIG_CPU_FLOOR_PCT` and the scan continues
slowly — it degrades, it does not stall.

**Worker count.** `CONFIG_WORKERS` defaults to `2`. Scanning is disk-bound as well as
CPU-bound, so more workers is generally slower. Raise it only if you have measured a gain on
your storage.

**Verifying impact after a scan.** `scan_summary_<run_id>.json` carries a `cpu_governor`
block showing the target, the share actually used, and time surrendered. The endpoint's
`performance_<run_id>.log` carries the same figures over time.

**Detail:** [CPU Impact Control](topics/CPU_Impact_Control.md) — how the governor works,
what it guarantees and what it does not, **why it replaced the old `script` / `os` throttle
modes**, tuning, telemetry reference, measured behaviour, and the Windows CPU ceiling.

---

# 11. Datasets & Schema

## Dataset naming

```
yara_scanner_matches_v2_<host>_<YYYYMM>     yara_scanner_scans_v2_<host>_<YYYYMM>
```

Each host writes **its own pair of datasets** (`CONFIG_LOOKUP_SHARD = "endpoint"`), and a
fresh pair begins **each month** (`CONFIG_LOOKUP_ROTATION = "monthly"`). `_v2` is the schema
version.

**This is a workaround, not a preference.** A single dataset for the whole estate would be
the better design — every row already carries `scan_id`, `run_id`, `scan_date`, `hostname`
and `tenant_id`, so filtering alone would give you everything. It is not used because
`lookups/add_data` is not concurrency-safe: two endpoints writing the same dataset collide
on a server-side clone-table race and the rows are **silently lost** (measured: ~2 of 8
batches landed at 8-way concurrency; client-side jitter does not help). One writer per
dataset makes the collision impossible — verified at 8/8. Monthly rotation exists for a
second platform limit: `add_data` merge time scales with dataset size, so an unbounded
dataset eventually stops accepting writes.

The cost is dataset count: a 500-endpoint fleet produces on the order of 1,000 datasets a
month. Control it by bucketing rather than per-host — `CONFIG_LOOKUP_SHARD` accepts a
literal label (`wave1`, `emea`) so hosts group into a fixed number of shards — and by
deleting old months with `xdr_data_management.py`.

**Querying is unaffected either way.** Dashboards match `yara_scanner_matches*` wildcards,
so shards fan back in automatically and filtering by `scan_id` or `scan_date` behaves
exactly as it would against one dataset.

> Set `CONFIG_LOOKUP_SHARD = "none"` only for a single scanning endpoint — at fleet scale
> that is the configuration measured at 2/8 delivery. Full detail and the reasoning behind
> both defaults: [Datasets and Maintenance](topics/Datasets_and_Maintenance.md).

## `yara_scanner_matches_v2_<host>_<YYYYMM>` — one row per matched string

`tenant_id`, `scan_id`, `run_id`, `scan_date`, `hostname`, `os_info`, `os_type`,
`ip_address`, `rule`, `filename`, `file_size`, `file_sha256`, `file_creation_time`,
`scan_folder`, `match`, `offset`, `matched_length`, `string`, `severity`,
`event_timestamp_ms`, `date_of_scan`.

## `yara_scanner_scans_v2_<host>_<YYYYMM>` — scan lifecycle

`tenant_id`, `scan_id`, `run_id`, `scan_date`, `hostname`, `os_info`, `os_type`,
`ip_address`, `status` (initiated/running/completed/cancelled/failed), `scan_folder`,
`files_scanned`, `files_skipped`, `detections`, `valid_rules`, `failed_rules`,
`scan_rate_fps`, `elapsed_secs`, `total_paused_secs`, `throttle_mode`, `posture`,
`event_timestamp_ms`, `message`.

## Per-scan summary on the endpoint

Every run also writes a machine-readable `scan_summary_<run_id>.json` under the scanner's
`logs/` dir (outcome, duration, counts, throttle, **alert + dataset delivery stats**, top
rules, and the resolved dataset names) — one file to parse instead of six text logs. Log
retention keeps the last 10 scans (`YARA_LOG_KEEP`).

## Keeping datasets bounded

Rotation bounds each dataset's size, but never deletes anything — old months accumulate.
`xdr_data_management.py` removes them:

```bash
python3 xdr_data_management.py --report                      # inventory (default)
python3 xdr_data_management.py --older-than-months 6 --yes   # drop months older than 6
```

Dry run unless `--yes`. It never deletes the current month, a future-dated month, an
unsuffixed dataset, a newer schema version, or anything outside the `yara_scanner_*` naming
contract. **No scan depends on it having run** — if it never runs, datasets grow but every
scan still succeeds.

**Detail:** [Datasets and Maintenance](topics/Datasets_and_Maintenance.md) — why sharding
and rotation both exist, the report's `frozen` vs *not rotated* distinction, all safety
rails, and schema-change rules.

---

# 12. Dashboard & XQL

Import `dashboards/xdr/YARA Scanner (Lookup).json` (**Dashboards → Import**). It ships **40
widgets** across detections (by OS / scan-folder / file-size / severity / matched-length), fleet
coverage, rule health (valid/failed/skipped), throughput & throttle, single-value KPI tiles, and
alert-channel trends. Widgets build on the sharded lookup datasets via the `*` wildcard (plus the
reliable `alerts` dataset); individual queries are in `widgets/xdr/*.xql`, each validated
live against the tenant.

Lookup rows carry no `_time`, so time-filtering uses `event_timestamp_ms`. The `*` wildcard
fans every per-endpoint shard (and schema version) into one fleet-wide result.

**Top rules by hits:**

```sql
dataset = yara_scanner_matches* | comp sum(match_count) as hits by rule | sort desc hits | limit 15
```

**Latest state per scan:**

```sql
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id
| comp count() as scans by status
```

**Recent matches for a host (tenant_id present):**

```sql
dataset = yara_scanner_matches* | filter hostname = "<host>"
| sort desc event_timestamp_ms
| fields tenant_id, rule, filename, string, severity, scan_id | limit 20
```

**Cancelled scans audit:**

```sql
dataset = yara_scanner_scans* | filter status = "cancelled"
| sort desc event_timestamp_ms
| fields hostname, scan_id, files_scanned, detections, message | limit 50
```

---

# 13. Troubleshooting

Symptom, cause and fix for delivery failures, empty scans, rejected parameters,
cancellation and dataset problems: **[Troubleshooting](Troubleshooting.md)**.

Start with `scan_summary_<run_id>.json` on the endpoint — it carries the scanner version,
the outcome, every delivery counter, and the CPU governor result in one file.

---

*Repository: `github.com/ayman-m/yarascanner`. This guide uses generic placeholders
(`<tenant>`, `<region>`, `<api-key>`, `<host>`) — substitute your own tenant values
locally and keep credentials out of shared version control.*
