% YARA Scanner for Cortex XDR — Deployment Guide
% Cortex XDR edition (`xdr_yara_scanner.py`, v2)
% Version 2.0 · 2026-07-10

---

# 1. Overview

This guide explains how to deploy `xdr_yara_scanner.py` as a managed response script in
**Cortex XDR Action Center** and land its results in XDR as **alerts** and **lookup
datasets** for hunting, dashboards, and incident response.

Unlike the XSIAM edition (which streams telemetry to a generic HTTP collector), the XDR
edition uses the **Cortex XDR public API** directly:

| Channel | XDR API | Result |
|---------|---------|--------|
| Alerts | **Insert Parsed Alerts** (`/public_api/v1/alerts/insert_parsed_alerts`) | One alert per distinct finding (`rule + file@offset`) → feeds XDR incident creation |
| Match records | **Lookup dataset** `yara_scanner_matches_v2_<host>` (`/xql/lookups/add_data`) | One row per matched string; per-endpoint shard, queried via `yara_scanner_matches*` |
| Scan lifecycle | **Lookup dataset** `yara_scanner_scans_v2_<host>` | initiated / running / completed / cancelled / failed rows |

Every row and alert is tagged with a **`tenant_id`** derived from your API URL, so the
data is safe to consolidate across tenants.

> **v2 highlights:** Advanced (HMAC) authentication with auto-detection, per-channel
> output flags, configurable CPU throttling with an OS-managed mode, cooperative scan
> cancellation, fixed-name lookup datasets, a dedicated dashboard, and automation
> playbooks.

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
| `ResultsUploader` | Insert Parsed Alerts channel (per matched string) |
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
| Endpoint OS | Windows, Linux, or macOS (the agent ships an embedded Python 3.x with `yara`, `psutil`, `requests`) |
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
| 2 | `scan_folder` | Target path, or `default` |
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
| `CONFIG_THROTTLE_MODE` | `script`/`os`/`off` | `script` | CPU pacing strategy (§10) |
| `CONFIG_CPU_HIGH_THRESHOLD` | int or `None` | `None` | Pause-entry % CPU (`None` = profile default) |
| `CONFIG_CPU_CRITICAL_THRESHOLD` | int or `None` | `None` | Critical % CPU (`None` = profile default) |
| `CONFIG_MAX_PAUSE_SECS` | int or `None` | `None` | Cap on one continuous CPU pause |
| `CONFIG_TENANT_ID` | string | `""` | Tenant tag (`""` = derive from API URL) |
| `CONFIG_LOOKUP_SHARD` | `endpoint`/`none`/`<label>` | `endpoint` | Dataset sharding (§11) |
| `CONFIG_OPTIONS` | `key=value,key=value` | `""` | Rarely-needed extra overrides applied every run |

> Advanced / automation only: the internal `run(...)` API and the CLI still accept a per-run
> `options` string that overrides any constant above — but the Action Center `main` entry point
> deliberately does **not** expose it, so operators aren't faced with a long input list.

---

# 8. Step 4 — Run the Script on Endpoints

## 8.1 Ad-hoc run from the UI

**Action Center → Scripts** → select the script → **Run** → pick target endpoints →
supply inputs (`yarafile` = your base64, `scan_folder`, `alert_severity`, `mode=scan`,
`options`). Track under **Action Center → All Actions**.

## 8.2 Programmatic (API)

```bash
# core of the playbook flow — run a library script with parameters
POST /public_api/v1/scripts/run_script/
{"request_data": {"script_uid": "<uid-from-get_scripts>", "timeout": 3600,
  "filters": [{"field": "endpoint_id_list", "operator": "in", "value": ["<endpoint-id>"]}],
  "parameters_values": {"yarafile": "<b64>", "scan_folder": "default",
                        "alert_severity": "low", "mode": "scan", "options": ""}}}
```

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

To stop a running scan, run the same script with `mode=cancel` on the same endpoints
(or use `YARA_Scanner_Canceller.yml`). This drops a cancel flag that the running scan's
watcher detects within ~5 s; the scan drains gracefully, writes a terminal `cancelled`
row to `yara_scanner_scans`, and returns `Scan cancelled by operator: …`. POSIX
`SIGTERM`/`SIGINT` route into the same path.

---

# 10. Resource Management

The scanner never wants to compete with real workload. Three modes, via `throttle_mode`:

| Mode | Behavior |
|------|----------|
| `script` (default) | Worker **pauses while system CPU is above `cpu_high_threshold`**, re-checks each interval, and resumes only once CPU drops below `high − 10` (hysteresis). Bounded by `max_pause_secs`; wall-clock pause time is reported per scan. |
| `os` | Script sleeps disabled; the process drops to **idle-tier priority** (Windows IDLE/background; Linux `nice 19` + `ionice idle`; macOS `nice 19`) and the OS scheduler arbitrates. |
| `off` | No throttling — for dedicated maintenance windows. |

---

# 11. Datasets & Schema

## Per-writer sharding (why the names have a suffix)

XDR's `lookups/add_data` is **not concurrency-safe**: two endpoints writing the *same*
lookup dataset at once collide on a server-side clone-table race and lose rows (measured
~2/8 landing at 8-way concurrency, and client-side retries/jitter do not fix it). The
scanner therefore writes **one dataset per endpoint** — no two writers ever touch the same
dataset — which lands **100%** at any fleet scale. Names are:

```
yara_scanner_matches_v2_<host>     yara_scanner_scans_v2_<host>
```

`_v2` is a **schema version** (bumped only when the row shape changes; `add_data` silently
drops rows carrying fields an existing dataset doesn't know, so a new shape needs a new
name). `<host>` is a slugged, hash-suffixed endpoint id. Sharding is configurable via the
`lookup_shard` option / `YARA_LOOKUP_SHARD` env: `endpoint` (default), `none` (one legacy
shared dataset — only safe at ~1 concurrency), or a literal wave/site label.

**Dashboards fan the shards back in with a wildcard** — `dataset = yara_scanner_matches*`
spans every host and schema version at once (XQL supports `*` and `union`).

## `yara_scanner_matches_v2_<host>` — one row per matched string

`tenant_id`, `scan_id`, `run_id`, `scan_date`, `hostname`, `os_info`, `os_type`,
`ip_address`, `rule`, `filename`, `file_size`, `file_sha256`, `file_creation_time`,
`scan_folder`, `match`, `offset`, `matched_length`, `string`, `severity`,
`event_timestamp_ms`, `date_of_scan`.

## `yara_scanner_scans_v2_<host>` — scan lifecycle

`tenant_id`, `scan_id`, `run_id`, `scan_date`, `hostname`, `os_info`, `os_type`,
`ip_address`, `status` (initiated/running/completed/cancelled/failed), `scan_folder`,
`files_scanned`, `files_skipped`, `detections`, `valid_rules`, `failed_rules`,
`scan_rate_fps`, `elapsed_secs`, `total_paused_secs`, `throttle_mode`, `posture`,
`event_timestamp_ms`, `message`.

Growth is bounded by the `scan_date` column — prune with targeted `lookups/remove_data` by
`scan_date` as an operational procedure.

## Per-scan summary on the endpoint

Every run also writes a machine-readable `scan_summary_<run_id>.json` under the scanner's
`logs/` dir (outcome, duration, counts, throttle, **alert + dataset delivery stats**, top
rules, and the resolved dataset names) — one file to parse instead of six text logs. Log
retention keeps the last 10 scans (`YARA_LOG_KEEP`).

---

# 12. Dashboard & XQL

Import `dashboards/Yara XDR Scanner (Lookup).json` (**Dashboards → Import**). It ships **40
widgets** across detections (by OS / scan-folder / file-size / severity / matched-length), fleet
coverage, rule health (valid/failed/skipped), throughput & throttle, single-value KPI tiles, and
alert-channel trends. Widgets build on the sharded lookup datasets via the `*` wildcard (plus the
reliable `alerts` dataset); individual queries are in `widgets/xdr_lookup/*.xql`, each validated
live against the tenant.

Lookup rows carry no `_time`, so time-filtering uses `event_timestamp_ms`. The `*` wildcard
fans every per-endpoint shard (and schema version) into one fleet-wide result.

**Top rules by hits:**

```sql
dataset = yara_scanner_matches* | comp count() as hits by rule | sort desc hits | limit 15
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

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No alerts and no dataset rows | Standard-only auth against an **Advanced** key (HTTP 401) | Ensure v2; leave `XDR_AUTH_TYPE=auto` (or force `advanced`). Verify creds in Step 1. |
| `Dataset not found` on `add_data` | Dataset not created yet | The scanner creates both datasets on start; check the upload log for the create call and API permissions. |
| `parameters_values contain invalid/missing parameters` | Library script inputs don't match the entry point | With Entry Point `main`, pass only the 3 inputs in §7 (`yarafile, scan_folder, alert_severity`); with Entry Point `cancel`, pass none. |
| Playbook can't find the script | `script_name` mismatch | Set the playbook's `script_name` input to the exact library script name. |
| `Scan failed: N rules failed compilation` | Bad YARA syntax | Inspect `failed_rules/` on the endpoint; valid rules still ran. |
| Scan won't stop | — | Run `mode=cancel` (or the Canceller playbook) on the same targets; watch for the terminal `cancelled` row. |
| `tenant_id` shows `unknown` | Non-standard API URL | Pass `tenant_id=<slug>` in `options`. |

---

*Repository: `github.com/ayman-m/yarascanner`. This guide uses generic placeholders
(`<tenant>`, `<region>`, `<api-key>`, `<host>`) — substitute your own tenant values
locally and keep credentials out of shared version control.*
