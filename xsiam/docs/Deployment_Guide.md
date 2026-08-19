% YARA Scanner for Cortex XSIAM — Deployment Guide
% Cortex XSIAM edition (`xsiam_yara_scanner.py`)
% Version 4.4.0 · Released 2026-08-17

---

# 1. Overview

This guide explains how to deploy `xsiam_yara_scanner.py` as a managed response
script in **Cortex XSIAM Action Center** and stream its results into XSIAM via an
**HTTP Log Collector** for hunting, dashboards, and alerting.

The scanner is a multi-threaded, throttled YARA engine designed to run safely on
production endpoints. While scanning, it streams categorized telemetry over HTTPS to
your tenant:

| Type | Purpose |
|------|---------|
| `yara_match` | One record per **(rule, file) finding** — not per hit. `match_count` carries the true, uncapped hit total; `offsets`/`strings` carry a sample of up to 50, with `truncated` set when there were more. Aggregate with `sum(to_integer(match_count))`, never `count()`. |
| `performance` | Per-worker throughput (files processed, avg time, error rate) |
| `statistics` | Periodic scan progress (queue size, scan rate, system metrics) |
| `statistics_summary` | Phase boundaries (initialization, completion) with system info |
| `system_resource_snapshot` | Process/system CPU, memory, disk, network, trends |
| `scanner_initialization` | One-shot startup record |
| `scan_completion_summary` | One-shot completion / failure record |

Each record is ingested into the `yara_scans_raw` dataset, parsed, and surfaced in the
prebuilt dashboards.

> **XDR vs. XSIAM:** this repository ships two editions. `xsiam_yara_scanner.py` (this
> guide) streams full telemetry to a **generic HTTP Log Collector / webhook**.
> `xdr_yara_scanner.py` uses the Cortex XDR **Insert Parsed Alerts API** plus **lookup
> datasets**, and is covered by the [XDR Deployment Guide](../../xdr/docs/Deployment_Guide.md).

---

# 2. Script Design & Capabilities

## 2.1 Design philosophy

1. **Do no harm to production hosts.** Scanning runs with throttled CPU, bounded
   memory, and graceful back-off whenever the host gets busy. The "light" profile is
   the runtime expression of this priority.
2. **Lose nothing.** Every YARA hit is written both to disk (forensic evidence) and
   streamed to XSIAM. If the network drops or the collector returns 5xx, an in-memory
   queue + circuit breaker absorb the failure without dropping events.
3. **Operate in the background.** No interactive prompts, no required environment
   configuration. A few positional arguments and the script is ready for unattended
   execution across hundreds of endpoints in parallel.

## 2.2 Internal architecture

The runtime is a producer/consumer pipeline of single-responsibility classes connected
by bounded queues — file walkers feed scan workers, scan workers feed an upload thread.

| Component | Responsibility |
|-----------|----------------|
| `ScanConfig` | Single source of truth for rules, paths, thresholds, env-var tuning |
| `YaraScanner` | Orchestrator — builds the work queue, spawns workers, drives the scan loop |
| `FileHasher` | SHA256 for each matched file — identifies it in `file_mapping.txt` and collapses duplicate content to one blob in the evidence ZIP |
| `LogManager` | Rotating local log files, one per category (scanner_*, errors_*, stats_*) |
| `WebhookUploader` / `ResultsUploader` | Background upload threads with retry + backoff + circuit breaker |
| `StatisticsManager` / `SystemResourceMonitor` | Periodic progress and resource telemetry |

## 2.3 Capability matrix

| Capability | Notes |
|------------|-------|
| Multi-threaded scanning | Producer/consumer with a bounded work queue |
| Real-time streaming | Matches and telemetry POSTed to the collector as they occur |
| Resilient delivery | Exponential backoff, timeout protection, circuit breaker, local JSON backups |
| Evidence collection | `file_mapping.txt` (every matched path + SHA256) and the per-rule alert texts packaged into an evidence ZIP. Matched **file copies** are excluded by default since v4.2.0 — see `YARA_COLLECT_MATCHED_FILES` in §14 |
| Graceful shutdown | Workers drain, in-flight uploads finish, evidence ZIP still produced |
| Cross-platform | Single script — Windows, Linux, macOS; adapts paths and cleanup per OS |
| Privilege-aware | Detects root / SYSTEM; warns on macOS without Full Disk Access |

## 2.4 Light profile

This is the **light** variant, tuned for live production hosts:

| Aspect | Light profile |
|--------|---------------|
| Worker count | Capped at **2** regardless of `YARA_THREADS` |
| CPU throttling | **Always on** — fixed-sleep design (see note below) |
| Performance / resource / FD monitors | **Off** by default — opt in with the `YARA_ENABLE_*` env vars |
| Process priority | **Lowered** at startup (Below-Normal / nice) |

> ### CPU throttling in this edition
>
> The XSIAM edition applies a **bounded sleep** when system CPU is above its high or
> critical threshold, so a scan slows down on a busy host rather than stopping. Thresholds
> and the maximum pause are configurable via the `YARA_LIGHT_*` environment variables in §14.
>
> Because it reacts to **system-wide** CPU, it also yields to load it did not itself cause.
> The sleep is bounded, so the effect is a slower scan, never a stalled one.

**Use the light profile** when scanning live production servers, user workstations
during business hours, or any environment where the host must stay responsive.

## 2.5 Output artifacts

After a run, results live in three places:

| Where | What | Retention |
|-------|------|-----------|
| XSIAM dataset `yara_scans_raw` | Streamed JSON events (matches, statistics, performance, snapshots, summaries) | XSIAM standard dataset retention |
| Endpoint working directory | `logs/scanner_*.log`, `errors_*`, `statistics_*`, `failed_rules/`, `alert/<rule>.txt`, evidence ZIP | Until the cleanup task runs, then `*.alert` |
| Action Center action result | One-line summary string returned by `main()` (file/rule/match counts) | Action Center default |

---

# 3. How the Pipeline Works

Three things must line up exactly, or ingestion silently routes to the wrong dataset
and dashboards go blank:

| What | Where | Required value |
|------|-------|----------------|
| Vendor | HTTP Collector config | `yara` |
| Product | HTTP Collector config | `scans` |
| Target dataset | Parsing rule `[INGEST: target_dataset=]` | `yara_scans_raw` |

---

# 4. Prerequisites

| Item | Value / Notes |
|------|---------------|
| XSIAM role | A user with **Instance Administrator** privileges (to create HTTP collectors and upload scripts) |
| Cortex Agent | Installed and connected on each target endpoint |
| Endpoint OS | Windows, Linux, or macOS |
| Python | The Cortex Agent ships an embedded Python runtime — no separate install needed |
| Python packages | `yara-python`, `psutil`, `requests` (declared on the script; the Action Center installs them) |
| Privileges | Run as **root / SYSTEM** for full coverage; otherwise system paths are partially skipped |
| Disk space | ~200 MB on the endpoint for the working directory and evidence ZIP |
| Network | Outbound HTTPS to your XSIAM collector URL (the script auto-retries with backoff) |

---

# 5. Step 1 — Create the HTTP Log Collector

The HTTP Log Collector receives the scanner's JSON events.

1. In XSIAM: **Settings → Configurations → Data Collection → Custom Collectors**.
2. **+ Add Instance** for **HTTP Log Collector**.
3. Fill in the form:

| Field | Value |
|-------|-------|
| Name | `YARA Scanner Collector` |
| Compression | `uncompressed` |
| Log Format | **JSON** |
| Vendor | `yara` |
| Product | `scans` |

> XSIAM auto-creates the dataset `yara_scans_raw` (`<vendor>_<product>_raw`).

4. **Save & Generate Token** — the token is shown **only once**; copy it and store it
   in a vault.
5. Hover the new collector row → **Copy URL**. It has the form:

```
https://api-<tenant>.xdr.<region>.paloaltonetworks.com/logs/v1/event
```

Save the **URL** and the **token** for Step 3.

---

# 6. Step 2 — Add the Parsing Rule

The parsing rule extracts JSON fields from the `data` object so they become first-class
XQL columns.

1. **Settings → Configurations → Data Management → Parsing Rules → New Rule**.
2. Name it `yara_scans_raw_parsing_rule`.
3. Paste the full rule body from [`parsing_rule.xql`](../parsing_rules/parsing_rule.xql) in this repo. The header reads:

```text
[INGEST:vendor="yara", product="scans", target_dataset="yara_scans_raw", no_hit = keep]
```

- `vendor` and `product` must match the HTTP Collector exactly.
- `target_dataset` must be `yara_scans_raw`.
- `no_hit = keep` ensures records matching no filter still land in the dataset.
- The rest of the file extracts every field the shipped dashboards filter or aggregate on as a
  bare column (`rule_id`, `active_workers`, `sys_cpu_percent`, `worker_id`, etc.) out of the raw
  `data` JSON object. Without it, matching rows still land in `yara_scans_raw` — `hostname`,
  `type`, `message`, and the platform's own collector metadata populate correctly — but every
  dashboard widget that filters on one of those extracted fields (which is most of them) shows
  **"Could not Visualize"**, indistinguishable at a glance from a scanner bug.

4. **Validate**, then **Save**.

---

# 7. Step 3 — Configure the Script with Your Tenant Token

The script ships with placeholder credentials. **Replace them** with your Step 1 values.
Open `xsiam_yara_scanner.py` and set, near the top of the file:

```python
DEFAULT_API_KEY      = "<paste-your-collector-token>"
DEFAULT_API_ENDPOINT = "https://api-<tenant>.xdr.<region>.paloaltonetworks.com/logs/v1/event"
```

> **Security note:** the edited `.py` now contains a tenant token — treat it as a secret.
> Do not commit it to shared version control; rotate the token if the file leaves a
> controlled location.

---

# 8. Step 4 — Upload the Script to the Action Center

1. **Action Center → Action Configurations Center → Scripts** *(older menus: Endpoints
   → Scripts Library)*.
2. **New → Upload Script** and select your saved `xsiam_yara_scanner.py`.
3. Metadata:

| Field | Value |
|-------|-------|
| Script Name | `YARA Scanner — XSIAM` |
| Description | Multi-threaded YARA scan with real-time XSIAM ingestion (light profile). |
| Supported OS | **Windows, Linux, macOS** (select all three) |
| Timeout (seconds) | `21600` (6 h — adjust to your largest expected scan window) |
| Entry Point | `main` |
| Run as | Administrator / root |

4. **Input parameters** (map to `main(yarafile, scan_folder, alert_severity)`):

| Order | Name | Type | Required | Description |
|-------|------|------|----------|-------------|
| 1 | `yarafile` | String | Yes | Base64-encoded YARA rule(s) — see Step 5 |
| 2 | `scan_folder` | String | No | Path to scan, a comma-separated list of paths (multi-location scan; invalid entries skipped with a warning), or `default` for full-system scan |
| 3 | `alert_severity` | String | No | `low` \| `medium` \| `high` (default `low`) |

5. **Output**: `String`. (Optional) declare Python packages `yara-python`, `psutil`,
   `requests`. **Save** — status becomes **Available**.

---

# 9. Step 5 — Prepare Your YARA Rules (Base64)

The first argument must be base64-encoded (the decoder refuses raw text).

```bash
# macOS / Linux
base64 -w0 my_rules.yar > my_rules.b64          # (no -w on macOS: base64 -i my_rules.yar -o my_rules.b64)
# Repo helper (any OS)
python3 encode_rules.py my_rules.yar -o my_rules.b64
# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("my_rules.yar")) > my_rules.b64
```

The base64 string is what you paste into the `yarafile` field. It may be prefixed with
`b64:` (the decoder strips it). **Size limit:** inputs over 50 MB are rejected — split
large rule packs across runs.

---

# 10. Step 6 — Run the Script on Endpoints

## 10.1 Ad-hoc run from the UI

1. **Action Center → Scripts** → select **YARA Scanner — XSIAM** → **Run**.
2. **Target endpoints** by hostname, IP, group, or saved filter.
3. **Inputs:** paste the base64 into `yarafile`, set `scan_folder` (e.g. `C:\Users`,
   `/home`, or `default`), `alert_severity`.
4. **Run**, and track under **Action Center → All Actions**.

## 10.2 From a correlation rule / playbook

In a correlation rule's **Action** tab, choose **Run Script** → **YARA Scanner — XSIAM**
to fire scans automatically on hosts that produced a high-severity alert.

## 10.3 Programmatic (API)

```bash
curl -sS -X POST \
  "https://api-<tenant>.xdr.<region>.paloaltonetworks.com/public_api/v1/scripts/run_script/" \
  -H "Authorization: <api-key>" -H "x-xdr-auth-id: <key-id>" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {"script_uid": "<script-uid>", "timeout": 21600,
        "filters": [{"field": "endpoint_id_list", "operator": "in", "value": ["<endpoint-id>"]}],
        "parameters_values": {"yarafile": "<base64-rules>", "scan_folder": "default", "alert_severity": "low"}}}'
```

The response includes `action_id`; poll `/public_api/v1/actions/get_action_status/`.

> If your tenant issues **Advanced** API keys, this call requires HMAC signing. Send
> `x-xdr-nonce` (a random string), `x-xdr-timestamp` (epoch milliseconds) and
> `Authorization = sha256(api_key + nonce + timestamp)`, plus `x-xdr-auth-id` with your key
> id. **Standard** keys instead send the key directly as `Authorization`.

## 10.4 What the script does on the endpoint

1. Creates the working directory (`C:\yara_scanner`, `/opt/yara_scanner`, or
   `/usr/local/yara_scanner`).
2. Decodes + compiles your rules; logs `scanner_initialization`.
3. Walks the target tree (skipping VMs/disk images, caches, and Cortex agent paths).
4. Two worker threads scan files; throttles when CPU is high.
5. Each match → `yara_match` POST; periodic `performance` / `statistics` events.
6. On finish: `scan_completion_summary` + evidence ZIP.
7. Schedules a cleanup task to flip `*.txt` alert artifacts to `*.alert`.

---

# 11. Step 7 — Validate Ingestion with XQL

Open **Investigator → Query Builder → XQL**.

**Any data at all?**

```sql
dataset = yara_scans_raw | sort desc _time | limit 50
```

**Confirm the parsing rule fired** (fields should be populated, not null):

```sql
dataset = yara_scans_raw
| filter type = "yara_match"
| fields _time, hostname, ipAddress, rule_id, file_name, string, offset
| sort desc _time | limit 100
```

**Completion summaries:**

```sql
dataset = yara_scans_raw
| filter type = "scan_completion_summary"
| fields _time, hostname, message, level | sort desc _time | limit 20
```

---

# 12. Step 8 — Import the Dashboards

| File | Dashboard | Shows |
|------|-----------|-------|
| `dashboards/xsiam/YARA Matches.json` | **Yara Matches** | Match counts, severity trend, top rules, top hosts, files |
| `dashboards/xsiam/YARA Scan Performance.json` | **Yara Scan Performance** | Initiated/completed scans, throughput, CPU/memory, errors |

1. **Dashboards & Reports → Dashboards Manager**.
2. **⋮ menu → Import Dashboard** → select the JSON → **Import**. Repeat for the second.
3. Open each — widgets self-populate from `dataset = yara_scans_raw`.

Individual widget queries are in `widgets/xsiam/*.xql` if you prefer to build custom
dashboards.

## 12.1 The CPU / memory widgets need at least one **finished** scan

> **Expect these four widgets to be blank while a scan is still running — that is correct
> behaviour, not a broken dashboard or a missing parsing rule.**
>
> - Yara - Average System CPU Utilization
> - Yara - Average Process CPU Utilization
> - Yara - Average System Memory Utilization
> - Yara - Average Memory Allocation

Each of these averages resource samples taken *inside a completed scan window*. They pair a
start marker (`Worker thread startup completed`) with the matching completion marker
(`Target scan completed:`) per host, and then average only the `system_resource_snapshot`
rows that fall between the two. A scan that has started but not finished has no end marker
yet, so it contributes nothing and the widget renders **"Could not Visualize"**.

Practical consequences:

- On a first deployment, these stay blank until the **first endpoint finishes** — on a full
  `C:\` scan that can be tens of minutes to hours.
- With a long-running scan in flight, they show only *previously completed* runs, so the
  numbers can look stale while a scan is clearly active.
- If they are blank and no scan has ever completed on any endpoint, that is expected. Verify
  with:
  ```
  dataset = yara_scans_raw | filter message contains "Target scan completed:" | comp count() as finished_scans by hostname
  ```
  Zero rows means nothing has finished yet — wait, or scan a small folder first to get one
  completed window on the board.

They also require resource sampling to be switched on (see §7): with
`ENABLE_RESOURCE_MONITOR = False` no `system_resource_snapshot` rows are produced at all, and
these four widgets stay blank no matter how many scans complete.

The remaining widgets (matches, throughput, worker stats, scan counts) do **not** wait for a
completed scan and populate while a scan is in progress.

---

# 13. XQL Recipe Library

**Top 10 hosts by matches (24 h):**

```sql
dataset = yara_scans_raw | filter type = "yara_match"
| alter hits = to_integer(match_count)
| comp sum(hits) as hits by hostname | sort desc hits | limit 10
```

**Top rules across the fleet:**

```sql
dataset = yara_scans_raw | filter type = "yara_match"
| alter mc = to_integer(match_count)
| comp sum(mc) as hits, count_distinct(hostname) as hosts by rule_id
| sort desc hits | limit 25
```

**Files matched by a specific rule:**

```sql
dataset = yara_scans_raw
| filter type = "yara_match" and rule_id = "Suspicious_Mimikatz_Strings"
| fields _time, hostname, file_name, offset, string | sort desc _time
```

**Hosts that started but never completed a scan (24 h):**

```sql
dataset = yara_scans_raw
| filter type in ("scanner_initialization", "scan_completion_summary")
| comp count_distinct(type) as type_count, values(type) as types by hostname, scan_id
| filter type_count = 1 and types contains "scanner_initialization"
| fields hostname, scan_id, types
```

**Convert matches into alerts (correlation rule, severity = High):**

```sql
dataset = yara_scans_raw | filter type = "yara_match"
| alter alert_name = concat("YARA: ", rule_id),
        alert_description = concat("Match in ", file_name, " at offset ", offset)
| fields _time, hostname, ipAddress, rule_id, file_name, string, offset, alert_name, alert_description
```

---

# 14. Operations & Tuning

These are read from the endpoint's environment. The Action Center execution form only
carries the script's three declared inputs (rules, scan folder, severity) — it cannot set
arbitrary variables — so set these on the endpoint beforehand, or edit the matching
constant at the top of the script before uploading it, which is the usual route.

An invalid value never kills a scan: a non-numeric or out-of-range setting is ignored with
a warning and the documented default is used instead.

| Variable | Default | Purpose |
|----------|---------|---------|
| `YARA_COLLECT_MATCHED_FILES` | false | Copy every matched file into the evidence ZIP. **Off since v4.2.0** — it wrote 2.8 GB to a scanned host in testing. With it off the ZIP still carries `file_mapping.txt` (every path + SHA256) and the per-rule alert texts, so matched files stay identifiable and fetchable on demand. |
| `YARA_MAX_ALERT_OFFSETS` | 50 | Offsets rendered per finding in `alert/<rule>.txt`. **New in v4.3.0.** The per-string-ID hit census above them is never capped, so which string fired and how often survives in full; only the individual offsets are sampled. `0` disables the cap. |
| `YARA_MAX_MB` | 64 | Skip files larger than N MB |
| `YARA_THREADS` | 2 | Worker count (capped at 2 by the light profile) |
| `YARA_QUEUE_SIZE` | 4 | Internal scan queue depth |
| `YARA_PROGRESS_LOG_SECS` | 30 | Seconds between `statistics` progress events. Clamped to a 1s minimum — setting `0` does **not** disable progress logging; use a large value instead. |
| `YARA_ENABLE_PERF_MONITOR` | false | Enable per-worker `performance` events |
| `YARA_ENABLE_RESOURCE_MONITOR` | false | Enable `system_resource_snapshot` events |
| `YARA_ENABLE_FD_MONITOR` | false | Watch file-descriptor count (Linux/macOS) |
| `YARA_LIGHT_HIGH_CPU` | 80 | CPU % threshold to start throttling |
| `YARA_LIGHT_CRITICAL_CPU` | 90 | CPU % threshold for aggressive throttling |
| `YARA_SCANNER_DIR` | OS-dependent | Override the working directory |

---

# 15. Troubleshooting

Symptom, cause and fix: **[Troubleshooting](Troubleshooting.md)**.

---

*Repository: `github.com/ayman-m/yarascanner`. This guide uses generic placeholders
(`<tenant>`, `<region>`, `<token>`) — substitute your own tenant values locally and keep
tokens out of shared version control.*
