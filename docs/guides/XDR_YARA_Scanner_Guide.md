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
| Alerts | **Insert Parsed Alerts** (`/public_api/v1/alerts/insert_parsed_alerts`) | One alert per **finding** (`rule + file`, offset-free identity; hit count + sample inside) → feeds XDR incident creation. Storm-capped at `CONFIG_ALERT_MAX_PER_SCAN` (default 500) with one rollup alert per rule beyond it |
| Match records | **Lookup dataset** `yara_scanner_matches_v2_<host>_<YYYYMM>` (`/xql/lookups/add_data`) | One row per matched string; per-endpoint shard, **monthly-rotated** (bounds `add_data` merge time, which grows with dataset size), queried via `yara_scanner_matches*` |
| Scan lifecycle | **Lookup dataset** `yara_scanner_scans_v2_<host>_<YYYYMM>` | initiated / running / completed / cancelled / failed rows |

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
| `CONFIG_ALERT_MAX_PER_SCAN` | int | `500` | Max per-finding alerts per scan; beyond → one rollup per rule |
| `CONFIG_LOOKUP_ROTATION` | `monthly`/`none` | `monthly` | Monthly dataset rotation (§11) |
| `CONFIG_OPTIONS` | `key=value,key=value` | `""` | Rarely-needed extra overrides applied every run |

**Retired constants.** `CONFIG_THROTTLE_MODE`, `CONFIG_CPU_HIGH_THRESHOLD`,
`CONFIG_CPU_CRITICAL_THRESHOLD` and `CONFIG_MAX_PAUSE_SECS` no longer exist — see §10 for
why. The equivalent *runtime options* are still accepted and translated, so existing
scripts and scheduled jobs keep running: `throttle_mode=off` → `cpu_guarantee=none`;
`throttle_mode=script` or `os` → `cpu_guarantee=headroom`. Unknown keys still fail loudly.

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

To stop a running scan, run the **`cancel` entry point** as a second Action Center action
against the same endpoints (or use `YARA_Scanner_Canceller.yml`). This writes a flag file
that the running scan polls; the scan **stops scanning within ~5 s**, drains what it has,
writes a terminal `cancelled` row to `yara_scanner_scans`, and returns
`Scan cancelled by operator: …`.

Verified live: a scan stopped after 7,592 files with both workers halting **4.45 s** after
the flag was detected.

> ### Console Cancel vs the `cancel` entry point — they are not equivalent
>
> **Measured on agent 9.2.0.90 (Windows), 2026-08-02.** Cancelling a running *script*
> action from the console **does stop it — by killing the payload process**. Two endpoints
> mid-scan went to status `ABORTED`, both payload PIDs died, and neither wrote a terminal
> `cancelled` row or a scan summary. Their logs stop mid-walk with no cleanup.
>
> Note this contradicts the wording in the Cortex documentation for *agent upgrades*
> (*"once the Status is In Progress… cannot be canceled from the management console"*).
> That statement describes upgrades, **not script executions**, and should not be assumed to
> generalise.
>
> | | Console Cancel | `cancel` entry point |
> |---|---|---|
> | Stops the scan | yes, immediately | yes, within ~5 s |
> | Method | **hard kill** of the payload | cooperative flag |
> | Terminal `cancelled` row | **no** | yes |
> | Scan summary written | **no** | yes |
> | Queued alerts / dataset rows | **discarded** | drained first |
> | Drivable from API / SOAR | **no** | yes |
>
> **Use the `cancel` entry point when you want to stop a scan and keep what it found.**
> Use the console Cancel when you just need it dead immediately and do not care about the
> findings discovered so far.
>
> #### Evidence (action 564, three endpoints, 2026-08-02)
>
> One console Cancel against a three-endpoint scan. `xdr-agent` had already finished; the
> two Windows endpoints were mid-scan.
>
> | | `xdragent2` | `xdragent` | `xdr-agent` |
> |---|---|---|---|
> | action status | `ABORTED` | `ABORTED` | `COMPLETED_SUCCESSFULLY` |
> | payload PID | **dead** | **dead** | exited normally |
> | `cancel.flag` written | no | no | no |
> | `"cancelled by operator"` in log | **no** | **no** | n/a |
> | `CLEANUP AND FINALIZATION` | **no** | **no** | yes |
> | `scan_summary_*.json` | **not written** | **not written** | written |
> | last system-log line | mid-walk, no cleanup | mid-walk, no cleanup | normal completion |
>
> Uploads were still succeeding shortly before termination (`Lookup batch ok (170 rows)`),
> so delivery was healthy — the process was killed mid-flight, not failing.
>
> #### The consequence that matters: orphaned lifecycle rows
>
> A killed scan **never writes a terminal row**, so its lifecycle is stuck permanently:
>
> ```
> xdr-agent   20260802_163940_695801   initiated -> completed   (210,170 files)
> xdragent2   20260802_163943_963902   initiated                 <- stuck forever
> xdragent    20260802_163945_164907   initiated -> running      <- stuck forever
> ```
>
> Any dashboard widget counting "scans in progress" or "initiated vs completed" will show
> console-cancelled scans as **running indefinitely**, long after the process is dead. If
> you judge cancellation by the dashboard rather than the action status, it looks as though
> the cancel did nothing — the process stopped, but the record never closed.
>
> **The scanner cannot fix this.** Signal handlers cannot be installed (scripts run off the
> main thread), and on Windows termination is `TerminateProcess`, which no handler could
> intercept. Writing a terminal row on console cancel is impossible by construction. The
> `cancel` entry point exists precisely because it is the only path that closes the record.
>
> **There is no public API to cancel an action.** The cancel/abort endpoints live under
> `/api/webapp/` — the console's private backend, which needs an interactive MFA session and
> is not supported for automation. The `cancel` entry point is therefore the *only*
> API-drivable way to stop a running scan, which is what makes it usable from SOAR.
>
> **Signals do not work either.** The agent runs scripts on a worker thread, so
> `signal.signal()` raises *"signal only works in main thread of the main interpreter"* on
> both Windows and Linux. A polled flag file is the only cooperative mechanism available.

**Known latency.** The scan stops *scanning* within ~5 s, but the process can take up to
about a minute to *exit*, because the directory walk observes the flag only between
`os.walk` yields — an interval that is unbounded on large trees. No files are scanned in
that window and results are unaffected. The same cause makes `control/running.json` go stale
during long walks, so a `cancel` may report `scanner running: no` while a scan is in fact
running.

---

# 10. Resource Management — the CPU governor

The scanner bounds **its own share of the machine**. It does *not* react to load other
processes create. Answering "will this scan slow my host?" is this section.

## 10.1 Policies

| `CONFIG_CPU_GUARANTEE` | Behaviour |
|---|---|
| `headroom` (default) | **Adaptive.** Target = `100 − CONFIG_CPU_HEADROOM_PCT − (what everyone else is using)`. A quiet machine gets a fast scan; a busy one gets a quiet scanner. |
| `budget` | **Fixed.** Never exceed `CONFIG_CPU_BUDGET_PCT` of the host, whatever else is happening. Predictable, and easy to state in a change request. |
| `none` | No CPU governing. Low process priority still applies. |

**How it acts.** The governor measures the scanner's own CPU as a share of the whole host
(`process_cpu ÷ cpu_count`), compares it to the target, and sleeps each worker *in
proportion to the work it just did*. Proportional sleeping keeps the slowdown factor stable
regardless of file size or machine speed.

**The floor is the anti-stall guarantee.** Under heavy external load the target drops to
`CONFIG_CPU_FLOOR_PCT` and the scan continues slowly — it never stops. No throttle can
create headroom that another process is consuming, so the scanner shrinks to its floor
rather than waiting for room that will not appear.

## 10.2 Why the old `script`/`os`/`off` modes were replaced

The previous design watched **system-wide** CPU and paused while it exceeded a threshold.
Measured on an 8-core Linux endpoint:

- With unrelated load holding ~74% CPU, the scanner **parked 285 s of a 347 s scan** waiting
  for a resume condition (CPU below 70%) that sustained external load never allowed. With a
  longer load it parked **593 s of a 594 s scan** — a 65.9× slowdown.
- It was reacting to load it did not cause.
- Across 2, 4 and 8 cores under saturating load, throttling protected the competing workload
  by **−3% to +1% versus not throttling at all**.
- `os` mode was not a safe substitute: idle priority **starved** on a saturated 8-core host,
  taking 252 s versus 77 s unthrottled.

The governor fixes the stall (65.9× → 2.07×) and can state a number. Be aware what it does
*not* claim: on a host where the scanner only ever uses a small share, throttling of any
kind changes host impact very little. Its real value is that a scan **never stalls** on a
busy machine, and that the promise is measurable after the fact.

## 10.3 Worker count

`CONFIG_WORKERS` defaults to **2. Leave it there unless you have measured otherwise.**
More workers measured *slower* (8-core Linux, 93k files, warm cache):

| Workers | Wall clock |
|---|---|
| **2** | **71 s** |
| 4 | 93 s (+31%) |
| 8 | 101 s (+42%) |

Scanning is disk-bound as well as CPU-bound, so extra concurrent readers cause seek
contention rather than useful overlap. The setting exists so operators with fast NVMe can
raise it *after measuring* — not as a default to tune upward.

## 10.4 Measured behaviour

Linux, 8 cores, `/usr` (93,116 files), 3 rounds:

| Condition | Wall clock | Slept |
|---|---|---|
| idle, `none` | 64 s | 0 s |
| idle, `headroom` | 68 s | 0 s |
| **saturating external load, `headroom`** | **153 s** | 40 s |
| saturating external load, `budget=20%` | 131 s | 0 s |

Governing an idle host costs about **6%**. Under load the scan still completes.

## 10.5 Telemetry

`performance_<run_id>.log` carries one header per run and a `CPU_GOVERNOR` line on
meaningful change or every 30 s:

```
THROTTLE_CONFIG {"cpu_guarantee":"headroom","cpu_headroom_pct":30.0,...,
                 "host_cores":8,"cpu_affinity_count":2,"cpu_priority":"below_normal"}
CPU_GOVERNOR    {"policy":"headroom","target":70.0,"own":8.1,"others":0.0,
                 "ratio":0.0,"slept_secs":0.0,"floor_hits":0,"t":...}
```

`own` is a share of the **whole host** — it should never exceed 100. The scan summary
carries the same figures under `cpu_governor`, which is your after-the-fact evidence that
the promise held.

## 10.6 Windows note

The Cortex agent pins payload processes to **2 CPU cores** regardless of host size
(visible in every scan as `host_cores: 8, cpu_affinity_count: 2`). The scanner therefore
cannot exceed roughly **25% of an 8-core Windows host whatever you configure** — the agent
has already applied coarse containment. The governor stays effectively idle there until
other processes push the target below that ceiling.

---

# 11. Datasets & Schema

## Per-writer sharding (why the names have a suffix)

XDR's `lookups/add_data` is **not concurrency-safe**: two endpoints writing the *same*
lookup dataset at once collide on a server-side clone-table race and lose rows (measured
~2/8 landing at 8-way concurrency, and client-side retries/jitter do not fix it). The
scanner therefore writes **one dataset per endpoint** — no two writers ever touch the same
dataset — which lands **100%** at any fleet scale. Names are:

```
yara_scanner_matches_v2_<host>_<YYYYMM>     yara_scanner_scans_v2_<host>_<YYYYMM>
```

`_v2` is a **schema version** (bumped only when the row shape changes; `add_data` silently
drops rows carrying fields an existing dataset doesn't know, so a new shape needs a new
name). `<host>` is a slugged, hash-suffixed endpoint id. Sharding is configurable via the
`lookup_shard` option / `YARA_LOOKUP_SHARD` env: `endpoint` (default), `none` (one legacy
shared dataset — only safe at ~1 concurrency), or a literal wave/site label.

**Dashboards fan the shards back in with a wildcard** — `dataset = yara_scanner_matches*`
spans every host and schema version at once (XQL supports `*` and `union`).

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

Growth is bounded by the `scan_date` column — prune with targeted `lookups/remove_data` by
`scan_date` as an operational procedure.

## Per-scan summary on the endpoint

Every run also writes a machine-readable `scan_summary_<run_id>.json` under the scanner's
`logs/` dir (outcome, duration, counts, throttle, **alert + dataset delivery stats**, top
rules, and the resolved dataset names) — one file to parse instead of six text logs. Log
retention keeps the last 10 scans (`YARA_LOG_KEEP`).

## Keeping datasets bounded — `xdr_data_management.py`

Rotation bounds each dataset's **size**, which is what keeps `add_data` fast. It does not
delete anything: old months accumulate on the tenant indefinitely. `xdr_data_management.py`
is a small standalone script that removes them.

**It is deliberately not a prerequisite for anything.** The scanner creates its own datasets
and writes to them self-sufficiently. If this script never runs, datasets get large and
eventually slow, but **every scan still succeeds**. Cleanup is optional work; creation is
not, and coupling them would mean a scan could fail because a different script had not run.

Run it from a workstation with the same credentials as the toolkit:

```bash
python3 xdr_data_management.py --report                      # inventory (default action)
python3 xdr_data_management.py --older-than-months 6 --yes   # drop months older than 6
python3 xdr_data_management.py --delete-legacy --yes         # drop pre-v2 schema datasets
```

`--report` lists every YARA dataset with kind, host and age in months, and flags two
conditions worth knowing about:

- **`frozen`** — an unsuffixed dataset that has rotated siblings. It predates rotation, is
  no longer written to, and is not deleted by this tool: an unsuffixed dataset holds *all*
  pre-rotation history for that host, so removing one is a bigger decision than dropping a
  month.
- **not rotated** — an unsuffixed dataset with *no* rotated siblings, i.e. the deployment is
  running `CONFIG_LOOKUP_ROTATION="none"` and that dataset really will grow without bound.
  The report names the exact config change.

### Safety rails

Nothing is deleted if it is the **current month** (a scan may be writing to it), a
**future-dated month** (clock skew), **unsuffixed**, on a **newer schema version** than this
host understands, or **outside the `yara_scanner_*` naming contract**. On top of that it is
a **dry run unless `--yes`**, and `--older-than-months` has no default — so a bare `--yes`
deletes nothing.

> Deleting a dataset a scan is actively writing to does not error the scan: the scanner
> keeps POSTing rows to a name that no longer exists and gets HTTP 400 per batch. Across a
> fleet mid-scan that is silent, partial data loss discovered days later as a dashboard gap.
> Hence the current-month guard.

A failed delete is reported and the run continues to the next dataset, so one dataset with
dependencies cannot strand the whole cleanup. Exit code is non-zero if any deletion failed.

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
