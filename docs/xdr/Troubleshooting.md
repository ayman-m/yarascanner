# Troubleshooting — XDR YARA Scanner

Applies to scanner **v2.0.0**. Companion to the XDR YARA Scanner Guide.

Before anything else, confirm which build the endpoint ran: `scanner_version` in
`scan_summary_<run_id>.json`, or the `VERSION` line at the top of
`yara_processing_<run_id>.log`. Behaviour differs between releases.

---

## Where to look first

Every scan writes to the scanner's `logs/` directory on the endpoint. In order of
usefulness:

| File | Tells you |
|---|---|
| `scan_summary_<run_id>.json` | Outcome, counts, delivery stats, CPU governor result — one file instead of six |
| `scan_errors_<run_id>.log` | Everything that went wrong |
| `uploads_<run_id>.log` | Per-batch alert and dataset delivery |
| `yara_processing_<run_id>.log` | Version, rule compilation, skipped rules |
| `performance_<run_id>.log` | CPU governor behaviour over time |

## The scan ran but nothing appeared in XDR

| Symptom | Likely cause | Fix |
|---|---|---|
| No alerts **and** no dataset rows | Standard-only auth against an **Advanced** key (HTTP 401) | Leave `XDR_AUTH_TYPE=auto`, or force `advanced`. Re-check the credentials from Step 1 of the guide. |
| `SCAN ABORTED — credentials are not set` | `DEFAULT_XDR_API_*` still hold `replace_with_*` placeholders | Edit the three lines at the top of the script and re-upload. The scan aborts deliberately rather than scanning and discarding every finding. |
| `delivery_shortfall` is non-empty in the summary | Some or all findings never reached XDR | Read the message — it names the channel and the count. The findings are complete in the local logs on the endpoint. Check the API key's permissions and network path, then re-run. |
| `Dataset not found` on `add_data` | Dataset not created yet | The scanner creates both datasets at start; check `uploads_*.log` for the create call and confirm the key has the **Data Management** permission. |
| Rows land for some hosts but not others | Two writers on one dataset | Only happens with `CONFIG_LOOKUP_SHARD = "none"` at fleet scale. Use `endpoint` (default) or a bucket label. |

## The scan found nothing

| Symptom | Likely cause | Fix |
|---|---|---|
| `0 files scanned`, with a skip-path warning in the log | The target sits under a platform skip-list (`/tmp`, `/proc`, `/private/tmp`, and similar) | Scan a path outside the exclusion. The warning names both the folder and the rule that caught it. |
| Far fewer matches than expected | Rules were skipped, not run | Check `skipped_rules_count` in the summary. Rules importing an unavailable module are skipped, not fatal — see [Rule Compatibility](topics/Rule_Compatibility.md). |
| `Scan failed: N rules failed compilation` | YARA syntax errors | Inspect `failed_rules/` on the endpoint. Valid rules still ran. |
| Rules work locally but not on the endpoint | Different libyara build | Expected. Compare `yara.YARA_VERSION`, not Python versions — see [Rule Compatibility](topics/Rule_Compatibility.md). |

## Running the script

| Symptom | Likely cause | Fix |
|---|---|---|
| `parameters_values contain invalid/missing parameters` | Inputs don't match the entry point | Entry point `main` takes exactly three inputs (`yarafile`, `scan_folder`, `alert_severity`); `cancel` takes none. Any extra key is rejected. |
| `Unknown option '<key>'` at startup | A retired or misspelled option key | The error lists every valid key. `lookup_rotation` and `alert_max_per_scan` are constants only and have no per-run equivalent. |
| Playbook can't find the script | `script_name` mismatch | Set the playbook's `script_name` to the exact library script name. |
| Nothing printed when run from a terminal | Build predates v2.0.0 | Older builds exited silently from the CLI. v2.0.0 prints `SCAN_RESULT: ...`. |

## Stopping a scan

| Symptom | Likely cause | Fix |
|---|---|---|
| Scan won't stop | — | Run the script's `cancel` entry point against the same endpoints. It stops within ~5 s and keeps the findings. |
| A cancelled scan still shows as running on the dashboard | It was stopped with the **console** Cancel | Expected. That path kills the process, so no terminal row is ever written. See [Scan Cancellation](topics/Scan_Cancellation.md). |
| `scanner running: no` from the cancel command | No scan in progress on that endpoint | The scan already finished, or it was killed by the console Cancel. |

## Host impact

| Symptom | Likely cause | Fix |
|---|---|---|
| Scan is very slow on a busy machine | Working as designed — the governor yielded to other load | Confirm with `floor_hits` in the summary. Raise `CONFIG_CPU_FLOOR_PCT` to guarantee more pace, or switch to `budget`. See [CPU Impact Control](topics/CPU_Impact_Control.md). |
| Scan uses less CPU than configured on Windows | The agent pins payloads to 2 cores | A hard platform ceiling of ~25% on an 8-core host, below anything you configure. |
| Raising `CONFIG_WORKERS` made it slower | Scanning is disk-bound | Expected. 2 is the default because it measures fastest. |

## Datasets

| Symptom | Likely cause | Fix |
|---|---|---|
| Too many datasets | Per-host sharding plus monthly rotation | Bucket hosts with a literal `CONFIG_LOOKUP_SHARD` label, and delete old months with `xdr_data_management.py`. See [Datasets and Maintenance](topics/Datasets_and_Maintenance.md). |
| Writes got slower over time | Merge time scales with dataset size | Confirm `CONFIG_LOOKUP_ROTATION = "monthly"`. |
| Rows accepted but absent (`records_skipped=N`) | Row carries a field the dataset's schema doesn't have | Schemas are fixed at creation. A changed row shape needs a new schema version. |
| `tenant_id` shows `unknown` | Non-standard API URL | Set `CONFIG_TENANT_ID`, or pass `tenant_id=<slug>` per run. |

## Still stuck

Collect these before raising it:

1. `scan_summary_<run_id>.json` — carries the version, outcome, and every delivery counter
2. `scan_errors_<run_id>.log`
3. The agent version and OS of the affected endpoint
4. The rule file, if compilation is involved
