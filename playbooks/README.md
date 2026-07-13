# Cortex Playbooks — YARA Scanner

Automation playbooks that launch (and cancel) the YARA scanner on Cortex agents via
**Action Center**, using the built-in **Cortex Core - IR** integration. They work on
Cortex XDR (the `edr` module) and XSIAM, wherever the automation engine + Cortex Core - IR
commands are available.

| Playbook | Purpose |
|----------|---------|
| `YARA_Scanner_Runner.yml` | Resolve the library script + target endpoints, then run the scanner with its parameters (`core-script-run`). |
| `YARA_Scanner_Canceller.yml` | Same targeting, but runs the scanner with `mode=cancel` to gracefully stop a running scan. |

Each is a linear flow: `core-get-scripts` (name → `script_uid`) → `core-get-endpoints`
(hostname/group → endpoint IDs) → `core-script-run` (execute with parameters). That exact
command sequence has been validated live against a Cortex XDR tenant.

## ⚠️ Prerequisite — upload the scanner with the right inputs

There is **no public API to upload a library script**, so the scanner is added via the console
once. Critically, **`core-script-run` rejects any parameter set that does not exactly match the
script's defined inputs** (verified: `parameters_values contain invalid/missing parameters`).

So the scanner **must be uploaded with the `main` entry point's exactly-3 string inputs, in
order** (matching `main(yarafile, scan_folder, alert_severity)`):

1. `yarafile` — base64-encoded YARA rules
2. `scan_folder` — target path or `default`
3. `alert_severity` — `low` | `medium` | `high`

All other behaviour (alerts/dataset/collect_files/throttle/cpu/tenant/sharding) is now set in the
**CUSTOMER CONFIG** block at the top of the script, not passed per run. To cancel a running scan,
upload/run with Entry Point = **`cancel`** (no inputs).

Entry point: `main`. Give it a name and set the `script_name` playbook input to match
(default `xdr_yara_scanner_v4`).

> **Playbooks deferred:** the bundled `YARA_Scanner_Runner.yml` / `YARA_Scanner_Canceller.yml`
> still pass the old 5-input parameter set. Before using them, trim the Runner's `parameters` to
> the 3 inputs above and point the Canceller at the `cancel` entry point — otherwise
> `core-script-run` will reject the call.

## Import

Console → **Settings → Configurations → Object Setup → Playbooks** (or *Custom Content*):
import `YARA_Scanner_Runner.yml` and `YARA_Scanner_Canceller.yml`. Confirm the **Cortex Core - IR**
integration is enabled.

## Run

**Manually** — open the playbook, click **Run**, and supply inputs:

| Input | Example |
|-------|---------|
| `script_name` | `xdr_yara_scanner_v4` |
| `yarafile` | *(base64 of your `.yar`; e.g. `python3 encode_rules.py test_rules.yar`)* |
| `scan_folder` | `C:\Users` or `default` |
| `alert_severity` | `low` |
| `mode` | `scan` |
| `options` | `create_alerts=true,write_dataset=true` |
| `endpoint_hostnames` | `WINSERVER01` |
| `endpoint_groups` | *(optional)* |

Targeting must resolve at least one **connected** endpoint (by hostname and/or group).

## Schedule as a Job (recurring scans)

Console → **Investigation & Response → Automation → Jobs → + New Job**:

1. **Trigger:** `Time triggered` with your cron/recurrence (e.g. daily 02:00).
2. **Playbook:** `YARA Scanner Runner`.
3. **Inputs:** set `script_name`, `yarafile`, `scan_folder`, `alert_severity`, `options`, and the
   endpoint targeting the same way as a manual run.

For fleet rollouts, target by `endpoint_groups` rather than hostnames.

## Cancelling a running scan

Run `YARA Scanner Canceller` (manually or as an ad-hoc action) with the same `script_name` and the
target hostnames/groups. It dispatches the scanner in `mode=cancel`, which drops the cancel flag;
the running scan stops within ~5s and writes a terminal `cancelled` row to `yara_scanner_scans`.

## Verify a run

After the playbook runs, matches and lifecycle rows land in the lookup datasets. Verify with the
bundled skill:

```bash
.claude/skills/xdr-yara-scan-test/scripts/verify.py --hostname <host>
```

or in XQL: `dataset = yara_scanner_scans | filter hostname = "<host>" | sort desc event_timestamp_ms`.

## Alternative — no playbook engine

If a tenant lacks the automation engine, the same targeting + scheduling is achievable purely via
the API using the test skill's `run_scan.py` on a cron/Broker VM — no playbook import required.
