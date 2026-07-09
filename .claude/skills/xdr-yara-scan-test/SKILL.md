---
name: xdr-yara-scan-test
description: Test the YARA scanner (xdr_yara_scanner.py) end-to-end on a Cortex XDR endpoint using the XDR public API — no UI upload. Use when asked to run/test/validate the YARA scan on an XDR endpoint (e.g. WINSERVER01), deliver a scan via Action Center, cancel a running scan, or verify that matches/scan telemetry landed in the yara_scanner_matches / yara_scanner_scans lookup datasets. Handles Advanced (HMAC) auth and corporate-proxy TLS.
---

# XDR YARA Scan Test

Drives `xdr_yara_scanner.py` on a live Cortex XDR endpoint through the public API and
verifies the results, without uploading anything to the script library.

## How it works

There is **no public script-upload API**, so the script library is UI-managed. For
API-driven testing this skill runs the scanner as an **inline snippet** via
`run_snippet_code_script` (the agent's embedded Python 3.12 has yara/psutil/requests).
`build_snippet.py` injects the real creds, neutralizes the `__main__` guard, and appends
a `main(...)` call. Production deployment is still a manual UI upload of the scanner as a
library script, then `run_script` — this skill is for **testing**.

Action lifecycle: `run_snippet` → `{action_id}` → poll `actions/get_action_status` →
`scripts/get_script_execution_results` (per-endpoint stdout). Dataset verification uses
the XQL query API.

## Prerequisites

1. **Credentials** — a `.env` at the repo root with `XDR_API_ID`, `XDR_API_URL`,
   `XDR_API_KEY` (gitignored). The key is typically **Advanced** (HMAC) — the scripts
   default to Advanced and fall back to Standard automatically in `check.py`.
2. **Python** — `pip install requests` (the repo `requirements.txt` covers it).
3. **TLS (only if behind a corporate proxy that MITMs HTTPS):**
   ```bash
   export XDR_CA_BUNDLE="$(scripts/make_ca_bundle.sh)"
   ```
   The agent side never needs this.

All scripts live in `scripts/` and share `xdr_lib.py`. Run them from anywhere; they
locate `.env` and the scanner by walking up to the repo root.

## Workflow

```bash
cd .claude/skills/xdr-yara-scan-test/scripts
export XDR_CA_BUNDLE="$(./make_ca_bundle.sh)"        # corporate proxy only

# 1) preflight: auth + endpoint reachable
python3 check.py --hostname WINSERVER01

# 2) run an end-to-end scan (seeds a small folder with guaranteed-match content)
python3 run_scan.py --hostname WINSERVER01 --seed-files 0
#   -> prints "SCAN_RESULT: ... N matches found | <posture>"

# 3) verify data landed (matches + scan lifecycle rows, tenant_id populated)
python3 verify.py --hostname WINSERVER01
```

### Testing the output-channel flags

Pass `--options` (a `key=value,key=value` string mapped to the scanner's options):

```bash
python3 run_scan.py --hostname WINSERVER01 --seed-files 0 --options create_alerts=false
python3 run_scan.py --hostname WINSERVER01 --seed-files 0 --options write_dataset=false
python3 run_scan.py --hostname WINSERVER01 --seed-files 0 --options collect_files=true
python3 run_scan.py --hostname WINSERVER01 --seed-files 0 --options throttle_mode=os
```
Valid keys: `create_alerts, write_dataset, collect_files, throttle_mode,
cpu_high_threshold, cpu_critical_threshold, max_pause_secs, tenant_id`.

### Testing cancellation

```bash
# start a long scan (seed many files so it runs long enough to cancel)
python3 run_scan.py --hostname WINSERVER01 --seed-files 6000 &
sleep 12
python3 cancel_scan.py --hostname WINSERVER01      # -> "scanner running: yes"
```
The running scan detects the cancel flag within ~5s and returns
`Scan cancelled by operator: ...`; a terminal `cancelled` row appears in
`yara_scanner_scans` (check with `verify.py`).

### Scanning a real path

```bash
python3 run_scan.py --hostname WINSERVER01 --scan-folder 'C:\Users\Public' --severity high
```
Omit `--seed-files` (or the folder defaults to `default` = full scan — heavy).

## Scripts

| Script | Purpose |
|--------|---------|
| `xdr_lib.py` | XDR API client (Advanced/Standard auth, endpoints, run_snippet/run_script, action polling, XQL) |
| `check.py` | Preflight: validate auth, locate the endpoint |
| `build_snippet.py` | Wrap the scanner into a runnable snippet (creds injected; scan or cancel mode; optional seeded folder) |
| `run_scan.py` | Build + run a scan on an endpoint, poll, print the summary |
| `cancel_scan.py` | Deliver `mode=cancel` to a running scan |
| `verify.py` | XQL: show matches + scan-lifecycle rows for a host |
| `make_ca_bundle.sh` | Build a CA bundle for corporate-proxy TLS (local machine only) |

## Notes & gotchas

- **Snippet import allowlist:** the agent sandbox rejects some stdlib imports (e.g.
  `secrets`, `tempfile`). The scanner and snippets avoid them (nonce uses `os.urandom`).
- **Generated snippets embed real creds** — they are written under `local_test/`
  (gitignored). Never commit them.
- **yara version:** the agent ships yara 4.1.0; the scanner normalizes old/new match
  APIs, so basic rules work regardless.
- The endpoint filter field for actions is `endpoint_id_list`; targeting is scoped to the
  single resolved endpoint id (the run reply reports `endpoints_count`).
