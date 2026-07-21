---
name: xdr-action-center-api
description: Use when automating Cortex XDR Action Center operations for the YARA scanner through the supported public REST API — running the scanner (or any library script) on endpoints, cancelling a running scan, polling action status, retrieving execution results, or listing script-library data from code/CI/SOAR instead of the console. Also use when asked whether /api/webapp/* console endpoints can be scripted or included in an integration.
---

# XDR Action Center API Automation (YARA Scanner)

Automate the full YARA-scan lifecycle — deliver, track, verify, cancel — using **only
documented Cortex XDR public APIs** (`/public_api/v1/...`). Works from any host with API
access: cron, CI, SOAR, or an LLM agent driving the repo toolkit.

## Auth & setup

```bash
export XDR_API_URL="https://api-<tenant>.xdr.<region>.paloaltonetworks.com"
export XDR_API_ID="<key id>"
export XDR_API_KEY="<key secret>"
# TLS-intercepting proxy? export XDR_CA_BUNDLE=/path/to/ca_bundle.pem
```

Both key types work — **Advanced (HMAC) and Standard are auto-detected** by the toolkit
(`build_xdr_headers` / `XDRActionCenter._detect_auth`). For the exact least-privilege
role recipes (two separate keys: scanner delivery vs automation, with per-operation
permission components for XDR and the collector-token model for XSIAM), see
**references/api-permissions.md**.

## Quick reference — task → command → public API

| Task | Toolkit command (`xdr_action_center.py`) | Public API behind it |
|---|---|---|
| List/resolve endpoints | `endpoints` | `endpoints/get_endpoint` |
| List library scripts + inputs | `scripts` | `scripts/get_scripts`, `get_script_metadata` |
| Run the scanner (no library upload) | `run-scanner --hostname H --rules r.yar --scan-folder P` | `scripts/run_snippet_code_script` |
| Run an uploaded library script | *(see references/public-api-map.md)* | `scripts/run_script` |
| Track a run | *(built into the commands above)* | `actions/get_action_status` |
| Fetch per-endpoint output | *(built in)* | `scripts/get_script_execution_results` |
| **Cancel a running scan** | `cancel --hostname H` | `run_snippet_code_script` delivering the scanner's `cancel` entry point (cooperative, ~5 s) |
| Verify matches/lifecycle landed | `verify --hostname H` | `xql/start_xql_query_python` over `yara_scanner_*` datasets |
| Retire old lookup datasets | `prune-datasets` | `xql/delete_dataset`, `xql/lookups/remove_data` |

Full endpoint paths, request shapes, and docs links: **references/public-api-map.md**.

## One end-to-end example

`scripts/yara_scan_automation.py` — resolve endpoint → deliver scan → poll → print the
endpoint's scan summary → verify dataset rows:

```bash
python3 scripts/yara_scan_automation.py --hostname HOST01 \
    --rules rules.yar --scan-folder /tmp/target        # add --cancel-after 30 to test cancellation
```

## For LLM agents

- Import the toolkit as a library: `from xdr_action_center import XDRActionCenter` —
  `run_scanner()`, `run_snippet_wait()`, `xql()`, `endpoint_id()` are the primitives.
- `run_snippet_wait()` blocks through the run→poll→results lifecycle and returns
  per-endpoint stdout; prefer it over hand-rolling the three calls.
- Verify delivery from the **scan summary on the endpoint** (`scan_summary_<run_id>.json`,
  fields `alert_delivery` / `dataset_delivery`) — totals always balance; `undelivered > 0`
  means a platform ceiling was hit, not silent loss.

## Console-internal endpoints (`/api/webapp/*`) — do not script them

Endpoints under `/api/webapp/` (e.g. `scripts/create_script`, `scripts/update_script`,
`scripts/build_script_manifest`, `get_data`, `actions_center/actions/abort|cancel`) are the
**private backend of the Cortex XDR web console UI**. They are not part of the documented
public API: not supported for integrations, not covered by API-key auth (they require an
interactive, MFA-authenticated console session), and subject to change without notice on
any content update. Supported equivalents for each are mapped in
**references/public-api-map.md** — in short: script library create/update is a one-time
console upload (then fully API-drivable via `run_script`), or skip the library entirely
with `run_snippet_code_script`; scan cancellation is the scanner's cooperative `cancel`
entry point plus `get_action_status`.

## Common mistakes

| Mistake | Fix |
|---|---|
| `run_script` rejects parameters ("invalid/missing parameters") | The parameter set must **exactly** match the library script's defined inputs — upload the scanner with the 3-input `main` signature |
| Snippet fails to import `secrets`/`tempfile` | The agent's snippet sandbox enforces an import allowlist — use `os.urandom` etc. |
| Target endpoint ignored | Only **connected** endpoints run scripts; check `endpoints` output first |
| 401 on every call | Key type mismatch — let the toolkit auto-detect, or set `XDR_AUTH_TYPE=advanced` |
| TLS errors on corporate networks | Set `XDR_CA_BUNDLE` to a bundle containing your proxy CA |
