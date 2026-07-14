# Cortex XDR public API map — Action Center / YARA scan automation

All supported automation in this repo uses documented endpoints under
`/public_api/v1/...` with API-key auth (Advanced/HMAC or Standard). Source of truth:
the [Cortex XDR REST API reference](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API).

## Script execution & tracking

| Operation | Method + path | Docs |
|---|---|---|
| List library scripts | `POST /public_api/v1/scripts/get_scripts/` | [Get Scripts](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Scripts) |
| Script inputs/metadata | `POST /public_api/v1/scripts/get_script_metadata/` | [Get Script Metadata](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Script-Metadata) |
| Script source | `POST /public_api/v1/scripts/get_script_code/` | [Get Script Code](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Script-Code) |
| Run a library script | `POST /public_api/v1/scripts/run_script/` | [Run Script](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Run-Script) |
| Run inline Python (no library) | `POST /public_api/v1/scripts/run_snippet_code_script/` | [Run Snippet Code Script](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Run-Snippet-Code-Script) |
| Track an action | `POST /public_api/v1/actions/get_action_status/` | [Get Action Status](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Action-Status) |
| Execution status per run | `POST /public_api/v1/scripts/get_script_execution_status/` | [Get Script Execution Status](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Script-Execution-Status) |
| Per-endpoint stdout/results | `POST /public_api/v1/scripts/get_script_execution_results/` | [Get Script Execution Results](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Script-Execution-Results) |
| Files returned by a script | `POST /public_api/v1/scripts/get_script_execution_result_files/` | [Get Script Execution Result Files](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Script-Execution-Result-Files) |

Lifecycle: `run_script`/`run_snippet_code_script` → `{action_id, group_action_id}` →
poll `get_action_status` → `get_script_execution_results`. The repo toolkit's
`run_snippet_wait()` wraps the whole chain.

## Endpoints, delivery, and datasets (used by the scanner itself)

| Operation | Method + path |
|---|---|
| Resolve/list endpoints | `POST /public_api/v1/endpoints/get_endpoint/` |
| Create alerts from matches | `POST /public_api/v1/alerts/insert_parsed_alerts/` |
| Write dataset rows | `POST /public_api/v1/xql/lookups/add_data/` |
| Create a dataset | `POST /public_api/v1/xql/add_dataset/` |
| List datasets | `POST /public_api/v1/xql/get_datasets/` |
| Query results | `POST /public_api/v1/xql/start_xql_query_python/` (+ get results) |
| Delete a dataset | `POST /public_api/v2/xql/delete_dataset/` |
| Delete rows by filter | `POST /public_api/v1/xql/lookups/remove_data/` |

## `/api/webapp/*` endpoints — internal console backend, not for integrations

Endpoints under `/api/webapp/` (examples seen in browser dev tools:
`scripts/create_script`, `scripts/update_script`, `scripts/build_script_manifest`,
`get_data`, `actions_center/actions/abort`, `actions_center/actions/cancel`) are the
private API that the **Cortex XDR web console UI** calls internally. They are:

- **Not part of the documented public API** — absent from the REST API reference above
- **Not supported for external integrations** — no compatibility guarantees; request and
  response shapes change without notice with console updates
- **Not reachable with API keys** — they authenticate the interactive console session
  (MFA/SSO browser login), not `x-xdr-auth-id`/HMAC headers

### Supported equivalents

| Console-internal endpoint | Supported path |
|---|---|
| `scripts/create_script`, `update_script`, `build_script_manifest` | Script library create/update is a **one-time console upload** (Action Center → Script Library). After that, execution is fully API-drivable via `run_script`. To avoid the library entirely, deliver the script inline with `run_snippet_code_script`. |
| `get_data` (script library listing) | `get_scripts` + `get_script_metadata` + `get_script_code` |
| `actions_center/actions/abort`, `.../cancel` | For this scanner: deliver the **`cancel` entry point** (`mode=cancel`) via `run_script`/`run_snippet_code_script` — the running scan stops cooperatively in ~5 s, drains uploads, and writes a terminal `cancelled` lifecycle row. Track any action with `get_action_status`. |
