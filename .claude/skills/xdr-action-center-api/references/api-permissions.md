# Least-privilege API key roles/permissions — YARA scanner (XDR & XSIAM)

How the required permissions were established: the REST API reference pages state only the
generic 403 ("The provided API Key does not have the required RBAC permissions"), so the
per-operation mapping below uses the **platform's own RBAC catalog** — the
`POST /public_api/v1/rbac/get_roles` API returns every role's granted permission
*components* (the same component names shown in the console's custom-role editor). Key
facts verified against a live tenant: the built-in role grants listed here, and that the
alert-write and dataset-write components are granted **only to Admin** among built-ins —
which is why least privilege requires **custom roles**, not a built-in.

## Cortex XDR — use two keys, not one

The scanner (on endpoints) and the automation tooling (run/cancel/track) need different
permissions. Splitting them keeps each key minimal and lets you revoke independently.

### Key 1 — scanner delivery key (embedded in the uploaded script)

Used by every endpoint running the scan. It only *writes results* — it can't run scripts,
read endpoints, or query.

| Operation (API) | Required permission component |
|---|---|
| Create alerts — `alerts/insert_parsed_alerts` | **Issues / Alerts & Incidents** → *Edit* |
| Write dataset rows — `xql/lookups/add_data` | **Data Management** → *Edit* |
| Create datasets — `xql/add_dataset` | **Data Management** → *Edit* |
| List datasets — `xql/get_datasets` | **Data Management** → *View* |

**Custom role recipe `yara-scanner-delivery`:** Issues/Alerts & Incidents (Edit) +
Data Management (Edit). Nothing else. No endpoint scope needed (it touches no endpoints).

> Among built-in roles, only **Admin** carries Issues-edit and Data Management — never
> deploy the scanner with an Admin key; create the custom role.

### Key 2 — automation key (Action Center run/cancel/track; optional)

Only needed if scans are driven via API/SOAR/cron rather than the console.

| Operation (API) | Required permission component |
|---|---|
| Run library script — `scripts/run_script` | **Run Standard Script** + **Run High-Risk Script** (a fleet file-reading scanner is classified high-risk) |
| Run inline snippet — `scripts/run_snippet_code_script` | **Run High-Risk Script** |
| List scripts/metadata/code — `scripts/get_*` | **Agent Scripts Library** (View) + **Scripts** (View) |
| Track actions — `actions/get_action_status`, `scripts/get_script_execution_*` | **Action Center** (View) |
| Resolve endpoints — `endpoints/get_endpoint` | Endpoint administration *View* + role **endpoint scope** limited to the target groups |
| Verify results — XQL query APIs | **Query Center** (+ Query Library) |
| Cancel a scan | same as run (it delivers the `cancel` entry point) |

**Custom role recipe `yara-scanner-automation`:** the components above, endpoint scope
restricted to the endpoint groups you actually scan. The built-in **Privileged
Responder** covers this surface (verified from live role grants) but is broader than
needed — prefer the custom role.

**Do not** grant the automation key Data Management: dataset pruning
(`delete_dataset` / `lookups/remove_data`) is a rare maintenance task — run it with the
delivery key or an interactive admin session.

### Both keys

- Use the **Advanced** key type (per-request HMAC; replay-resistant — the scanner and
  toolkit auto-detect it) and set an expiry.
- Validation is cheap: the scanner **aborts loudly** on placeholder credentials, and any
  missing permission surfaces immediately as HTTP 403 lines in `uploads_<run_id>.log` —
  run one small-folder smoke scan after creating the key.

## Cortex XSIAM

The XSIAM edition delivers everything to an **HTTP Event Collector**, so its key model is
different:

| Concern | Answer |
|---|---|
| Key used by the scanner | The **HTTP collector token** generated when the collector instance is created (Settings → Data Sources → Custom Collectors → HTTP). It is a write-only ingestion bearer for `POST /logs/v1/event` — it carries **no RBAC role** and cannot read or administer anything. |
| Least-privilege blast radius | Log injection into that collector's dataset only. |
| One-time setup permission | Creating the collector is a console task requiring the **Data Sources / Log Collections** components (an admin-type action, done once — not by the scanner key). |
| Automating scans on XSIAM via Action Center | Same platform RBAC as XDR — apply the *automation key* recipe above (Run Script components, Action Center, Agent Scripts Library, Query Center). |

## Verifying on your own tenant

Component names can shift slightly across releases. Reproduce the mapping on any tenant:

```bash
# returns each role's granted permission components (role_names is REQUIRED — an empty
# list errors; pass the built-in names)
POST /public_api/v1/rbac/get_roles
{"request_data": {"role_names": ["Admin", "Viewer", "Responder", "Privileged Responder"]}}
```

Then build the custom roles in **Settings → Access Management → Roles** by selecting the
components listed above, and bind each API key to its role in **Settings → API Keys**.
