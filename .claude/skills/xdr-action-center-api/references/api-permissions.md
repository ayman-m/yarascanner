# Least-privilege API key roles/permissions — YARA scanner (XDR & XSIAM)

How the required permissions were established: the REST API reference pages state only the
generic 403 ("The provided API Key does not have the required RBAC permissions"), so the
mapping below was **verified empirically on a live tenant** — a custom role was created
with candidate permissions, an API key bound to it, and each delivery API called until it
returned 200. The permission *component* names are those shown in the console's custom-role
editor; the machine keys (in `code`) are what `POST /platform/iam/v1/role` expects.

> **Verified result (not a guess):** `insert_parsed_alerts` requires **External Issues
> Mapping**, *not* "Cases and Issues / Alerts" as one might assume from the UI — a
> Cases-and-Issues-only key gets 403 "Insufficient permissions for api key" on alert
> insert while datasets still succeed. The two-permission delivery role below was smoke-
> tested end-to-end: 6/6 finding alerts delivered, 8/8 dataset rows, 0 failed, 0 forbidden.

## Cortex XDR — use three keys, not one

The scanner (on endpoints), the automation tooling (run/cancel/track) and the
dataset-management pack (consolidate/prune) need different permissions. Splitting them keeps
each key minimal and lets you revoke independently — which matters most for the third, since
it is the only one that can delete data.

### Key 1 — scanner delivery key (embedded in the uploaded script)

Used by every endpoint running the scan. It only *writes results* — it can't run scripts,
read endpoints, or query.

| Operation (API) | Required permission component | Machine key |
|---|---|---|
| Create alerts — `alerts/insert_parsed_alerts` | **External Issues Mapping** (Configurations → Data Collection) | `external_alerts_action` |
| Write dataset rows — `xql/lookups/add_data` | **Data Management** (Configurations → Data Management) | `data_management_action` |
| Create datasets — `xql/add_dataset` | **Data Management** | `data_management_action` |
| List datasets — `xql/get_datasets` | **Data Management** | `data_management_action` |

**Custom role recipe `yara-scanner-delivery`:** External Issues Mapping +
Data Management. Nothing else. No endpoint scope needed (it touches no endpoints).
**Verified sufficient** by live smoke test (6/6 alerts + datasets, 0 forbidden).

> Do **not** use "Cases and Issues / Alerts" for the alert permission — verified to 403 on
> `insert_parsed_alerts`. Insert Parsed/CEF Alerts is an *external-alert ingestion* API, so
> it is governed by **External Issues Mapping**. Among built-ins only **Admin** carries both
> required components — create the custom role, never deploy an Admin key.

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

**Do not** grant the automation key Data Management: for *this* key's job (run/cancel/track)
it is not needed. Note this caveat used to end "…dataset pruning is a rare maintenance task
— run it with the delivery key or an interactive admin session." That is no longer true:
the `Packs/YaraDatasetManagement` XSOAR pack prunes and consolidates on an unattended
twice-daily schedule, so pruning is now routine automated behaviour and needs its own key.
See **Key 3** below.

### Key 3 — dataset-management key (consolidation + retention pruning)

Used by the `Packs/YaraDatasetManagement` XSOAR pack (`YaraConsolidateStatus`,
`YaraConsolidateApply`, `YaraReport`, `YaraCleanup`) and by the `xdr_consolidate.py` /
`xdr_data_management.py` CLIs. It never touches endpoints or scripts — it only reads and
reshapes lookup datasets.

| Operation (API) | Required permission component | Machine key |
|---|---|---|
| List datasets — `xql/get_datasets` | **Data Management** | `data_management_action` |
| Create per-scan target — `xql/add_dataset` | **Data Management** | `data_management_action` |
| Write rows — `xql/lookups/add_data` | **Data Management** | `data_management_action` |
| Remove rows — `xql/lookups/remove_data` | **Data Management** | `data_management_action` |
| Delete a shard — `xql/delete_dataset` (v2 path) | **Data Management** | `data_management_action` |
| Read counts/rows/gates — XQL query APIs | **Query Center** | `investigation_query_view` |

**Custom role recipe `yara-dataset-management`:** Data Management + Query Center. No
endpoint scope (it touches no endpoints), no script components, no External Issues Mapping
(it creates no alerts).

#### Three findings from enumerating this tenant's real RBAC (2026-08-13)

Taken from `GET /platform/iam/v1/role/permission-config` (91 components) and
`POST /public_api/v1/rbac/get_roles` for the four built-ins — not from the docs.

1. **Data Management has no view-only tier.** Its row is literally
   `view=- action=data_management_action`. Every other dataset-ish component in the list has
   a `view=` variant; this one does not. So *there is no way to grant read-only dataset
   access* — the moment a key can list or read datasets through this component it can also
   `delete_dataset`. Least privilege bottoms out here.
2. **Among the built-in roles, only Admin has Data Management.** Privileged Responder,
   Responder and Viewer all carry Query Center and Query Library but **not** Data Management.
   There is therefore no built-in role that fits this pack — a custom role is mandatory
   unless you are willing to deploy an Admin key, which you should not.
3. **The granular-looking dataset permissions are not usable in a custom role.** Admin's
   grant list shows `Create Datasets`, `Dataset Management`, `Datasets Access Control` and
   `Edit Public Datasets` — none of which appear in `permission-config`, so
   `POST /platform/iam/v1/role` cannot reference them. They are console/legacy surface names,
   not custom-role building blocks. Do not go hunting for a narrower dataset role built out
   of them; it cannot be constructed.

**Consequence for the pack, and why its design is shaped the way it is.** Because the
delete capability cannot be withheld at the RBAC layer, the guardrails on destructive
behaviour have to live in the *code*, and they do: `YaraCleanup` is dry-run by default with
an explicit opt-in argument, applies seven independent safety rails on both selection paths,
and takes the consolidation lock before deleting. Treat those as the real control — the API
key is not, and cannot be made, the thing that stops a bad delete.

> **Not yet split empirically: Query Center `view` vs `action`.** Running an XQL query is a
> read, and the built-in **Viewer** role carries Query Center, which is why
> `investigation_query_view` is the recommended starting grant. It has not been isolated on
> a live tenant the way the External-Issues-Mapping finding above was. If XQL returns 403
> with view only, escalate that one component to `investigation_query_action` and record the
> result here.

### All keys

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

**Creating roles/keys on XSIAM via API:** the XSIAM Platform APIs expose the full set —
`POST /platform/iam/v1/role` (create), `GET /platform/iam/v1/role` (list),
`DELETE /platform/iam/v1/role/{role_id}`, `GET /platform/iam/v1/role/permission-config`
(machine keys), and `POST /public_api/v1/api_keys/generate` / `.../delete`. Same shapes and
same gotchas as XDR (epoch-ms expiration, reference roles by pretty_name). The collector
token, however, is generated in **Settings → Data Sources → the HTTP collector instance**,
not via these role APIs — it is not an RBAC key.

## Creating the custom role + key — console **or** API

### Option A — console (no special API permission needed)

1. **Settings → Access Management → Roles → Add** — name it `yara-scanner-delivery`, enable
   **External Issues Mapping** and **Data Management** (leave everything else off), save.
2. **Settings → API Keys → New Key** — Security Level **Advanced**, Role
   `yara-scanner-delivery`, set an expiry, copy the key + note its **ID**.
3. Put the key/ID/FQDN into the scanner's `DEFAULT_XDR_*` constants and upload.
4. (Optional) repeat for `yara-scanner-automation` with the automation components.

### Option B — fully via public API (IAM Platform APIs)

The whole thing is scriptable — `scripts/manage_role_key.py` in this skill wraps it. The
raw calls (all verified live):

```bash
# 1) discover the exact machine keys for your tenant + their dependencies
GET  /platform/iam/v1/role/permission-config

# 2) create the role (component_permissions = machine keys; include any dependency the
#    permission-config lists, e.g. Data Management/External Issues Mapping have none extra)
POST /platform/iam/v1/role
{"request_data": {"pretty_name": "yara-scanner-delivery",
                  "description": "YARA delivery: alerts + datasets",
                  "component_permissions": ["external_alerts_action", "data_management_action"]}}

# 3) generate an Advanced key bound to the role (reference the role by PRETTY NAME here,
#    NOT role_id; expiration is epoch-MILLIS, 0 is rejected — pass now+ms or a real date)
POST /public_api/v1/api_keys/generate
{"request_data": {"roles": ["yara-scanner-delivery"], "security_level": "advanced",
                  "expiration": 1790000000000, "comment": "yara delivery key"}}
# -> reply: {"id": <auth-id>, "key": "<secret, shown once>"}

# cleanup helpers
POST   /public_api/v1/api_keys/delete   {"request_data":{"filters":[{"field":"id","operator":"in","value":[<id>]}]}}
DELETE /platform/iam/v1/role/{role_id}
```

**Gotchas (all hit during live verification):**
- `permission-config` dependency closure: enabling a permission may require its parents
  (e.g. Cases-and-Issues needs Playbooks→Scripts). Data Management and External Issues
  Mapping need **no** extra dependencies — that's part of why they make a clean minimal role.
- `api_keys/generate` `expiration` must be **epoch-milliseconds** (`0` → HTTP 500
  "must be integer in epoch milliseconds"); reference roles by **pretty_name**, not the
  `role_id` returned at creation (`role_id` → 500 "Unknown custom roles").
- Creating roles/keys itself needs an **Access-Management-privileged** key (or just use the
  console, Option A). This is a one-time setup action, not something the scanner does.

### Verify the mapping any time

```bash
GET /platform/iam/v1/role                      # list roles incl. custom, is_custom flag
POST /public_api/v1/rbac/get_roles             # each role's granted components (role_names REQUIRED)
{"request_data": {"role_names": ["Admin", "Privileged Responder"]}}
```

After creating the key, run one small-folder smoke scan — the scanner aborts loudly on bad
creds, and any missing permission shows immediately as an HTTP 403 line in
`scan_errors_<run_id>.log` ("Insufficient permissions for api key").
