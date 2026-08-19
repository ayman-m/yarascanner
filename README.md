# YARA Scanner for Cortex XDR & XSIAM

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Fleet-scale YARA scanning delivered through the Cortex agent — alerts sized for triage,
> datasets sized for forensics, and delivery accounting that always balances.

A multi-threaded, resource-aware YARA scanning engine that runs on endpoints **through the
Cortex agent** (Action Center, automation playbooks, scheduled jobs). Matches flow back into
the Cortex platform as alerts, datasets and dashboards, with no extra infrastructure on the
endpoint.

---

## Pick your platform

Everything for each platform lives in its own folder. Go to yours and stay there.

| | |
|---|---|
| ### ▶ [**`xdr/`** — Cortex XDR](xdr/) | ### ▶ [**`xsiam/`** — Cortex XSIAM](xsiam/) |
| Findings via **Insert Parsed Alerts** + **XQL lookup datasets** | Findings via the **HTTP Log Collector** (NDJSON) |
| Per-host datasets, merged per scan by a consolidation pack | One collector dataset, no sharding |
| [Deployment](xdr/docs/Deployment_Guide.md) · [Troubleshooting](xdr/docs/Troubleshooting.md) · [Capabilities](xdr/docs/CAPABILITIES.md) | [Deployment](xsiam/docs/Deployment_Guide.md) · [Troubleshooting](xsiam/docs/Troubleshooting.md) · [Capabilities](xsiam/docs/CAPABILITIES.md) |

**They are separate codebases, not one file with a flag.** The scanning half is near-identical;
the delivery half is genuinely different code with different failure modes. The reason is one
platform fact: XDR's `lookups/add_data` is **not concurrency-safe** — two endpoints writing the
same dataset collide server-side and silently lose rows (measured: 8 concurrent writers, 87% of
rows lost). So XDR shards per host and consolidates afterwards, while XSIAM's collector simply
accepts concurrent writers. Almost every other difference follows from that one.

---

## What is at the root, and why

Everything platform-specific is under `xdr/` or `xsiam/`. What stays here belongs to **both**,
or to the repository itself:

| Path | Why it is not in an edition folder |
|---|---|
| **`tests/`** | Most tests exercise **both** editions from one file, via a shared `EDITIONS` list. They are the mechanism that stops the two scanners drifting apart, so they belong to the pair — splitting them would mean duplicating them (they drift) or breaking them (they stop guarding). |
| **`CHANGELOG.md`** | One chronology. Many entries are fixes applied to both editions together; splitting it would duplicate those and lose the ordering that shows when a fix crossed over. |
| **`encode_rules.py`** | Edition-neutral helper — base64-encodes a rules file for either scanner. |
| **`test_rules.yar`** | Sample ruleset used by both editions' quick starts. |
| **`RELEASING.md`** | Internal release process for the repository, not for a platform. |
| `README.md`, `LICENSE`, `requirements.txt` | Repository entry point, licence, one shared Python environment. |
| `images/` | Assets for this README. |

```
.
├── xdr/                  ← everything Cortex XDR
│   ├── xdr_yara_scanner.py, xdr_action_center.py,
│   │   xdr_consolidate.py, xdr_data_management.py
│   ├── Packs/            dataset-consolidation content pack
│   ├── playbooks/        Action Center runner + canceller
│   ├── docs/  dashboards/  widgets/
│   └── README.md
├── xsiam/                ← everything Cortex XSIAM
│   ├── xsiam_yara_scanner.py
│   ├── parsing_rules/
│   ├── docs/  dashboards/  widgets/
│   └── README.md
├── tests/                dual-edition test suite
├── conftest.py           puts both editions on sys.path
└── CHANGELOG.md  RELEASING.md  encode_rules.py  test_rules.yar
```

---

## Running the tests

One suite covers both editions:

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -q
```

`conftest.py` at the root puts `xdr/` and `xsiam/` on `sys.path`, so the tests import each
scanner by its plain module name. The scanners are deliberately **not** packages — they are
delivered to endpoints as flat single-file snippets, and making them package members would
change how they import at the one place that matters most.

---

## 9. Security considerations

- **Credentials live in the script** (uploaded to the console script library) or in environment
  variables for the CLI toolkit — never commit real keys to source control (`.env` is gitignored).
- **Least-privilege key roles**: use two separate XDR keys — a *scanner delivery* key
  (**External Issues Mapping** for alerts + **Data Management** for datasets — verified
  by live smoke test) and an optional *automation* key (script execution + Action Center +
  query, endpoint-scoped). The XSIAM collector key is a write-only ingestion token with no
  RBAC role. Exact per-operation recipes, the create-role/key API flow, and the
  `manage_role_key.py` helper:
  [.claude/skills/xdr-action-center-api/references/api-permissions.md](.claude/skills/xdr-action-center-api/references/api-permissions.md).
- Runs against protected paths degrade gracefully (permission errors are counted + logged, not
  fatal). Evidence collection (`CONFIG_COLLECT_FILES`) copies matched files — leave it off unless
  your handling process requires it.
- All uploads are HTTPS. On TLS-intercepting networks, point `XDR_CA_BUNDLE` /
  `REQUESTS_CA_BUNDLE` at your CA chain for the CLI toolkit (endpoint agents are unaffected).

---

---

## 12. License & support

MIT — see [LICENSE](LICENSE). Issues and contributions via GitHub. For Cortex platform questions,
see the [Cortex XDR](https://docs-cortex.paloaltonetworks.com/p/XDR) and
[Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/p/XSIAM) documentation; for YARA rule
authoring, the [YARA documentation](https://yara.readthedocs.io/).
