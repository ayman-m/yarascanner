# YARA Scanner for Cortex XDR & XSIAM

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Fleet-scale YARA scanning delivered through the Cortex agent — alerts sized for triage,
> datasets sized for the deep dive.

A multi-threaded, resource-aware YARA scanning engine that runs on endpoints **through the
Cortex agent**, delivered as a script rather than installed software. Matches return as alerts,
datasets and dashboards, with no extra infrastructure on the endpoint.

## Pick your platform

Everything for each platform lives in its own folder. Go to yours and stay there.

| | |
|---|---|
| ### ▶ [**`xdr/`** — Cortex XDR](xdr/) | ### ▶ [**`xsiam/`** — Cortex XSIAM](xsiam/) |
| Findings via **Insert Parsed Alerts** + **XQL lookup datasets** | Findings via the **HTTP Log Collector** (NDJSON) |
| One dataset per host, plus automations to consolidate and prune them | One collector dataset, no sharding |
| **[Start with `xdr/README.md`](xdr/README.md)** — what to upload, the data model, the two consolidation modes, sizing | **[Start with `xsiam/README.md`](xsiam/README.md)** |
| [Deployment](xdr/docs/Deployment_Guide.md) · [Capacity](xdr/docs/CAPACITY.md) · [Troubleshooting](xdr/docs/Troubleshooting.md) · [Capabilities](xdr/docs/CAPABILITIES.md) | [Deployment](xsiam/docs/Deployment_Guide.md) · [Troubleshooting](xsiam/docs/Troubleshooting.md) · [Capabilities](xsiam/docs/CAPABILITIES.md) |

**They are separate codebases, not one file with a flag.** The scanning half is near-identical;
the delivery half is genuinely different code with different failure modes. The reason is one
platform fact: XDR's `lookups/add_data` is **not concurrency-safe** — two endpoints writing the
same dataset collide server-side and silently lose rows (measured: 8 concurrent writers, 87% of
rows lost). So XDR shards per host and consolidates afterwards, while XSIAM's collector simply
accepts concurrent writers. Almost every other difference follows from that one.

Anything XDR-specific — upload list, API key types, dataset lifetimes, capacity numbers — is in
[`xdr/README.md`](xdr/README.md) and is not repeated here.

## What is at the root, and why

Everything platform-specific is under `xdr/` or `xsiam/`. What stays here belongs to **both**,
or to the repository itself:

| Path | Why it is not in an edition folder |
|---|---|
| **`tests/`** | Most tests exercise **both** editions from one file, via a shared `EDITIONS` list. They are the mechanism that stops the two scanners drifting apart, so they belong to the pair — splitting them would mean duplicating them (they drift) or breaking them (they stop guarding). |
| **`CHANGELOG.md`** | One chronology. Many entries are fixes applied to both editions together; splitting it would duplicate those and lose the ordering that shows when a fix crossed over. |
| `encode_rules.py`, `test_rules.yar` | Edition-neutral: a rules base64-encoder and the sample ruleset both quick starts use. |
| `tools/`, `conftest.py` | Repository machinery — pack build and the `sys.path` shim that puts both editions on the import path. Never shipped to a tenant. |

```
.
├── xdr/     xdr_yara_scanner.py · xdr_action_center.py · xdr_consolidate.py
│            xdr_data_management.py · Packs/ (dataset-management pack)
│            playbooks/ · docs/ · dashboards/ · widgets/
├── xsiam/   xsiam_yara_scanner.py · parsing_rules/
│            docs/ · dashboards/ · widgets/
├── tests/   dual-edition test suite
└── tools/  conftest.py  CHANGELOG.md  encode_rules.py  test_rules.yar
```

## Running the tests

One suite covers both editions:

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -q
```

`conftest.py` puts `xdr/` and `xsiam/` on `sys.path`, so tests import each scanner by its plain
module name. The scanners are deliberately **not** packages — they ship to endpoints as flat
single-file snippets, and making them package members would change how they import at the one
place that matters most.

## Credentials and safety

- **Credentials live in the uploaded script and automations**, or in environment variables for
  the CLI toolkit — never commit real keys (`.env` is gitignored). XDR needs two *different key
  types*; the exact model, and the one missing permission that fails silently, are in
  [`xdr/README.md`](xdr/README.md). The XSIAM collector key is a write-only ingestion token.
- Protected paths degrade gracefully — permission errors are counted and logged, not fatal.
  Evidence collection (`CONFIG_COLLECT_FILES`) copies matched files and is **off by default**.
- All uploads are HTTPS. On TLS-intercepting networks, point `XDR_CA_BUNDLE` /
  `REQUESTS_CA_BUNDLE` at your CA chain for the CLI toolkit (endpoint agents are unaffected).

## License & support

MIT — see [LICENSE](LICENSE). Issues and contributions via GitHub. For Cortex platform
questions see the [Cortex documentation](https://cortex-docs.paloaltonetworks.com/); for YARA
rule authoring, the [YARA documentation](https://yara.readthedocs.io/).
