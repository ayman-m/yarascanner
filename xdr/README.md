# YARA Scanner — Cortex XDR edition

Everything for running the YARA scanner on **Cortex XDR** lives in this folder. If you are
on XSIAM, you want [`../xsiam/`](../xsiam/) instead — the two editions are separate
codebases with different delivery models, and mixing them will not work.

## How this edition delivers findings

XDR has **no HTTP log collector**. Findings leave the endpoint through two independent
channels, which is the main thing that makes this edition different from XSIAM:

| Channel | Carries | Grain |
|---|---|---|
| **Insert Parsed Alerts** | one alert per file x rule | the triage grain, capped per scan |
| **XQL lookup datasets** | every finding, with matched-string detail | the forensic grain |

Because `lookups/add_data` is **not concurrency-safe** — two endpoints writing one dataset
collide server-side and lose rows — each host writes to its **own** dataset. That is correct
for writing but leaves one dataset pair per host, so the consolidation pack below merges each
finished scan's shards into a single per-scan dataset.

## What is here

| Path | What it is |
|---|---|
| `xdr_yara_scanner.py` | The scanner. Delivered to endpoints via Action Center. |
| `xdr_action_center.py` | API toolkit — deliver, track, verify, cancel. |
| `xdr_consolidate.py` | Per-scan dataset consolidation logic (pure, unit-tested). |
| `xdr_data_management.py` | CLI for consolidation and retention pruning. |
| `Packs/YaraDatasetManagement/` | The same logic delivered as a content pack. |
| `playbooks/` | Action Center runner and canceller. |
| `docs/` | Deployment, troubleshooting, capabilities, test plan, round results. |
| `dashboards/`, `widgets/` | Console dashboards and their XQL widgets. |

## Start here

1. **[docs/Deployment_Guide.md](docs/Deployment_Guide.md)** — install and first scan.
2. **[docs/Troubleshooting.md](docs/Troubleshooting.md)** — when something looks wrong.
3. **[docs/topics/](docs/topics/)** — CPU impact, cancellation, datasets and maintenance,
   rule compatibility, known limitations.

## Reference

- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — every catalogued capability, what
  controls it, and how to observe it on a live scan.
- **[docs/TEST_PLAN.md](docs/TEST_PLAN.md)** — the acceptance criteria, agreed before any
  scan runs.
- **[docs/TEST_TRACKING.md](docs/TEST_TRACKING.md)** — per-capability status.
- **[docs/rounds/](docs/rounds/)** — what each live round actually found.

## Tests

Tests live at the repo root in [`../tests/`](../tests/), not here, and that is deliberate:
most of them exercise **both** editions through a shared `EDITIONS` list. They are what stops
the two scanners drifting apart, so they belong to the pair rather than to either edition.

```bash
python3 -m pytest tests/ -q      # from the repo root
```
