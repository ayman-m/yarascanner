# YARA Scanner — Cortex XSIAM edition

Everything for running the YARA scanner on **Cortex XSIAM** lives in this folder. If you are
on XDR, you want [`../xdr/`](../xdr/) instead — the two editions are separate codebases with
different delivery models, and mixing them will not work.

## How this edition delivers findings

XSIAM has an **HTTP Log Collector**, so findings leave the endpoint as NDJSON over a single
channel into one dataset. There is no per-host sharding and no consolidation step, because
the collector accepts concurrent writers — which is precisely what XDR's lookup API does not.

That one difference is why the two editions are not a single file with a flag: the delivery
half of the scanner is genuinely different code, with different failure modes, different
back-pressure and different books.

## What is here

| Path | What it is |
|---|---|
| `xsiam_yara_scanner.py` | The scanner. Delivered to endpoints via Action Center. |
| `parsing_rules/` | The XSIAM parsing rule for the collector's dataset. |
| `docs/` | Deployment, troubleshooting, capabilities, test plan, round results. |
| `dashboards/`, `widgets/` | Console dashboards and their XQL widgets. |

## Start here

1. **[docs/Deployment_Guide.md](docs/Deployment_Guide.md)** — install, collector setup,
   first scan.
2. **[docs/Troubleshooting.md](docs/Troubleshooting.md)** — when something looks wrong.

## Reference

- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — every catalogued capability, what
  controls it, and how to observe it on a live scan.
- **[docs/TEST_PLAN.md](docs/TEST_PLAN.md)** — the acceptance criteria, agreed before any
  scan runs.
- **[docs/TEST_TRACKING.md](docs/TEST_TRACKING.md)** — per-capability status: 276 of 297
  criteria executed, 0 failures.
- **[docs/rounds/](docs/rounds/)** — what each live round actually found, including the
  eight defects the acceptance work surfaced.

## Tests

Tests live at the repo root in [`../tests/`](../tests/), not here, and that is deliberate:
most of them exercise **both** editions through a shared `EDITIONS` list. They are what stops
the two scanners drifting apart, so they belong to the pair rather than to either edition.

```bash
python3 -m pytest tests/ -q      # from the repo root
```
