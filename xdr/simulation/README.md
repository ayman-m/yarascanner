# Dataset-management simulation probes

Small scripts that prove — against the live tenant, not by reasoning — the API assumptions
the [dataset-management design](../docs/design/Dataset_Management_Design.md) rests on.

**These are not the product and not a full simulation.** Each probe tests ONE assumption and
prints PASS or FAIL with the numbers behind it. The point is to find out which assumptions
are wrong *before* building on them.

Every object they create is prefixed `yara_sim_`, so a stray run cannot touch real scanner
data, and `cleanup.py` removes everything carrying that prefix.

## The probes, in the order to run them

| # | Script | Assumption under test |
|---|---|---|
| 1 | `sim_scan.py` | one host can create its own data lookups, write findings, and register in the shared tracker with started + completed rows |
| 2 | `sim_fleet.py` | **the critical one** — many hosts can write to ONE shared tracker without losing rows |
| 3 | `sim_playbook.py` | given only the tracker, the playbook can find, merge, verify, delete and prune — with no wildcard and no name derivation |
| 4 | `sim_correlation.py` | a correlation rule can watch the tracker and fire |

```bash
cd xdr/simulation
python3 sim_scan.py --host simhost1 --matches 25
python3 sim_fleet.py --hosts 24 --mode naive
python3 sim_fleet.py --hosts 24 --mode verify --jitter 60
python3 sim_playbook.py --dry-run
python3 sim_playbook.py
python3 sim_correlation.py
python3 cleanup.py
```

Requires `.env` at the repo root with `XDR_API_ID` / `XDR_API_URL` / `XDR_API_KEY`
(Advanced key), and `XDR_CA_BUNDLE` set if you are behind a TLS-intercepting proxy.

## Why probe 2 is the one that matters

The tracker is a **shared** dataset — every host writes to it. That is precisely the
collision the per-host split exists to avoid. Measured previously on this tenant: 8 threads
writing 1,601 rows to one lookup dataset landed 201 of them — **87% silently lost**, with
no error raised to 7 of the 8 writers.

The tracker writes far less: 2 rows per scan, not hundreds. But "less" is not "safe", and
the difference has to be measured. Probe 2 runs three modes so the result says *which
mitigation is needed* rather than just pass/fail:

- `naive` — everyone at once, no jitter, no verify. The worst case.
- `jitter` — starts spread over N seconds. Shows what jitter alone buys.
- `verify` — jitter plus read-back-and-retry. The proposed design.

**A lost `started` row is the serious failure**, not a lost `completed` one: it means a real
dataset was never registered, so it is never consolidated and never cleaned up — invisible
and permanent.

## The question probe 4 exists to force

Correlation rules are built for streaming event data. **Lookup datasets are state.** Probe 4
checks whether a rule can take a lookup as its source at all — and if it cannot, the tracker
has to be an *ingested* dataset rather than a lookup, and the design changes again.

Better to discover that from a 60-line script than from a built playbook.
