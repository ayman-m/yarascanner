# YARA Scanner — Comprehensive Test Harness

Automated, API-driven test battery for `xdr_yara_scanner.py`, exercising both a Windows and
a Linux Cortex agent end-to-end (auth → scan → datasets → on-endpoint artifacts). Everything
runs through the Cortex XDR public API via `../xdr_action_center.py` — no library upload, no
manual steps.

## Components

| File | Purpose |
|------|---------|
| `gen_rules.py` | Generates `yara_rules/*.yar` — 20 files from 1 rule to 500 rules, covering plain/wide/hex/regex strings, `pe`/`elf`/`math`/`hash` modules, meta severity, module auto-injection, deliberately-failing rules, cuckoo-skip, condition-only, external vars, duplicate names, many-string rules, and no-match packs |
| `seed_corpus.py` | Seeds a deterministic corpus on an endpoint (`C:\yara_corpus` / `/opt/yara_corpus`): decoy detection strings, EICAR, UTF-16 file, 1 MB high-entropy blob, real PE/ELF binaries, nested dirs |
| `run_matrix.py` | Runs every rule file + flag/throttle/throughput variants as separate XDR actions on both machines (bounded concurrency), recording `results/matrix.jsonl` |
| `analyze.py` | Summarizes results, cross-checks the `yara_scanner_matches` / `yara_scanner_scans` datasets, computes the compile-time-vs-rule-count curve and big-folder throughput, and flags anomalies |

## Run it

```bash
export XDR_CA_BUNDLE="$(.claude/skills/xdr-yara-scan-test/scripts/make_ca_bundle.sh)"   # corporate proxy only
python3 tests/gen_rules.py                     # -> tests/yara_rules/*.yar
python3 xdr_action_center.py run-snippet --hostname <win-host> --code-file tests/seed_corpus.py   # seed Windows
# (Linux corpus can be seeded the same way, or over SSH)
python3 tests/run_matrix.py                    # -> tests/results/matrix.jsonl
python3 tests/analyze.py                       # summary + XDR cross-check + perf + anomalies
```

## What the matrix covers (per machine)

- **All 20 rule files** against the seeded corpus (compilation + matching correctness).
- **Output flags:** `create_alerts=false`, `write_dataset=false`, `collect_files=true`.
- **Throttle modes:** `throttle_mode=os`, `throttle_mode=off` (with the 500-rule pack).
- **Throughput:** a real large folder (`C:\Windows\System32` / `/usr/bin`).
- **Cancellation** is exercised separately (start a long scan, deliver `mode=cancel`).

Each action is independent and its `action_id` is recorded, so any result can be traced in the
XDR Action Center and correlated with the lookup datasets.

> The seeded corpus and rule files contain benign detection *signatures* (e.g. `mimikatz`,
> EICAR) as plain text so scans produce deterministic hits — there is no live malware.

## Verified — xdr_data_management.py (2026-08-02)

Live dry-run verification against the EU tenant:

- `--report` listed **12** YARA lookup datasets: 6 rotated (`_202607`, 1 month old) and
  6 unsuffixed pre-rotation leftovers, correctly labelled `frozen` because rotated
  siblings exist for the same host+kind.
- `--older-than-months 0` selected only the 6 rotated datasets and printed
  `DRY RUN - nothing deleted`. No unsuffixed dataset was ever a candidate.
- A bare `--yes` printed the report and deleted nothing (no window given ⇒ nothing
  selected), confirming `--older-than-months` having no default is a real safety rail.
- Live deletion is deliberately NOT automated. This is a shared tenant and
  `delete_dataset` is irreversible.

Found by this run: unsuffixed datasets sitting beside rotated ones are *abandoned*, not
evidence of `rotation=none`. The original message told operators to enable a setting that
was already enabled. Fixed via `has_rotated_sibling`.
