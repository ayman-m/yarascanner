% YARA Scanner — Comprehensive Test & Performance Report
% Cortex XDR edition (`xdr_yara_scanner.py`, v2)
% 2026-07-10

---

# 1. Executive summary

The XDR YARA scanner was tested end-to-end on **two live Cortex agents** — a Windows and a
Linux endpoint — driven entirely through the Cortex XDR public API (`run_snippet_code_script`),
with results verified both in XDR (datasets + alerts) and on the endpoints themselves (logs,
evidence, artifacts). The battery: **20 YARA rule files** spanning 1 to 500 rules and every rule
shape, a deterministic seeded corpus, a **52-action scan matrix**, targeted concurrency
reproduction, and dedicated alert / logging / performance probes.

**Headline results**

- **Scanning correctness is excellent.** All 20 rule types matched correctly and
  platform-appropriately (PE modules fire on Windows, ELF on Linux); module auto-injection,
  duplicate-rule handling, failed-rule isolation, and 500-rule compilation all work.
- **The dataset concurrency limitation is SOLVED,** not merely mitigated: per-writer dataset
  sharding gives each endpoint its own lookup dataset, eliminating the server-side write race
  (verified **8/8** landing under 8-way concurrency, vs ~2/8 before). Dashboards fan the shards
  back in with a `dataset = yara_scanner_matches* | …` wildcard.
- **Alert aggregation is now deliberate.** Alert identity is a stable per-finding key
  (`rule + file@offset`), so alerts are 1:1 with distinct matches within a scan **and** idempotent
  across re-scans (a repeated scan adds 0 duplicate alerts).
- **Per-scan wall time roughly halved** (~45 s → ~22 s steady-state) by parallelizing the
  end-of-scan dataset drain and failing hung connections fast.
- **Endpoint logging and dataset telemetry were enriched** (structured `data` payloads now
  persisted, a machine-readable per-scan summary JSON, longer log retention, `os_type` /
  `file_size` / `scan_folder` / `matched_length` fields).

**Environment**

| | Windows | Linux |
|---|---|---|
| Host | Windows Server 2022 | Ubuntu 22.04 (GCP) |
| Agent | 9.2.0.90 | 9.2.0.134 |
| Embedded Python | 3.12.4 | 3.13.1 |
| yara | 4.1.0 | 3.11.0 |
| yara modules present | pe, elf, math, hash, time | pe, elf, math, hash, time |
| Execution context | SYSTEM | root |

---

# 2. Methodology

- **Rule files** (`tests/gen_rules.py` → `tests/yara_rules/*.yar`): 20 files, 1–500 rules,
  covering plain/wide/hex/regex strings, `pe`/`elf`/`math`/`hash` modules, meta severity, module
  auto-injection, deliberately-failing rules, cuckoo-skip, condition-only, external variables,
  duplicate rule names, a 200-string single rule, and a no-match pack.
- **Corpus** (`tests/seed_corpus.py`): decoy detection strings (mimikatz, ransomware, LOLBin,
  webshell, PowerShell, Cobalt Strike), EICAR, a UTF-16 file, a 1 MB high-entropy blob, real
  PE/ELF binaries, and nested directories.
- **Matrix** (`tests/run_matrix.py`): 52 actions — every rule file + output-flag variants +
  throttle modes + a large-folder throughput scan — each a **separate XDR action**.
- **Concurrency probes:** repeated N-way concurrent scans with unique `tenant_id` markers,
  counting landed rows in the lookup datasets and alerts, across shared-dataset, jittered, and
  per-writer-sharded strategies.
- All orchestration went through **`xdr_action_center.py`**, the unified API toolkit.

> Wall-clock timings include per-action agent scheduling/startup overhead; treat them as relative.

---

# 3. Correctness results

All actions completed with **zero execution errors**. Representative confirmations:

| Rule file | Windows | Linux | Confirms |
|-----------|---------|-------|----------|
| `01_single` (1 rule) | 2 | 2 | basic string match |
| `03_hex` | 2 (PE MZ) | 3 (ELF magic) | byte-pattern + platform specificity |
| `05_wide` | 3 | 2 | UTF-16 wide strings (incl. inside notepad.exe) |
| `06_module_pe` | 4 | 0 | `pe` module — Windows only |
| `07_module_elf` | 0 | 6 | `elf` module — Linux only |
| `08_module_math_hash` | 1 | 1 | **`math` auto-injection** (no `import` line) |
| `11_externals` | 14–15 | 15 | `filename`/`filepath` externals (**after fix**; was 0) |
| `12_mixed_failing` | 3 match / 2 failed | same | failed rules isolated, scan continues |
| `18_dup_names` | 4 | 4 | duplicate rule names namespaced |
| `15_big_500` (500 rules) | 22 | 22 | large-set compilation + matching |
| `20_no_match` | 0 | 0 | clean-scan path |

> `11_externals` is a filename/path-matching rule, so its exact count tracks the precise corpus
> contents on the host (which drifted by one file across many test runs). The telemetry/schema
> changes made in this pass touch only how matches are **recorded**, never how they are **found** —
> detection counting is separated from the upload layer.

---

# 4. Performance

## 4.1 Compilation is cheap; wall time is dominated by delivery, not compile

An early read of the concurrency-4 matrix suggested compile time scaled steeply with rule count
(500-rule scans ran ~110–122 s wall vs ~40 s for one rule). **Direct measurement corrected this:**
with the scanner now reporting `compile_seconds` in the scan summary, a **500-rule pack compiles
in ~0.17 s** (measured on Linux/yara 3.11); the pack's whole cold run is ~27 s wall. The earlier
80-second spread was **add_data delivery latency and agent overhead under the old sequential
drain**, not compilation. For the simple string/hex/regex rules in the test packs, compile is not
the bottleneck at any size up to 500.

| Rules | Fresh compile (measured) | Cached load |
|-------|--------------------------|-------------|
| 500 (simple) | ~0.17 s | ~0.02 s |

A **disk rule-cache** (`rules.save()`/`yara.load()`, content+version-keyed) was still added — it is
near-free, falls back safely on any load failure, and pays off for genuinely expensive compiles
(very large or regex-heavy packs). For the test corpus its benefit is marginal because compile was
already sub-second. `compile_source` (`fresh`|`cache`) and `compile_seconds` are in every scan
summary so the effect is measurable per run.

## 4.2 Throughput on a large folder

| Target | Files | Wall | Files/s (incl. overhead) |
|--------|-------|------|--------------------------|
| Windows `C:\Windows\System32` | 14,962 | 70 s | ~214 |
| Linux `/usr/bin` | 985 | 43 s | ~23 |

The Linux figure is **byte-bound, not file-bound** (`/usr/bin` holds fewer but much larger ELF
binaries). Both stayed within the light-profile CPU envelope (`paused=0 s`).

## 4.3 Per-scan finalization cost — investigated and halved

A trivial 10-file scan was taking ~45 s wall even though the **scan itself finished in <1 s**.
Merging the endpoint logs by timestamp pinpointed the cost: it is **entirely in the lookup
`add_data` POSTs**, not the scan. Each `add_data` merge is **~10 s server-side**, and a single
hung TCP connection burned another ~22 s before retry.

Two client-side fixes were applied:

- **Parallel drain.** The matches and scans datasets are *different* datasets, so their two slow
  POSTs are now flushed concurrently at shutdown instead of back-to-back.
- **Fast-fail connect timeout.** `add_data` now uses a `(connect=5 s, read=30 s)` timeout so a
  hung connection retries in seconds while still tolerating the slow merge.

**Result: steady-state per-scan wall ~45 s → ~22 s.** The first scan on a *new* endpoint is a bit
higher (~32–50 s) because it also pays a one-time `add_dataset` creation (~10 s); every subsequent
scan reuses the dataset.

## 4.4 Throttle

Under the (idle) test hosts no CPU pressure occurred, so `total_paused_secs=0` across all modes;
`throttle_mode=os`/`off` completed identically to `script`.

---

# 5. Bugs found & fixes

## 5.1 FIXED — `filename` / `filepath` externals were non-functional
`YARA_COMPILE_EXTERNALS` declared only `filepath`, and the match call never populated it. **Fix:**
declare both externals and pass `externals={"filepath": path, "filename": basename}` to
`rules.match()`. Verified: `11_externals` went from **0 → 14–15 matches**.

## 5.2 SOLVED — lookup-dataset row loss under concurrent writes
**Root cause:** XDR's `lookups/add_data` stages each write through a per-write BigQuery clone table
and holds the dataset through a slow merge; concurrent writes to the **same** dataset collide with
`HTTP 500 … clone was not found`. Time-spreading can't fix it — even **45 s of pre-write jitter
across 8 writers still lost 7/8**, because a single write's merge conflicts for a long window.

**The fix — per-writer dataset sharding.** Each endpoint writes its own dataset
(`yara_scanner_matches_v2_<host>`, `yara_scanner_scans_v2_<host>`), so no two writers ever touch
the same dataset. Verified landing:

| Strategy | 8-way concurrent landing |
|----------|--------------------------|
| Shared dataset | ~2/8 (25%) |
| Shared + 45 s jitter | 1/8 |
| **Per-writer shard** | **8/8 (100%)**, and *faster* (no retries) |

Dashboards fan the shards back in with a wildcard — **verified that XDR XQL supports both
`dataset = yara_scanner_matches*` and `union`** — so fleet-wide views are unchanged. The
per-endpoint model gives exactly one writer per dataset because an endpoint runs its scans
serially. Sharding is configurable (`lookup_shard` option / `YARA_LOOKUP_SHARD`): `endpoint`
(default), `none` (legacy shared), or a literal wave/site label. Light client-side insurance
(bigger batches, small pre-write jitter, full-jitter retries) remains for the rare case of two
scans on the *same* host.

## 5.3 FIXED — alert aggregation not 1:1 with matches
Alert identity embedded the scan timestamp, which (a) collapsed distinct matches sharing a
millisecond and (b) minted brand-new alerts on every re-scan. **Fix:** alert identity is now a
stable per-finding key (`YARA Match: <rule> | <file>@<offset> | Host: <host>`). Verified: 2
distinct files → 2 distinct alerts; **re-scanning the same files added 0 new alerts** (XDR updates
the existing alert instead of duplicating). Aggregation is now a deliberate, controllable property.

## 5.4 FIXED — schema changes silently dropped rows
XDR lookup datasets have a fixed schema; `add_data` **silently skips** rows carrying fields the
existing dataset doesn't know about (observed `records_skipped=4, records_added=0`). **Fix:** the
dataset name carries a schema-version tag (`…_v2_…`); bumping it on any schema edit creates a fresh
dataset with the new shape, while the dashboards' `*` wildcard still spans old and new versions.

## 5.5 MINOR (documented) — unavailable-module rule counted as "failed" not "skipped"
A rule using an unavailable module via a top-level `import` (e.g. `cuckoo`) is reported under
"failed compilation" rather than "skipped". The rule correctly does not run either way; cosmetic.

## 5.6 Second-pass adversarial review — 9 fixes + 3 enhancements

A multi-agent adversarial review of the telemetry/concurrency/perf changes surfaced (and
independently verified) nine real defects, all fixed and re-tested live:

- **`verify` / CLI examples queried bare dataset names** — after sharding, `verify` and the docs
  read `yara_scanner_matches` (which no longer receives rows) instead of the `*` wildcard, so they
  reported 0 rows for scans that actually landed. Fixed to `yara_scanner_matches*` (verified: 4
  matches + 4 scan rows now surface).
- **A crashed scan was recorded as `outcome:"completed"`** in the summary JSON (the critical-error
  path never set `scan_failed`). Fixed so a crash records `outcome:"failed"`.
- **Alert identity collapsed same-basename files** — two different files sharing a basename merged
  into one alert. Fixed by folding a stable full-path hash into the identity.
- **`matched_length` used the rendered string length** (hex doubles, wide halves). Fixed to the
  match byte length.
- **Drain deadline < single-batch retry budget** — under a hung `add_data` endpoint the drain
  thread could be killed mid-POST, losing a batch *silently*. Fixed with a wall-clock deadline so
  loss is accounted and logged.
- **Producer-side `queued`/`dropped` counters** were unlocked; **orphaned `.json.tmp`** summaries
  were never pruned — both fixed.

Three enhancements were designed, built, and verified:

- **Cuckoo skip-vs-fail** — a rule using an unavailable module (e.g. `cuckoo`) is now counted as
  *skipped*, not *failed* (verified `13_cuckoo_skip` → `failed=0`, was 1).
- **Rule-compile disk cache** — content+version-keyed `save`/`load` with a counts sidecar; verified
  cold→`fresh`, warm→`cache`, identical matches.
- **`prune-datasets` CLI** — XDR *does* expose `delete_dataset` (v2) and `remove_data` (v1); the new
  subcommand classifies current-vs-legacy datasets and cleans up legacy/old ones (dry-run by
  default; `--yes` to execute).

**A second adversarial pass** (re-reviewing the fixes themselves) caught a further 8 issues — most
importantly a **silent detection regression the cuckoo fix had introduced**: a rule merely
*mentioning* an unavailable module name as a literal hunt string (e.g. `"cuckoo.conf"`) was being
skipped instead of compiled. Fixed by gating the module-usage check on the module actually being
imported in the source (verified: the literal-hunt rule now matches; genuine dropped-import rules
still skip). The pass also hardened the drain deadline (guarantee ≥1 attempt), the `prune-datasets`
classifier (dict-reply unwrap + refuse to prune *newer*-version datasets on a version skew), and
rule-cache edge cases (missing-sidecar count recovery, `.tmp` orphan sweep). Coverage tests
confirmed **cancellation** (cancelled mid-scan at 12,024/14,962 files), **CPU throttling**
(`paused=133 s` under load — previously untested), rule-cache **corruption fallback**, and the
delete path (v2 datasets preserved by the keep-guard).

---

# 6. Telemetry & logging enhancements

- **Structured log payloads persisted.** Log call sites passed a `data=` dict that was previously
  **dropped**; it is now serialized (capped) onto the line, so error types, failure reasons, worker
  stats, and scan scope survive in the logs.
- **Machine-readable per-scan summary.** Each run writes one `scan_summary_<run_id>.json`
  (outcome, duration, files, matches, rules, scan rate, throttle, **alert + dataset delivery
  counts**, top rules, and the resolved shard dataset names) — one file for tools to read instead
  of grepping six text logs. Written after the uploaders drain so delivery counts are final.
- **Longer, safer log retention.** Retention raised from 2 → 10 scans (configurable via
  `YARA_LOG_KEEP`) and now prunes the JSON summaries alongside the logs.
- **Richer dataset rows.** Matches gained `os_type`, `file_size`, `scan_folder`, `matched_length`;
  scan-lifecycle rows gained `os_type`, `scan_folder` — enabling OS-segmented and scope-aware
  dashboards without string-parsing `os_info`.

---

# 7. Recommendations

1. **Deploy with per-endpoint sharding (default).** It makes both detections *and* dashboards
   reliable at any fleet scale with no server changes.
2. **Point dashboards at the wildcard datasets** (`yara_scanner_matches*` / `yara_scanner_scans*`),
   as the shipped widgets now do.
3. **Detections remain alert-first.** `create_alerts=on` (default) feeds XDR incidents reliably and
   is concurrency-robust; the sharded datasets add fleet trend/hunting visibility.
4. **Compile is cheap** (~0.17 s for 500 simple rules); the disk rule-cache is a near-free safeguard
   that only matters for very large or regex-heavy packs. Per-scan wall is dominated by the ~10 s
   `add_data` delivery, not compilation.
5. **Expect ~10 s of `add_data` latency per dataset per scan.** For latency-sensitive fleets,
   `write_dataset=false` skips lookup writes entirely and relies on alerts; bump
   `YARA_LOOKUP_SCHEMA_VER` only when the row shape changes.

---

# 8. Reproducing this report

Everything is scripted and re-runnable (see `tests/README.md`):

```bash
export XDR_CA_BUNDLE="$(.claude/skills/xdr-yara-scan-test/scripts/make_ca_bundle.sh)"
python3 tests/gen_rules.py
python3 xdr_action_center.py run-snippet --hostname <host> --code-file tests/seed_corpus.py
python3 tests/run_matrix.py
python3 tests/analyze.py
```

The corpus and rules contain only benign detection *signatures* (mimikatz strings, EICAR) as plain
text — there is no live malware. All identifiers in this report are generic; no tenant, endpoint,
or credential values are included.
