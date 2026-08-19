# XDR Round 1 — Resource discipline and host footprint

**IN PROGRESS.** 6 legs delivered and their evidence collected; 13 of 134 criteria scored so far. The remaining criteria have no check written yet and are recorded `not_run`, never assumed to pass.

## The leg matrix

Sequential by design: two scans on one host contend for the CPU and I/O this round
measures, so a concurrent run would measure the wrong thing.

| Leg | Configuration | Files | Duration | Outcome |
|---|---|---|---|---|
| A | defaults | 93,127 | 108.5s | completed, fresh compile |
| B | `cpu_guarantee=none` | 93,127 | 65.8s | completed |
| C | `cpu_guarantee=budget,cpu_budget_pct=25,cpu_floor_pct=10` | 93,127 | 69.6s | completed |
| D | `cpu_guarantee=bogus` | 0 | — | **aborted, by design** |
| E | `YARA_SCANNER_DIR=/opt/yara_lab`, monitors off, FD on, `YARA_WORKER_REPORT_SECS=0` | 93,127 | 53.4s | completed |
| F | `workers=2`, cadences shortened, `YARA_QUEUE_SIZE=100` | 93,127 | 50.8s | completed |

Endpoint `xdr-agent` (Ubuntu 22.04, e2-highcpu-8, agent 9.2.0.134), target `/usr`,
ruleset a single sentinel string that matches nothing — Round 1 measures resource
discipline, and findings are Round 2's subject. Delivery channels stayed ON throughout,
because the delivery books are themselves catalogued capabilities.

## Scored so far

| ID | Pri | Capability | Status | Evidence |
|---|---|---|---|---|
| `LIFE-001` | core | Action Center scan entry point (main) — only 3 opera | pass | no options string; posture resolved to 'alerts=on dataset=on files=off cpu=headroom mode=scan' |
| `LIFE-075` | core | Run identity: run_id, scan_id and their propagation | pass | run_id=20260819_035240_307745 scan_id=xdr-agent_20260819_035240_307745_yara_ed2487d26819; 9 artefacts all carry it |
| `PERF-001` | core | CPU governor policy selector (headroom / budget / no | pass | A=headroom B=none(samples 0, paused 0) C=budget; D aborted on bogus |
| `PERF-003` | core | Budget policy — fixed cap on the scanner's share | pass | target=25.0 constant across 2 samples, floor_hits=0 |
| `PERF-017` | core | Worker thread count and the auto (cores // 2) mode | pass | workers=2 honoured: declared=2, distinct workers started=2 |
| `PERF-029` | core | Progress heartbeat thread (whole-scan progress telem | pass | leg A: 3 lines in 108s (~30s cadence); leg F at 5s: 8 lines in 51s |
| `PERF-079` | core | End-of-run performance summary lines | pass | 1 SCAN COMPLETED, 0 SCAN FAILED, 1 worker summary |
| `PERF-080` | core | Both psutil monitors are OFF by default — every perf | pass | no psutil monitor started by default; samples_collected=0 |
| `PERF-086` | core | Governor final state persisted as a structured cpu_g | pass | cpu_governor block complete and slept totals agree on every leg |
| `PERF-087` | supporting | Per-worker throughput reports are time-gated, not fi | pass | leg A: 8 lines for 93,127 files (ungated ~931, 116x fewer); leg E with the gate disabled: 932 lines |
| `PERF-088` | supporting | Governor sampling-cadence counters (`samples_taken`, | pass | samples_taken=101 vs 4 emitted line(s) (25x divergence), last gap 1.001s |
| `STOR-021` | core | Evidence ZIP creation and naming | pass | evidence_xdr-agent_20260819_035240_307745.zip produced on a zero-match run |
| `STOR-039` | core | rule_cache/ — compiled-ruleset disk cache (XDR-only; | pass | A fresh (0.01s) -> B cache (0.0s) |

## What the evidence shows

**The worker-throughput gate, proven from both sides.** Leg A emitted **8** `Worker Performance` lines for 93,127 files; leg E, with `YARA_WORKER_REPORT_SECS=0` disabling the gate, emitted **932** — against a predicted ungated count of ~931 (93,127 ÷ 100). A one-sided check would have shown only that the number was small.

**The governor's sampling counters make an unobservable capability observable.** Leg A sampled **101** times while emitting **4** `CPU_GOVERNOR` lines — a 25x divergence, with `secs_since_last_sample` at 1.001s. Four lines in 108 seconds is indistinguishable from stalled sampling without that counter, which is precisely why the capability was filed unobservable before this branch.

**An unrecognised governor policy aborts rather than falling back.** Leg D returned `Scan failed: ... Critical error occurred` and wrote no summary at all. A silent fallback to the default would have produced a clean-looking run under a policy the operator did not choose.

**The governor is close to free when it is not pacing.** All three policy legs paced zero seconds — on an idle 8-core host the headroom target (63.1%) sat far above the scanner's own share (18.5%). This matches the XSIAM measurement that the governor costs little when it has nothing to do.

## Harness defects found and fixed during the round

Recorded because each would have produced a wrong result rather than an error:

1. **Evidence mis-attribution.** The collector paired legs to on-host runs by ordered `zip()`. Leg D aborts and writes **no summary**, so every later leg shifted up by one — D was scored against E's run and E against F's. The posture guard could not catch it because E and F are both `cpu=headroom`. Attribution now walks the legs, consuming the earliest unclaimed summary matching that leg's full signature (scanner root **and** posture), and a leg that aborts consumes nothing.
2. **`run_snippet` returns a dict**, not a bare action id.
3. **`endpoint_stdout` returns `{endpoint_id: text}`**, and the two runners disagreed on coercing it. Normalised in the evidence layer rather than trusting the producer: a dict reaching a check surfaces as an AttributeError inside it and reads like a scanner defect.
4. **A remote tar glob expanded in the wrong directory**, silently producing an archive with no logs in it.

## Still to do

- Write checks for the remaining 121 criteria
- Legs for host cleanup (`CONFIG_HOST_CLEANUP` off / always / on_delivery), log retention across four runs, and queue saturation under a deliberately small queue
- Tenant-side XQL evidence for the lifecycle-row criteria (`LIFE-024`, `LIFE-025`, `PERF-034`, `TRAV-057`)
