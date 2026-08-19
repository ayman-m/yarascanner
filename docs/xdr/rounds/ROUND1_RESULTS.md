# XDR Round 1 — Resource discipline and host footprint

**13 legs delivered. 134 of 134 criteria have a check. 0 failures outstanding.**

| Status | All (134) | core (27) |
|---|---|---|
| pass | 66 | 24 |
| fail | 0 | 0 |
| blocked | 68 | 3 |

Two genuine defects were found, fixed, and **re-verified on a fresh live run** rather
than marked passed on the strength of the patch.

## The leg matrix

Sequential throughout: two scans on one host contend for the CPU and I/O this round
measures, so a concurrent run would measure the wrong thing.

| Leg | Configuration | Host | Files | Duration |
|---|---|---|---|---|
| A | defaults | xdr-agent | 93,127 | 108.5s |
| B | `cpu_guarantee=none` | xdr-agent | 93,127 | 65.8s |
| C | `budget=25%`, `floor=10` | xdr-agent | 93,127 | 69.6s |
| D | `cpu_guarantee=bogus` | xdr-agent | — | **aborted by design** |
| E | `YARA_SCANNER_DIR=/opt/yara_lab`, monitors off, gate disabled | xdr-agent | 93,127 | 53.4s |
| F | `workers=2`, cadences shortened | xdr-agent | 93,127 | 50.8s |
| G | `YARA_QUEUE_SIZE=8` | xdr-agent | 93,127 | ~60s |
| H | `YARA_LOG_KEEP=2` | xdr-agent | 93,127 | 46.5s |
| I | `CONFIG_HOST_CLEANUP="always"` | xdr-agent | 93,127 | ~55s |
| J | both psutil monitors ON | xdr-agent | 93,127 | ~60s |
| K | **6 CPU burners** — the only paced leg | xdr-agent | 93,127 | 129.8s |
| L | verification on the fixed build, queue=8 | xdr-agent | 93,127 | ~60s |
| M | **Windows**, `C:\Program Files` | xdragent2 | 1,721 | 19.1s |

## The two defects

### 1. Backpressure worked; its evidence did not exist

Leg G forced the queue to 8 against 97,430 paths and produced **zero** saturation log
lines. Backpressure itself was flawless — 93,127 + 4,303 reconciled exactly with the
default run and there were no enqueue failures, so paths are blocked on and never
dropped. But `_enqueue_scan_path` uses `put(timeout=1.0)`, so `Full` raises only after
the producer stalls a **whole second**, and eight workers drain a queue of eight in
~10ms. `queue_full_events` counted the event, but its only reader was the modulo-25
gate on that same unreachable line.

So "never saturated" and "saturated constantly without a full-second stall" left
identical evidence — and two catalogued capabilities name that line as what decides them.

Fixed by surfacing the counter in the run summary. The blocking behaviour is
deliberately unchanged: shortening the timeout would trade a real property (never drop a
path) for observability convenience.

### 2. The log-stats snapshot was half-live

Two completion records documented to carry identical stats disagreed, and one did not
agree with itself:

```
pre-fix   system      by_type sums 67, total_logs 67   consistent
          statistics  by_type sums 69, total_logs 67   2 over its own total
post-fix  system      55 / 55                          consistent
          statistics  55 / 55                          consistent, and identical
```

`get_upload_statistics()` returned `self.upload_stats.copy()`, and `dict.copy()` is
**shallow**: `total_logs` snapshotted by value, `by_type` handed back by reference and
still being mutated. The gap is exactly the records written between snapshot and
serialisation. Both editions carried it.

## What the evidence established

**The governor's anti-stall design, under real load (leg K).** Six burners drove
`others` to 75.5%, collapsing headroom's target to `100 − 60 − 75.5 = −35.5`. The floor
clamped it to 5.0 on **116 of 118 samples**, the controller wound the sleep ratio to
6.749 within its 20.0 limit, the actuator paced **170.9s**, and the scanner's own share
fell to 3.5% — while still completing all 93,127 files. It shrank; it did not halt.
Every other leg had `ratio 0.0` and `slept 0s`, so none of this was testable before.

**Two of this branch's own fixes, with controls.** The worker-throughput gate: 8 lines
for 93,127 files, against **932** on leg E with `YARA_WORKER_REPORT_SECS=0` — a
predicted ~931. The governor counters: 101 samples against 4 emitted lines, a 25×
divergence that made a capability catalogued *unobservable* into one you can assert on.

**An unrecognised policy aborts.** Leg D returned `Scan failed: Critical error occurred`
and wrote no summary. A silent fallback would have produced a clean-looking run under a
policy nobody chose.

**Host cleanup and retention, on disk.** Cleanup (`always`, keep=`summary`) left exactly
one artefact — its summary — removed the other eight, emptied `alert/`, `evidence/`,
`failed_rules/` and `control/`, and left `rule_cache` intact. The cleanup-off leg kept
all nine, so the opt-in half is proven too. Retention (`keep=2`) pruned four older runs
and left `/opt/yara_lab` untouched — retention is per scanner-dir.

**Lifecycle rows, tenant-side.** Leg F at a 5s heartbeat produced 7 running rows
advancing 13,361 → 84,011 on gaps of [5.0, 5.0, 6.89, 5.0, 5.06, 5.0], with the terminal
row matching the local summary exactly and `files_skipped` non-decreasing throughout.
These four can only be decided from the dataset: a row written locally and dropped in
delivery looks identical from the host.

## Harness defects — five, each producing a wrong RESULT rather than an error

1. **Evidence mis-attribution.** The collector paired legs to runs by ordered `zip()`;
   leg D aborts and writes no summary, so every later leg shifted up one and D was
   scored against E's run. The posture guard missed it because E and F are both
   `cpu=headroom`. Attribution now matches on full signature (scanner root **and**
   posture) and an aborting leg consumes nothing.
2. **A silent re-pin.** The pinned scanner is `chmod 444` on purpose, so `cp … 2>/dev/null`
   hit `EACCES` and the redirect swallowed it — legs J and K ran the **pre-fix** build
   while the log reported the new commit. Caught only because leg K's summary lacked a
   field the fix adds. Re-pinning now compares SHA-256 and exits non-zero on mismatch.
3. `run_snippet` returns a dict, not an action id.
4. `endpoint_stdout` returns `{endpoint_id: text}` and the two runners disagreed on
   coercing it — normalised in the evidence layer, so a dict cannot reach a check and
   read like a scanner defect.
5. A remote tar glob expanded in the wrong directory, silently archiving no logs.

## The 68 blocked, and what would decide them

`blocked` is not a pass. Each names the run that would settle it. The main clusters:

- **No run longer than 130s** — the performance ring buffer's 1000-sample cap, its
  band metrics, and the longer cadences need 300s–20min runs.
- **Windows-specific paths** — one Windows leg exists now, but the affinity capture
  (the agent pins 2 of 8 cores) and the scheduled-task cleanup need their own legs.
- **Unreadable-file handling** — every leg ran as root against `/usr`, so
  `No read permission` never appeared in any skip breakdown. Needs a planted unreadable
  tree scanned non-root.
- **FD monitoring** — leg J enabled it, but without pre-opened descriptors both
  thresholds stay silent, and `fd_samples_taken` has no reader, so "sampled and fine"
  cannot be told from "never sampled".
- **XQL for the remaining lifecycle fields** — captured for legs A, F and H only.

Several agents proved falsifiability rather than assuming it: a mutation harness copies
the evidence, corrupts exactly the value each check keys on, and confirms the check
flips to FAIL. All 15 checks in one chunk were verified that way.

## One criterion needs correcting, not the scanner

`PERF-009`'s threshold measures sampler liveness against `duration_secs`, which includes
rule compilation and the post-scan uploader drain — phases with no governor call site —
while its own continuity clause says the working phase. Two legs read as under-met
against the literal text and comfortably met against the working phase. The threshold
text should be fixed; the scanner is fine.
