# XSIAM YARA Scanner — Live Acceptance Testing, All Rounds

All **297 catalogued XSIAM capabilities** were assigned to a round or to an
explicitly-reasoned `not covered`, and every assigned criterion was then executed against
live endpoints on the XSIAM tenant.

| Round | Theme | Criteria | Pass | Fail | Endpoints |
|---|---|---|---|---|---|
| **1** | Resource discipline | 53 | **53** | 0 | `xsoar`, `OfficeiMac` |
| **2** | False-positive flood | 106 | **106** | 0 | `xsoar`, `thor` |
| **3** | Precision and resilience | 113 | **113** | 0 | `xsoar`, `OfficeiMac`, `thor` |
| — | Not covered, with reasons | 25 | — | — | — |
| | **Total** | **297** | **272** | **0** | |

25 archived run bundles and 15 targeted probes. Every criterion is decided from evidence
on disk — the endpoint's own logs and artefacts plus the events that reached
`yara_scans_raw` on the tenant — not from a scan's exit status.

---

## Defects found and fixed

### 1. The delivery books double-counted on cancelled runs

A whole-filesystem scan cancelled mid-walk read the same counter three times, 500 apart:

```
[15:13:57] Match delivery final: matches=69150 ok=56504 failed=0 undelivered=12146
result line                    :                ok=57004        undelivered=12146
scan_summary_<run_id>.json     :                ok=57504        undelivered=12146
```

`undelivered` froze while `ok` climbed by exactly one batch at a time, so
`ok + undelivered` reached 69,650 against 69,150 findings — 500 items in two buckets at
once. The same log named the cause at the same timestamp as its own "final" ledger:
`Upload thread did not terminate within 60s timeout`.

`_upload_worker` consulted `stop_upload_thread` only in its `except Empty` branch, which
is unreachable under exactly the condition the flag exists for: a full queue never raises
`Empty`. After `stop()` spent the drain budget and queued a sentinel behind 12,146 items,
the loop kept sending; the join timed out; `stop()` booked the still-queued items
`undelivered`; and the live thread then delivered 1,000 of them into `successful_uploads`.

**Fixed** by checking the flag before taking work. `stop()` has already spent the whole
backlog-proportional budget by then, so anything still queued is past its window and
belongs in `undelivered` — which is what the field is documented to mean.

Verified live at three scales, balancing to the item each time:

| Run | Findings | ok + failed + undelivered |
|---|---|---|
| cancelled whole-filesystem | 61,186 | 35,504 + 0 + 25,682 ✓ |
| Linux whole-machine | 925,507 | 255,516 + 0 + 669,991 ✓ |
| Windows whole-machine | 2,574,430 | 2,100,002 + 0 + 474,428 ✓ |

This mattered beyond arithmetic: the operator's result line derives its shortfall
denominator from `ok+failed+undelivered`, so an inflated sum understated the loss
percentage while overstating both totals — in the one scenario the counter exists for.

### 2. Worker throughput logging was unbounded, and shipped

A 323,261-file scan wrote 3,260 `Worker Performance |` lines — 99.5% of a 390 KB
performance log, burying the six governor samples that diagnose a scan. XQL showed the
same events were **shipped**: 3,274 of the 3,475 events that run delivered, 94% of the
customer's ingestion for it.

The trigger was `files_processed % 100 == 0`, tying volume to the host's file count. A
10M-file server would ship ~100,000 events and write ~12 MB per run.

**Fixed** by keeping the 100-file trigger as the sampling point and gating emission on a
per-worker 30 s interval, matching the governor and progress heartbeats. Volume now scales
with scan duration. Live: 636 events → 22 on the same target.

### 3. The reference promised a worker cap that had been removed

The entry described `max(1, min(2, configured_workers))` with a "hard ceiling 2 even if
YARA_THREADS is larger". The code has read `max(1, configured_workers)` since the clamp
was removed, so the entry told operators the opposite of what ships. Its Observe field
also instructed the reader to set `YARA_THREADS=99` and "confirm max_workers<=2" — a test
that asserts the bug.

Corrected, and the reason 2 remains the *default* recorded: this work is disk-bound.
Measured on `xsoar` over `/usr` (63,304 files): **1 worker 41.24 s, 2 workers 41.52 s,
8 workers 46.55 s**. Eight is 12% slower than two.

### 4. The queue-saturation notice is unreachable in normal operation

Five entries pointed at `Scan queue saturated (N items)` as the way to observe producer
backpressure. Measured with 1 worker behind a 2-slot queue — the tightest configuration
the knobs allow — it was emitted **zero** times over 63,304 files.

It lives inside `except Full`, and `put()` uses a 1.0 s timeout, so raising `Full` needs
the queue full for a whole second while a worker drains a file in ~0.7 ms. Backpressure
itself is fine: `put()` blocks, nothing is dropped, and `files_scanned + files_skipped`
reconciles exactly. Queue **depth** is the signal that works. Documentation corrected.

### 5. The alert-rotation entry was silently Windows-specific

It told readers to "wait past the scheduled time" for the `.txt` → `.alert` rotation. On
Linux there is nothing to wait for: `_schedule_linux_cleanup` ends with
`systemctl start yara-cleanup.service` — synchronous, `check=True`, against a
`Type=oneshot` unit whose `ExecStart` is the rename script — so the rotation completes
inside the scan's own finalisation.

```
RUN1: Scan completed: 5 files scanned | 1 rules failed compilation
AFTER_SCAN1   alert: ['lc_ok.alert']     <- already rotated
CLEANUP_RC: 0
AFTER_CLEANUP alert: ['lc_ok.alert']     <- nothing left to rename
```

"Scheduled" was accurate for Windows, where the task is registered but not started. The
heading and Observe now say which platform does which.

---

## What the rounds established

**Resource discipline.** The CPU governor is effectively free when it is not pacing —
39.82 s (sd 1.81) with it against 37.89 s (sd 0.82) without, across three runs each, a gap
smaller than the within-configuration spread. `ratio` stayed 0.0 throughout: two workers
on sixteen cores peak near 12% own share, so a 70% target is never approached. The
governor only becomes load-bearing at high worker counts.

**Caps degrade detail, never counts.** A 6,000-hit storm finding shipped `match_count:
6000` and `match_ids: {"$h": 6000}` — the complete per-string-ID census — alongside 50
sampled offsets and `truncated: true`. The alert file on disk agrees.

**Delivery has two channels and only one publishes its request count.** The flood shipped
16,055 events: 12,001 `yara_match` on the match channel, 4,054 telemetry over 9 requests —
450 per request, inside the 500 cap. `match_delivery` books *findings*, not requests, so
dividing all events by the telemetry request count reports ~1,784 and looks like a cap
violation. It is the wrong denominator.

**Every event carries the same envelope.** `hostname`, `ipAddress`, `level`, `message`,
`os_info`, `scan_id`, `source`, `timestamp`, `timestamp_iso`, `type`, `uploader_version`,
across all 8 sampled types. (`ipAddress` reads `Unknown` on `xsoar`; the summary agrees,
but neither carries a usable address on that host.)

**Malformed packs split as designed, identically on all three platforms.** An 11-rule pack
with one syntax error and one import of an unavailable module yielded 9 valid / 1 failed /
1 **skipped** everywhere — skipped and failed staying separate numbers, the distinction
that was conflated once before. The parser counted 11 declarations, not 15, ignoring
`rule` planted in a line comment, a block comment, a string literal and a meta value.

**Cancellation is honest about what it lost.** `Scan cancelled (source=action_center)`,
never "completed", with `failed=0` separated from `undelivered` — nothing rejected, those
were never attempted — and `control/` empty afterwards, so the flag is consumed rather
than left to shadow the next run. A 24-hour-old flag planted before module import neither
fires nor lingers.

**Skip predicates are selective, not blanket.** Each was tested with a positive *and* a
negative case, because "it skipped something" and "it skips everything" are
indistinguishable otherwise:

| Predicate | Skipped | Scanned |
|---|---|---|
| Vendor agent root | `/opt/traps/` — 4,825 real files, 0 scanned | `/opt/traps-backup/` sibling |
| Bounded fragment | `node_modules/` | `node_modules-bk/` |
| Extension / filename | `.iso`, `.vmdk`, `.dmg`, `.DS_Store`, `Thumbs.db`, `desktop.ini` | `control.txt` |
| Windows junction | `Application Data` (legacy name) | benign `jlink` |
| Browser carve-out | `library/caches/other_app/`, and firefox under `/volumes/` | firefox, Safari, Chrome caches |

**Platform divergence is real and documented.** macOS skips one extra file per identical
tree (AppleDouble/`.DS_Store`); `disk_io_mb` is structurally zero there (`R:0.0MB` against
Linux's `R:937.1MB`) while CPU and memory still report; and the scheduled cleanup never
runs on Darwin — the script is written on both platforms, but only Linux ends up rotated
(macOS 7 `.txt` / 0 `.alert` against Linux 7 `.alert`).

**Windows default scope is every mounted volume.** No target selects `C:\ D:\ E:\ J:\` —
three fixed plus one removable *with media*. `win_skip_drive` is empty by default, so
nothing is excluded by policy; the absent letters are empty card-reader slots failing
discovery's readiness check. Worth knowing operationally: a USB stick left in a server is
in scope by default.

---

## Not covered — 25, each with a reason

Recorded as `not_covered` rather than left blocked, because none can pass.

### unsafe-injection (4)
Reproducing these means damaging a live host or a shared tenant.

- `PERF-010` Governor fail-open when CPU cannot be read
- `DELI-006` Circuit breaker on the telemetry channel
- `DELI-055` Circuit-open batches go to the tail of the upload queue
- `LIFE-024` Critical-error path in `main()`

### wont-run (6)
The input cannot be delivered, or the platform does not exist on this tenant.

- `RULE-002` Rule input size cap — a >50,000,000-character argument exceeds both the
  Action Center parameter field and POSIX `ARG_MAX`
- `RULE-029` Split-stage failure isolation
- `TRAV-008` Unknown-platform target fallback — needs an OS that is not Windows, Linux or
  macOS
- `TRAV-031` No directory skipping on unrecognised platforms — same
- `LIFE-022` Fatal worker failure path
- `LIFE-065` One failing scan target abandoned mid-walk while the rest continue

### needs-instrumentation (5)
The code emits nothing an external observer can read.

- `PERF-009` Governor sampling cadence
- `PERF-045` File-descriptor leak sampling
- `RULE-044` Dead cached-hit dict ingestion path
- `TRAV-045` macOS case-sensitivity probe file
- `DELI-047` Upload channels can be disabled independently

### no-artefact (4)
The value exists only inside a call, or the collector normalises the distinction away.

- `RULE-021` Compile-time externals declaration
- `TRAV-037` Second-line skip check inside the worker — shares one `skip_reasons` key with
  the producer's, so no artefact separates the two arms
- `DELI-004` Approximate byte accounting for batch sizing
- `DELI-053` Critical-path events post single-object JSON, not NDJSON

### cannot-construct (3)
No input we can choose reliably produces the shape.

- `RULE-028` Un-splittable pack forensics
- `RULE-033` Combined-compile failure reporting — needs rules that pass individually but
  fail together
- `TRAV-018` File-level junction skip — needs a FILE-type reparse point; `mklink /J`
  creates directory junctions only, and a file symlink needs a privilege we lack

### disabled-by-design (1)
- `TRAV-019` Real-path deduplication — present but deliberately off, so there is no
  behaviour to observe

### unreachable (1)
- `PERF-013` Governor sampling during producer backpressure — inside `except Full`, which
  a 1.0 s `put()` timeout makes unreachable; measured at zero with 1 worker and a 2-slot
  queue

### no-delivery-path (1)
- `LIFE-025` KeyboardInterrupt handling — Action Center has no signal channel to a running
  payload; console Cancel hard-kills instead, which is a different path

---

## Open follow-up

**Junction cycle protection.** `_should_skip_junction` prunes only six legacy Windows
names, and real-path deduplication is present-but-disabled (`TRAV-019`). A junction
pointing at one of its own ancestors without a legacy name therefore has cycle protection
from neither mechanism. Verified live that a benign junction *is* followed (3 files scanned
where 2 were planted). Deliberately not probed further — confirming it on a live endpoint
means hanging the endpoint. Tracked separately.

---

## Notes for whoever runs this next

The harness lessons that cost the most time, so they need not be rediscovered:

- **Action Center truncates a script's stdout at 10,240 characters.** Bulk evidence must be
  compressed and chunked back; a single-line base64 of any real log arrives cut mid-stream.
  It bit twice more: a chunk that comes back short is a *hole*, not an end (validate the
  length and retry, or the stream dies on a zlib checksum after every individual call
  "succeeded"), and on a whole-machine Windows scan thousands of per-file error lines
  filled the budget and pushed out the `SUMMARY_PATH` the collector keys on.
- **Knobs are read at module import.** A snippet *is* the module, so the env prelude must
  precede the scanner source. Setting `YARA_THREADS` in the footer changes nothing while
  appearing to work.
- **macOS cannot scan targets under `/tmp` or `/var`.** Both are in the macOS skip list and
  `TMPDIR` resolves under `/var/folders`, so a target there is rejected as "No valid scan
  directory" before any predicate runs. `/Users/Shared` works.
- **A seed directory must not collide with `YARA_SCANNER_DIR`.** The scanner correctly
  self-skips its own directory, so a colliding target scans nothing and reports
  "1 requested target(s) EXCLUDED by the skip list".
- **Several capabilities can only be decided on the tenant.** `system_resource_snapshot`
  and `resource_monitoring_summary` appear in no log file; they exist only in
  `yara_scans_raw`, queried by `scan_id`.
