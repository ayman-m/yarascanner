# XSIAM YARA Scanner — Live Acceptance Testing, All Rounds

All **297 catalogued XSIAM capabilities** were assigned to a round or to an
explicitly-reasoned `not covered`, and every assigned criterion was then executed against
live endpoints on the XSIAM tenant.

| Round | Theme | Criteria | Pass | Fail | Endpoints |
|---|---|---|---|---|---|
| **1** | Resource discipline | 55 | **55** | 0 | `xsoar`, `OfficeiMac` |
| **2** | False-positive flood | 107 | **107** | 0 | `xsoar`, `thor` |
| **3** | Precision and resilience | 114 | **114** | 0 | `xsoar`, `OfficeiMac`, `thor` |
| — | Not covered, with reasons | 21 | — | — | — |
| | **Total** | **297** | **276** | **0** | |

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

### 6. The macOS case probe ran once per FILE

`_is_case_sensitive_fs()` decides case-folding by experiment on Darwin — create
`/tmp/CaSe_TeSt_YaRa_<pid>`, write, stat the lowercased name, unlink. It is reached from
`_get_real_path()`, which `scan_file()` calls for every file past the pre-checks.

A live macOS run scanned 48,921 files, so ~49,000 create/write/stat/unlink cycles in
`/tmp` to re-answer a question whose answer cannot change while the process lives. It was
also the scanner's only per-file WRITE: a tool that reads the disk looking for malware
should not leave tens of thousands of file creations behind on the host it is scanning.

**Fixed** by answering once and caching for the process, under a lock so racing workers
cannot double-probe. A failed probe is cached too — otherwise an unwritable `/tmp` costs
one exception per scanned file. Verified live: **400 files → 1 probe**, 0 leftover files.

### 7. FD leak sampling barely ran, raced, and stayed silent

The check sat at the end of `scan_file`, after six early returns including
`return True, "Scanned and matched"`. Three defects in one block:

- **Reach** — it ran only on files scanned that did *not* match. On the Round 2 flood
  (8,003 files, 4,002 matching) over half the scan bypassed it; against a ruleset matching
  everything it never ran at all. FD monitoring went quiet exactly when the scanner held
  the most handles.
- **Race** — `files_since_fd_check += 1` ran unlocked from every worker, so the
  read-modify-write dropped increments and the effective interval was longer than
  configured and unpredictable.
- **Silence** — only threshold breaches emitted anything, so "sampled 40 times, all
  healthy" and "never sampled" left identical evidence.

**Fixed** by extracting `_maybe_sample_fds()` and calling it before any early return, under
`lock_counts`, recording `fd_samples_taken` and `last_fd_count`. Verified with a ruleset
matching **every** file — the configuration that previously yielded zero samples: 500
files, 500 matches, **10 samples at interval 50**.

### 8. An unreachable match path that would have corrupted silently

`_iter_hit_fields` accepted a second shape: a dict whose `strings` were
`(offset, id, hex-text)` triples rehydrated with `bytes.fromhex`. That implies a match
cache the scanner does not have. Enumerated: three call sites all iterate `matches`;
`matches` has one binding, `self.rules.match(...)`, which returns `Match` objects;
`_write_alerts` takes it as a parameter but has a single caller passing that local; no
module outside the scanner imports it.

Removed rather than kept "for safety", because it was not safe — its decode fallback was
`hx.encode("utf-8", errors="ignore")` on anything `bytes.fromhex` rejected, so a non-hex
string produced **wrong bytes silently** instead of raising.

**The deletion surfaced more than itself.** Six alert offset-cap tests were building
dict-shaped hits, so the cap that prevents a 220 MB alert file had only ever been
unit-tested through the branch production never runs. The behaviour was correct — a live
storm-file scan showed `Matched Strings (showing 50 of 6000)` — but those tests were not
what confirmed it. The fixture now builds a Match-shaped hit carrying bytes rather than
hex text, which is the difference that let the two paths drift apart unnoticed.

I had checked for importers outside the scanner and found none, which was true. I had not
counted the test suite as a consumer. It was.

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

## Not covered — 21, each with a reason

Recorded as `not_covered` rather than left blocked, because none can pass.

### unsafe-injection (4)
Reproducing these means damaging a live host or a shared tenant.

- `DELI-006` Circuit breaker on the telemetry channel
- `DELI-055` Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-bounce) — Circuit-open reordering requires an induced collector outage mid-scan. The only way to cause one on this tenant is to break the collector for every ot…
- `LIFE-024` Critical-error path in main() — The critical-error path needs an induced fatal failure inside main(). Causing one on a live endpoint means deliberately corrupting the scanner's own s…
- `PERF-010` Governor fail-open when CPU cannot be read — Reaching the fail-open branch needs psutil's CPU read to raise, which cannot be induced on a live endpoint without breaking the host.

### wont-run (6)
The input cannot be delivered, or the platform does not exist on this tenant.

- `LIFE-022` Fatal worker failure path — Requires injecting a failure we cannot safely cause: scan_file's blanket handler (5093-5099 equivalent) and _worker's inner handler (4859-4866) absorb…
- `LIFE-065` One failing scan target is abandoned mid-walk; the rest of the scan continues and still reports success — Requires injecting a failure we cannot safely cause on a live tenant. The handler only fires for non-OSError exceptions raised by the loop body (log_m…
- `RULE-002` Rule input size cap — Cannot deliver the input. A >50,000,000-character argv value exceeds both the Action Center script-parameter field and POSIX ARG_MAX (~2 MB on the xso…
- `RULE-029` Split-stage failure isolation — Requires injecting a failure we cannot cause. _get_yara_top_level_statements is a total character-scanner over any str input (no regex backtracking, n…
- `TRAV-008` Unknown-platform target fallback — Requires a platform we do not have. The branch fires only when platform.system() is neither 'Windows', 'Linux' nor 'Darwin'; every endpoint in the XSI…
- `TRAV-031` No directory skipping on unrecognised platforms — Requires a platform we do not have. The final else-branch of _is_special_file (5230-5231) and the empty-list assignment in ScanConfig (3084-3086) exec…

### no-artefact (4)
The value exists only inside a call, or the collector normalises the distinction away before it lands.

- `DELI-004` Approximate byte accounting for batch sizing — The per-batch byte estimate is internal to batch assembly and is never reported. Batch OCCUPANCY is observable and is covered by DELI-003; the byte ac…
- `DELI-053` Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the collector sees — The collector normalises single-object JSON and NDJSON into the same rows, so yara_scans_raw cannot distinguish the two framings. Proving it needs a p…
- `RULE-021` Compile-time externals declaration — The externals set is declared inside the compile call and never surfaces in any log, event or file. Nothing an external observer can read distinguishe…
- `TRAV-037` Second-line skip check inside the worker — The worker's second-line skip check writes the same skip_reasons key as the producer's, so no artefact separates the two arms. Closing it needs instru…

### cannot-construct (3)
No input we can choose reliably produces the shape.

- `RULE-028` Un-splittable pack forensics — Needs a pack the splitter cannot divide at all. Every malformed pack tried still splits; producing one that defeats the splitter without also defeatin…
- `RULE-033` Combined-compile failure reporting — Needs rules that compile individually but fail in combination. That is a property of libyara's namespace handling, not something a chosen input reliab…
- `TRAV-018` File-level junction skip, counted — The counted branch needs a FILE-type reparse point. mklink /J creates directory junctions only (removed by the dirs[:] filter, which increments no cou…

### unreachable (1)
A guard upstream makes the branch unreachable in normal operation.

- `PERF-013` Governor sampling during producer backpressure — The _sample_governor() call sits inside `except Full`, and put() uses a 1.0 s timeout. Measured with 1 worker behind a 2-slot queue — the tightest con…

### disabled-by-design (1)
Present but deliberately off, so there is no behaviour to observe.

- `TRAV-019` Real-path deduplication (present but disabled) — Real-path deduplication is present but deliberately disabled, so there is no behaviour to observe. Its absence is recorded against the junction-cycle …

### no-delivery-path (1)
There is no channel through which the trigger can be delivered.

- `LIFE-025` KeyboardInterrupt handling — KeyboardInterrupt cannot be delivered to a payload through Action Center — there is no signal channel to the running script. Console Cancel hard-kills…

### deleted (1)
Removed from the scanner after its unreachability was enumerated.

- `RULE-044` Dead cached-hit dict ingestion path in match-field extraction — Deleted. The dict arm was unreachable in production: three call sites all iterate `matches`, which has one binding to self.rules.match() returning Mat…

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
