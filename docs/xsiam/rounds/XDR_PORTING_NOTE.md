# Porting the round findings into the XDR edition — CLOSED

The three acceptance rounds were scoped to XSIAM, so every round-driven fix landed in
`xsiam_yara_scanner.py` alone and this file originally recorded the resulting drift.
That drift is now closed: all four defects and both observability additions have been
ported, each behind a test that was red for XDR first.

Nothing here was ported on the strength of the XSIAM finding alone. Each item was
re-derived against the XDR source, and three of the six turned out to differ in ways
that changed either the fix or its justification.

| # | Item | Outcome |
|---|---|---|
| 1 | FD sampling after the matched early return | Ported unchanged |
| 2 | Uncached macOS case-sensitivity probe | Ported, plus a bare `except:` |
| 3 | Unreachable dict-hit path | Ported, plus a dead producer XSIAM never had |
| 4 | Upload worker stop flag | Ported after its own analysis — the caveat did not bite |
| 5 | Worker throughput rate limit | Ported; the XSIAM justification does **not** transfer |
| 6 | Governor sampling counters | Ported unchanged |

---

## Where XDR differed

### 3. The dict path had a producer here

XSIAM's dict arm was unreachable because nothing could build a dict-shaped hit. XDR
contained `_serialize_matches()` — a complete JSON serialiser for match objects — which
XSIAM never had. It had **zero call sites of its own**: dead code feeding a dead branch.

Both were removed together. Deleting the consumer alone would have left a live-looking
helper whose output nothing could accept, which is a worse trap than either piece alone.

The XSIAM deletion broke six alert offset-cap tests that had been exercising the dead
arm. Nothing regressed here, because that earlier rewrite had already fixed the shared
`_hit()` helper for both editions.

### 4. The stop-flag caveat inverted on inspection

This note previously warned that XDR "deliberately holds `stop_upload_thread` false
during a rate-limited requeue window, so the XSIAM fix could cause the loss it prevents."

Reading `stop()` **in order** shows the window closes before the flag is set:

1. queue the storm rollups
2. drain, requeue **enabled**, flag still `False` ← the deliberate window
3. `self.stop_upload_thread = True` ← window closed
4. queue the `None` sentinel
5. `join(THREAD_CLEANUP_TIMEOUT)`
6. book whatever is still queued as `undelivered`

A guard gated on the flag being `True` cannot shorten a window that exists only while
the flag is `False`. From step 3 onward requeue is disabled regardless —
`_upload_alert_batch`'s own requeue test reads the same flag.

The hazard, meanwhile, is real. Reproduced at shrunk windows:

```
ok=1560 + failed=0 + undelivered=18920 = 20480, from 20000 ever queued
```

480 items in two buckets, and `successful_uploads` climbing 1020 → 1560 *after* the
books were published while `undelivered` stayed frozen — the XSIAM symptom exactly.
At shipped values the exposure is any backlog over ~500 alerts: `ALERT_BATCH_SIZE` 60
per POST, no faster than `ALERT_MIN_BATCH_INTERVAL` 7 s, against a 60 s join.

`tests/test_xdr_delivery_books_balance.py` is a separate file rather than a parametrised
case, because the uploaders genuinely differ. Its fourth test watches the flag during the
drain and asserts it is still `False`, so the reasoning above is enforced rather than
argued — it passed before the fix and still passes.

### 5. The throughput justification does not transfer

On XSIAM these lines were **shipped**: 3,274 events, 94% of that run's tenant ingestion.
XDR's `log_worker_performance → log_performance → _log` writes to a local file only —
`PERFORMANCE` entries never leave the endpoint.

The fix is still worth making, for a different cost: endpoint disk and log legibility.
One XSIAM scan wrote 3,260 of these lines, burying the six governor samples that actually
diagnose a scan; a 10M-file server would write ~100,000 lines and ~12 MB per run.

This is the item the note asked to *measure before deciding* rather than inherit, and
that instruction earned its keep — carried across unexamined, the ingestion claim would
simply have been false.

---

## What this changed about the test suite

Five previously XSIAM-only test files are now parametrised over both editions:

- `test_fd_sampling_reach.py`
- `test_case_probe_cached.py`
- `test_hit_field_extraction.py`
- `test_worker_report_rate.py`
- `test_governor_sampling_cadence.py`

The two editions carry independent copies of this code, and every defect above existed
in both. Parametrising is what stops them drifting apart again — a duplicated test file
drifts as easily as the code it guards.

496 tests passing, up from 460 when the rounds closed.

---

## Still open

**Junction cycle protection.** `_should_skip_junction` prunes six legacy Windows names,
and real-path deduplication is present-but-disabled. A junction pointing at its own
ancestor without a legacy name has protection from neither. Unchanged in both editions;
deliberately not probed, because confirming it on a live endpoint means hanging the
endpoint.
