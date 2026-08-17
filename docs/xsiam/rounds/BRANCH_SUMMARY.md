# `fix/xsiam-evidence-footprint` — what this branch changes

64 commits. 45 files, +15,559 / −2,133. `xsiam_yara_scanner.py` moves +1,033 / −579; the
rest is tests (20 new files, 460 passing) and the capability/test documentation.

`xdr_yara_scanner.py` also changes on this branch (+902), but entirely from the SIXTEEN
commits that predate the acceptance rounds — cross-edition fixes that landed in both
editions together. **No round-driven fix touches it.** That distinction matters below.

The branch does two things: it **executes every catalogued XSIAM capability against live
endpoints** for the first time, and it **fixes what that found**.

---

## Result

| Round | Theme | Criteria | Pass | Fail |
|---|---|---|---|---|
| 1 | Resource discipline | 55 | 55 | 0 |
| 2 | False-positive flood | 107 | 107 | 0 |
| 3 | Precision and resilience | 114 | 114 | 0 |
| — | Not covered, each with a stated reason | 21 | — | — |
| | **Total** | **297** | **276** | **0** |

25 archived run bundles, 15 targeted probes, across `xsoar` (Ubuntu), `thor` (Windows) and
`OfficeiMac` (macOS). Every criterion is decided from evidence on disk plus the events that
reached `yara_scans_raw` — not from a scan's exit status.

---

## Where a reviewer should start

**1. `xsiam_yara_scanner.py` — five behavioural changes.** Everything else follows from
these. In rough order of consequence:

| Change | Why |
|---|---|
| `_upload_worker` checks its stop flag before taking work | The flag was consulted only in `except Empty`, unreachable against a full queue. Items counted `undelivered` were then delivered and counted again — `ok + undelivered` exceeded the finding count by one batch. |
| `_maybe_sample_fds()` extracted, called before every early return, counter under lock | FD sampling ran only on files that were scanned and did *not* match — zero samples against a ruleset matching everything — and its increment raced across workers. |
| `_is_case_sensitive_fs()` cached per process | It ran per file on macOS: ~49,000 `/tmp` create/write/stat/unlink cycles on a 48,921-file scan, and the scanner's only per-file write. |
| Worker throughput logging gated on a 30 s per-worker interval | 3,260 lines and 3,274 shipped events on one scan — 94% of that run's ingestion. |
| `_iter_hit_fields` reduced to one shape | The dict arm was unreachable and its decode fallback produced wrong bytes silently rather than raising. |

**2. `docs/xsiam/rounds/SUMMARY.md`** — the eight defects with their evidence, and the
21 not-covered capabilities grouped by reason. This is the document to read if you want
the findings rather than the diff.

**3. `docs/xsiam/rounds/XDR_PORTING_NOTE.md`** — **two of these defects exist unfixed in
`xdr_yara_scanner.py` with the identical shape.** The rounds were scoped to XSIAM, so no
round-driven fix was applied there (the XDR diff on this branch is all pre-round
cross-edition work). One further defect looks the same there but must not be blind-ported: XDR's
uploader deliberately holds `stop_upload_thread` false during a rate-limited requeue
window, so forcing an early break could cause the loss the XSIAM fix prevents.

**4. `tests/`** — 20 new files. Each was written failing first, and the docstrings carry
the measured numbers that motivated them, so a reviewer can see what real behaviour the
test is pinning rather than inferring intent from assertions.

---

## Notable in review

**No acceptance criterion ever failed.** All 276 passed. None of the eight defects was
found by a test going red — they came from writing the criteria (which forces you to state
what should be true, and that is when stale documentation contradicts the code), from
reading evidence that had already passed, and from asking whether code paths could execute
at all.

**A criterion that only checks a field is *present* passes on a broken build.** `LIFE-014`
did exactly that until it was rewritten to assert the delivery fields *sum* to the finding
count — which is what caught the double-count.

**Skip predicates are tested with a positive and a negative case.** "It skipped something"
and "it skips everything" are indistinguishable otherwise. The vendor-agent exclusion is
checked against the *real* `/opt/traps` (4,825 files, zero scanned) with a planted
`/opt/traps-backup` sibling as the control, because `lin_skip_directory` matches on the
absolute path and a synthetic copy cannot reach that branch.

**One deletion surfaced more than itself.** Removing the dead dict path broke six alert
offset-cap tests — they had been building dict-shaped hits, so the cap preventing a 220 MB
alert file had never been unit-tested through the code that ships. The live storm-file run
is what confirmed that behaviour, not the unit tests.

---

## Open items, not addressed here

- **Junction cycle protection.** `_should_skip_junction` prunes six legacy Windows names,
  and real-path deduplication is present-but-disabled. A junction pointing at its own
  ancestor without a legacy name has protection from neither. Verified live that a benign
  junction *is* followed; deliberately not probed further, because confirming it on a live
  endpoint means hanging the endpoint.
- **XDR port**, per the porting note above.

---

## Reproducing

The harness lives outside the repo (session scratchpad) and is not part of this branch.
`docs/xsiam/TEST_PLAN.md` carries every criterion with its assertion, threshold, setup and
evidence artefact; `TEST_TRACKING.md` carries the per-capability status. Both are generated
from a single source of truth, as is the summary's header table and not-covered inventory —
hand-maintained totals had already drifted four criteria behind within one working session.
