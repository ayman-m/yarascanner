# `fix/xsiam-evidence-footprint` — what this branch changes

70 commits. 47 files, +16,146 / −2,210. Tests and the capability/test documentation are
most of it; 496 tests pass, up from 460 when the rounds closed.

The branch does three things: it **executes every catalogued XSIAM capability against
live endpoints** for the first time, it **fixes what that found**, and it **ports those
fixes into the XDR edition**.

`xdr_yara_scanner.py` moves +741 / −445 on the branch overall (`xsiam_yara_scanner.py`, +1,033 / −579). Two distinct groups of
commits touch it, and the distinction matters below:

- **Sixteen commits predating the rounds** — cross-edition fixes that landed in both
  editions together, unrelated to the acceptance work.
- **Six commits after the rounds closed** (+207 / −77) — the round findings ported
  across, each re-derived against the XDR source rather than taken on trust.

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

**3. `docs/xsiam/rounds/XDR_PORTING_NOTE.md`** — the port, and the three places XDR
turned out to differ. Every defect above existed in both editions; none was ported on
the strength of the XSIAM finding alone. Two differences are worth a reviewer's time: the dict-hit path
had a *producer* in XDR that XSIAM never had (dead code feeding a dead branch, removed
together), and the stop-flag caveat this note previously carried — that XDR's deliberate
requeue window made the fix unsafe — inverted on inspection, because that window closes
before the flag is set. There is now a test that watches the flag during the drain and
asserts it, rather than leaving it argued.

**4. `tests/`** — 25 files, 496 passing. Each was written failing first, and the
docstrings carry the measured numbers that motivated them, so a reviewer can see what
real behaviour the test is pinning rather than inferring intent from assertions. Five
files that were XSIAM-only are now parametrised over both editions: the two scanners
carry independent copies of this code, and a duplicated test file drifts as easily as
the code it guards.

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
XDR port: **closed**, per the porting note above.

---

## Reproducing

The harness lives outside the repo (session scratchpad) and is not part of this branch.
`docs/xsiam/TEST_PLAN.md` carries every criterion with its assertion, threshold, setup and
evidence artefact; `TEST_TRACKING.md` carries the per-capability status. Both are generated
from a single source of truth, as is the summary's header table and not-covered inventory —
hand-maintained totals had already drifted four criteria behind within one working session.
