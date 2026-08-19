# XDR Round 4 — Dataset management

**IN PROGRESS.** Criteria in [ROUND4_CRITERIA.md](ROUND4_CRITERIA.md), written before this
round ran.

## The full cycle works

Four hosts seeded, each with its own data lookup and a started/completed pair in the
tracker. The consolidation pass, driven only by the tracker:

```
tracker reports 4 completed scan(s)

  dm1 … dm4   source read from the tracker row, not derived
              verified 12 == 12; deleting source rows and retiring tracker rows

tracker rows remaining: 1
PASS  tracker pruned surgically, not dumped and rewritten
```

Three things that matter are established by that run:

- **The source dataset name came from the tracker row**, not from re-deriving it out of the
  hostname. The shard suffix is a 6-hex hash, so deriving it would mean reimplementing that
  hash in the playbook and keeping the two in lockstep forever.
- **Row-count parity was checked before any delete** — 12 == 12 on each scan. Deletion only
  ever follows verification.
- **The tracker was pruned surgically.** `remove_data` filtered on `scan_id` removed exactly
  that scan's rows and left the rest, so the dump-rewrite-restore workaround considered
  earlier is not needed. Proven separately: 6 rows in, filter one scan, `{'deleted': 2}`,
  the other two scans intact.

Covers D2.1, D2.2 (positive half), D6.1.

## Edge cases

The happy path is the easy half. `xdr/simulation/sim_edge.py` seeds each situation
deliberately rather than waiting for it to occur:

| Case | Criterion | What it seeds |
|---|---|---|
| D1.2 | still-running scans are untouched | a host with a `started` row and no terminal row |
| D1.4 | the 24h abandoned cutoff | a **pair** — 25h old must qualify, 23h old must not |
| D2.2 | count mismatch keeps everything | a deliberately partial merge |
| D3.1 | cancelled findings are preserved | a `cancelled` terminal row with findings present |
| D3.4 | an empty dataset retires cleanly | tracker rows with zero findings |

D1.4 is a pair on purpose. A single 25h-old scan only shows the cutoff fires; it says
nothing about whether the cutoff is in the right *place*. The 23h control is what
distinguishes "abandons after a day" from "abandons anything not finished this hour".

## Edge cases — 5/5 pass

```
D1.2  running scan not selected; its dataset unchanged at 7 rows
D1.4  25h-old scan past the cutoff: True;  23h-old scan past it: no
D2.2  merged 4 != source 9, and all 9 source row(s) survive — nothing deleted on a mismatch
D3.1  cancelled scan is selectable (status='cancelled') with its 6 finding(s) intact
D3.4  empty scan: 0 finding row(s), 2 tracker row(s) — nothing to merge, still discoverable
```

D1.4 is the one worth reading twice. Both halves had to hold: the 25h scan qualifies **and**
the 23h scan does not. A single aged scan shows only that the cutoff fires, not that it sits
in the right place.

D2.2 is the safety property stated as arithmetic — a partial merge left every one of the 9
source rows in place. Deletion follows verification, never precedes it.

## D4.2 — a gap the criteria found in the tests, not the code

`acquire_consolidation_lock` carries two safety parameters that were implemented and
documented but had **no test anywhere**:

- `on_takeover` — fires when this run steals another run's lock, so a steal is reported
  rather than presented as an ordinary pass
- `unreadable_is_held` — treats a marker whose row cannot be read as *held* rather than
  stale. That is the `add_data` create-lag window right after another run took the lock, and
  `YaraCleanup` passes it because its cost of a wrong takeover is irreversible: it deletes
  datasets, and an unconsolidated shard is a scan's only copy.

Both guard the same failure — two passes mutating the same shards, each believing it holds
the lock. Consolidation merges twice, which is recoverable; cleanup deletes concurrently,
which is not. A regression dropping either would have passed the whole suite.

Now pinned by `tests/test_lock_takeover_reporting.py`, 8 cases. The valuable ones are the
negative halves: a lock we did *not* take must not fire the callback, standing down must not
delete the other run's marker, and the strict flag must change **only** the unreadable case —
if it also made a genuinely stale lock un-takeable, cleanup would deadlock behind any marker
whose owner died.

## D3.1 / D3.2 — the terminal set was untested in both copies at once

`TERMINAL_LIFECYCLE = {"completed", "cancelled", "failed"}` decides whether a host's shard
is ever eligible for consolidation. The strings `"cancelled"` and `"failed"` appeared
nowhere in `tests/test_consolidation.py`. Measured by mutation rather than assumed:

```
narrow the set to {"completed"} in xdr_consolidate.py alone  ->  1 of 74 tests fails
narrow it in BOTH copies in tandem                           -> 74 of 74 tests PASS
```

The single test that fires on the one-sided edit is
`test_pack_copy_gate_logic_matches_xdr_consolidate`, and it compares the two files'
**source text**. It guards drift between the copies, so it cannot see an edit applied to
both. A consistency check proves the copies agree; it never proves that what they agree on
is correct.

What the passing-suite mutation would have shipped: every cancelled or failed scan is
permanently non-terminal, so its shard is never consolidated, never cleaned up, and its
findings sit stranded on a dataset nobody merges. That is the precise outcome this
subsystem exists to prevent, and it survived the full suite.

Both states are terminal for a reason worth stating plainly. Cancelling a scan does not
un-find what it already found — a scan stopped 80% through a filesystem holds 80% of a real
answer. And a scan that *failed* is the case you most want the evidence from.

Now pinned by `tests/test_partial_scans_are_preserved.py`, 28 cases, every one run against
**both** implementations — the pack copy is what executes on the tenant, so a guarantee
proven only in `xdr_consolidate.py` is not a guarantee. The negative halves carry the
weight: `running`, `initiated`, `""` and `None` must stay non-terminal, or "everything is
terminal" would pass the positive cases just as well and a shard could be merged and
deleted while its scan was still writing to it. One ordering case is included too — an
out-of-order `running` row older than the cancellation must not revive a finished scan.

## Still to run

D1.3 (Action Center state as the independent second check), D1.5, D2.3–D2.6, D3.3,
D4.1 / D4.3 / D4.4 (live lock contention, isolated delete failure, crash recovery),
D5.1–D5.3 (clock skew both directions), D6.2–D6.4.

Much of D4 and D5 is already covered by the 74 existing unit tests in
`tests/test_consolidation.py` — lock, stale, skew, quiet-period and terminality are all
heavily exercised there. The remaining work is checking which criteria those tests actually
decide versus which only look covered, which is how D4.2 and D3.1/D3.2 both surfaced.
