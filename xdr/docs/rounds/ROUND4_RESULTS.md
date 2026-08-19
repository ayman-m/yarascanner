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

## Still to run

D1.3 (Action Center state as the independent second check), D1.5, D2.3–D2.6, D3.2, D3.3,
D4.1–D4.4 (lock contention, stale takeover, isolated delete failure, crash recovery),
D5.1–D5.3 (clock skew both directions), D6.2–D6.4.
