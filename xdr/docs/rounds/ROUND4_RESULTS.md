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

## Mutation audit — turning the method into a sweep

D4.2 and D3.1/D3.2 were both found the same way: ask not "is there a test named after this
gate" but "would the suite go red if this gate were wrong". That question can be asked
mechanically, so it was — every safety constant mutated to a value that would be a real
production failure, applied to **both copies at once**, suite re-run, survivors reported.

Applying to both copies is the whole trick. A one-sided edit trips the source-text parity
test for the wrong reason (drift), which tells you nothing about whether the behaviour is
covered. Mutating in tandem routes around the parity check and asks the behavioural
question directly.

First pass, 8 mutants, **3 survived**:

| Mutation | What shipping it would mean |
|---|---|
| `DEFAULT_QUIET_SECS` 900 → 0 | shards merged the instant a scan reports done, while its uploader is still draining |
| `DEFAULT_ABANDONED_SECS` 24h → 10y | nothing is ever abandoned; a crashed host's shard stranded forever |
| `DEFAULT_ROW_CEILING` 2e6 → 1e15 | no refusal on an implausibly huge merge |

One root cause behind all three: every one of these is overridable per call, and the
existing tests always pass explicit values. The *logic* is thoroughly covered; the
*defaults* had never been exercised once. Nobody passes `quiet_secs` on a real run — the
tenant gets the defaults, so an edit to any of the three reached production behaviour with
no test in the way.

Now pinned by `tests/test_consolidation_defaults.py`, 11 cases across both copies. Two of
them assert a **relationship** rather than a literal, because two of these numbers are not
arbitrary — the source comments justify them against facts outside the module, and nothing
enforced that justification:

- `DEFAULT_QUIET_SECS >= xdr_yara_scanner.LOOKUP_DRAIN_MAX_SECS` — a scan reports
  `completed` and then keeps draining queued batches. Raising the scanner's drain budget
  without raising the quiet period now fails here instead of silently truncating uploads on
  the tenant.
- `DEFAULT_ABANDONED_SECS > 6h` — the Action Center's script cap. This is the floor that
  stops a merely-slow scan being declared abandoned and having its shard deleted underneath
  a live writer.

Second pass after those tests landed: **8 of 8 caught, 0 survivors.**

### Wave 2 — the gate functions, each mutation mapped to a criterion

Constants were the easy half. The second wave mutated the gate *functions*, choosing each
mutation so that a survivor would name the criterion it invalidates.

| Criterion | Mutation | Result |
|---|---|---|
| D1.3 | `shard_is_terminal` ignores the Action Center state | caught |
| D1.5 | `parse_shard` anchoring removed | **survived** |
| D5.1 | `_newest_ms` drops the server stamp (the "DO NOT simplify" case its docstring warns about) | caught |
| D5.1 | `_max_ms` takes the earlier of the two stamps | caught |
| D5.2 | guard 1 removed — endpoint stamp ahead of ingest is kept | caught |
| D5.3 | guard 2 removed — implausible server stamp is kept | caught |

Five criteria decided on evidence rather than assumption: **D1.3, D5.1, D5.2 and D5.3 are
genuinely covered** by the existing suite. Those tests were not merely named after the
behaviour, they decide it.

**D1.5 was the survivor, and getting there took two wrong turns worth recording.**

The first mutation dropped the `^` from `_SHARD_RE`. It survived — but `parse_shard` calls
`.match()`, which anchors at the start whether or not the pattern says so, so that edit was
an *equivalent mutant*: different source, identical behaviour. A survivor proves nothing
until the mutation is confirmed to change what the code does. The second attempt swapped
`.match()` for `.search()` and also survived, for the mirror reason: the `^` was still
there.

So `^` and `.match()` are redundant with each other, and removing either alone is harmless.
That is real defence in depth in the code, and it is only visible from having tried.

Removing **both** finally changes behaviour — `customer_yara_scanner_matches_v3_host_abc123`
parses as ours — and against that mutation the pre-existing suite scored **157 passed**.
D1.5 was genuinely untested.

The asymmetry is what makes it matter. Failing to select one of our own datasets leaves a
shard behind and the next pass picks it up. Selecting someone else's *deletes a customer's
data*, because consolidation deletes sources once it has merged them.

Now pinned by `tests/test_foreign_datasets_are_not_candidates.py`, 42 cases across both
copies: 4 of our own shard shapes as positive controls (a pattern matching nothing would
otherwise pass every negative case while silently consolidating nothing), 14 foreign names,
and two self-protection cases that are easy to miss — the tool's own
`yara_scanner_consolidation_lock` must not parse as a shard, and neither must a per-scan
*target*, or a second pass would fold consolidated output back into itself as a source.

Second pass: **6 of 6 caught, 0 survivors.**

## Still to run

D2.3–D2.6, D3.3,
D4.1 / D4.3 / D4.4 (live lock contention, isolated delete failure, crash recovery),
D6.2–D6.4.

D1.3, D1.5 and D5.1–D5.3 are now decided — see the mutation audit above.

Much of D4 and D5 is already covered by the 74 existing unit tests in
`tests/test_consolidation.py` — lock, stale, skew, quiet-period and terminality are all
heavily exercised there. The remaining work is checking which criteria those tests actually
decide versus which only look covered, which is how D4.2 and D3.1/D3.2 both surfaced.
