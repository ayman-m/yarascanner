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

### Wave 3 — merge integrity, the "no finding is lost" half

`plan_consolidation` is the last gate before deletion. Everything upstream can afford to be
conservative; if this returns `ok=True` the sources are deleted, and a deleted lookup
dataset is gone. Five mutations, **2 survived** — and both survivors are single-character
edits to the same comparison:

| Criterion | Mutation | Result |
|---|---|---|
| D2.2 | sources deleted without verifying the count | caught |
| D2.1 | `target_count == source_total` → `>=` | **survived** |
| D2.5 | the row ceiling never refuses | caught |
| D2.5 | ceiling judged on the target, i.e. after writing | caught |
| D2.6 | `source_total > 0` → `>= 0` | **survived** |

Neither survivor is a typo review would catch, and each quietly converts "I counted the
rows into the target and they are all there" into something much weaker:

- **`>=` instead of `==`** accepts a target holding *more* rows than its sources. That is
  not a success, it is a double-merge — and accepting it deletes the sources, which are the
  only evidence the duplication ever happened. This is also what D2.6's idempotency
  guarantee rests on.
- **`>= 0` instead of `> 0`** makes `0 == 0` count as proof. `run_consolidation` passes
  `target_count=0` when the target does not exist, so a scan whose sources also count zero —
  genuinely empty, or a count query that failed — reads as verified and has its shards
  deleted on the strength of two zeroes agreeing.

Now pinned by `tests/test_merge_verification_is_positive_evidence.py`, 14 cases across both
copies. The framing that makes them cohere: **verification must be positive evidence that
rows arrived, not the absence of disagreement.** Includes the tight boundary (one row over
is still a mismatch, so a loosened comparison cannot hide behind a generous fixture) and the
ordering case — an oversize job that merged correctly is still refused, because if the count
check ran first the ceiling would only ever fire on jobs that had already failed.

Second pass: **5 of 5 caught, 0 survivors.**

### Waves 4 and 5 — retention, dry-run, locking, failure isolation

**Wave 4 (retention, `xdr_data_management.py`): 6 mutants, 0 survived.** Every guard is
verified — current-month, future-dated and unsuffixed protection on both the rotated and
legacy paths, plus the quiet-window recency filter that catches the case where a dataset's
calendar age and its real liveness disagree. **D6.3 and D6.4 are covered as they stand.**

**Wave 5: 5 mutants, 1 survived.**

| Criterion | Mutation | Result |
|---|---|---|
| D6.2 | `run_consolidation` defaults to writing | **survived** |
| D6.2 | the report pass no longer forces dry-run | caught |
| D4.1 | a live lock stops blocking a second pass | caught |
| D4.2 | an unreadable lock marker reads as free | caught |
| D4.3 | one delete failure aborts the whole pass | caught |

The survivor is the same shape as wave 3's: `dry_run=True` flipped to `False` with the
suite green, because **every existing test passes the flag explicitly, so the default was
never exercised once.**

The default is the protection. A caller passing `dry_run=False` has decided to write; a
caller passing nothing has not decided anything, and the only safe reading of "not decided"
is "do not touch the tenant". A dry run that writes is worse than no dry run at all, since
it is the mode people reach for precisely when they are unsure.

Now pinned by `tests/test_dry_run_is_the_default.py`, 8 cases across both copies, driven
through the existing `SpyClient` so the assertion is "no mutating call was made", not
"the final state looks unchanged" — those differ when a write and a delete cancel out.

The first test in that file is a **positive control** proving the fixture genuinely
consolidates 65 rows when told to write. Without it, every "nothing was mutated" assertion
would pass just as well against a fixture that was never going to do anything, and the file
would stay green with dry-run completely broken.

Second pass: **11 of 11 caught across both waves, 0 survivors.**

### Wave 6 — D2.3, the largest gap in the round

Three corruptions of `_coerce_row`, each leaving the row count exactly right. **All three
survived the entire suite:**

| Mutation | Effect on counts | Effect on findings |
|---|---|---|
| every text value → `""` | none | rule names, file paths, hostnames all emptied |
| every number → `0` | none | offsets, file sizes, match counts all zeroed |
| non-`str` text → `None` | none | a text field that read back as a number is lost |

Counts balance under all three, so `plan_consolidation` reports verified and the source
shards are deleted. The findings that survive are blank, and the only copies that said
anything have been deleted as "successfully merged" — silent, total, unrecoverable loss of
content, with every count in the report agreeing that it went perfectly.

This is exactly why the criterion is worded *"not just the count"*. Row-count arithmetic is
necessary and it was covered thoroughly; it is simply blind to this, because a corrupted row
is still a row. Six waves of auditing found nothing else with this blast radius.

`_coerce_row` is where the risk concentrates, and not by accident. It exists **to rewrite
values** — XQL read-back does not round-trip types, so `number` fields return as `'0'` or
`9.0` and `add_data` silently drops whole rows whose types mismatch. A function whose job is
changing values is one where "changed it correctly" and "destroyed it" are adjacent edits.

Now pinned by `tests/test_row_content_survives_the_merge.py`, 10 cases across both copies,
comparing source to target **field by field** for every finding. Two fixture choices carry
more weight than they look: `file_size=1`, the smallest value still distinguishable from a
zeroed field, and `offset=0`, which proves the assertion checks the actual value rather than
truthiness — a zeroing mutation is invisible to any test that only asks whether a field is
present.

Second pass: **3 of 3 caught, 0 survivors.**

### Wave 7 — the last three, where the behaviour was already right

D2.4, D3.3 and D4.4 were not gaps in the code. The behaviour was correct; what was missing
was anything that would notice if it stopped being correct.

**D2.4 is the one that matters.** It is the criterion the entire per-host sharding design
exists to satisfy: `add_data` is not concurrency-safe, and 8 threads writing one dataset lost
**87% of 1,601 rows** when measured live. Consolidation is safe only because it is the single
sequential writer to its target — which is true *by construction*, the write path being a
plain `for` loop over batches.

"True by construction" is precisely what a well-meant refactor deletes. Parallelising a loop
of slow network calls is the obvious optimisation, and `_delete_many` right below it *is*
threaded, which makes the sequential write path look like an oversight rather than a
decision. Verified by actually making that refactor: the new test fails, while the
pre-existing suite caught it only through the source-text parity check — the same blind spot
that opened this whole audit, since applying the refactor to both copies silences it.

The test asserts on the *calls*, not the resulting data: `FakeClient`'s dict extend happens
to be safe under the GIL, so a fully parallelised writer produces a perfectly correct row
count. A count-based assertion would pass. This is D2.3's blindness in a second costume.

**D3.3** — an abandoned scan's partial findings are merged, not dropped, with the negative
half (a scan that reported a minute ago is still protected) included; without it,
"consolidate every non-terminal scan" would pass the positive case while deleting shards out
from under live scans.

**D4.4** — both directions of crash recovery. A pass that died mid-write leaves a target with
some rows: the count does not match, so nothing is deleted and the sources stay available for
a later pass. A pass that wrote everything and died before deleting is recognised as finished
and cleaned up rather than re-merged, which is what makes the operation resumable rather than
merely safe to abandon. The orphaned-lock half is covered by
`tests/test_lock_takeover_reporting.py`.

## Round 4 — closed

All 24 criteria are decided. **659 tests pass, 0 outstanding failures.**

| Group | Criteria | How decided |
|---|---|---|
| D1 Selection | D1.1–D1.5 | live edge cases (D1.2, D1.4) + mutation audit (D1.3, D1.5) |
| D2 Merge integrity | D2.1–D2.6 | live (D2.2) + mutation audit (D2.1, D2.3, D2.4, D2.5, D2.6) |
| D3 Partial scans | D3.1–D3.4 | live (D3.1, D3.4) + mutation audit (D3.1, D3.2, D3.3) |
| D4 Concurrency | D4.1–D4.4 | mutation audit (D4.1, D4.3) + dedicated tests (D4.2, D4.4) |
| D5 Clock skew | D5.1–D5.3 | mutation audit — all three already covered |
| D6 Retention | D6.1–D6.4 | live (D6.1) + mutation audit (D6.2, D6.3, D6.4) |

**Seven waves, 33 mutants, 10 survivors — every one now closed.** Each wave was re-run
after its tests landed and scored 0 survivors against the full consolidation test set
(`test_consolidation`, `test_pack_data_management`, `test_data_management`,
`test_lock_takeover_reporting` and the seven files this round added).

A single combined re-run against the entire `tests/` tree was started and killed by the
background-job time limit partway through wave 1, so it is not evidence of anything. It
would not have added coverage regardless — the tests it would have pulled in exercise the
scanner, and no scanner test can catch a consolidation mutant. The scoped set is the
relevant one. (The killed run left two `.bak` files behind; the sources themselves were
verified byte-identical to HEAD, since the restore runs before the cleanup.)

### What the round actually found

Not one gap was a missing feature. Every one was a **guarantee that held in the code and
would have gone on holding right up until someone changed it**, with nothing in 74 existing
tests to object. The five distinct blind spots, in the order they cost the most:

1. **Counting is not reading.** (D2.3) The suite verified row counts exhaustively and never
   once checked what a row said. Blank every finding, keep the counts, and the merge reports
   success and deletes the originals.
2. **Consistency is not correctness.** (D3.1/D3.2, D2.4) A parity test comparing two copies
   proves they agree, never that what they agree on is right. Apply the same wrong edit to
   both and it goes quiet — which is exactly what a refactor does.
3. **The default is the contract.** (D6.2, and the three constants in wave 1) Every test
   passed these values explicitly, so the values the tenant actually runs on were never
   exercised. Nobody passes `quiet_secs` on a real run.
4. **Verification must be positive evidence.** (D2.1, D2.6) `0 == 0` is not proof a merge
   happened, and a target holding *more* rows than its sources is a double-merge, not a
   success.
5. **True-by-construction is a property, not a guarantee.** (D2.4) The single sequential
   writer was safe because of how the loop was written, next to a threaded delete path that
   makes the sequential one look accidental.

### On the method

Three findings came from asking "would the suite go red if this were wrong" rather than "is
there a test named after this", and that question turned out to be mechanisable. Two things
it demands, both learned by getting them wrong here:

- **Apply the mutation to both copies.** A one-sided edit trips the parity test for the
  wrong reason and tells you nothing about behavioural coverage.
- **Confirm the mutation changes behaviour before believing a survivor.** D1.5 produced two
  consecutive *equivalent mutants* — dropping `^` from a pattern used with `.match()`, then
  swapping `.match()` for `.search()` while `^` was still present. Both survived while
  changing nothing. The gap turned out to be real, but only a third attempt proved it, and
  the first two would have been reported as findings by a less careful pass.

That second point also produced the one genuinely reassuring result: `^` and `.match()` are
redundant with each other, so the dataset-ownership check is protected twice over. That is
only visible from having tried to break it.

The harnesses live in the session scratchpad rather than the repo — they mutate tracked
source files in place, and a crash mid-run leaves the tree modified. Each restores from a
backup in a `finally` and verifies by SHA-256, but that is a reason to run them deliberately,
not a reason to make them convenient.
