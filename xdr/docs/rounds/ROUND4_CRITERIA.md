# Round 4 — Dataset management: acceptance criteria

Written **before** the round runs, as with rounds 1–3. Criteria are the contract; a bar
moved after seeing results is not a bar.

Round 4 differs from the first three in what it tests. Rounds 1–3 exercise the **scanner**;
this one exercises `xdr_consolidate.py`, `xdr_data_management.py` and the
`YaraDatasetManagement` pack — the code that bounds dataset growth after the scanning is
over.

## The objective, as a single binding claim

> No per-host dataset remains once its scan has finished, or once 24 hours have passed
> since that scan started — **and no finding is lost achieving that.**

Every criterion below serves one half of that sentence. The second half is the harder one:
it is trivially easy to bound dataset count by deleting things.

## How it is triggered

**Run on demand.** Open an issue and run the consolidation playbook against it, or run it
from the playground. There is no automated trigger, and the criteria below do not assume
one — verified during this branch: correlation rules cannot see dataset creation
(`preset = datasets` 404, `dataset = datasets` 403, `internal_auditing` empty,
`metrics_source` covers ingestion collectors only), cannot use wildcard sources, and a
shared tracking lookup loses 79% of its rows under concurrent writes.

---

## D1 — Selection: what gets consolidated

| # | Must be true | Evidence |
|---|---|---|
| D1.1 | Every per-host dataset belonging to a **finished** scan is selected | listing before vs after; each selected name appears in the run's report |
| D1.2 | A dataset whose scan is **still running** is not selected, not read and not deleted | seed a host with an `initiated` row and no terminal row; its dataset is byte-identical after the pass |
| D1.3 | Terminality is established **two independent ways** — the lifecycle row *and* the Action Center action state | a host whose lifecycle row says `running` but whose action terminated is still selected |
| D1.4 | A scan with no terminal row and **no activity for 24h** is treated as abandoned and consolidated | seed rows aged past the cutoff; confirm selection, and that a 23h-old scan is **not** selected |
| D1.5 | Datasets outside the `yara_scanner_*` contract are never candidates | plant a similarly-named foreign dataset; it is untouched and unlisted |

## D2 — Merge integrity: nothing is lost

| # | Must be true | Evidence |
|---|---|---|
| D2.1 | The per-scan target holds **exactly** the sum of its sources' rows | count target vs sum(sources) before deletion |
| D2.2 | Sources are deleted **only after** that count matches | force a mismatch; confirm every source survives and the run reports it |
| D2.3 | Row **content** survives, not just the count | sample rows by `(scan_id, rule, file_path)` in source and target |
| D2.4 | Consolidation is a **single sequential writer** to its target | no concurrent write to one dataset anywhere in the pass |
| D2.5 | A merge above the row ceiling is **refused up front**, not half-built | seed past the ceiling; no partial target is created |
| D2.6 | Re-running the pass is **idempotent** — no double-count, no duplicate target rows | run twice; counts identical |

## D3 — Partial and failed scans

| # | Must be true | Evidence |
|---|---|---|
| D3.1 | A **cancelled** scan's findings are merged and preserved, not discarded | seed a `cancelled` terminal row with rows present; they appear in the target |
| D3.2 | A **failed** scan's findings are likewise preserved | same, with `failed` |
| D3.3 | An **abandoned** scan's partial findings are preserved | same, via the 24h path |
| D3.4 | A scan whose dataset is **empty or absent** is retired cleanly, not treated as an error | tracker/listing says it exists, dataset holds 0 rows; pass completes, nothing else affected |

## D4 — Concurrency and failure isolation

| # | Must be true | Evidence |
|---|---|---|
| D4.1 | Two consolidation passes cannot run at once | start a second while the first holds the lock; it reports `lock_held_by_other_run` and deletes nothing |
| D4.2 | A stale lock is taken over **only** past the staleness window, and the takeover is reported, never silent | plant a stale marker; confirm the report names it |
| D4.3 | One dataset failing to delete does not strand the rest of the pass | make one delete fail; the others still complete and the failure is listed |
| D4.4 | A crash mid-pass leaves no half-built target and no orphaned lock | kill mid-run; confirm state is recoverable and the next pass proceeds |

## D5 — Clock skew

| # | Must be true | Evidence |
|---|---|---|
| D5.1 | Age is judged from **both** the endpoint stamp and the platform ingest time, taking the later | rows with an endpoint clock running ahead do not age out early |
| D5.2 | An endpoint clock running **behind** cannot make a live scan look abandoned | seed a live scan with old endpoint stamps; it is not selected |
| D5.3 | Skew beyond the backstop window falls back to the endpoint stamp rather than deferring forever | rows past the backstop are still eligible |

## D6 — Retention and reporting

| # | Must be true | Evidence |
|---|---|---|
| D6.1 | Every pass reports what it selected, merged, skipped and deleted, with a reason per skip | the run's own output; a silently-skipped dataset is indistinguishable from a bug |
| D6.2 | A dry run mutates **nothing** and says so | listing identical before and after; output states the mode |
| D6.3 | Retention pruning never deletes the current month, a future-dated month, or an unsuffixed dataset | seed all three; confirm each is kept with its reason |
| D6.4 | Deletion is refused for any dataset written within the quiet window | seed a recently-written dataset with an old-looking name |

---

## Not covered, and why

- **Automated triggering** — out of scope for this release by decision; the trigger is manual.
- **Fleet-scale concurrency** — the shared-tracker approach was abandoned after measurement
  (79% row loss at 24 concurrent writers), so there is no shared write path left to test.
- **The XSOAR pack's console behaviour** — the pack wraps the same logic as the CLI and is
  kept in step by `tests/test_consolidation.py` and `tests/test_pack_data_management.py`,
  which compare the two statement by statement. Console-only behaviour needs a console.
