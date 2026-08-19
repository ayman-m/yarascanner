# Dataset management — design

**Status: DESIGN, not built. Round 4 testing is on hold until this is agreed.**

Supersedes the trigger described in earlier drafts. Written 2026-08-19 after the original
trigger was shown to be unbuildable on this platform.

---

## 1. What forced the redesign

The original idea was a correlation rule that fires when a new per-host dataset appears.
Verified against the live tenant, **that cannot be built**:

| Surface | Result |
|---|---|
| `preset = datasets` | HTTP 404 — no such preset |
| `dataset = datasets` | HTTP 403 "Datasets not found" |
| `internal_auditing` | exists, returns **0 rows** even over 30 days |
| `metrics_source` | populated, but every row is an ingestion **collector** (7 sources, all Office 365). **0 rows** matching yara or lookup — and structurally so: it meters what arrives through collectors, and lookup rows arrive through `lookups/add_data`, which is not a collector. |
| `xql/get_datasets` | works — 367 datasets — but it is a **REST** call. Correlation rules run XQL. |

**There is no XQL-visible record that a dataset was created.**

The obvious fallback was a wildcard over the per-host shards
(`dataset = yara_scanner_scans_v3_*`). That query runs fine as an ad-hoc query — verified —
but **correlation rules do not support wildcard dataset sources**. So that route is closed
too.

A correlation rule therefore needs **one fixed dataset name** to watch, and nothing that
exists today gives it one.

---

## 2. The design

Two kinds of lookup dataset, with different jobs.

### 2.1 Data lookups — per host, unchanged

```
yara_scanner_matches_v3_<host>_<6hex>[_<YYYYMM>]
yara_scanner_scans_v3_<host>_<6hex>[_<YYYYMM>]
```

One pair per host, because `lookups/add_data` is not concurrency-safe — measured at
**87% row loss** with 8 endpoints writing one dataset, no error raised to any writer. This
is the part that must never be shared.

### 2.2 Tracking lookup — one, fixed name, shared

```
yara_scanner_scan_tracker
```

Every host writes **two rows per scan**:

| When | `event` |
|---|---|
| scan begins | `started` |
| scan reaches a terminal state (completed / cancelled / failed) | `completed` |

Proposed columns:

| Column | Why it is there |
|---|---|
| `scan_id` | the join key for everything |
| `hostname` | operator readability |
| `event` | `started` \| `completed` |
| `event_ts_ms` | endpoint clock |
| `status` | terminal status on the `completed` row (completed/cancelled/failed) |
| `matches_dataset` | **the literal dataset name** |
| `scans_dataset` | **the literal dataset name** |
| `run_id` | ties back to on-host artefacts |
| `files_scanned`, `matches` | lets an operator triage without opening the shard |
| `action_id` | the Action Center action, for the independent terminal check |

**Carrying the literal dataset names is the point.** The shard suffix is a 6-character hash
of the host (`xdr_agent_cd7e9b`), so deriving the name from `hostname` would mean
reimplementing that hash inside the playbook and keeping the two in lockstep forever. The
row states the name; the playbook queries that exact name; no derivation, no wildcard, no
coupling.

### 2.3 The trigger

```
dataset = yara_scanner_scan_tracker
| filter event = "completed"
```

One fixed dataset. No wildcard. The issue it raises carries `scan_id`, and the playbook
reads the tracking rows for that `scan_id` to learn exactly which datasets to merge.

---

## 3. What this changes about the edge cases

Some carry over unchanged, some change shape, and the design introduces new ones.

### 3.1 Improved by the new design

| Case | Before | Now |
|---|---|---|
| **Host went offline mid-scan** | inferred from the age of the newest row — indirect, and vulnerable to a rewrite refreshing the timestamp | **directly observable**: a `started` row with no matching `completed`. Much stronger signal. |
| **Which datasets belong to this scan** | derived by listing and parsing names | stated literally in the tracking row |

### 3.2 Carried over, still applicable

- Scan cancelled or failed — still merged, findings preserved. **The scanner must write the
  `completed` row on these paths too**, or they look abandoned.
- Quiet period before touching a shard, so a still-draining uploader is not cut off.
- Verify merged row count against the sum of sources before deleting anything.
- Row ceiling: refuse a merge too large rather than half-build it.
- Consolidation lock against overlapping runs.
- Clock skew: judge age from both endpoint and ingest timestamps.
- One delete failing must not strand the rest of the pass.

### 3.3 NEW — introduced by this design

**(a) The tracking dataset is itself a concurrent-write target.** Every host in the fleet
writes to it. That is the exact collision the per-host split exists to avoid — but at
**2 rows per scan** rather than thousands. The 87% measurement was 1,601 rows across 8
simultaneous writers; this is a different regime and must be **measured, not assumed**.
First test of Round 4.

**(b) A lost `completed` row orphans a real dataset. This is the most dangerous case.**
If a collision drops that row, the correlation rule never fires, and that host's dataset is
never cleaned up — and is now *invisible*, because the tracker is the only thing the
trigger reads. Silent, permanent growth.

Mitigation, and it should be part of the design rather than an afterthought: the tracker is
the **fast path**, not the only path. A periodic reconciliation — the existing `YaraReport`
listing datasets over REST — compares what exists against what the tracker knows, and
reports anything present on the tenant but absent from the tracker. The REST listing has no
wildcard restriction because it is not a correlation rule.

**(c) A `completed` row whose data write failed.** The tracker says a dataset exists; it is
empty or absent. The playbook must treat "nothing to merge" as a normal outcome and simply
retire the tracking rows.

**(d) Duplicate tracking rows** from `add_data` retries. Consolidation must be idempotent
per `scan_id` — merging twice must not double-count, and the row-count verification is what
catches it.

**(e) The tracker must NOT rotate monthly.** Rotation would produce
`yara_scanner_scan_tracker_202608`, and the correlation rule would need a wildcard again —
reintroducing the exact problem this design exists to solve. It must stay one fixed name
forever, which means its growth is bounded by **deleting rows** (`lookups/remove_data`)
after consolidation, never by rotating the dataset.

**(f) Tracker retention ordering.** Rows must not be pruned before consolidation has acted
on them, or the work is forgotten. Retire a scan's tracking rows only after its shards are
verified and deleted.

**(g) Two rows per scan, fleet-wide, forever.** 5,000 hosts scanned weekly is 520,000 rows
a year in one dataset. Bounded by (f), but the growth rate needs stating so it is a chosen
number rather than a surprise.

---

## 3.4 Answers to the three open design questions

### Q1. Write `started` AND `completed`, or only one?

**Both, and they have different jobs.**

| Row | Job |
|---|---|
| `started` | **Registration.** "This dataset now exists." |
| `completed` | **The trigger.** "It is ready to consolidate." |

The reason is edge case (b). If we wrote only on completion, a scan that dies — host
offline, crash, console hard-kill — writes **nothing**, so its dataset is orphaned *and
invisible*. That is the single worst outcome available, and it is also the most likely
failure on a real fleet.

With a `started` row, the dataset is registered the moment it exists. Even if the
`completed` row is later lost to a collision, the tracker still knows the dataset is there,
so reconciliation can find it **from the tracker itself** rather than depending on the REST
sweep as the only backstop. That converts a silent permanent orphan into a detectable one.

Writing only `started` does not work either: the rule would fire at scan start, when there
is nothing to consolidate, and the playbook would have to poll.

### Q2. Randomised start delay

**Yes, and it belongs on the scan start, not on the tracker write.**

Delaying only the tracker write leaves a window where the scan is running but unregistered;
if it dies there, the dataset is orphaned — exactly what `started` exists to prevent.
Delaying the scan start spreads the tracker write *and* the host CPU load *and* the tenant
ingestion, which is strictly better.

**But jitter alone is not sufficient, and should not be relied on.** With N hosts spread
over J seconds, writes arrive at roughly N/J per second: 5,000 hosts over 5 minutes is
~17/s, over 10 minutes ~8/s. The 87% loss was measured at **8 simultaneous writers**, so
at fleet scale jitter reduces the collision rate without removing it.

**The actual guarantee is write-then-verify.** After writing the `started` row, the scanner
reads it back — one row, one cheap query — and retries with backoff if it is absent. That
turns silent loss into detected-and-retried, which is the property we need. Jitter reduces
how often the retry is needed; verification is what makes it correct.

If verification shows collisions are still frequent at fleet scale, the fallback is a small
**fixed** set of tracker shards (say 8, chosen by hash of hostname) with one correlation
rule per shard. Still no wildcard, since the names are fixed and few.

### Q3. Can the tracker be pruned surgically? **Yes — verified live.**

`POST /public_api/v1/xql/lookups/remove_data/` removes rows by filter. Proven on a
throwaway dataset:

```
add 6 rows (3 scans x started/completed)   -> {'rows added': 6}
remove_lookup_data(ds, [{"scan_id": "scan_2"}])  -> {'deleted': 2}
survivors: scan_1 started+completed, scan_3 started+completed
```

So the dump-rewrite-restore workaround is **not needed**. Three constraints from the
toolkit, which the playbook must respect:

- filters are **OR across blocks, AND within a block**
- **exact values only** — no ranges, no wildcards, so prune by explicit `scan_id`
- **not concurrency-safe** — the caller must serialise, which the consolidation lock
  already provides

Retire a scan's two tracking rows in the same locked section that deletes its shards, after
the row-count verification passes. Never before: a tracking row removed early is a scan
forgotten.

---

## 4. Open questions for the design call

1. **What jitter window, and does write-then-verify hold at fleet scale?** The mechanism is
   settled (Q2); the numbers are not. Needs measuring at realistic host counts — it is the
   first Round 4 test.
2. **One rule or two?** `completed` is the happy path. The abandoned case is `started` with
   no `completed` after 24h, which is an *absence* — correlation rules handle "this
   happened" far better than "this did not". This may have to live in the reconciliation
   sweep rather than in a rule.
3. **Is the reconciliation sweep in scope for v1?** With `started` rows it is cheaper than
   before — it can run against the tracker alone, and only fall back to the REST listing to
   catch a dataset whose `started` row was also lost.
4. **Tracker retention** — rows retired at consolidation (Q3), or kept as an audit trail
   with their own window? Retiring is simplest and bounds growth; keeping them costs one
   more prune policy but gives history.

---

## 5. Testing

Round 4 acceptance criteria will be written **against this design**, not against the current
playbook, and not until the questions above are settled. The first criterion is (a) above:
if the tracking dataset cannot take the fleet's concurrent writes, the trigger does not
work and the rest of the design does not matter.
