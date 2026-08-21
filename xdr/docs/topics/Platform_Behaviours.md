# Platform Behaviours — how the Cortex lookup, XQL and Action Center APIs actually behave

*A reference of observed platform behaviour, organised by API surface. Every entry is either a
documented platform limit or a behaviour measured live on this tenant; where a number was
measured, the measurement is the fact and is kept.*

This file exists so the shipping scripts do not have to carry it. `xdr_yara_scanner.py` and the
five `YaraDatasetManagement` automations are customer-facing: their comments describe what the
code does, not how the platform was found to behave. **Anything a maintainer needs to know about
the platform before changing those files is here.**

Related documents, which this one deliberately does **not** repeat:

| Document | Covers |
|---|---|
| [Known_Limitations.md](Known_Limitations.md) | Residual risks and open questions — accepted risks, "confirmed not a gap", and things that still need live verification |
| [Datasets_and_Maintenance.md](Datasets_and_Maintenance.md) | Why the dataset names look the way they do; retention, rotation and consolidation as an operator workflow |
| [Scan_Cancellation.md](Scan_Cancellation.md) | Console Cancel vs. the `cancel` entry point, and orphaned lifecycle rows |
| [Rule_Compatibility.md](Rule_Compatibility.md) | Which YARA modules and libyara versions each agent ships |
| [CPU_Impact_Control.md](CPU_Impact_Control.md) | The CPU governor and what it does and does not promise |
| [../CAPACITY.md](../CAPACITY.md) | Measured bytes-per-row and how many hosts fit in the 50 MB cap |
| [../design/Dataset_Management_v2_Design.md](../design/Dataset_Management_v2_Design.md) | The 50 MB cap and 1,000,000-row truncation as design constraints |

---

## 1. Authentication — `/public_api/*`

**Two auth modes, and Advanced is the modern default.**

- **Advanced (HMAC).** Per-request headers: `x-xdr-nonce`, `x-xdr-timestamp`, and
  `Authorization: sha256(api_key + nonce + timestamp)`, plus `x-xdr-auth-id`.
- **Standard.** `Authorization: <api_key>` plus `x-xdr-auth-id`, no signature.

**Advanced headers must be rebuilt for every HTTP attempt.** The nonce and timestamp are
per-request and must not be replayed across retries. A caller that builds headers once and
reuses them across a retry loop will 401 on the retries.

**Auto-detection is a probe, not a negotiation.** `get_datasets` is used as a cheap
authenticated no-op: try Advanced, then Standard, cache the winner for the process. An
inconclusive or offline probe falls back to Advanced.

**A 401 does not recover across retries.** A rotated, expired or revoked key returns 401 on
every attempt, so retry loops treat 401 as terminal and fail on the first call rather than
sleeping through a 3/6/9 s or 5/10/15 s backoff ladder first.

**403 and "dataset not found" are distinguishable.** They arrive as different status codes with
different bodies, so an under-permissioned key is not silently read as a missing dataset.

**Permissions are split across two roles.** `add_data` / `remove_data` / `add_dataset` /
`delete_dataset` need **Data Management**; running XQL needs **Query Center**. A key with Data
Management but not Query Center can write rows and delete datasets but cannot run the
enumeration query the scanner's start-of-scan overwrite depends on — the overwrite then degrades
to a logged no-op and the dataset grows unbounded, while the scan itself still succeeds. See
`.claude/skills/xdr-action-center-api/references/api-permissions.md`.

**There is no generic REST bridge on this tenant.** The Cortex Core - IR integration's
`demisto-api-post` / `core-api-post` commands are **not registered** here at all (searching
automations for `*api*` / `*core*` returns zero results). An in-platform automation that needs
to reach the tenant's own public API must therefore carry its own credentials rather than
proxying through an integration.

---

## 2. Lookup dataset creation — `/public_api/v1/xql/add_dataset/`

**A lookup dataset's schema is FIXED at creation and cannot be altered in place.** The only way
to change a row shape is to create a differently-named dataset. This is why every dataset name
carries a `_v<N>` schema-version tag.

**Supported column types are `text`, `number`, `datetime`, `bool`.** There is **no array type
and no nested/object type.** A field that needs to hold a list must be declared `text` and carry
serialised JSON (see §8 for how to query it back).

**Dataset names must be lowercase `[a-z0-9_]` and start with a letter.** Any label derived from
a hostname must therefore be slugified. Because slugification and truncation are lossy, a short
hash of the *original* label is appended so two hosts that would otherwise collide land in
different datasets.

**Creating a dataset that already exists returns HTTP 500, not a 2xx or a 409.** The body
carries `err_extra` containing `"Dataset <name> already exists"`. Callers must treat that
specific 500 as success — it is the ordinary outcome when a `get_datasets` probe missed a
dataset that was in fact present.

**Creation is a hard prerequisite for writing.** Nothing is created implicitly; see §3.

**Schema versions coexist and must never be mixed in one operation.** A tenant mid-rollout writes
two row shapes at once, and an un-consolidated shard is its scan's only copy — so no old schema
is ever removed from the tooling's table, and a shape the tooling cannot resolve is a shard it
cannot merge. A v2 shard and a v3 shard for the same scan have **different columns**, so any
merge must handle exactly one version per call; mixing them under one schema mis-projects every
row. Fan-out across known versions happens a level up, not inside the merge.

The shapes still in circulation:

| Tag | Grain |
|---|---|
| `v2` | one row per matched string **OFFSET** (pre-3.0.0 scanner) |
| `v3` | one row per **(rule, file)** finding — offsets/strings/string_ids folded into the row |
| `v4` | one row per matched **FILE** — every rule that hit it folded into `rules`; `run_id`, `scan_date`, `scan_folder`, `date_of_scan` dropped as derivable or scan-constant |

An unrecognised version tag falls back to the **currently emitted** shape rather than raising —
the caller is about to create a dataset for rows this build emits, and that is the only shape
those rows can land in.

**Creation is not instantaneous.** For a short window after `add_dataset` returns, `add_data`
against the new dataset can still fail with `"no schema"` or `"not found"`. Callers retry that
specific pair of error substrings with a backoff (6 attempts, 3/6/9/12/15 s) before giving up.
The same lag is why a lock dataset with no readable row is treated as **held** rather than free
by the destructive caller — an unreadable lock is indistinguishable from one another run just
took.

---

## 3. Writing rows — `/public_api/v1/xql/lookups/add_data/`

### 3.1 It silently skips rows it does not understand

**`add_data` returns HTTP 200 and silently SKIPS any row carrying a field the dataset's schema
does not know about.** The reply reports `records_skipped=N, records_added=0`. Nothing errors,
nothing warns.

Consequences that are load-bearing:

- A dataset created from an **older** schema than the caller emits will accept every POST and
  drop every row. So a dataset must always be created with the shape the running build actually
  emits — never with a shape resolved from an operator-pinnable version tag.
- A dataset created from a **wider** schema than the caller emits is harmless (missing fields
  are not an error), which is why the asymmetry matters: only the narrow direction loses data.
- Adding a field to a row shape without bumping the schema version makes scans report success
  while their telemetry vanishes.

### 3.2 The reply's field names are inconsistent with the docs

The API documentation shows `added` / `updated` / `skipped`; **the tenant actually returns
`"rows added"` / `"rows updated"` / `"rows skipped"` (with spaces)**, and the consolidation path
has also seen `records_added`. Parsers must accept both spellings or they will read every
successful write as zero rows.

### 3.3 It is NOT concurrency-safe server-side

**XDR stages every `add_data` write through a per-write BigQuery "clone" table. Two writers
touching the SAME dataset at the same time race, the server returns a transient HTTP 500
`"...<dataset>_clone was not found"`, and the rows are LOST — not rejected.** The retry then
returns HTTP 200 and nothing anywhere reports a problem.

Measured on a live tenant:

| Configuration | Result |
|---|---|
| 8 endpoints writing one shared dataset | ~**2 of 8** batches landed |
| Same, with 45 s of client-side jitter across the 8 writers | still lost **7 of 8** |
| 8 concurrent writers to one dataset (consolidation measurement) | **87% row loss** |
| One writer per dataset | **8/8**, 100% landing at any scale |

**Client-side time-spreading cannot fix this.** The server holds the dataset through a slow
merge, and no amount of client-side politeness shortens that window.

**The only real fix is per-writer dataset sharding** — one writer per dataset, so the collision
cannot occur by construction. Everything else (large batches to reduce POST count, pre-write
jitter to decorrelate the fleet, full-jitter retries) is secondary insurance for the case of two
writers on the same host.

**Retry backoff must be full-jitter, not correlated.** Concurrent writers all fail the clone
race together; an `exp * 0.5..1` backoff makes them retry in step and keep colliding. A uniform
pick in `[0, ceiling]` decorrelates the herd.

### 3.4 Merge time scales with DATASET size, not payload size

Measured on-tenant, writing a **single row**:

| Dataset size | Time per write |
|---|---|
| 15,000 rows | ~13 s |
| 77,000 rows | ~31 s |

**An unrotated append-only dataset therefore gets progressively slower until writes exceed any
client read timeout, at which point it goes write-dead.** Observed live at ~77k rows, where a
host lost the majority of a scan's rows to read timeouts (500 of 36,106 rows landed).

This is the entire reason monthly rotation exists — it bounds each dataset's size permanently,
so write time stays flat forever. It is also why rotation is applied only to the **append-only**
`scans` dataset: the `matches` dataset is bounded by a per-scan overwrite instead (§4.3), and
rotating it as well would mint a new dataset every month and defeat the "one permanent dataset
per host" contract.

### 3.5 A read timeout is not a clean failure

**A read timeout means the server was mid-merge when the client hung up. The rows often commit
anyway.** So:

- Fail fast on **connect** (the server never saw the request — retry freely).
- Stay patient on the **read**: 120 s, well above the largest merge a size-bounded dataset can
  grow into.
- Cap retries after a **read** timeout separately and much lower (2 attempts = one retry). Each
  blind retry risks duplicating the whole batch *and* re-running the merge whose duration caused
  the timeout in the first place.
- Past that cap, book the batch **`unconfirmed`** — fate unknown, NOT added and NOT lost. Never
  report it as delivered: "may have committed" is not evidence.

There is no reconciliation for this. `delete_dataset` treats a subsequent "not found" as proof
the first attempt landed; `add_data` has no equivalent, so the duplicate-write risk is bounded
only by the callers' own idempotency checks.

### 3.6 Rate limits and batch sizing

- **~1,000 entries / 10 s** rate limit on the lookups write path.
- **500 rows per POST** is the working batch size. Larger payloads (e.g. 1,000) make the request
  slow enough that the **API gateway** returns 502s and read timeouts under concurrent fleet
  load, losing whole batches.
- Every POST is one chance to hit the clone race, so fewer, larger POSTs is strictly safer than
  many small ones.

### 3.7 A dataset can vanish mid-scan

`add_data` returns **HTTP 400 "Dataset not found"** if the dataset is gone. This is not
necessarily a configuration error: it happens for real when a consolidation or cleanup pass
elsewhere deletes a still-in-progress scan's dataset (measured live — a scan whose newest row
crossed a maintenance tool's abandoned-scan cutoff had its dataset pulled out from under it
mid-write). Since dataset creation only runs once at startup, a writer without a mid-flight
recreate path will keep failing silently for the rest of the scan.

---

## 4. Deleting rows — `/public_api/v1/xql/lookups/remove_data/`

### 4.1 Filter semantics

**Filters are OR across blocks and AND within a block, and they accept EXACT VALUES ONLY.**
There is no negation, no range and no pattern match, so *"everything that is not this scan"* is
not expressible. The values to remove must be enumerated first (one XQL) and then removed one
exact value at a time.

**The multi-block form is all-or-nothing**, so callers issue one exact-value block per call:
that keeps a single bad value from taking the others down with it.

The reply is `{"deleted": N}`.

### 4.2 It is NOT concurrency-safe

**`remove_data` is not concurrency-safe; the caller must serialize.** This constrains design in
two places: the scanner's start-of-scan flush runs inline and strictly sequentially before the
writer thread exists, and consolidation's row-level cleanup is sequential rather than batched in
parallel.

### 4.3 It is 19× cheaper than delete-and-recreate

Measured on this tenant:

| Operation | Time |
|---|---|
| `remove_data` filtered row delete, ~550 rows | **10.0 s** |
| `delete_dataset` + recreate | **190.2 s** |

That 19× gap is why the per-scan overwrite is a filtered row delete. It also **keeps the dataset
object alive** — and therefore its schema, and anything pinned to its name (dashboards, the
consolidation automations) — across the overwrite.

### 4.4 Open question: does it re-stamp `_insert_time`?

Whether the platform implements row removal as an in-place tombstone or as a rewrite/compaction
is **unverified** — settling it needs a destructive `remove_data` against a real shard holding
two scans. If it rewrites, one scan's cleanup re-arms an unrelated sibling scan's freshness
signal on the same shard. Recorded as an open question in
[Known_Limitations.md](Known_Limitations.md); the 7-day skew backstop (§9.3) exists to make the
answer non-load-bearing.

It cannot bite the scanner's start-of-scan flush, which removes every scan_id *except* the
current one at a moment when the current one has written nothing — there are no surviving rows
for a re-stamp to touch.

---

## 5. Deleting datasets — `/public_api/v2/xql/delete_dataset/`

Note the **v2** path; the other lookup and XQL endpoints are v1.

- **`force=True` is only needed to delete a dataset with dependencies** (correlation rules,
  scheduled queries).
- **A single delete takes ~60 s server-side.** Deletes of *different* datasets do not race
  (verified live), so they are issued in bounded-concurrent batches — 12 at a time. Even so,
  cleaning a large fleet is an hours-scale background job.
- **A delete can exceed the client read timeout while still committing.** So: a generous
  timeout, retries with a 5/10/15 s backoff, and — critically — a subsequent `"not found"` or
  `"NoneType"` error on a retry is treated as **success**, because it means the first attempt
  landed. (The CLI client uses 180 s explicitly; the in-platform automations use their client's
  90 s default.)
- **There is no undelete and no dataset versioning.** A mismatch or bug caught after the fact
  cannot be recovered, only avoided. Treat every delete as one-way.
- **Deleting a dataset a scan is actively writing to does not error the scan.** The scanner
  keeps POSTing to a name that no longer exists and receives HTTP 400 per batch. Across a fleet
  mid-scan that is silent, partial data loss discovered days later as a gap in dashboards.

---

## 6. Listing datasets — `/public_api/v1/xql/get_datasets/`

**The reply shape is inconsistent.** The payload may nest the list under `"data"` or under
`"datasets"`, and **the docs say each entry carries `dataset_name` while the tenant actually
returns `"Dataset Name"`**. Parsers must accept both spellings, or an existence probe will
report every dataset as missing.

A failed or unparseable probe should not be fatal: the correct fallback is to attempt
`add_dataset` anyway and let the "already exists" 500 (§2) settle it.

This is the one call that is not an XQL query, so it does not consume XQL quota and is reported
separately from the query count in the automations' cost accounting.

---

## 7. Running queries — `/public_api/v1/xql/*`

### 7.1 The call is asynchronous

`start_xql_query` returns a `query_id`; `get_query_results` is polled with `pending_flag: true`
until `status` is no longer `PENDING`. Any status other than `SUCCESS` is a real failure.

### 7.2 Above ~1,000 rows results are STREAMED, and `limit` is silently ignored

**Past roughly 1,000 rows the platform stops inlining results.** It returns a `stream_id`
instead of a `data` array, and the caller must fetch the rows from
`get_query_results_stream`.

**`get_query_results`' own `limit` parameter only controls INLINE responses.** Past the
threshold it is silently ignored and `"data"` never appears — which makes every large pull look
like **zero rows**. Measured live: a 2,448-row scan's matches vanished at the exact 1,000-row
boundary, and *requesting more rows, not fewer, was what broke it.*

**The stream response body is newline-delimited JSON** — one row object per line, not a single
JSON document — so `r.json()` fails on it and the raw text must be parsed line by line.

The scanner deliberately does **not** carry the stream endpoint or an NDJSON parser onto the
endpoint: the only query it runs returns one row per distinct `scan_id`, which would need >1,000
failed overwrites on a single host to reach the threshold. It reports the truncation plainly and
fails safe instead.

### 7.3 XQL truncates a result set at 1,000,000 rows, silently

There is no pagination and nothing warns you. Documented in
[../design/Dataset_Management_v2_Design.md §1.2](../design/Dataset_Management_v2_Design.md) and
[../CAPACITY.md](../CAPACITY.md); repeated here only so this file is complete on limits.

### 7.4 Query interpolation must be guarded

Dataset names are interpolated into query strings. Every name reaching that point comes from
`get_datasets` and then an anchored parse, but **the host segment of a shard name originates as
a hostname**, so the shape check is made explicitly rather than assumed. Per-scan target names
are safe by construction because `target_name()` slugifies the scan_id down to `[a-z0-9_]`.

### 7.5 A query error must fail closed

Every safety rail in the cleanup path that depends on a live query (§10) **keeps** the dataset
when the query errors. An unreadable lifecycle means UNKNOWN, never "finished".

---

## 8. XQL language behaviours

**A JSON array held in a `text` column is queryable.** Verified live on this tenant:

```
| alter r = json_extract_array(rules, "$")
| arrayexpand r
| alter rule = json_extract_scalar(r, "$.rule")
| comp count() as n by rule
```

This is what makes the `text`-column workaround for the missing array type (§2) acceptable
rather than opaque.

**`json_extract_scalar(x, "$.$ip")` is NOT a valid JSONPath.** YARA string identifiers begin
with `$`, so an object keyed by the identifier — `{"$ip": 50}` — can be *stored* but never
*queried*. The v4 schema therefore stores `string_ids` as an **array of `{id, count}` objects**
precisely so it stays reachable.

**`comp count() as n by <field>` over a lookup dataset is the verified idiom** for distinct-value
enumeration and for per-group aggregation, and is used for: distinct `scan_id`s in a shard,
per-`scan_date` counts, and lifecycle status rollups. Extending a single `comp` stage with an
extra aggregate and extra group keys (e.g. `comp count() as n, max(event_timestamp_ms) as ts by
scan_id, hostname, rule`) is exercised live; the automations that rely on the extended form keep
a fallback to the unmodified idiom in case a tenant rejects it.

**`max(_insert_time)` rides along in the same `comp` stage** and is verified working on the live
tenant. `_insert_time` is also present as a system column on raw row pulls (`dataset = X`),
though that form is not itself live-verified — see [Known_Limitations.md](Known_Limitations.md).

**`_insert_time` arrives in inconsistent shapes.** Parsers must accept int, float,
numeric string, exponent-notation string and ISO-8601, and degrade to "no signal" rather than
raising on anything else.

**A query against a dataset that does not exist errors with "not found" wording** rather than
returning an empty set. Callers that mean "nothing there" must translate it.

---

## 9. Timing, clocks and freshness signals

### 9.1 Action Center terminal states

The set of Action Center statuses this repo's tooling has observed as **terminal** from live
polling:

```
COMPLETED_SUCCESSFULLY   FAILED   ABORTED   EXPIRED   TIMEOUT
CANCELED   CANCELLED   COMPLETED_WITH_ERRORS   COMPLETED_PARTIAL
```

**Both the one-L and two-L spellings of "cancel(l)ed" occur** — match on both. The scanner's own
lifecycle vocabulary is separate and smaller: `completed` / `cancelled` / `failed` are terminal;
`initiated` and `running` are not.

### 9.2 The Action Center script timeout is 6 hours

This is the floor under every "is this scan still alive?" decision. The abandoned-scan cutoff is
24 h precisely because it must comfortably exceed 6 h, so a scan still legitimately running can
never be mistaken for abandoned.

### 9.3 Endpoint clocks drift relative to platform ingest

A row cannot be *authored* after the platform *ingested* it, so any excess of
`event_timestamp_ms` over `_insert_time` is the endpoint's clock running ahead. Measured live on
real shards, the honest gap (upload latency, ingest first) was **3.2 s / 3.7 s / 5.2 s / 5.4 s /
66.8 s**. The tolerance is set at **5 minutes** — generous headroom over that without tolerating
a genuinely wrong clock.

The freshness signal both time gates measure against is therefore
`max(event_timestamp_ms, _insert_time)` with implausible values discarded first (endpoint stamp
ahead of ingest; server stamp far in the future of now). It must never be reduced to
`_insert_time` alone, and it may only ever be computed over **source shards**, never over a
per-scan target.

### 9.4 The 7-day skew backstop

Past 7 days of endpoint silence, the endpoint stamp alone is enough to settle both gates. This
is what guarantees the abandoned cutoff cannot be deferred without limit if `remove_data` turns
out to re-stamp `_insert_time` (§4.4). The trade is explicit: it gives back skew protection only
for a clock wrong by more than a week.

### 9.5 The quiet period is 900 s

`DEFAULT_QUIET_SECS = 900` is set at or above the scanner's maximum lookup drain budget (600 s)
plus margin, so a scan that has stopped producing rows really has finished draining.

---

## 10. The dataset naming contract, and what depends on it

Name shapes this tooling mints and recognises:

```
yara_scanner_matches_v<N>_<host>_<6hex>              permanent per-host, never rotated
yara_scanner_scans_v<N>_<host>_<6hex>[_<YYYYMM>]     append-only, monthly-rotated
yara_scanner_matches_v<N>_scan_<slug>                consolidated per-scan target
yara_scanner_summary_v<N>_scan_<slug>                summary-only per-scan target
yara_scanner_consolidation_lock                      overlap guard
yara_scanner_consolidation_runs                      consolidation run log
yara_scanner_cleanup_runs                            cleanup run log
```

**A name that does not round-trip to a shape this tooling mints is a name it must not delete
rows from.** That is the outermost safety rail: unrelated tenant data is unreachable by
construction.

**Month-suffix parsing is deliberately biased.** A trailing group is read as a rotation month
only if it is a plausible `YYYYMM` (`20xx`, month `01`–`12`). A host segment that is itself
exactly that shape is indistinguishable from a month and is resolved **as a month**, because the
worst outcome of that reading is declining to delete something that looks recent — whereas
reading it as a host could delete a whole host's history in one call. The year/month **range
check is load-bearing**: a bare `\d{6}` reads `110501` as year 1105 (older than every retention
window, so the ambiguity resolves toward *deleting*) and crashes month arithmetic outright on an
`HHMMSS` tail like `143025`.

**The summary target's `kind` segment is `summary`, not `matches_summary`, and the choice is
load-bearing.** `yara_scanner_matches_summary_v4_scan_<slug>` matches the YARA-owned regex
(`yara_scanner_matches(_.*)?`) but *not* the current-version regex (which requires
`matches_v<VER>`), so classification would file every summary target under **legacy** — and a
cleanup run with `delete_legacy=true` would delete them all. The chosen form matches neither
regex, so it is invisible to that classification and can never become a deletion candidate. It
is equally invisible to the shard regex, so no consolidation pass can mistake a summary target
for a source shard and try to merge it into itself. The stated consequence: cleanup will never
prune summary targets either.

**Names outside the versioned contract still need the rails.** The oldest legacy names predate
the `_v<N>` segment entirely (`yara_scanner_scans_hostA`), so gating a rail on "the full name
parsed" exempts exactly the least replaceable data — an unversioned, unsuffixed dataset holding
*all* of a host's pre-rotation history. The two facts the rails need (is it a per-scan target;
does it carry a month suffix) are derived from the raw name when the full contract will not
parse. Genuinely pre-contract names with no `yara_scanner_` prefix at all are *not* given an
inferred unsuffixed-ness, because that would make legacy deletion vacuous for the oldest data it
exists to remove — the two live-query rails remain the last line of defence for those.

**Deletion safety rails, in the order they apply** (each *keeps* the dataset when it fires, and
each keeps it on a query error too):

1. Never the **current month** — a scan may be writing to it.
2. Never a **future-dated month** — clock skew must not destroy data.
3. Never an **unsuffixed** dataset — same API call, categorically different blast radius (all of
   a host's history, not one month).
4. Never a **newer schema version** than this caller assumes.
5. Never a name **outside the `yara_scanner_*` contract**.
6. Never a dataset **written to within `min_quiet_hours`** — checked live via XQL.
7. Never a dataset **still holding a scan_id consolidation has not verified** into a per-scan
   target — checked live via XQL.

Rails 1–5 are derived from the name; **rails 6 and 7 are the only two that can see an endpoint
still WRITING to a dataset whose name says it is ancient**, which is why a name-derived
classification is never on its own enough to authorise a delete.

**`min_quiet_hours = 0` does not relax rail 6, it disables it.** The comparison
`(now - newest) < 0` is false for every dataset, including one whose newest row landed a second
ago. The pack floors the value rather than letting the rail be switched off from a console
field.

**A too-high assumed schema version fails in the dangerous direction.** Set it one version above
the fleet and every live, actively-written dataset reclassifies as *legacy*. A non-numeric value
is worse: it makes the current-version regex match nothing and the comparison
`v > cur_ver` never fire, so the entire tenant lands in `legacy`. Non-numeric input is refused
loudly at the point it is set, because that is the only place the distinction can still be made;
the too-high numeric case (`2 > 3` is simply False) is caught downstream by rails 6 and 7.

---

## 11. Concurrency control across automations

**A lock dataset is the overlap guard.** `yara_scanner_consolidation_lock` holds one row
(`holder`, `started_ms`). Two consolidation passes writing the same per-scan target is exactly
the collision per-host sharding exists to prevent (§3.3).

**The two callers judge a contended lock differently, on purpose:**

| Caller | Staleness window | Unreadable lock row | Why |
|---|---|---|---|
| Consolidation | **2 h** | treated as free | Cost of a wrong takeover is a redundant merge; the window exists so a crashed pass cannot park the pipeline forever |
| Cleanup / prune | **6 h** — set well above any consolidation runtime measured in this project | treated as **HELD** | Cost of a wrong takeover is deleting datasets while a consolidation is mid-copy — irreversible. An unreadable row is exactly the `add_data` create-lag window right after another run took the lock |

**A dry run never takes the lock.** It mutates nothing and must stay safe to run concurrently
with anything.

**A real prune takes the lock BEFORE evaluating the rails**, because rails 6 and 7 are
point-in-time checks and a consolidation pass starting between the checks and the deletes would
race them.

**Lock events exist only in the log stream, never in the structured result** — the "stale or
unreadable, taking over" that precedes force-deleting another run's marker, and the "could not
release" that parks every following pass until the marker goes stale. Both are otherwise
invisible to an operator, which is why the automations surface them explicitly.

---

## 12. Insert Parsed Alerts

- **Hard cap of 60 alerts per POST.** The endpoint accepts a *list*, so batching is what makes a
  match-heavy scan deliverable at all.
- **Rate limited at ~600 alerts/min, SHARED across every endpoint using the same API key.** When
  tripped, the API returns **HTTP 500 "Exceeding the rate limit"** (and sometimes 429). Pacing at
  60 alerts every ≥7 s ≈ 510/min stays under it. Without pacing, over-fast batches fail and
  their retries burn the upload window, starving the rest of the scan's alerts.
- **Honour the server's `Retry-After` when present**; otherwise back off exponentially, with a
  longer floor when the failure was a rate limit (a 1–2 s retry just trips it again).
- **A rate-limited batch is not a failed batch.** It can be requeued for a later window, bounded
  by a global wall-clock budget so a permanently-saturated key cannot loop forever. Requeuing
  cannot beat the shared server-side ceiling — only ride out transient saturation.
- **XDR aggregates alerts that share an `alert_name`.** This makes the alert name the identity,
  with two consequences observed live:
  - Putting the **timestamp** in the name makes every re-scan mint new alerts (a flood) *and*
    collapses distinct matches that shared a millisecond into one.
  - Putting the **offset** in the name makes every string hit its own alert (measured: a 22×
    flood on a multi-string rule) and breaks idempotency whenever a file edit shifts offsets.
  - The stable choice is `(rule, file)` — with a hash of the **full path**, since a basename
    alone collapses per-user copies of one dropper and `file_sha256` alone cannot separate
    byte-identical copies at different locations.

---

## 13. The Cortex agent payload runtime

These constrain `xdr_yara_scanner.py`, which runs as an Action Center script payload on the
endpoint.

- **The snippet/script sandbox enforces an import allowlist that rejects `secrets`.** Use
  `os.urandom` for nonce generation.
- **The agent pins Windows payload processes to a SUBSET of the host's cores** (measured: 2 of
  8). Any logic that reasons about system-wide CPU must record the affinity count, or the
  behaviour is inexplicable from the logs. `psutil.cpu_affinity()` does not exist on macOS
  (raises `AttributeError`), so the host core count must be recorded separately from it or the
  denominator is lost on every Darwin run.
- **`psutil.io_counters()` also does not exist on macOS.** Unguarded, it aborts the whole metrics
  block and zeroes memory and network readings that *do* work there.
- **`psutil`'s first `cpu_percent()` call always returns 0.0**, per `Process` object and for the
  system-wide reading. A fresh `psutil.Process()` per tick therefore reports 0.0% forever; a
  long-lived primed handle is required.
- **Action Center truncates a script's stdout at 10,240 characters.** A chatty scan pushes the
  result line out of the window entirely, so root-logger output must go to a file rather than
  stdout, and the result line must be the only thing that competes for that budget.
- **"Run by entry point" turns each parameter of the selected function into an operator input
  field.** Keeping the operator-facing entry point to three parameters is what keeps that form
  short; everything else belongs in module-level configuration.
- **Windows refuses to delete a file that is still open** (`WinError 32`), where POSIX does not.
  Every per-run log handler must be closed before anything removes the logs directory — including
  the root-logger handler, which is the one cleanup's own messages write through while it is
  deleting that very file.
- **Console Cancel hard-kills the payload.** It never writes a terminal lifecycle row, so the
  scan's lifecycle stays at `initiated`/`running` permanently. See
  [Scan_Cancellation.md](Scan_Cancellation.md); the abandoned-scan cutoff (§9.2) exists because
  of it.
- **`os.walk` yields only after its internal recursion produces the next directory**, so a
  cooperative cancel flag can go unobserved for an unbounded interval — measured on `C:\`, both
  workers stopped 4.45 s after a cancel but the process took a further **50 s** to exit. Driving
  the traversal with an explicit stack bounds cancellation latency to one `scandir`.
- **`os.walk` yields a directory root with no trailing separator.** Any path-fragment matcher
  using a bounded `/fragment/` form must also check the tail, or the directory that *is* the
  excluded component matches nothing while every file inside it matches.
- **`zipfile` only WARNS on a repeated arcname and stores the member anyway.** A content-addressed
  archive iterated by *path* therefore silently carries N copies of identical bytes while readers
  can only ever extract the first. Measured: 22,918 matched paths held 22,213 distinct files —
  705 redundant copies, **506 MB**.
- **`yara-python`'s `rules.save()` / `load()` serialization format is bound to the libyara
  version.** A compiled-ruleset disk cache must key on the exact rule text *and* the libyara
  version, binding version, platform, declared externals, module availability and a format tag,
  or it can load a stale or cross-version bundle. Any load failure must fall back to a fresh
  compile. Note that the cache key must also cover the rule **classification** logic: if that
  changes without a format-tag bump, a warm host keeps running the pre-change bundle
  indefinitely. Which modules each agent's libyara actually has is in
  [Rule_Compatibility.md](Rule_Compatibility.md).
- **Two concurrent scans on one host are not a supported configuration** under the per-scan
  overwrite model. The second scan's start-of-scan flush deletes the first's rows, because from
  the dataset's point of view they *are* a previous scan_id. One host holds one current scan; the
  `running.json` liveness marker reports that but does not enforce it.

---

## 14. The XSOAR / XSIAM automation runtime

These constrain the five `YaraDatasetManagement` automations.

- **`from CommonServerPython import *` rebinds the bare name `datetime` to the datetime CLASS.**
  CommonServerPython does `from datetime import datetime, timedelta` and declares no `__all__`.
  Any module needing the datetime *module* (`datetime.date.today()`) must re-import it **below**
  the star-import. Moving those imports up into the file's import block makes every month
  calculation fail on the tenant with `AttributeError` while unit tests stay green.
- **XSOAR MERGES (appends to) list-valued context by default across repeated calls to the same
  investigation**, rather than replacing it. Measured live: `eligible_scan_ids` grew
  **72 → 141 → 177** across consecutive status checks on one issue, even though each call's own
  return value was the correct current set. Every automation must clear its context path before
  writing, or a downstream condition task reads a poisoned union.
- **An XSOAR docker image is long-lived and serves many automation executions from one process.**
  Module globals and `os.environ` mutations outlive a single execution, so anything a run sets
  (e.g. the assumed schema version) must be reset explicitly on every run rather than inherited
  from whatever ran last.
- **An automation cannot `import` a repo module at runtime.** This is why each automation inlines
  the shared library verbatim rather than importing it, and why the ported copies drop the
  `import xdr_consolidate as C` qualifier.
- **A boolean argument may arrive as an absent key, an empty string, or a string.** Absent or
  empty must be False (that is what makes `execute` a dry run by default); anything else should
  go through strict coercion so an unrecognised value raises rather than being quietly read as
  either truth value.
- **`return_error` halts the task**, so a playbook's own downstream "flag failures" task is never
  reached from a crash path. A crash that needs to be visible must be recorded to a queryable
  dataset *before* `return_error` is called.
- **Per-run War Room entries and investigation context are not queryable across runs.** A durable
  record of what an irreversible action did requires its own lookup dataset.
- **Do not write cleanup rows into the consolidation run-log dataset.** Its schema and status
  vocabulary describe a consolidation pass, and the Consolidation Run Health widget reads "a row
  in the last ~24 h" as proof the merge Job is alive — so a cleanup row there would mask a dead
  merge Job.
- **A whole-pack zip install sets `system:true`**, after which the automations are updatable only
  from the console. See `Packs/YaraDatasetManagement/README.md`.
- **A numeric column cannot carry `None` on this API.** "No retention window was given" is a
  distinct, meaningful state and must be encoded as a sentinel (`-1`), not null.
- **A rendered fixed-width table needs a code fence** to keep its columns aligned in the War Room.

---

## 15. Capacity constants and where they come from

| Constant | Value | Basis |
|---|---|---|
| Lookup dataset size cap | **50 MB** | Platform, documented, not tunable |
| XQL result truncation | **1,000,000 rows**, silent, no pagination | Platform |
| XQL inline/stream threshold | ~**1,000 rows** | Measured live at the exact boundary |
| Alerts per POST | **60** (hard cap) | Platform |
| Alert rate limit | ~**600/min** per API key, shared | Platform |
| `add_data` rate limit | ~**1,000 entries / 10 s** | Platform |
| Rows per `add_data` POST | **500** | Larger payloads draw gateway 502s under fleet load |
| Dataset delete | ~**60 s** server-side, 12 concurrent | Measured; different-dataset deletes do not race |
| Row ceiling per consolidation | **2,000,000** | Calibrated well above the platform limit; refuses a merge too large to finish rather than half-building a target |
| Row pull per scan | **50,000** | For a single scan on a single host this is an extreme outlier |
| Quiet period | **900 s** | ≥ scanner max drain budget (600 s) + margin |
| Abandoned-scan cutoff | **24 h** | > the 6 h Action Center script timeout |
| Clock-skew tolerance | **5 min** | Measured honest gaps of 3.2–66.8 s |
| Skew backstop | **7 days** | Bounds deferral if `remove_data` re-stamps `_insert_time` |
| Consolidation lock staleness | **2 h** | Cost of a wrong takeover is a redundant merge |
| Prune lock staleness | **6 h** | Above any consolidation runtime measured here; a wrong takeover is irreversible |
| Default `min_quiet_hours` | **24 h** | Deliberately generous — proving no active writer at all, not just outlasting the drain window |
| `add_data` timeout | **5 s connect / 120 s read** | Read is well above the largest merge a size-bounded dataset can reach |
| `remove_data` timeout | **5 s connect / 200 s read** | 20× the measured 10.0 s flush |
| Attempts after a read timeout | **2** (one retry) | Each blind retry risks duplicating the batch |
| Whole-flush wall-clock budget | **300 s** | 20× the measured cost; bounds a pathological tenant's delay on every scan start |
| v4 matches row | ~**749 B** measured / ~994 B modelled | [../CAPACITY.md](../CAPACITY.md) |
| Summary row | ~**163 B** | ≈ 321,000 (host, rule) pairs per 50 MB target |

**The fleet limit for a summary target is rules matched per host × hosts in the scan** — never
host count on its own.

**Dataset size tracks how often rules fire, not how much you scan.** A targeted scan with loose
string rules costs more than a filesystem sweep with precise ones. See
[../CAPACITY.md](../CAPACITY.md).
