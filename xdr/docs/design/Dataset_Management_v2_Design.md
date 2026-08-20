# Dataset management v2 — design

**Status: DESIGN, agreed shape, not built.** Supersedes `Dataset_Management_Design.md`
(2026-08-19) for everything concerning *what consolidation produces and how it is bounded*.
The parts of that document about the correlation-rule trigger stand as history; §6 of it
already killed the shared endpoint-written tracker on concurrency grounds, and §1 of this
document kills two more of its load-bearing assumptions on capacity grounds.

Written 2026-08-20, after a day of measurement against `api-emea-cxdrp.xdr.eu.paloaltonetworks.com`
and against the shipped parsers in this repo. Every claim below is either cited to `file:line`,
reproduced by running the real code, or marked **UNPROVEN**.


> **Capacity figures superseded.** This document models 994 B/row from the `/etc` scan. A
> later `/usr` scan (93,137 files, 1,836 findings, 1,097 v4 rows) measured **749 B/row** and a
> **1.97% match rate**, so the per-host estimates here are pessimistic by roughly 25% on bytes
> and far more on file counts. The design and its constraint analysis stand; for the numbers to
> quote a customer, use [`../CAPACITY.md`](../CAPACITY.md), which is measured rather than
> modelled. The disagreement is itself the finding: dataset size tracks how often rules fire,
> not how much is scanned.


---

## 1. What changed

Six facts. Four are platform limits we did not previously know; two are defects in what we
have already shipped. Together they invalidate the current design's central promise.

### 1.1 A lookup dataset is capped at 50 MB. Hard.

Documented on the lookups API page. This is the fact the entire previous design is silent
about, and the silence is total: grepping `Dataset_Management_Design.md` for
`50 MB|byte|size|truncat|capacity|1,000,000` returns exactly one hit — line 297, "At any real
fleet **size**" — and that is about host count. The old design reasons in two currencies,
*concurrency* and *dataset count*, and never once in bytes. Every invalidation in this section
follows from that one omission.

Two consequences land immediately on that document:

- **§3.3(e), lines 145-149 — the fixed-name tracker.** *"It must stay one fixed name **forever**,
  which means its growth is bounded by **deleting rows** … never by rotating the dataset."* A
  never-rotating dataset is exactly what a hard cap forbids. At the measured lifecycle grain
  (2 rows / ~1.2 KB per scan → ~600 B/row) the tracker holds ~87,000 scans and stops. The
  document's own workload — §3.3(g): *"5,000 hosts scanned weekly"* — reaches that in ~17 weeks,
  and its stated year-one figure of 520,000 rows is **312 MB — 5.9× the cap**. Rotation was
  rejected to protect the correlation rule; the platform now forbids the alternative. The two
  constraints are mutually unsatisfiable. §6 of that document already killed this dataset for
  concurrency; capacity is a second, independent kill.
- **§3.3(g), line 155** — *"the growth rate needs stating so it is a chosen number rather than a
  surprise."* It is not a number to choose. It is a wall.

### 1.2 XQL truncates a result set at 1,000,000 rows, silently.

Status `SUCCESS`, no flag, no error. There is no pagination — *"The API does not support
pagination"*, verbatim; no offset or cursor in the request schema, and no offset stage in XQL.
Inline results cap at 1,000 rows and hand off a `stream_id` past that, and the stream does not
raise the 1,000,000. Our own code already documents the inline half of this at
`xdr/xdr_action_center.py:341-345`: *"get_query_results' own `limit` only controls INLINE
responses; past that threshold it is silently ignored"* — which means the `limit=50000` in
`_rows_for_scan` (`xdr/xdr_consolidate.py:490`) is **inert**, and the effective read bound is
the platform's silent 1M cut.

The non-XQL read path is not an escape: `POST /public_api/v1/xql/lookups/get_data` caps at
10,000 entries with no pagination.

This interacts badly with the safety design. `plan_consolidation` (`xdr_consolidate.py:400-414`)
compares a `comp count()` — one row back, never truncated — against rows actually pulled. A
truncated read therefore makes `written < source_total` **forever**: `count_mismatch` at `:414`,
sources never deleted, target permanently partial, and every retry reproduces it identically.
Verify-before-delete converts a truncation into a *permanent deadlock*: safe for the data,
fatal for the pipeline.

### 1.3 The row ceiling is calibrated 38× above the platform and can never fire first.

`DEFAULT_ROW_CEILING = 2_000_000` (`xdr_consolidate.py:61`) is ~1,896 MB of v4 rows. The guard
is checked against the source total *before* writing (`:407`, and again at `:692-694`), which is
the right design — but at a value the platform will always beat to the punch.

The general lesson, and it governs every constant in this document: **a guard is only a guard if
it fires before the thing it is guarding against.** A consumer-side ceiling set above the
platform's own limit is decoration.

### 1.4 The fan-in defect: consolidation has nothing to fan in.

Separately confirmed and documented in `xdr/docs/findings/CONSOLIDATION_SCAN_ID_MISMATCH.md`.
`scan_id` is `f"{hostname}_{run_id}_yara_{rule_hash[:12]}"` (`xdr/xdr_yara_scanner.py:2991`)
while the shard name is a function of (hostname, month) (`:4244-4252`, via `_dataset_shard_suffix`
at `:709`). So every `scan_id`'s rows of one kind live in exactly **one** shard. The fan-in
factor is identically 1, therefore `targets = |scan_ids| >= |shards|` — never a reduction, and
strictly one extra pair per re-scan within a month.

Measured against the real module and the real fake client: 20 hosts, one campaign → 40 shards →
**40 targets**. Control with a shared `scan_id`: 40 → **2**. The merge machinery is correct. It
is being handed nothing to merge.

### 1.5 Consolidation converts a prunable population into an immortal one.

Per-scan targets are excluded from retention at `xdr/xdr_data_management.py:137-141`, and again
on the legacy path at `:302-305`, on the reasoning quoted in the code: *"after the source shards
were deleted it is the only copy of that scan."* Verified by running the shipped selector: given
one month-suffixed shard and one per-scan target, the shard is deletable and the target is
skipped.

That reasoning is true, and it is also true of every shard on the tenant. Retention exists
precisely to delete only-copies on a schedule. Conflating "only copy" with "must never be
deleted" is what produced the immortal population. **On this two-host lab, every test scan of
every host leaves 2 permanent datasets** — the lab accumulates clutter in proportion to how much
we test, which is the opposite of what the tool advertises.

### 1.6 Two facts about our own tooling that no design had noticed.

**(a) The drift gate covers 1 of 12 copies.** `parse_shard` exists in **12** files in this repo —
`xdr/xdr_consolidate.py`, six `Packs/YaraDatasetManagement/Scripts/*/*.py`, and five embedded
`.yml` copies (`Scripts/YaraConsolidateFast/YaraConsolidateFast.yml` and the four under
`unified/`). `parse_dataset_name` exists in 11. Both drift gates —
`tests/test_consolidation.py:1313` and `tests/test_pack_data_management.py:36` — compare only
`YaraConsolidateCommon.py`. None of the six pack automations imports it; each carries its own
copy. The gate is ~9% as strong as it reads.

**(b) The consolidation lock leases for 2 hours; a fleet merge takes 53.** `DEFAULT_LOCK_STALE_SECS
= 2 * 3600` (`xdr_consolidate.py:110`), commented *"generous: real runs take minutes, not hours."*
`started_ms` is stamped once at acquire (`:163`) and never refreshed, and `acquire_consolidation_lock`
steals any lock older than the lease. A 7,000-host merge at the documented `add_data` rate of
1,000 entries / 10 s is 52.8 hours — **26 consecutive lock steals**, each producing a second
writer against the same open target. That is the exact 87%-loss collision the lock exists to
prevent, and on the verifying path it degrades to a permanent `count_mismatch`; on
`YaraConsolidateFast`, which does not verify, to silent row loss.

### 1.7 What all of that costs, in one table

Measured on a real scan today (`xdr-agent`, `/etc`, 4 rules):

| | B/row | rows/host-scan | bytes/host-scan | machines per 50 MiB dataset |
|---|---|---|---|---|
| v3 | 838 | 5,240 | 4,391,120 | **11** |
| v4 (just shipped) | 994 | 2,713 | 2,696,722 | **19** |

v4's entire benefit is 11 machines → 19 machines, in a design that needs three orders of
magnitude. The scans (lifecycle) dataset is 2 rows / ~1.2 KB per scan and is negligible
throughout.

---

## 2. The objective

### 2.1 The old objective, and why it is unachievable

`xdr_consolidate.py:12` states it: *"so the tenant's dataset count is bounded by scans, not
hosts."* `Datasets_and_Maintenance.md:182` restates it. It cannot be delivered, for two
independent reasons:

1. Under the shipped scanner, `scans >= hosts` always (§1.4), so the bound is true and vacuous.
2. Even with fan-in fully restored, the 50 MB cap forces `ceil(N / 19)` datasets per scan at the
   measured `/etc` grain, and *more than one dataset per host* for a full-filesystem scan at the
   lab's measured hit rate. "One dataset per scan" is arithmetically impossible above 19 hosts.

The cap re-derives, from the platform side, exactly the per-scan sharding requirement that
consolidation existed to eliminate. Restoring fan-in without also sharding the target would
convert today's harmless 1:1 no-op into an **active failure at 20 hosts**, because `target_name`
(`xdr_consolidate.py:177-180`) emits exactly one name per `(kind, ver, scan_id)` with no shard
index and no rollover.

### 2.2 The binding claim

> **A month of fleet scanning leaves a number of lookup datasets proportional to the bytes it
> produced, not to the number of hosts that produced them — and every dataset consolidation
> creates is deletable by the same age-based retention that governs the shards it replaced.**

Two clauses, both falsifiable, and the second is not optional garnish. A design that reduces
count while minting immortal datasets is the one we already have, and it is strictly worse than
doing nothing.

Concretely, at the measured `/etc` grain and monthly cadence: **28 host-scans collapse into one
dataset, and nothing consolidation creates outlives the retention window.**

---

## 3. The recommended design: byte-bounded monthly parts

### 3.1 Where it comes from

This is a synthesis, not a pick. Three designs were written and judged; the spine is the
byte-packing one, with two of the other two's best ideas grafted on and one of their premises
explicitly rejected.

| Taken | From | Why |
|---|---|---|
| Byte-bounded numbered parts, keyed on (kind, ver, month) | **chunked** | The only packing key that is knowable client-side and tight against the actual constraint. Needs no scanner change, so it works on the tenant's existing v2/v3 data today. |
| Month in the dataset name, so retention is *inherited* rather than rewritten | **chunked** | Verified below: the shipped selector already prunes it, unchanged. |
| The `parse_shard` self-consumption guard, and the discovery that it is needed | **chunked** | Verified real. The shipped consolidator *will* eat its own output. |
| Silent-truncation detection via the existing `_scan_stats` count | **chunked** | Free, and it retires §1.2's permanent deadlock. |
| "The scan is the atom of verification and cleanup" — stated as an invariant | **campaign** | Its host-is-the-atom rule, generalised. Makes verification granularity equal cleanup granularity by construction. |
| The naming-collision discipline: shapes must be *structurally* disjoint, never prefix-guarded | **campaign** | Its `c_`-prefix finding — a host named `C-01` would have gone permanently invisible. The lesson generalises to our part names. |
| `campaign_id` as a real column (decoupled from packing) | **campaign** | `remove_lookup_data` is exact-value-only, so campaign-scoped row cleanup *requires* a column. Independently valuable; not on the critical path. |
| "Calibrate the guard below the platform, not above it" | **tiered** | Its diagnosis of why `DEFAULT_ROW_CEILING` never fires is the sharpest single observation in the set, and it governs every constant here. |
| `R_hit` / hit-rate measurement as standing instrumentation | **tiered** | Measurable today on data that already exists. It is what decides whether §5.1 ever becomes urgent. |

**Rejected, and why it matters to say so:** *tiered*'s core proposal — move full fidelity out of
lookups into an on-endpoint bundle and keep only a per-`(scan, rule)` scorecard — is the most
structurally correct answer to the byte problem, and it is deferred rather than adopted. Two
reasons. It does not reduce dataset count at all (7,000 hosts still means 14,000 shards/month,
by its own admission), so it must be *paired* with something like this design rather than
replacing it. And its evidence path is not buildable as specified: `read_file`
(`xdr_action_center.py:250`) caps at `max_bytes=2_000_000` against a **live** endpoint, so a
bundle for a host at the measured full-filesystem hit rate is orders of magnitude past the
transport, and a reimaged host has no evidence at any price. Its diagnosis is kept; its grain
change is not taken now. §5.1 records the condition under which we revisit it.

Also rejected, permanently, so nobody re-proposes it: **alerts as a storage tier.** Insert
Parsed Alerts is rate-limited to ~600 alerts/min *shared across every endpoint on the API key*
(`xdr_yara_scanner.py:162-166`, and the 500-per-scan rollup cap at `:260`). A 7,000-host campaign
at 2,713 findings/host is 19M alerts ≈ 22 days of continuous posting. The alert channel is a
notification tier with a throughput ceiling tighter than the 50 MB cap.

### 3.2 The rule, for a customer

> Consolidation no longer makes one dataset per scan. It keeps a short numbered series of
> storage bins per month — `yara_scanner_matches_v4_part001_202608`, `part002`, and so on. Each
> bin is filled with finished scans' findings until it is nearly full against the platform's
> 50 MB dataset limit, then sealed, and the next scan goes into the next bin. A scan normally
> lands whole in one bin; a very large scan is split across consecutive bins. Every bin's name
> carries the month whose scans it holds, so bins are pruned by exactly the same age-based
> retention you already run against the per-host datasets — **nothing consolidation creates
> lives forever.** Your dashboards need no change: they already match `yara_scanner_matches*`
> and pick up bins automatically.

### 3.3 The name, and why every segment is where it is

```
shard (unchanged):  yara_scanner_<kind>_v<ver>_<host>_<6hex>[_<YYYYMM>]
part  (new):        yara_scanner_<kind>_v<ver>_part<NNN>_<YYYYMM>
```

`NNN` is zero-padded to 3 and widens past 999 (§4.5).

**The month goes last, and that is load-bearing in two directions at once.** Run against the
shipped parsers:

```
parse_dataset_name("yara_scanner_matches_v4_part007_202608")
  -> {kind: 'matches', version: 4, host: 'part007', month: '202608', scan_target: False}

parse_shard("yara_scanner_matches_v4_part007_202608")
  -> {kind: 'matches', ver: '4', host: 'part007_202608', month: None}     # MATCHES. Hazard.
```

The first result is the whole retention fix: `MONTH_RE` (`xdr_data_management.py:54`) reads the
trailing `_202608` as the rotation month and `part007` as the host, so the part flows through
`select_rotated_for_deletion` (`:119`) as an ordinary rotated dataset — has a month, not the
current month, not future, `scan_target` False → **candidate**, with zero selector changes. The
immortality exclusion at `:137-141` keys on `scan_target`, which is False. Retention is
*inherited*, not rewritten, and code we do not write cannot be wrong.

The second result is a live defect we would create. `_SHARD_RE` (`xdr_consolidate.py:46`) has host
group `.+?_[0-9a-f]{6}`, and `202608` is six valid hex digits, so `part007_202608` reads as a
host. Ship the name without a guard and **the consolidator re-consumes its own parts as source
shards, merging parts into parts forever — and verification passes, because the row counts
genuinely agree.** `_PART_RE` must therefore be tested *before* `_SHARD_RE` in `parse_shard`, which
returns `None` for a match, mirroring the existing `scan_`/`scan` exclusion at `:190-193`.

**The guard is structural, not a prefix test.** This is the lesson lifted from the campaign
design, which found that a `c_`-prefix guard would make a host named `C-01` (slugging to
`c_01_<hex>`) permanently invisible to consolidation. Ours is:

```
_PART_RE = ^yara_scanner_(?P<kind>matches|scans)_v(?P<ver>\d+)
           _part(?P<part_no>\d{3,})_(?P<month>20\d{2}(?:0[1-9]|1[0-2]))$
```

A *month-suffixed* shard can never match it: the shard's host segment mandatorily ends in
`_<6hex>` (`_dataset_shard_suffix`, `xdr_yara_scanner.py:709-720`), and `part\d{3,}` contains no
underscore. Verified in the other direction too — a host that genuinely slugs to `part007` still
reads as a shard, because of that mandatory hex suffix:

```
parse_shard("yara_scanner_matches_v4_part007_a1b2c3_202608")
  -> {host: 'part007_a1b2c3', month: '202608'}     # still a shard. Correct.
```

**Residual, stated because it is not zero.** An *unrotated* shard (`CONFIG_LOOKUP_ROTATION="none"`)
for a host slugging to exactly `part<digits>` whose 6-hex suffix also happens to be a plausible
`20YY(01-12)` would be eaten by `_PART_RE`. The hex space admits 1,200 of 16^6 values → 7.2e-5,
times the host-name condition. Mitigation is a pinned regression test plus, if we ever see it,
an index cross-check (a name matching `_PART_RE` with no placement rows in the index is not a
part). Not worth more machinery than that, but worth writing down.

### 3.4 The packing rule

Let `PART_BYTE_BUDGET = 40_000_000` and
`row_bytes(r) = len(json.dumps(r, separators=(",",":"), default=str))` measured on the *coerced*
row — exactly what goes on the wire via `_coerce_row` (`xdr_consolidate.py:551`). Per bin key
`(kind, ver, month)`, processing scans in `scan_id` order:

1. Open part = the highest-numbered part for the key with `bytes_used < budget`; else open `N+1`.
2. `need = Σ row_bytes` for this scan.
3. `need ≤ budget − bytes_used` → write into the open part.
4. `need ≤ budget` → **seal** the open part, open the next, write there.
   *(A scan is never split when it could be whole.)*
5. `need > budget` → split across consecutive parts, filling and sealing each.
6. Verify, then clean the source rows — **once, after the scan's last part**, never per part.

Sealing is one-way. A sealed part is never written again, which is what makes `bytes_used`
monotone and the accounting auditable.

**The month is the scan's, not the consolidator's.** Derived from the rows'
`event_timestamp_ms`, not from `time.time()`. Keying on the clock would let an Aug 31 scan
consolidated Sep 1 land in a September part and outlive its own retention window by a month, and
would create parts spanning two months whose age label means nothing. Keyed on the scan's month,
a part's label is exactly true of every row in it.

### 3.5 The invariant

> **The scan is the atom of verification and cleanup.** A scan's rows may span several parts, but
> they are counted as a set, verified as a set, and removed from their sources as a set. A scan
> is never partially cleaned.

This is campaign's host-is-the-atom rule generalised to our packing key, and it is what makes
splitting safe. The specific hazard splitting introduces is a scan half-verified against one part
and then cleaned anyway; the invariant closes it by construction rather than by care. It is why
step 6 above says *once, after the last part* — that ordering is not an optimisation, it is the
invariant's only enforcement point.

Verification stays exact and gets *cheaper* than today for a large scan: instead of one
`comp count()` on a monolithic target, it is `Σ` over the scan's `k` touched parts of
`dataset = <part> | filter scan_id = "S" | comp count() as n` — at most `k+1` aggregations, each
returning one row, none of them ever truncated. **Parts are never read back by row content,
only by aggregation, so the 1M read cap never applies to the target side at all.** That is a
structural advantage over any design that verifies by pulling rows out of the target.

### 3.6 The index

`yara_scanner_index_parts_<YYYYMM>` — one row per (part, scan_id) placement:

| column | job |
|---|---|
| `part`, `kind`, `ver`, `month`, `part_no` | identity |
| `scan_id`, `hostname` | the reader's map from a scan to its parts |
| `rows`, `bytes` | `bytes_used` across runs, via one `comp sum(bytes) by part` |
| `sealed` | one-way seal state |
| `event_timestamp_ms` | ordinary retention bookkeeping |

It is a shared lookup, which the old design rightly killed for the endpoint-written tracker (§6
there, 75-87% loss) — but that verdict was about **concurrency**, and this has exactly **one
writer, ever**: the consolidator, already single-sequential and already holding
`acquire_consolidation_lock`. `yara_scanner_consolidation_runs` (`YaraConsolidateApply.py:175`) is
the existing precedent for a single-writer shared lookup on this tenant. Unlike that one, this
rotates monthly and has a retirement path: a placement row is removed by exact-value
`remove_lookup_data(index, [{"part": <name>}])` when its part is deleted, and the whole index
dies with its month.

It is **self-healing on the row axis**: after each write, compare `comp count()` on the part
against the index's `Σ rows`; on divergence, rebuild that part's placements from
`comp count() as n by scan_id` on the part itself.

**It is not self-healing on the byte axis, and that gap needs closing.** `acquire_consolidation_lock`
documents itself as *"Best-effort mutual exclusion, **NOT** a true distributed lock"*
(`xdr_consolidate.py:105`), with an explicit `on_takeover` path. A takeover mid-run would corrupt
the one axis the self-heal cannot reconstruct, and the budget headroom is already spent absorbing
the byte-ratio risk (§7.1) — two risks stacked on one margin. The fix is cheap and mandatory:
**on lock acquisition, re-measure the open part's bytes from its own rows rather than trusting the
index**, so `bytes_used` is always recoverable without the index. Combined with the heartbeat in
§3.7, a takeover becomes a slow start rather than a corruption.

The index's own capacity: ~200 B/row → 262,144 placements per 50 MiB month. 7,000 monthly scans
uses 7,000 (37× headroom); weekly, 30,000 (8.7×).

### 3.7 What changes, by file

#### `xdr/xdr_yara_scanner.py` — nothing

`scan_id` (`:2991`), the shard name (`:4244-4252`), `_dataset_shard_suffix` (`:709`),
`MATCHES_SCHEMA_V4`, rotation, the schema version (`:374`, `:4183`) — all untouched. No schema
bump, no option key, no delivery change, no fleet rollout window, no mixed-grain coexistence
period. **This is the design's central practical advantage and it should be weighed as such:** it
is the only reason this works on the tenant's existing v2/v3 datasets on day one. Two comment
blocks (`:361-362`, `:4245-4248`) deserve a mention of parts; zero code.

`campaign_id` (§3.9) is the one scanner change, and it is deliberately *not* on this critical
path.

#### `xdr/xdr_consolidate.py` — the bulk

| Symbol | Change |
|---|---|
| `parse_shard` (`:183`) | **Mandatory guard**, first statement: `if _PART_RE.match(name): return None`. Without it the tool eats its own output (§3.3). |
| new `_PART_RE`, `parse_part`, `part_name(kind, ver, month, n)` | Per §3.3. |
| `target_name` (`:177`) | Retained as a shim, used **only** by the legacy-retirement path (§6, Phase 2) and by un-ported pack copies until they land. |
| `DEFAULT_ROW_CEILING` (`:61`) | Deleted as the guard. Replaced by `PART_BYTE_BUDGET = 40_000_000` and `MAX_SCAN_PARTS = 10` (§4.4). Bytes are the currency now. |
| new index helpers | `_index_dataset(month)`, `_read_placements`, `_record_placement`, `_bytes_used`, `_open_part`, `_remeasure_open_part`. |
| `group_shards_by_scan` (`:201`) | Grouping key gains the scan's month, derived from `_scan_stats`' `newest`. |
| `plan_consolidation` (`:400`) | `target_count` becomes `Σ` over the scan's touched parts of a filtered `comp count()`. Two new refusals: `outside_retention_window` (§3.8) and `scan_exceeds_max_parts`. The verify-before-delete guarantee is preserved bit-for-bit. |
| `_rows_for_scan` (`:490`) | Add the truncation detector: `_scan_stats` (`:522`) has already computed this shard's exact `comp count()` for this scan, so `len(rows) < stat.count` is free. Abort with new reason `source_read_truncated` rather than writing a partial part and deadlocking on `count_mismatch` forever (§1.2). |
| `_cleanup_verified_scan_rows` (`:496`) | Body unchanged; call site moves to after the scan's **last** part verifies (§3.5). |
| `run_consolidation` (`:604`) | The write section (`:756-771`) becomes the packing loop of §3.4. Idempotency PATH A (`:721`) and A2 (`:745`) re-key on the index rather than on `_count(target)`. |
| `acquire_consolidation_lock` (`:110-172`) | **Heartbeat `started_ms`** every `_WRITE_BATCH` flush or 60 s, whichever comes first, so the 2 h lease measures liveness rather than start time (§1.6b). On acquisition, `_remeasure_open_part` (§3.6). |
| `_gate_scan` (`:916`), `build_terminal_map` (`:340`), `_newest_ms`, `_scan_stats`, `_delete_many` (`:890`), `KNOWN_MATCHES_SCHEMA_VERSIONS` (`:458`), `matches_schema_for` | **Unchanged.** Every existing safety rail survives intact. |

`ver` is in the bin key, so a v2, v3 and v4 scan can never share a part. Required — their columns
differ — and it matches `run_consolidation`'s existing per-version discipline.

#### `xdr/xdr_data_management.py`

| Symbol | Change |
|---|---|
| `parse_dataset_name` (`:63`) | Add a `part_target: bool` flag for reporting. Do **not** set `scan_target` for a part — that flag *is* the immortality flag. |
| `select_rotated_for_deletion` (`:119`) | **No functional change.** Verified against the shipped selector: given `[part007_202602, part008_202608, <legacy scan target>, <real shard>_202602]` at `older_than_months=3, now=202608`, it returns candidates `['…part007_202602', '…xdr_agent_cd7e9b_202602']`, skips `part008_202608` as *"current month — a scan may be writing to it"*, and still skips the legacy `_scan_` target. **The open part is protected by the existing current-month rail, for free.** Only a report string needs a tweak. |
| `filter_unconsolidated` (`:197`) | **Mandatory rewrite — without it parts are immortal again, for a subtler reason than before.** It computes `C.target_name(kind, ver, sid)`; for a part's scan that yields a nonexistent `…_scan_<sid>`, so `tcount` is 0 or −1, never `n`, so every part is permanently reported "stuck" and never deleted. Two fixes: (a) if the candidate is a part, skip the check — it *is* the consolidated copy; (b) for a shard, ask the index (`Σ index.rows where scan_id = sid` vs the shard's count for `sid`, plus "the named parts still exist"). |
| `filter_recently_written` (`:167`) | Unchanged, and now load-bearing — see §3.8. |
| `render_report` (`:322`) | Replace the per-scan *"CONSOLIDATED TARGETS … Never a cleanup candidate"* block (`:274-281`) — that paragraph **is** the immortality doctrine in prose — with a parts summary: part, month, rows, bytes used / budget, sealed. The fill column is the operator's early warning that the budget is mis-tuned for their ruleset. |
| new | Index retirement sweep — the index name does not match `YARA_OWNED_RE` (`xdr_action_center.py:44`), so it is invisible to `classify_yara_datasets` (`:474`) and needs an explicit path. Safe from `--delete-legacy`, but also not pruned by it. And `--retire-scan-targets --older-than-months N` for the legacy immortal population (§6, Phase 2). |
| `--row-ceiling` (`:~468`) | → `--part-bytes`; keep `--row-ceiling` as a deprecated no-op alias so existing Job configs do not error. |

#### The pack — twelve copies, one gate

Every logic change above must land in all six `Packs/YaraDatasetManagement/Scripts/*/*.py`
automations and the five embedded `.yml` copies. **Widening `_SHARED_GATE_FUNCS` coverage
(`tests/test_consolidation.py:1273-1287`) from `YaraConsolidateCommon.py` to all of them is a
prerequisite commit, not cleanup** (§1.6a) — it is cheap, it is a pure no-op today, and it is the
only thing that makes the rest of this tractable rather than a drift hazard.

`YaraConsolidateFast` keeps its documented asymmetry (matches merged, scans retention-only) and
needs one extra decision: it buys no verification, so it cannot use the per-part filtered count.
It records bytes **optimistically** — what it sent, not what landed. A failed write therefore
inflates `bytes_used` and seals early, which errs toward under-filling. That is the safe
direction, and it should be stated in its docstring rather than discovered.

`Playbooks/playbook-YARA_Dataset_Consolidation.yml` passes only `scan_id` lists and reads
`eligible/pending/failed_scan_ids` — **no functional change** — but its description at `:4` and
`:43` ("into one dataset per scan") becomes false and must be reworded.

#### Widgets — no change required

Verified across all 41 files in `xdr/widgets/`: every one reads through bare-prefix wildcards,
`dataset = yara_scanner_matches*` (14 files) or `yara_scanner_scans*` (the rest), with no version
or host segment. `yara_scanner_matches_v4_part007_202608` joins them automatically. The read path
was designed for this from the start (`xdr_yara_scanner.py:361-362`: *"dashboards fan back in with
a wildcard"*) and already spans mixed v2/v3/v4 shapes.

**Reader semantics, to be said plainly to operators:** a single-scan query becomes
`dataset = yara_scanner_matches* | filter scan_id = "<id>"`. The wildcard *is* the union; XQL
offers no other, and the index is a diagnostic, not a required read path. The double-count window
between merge and source cleanup is unchanged from today and is already narrowed by
`_cleanup_verified_scan_rows`.

One new widget is worth adding from the index: part fill level, seal state, bytes vs budget.

### 3.8 The hard precondition that is not an optimisation

**Refuse to consolidate any scan whose month already sits outside the retention window.**

Consolidating a stale scan mints a part labelled with that stale month — instantly age-eligible,
with its sources just deleted. The only thing standing between it and same-day deletion is
`filter_recently_written`'s 24 h quiet check (`xdr_data_management.py:167`). That is one rail
between a merge and permanent data loss, and it is a rail designed for a different job.

This is **the design's only data-loss path**, and it belongs in `plan_consolidation` as a refusal
reason (`outside_retention_window`), not in a runbook and not as a "cheap add". It also happens to
save hours of `add_data` spent merging data the next prune deletes.

### 3.9 `campaign_id`, deliberately off the critical path

Add `campaign_id` as a real column to the matches and scans schemas at the next schema bump,
populated from a new option key generated once per Action Center group action. It rides inside
existing snippet param 5 (`xdr_yara_scanner.py:8388-8400`), so **no script-library re-definition is
needed** — only code.

Two reasons it earns its place, both independent of this design:

- `remove_lookup_data` filters are **exact values only, no wildcards** (old design §3.4/Q3). So
  campaign-scoped row cleanup *requires* it as an exact-match column; a prefix on `scan_id` would
  force one filter block per host-scan.
- *"Did my fleet scan actually reach every host"* is currently only approximable. One new widget —
  `comp count_distinct(hostname) as hosts_done, max(campaign_size) as hosts_expected by campaign_id` —
  answers it exactly.

And one reason it is **not the packing key**: making it so would gate every byte of benefit behind
a full fleet rollout to a new schema *plus* a permanent per-launch orchestration ritual that can be
forgotten, with no recovery for an untagged scan. Packing on (kind, ver, month) is indifferent to
whether `campaign_id` exists, to whether it was set, and to the fan-in defect entirely. That
indifference is the point.

---

## 4. Capacity

All figures at the measured `/etc` grain unless stated. Cap = 50 MiB = **52,428,800 B**. Budget =
**40,000,000 B** (76.3% of cap).

### 4.1 The two numbers a reader needs

```
rows per part   = 40,000,000 / 994 B      = 40,241
rows per host-scan (measured, /etc, 4 rules) = 2,713
host-scans per part = 40,241 / 2,713      = 14
```

**Fourteen host-scans per part.** Whole-scan packing leaves 2,259 rows of tail slack (5.6%);
combined with the budget headroom, a full part uses 37,754,108 B = **72.0% of the platform cap**.
That is the price of not knowing the stored-byte ratio yet (§7.1).

| | B/row | rows/part | rows/host-scan | **host-scans per part** |
|---|---|---|---|---|
| v3 | 838 | 47,732 | 5,240 | **9** |
| v4 | 994 | 40,241 | 2,713 | **14** |
| scans (lifecycle) | ~600 | 66,666 | 2 | **33,333** |

One `scans` part covers any realistic campaign.

### 4.2 How many machines can I scan? — look it up

**Machines per part is set by rows per host-scan, and nothing else.** Find your row count in the
left column:

| rows per host-scan | typical of | host-scans per part | reduction at monthly cadence |
|---|---|---|---|
| 100 | a tight pack on a clean host | 402 | 804× |
| 1,000 | a targeted malware-family pack | 40 | 80× |
| **2,713** | **measured: `/etc`, 4 broad lab rules** | **14** | **28×** |
| 5,000 | | 8 | 16× |
| 10,000 | a broad hygiene pack | 4 | 8× |
| 20,000 | | 2 | 4× |
| 40,241 | | 1 | 2× |
| 80,000 | | splits over 2 parts | 1× |
| 300,000 | full filesystem at the lab's near-unity hit rate | splits over 8 parts | 0.25× |
| **> 402,410** | runaway ruleset | **REFUSED** (`scan_exceeds_max_parts`) | — |

**Machines per campaign is unbounded.** Past 14 machines nothing happens except a new part. This
is the direct answer to the question the old design could not give: there is no host count at
which this fails, in contrast to a single per-scan target, which fails at exactly 20.

### 4.3 Fleet sizes, in datasets

Monthly cadence, `/etc` grain, whole-scan packing:

| fleet | shards/month (2N) | matches parts | scans parts | total after | reduction |
|---|---|---|---|---|---|
| 10 | 20 | 1 | 1 | **2** | 10× |
| 20 | 40 | 2 | 1 | **3** | 13.3× |
| 100 | 200 | 8 | 1 | **9** | 22.2× |
| 1,000 | 2,000 | 72 | 1 | **73** | 27.4× |
| 7,000 | 14,000 | 500 | 1 | **501** | **27.9×** |
| 50,000 | 100,000 | 3,572 | 2 | **3,574** | 28.0× |

Asymptotically constant at `2 × host-scans-per-part = 28×`.

For contrast, the same 7,000-host campaign under the alternatives: per-scan targets on the shipped
`scan_id` give 14,000 → 14,000 (**1.0×, no reduction**); fixing fan-in *and* sharding the target
gives `ceil(7000/19) × 2 = 738`. **Byte-packing beats id-packing 501 to 738**, and needs no scanner
change, no schema bump, and no mixed-grain rollout window — because the byte budget is the tightest
available packing key and it is already knowable client-side.

### 4.4 Cadence, and the one clean result

Shards are month-rotated, so a host's `S` scans in a month share one shard pair: shards = `2H`
regardless of `S`. Parts scale with volume. With 14 host-scans per part:

```
R = 28 / S
```

| cadence | S | R | parts/mo (7,000 hosts) | shards/mo |
|---|---|---|---|---|
| monthly | 1 | **28×** | 501 | 14,000 |
| weekly | 4 | **7×** | 2,001 | 14,000 |
| fortnightly-ish | 19 | **1.47×** | 9,501 | 14,000 |
| daily | 30 | 0.93× | 15,001 | 14,000 |

Naïvely that last row says chunking loses at daily cadence. It does not, and the reason is worth
stating because it is the cleanest consequence of the whole analysis: **a shard itself busts the
50 MiB cap at `S × 2,696,722 > 52,428,800`, i.e. at `S > 19`.** So in the entire regime where
shards work at all, `S ≤ 19`, and `R = 28/S ≥ 1.47×`. Above `S = 19` the scanner is already
failing and the comparison is against something broken.

> **Wherever a shard is viable, parts reduce dataset count. Where a shard is not viable, parts are
> the only structure that can hold the data at all.**

### 4.5 What actually runs out

| # | Limit | Where it bites | Headroom at 7,000 hosts, monthly |
|---|---|---|---|
| 1 | Stored:payload byte ratio (**UNPROVEN**) | budget must stay under the cap | tolerates up to **1.31** |
| 2 | `MAX_SCAN_PARTS = 10` → 402,410 rows / host-scan | a runaway ruleset, refused not half-built | 148× |
| 3 | XQL 1M silent truncation, per (shard, scan_id) | now **detected**; limit #2 refuses first | 2.5× below the cap by construction |
| 4 | `add_data` wall clock | 52.8 h; **breaches the 2 h lock lease 26×** | see §5.7 |
| 5 | Part-number space `part%03d` | 999 × 40 MB = **39.96 GB** per (kind, ver, month) = 13,986 host-scans/mo | 2× |
| 6 | Index 50 MiB | 262,144 placements/month | 37× |

On #5: past 999 the format widens to 4 digits, at which point names sort lexically wrong
(`part1000` < `part999`). That is harmless because the open part is selected **numerically from
the index**, never lexically — and that fact must be pinned by a test, because it is exactly the
kind of thing a later refactor breaks silently.

On #2 and #3 together, note what changed. `MAX_SCAN_PARTS = 10` puts the refusal at 402,410 rows,
**2.5× below** the platform's 1M truncation, and the refusal is computed from `_scan_stats`'
exact `comp count()` (`xdr_consolidate.py:522`) before any row is pulled. The guard fires before
the platform. That is the one property `DEFAULT_ROW_CEILING = 2_000_000` never had (§1.3). The
value 10 is calibrated to admit the worst regime we have actually measured — ~300,000 rows for a
full-filesystem scan at the lab's near-unity hit rate — with margin, and to refuse anything beyond
it.

### 4.6 Time, and what binds first now

| fleet | rows | add_data time | shard-delete time (12-wide, ~60 s each) | lock steals at a 2 h lease |
|---|---|---|---|---|
| 10 | 27,130 | 4.5 min | 1.7 min | 0 |
| 100 | 271,300 | 45 min | 17 min | 0 |
| 1,000 | 2,713,000 | 7.5 h | 2.8 h | **3** |
| 7,000 | 18,991,000 | **52.8 h** | 19.4 h | **26** |

**The binding order has changed, and this is the headline of the whole capacity section.** Before:
the 50 MB write cap bound at 20 hosts, 18× earlier than anything else. After: the write cap does
not bind at any fleet size, and what binds is **wall clock and the lock lease** — a schedule
problem and a bug, in that order. The bug is not optional: 26 lock steals is 26 concurrent second
writers against an open part, which is precisely the 87%-loss collision the lock exists to
prevent. Heartbeat the lease (§3.7) before anyone runs this at fleet scale.

One available speedup is worth naming and not relying on: parts are *different datasets*, and the
87% loss was measured on *same-dataset* concurrency. Concurrent writes to different parts would cut
52.8 h to ~4.4 h at 12-wide — but different-dataset **writes** are **UNPROVEN** safe in this repo
(only different-dataset *deletes* were verified). Measure before building on it.

---

## 5. What is not solved, and what the customer must be told they cannot do

### 5.1 The shard side is not fixed. This is the largest remaining gap.

A host writing more than 50 MiB in a month breaks **its own shard**, before consolidation ever
sees it. At the measured `/etc` grain that is 19 scans a month. For a full-filesystem scan at the
lab's measured near-unity hit rate — ~300,000 matched files, 298 MB — it is **every host, on the
first scan.**

Parts hold what shards produce; they cannot rescue what a shard could not accept. There is no
producer-side guard anywhere: the scanner will happily keep calling `add_data` past the cap, and
we do not currently know whether the platform refuses that loudly or silently (§7.1).

The sketched fix, deliberately *not* scoped into this design, is a scanner-side byte budget that
rolls the shard to a sub-month sequence — `<host>_s02_<6hex>_<YYYYMM>`, which parses today as an
ordinary shard for a host named `<host>_s02` and therefore needs no parser change and prunes
normally. It is Phase 5 (§6), gated on the hit-rate measurement in §7.7, because it is unnecessary
for a targeted pack and unavoidable for a broad one, and we do not yet know which our customers
run.

### 5.2 The fan-in defect is not fixed

Multi-host correlation on `scan_id` is exactly as it is today. Anyone who wanted "one dataset per
campaign" does not get it — and cannot get it on this platform above 19 hosts anyway (§2.1). What
they get is `campaign_id` as a column and a coverage widget (§3.9).

### 5.3 Per-scan dataset isolation is gone

A scan's rows are no longer in a dataset named after it. Anything that wanted dataset-level
granularity per scan — a per-scan export, dataset-scoped RBAC, "hand me this campaign's data" —
becomes a `filter`, not a name. **This is the single largest concession and it is irreversible
without re-sharding.**

### 5.4 Retention granularity coarsens to the part

A part is deleted whole. One scan's findings cannot be kept longer than its 14 part-mates', and a
part cannot be dropped early because one scan in it turned out to be junk. `remove_data` by
`scan_id` still works for surgical row removal, but the **dataset** is now the retention unit.

### 5.5 Blast radius per delete rises ~14×

A mistaken delete destroys ~14 host-scans instead of one host's month. Every existing rail is
unchanged and adequate; the *consequence* of a rail failing is larger.

### 5.6 Consolidated findings become deletable

That is the entire point of §2.2 and §3.3, but it is a real behaviour change: those datasets are
immortal today, and it is worth assuming someone is relying on that by accident.

### 5.7 None of the time costs improve

A 7,000-host campaign is still 18,991,000 rows: ~52.8 h of `add_data` and ~19.4 h of shard
deletion. **This is a scheduled Job, not an interactive command, at any fleet size that motivated
the tool**, and it must stay per-scan resumable. Consolidation runs must not be allowed to overlap
the next scheduled one.

### 5.8 24% of every part is wasted by construction

Plus 5.6% tail slack. The design buys safety margin with capacity, and it buys it against a ratio
we have not yet measured. §7.1 replaces the guess with a number, and the budget should be re-tuned
from it.

### 5.9 New shared state

The index is a new dataset, a new divergence mode, and a new thing to prune — mitigated by
self-healing, monthly rotation, and the byte re-measurement of §3.6, but it did not exist before.

### 5.10 Twelve hand-ported copies

Every logic change lands twelve times, gated by two drift tests that must be widened first.

---

## 6. Migration, from the tenant as it actually is

**Current state:** 183 datasets, mixed v2/v3, five automations deployed, v4 shipped today, and an
unknown number of immortal `_scan_` targets from earlier applied consolidation and from lab
testing.

**Why this design works on that tenant at all:** packing is keyed on (kind, ver, month) and is
**completely indifferent to the fan-in defect**. It does not care whether the v2/v3 shards' scan
ids fan in (they do — pre-v4 history shares a rule-hash `scan_id`) or whether the v4 ones do not.
It needs no scanner change, so the 183 existing datasets are consolidatable on day one. A design
keyed on a new schema column could not touch any of them until the fleet had fully rolled over.

`ver` in the bin key means v2 and v3 pack into separate series
(`yara_scanner_matches_v2_part001_202607`, `…_v3_part001_202607`), which is required because their
columns differ. Note for the operator: `YARA_SCHEMA_VERSION` defaults to `"2"`
(`xdr_action_center.py:43`), so with the default, v3/v4 parts classify as "newer" and are protected
from `--delete-legacy`, while v2 parts classify as CURRENT and are equally safe. An operator who
sets `YARA_LOOKUP_SCHEMA_VER=4` and runs `--delete-legacy` will delete v2 and v3 parts along with
their source shards — which is correct, and worth knowing before doing it.

### Phase 0 — today, no code

**Stop running `xdr_data_management.py --consolidate --yes`.** Already the finding document's
operational conclusion; capacity reinforces it. Today the tool trades prunable datasets for
unprunable ones at no count reduction, and the first fix that restores fan-in without sharding the
target would break it at 20 hosts. Dry runs remain safe and informative.

### Phase 1 — prerequisites. All no-ops on today's tenant. Ships first, alone.

1. Widen `_SHARED_GATE_FUNCS` coverage to all 12 `parse_shard` / 11 `parse_dataset_name` copies
   (`tests/test_consolidation.py:1273-1287`, `tests/test_pack_data_management.py:36`).
2. Ship the `parse_shard` part-guard (`_PART_RE` → `None`) to **all twelve copies**.
3. Heartbeat the consolidation lock; re-measure the open part's bytes on acquisition.

**The ordering is load-bearing and it is not the obvious ordering.** The guard must reach the pack
copies *before* any CLI change, because a tenant running a new CLI against an un-ported pack has a
scheduled automation that re-consumes parts as source shards, merging parts into parts under the
same lock, with verification passing because the counts genuinely agree. It is a pure no-op today
— no parts exist — and shipping it late is the worst mid-migration failure available.

### Phase 2 — retention repair. Independently valuable, independently shippable.

4. Rewrite `filter_unconsolidated` to be part-aware (`xdr_data_management.py:197`).
5. Replace the *"per-scan CONSOLIDATED TARGETS … Never a cleanup candidate"* report block.
6. Add `--retire-scan-targets --older-than-months N` for the legacy immortal population. Their
   names carry no month by design, so they must be aged by content
   (`comp max(event_timestamp_ms)`, the query shape `filter_recently_written` already uses) and
   sit behind an explicit flag, because it deletes what today's code calls the only copy.

**Do not bundle this behind the parts work.** It un-does the harm already done, it clears the lab's
accumulated test clutter, and it needs none of the packing machinery. Run it once and the `_scan_`
shape is dead.

### Phase 3 — parts

7. `_PART_RE`, `part_name`, the packing writer, the index, `--part-bytes`, the truncation detector,
   `outside_retention_window`, `MAX_SCAN_PARTS`.
8. Run `--report`. Then `--consolidate` **dry-run** and read the planned part layout. Then `--yes`
   on a **single (kind, ver, month) bin key** first.
9. Port all twelve copies; both drift gates go green.

### Phase 4 — `campaign_id`, at the next schema bump

10. New option key, new column on both schemas, `run_scanner_fleet` in `xdr_action_center.py`,
    a `new-campaign` CLI subcommand for console launches, and the Campaign Coverage widget.
    Nothing in Phases 1-3 depends on it.

### Phase 5 — conditional, gated on §7.7

11. Scanner-side shard byte budget with sub-month rollover (§5.1). Build it only if the hit-rate
    measurement shows real rulesets busting the shard's own 50 MiB cap.

### What breaks mid-migration, named

- Between Phase 3 and step 9, `YaraReport`'s inventory mislabels parts (host `part007`) until its
  `render_report` ports. **Cosmetic.**
- An un-ported `filter_unconsolidated` refuses to delete shards it cannot resolve. **Conservative,
  but it stalls cleanup** until step 9.
- Any operator runbook or saved query naming a `_scan_<id>` dataset stops resolving after Phase 2
  step 6.
- Both drift gates fail on every intermediate commit until all twelve copies are mirrored. **That
  is the gate working**, and it must not be relaxed for this work.

---

## 7. What must be proven on a live tenant

Each of these is a statement that is currently unproven and that this design's correctness depends
on. Ordered by the cost of being wrong.

### 7.1 The stored:payload byte ratio is below 1.31 — **the biggest risk**

The whole design rests on `PART_BYTE_BUDGET` being below 50 MiB *in the units the platform actually
counts*. Our 994 B/row is a JSON-payload measure. If the true ratio exceeds **1.31**, a 40,000,000 B
budget crosses the cap, `add_data` fails partway through a part, and the result is a half-written
part plus a `count_mismatch` that never clears — precisely the deadlock this design exists to
avoid, arriving through the mechanism it trusts most. The ratio is also unlikely to be constant: a
wide v4 row (many rules, `truncated=true`, long `strings`) and a narrow single-rule row may store
very differently.

**Test, in this order.**

- **P1a — one API call, before any code is written.** Dump the raw `get_datasets` response
  (`xdr_action_center.py:372`) for a known-populated shard and look for any size/bytes/rows field.
  Today it is consumed for `Dataset Name` and `Type` only. If a size field exists, the entire
  estimate is replaced by a measurement and this risk mostly evaporates.
  **Acceptance:** the response either carries a size field (adopt it) or provably does not.
- **P1b — calibrate to failure.** On a throwaway lookup with the real `MATCHES_SCHEMA_V4`, write
  real v4 rows in 500-row batches, tracking cumulative payload bytes and cumulative `records_added`,
  until `add_data` errors or rows stop landing. **The payload-byte total at the failure point is
  the conversion factor.** Run it twice — once with wide rows drawn from a real high-rule-count
  scan, once with narrow single-rule rows — and set the budget from the **worse** ratio, never the
  average.
  **Acceptance:** both ratios known; budget re-derived from the worse one; if they differ by more
  than ~15%, that fact and the widened headroom are recorded here.
  This also answers the §5.1 question of whether the cap fails loudly or silently.

### 7.2 A part name is prunable, and is never re-consumable

Both directions currently verified offline against the shipped parsers; they must become pinned
regressions because both fail silently in production.
**Acceptance:** `parse_shard(part_name(...)) is None`; `select_rotated_for_deletion` returns an
aged part as a candidate and the current-month part as a skip; a host slugging to `part007` with a
real hex suffix still parses as a shard.

### 7.3 `filter_unconsolidated` returns a part as a survivor, not as "stuck"

Currently fails. Invisible in production until parts are already immortal.
**Acceptance:** a part is a survivor; a shard whose scans are fully placed in existing parts is a
survivor; a shard with an unplaced scan is skipped.

### 7.4 The split path holds its invariant

Against a fake client enforcing a hard byte cap, synthesise a scan exceeding the budget and assert:
(a) no part ever exceeds budget; (b) `Σ` per-part filtered counts equals the source count;
(c) `_cleanup_verified_scan_rows` fires **exactly once**, after the final part; (d) a mid-split
failure leaves earlier parts sealed and correct, and the scan re-runnable without duplicating rows.
**Acceptance:** all four, plus the numeric (not lexical) open-part selection past `part999`.

### 7.5 The lock survives a run longer than its lease

**Acceptance:** a simulated 3-hour run holds the lock throughout; a genuinely dead holder is still
stolen after the lease; on takeover, `bytes_used` for the open part is recovered from the part's own
rows without consulting the index, and the resulting seal decision is identical.

### 7.6 `remove_lookup_data` latency against a large shard

Campaign cleanup is serialised. 7,000 serial calls at an unmeasured latency is the one remaining
unbounded cost in the design.
**Acceptance:** a single call against a real multi-scan shard timed, and the 7,000-host projection
added to §4.6.

### 7.7 `R_hit` and the real hit rate — standing instrumentation

The design's independent variable is rows per host-scan, and rows are one per **matched** file
(`xdr_yara_scanner.py:4128`), so the row count is set by the **ruleset's hit rate**, not by disk
size. Our 2,713 comes from a deliberately broad 4-rule lab pack over `/etc` at a hit rate near
unity, and it cannot be extrapolated. This is measurable **today, on data that already exists,
before a line of code is written**:

```
dataset = yara_scanner_matches_v4_*
| alter r = json_extract_array(rules, "$") | arrayexpand r
| alter rule = json_extract_scalar(r, "$.rule")
| comp count_distinct(rule) as R_hit, count() as file_rows by scan_id, hostname
```

Run it against a realistic customer ruleset over a full filesystem on `xdr-agent` (Linux) and
`xdragent2` (Windows, user `ayman`) per `CLAUDE.md`, weighting the Windows figure more heavily.
**Acceptance:** `file_rows` per host-scan recorded for both platforms; §4.2's lookup table
annotated with where real packs actually land; and Phase 5 (§5.1) opened or closed on the answer.

*(This measurement was attempted today and blocked: `gcloud compute ssh xdr-agent` failed with
expired credentials — `Request had invalid authentication credentials`. It is one re-auth and one
`find / -xdev -type f | wc -l` away.)*

---

## 8. Summary of the decisions

1. **The old objective is dead.** "One dataset per scan" is impossible above 19 hosts. The
   achievable objective is bytes-proportional dataset count with universally prunable output (§2.2).
2. **Pack by bytes into monthly numbered parts**, keyed on (kind, ver, month), 14 host-scans per
   part at the measured grain, unbounded in fleet size.
3. **The month goes last in the name**, which makes the shipped retention selector prune parts with
   no code change — and which makes a `parse_shard` guard mandatory, because the same property lets
   the consolidator eat its own output.
4. **The scan is the atom** of verification and cleanup, even when it spans parts.
5. **Every guard is calibrated below the platform**, not above it — the lesson `DEFAULT_ROW_CEILING`
   taught the expensive way.
6. **Ship the drift-gate widening, the part-guard and the lock heartbeat first**, as no-ops. Ship
   the retention repair second, alone. Parts third.
7. **`campaign_id` is a column, not a packing key** — it earns its place for exact-value row cleanup
   and coverage reporting, and it must not gate any byte of benefit behind a fleet rollout.
8. **Measure the byte ratio before shipping.** One `get_datasets` call may retire the design's
   biggest risk outright.
