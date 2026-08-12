# Datasets and Maintenance — technical detail

*Applies to scanner **v2.1.0**. History of changes: [release notes](../../../CHANGELOG.md).*

Companion to the XDR YARA Scanner Guide. Read this to understand why the dataset names look
the way they do, and how to stop them growing forever.

---

## 1. What the scanner writes

Two lookup datasets per host:

```
yara_scanner_matches_v2_<host>_<YYYYMM>     one row per matched string
yara_scanner_scans_v2_<host>_<YYYYMM>       one row per scan lifecycle event
```

The name carries four things, and each is there for a reason:

| Part | Why |
|---|---|
| `_v2` | schema version — bumped whenever the row shape changes |
| `_<host>` | per-writer sharding (§2) |
| `_<YYYYMM>` | monthly rotation (§3) |

The scanner **creates these itself** if they do not exist. It never depends on any other
script having run first.

## 2. Why not one dataset for everything?

**One dataset would be the better design.** One object to manage, one place to query, no
proliferation. Every row already carries `scan_id`, `run_id`, `scan_date`, `hostname` and
`tenant_id`, so a single dataset would give you everything you need by filtering — nothing
about the *data* requires splitting it.

**We chose per-host datasets anyway, because the platform will not support the better
design.** This is a deliberate trade-off forced by a limitation in `lookups/add_data`, and
it is worth being precise about what goes wrong, because the failure is silent.

### What happens if you point a fleet at one dataset

XDR stages every `add_data` write through a per-write clone table. Two endpoints writing the
**same** dataset at the same time collide, the server returns a transient
`HTTP 500 ..._clone was not found`, and **the rows are lost**. Not rejected — lost. The
retry returns HTTP 200 and nothing anywhere reports a problem.

Measured on a live tenant with 8 endpoints writing one shared dataset: roughly **2 of 8
batches landed**. Spreading the writes client-side does not fix it — 45 seconds of jitter
across those 8 writers still lost most of them, because the server holds the dataset through
a slow merge that no amount of client-side politeness can shorten.

It also degrades as it grows. Merge time scales with the **size of the dataset**, not the
size of the write (§3), so a single fleet-wide dataset becomes the largest and slowest
object you have, widening the very window in which collisions happen. The failure mode
compounds.

With one writer per dataset the collision cannot occur by construction. Delivery was
verified at **8/8**.

### The cost we accept in exchange

**Dataset count.** Per-host sharding combined with monthly rotation means a 500-endpoint
fleet creates on the order of **1,000 datasets a month**. That is a real operational cost
and the honest reason it is tolerated is that the alternative loses customer data.

Two levers control it:

- **Bucket instead of per-host.** `CONFIG_LOOKUP_SHARD` accepts a literal label, so you can
  group hosts into a fixed set of shards — `wave1`, `emea`, `site-3` — rather than one per
  endpoint. Ten buckets across 500 hosts is 10 datasets, not 500. Choose a bucket count high
  enough that few endpoints in the same bucket scan concurrently; the risk returns as the
  number of simultaneous writers per dataset rises above one.
- **Delete old months.** `xdr_data_management.py` (§4) removes them on whatever retention
  you choose.

**What you do not lose is the query experience.** Dashboards match
`yara_scanner_matches*` / `yara_scanner_scans*` wildcards, so shards fan back in
automatically and a query spans the whole estate regardless of how many datasets sit behind
it. Filtering by `scan_id`, `scan_date` or `hostname` works exactly as it would against a
single dataset.

> Set `CONFIG_LOOKUP_SHARD = "none"` only for a single scanning endpoint. At fleet scale it
> is the configuration measured above at 2/8 delivery.

## 3. Monthly rotation — why the name carries a date

`CONFIG_LOOKUP_ROTATION = "monthly"` (the default) appends `_<YYYYMM>`, so a fresh dataset
begins each month.

**This exists because `add_data` merge time scales with dataset SIZE, not payload size.**
Measured on a live tenant, writing a single row:

| Dataset size | Time per write |
|---|---|
| 15,000 rows | ~13 s |
| 77,000 rows | ~31 s |

An unrotated dataset therefore gets progressively slower until writes exceed any client
timeout and it goes **write-dead** — observed at ~77k rows, where a host lost the majority
of a scan's rows to read timeouts.

Rotation bounds each dataset's size permanently, so write time stays flat forever.

> Rotation **bounds size but deletes nothing.** Old months accumulate on the tenant
> indefinitely. That is what §4 is for.

## 4. Cleanup — `xdr_data_management.py`

A small standalone script that deletes whole old datasets.

**It is deliberately not a prerequisite for anything.** The scanner creates its own datasets
and writes to them self-sufficiently. If this script never runs, datasets get large and
eventually slow, but **every scan still succeeds**. Cleanup is optional work; creation is
not, and coupling them would mean a scan could fail because a different script had not run.

```bash
python3 xdr_data_management.py --report                      # inventory (default action)
python3 xdr_data_management.py --older-than-months 6 --yes   # drop months older than 6
python3 xdr_data_management.py --delete-legacy --yes         # drop pre-v2 schema datasets
```

### Reading the report

`--report` lists every YARA dataset with kind, host and age in months, and flags two
conditions:

| Flag | Meaning |
|---|---|
| **`frozen`** | An unsuffixed dataset that has rotated siblings. It predates rotation, is no longer written to, and is left alone. |
| **not rotated** | An unsuffixed dataset with *no* rotated siblings — rotation is off for that deployment and the dataset really will grow without bound. The report names the config change. |

Neither is ever deleted automatically: an unsuffixed dataset holds **all** pre-rotation
history for a host, so removing one is a bigger decision than dropping a month.

### Safety rails

Nothing is deleted if it is:

1. **the current month** — a scan may be writing to it
2. **a future-dated month** — clock skew must not destroy data
3. **unsuffixed** — see above
4. **on a newer schema version** than this host understands
5. **outside the `yara_scanner_*` naming contract** — unrelated tenant data is unreachable
6. **written to more recently than `--min-quiet-hours`** (default 24h, checked live via
   XQL) — a rotation suffix reflects when a dataset was *created*, not when it was last
   written; a long-running scan against a host whose shard rotated months ago is still
   writing to that "old-looking" name
7. **still holding a scan_id `--consolidate` (§5) hasn't fully verified into a per-scan
   target** — most often a scan that tripped the row ceiling, or was never consolidated at
   all; deleting it would be the only copy of that scan's findings gone for good

Plus: **dry run unless `--yes`**, and `--older-than-months` has no default, so a bare `--yes`
deletes nothing. Rails 6 and 7 each cost one extra XQL query per candidate dataset and, like
every other rail here, skip (keep) the dataset rather than delete it if that query errors.

> **Why the current-month guard matters.** Deleting a dataset a scan is actively writing to
> does not error the scan — the scanner keeps POSTing rows to a name that no longer exists
> and receives HTTP 400 per batch. Across a fleet mid-scan that is silent, partial data loss
> discovered days later as a gap in the dashboards.

A failed delete is reported and the run continues to the next dataset, so one dataset with
dependencies cannot strand the whole cleanup. Exit code is non-zero if any deletion failed.

## 5. Consolidation — one dataset per scan (`--consolidate`)

Deleting old months (§4) bounds *age*. It does not bound *count*: a large fleet still
produces two datasets per host every month. Consolidation addresses the count directly — it
folds each scan's per-host shards into a **single dataset per scan** and deletes the shards.

```bash
python3 xdr_data_management.py --consolidate                 # dry run — plan only
python3 xdr_data_management.py --consolidate --yes           # apply
python3 xdr_data_management.py --consolidate --scan-id <id>  # one scan (repeatable)
```

The result is `yara_scanner_matches_v2_scan_<scan_id>` / `..._scans_v2_scan_<scan_id>`: all
hosts for one scan, in one place, filterable by the same fields as before.

**This is a housekeeping step, not a requirement, and not a reporting fix.** Reporting never
needed it — dashboards query `yara_scanner_*` wildcards, so a query spans per-host and
per-scan datasets identically. Consolidation only reduces how many datasets exist.

### Why it is safe to run against live data

It deletes datasets, so it is deliberately conservative:

- **One sequential writer** per target — never exposed to the concurrent-write collision
  that per-host sharding exists to avoid (§2).
- **Verify before delete** — a shard is deleted only after the target's row count equals the
  sum of its sources. A mismatch keeps every source and reports it.
- **A shard is deleted only when every scan in it is consolidated.** A host re-scanned in
  the same month shares one dataset; deleting after a single scan would destroy the others.
  Re-running is idempotent — an already-consolidated scan is detected and not rewritten.
- **Abandoned-scan cutoff.** A scan stopped by the console Cancel leaves its lifecycle stuck
  at `running`/`initiated` forever (§5, and the Scan Cancellation guide), which would block
  its shard from ever being cleaned. A non-terminal scan whose newest row is older than
  **24 hours** (`--abandoned-after-hours`, past the 6 h action timeout so a live scan is
  never mistaken for one) is treated as abandoned: it stops blocking cleanup, and its partial
  matches are still consolidated rather than dropped.
- **Row ceiling** (`--row-ceiling`, default 2,000,000) refuses a consolidation too large to
  finish rather than half-building a target.

> **What "verify before delete" does *not* check.** The row-count comparison confirms the
> target has as many rows as its sources combined — it does not compare row *content*. A
> corrupted or duplicated write that happens to land on the same count would still pass and
> the source would still be deleted. And once `delete_dataset` runs, the platform has no
> undelete or dataset versioning to fall back on — a mismatch or bug caught after the fact
> cannot be recovered, only avoided by verifying before you run with `--yes`. Treat
> consolidation, like the pruning in §4, as one-way.

### What it will and will not clean

A scan is consolidated once it is **finished** — a terminal lifecycle row, or abandoned past
the cutoff. Scans still genuinely in progress are deferred to a later run. A per-host shard
is removed only once *all* of its scans are handled, so on a busy host you may see per-scan
targets appear while the shard persists until its last scan clears.

> Deleting a whole dataset takes ~60 seconds server-side on the tenants measured. Deletes of
> different datasets do not conflict, so consolidation runs them concurrently (12 at a time);
> even so, cleaning a large fleet is an hours-scale background job, not instant. Run it off-
> peak.

## 6. Row shapes

**`yara_scanner_matches_v2_*`** — one row per matched string: host, rule, file path, offset,
matched length, severity, scan id, timestamps.

**`yara_scanner_scans_v2_*`** — scan lifecycle. Each scan writes `initiated`, then a terminal
row (`completed` / `cancelled` / `failed`), plus periodic `running` rows.

> A scan stopped by the **console Cancel** never writes a terminal row, so its lifecycle
> stays at `initiated` or `running` permanently and dashboards show it as running forever.
> See the Scan Cancellation topic guide.

## 7. Schema changes

The row shape is pinned by the `_v2` tag for a reason: **`add_data` silently skips rows
carrying fields that are not in the existing dataset's schema.** It returns
`records_skipped=N, records_added=0` with HTTP 200 and no error anywhere.

A schema cannot be altered in place. So any change to the row shape requires bumping the
version tag, which starts new datasets. If you add a field without bumping, scans will
report success while their telemetry silently vanishes.
