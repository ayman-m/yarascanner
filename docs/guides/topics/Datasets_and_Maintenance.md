# Datasets and Maintenance — technical detail

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

## 2. Per-host sharding — why every host gets its own dataset

`CONFIG_LOOKUP_SHARD = "endpoint"` (the default) gives each host its own dataset pair.

**This is not organisational tidiness — it works around a server-side race.** XDR's
`lookups/add_data` stages each write through a per-write clone table. Concurrent writes to
the *same* dataset collide, producing a transient `HTTP 500 ..._clone was not found`, and
**rows are silently lost**.

Measured: with 8 endpoints writing to one shared dataset, roughly **2 of 8 batches landed**.
Client-side time-spreading does not fix it — even 45 seconds of jitter across 8 writers
still lost most of them, because the server holds the dataset through a slow merge.

With per-host sharding there is exactly one writer per dataset, and delivery was verified at
**8/8**.

Dashboards are unaffected: every widget matches `yara_scanner_matches*` / `yara_scanner_scans*`
wildcards, so shards fan back in automatically.

> Set `CONFIG_LOOKUP_SHARD = "none"` only if you have a single scanning endpoint. At fleet
> scale it loses data.

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

Plus: **dry run unless `--yes`**, and `--older-than-months` has no default, so a bare `--yes`
deletes nothing.

> **Why the current-month guard matters.** Deleting a dataset a scan is actively writing to
> does not error the scan — the scanner keeps POSTing rows to a name that no longer exists
> and receives HTTP 400 per batch. Across a fleet mid-scan that is silent, partial data loss
> discovered days later as a gap in the dashboards.

A failed delete is reported and the run continues to the next dataset, so one dataset with
dependencies cannot strand the whole cleanup. Exit code is non-zero if any deletion failed.

## 5. Row shapes

**`yara_scanner_matches_v2_*`** — one row per matched string: host, rule, file path, offset,
matched length, severity, scan id, timestamps.

**`yara_scanner_scans_v2_*`** — scan lifecycle. Each scan writes `initiated`, then a terminal
row (`completed` / `cancelled` / `failed`), plus periodic `running` rows.

> A scan stopped by the **console Cancel** never writes a terminal row, so its lifecycle
> stays at `initiated` or `running` permanently and dashboards show it as running forever.
> See the Scan Cancellation topic guide.

## 6. Schema changes

The row shape is pinned by the `_v2` tag for a reason: **`add_data` silently skips rows
carrying fields that are not in the existing dataset's schema.** It returns
`records_skipped=N, records_added=0` with HTTP 200 and no error anywhere.

A schema cannot be altered in place. So any change to the row shape requires bumping the
version tag, which starts new datasets. If you add a field without bumping, scans will
report success while their telemetry silently vanishes.
