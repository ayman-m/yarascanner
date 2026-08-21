# Capacity — how many machines can one scan cover?

Every number here is measured on `api-emea-cxdrp` against real scans on 2026-08-20, not
modelled. Where something is extrapolated it says so.

## The hard limit

**A lookup dataset is capped at 50 MB by the platform.** Documented on the lookups API page.
It is not tunable, and it is the constraint that decides everything below.

## Two real scans, two very different workloads

| | `/etc` | `/usr` |
|---|---|---|
| files scanned | ~2,713 matched | **93,137** |
| findings | 5,240 | **1,836** |
| match rate | pathological | **1.97%** |
| v4 rows written | 2,713 | **1,097** |
| rules per file | 1.93 | 1.67 |
| **bytes per row** | ~994 (modelled) | **749 (measured)** |
| **MB for that host** | ~2.57 | **0.78** |

The two disagree by design, and the disagreement is the most useful thing in this document.

`/etc` is small but pathological: the rules match `localhost`, `127.0.0.1` and `::1`, which
appear in a large fraction of config files. It produced *more* findings from *fewer* files than
the 93k-file `/usr` sweep did.

**So dataset size does not track how much you scan. It tracks how often your rules fire.** A
targeted scan with loose string rules costs more than a filesystem sweep with precise ones.
Anyone sizing this from "number of machines" or "size of the filesystem" alone will get it
wrong in both directions.

## Per-host budget

A host's own dataset holds one scan's detail (overwritten each scan under the v4 design).

```
50 MB / 749 B per row  =  ~70,000 matched files per host
```

Measured: the `/usr` scan used **1.6%** of that. Extrapolating at the observed 1.97% match rate,
a **1,000,000-file** filesystem yields ~19,700 findings, ~11,800 rows, **~8.4 MB — 17% of the
budget**. You would need roughly **6 million files on one machine** to fill a host dataset.

**A single host exceeding its own 50 MB is not a routine concern.** It needs a pathological
rule set, not a large disk. (Extrapolated from the measured rate — not itself measured.)

## Fleet budget — the number that actually binds

The consolidated per-scan dataset carries one row per (host, rule): which rules fired where.
No file detail, no counts.

**163 bytes per row. 321,649 rows in 50 MB.**

| rules matched per host | hosts per consolidated dataset |
|---|---|
| 4 | **80,412** |
| 10 | 32,164 |
| 25 | 12,865 |
| 50 | 6,432 |
| 100 | 3,216 |
| 200 | 1,608 |

**The limit is rules-matched-per-host, not host count.** With a tight rule set 80,000 machines
fit. With a noisy one, 1,600. Fleet size is almost irrelevant; rule discipline is everything.

## What to tell a customer

> Each scanned machine keeps its own dataset holding that scan's file-level findings, and one
> consolidated dataset records which rules fired on which machines. A machine's own dataset
> holds roughly 70,000 matched files — a full-filesystem scan typically uses under 20% of that.
> The consolidated view holds tens of thousands of machines with a focused rule set. The
> practical limit is how many rules match per machine, not how many machines you scan or how
> large their disks are.

### Caveats, stated plainly

1. **Per-host history does not survive.** Each host's dataset is overwritten by its next scan.
   Only the most recent scan's file-level detail exists. The consolidated dataset keeps the
   record that a rule fired; the file list does not survive. If history matters, that is the
   alerts channel, not lookups.
2. **The consolidated view carries no counts.** You can see that rule X fired on host Y, not on
   how many files. Deliberate — per-rule counts make the queries expensive. Ranking "which host
   is worst affected" requires opening that host's dataset.
3. **A pathological rule set can still overflow one host.** Roughly 70,000 matched files. Rules
   matching short, common strings are what get you there, not filesystem size.
4. **Overwriting has a cost.** A dataset delete is ~60s server-side. Per host, per scan, at
   fleet scale that is significant and needs measuring before a large rollout.

## Provenance

- Row sizes: JSON payload with platform columns (`_insert_time` etc.) stripped, sampled 300 rows.
- `/usr` scan: `action_id=672`, xdr-agent, schema v4, 2026-08-20.
- The 50 MB cap and the 10,000-row `lookups/get_data` cap are documented, not measured here.
- The 1,000,000-row XQL truncation is documented and **silent** — see
  `design/Dataset_Management_v2_Design.md` §1.2.
