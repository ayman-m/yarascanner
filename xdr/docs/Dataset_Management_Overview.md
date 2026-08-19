# Dataset management — what it does and why

*Customer-facing overview. Cortex XDR only.*

---

## The problem it solves

On Cortex XDR the scanner writes its findings into **XQL lookup datasets**. That API has one
property that shapes everything below: **it is not safe for concurrent writers.** Two
endpoints writing the same dataset at the same time collide server-side and silently lose
rows — we measured 8 endpoints writing one dataset together and **87% of the rows never
arrived**, with no error raised to either writer.

So each host writes to **its own dataset**. Nothing is ever lost, and no scan can corrupt
another's data.

The cost of that choice is dataset count. A 5,000-host scan produces 5,000 dataset pairs.
That is correct but not sustainable — which is what dataset management exists to fix.

**The objective, in one sentence:** *no single-host dataset should remain once its scan has
finished, or once a day has passed since the scan started — and no finding is ever lost to
achieve that.*

---

## How it works

Three pieces, in order:

### 1. A correlation rule notices new per-host datasets

A correlation rule watches for per-host YARA datasets appearing on the tenant and raises an
**issue**: *"new single-host YARA datasets exist and need consolidating."*

> Cortex XDR has no scheduled-job facility, so a correlation rule raising an issue is the
> supported way to trigger automation on a recurring basis. This is the trigger we are
> building for your environment.

### 2. The issue triggers the consolidation playbook

The playbook picks up the issue and, for each scan it finds:

- lists the per-host datasets belonging to that scan
- **checks whether that host is still scanning** — from the scan's own lifecycle rows *and*
  independently from the Action Center action state
- leaves anything still running strictly alone

### 3. Finished scans are merged, then their sources are removed

For each scan that is genuinely finished, the playbook:

1. creates one **per-scan** dataset,
2. copies every host's rows into it as a **single sequential writer** — so consolidation is
   never exposed to the very collision it is cleaning up after,
3. **verifies the merged row count equals the sum of the sources**, and only then
4. deletes the per-host datasets.

If the counts do not match, **nothing is deleted** and the mismatch is reported.

The result: one dataset per scan instead of one per host, with the same rows in it.

---

## Edge cases, and what happens in each

These are the situations the playbook is built to handle. Each one has a defined behaviour
rather than a default.

| Situation | What the playbook does |
|---|---|
| **Scan still running on that host** | Leaves it completely alone. Nothing is read, merged or deleted while a scan may still be writing. |
| **Scan finished normally** | Merges and deletes the source, after the row-count check passes. |
| **Scan was cancelled part-way** | Still merged. A cancelled scan's findings are **real findings** — they are preserved, never discarded. |
| **Scan failed** | Same: merged and preserved. A failure is a reason to keep the evidence, not to drop it. |
| **Host went offline mid-scan, no completion ever recorded** | After **24 hours** from the scan's start it is treated as abandoned, and its partial findings are merged and preserved. The 24-hour window is comfortably longer than the platform's own 6-hour script limit, so a scan that is genuinely still running can never be mistaken for an abandoned one. |
| **Scan cancelled from the console, leaving the status stuck at "running"** | Caught by the second, independent check: the Action Center action state. A host whose lifecycle row is stuck but whose action has terminated is correctly recognised as finished. |
| **Long scan, several hours** | Handled by the two checks above, not by a timer. A multi-hour scan that is still writing is still running, and is left alone. |
| **Scan just finished; the endpoint may still be uploading** | A quiet period applies after the last row before anything is touched, so a still-draining uploader is not cut off mid-flight. |
| **Endpoint clock wrong** | Age is judged from both the endpoint's timestamp and the platform's own ingest time, taking whichever is later, with a tolerance for normal upload latency. A wrong clock cannot make a live scan look old enough to clean up. |
| **Two consolidation runs overlapping** | A lock ensures only one runs at a time. The second reports that it skipped and exits — it does not proceed. |
| **A scan too large to merge safely** | Refused up front with a clear reason, rather than half-built and left stranded. |
| **Merged row count does not match the sources** | Every source is kept and the mismatch is reported. Deletion only ever follows a successful verification. |
| **One dataset fails to delete** | The rest of the pass still completes. A single failure never strands the whole run. |

---

## What you get

- **One dataset per scan** instead of one per host, so tenant dataset count is bounded by
  how many scans you run, not by how many endpoints you have.
- **No finding lost** — merges are verified before anything is deleted, and partial results
  from cancelled, failed and abandoned scans are preserved rather than discarded.
- **A record of every pass**, so you can answer what was merged and what was skipped, and
  why.

---

## Status

The consolidation logic, the safety checks and the merge/verify/delete sequence are built
and unit-tested. **The correlation-rule trigger is being set up for your environment now.**

**Testing of the additional edge cases listed above is in progress**, and we will have more
detail at tomorrow's call. The content will be ready for your team to try in the new
environment.
