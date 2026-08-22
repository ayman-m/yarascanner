# Manual Validation Runbook — XDR YARA Scanner

*Scanner **3.4.0** · schema **v4** · pack: 5 automations + 1 playbook*

A hands-on procedure you run yourself, on your own tenant, to prove the scanner and
dataset management work end to end — and, just as importantly, that the **safety rails
actually fire**.

Everything here uses the **console and XQL only**. No repo scripts, no API client.

> **Not the same thing as [`TEST_PLAN.md`](TEST_PLAN.md).** That is the exhaustive
> capability-coverage matrix (467 capabilities, three rounds) — an engineering artifact.
> This is the afternoon's work that convinces *you* it runs correctly here.

| Part | What it proves | Time | Destructive? |
|---|---|---|---|
| [A](#part-a--deployment-checks) | Deployment and credentials are right | 10 min | No |
| [B](#part-b--first-scan) | A scan lands data end to end | 15 min | No |
| [C](#part-c--prove-the-overwrite) | The dataset is overwritten, not appended | 10 min | No |
| [D](#part-d--delivery-under-load) | Delivery holds at real volume; drain sizing | 45 min | No |
| [E](#part-e--dataset-management-read-only) | Inventory and readiness reporting | 10 min | No |
| [F](#part-f--consolidation) | The merge works and verifies before deleting | 30 min | **Yes** |
| [G](#part-g--prove-the-safety-rails-fire) | The guards actually stop things | 20 min | Partly |
| [H](#part-h--sign-off) | Sign-off sheet | — | — |

**Total ≈ 2½ hours**, most of it waiting on scans.

---

## Before you start

You need:

- [ ] A **test endpoint** you may scan freely (Windows or Linux). Not a production box.
- [ ] Console access to **Action Center** and **XQL Search**.
- [ ] The scanner uploaded as a library script, with a **Standard** API key filled in.
- [ ] The 5 automations uploaded, each with an **Advanced (HMAC)** key filled in.
- [ ] A small YARA rule file, base64-encoded, that you **know** will match something.

> **A rule that matches nothing makes most of this untestable.** For a throwaway test rule,
> a broad string like `"localhost"` or `"Copyright"` reliably matches on any host. Use it
> only for validation — never ship it.

### Find your host's dataset names

Every dataset carries a 6-hex host suffix. Get yours once and reuse it throughout:

**Console →** Settings → Data Management → Dataset Management, filter `yara_scanner`.

You are looking for a pair:

```
yara_scanner_matches_v4_<host>_<6hex>            ← no month suffix. This is correct.
yara_scanner_scans_v4_<host>_<6hex>_<YYYYMM>     ← month suffix. Also correct.
```

They **will not exist until your first scan**. That is expected — the scanner creates them.

Throughout this runbook, `MATCHES` and `SCANS` mean those two names.

---

## Part A — Deployment checks

No scans yet. These are cheap and catch the config mistakes that waste an afternoon.

### A1 · Scanner version

**Do:** Action Center → Scripts → your scanner → check the script body's `__version__`.

**Expect:** `3.4.0`

**Fails if:** anything lower. Later parts assume v4 behaviour that older builds don't have.

### A2 · Automations are present and are not `system`

**Do:** Settings → Automations, search `Yara`.

**Expect:** exactly five — `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`,
`YaraConsolidateSummary`, `YaraCleanup`.

**Fails if:** you see `YaraConsolidateFast` — that was removed; you're on an old pack.

### A3 · Credentials — the fastest test that finds a wrong key

**Do:** War Room → run:

```
!YaraReport
```

**Expect:** a dataset inventory table. On a fresh tenant it can legitimately say
*0 current-schema datasets* — that is still a **pass**, because it proves the key
authenticated.

**Fails if:** `HTTP 401`. That is a Standard key in an Advanced-key slot, a typo, or a
rotated key. The message cannot distinguish those — regenerate an **Advanced** key and
re-edit **all five** automations.

### A4 · Scanner key has Query Center

Easy to miss and it fails **silently later**, so check it now.

**Do:** Settings → Configurations → API Keys → your **scanner** key's role. Confirm it has
**Query Center** (`investigation_query_view`) alongside External Issues Mapping and
Data Management.

**Fails if:** absent. The scan will still run and still write — but the start-of-scan
overwrite will 403, fail safe, and the dataset will quietly accumulate. Part C is where
you would discover it the hard way.

---

## Part B — First scan

### B1 · Run a small scan

**Do:** Action Center → Scripts → your scanner → Run. Target your test endpoint.

| Input | Value |
|---|---|
| `yarafile` | your base64 rules |
| `scan_folder` | something small — `/etc` (Linux) or `C:\Windows\System32\drivers\etc` (Windows) |
| `alert_severity` | `low` |

Set the action **timeout to 30 minutes** even though this scan is quick — Part D explains why,
and there is no reason to learn that lesson on your first run.

**Expect:** the action reaches `COMPLETED_SUCCESSFULLY`, and the endpoint's output ends with:

```
SCAN_RESULT: Scan completed: <N> files scanned | 0 rules failed compilation |
             <M> matches found | ... alerts=on dataset=on ...
```

**Fails if:** `0 rules failed compilation` is not 0 → your rules use a module the agent's
YARA build lacks (agents run 4.1.0 on Windows/macOS, **3.11.0** on Linux). Fix the rules
before continuing — everything downstream depends on matches existing.

### B2 · The lifecycle rows landed

**Do:** XQL:

```
dataset = <SCANS>
| fields scan_id, status, files_scanned, detections, elapsed_secs, _insert_time
| sort desc _insert_time
| limit 10
```

**Expect:** at least two rows for one `scan_id` — `initiated` and a terminal
`completed`.

**Fails if:** no `completed` row. Either the scan is still running, or the payload was
killed. Check for a `scan_summary` file (B4) — if it's missing, it was killed.

> **Rows may appear out of order.** The `completed` row can have an *earlier*
> `_insert_time` than `initiated`. That is correct and deliberate — the terminal row is
> sent inline, ahead of the upload queue, so it survives even if the queue never drains.

### B3 · The match rows landed

**Do:** XQL:

```
dataset = <MATCHES>
| comp count() as rows, sum(rule_count) as rule_file_pairs, sum(match_total) as string_hits
  by scan_id
```

**Expect:** one row, one `scan_id`, `rows` > 0.

**Reading it:** these three numbers deliberately differ. `rows` is matched **files**;
`rule_file_pairs` is how many (rule, file) findings those represent; `string_hits` is
every individual string match. `rows ≤ rule_file_pairs ≤ string_hits` is the v4 grain
working, **not** data loss.

**Fails if:** more than one `scan_id` appears at this point (only one scan has run), or
`rows` is 0 while the scan reported matches.

### B4 · Delivery accounting on the endpoint

The authoritative record. **Do:** read the summary file on the endpoint:

| OS | Path |
|---|---|
| Windows | `C:\yara_scanner\logs\scan_summary_<run_id>.json` |
| Linux | `/opt/yara_scanner/logs/scan_summary_<run_id>.json` |
| macOS | `/usr/local/yara_scanner/logs/scan_summary_<run_id>.json` |

**Expect:**

```json
"scanner_version": "3.4.0",
"outcome": "completed",
"delivery_shortfall": "",
"dataset_delivery": { "queued": N, "records_added": N, "undelivered": 0, ... }
```

**The two things that matter:** `delivery_shortfall` is an **empty string**, and
`queued == records_added`.

**Fails if:** `delivery_shortfall` is non-empty → some rows never reached the tenant.
It names how many and confirms the findings are complete in the endpoint's local logs.
Most likely cause is a too-short action timeout — see Part D.

**Fails if:** the file doesn't exist at all → the run was killed before finishing. It is
written *after* the upload drain, so its absence is itself the diagnosis.

---

## Part C — Prove the overwrite

This is the behaviour most people don't believe until they see it.

### C1 · Note the current state

**Do:** XQL:

```
dataset = <MATCHES> | comp count() as rows by scan_id
```

Write down the `scan_id` and `rows`.

### C2 · Scan the same host again

Run **exactly the same scan** as B1 — same host, same folder, same rules.

### C3 · Confirm replacement, not accumulation

**Do:** the same query as C1.

**Expect:** still **exactly one** `scan_id` — and it is the **new** one. The first scan's
rows are gone.

**Fails if:** two `scan_id`s appear → the overwrite did not happen. Check A4 (Query Center
permission). Without it the flush 403s silently and the dataset accumulates — which is
precisely the failure this test exists to catch.

### C4 · Confirm the scans dataset did the opposite

**Do:**

```
dataset = <SCANS> | comp count() as rows by scan_id
```

**Expect:** **two** `scan_id`s — both scans. The lifecycle dataset is append-only and
must *not* be overwritten.

> Together, C3 and C4 are the whole dataset model in two queries: matches replaced,
> scans accumulated.

---

## Part D — Delivery under load

The part that finds the problem most likely to cost you data in production.

### D1 · A scan large enough to queue a real backlog

**Do:** run against a large target — `/usr` (Linux) or `C:\Windows` (Windows).

Set the action timeout **generously — 60 minutes**. You are testing delivery here, not
timeout behaviour.

**Note the wall-clock time** from launch to the action completing.

### D2 · Compare scan time against total time

**Do:** in the summary JSON, read `duration_secs`. Compare it to the wall-clock time you
measured.

**Expect:** total wall-clock is **meaningfully longer** than `duration_secs`. The gap is
upload drain.

**Reference measurement:** a 93,137-file scan took **169 s to scan** and **401 s to drain** —
the drain was 2.4× the scan. Your ratio will differ; the *existence* of the gap is the point.

### D3 · Confirm nothing was lost

**Do:** check `delivery_shortfall` and `dataset_delivery` as in B4.

**Expect:** shortfall empty, `undelivered: 0`.

### D4 · Now size your real timeout

You have just measured your own scan-to-drain ratio on your own hardware and link. Use it:

```
action timeout  ≥  expected scan time  +  measured drain  +  margin
```

**Starting point: scan estimate + 10 minutes.** Drain internals cap at 600 s, but a large
backlog plus retries can approach that.

> **Optional — prove the failure mode.** Re-run D1 with the timeout set deliberately short
> (e.g. 5 minutes on a scan you know takes longer). Expect: the action is killed,
> **no `scan_summary` file is written**, and the scans dataset still receives its terminal
> row. That last part is the inline-send working. Only do this if you want to see it.

---

## Part E — Dataset management (read-only)

Nothing here writes or deletes.

### E1 · Inventory

**Do:** `!YaraReport`

**Expect:** a table of every `yara_scanner_*` dataset with kind, host and state. Your live
matches dataset should be listed as a **permanent / overwrite** dataset — *not* as
"not rotated".

**Fails if:** it says `not rotated (no YYYYMM) — set CONFIG_LOOKUP_ROTATION="monthly"` for
your **v4** matches dataset. That advice is wrong for v4 and means you're running an old
pack. (For a v2/v3 dataset it is correct and expected.)

### E2 · Readiness

**Do:** `!YaraConsolidateStatus`

**Expect:** a count of eligible scans, plus any still in progress or blocked, with reasons.

**Reading it:** a scan you *just* ran will often show as **not** eligible. That is correct —
there is a 900-second quiet period so consolidation never races a still-draining uploader.
Wait it out rather than working around it.

---

## Part F — Consolidation

> ### ⚠ This part deletes data
> `YaraConsolidateApply` **has no dry-run mode**. There is no `execute` argument. A bare
> invocation merges and deletes source shards immediately.
>
> Run this against **test scans you are willing to lose**. Deleted datasets cannot be
> recovered — the platform has no undo.

### F1 · Preview first (safe)

**Do:** `!YaraConsolidateStatus`

Note which `scan_id`s are eligible. These are exactly what F3 will consume.

### F2 · Try summary mode first (non-destructive)

**Do:**

```
!YaraConsolidateSummary execute="false"
```

**Expect:** a dry-run report — what it *would* write, `written: 0`, and
`host shards deleted: 0`.

Then run it for real:

```
!YaraConsolidateSummary execute="true"
```

**Expect:** rows written to `yara_scanner_summary_v4_scan_<id>`, and
**`host shards deleted: 0`** — summary mode never deletes.

**Verify the source survived:**

```
dataset = <MATCHES> | comp count() as rows by scan_id
```

**Expect:** unchanged. This is the proof that summary mode is safe to schedule.

### F3 · Full consolidation (destructive)

**Do:**

```
!YaraConsolidateApply max_scans="4"
```

Pass `max_scans` explicitly the first time even though 4 is the default — it makes the
bound visible in the War Room record.

**Expect:** `N scan(s) consolidated`, and if more remain,
*"Pass was bounded… Run again to continue."*

**Verify the target exists and the source is gone:**

```
dataset = yara_scanner_matches_v4_scan_<slugified_scan_id> | comp count() as rows
```

**Expect:** the row count matches what the source held.

### F4 · Confirm the run was recorded

**Do:**

```
dataset = yara_scanner_consolidation_runs
| fields _insert_time, status, consolidated_count, failed_count
| sort desc _insert_time | limit 5
```

**Expect:** a **`started`** row *and* a terminal row (`success` / `partial_failure`) for
your run.

**Reading it:** a `started` row with **no** matching terminal row means a pass was killed —
or is still running. That pairing is the diagnostic you'll rely on in production.

### F5 · Drain the backlog

If F3 reported more remained, run it again until it stops saying so.

**Expect:** each pass consolidates up to `max_scans` and reports what's left. **It does not
resume itself** — that is by design, not a bug.

---

## Part G — Prove the safety rails fire

The most valuable part. A guard you have never seen trigger is a guard you are trusting on
faith.

### G1 · The consolidation lock

**Do:** start `!YaraConsolidateApply` and, while it is still running, start a **second**
one from another War Room tab.

**Expect:** the second returns
*"Skipped this pass — the consolidation lock is held by another concurrent run."*
and touches nothing.

**Why it matters:** without this, two runs could both delete sources after only one wrote a
target.

### G2 · Cleanup refuses to delete without opt-in

**Do:**

```
!YaraCleanup older_than_months="0"
```

**Expect:** a report of what it *would* delete, and **nothing deleted** — `execute`
defaults to false.

**Verify:** the datasets it named still exist.

### G3 · Cleanup will not touch your live matches dataset

**Do:** in the G2 output, find your live `<MATCHES>` dataset.

**Expect:** it appears in the **skipped** list with a reason like *permanent per-host
matches dataset*.

**Fails if:** it appears as a deletion candidate. Stop and do not run `YaraCleanup` with
`execute=true` — that is the guard that protects your deep-dive source.

### G4 · Cooperative cancel writes a terminal row

**Do:** start a long scan. While it runs, run the same script with **Entry Point = `cancel`**
(no inputs) on the same endpoint.

**Expect:** within ~5 s the scan stops and reports
`Scan cancelled by operator`. Then:

```
dataset = <SCANS> | fields scan_id, status | sort desc _insert_time | limit 5
```

**Expect:** a terminal **`cancelled`** row.

**Contrast — do not do this on a scan you care about:** the Action Center **console Cancel**
button hard-kills the payload and writes **no** terminal row, leaving the scan showing as
`running` until the 24-hour abandoned cutoff. That difference is exactly why the `cancel`
entry point exists.

### G5 · A schema-version mismatch — and why the two directions differ

`schema_version` tells the tooling which version counts as *current*. Getting it wrong is
**not symmetric**, and this is the one setting worth understanding before you touch it.

**Do (safe direction — a version too LOW):**

```
!YaraConsolidateStatus schema_version="2"
```

**Expect:** **0 current**, and your v4 datasets reported as **newer schema — never pruned**.
Nothing is touched.

**Why:** anything newer than the assumed current version is, by definition, something this
build doesn't understand — so it refuses to act on it. This is the safe failure, and it's the
one you'll hit in practice (a stale default, a pack not yet updated). It is also **silent** —
a run reporting 0 candidates and exiting cleanly can mean a version mismatch rather than an
empty backlog. Recognising that is the point of this test.

> ### ⚠ The other direction is not safe — do not test it casually
> Setting `schema_version` **too HIGH** (say `9` against v4 data) reclassifies every live
> dataset as **legacy**, and legacy datasets *are* eligible for deletion via
> `YaraCleanup`'s `delete_legacy` path. A typo, or a version bumped in automation ahead of
> the fleet, puts actively-written data in the deletable bucket.
>
> **Rails still stand between that and data loss**, and they are worth knowing:
> - if **any** newer-schema dataset exists, the whole blanket legacy deletion is **refused** —
>   the assumed version is provably stale, so it is not trusted
> - an **unsuffixed** dataset (which your live matches dataset is) is never a candidate
> - per-scan consolidated targets, the current month and future-dated months are never candidates
> - `execute` still defaults to false
>
> Verify by reading the skip reasons rather than by running a real delete.

---

## Part H — Sign-off

| # | Check | Pass |
|---|---|---|
| A1 | Scanner reports `3.4.0` | ☐ |
| A2 | Exactly five automations, no `Fast` | ☐ |
| A3 | `!YaraReport` authenticates | ☐ |
| A4 | Scanner key has Query Center | ☐ |
| B1 | Scan completes, 0 rules failed compilation | ☐ |
| B2 | `initiated` + terminal lifecycle rows present | ☐ |
| B3 | Match rows present, one `scan_id` | ☐ |
| B4 | `delivery_shortfall` empty, `queued == added` | ☐ |
| C3 | Second scan **replaces** — still one `scan_id` | ☐ |
| C4 | Scans dataset **accumulated** — two `scan_id`s | ☐ |
| D2 | Drain gap observed and measured | ☐ |
| D3 | No shortfall at volume | ☐ |
| D4 | Production timeout sized from your own measurement | ☐ |
| E1 | Live matches dataset reported as permanent, not "not rotated" | ☐ |
| E2 | Readiness reports quiet-period deferrals correctly | ☐ |
| F2 | Summary mode wrote rows and deleted **nothing** | ☐ |
| F3 | Apply merged and verified before deleting | ☐ |
| F4 | `started` + terminal rows both recorded | ☐ |
| G1 | Second concurrent Apply refused on the lock | ☐ |
| G2 | Cleanup dry-run deleted nothing | ☐ |
| G3 | Cleanup skipped the live matches dataset | ☐ |
| G4 | Cooperative cancel wrote a `cancelled` row | ☐ |
| G5 | Too-low version fails safe; too-high hazard understood | ☐ |

### Before you go to production

- [ ] Action timeout sized from **your** D2 measurement, not the reference figure
- [ ] Consolidation mode chosen — **Summary** (safe) or **Full** (destructive)
- [ ] Everyone who can run automations knows **`Apply` has no dry-run mode**
- [ ] `YaraCleanup` scheduled — if at all — in its **own** window, never alongside the merge
- [ ] Test rules removed; only real detection content ships
- [ ] A plan for draining a backlog larger than one bounded pass

---

## If something fails

Full failure-mode catalogue with causes and fixes:
**[Operations Deep Dive §13](Operations_Deep_Dive.md#13-failure-modes-catalogue)**.

The three that account for most first-run surprises:

| Symptom | Almost always |
|---|---|
| Rows missing, `delivery_shortfall` non-empty | Action timeout too short — it expired mid-drain (Part D) |
| Matches dataset accumulating scans | Scanner key missing **Query Center** (A4) |
| Consolidation reports 0 candidates and exits clean | `schema_version` mismatch, or the 900 s quiet period (E2) |
