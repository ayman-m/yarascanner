# Manual Validation Runbook — XDR YARA Scanner

*Scanner **3.4.0** · schema **v4** · pack: 9 automations + 1 playbook*

A hands-on procedure you run yourself, on your own tenant, to prove the scanner and
dataset management work end to end — and, just as importantly, that the **safety rails
actually fire**.

Everything here uses the **console and XQL only**. No repo scripts, no API client.

| Part | What it proves | Time | Destructive? |
|---|---|---|---|
| [A](#part-a--deployment-checks) | Deployment and credentials are right | 10 min | No |
| [B](#part-b--first-scan) | A scan lands data end to end | 15 min | No |
| [C](#part-c--prove-the-overwrite) | The dataset is overwritten, not appended | 10 min | No |
| [D](#part-d--delivery-under-load) | Delivery holds at real volume; drain sizing | 45 min | No |
| [E](#part-e--dataset-management-read-only) | Inventory and readiness reporting | 10 min | No |
| [F](#part-f--consolidation) | Both consolidation modes group correctly, and delete nothing | 30 min | No |
| [G](#part-g--prove-the-safety-rails-fire) | The guards actually stop things | 20 min | Partly |
| [H](#part-h--sign-off) | Sign-off sheet | — | — |

**Total ≈ 2½ hours**, most of it waiting on scans.

---

## Before you start

You need:

- [ ] A **test endpoint** you may scan freely (Windows or Linux). Not a production box.
- [ ] Console access to **Action Center** and **XQL Search**.
- [ ] The scanner uploaded as a library script, with a **Standard** API key filled in.
- [ ] All **9** automations uploaded. **Seven** of them need an **Advanced (HMAC)** key filled
      in: `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`,
      `YaraConsolidateSummary`, `YaraCleanup`, `YaraScanVerify`, `YaraWipeAllDatasets`. In each,
      the values to edit sit under the banner
      `CONFIGURATION - the only values in this file you need to edit`.
      `YaraScanVerify` and `YaraWipeAllDatasets` are the two most often left on placeholders —
      both then fail at client construction the first time they are run.
      `YaraRulesFromFile` and `YaraRulesDecode` need **no** credentials: they make no tenant
      API call.
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

**Expect:** exactly nine — `YaraReport`, `YaraConsolidateStatus`, `YaraConsolidateApply`,
`YaraConsolidateSummary`, `YaraCleanup`, `YaraWipeAllDatasets`, `YaraRulesFromFile`,
`YaraRulesDecode`, `YaraScanVerify`.

**What the four newer ones do**, if you have not met them yet:

| Automation | What it does |
|---|---|
| `YaraWipeAllDatasets` | Deletes every `yara_scanner_*` dataset. Destructive, confirm-gated. |
| `YaraRulesFromFile` | Validates an operator-uploaded YARA rules file and returns the base64 the Action Center scanner takes as its `yarafile` input. |
| `YaraRulesDecode` | The inverse: decodes that base64 back to readable rules and recomputes the ruleset hash, for verification and forensics. |
| `YaraScanVerify` | Bounded post-dispatch check that a dispatched scan wave actually started on its hosts. |

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
re-edit **all seven** automations that carry credentials: `YaraReport`,
`YaraConsolidateStatus`, `YaraConsolidateApply`, `YaraConsolidateSummary`, `YaraCleanup`,
`YaraScanVerify`, `YaraWipeAllDatasets`. In each of the seven, the values to edit sit under
the banner `CONFIGURATION - the only values in this file you need to edit`.

> **A passing `!YaraReport` proves one key, not seven.** It exercises `YaraReport` alone.
> `YaraScanVerify` and `YaraWipeAllDatasets` are the two most often left on placeholders,
> and neither is touched anywhere else in this runbook — both fail at client construction
> the first time they are run. Open all seven and confirm each carries your real values.
> `YaraRulesFromFile` and `YaraRulesDecode` have no `CONFIGURATION` block and need no key:
> they make no tenant API call.

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

> **A large match count is the test rules working, not a finding.** The repo's
> `test_rules.yar` — 10 rules, `alert_severity` `low`, `scan_folder` left at its default
> (full scan) — produced **1,134 detections across 1,012 matched files** over three hosts.
> That is normal, and every part of it is explicable:
>
> - **`MatchNotepad` and `MatchCalc` are far broader than `notepad.exe` and `calc.exe`.**
>   The strings `"Notepad"` and `"calc.exe"` appear in many Windows resource binaries —
>   `forfiles.exe.mui`, WinSxS resource DLLs, .NET GAC assemblies. `MatchNotepad` alone
>   fired **594** times.
> - **The realistic-looking signature rules fire benignly too.** `Mimikatz_Indicator`
>   matched `C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache-*` because Defender's
>   own signature cache literally contains the string `gentilkiwi`.
> - **A rules file matches itself.** A `.yar` file contains the very strings its rules
>   search for, so `test_rules.yar` shows up in its own results — as do any decoy files you
>   planted, by construction.
>
> Judge a validation run by `0 rules failed compilation` (B1) and by rows landing here —
> **not** by a low match count. These rules exist to prove the pipeline, not to detect
> anything.

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

**Expect:** a markdown report headed `### YARA consolidation readiness - N ready, M pending`,
with a **Ready to consolidate** table, a **Ruleset groups a run would produce** table naming the
target datasets, and a **Pending** table giving each held-back scan a `reason` code. There is no
*blocked* bucket — the row ceiling and count-mismatch refusals belong to the retired per-scan
merge, which this automation does not run.

**On a fresh or freshly-wiped tenant:** `### YARA consolidation readiness - 0 ready, 0 pending`,
with every count `0` and every list empty. That is the correct result, not a misconfiguration —
a tenant with no host matches or scans datasets gives the gate nothing to evaluate.

**Reading it:** eligibility is not a countdown from when the scan ran. A scan is ready once
its lifecycle row is **terminal**; a scan with no terminal row at all is treated as finished
only after `retention_hours` (24 by default). A scan still listed as *in progress* here is
one whose terminal row has not arrived yet.

> **Both gates apply the 900s quiet period — they no longer diverge.**
> A terminal scan is not eligible until its newest match row is at least **900 s** old. The
> scanner sends the terminal row *ahead* of the upload drain (B2), so grouping inside that
> window would copy a partial row set — permanently, because the `scan_id` then counts as
> already consolidated and its missing rows are never written.
>
> **This gate now lives in `YaraConsolidateStatus` too.** It previously asked only *terminal,
> or silent past `retention_hours`*, which made it roughly 15 minutes looser than F2 and F3 —
> so a scan could be listed as ready here and then be left alone by them. Status is Apply's
> preview and the playbook feeds its `eligible_scan_ids` straight into F3, so a preview that
> was more permissive than the run it previews was the defect. Both now apply the same
> *(terminal AND quiet) OR aged* test, and a just-finished scan is correctly reported as
> **pending** here, not ready.

> **"Ready" is not "work is outstanding".**
> Eligibility and outstanding work are different questions, and this is the output most often
> misread. **Ready** means the scan passed the gate above. It says nothing about whether the
> consolidated datasets are already up to date.
>
> So a tenant where everything has already been merged still lists every finished scan as
> ready. Run F2 or F3 against it and they will correctly report *"target already current …
> verified, not rewritten"* and write nothing. Neither output is wrong — Status answers
> *which scans passed the gate*, F2/F3 answer *does the target need rebuilding*. Expect this
> on any tenant you have just consolidated, including the baseline you take before a test
> scan.

---

## Part F — Consolidation

> ### This part does not delete data
> Both consolidation automations are **dry run by default**. `YaraConsolidateApply` takes an
> `execute` argument that defaults to `false`, exactly as `YaraConsolidateSummary` does — a
> bare `!YaraConsolidateApply` writes nothing and deletes nothing.
>
> Neither mode ever deletes a per-host matches dataset, and neither deletes a scans shard.
> The real runs below do **create and write** new datasets on your tenant, so run them on a
> tenant where that is welcome.

### F2 and F3 are not one job at two settings

They read the **same** sources and group them the same way — by the ruleset hash the scanner
leaves at the end of every `scan_id` — but they write different targets at different grain,
and neither deletes. On v4 you run **both** if you want both grains; the choice is grain, not
safety.

|  | `YaraConsolidateSummary` — F2 | `YaraConsolidateApply` — F3 |
|---|---|---|
| Reads | the per-host **matches** datasets (plus the scans shards, to see which scans have finished) | the same |
| Writes | `yara_scanner_summary_v4_rules_<rulehash>` — one row per (host, rule) | `yara_scanner_full_v4_rules_<rulehash>` — every column of every matched-file row |
| Deletes | nothing, ever | nothing, ever |
| Default | dry run (`execute` defaults `false`) | dry run (`execute` defaults `false`) |

One dataset per **ruleset**, not per scan — every host scanned in one Action Center launch
shares the ruleset hash, and that is the only component they do share.

**Why nothing is deleted, and why that is not an oversight.** The v4 per-host matches dataset
carries **no month suffix**: it is **permanent**, and the scanner **overwrites it wholesale**
at the start of the next scan on that host. There is no accumulating pile of shards to
reclaim, so there is nothing for consolidation to free — and the dataset stays put as the
deep-dive source that a consolidated row points back to. Two independent guards keep it that
way: it is excluded when datasets are enumerated, and the same answer is re-derived at every
destructive call site. The single `remove_lookup_data` call inside the full consolidation
targets **its own output dataset**, dropping `scan_id`s the sources no longer hold so a
re-run after a re-scan reconciles instead of duplicating.

A scan's file-level detail is therefore never lost to consolidation — it is lost to the
**next scan on that host**, which is precisely why you want a consolidated target written
before then.

> **The scans lifecycle shards are a separate concern, and nothing in Part F touches them.**
> Full mode reads them only to build the terminal map that decides which scans have finished.
> The only thing that deletes an aged month-suffixed scans shard is `YaraCleanup`, and
> nothing in the pack schedules it — see G2.

### F1 · Preview first (safe)

**Do:** `!YaraConsolidateStatus`

Note which `scan_id`s are eligible, and which ruleset groups they fall into. Those are the
scans F2 and F3 will group. Run them before the next scan on those hosts — not because
consolidation would delete their matches, but because that next scan will overwrite the
per-host dataset and a consolidated target is what keeps a record.

**Also preview the run itself:** `!YaraConsolidateApply execute="false"`

> **A dry run tells you what it would GROUP, not what it would WRITE.**
> The `execute=false` path reports the row count assembled from the **sources** and returns
> before it ever queries the target dataset. It does not perform the already-current check,
> because that check costs a query per ruleset group and a preview has nothing to protect by
> paying it.
>
> So on a tenant that is already consolidated, the dry run lists the full set under
> `#### Would write` with **Rows** reading *"N would be written"*, and the very same command
> with `execute=true` then reports the group as `target_already_current` — *"target already
> current … verified, not rewritten"* — and writes **zero**. Both are correct; they are
> measuring different things. Treat the dry run's row count as **the size of the group**, and
> the executed run's as **the work actually outstanding**.
>
> The dry run is still the number to write down before a real run — just compare it against
> the sources, not against what the executed pass reports.

### F2 · Summary — record what matched (non-destructive)

> **Summary's readable output is markdown.** It renders in the War Room as headings and
> tables. The plain-text lines earlier revisions of this runbook told you to look for are
> gone — there is no `DRY RUN - nothing was created or written.` sentence, no
> `host shards deleted: 0` line, and no uppercase `WRITTEN:` / `SKIPPED:` / `FAILED:` blocks.
> Check the heading text and the table row labels below instead.
>
> `YaraConsolidateApply` (F3) now reports the same way — headings and tables, no plain-text
> lines — so the F3 expectations below are written against the markdown too.

**Do:**

```
!YaraConsolidateSummary execute="false"
```

**Expect:** a report headed `### YARA summary consolidation - DRY RUN`, with
*"Nothing was created or written. Re-run with `execute=true` to apply exactly this."*
directly under it. Then check, by eye:

- a key/value table whose left column reads **Targets**, **Rows**, **Hosts covered**,
  **Scans covered**, **Skipped**, **Failed**, **Source datasets deleted**, **Sources read**,
  **Stale-row removal**, **XQL calls**, **Read mode** — in that order. On this path
  **Targets** and **Rows** are phrased *"N would be written"*
- **Source datasets deleted** reads `0 - this automation has no deletion path`. That row is
  what replaced `host shards deleted: 0`, and it is the non-destructive claim you are
  signing off
- **Sources read** reads *"N of N host matches dataset(s)"*. The two numbers matching is how
  you know the pass was not bounded by `max_datasets` — a bounded pass also turns
  **Stale-row removal** off
- a **`#### Would write`** table, one row per ruleset group, with the columns
  `Ruleset | Rows | Hosts | Scans | Est. size | Eligible because | Target`. The **Target**
  cell is the `yara_scanner_summary_v4_rules_<rulehash>` dataset it would create
- a **Detail collapsed.** paragraph whenever anything was read — *"The host datasets hold
  **130,657** file-level findings - one for every (file, rule) pair, so a file that matched three rules counts three times. Grouped by
  (host, rule) they become **1,127** rows, a **115.9x** reduction."* Both figures cover
  everything the pass **read**, gated or not, so the ratio does not move with the gate. That
  also means the row count in this sentence is **not** the row count in the table above,
  which counts only what passed the gate
- a **`#### Settings this run used`** table listing `schema_version`, `quiet_secs`,
  `retention_hours`, `max_datasets` and `execute`, with `execute` reading `false - dry run`.
  Read the `retention_hours` row exactly as it describes itself — *"fallback only: a scan
  that never reported a terminal status is treated as finished once its newest row is this
  old. NOT a deletion window - this automation deletes nothing"*

A **`#### Skipped - nothing was touched`** table appears only when something was gated. Its
columns are `Scan or ruleset | Dataset | Reason | Detail`, and **Reason** comes from a closed
set: `scan_in_progress`, `quiet_period`, `no_rule_hash`, `source_unreadable`,
`stale_removal_disabled`, `nothing_observed`. A scan you have just run showing `quiet_period`
— *"finished, but its newest row is inside the 900s quiet period - rows may still be
draining, so it is left alone"* — is the E2 gate working, not a fault. `#### Failed` and
`#### Warnings` likewise appear only when they have something to report; on a clean pass
neither is present and the **Failed** row of the key/value table reads `0`.

Then run it for real:

```
!YaraConsolidateSummary execute="true"
```

**Expect:** the same report, with exactly these differences:

- the heading is `### YARA summary consolidation - EXECUTED`, and the line under it reads
  *"Per-ruleset summary targets were created and written."*
- **Targets** and **Rows** are phrased *"N written"* — on a single-ruleset test, `1 written`
  and something like `24 written`
- **`#### Would write`** is replaced by **`#### Written`**, which carries two more columns:
  `Ruleset | Rows | Hosts | Scans | Refreshed | Stale rows dropped | Eligible because | Target`
- `execute` in the settings table reads `true`

**Fails if:** **Source datasets deleted** reads anything other than
`0 - this automation has no deletion path`. It is the same on both paths — summary mode never
deletes.

**Verify the source survived:**

```
dataset = <MATCHES> | comp count() as rows by scan_id
```

**Expect:** unchanged. This is the proof that summary mode is safe to schedule.

### F3 · Apply — the full-detail consolidation (non-destructive)

**Do:** the dry run first, which is what a bare invocation already gives you:

```
!YaraConsolidateApply
```

**Expect:** a report headed `### YARA full consolidation - DRY RUN`, with *"Every column of
every matched-file row, grouped by ruleset. Nothing was created or written. Re-run with
`execute=true` to apply exactly this."* directly under it. Then check, by eye:

- a key/value table whose left column reads **Outcome**, **Targets**, **Rows**, **Ruleset
  groups**, **Hosts covered**, **Skipped**, **Failed**, **Source datasets**, **Fleet
  progress** — in that order. On this path **Targets** and **Rows** are phrased
  *"N would be written"*
- **Outcome** reads `dry_run` — but only while `#### Failed` is absent. It reads
  `partial_failure` on a dry run that refused a group, because a refusal is a refusal
  whichever mode found it, and `dry_run` is the row that would otherwise hide the one
  failure a dry run can produce. The mode is named by the heading, not by **Outcome**
- **Source datasets** reads *"host matches datasets retired: 0 (dry run - retirement only
  happens after a write is read back and verified)"*. That row replaced the old constant
  `host matches datasets deleted: 0` line, and it now reports what this run did rather than
  a policy
- **Fleet progress** reads *"datasets: N of N - the whole fleet, so nothing is pending"*. The
  two numbers matching is how you know the pass was not bounded by `max_datasets` — a bounded
  pass says *"M of N this pass, K still to go - RE-RUN to continue"* and turns stale-row
  removal off
- a **`#### Would write`** table, one row per ruleset group, with the columns
  `Ruleset | Rows | Hosts | Scans | Target`. The **Target** cell is the
  `yara_scanner_full_v4_rules_<rulehash>` dataset it would create

A **`#### Skipped - nothing was touched`** table appears only when something was gated;
`#### Failed` likewise. Both carry a `Reason` column drawn from a closed set — `quiet_period`
and `scan_in_progress` are the two you should expect to see right after a scan, and
`row_ceiling_exceeded` is the one that does not clear by waiting.

Then run it for real:

```
!YaraConsolidateApply execute="true"
```

**Expect:** the same report, with exactly these differences:

- the heading is `### YARA full consolidation - EXECUTED`, and the line under it reads
  *"Per-ruleset full targets were created and written."*
- **Outcome** reads `success` (or `partial_failure` if anything is in `#### Failed`)
- **Targets** and **Rows** are phrased *"N written"*
- **`#### Would write`** is replaced by **`#### Written`**, which carries two more columns:
  `Ruleset | Rows | Hosts | Scans | New scans | Stale rows dropped | Target`
- **Source datasets** now reports the retirement outcome for a real pass — *"host matches
  datasets retired: N (a source is deleted only once its rows are read back from the ruleset
  dataset and counted…)"*. See **Verify what Apply left alone** below for what N should be

**Verify the target holds the grouped rows:**

```
dataset = yara_scanner_full_v4_rules_<rulehash> | comp count() as rows by scan_id
```

**Expect:** one row per consolidated `scan_id`, and the counts matching what those hosts'
matches datasets hold.

> **Do not** go looking for a `yara_scanner_matches_v4_scan_<slug>` or
> `yara_scanner_scans_v4_scan_<slug>` dataset. Earlier revisions of this runbook told you to.
> Those per-scan target names are obsolete — the full consolidation never creates them, and
> querying one returns a dataset-not-found error that reads exactly like a failed
> consolidation.

**Verify what Apply left alone:**

```
dataset = <MATCHES> | comp count() as rows by scan_id
```

**Expect:** whichever of two answers the **Source datasets** row of the report already told
you to expect, and read that row *first*:

- *retired: 0* — the per-host matches dataset is untouched, identical to F2: same dataset,
  same `scan_id`, same row count. This is the answer on every dry run, and on any executed
  pass whose write it could not read back and verify.
- *retired: N* — N per-host matches datasets were **deleted**, and querying one now returns
  dataset-not-found. That is `CONFIG_RETIRE_SOURCES_AFTER_FULL` (`True` as shipped) doing its
  job, not a fault: a source is retired only after its rows are read back **out of the
  ruleset target** and counted, so the rows are already safe, and the host's dataset comes
  back on its next scan. Confirm it by counting the same `scan_id` in
  `yara_scanner_full_v4_rules_<rulehash>` — that is the copy that now holds it.

**Fails if:** a source dataset is gone while its `scan_id` is *not* in the ruleset target, or
while **Source datasets** still reads `retired: 0`. Either way the report and the tenant
disagree, which is the one outcome this step exists to catch. Summary mode retires nothing at
all, so F2's source is unchanged regardless.

**Do:** `!YaraReport`

**Expect:** every per-host matches and scans dataset still present, and the new
`yara_scanner_full_v4_rules_<rulehash>` target listed as *this pack's own consolidated
output, never a candidate*.

**Reading it:** re-run `!YaraConsolidateApply execute="true"` with nothing changed. If the
sources were kept, the group comes back in `#### Skipped - nothing was touched` with reason
`target_already_current` — *"target already current … verified, not rewritten"* — and that
verified no-op is the reconciliation working, not a skipped pass. If they were retired, there
is nothing left to read and **Fleet progress** says so (`datasets: none found for this schema
version`); the ruleset target still holds the rows, and the next scan on that host recreates
its dataset for the following pass.

**One more shape worth recognising:** if another pass holds `yara_scanner_consolidation_lock`,
this run prints `### YARA full consolidation - STOOD DOWN` and one sentence saying which of
the two refusals it was — *"the consolidation lock is held by another concurrent run"* (wait
for that pass) or *"the marker exists but its row could not be read … (add_data create-lag)"*
(re-run in a minute) — followed by a `#### Lock events` list carrying the lock lines
themselves. Nothing was read, created, written or deleted on that path, and
`Yara.ConsolidateApply.lock_standdown_reason` carries the same answer as a code.

### F4 · Confirm the run was recorded

**Do:**

```
dataset = yara_scanner_consolidation_runs
| fields _insert_time, status, consolidated_count, failed_count
| sort desc _insert_time | limit 5
```

**Expect:** a **`started`** row *and* a terminal row (`success` / `partial_failure`) for
your `execute="true"` run.

**Reading it:** a `started` row with **no** matching terminal row means a pass was killed —
or is still running. That pairing is the diagnostic you'll rely on in production.

**Look for nothing from the dry runs.** Only an `execute="true"` pass writes to this
dataset; a preview changes nothing and is deliberately not logged. A pass that stood down on
the lock records its own status, `skipped_locked`, rather than `success`.

### F5 · A group too large to write

There is no bounded pass to drain and no `max_scans` argument. The per-pass bound is
`row_ceiling` (shipped default `60000`), and it is a **refusal**, not a partial write.

**Expect:** a ruleset group over the ceiling appears in the `#### Failed` table with
**Reason** `row_ceiling_exceeded` and **Detail** *"N row(s) exceeds the full-consolidation
ceiling of 60000 - REFUSED rather than half-filling …"*. Re-running will not help — it will
refuse identically.

**Expect it on a dry run too, and expect the header to say so.** The ceiling is checked
before the `execute` branch, so `!YaraConsolidateApply` on its own reaches this refusal —
and on that path **Outcome** reads `partial_failure`, not `dry_run`. That is deliberate: a
dry run is the default mode and this is the only failure it can produce, so a `status` that
reported `dry_run` here would hide from a playbook the one refusal an operator has to act
on. The heading still reads `DRY RUN`, and `dry_run` in context is still `true`.

**Do, if you hit it:** use `YaraConsolidateSummary` for a fleet that size (full detail runs
roughly 40× the rows of a summary), or raise `row_ceiling` deliberately, knowing lookup
writes were measured going dead around 70,000 rows.

---

## Part G — Prove the safety rails fire

The most valuable part. A guard you have never seen trigger is a guard you are trusting on
faith.

### G1 · The consolidation lock

**Do:** start `!YaraConsolidateApply execute="true"` and, while it is still running, start a
**second** one from another War Room tab.

**`execute="true"` is required for this test.** A dry run takes no lock — it has nothing to
serialise — so two concurrent previews will both simply run.

**Expect:** the second returns a report headed `### YARA full consolidation - STOOD DOWN`
over *"Skipped this pass: the consolidation lock is held by another concurrent run. Nothing
was read, created, written or deleted."*, followed by a `#### Lock events` list carrying the
lock line the run logged. It touches nothing, `status` is `skipped_locked` and
`lock_standdown_reason` is `held_by_running_pass`.

**The other standdown is worded differently on purpose.** If the marker dataset exists but
its row cannot be read yet — the `add_data` create-lag window right after another run took
the lock — the sentence instead reads *"the consolidation lock marker exists but its row
could not be read - most likely another run created it moments ago (add_data create-lag)"*
and `lock_standdown_reason` is `marker_unreadable`. The two used to render identically, so a
race that clears in a minute and a genuine collision could not be told apart. Re-run after a
minute for the second; wait for the running pass for the first.

`!YaraConsolidateSummary execute="true"` takes the **same** lock, so a Summary pass and an
Apply pass will not overlap either — but it stands down in its own words. Summary returns
exactly this, and nothing else:

```
Another consolidation run holds the lock - nothing was touched.
```

**This one path is not markdown.** That single sentence is the entire readable output: no
`### YARA summary consolidation` heading, no key/value table, no sections. Its context is
only `{"status": "lock_held_by_other_run"}` — none of the usual counters are set, so a
playbook branching on this pass should branch on that `status`.

**Why it matters:** the lock serialises **writers**, not deleters. Concurrent writers to one
lookup dataset lose rows — measured at 87% loss with eight of them — and two passes
reconciling the same consolidated target would each compute *stale* from a target the other
was mid-way through changing.

### G2 · Cleanup refuses to delete without opt-in

**Do:**

```
!YaraCleanup older_than_months="0"
```

**Expect:** a report of what it *would* delete, and **nothing deleted** — `execute`
defaults to false.

**Verify:** the datasets it named still exist.

**Reading it:** this is the **only** thing in the pack that deletes an aged month-suffixed
scans shard, and nothing schedules it. Those shards accumulate until you run this
deliberately — consolidation never removes them for you.

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
> - this pack's own consolidated output — the `_rules_<hash>` summary and full datasets — is
>   never a candidate, and neither is the current month or a future-dated month
> - `execute` still defaults to false
>
> Verify by reading the skip reasons rather than by running a real delete.

---

## Part H — Sign-off

| # | Check | Pass |
|---|---|---|
| A1 | Scanner reports `3.4.0` | ☐ |
| A2 | Exactly nine automations, no `Fast` | ☐ |
| A3 | `!YaraReport` authenticates, and all **seven** credentialled automations edited — `YaraScanVerify` and `YaraWipeAllDatasets` included | ☐ |
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
| E2 | Readiness reports in-progress scans as not yet eligible | ☐ |
| F2 | Summary mode wrote rows and deleted **nothing** | ☐ |
| F3 | Bare Apply was a **dry run**; `execute="true"` wrote the full ruleset target and deleted **nothing** | ☐ |
| F4 | `started` + terminal rows both recorded for the `execute="true"` run | ☐ |
| G1 | Second concurrent Apply refused on the lock | ☐ |
| G2 | Cleanup dry-run deleted nothing | ☐ |
| G3 | Cleanup skipped the live matches dataset | ☐ |
| G4 | Cooperative cancel wrote a `cancelled` row | ☐ |
| G5 | Too-low version fails safe; too-high hazard understood | ☐ |

### Before you go to production

- [ ] Action timeout sized from **your** D2 measurement, not the reference figure
- [ ] Consolidation scheduled at the grain you actually want — `Summary` for one row per
      (host, rule), `Apply` for every column of every matched-file row, or both. They differ
      in grain, not in safety: neither deletes anything, and either one scheduled alone still
      keeps a record of a scan's matches once the next scan overwrites that host
- [ ] Whatever you schedule is scheduled with **`execute="true"`** — everyone who can run
      these knows that a bare invocation is a **dry run that writes nothing**
- [ ] `YaraCleanup` scheduled — if at all — in its **own** window, never alongside the
      consolidation. It is the only thing that deletes, and nothing schedules it for you
- [ ] Test rules removed; only real detection content ships
- [ ] `row_ceiling` sized for your fleet, or `Summary` chosen instead — a group over the
      ceiling is refused outright, and re-running will not get it in

---

## If something fails

Full failure-mode catalogue with causes and fixes:
**[Operations Deep Dive §13](Operations_Deep_Dive.md#13-failure-modes-catalogue)**.

The three that account for most first-run surprises:

| Symptom | Almost always |
|---|---|
| Rows missing, `delivery_shortfall` non-empty | Action timeout too short — it expired mid-drain (Part D) |
| Matches dataset accumulating scans | Scanner key missing **Query Center** (A4) |
| Consolidation reports 0 candidates and exits clean | `schema_version` mismatch; or every scan is still lacking a terminal lifecycle row, or is still inside the 900 s settle window (E2) |
