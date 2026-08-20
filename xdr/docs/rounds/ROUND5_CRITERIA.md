# Round 5 — Dataset management, live: acceptance criteria

Written **before** the round runs, as with rounds 1–4. Criteria are the contract; a bar
moved after seeing results is not a bar.

Round 4 decided all 26 D-criteria, but it decided them against `FakeClient` and against
`xdr/simulation/sim_edge.py`. That simulator imports `argparse`, `time` and `simlib` and
**nothing from `xdr_consolidate` or `YaraConsolidateCommon`** (`sim_edge.py:12-16`); it
seeds a shared tracker dataset named `yara_sim_matches_<host>` (`simlib.py:69-74`), which
`parse_shard` rejects and the shipped discovery path (`_list_yara_datasets` +
`_SHARD_RE`, `xdr_consolidate.py:46-48`, `:954`) can never see. Round 4 therefore validated
the *live API primitives* under a prototype architecture, and validated the *shipped logic*
only against a fake. That is not a criticism of Round 4 — it is the reason Round 5 exists.

## The objective, as a single binding claim

> The consolidation code that ships — `xdr_consolidate.py`, the `YaraDatasetManagement`
> pack and its playbook — does on the tenant, against real shards written by real
> endpoints, exactly what the fake said it does: **every finished scan's shards are merged
> into one per-scan dataset holding every row, and nothing belonging to a scan that has not
> finished is read, rewritten or deleted.**

Both halves are load-bearing. Round 4 already showed that bounding dataset count is easy;
the whole difficulty is bounding it without losing a finding, and the fake cannot fail in
the ways a tenant does — string-typed counts, ingest lag, streamed reads, a live agent
writing to a shard mid-pass.

## How it is triggered

**Manually, from XSOAR.** There is no Job primitive on this tenant and correlation rules
were proven unable to see dataset creation (Round 4). The playbook is started against an
**issue**, not from the playground — `!setPlaybook name="YARA Dataset Consolidation"`
(display name from `playbook-YARA_Dataset_Consolidation.yml:3`). The two automations
`YaraConsolidateStatus` / `YaraConsolidateApply` *do* run in the playground, and the CLI
`xdr/xdr_data_management.py --consolidate` is a third entry point. **These three are not
equivalent, and Round 5 must say which one produced each verdict:**

- **`quiet_secs` is unreachable from the playbook.** `grep -c quiet_secs` on the playbook
  YAML is **0**. Its inputs are `scan_id`, `poll_interval_minutes`, `poll_timeout_minutes`,
  `row_ceiling`, `abandoned_after_hours` only (`:380-409`), and tasks 1/4/6 pass three of
  those (`:89-94`, `:199-204`, `:262-268`). Every playbook run is
  `DEFAULT_QUIET_SECS = 900` (`xdr_consolidate.py:60`).
- **The run log is discarded by the pack.** `YaraConsolidateStatus.py:30` passes
  `log=lambda *a: None`; `YaraConsolidateApply.py:75` keeps only
  `[m for m in log_lines if "lock" in m.lower()]`. Any criterion whose evidence is a log
  line must be earned through the CLI.
- **Gate B is dead on every shipped path.** `action_state_for` is supplied by exactly one
  call site in the repository — `tests/test_consolidation.py:144`. Not by
  `YaraConsolidateApply.py:20-29`, not by `YaraConsolidateStatus.py:16-26`, not by
  `xdr_data_management._run_consolidate`, not by the playbook. It defaults `None`
  (`xdr_consolidate.py:590`, `:777`, `:824`), so `astate` at `:373` is always `None` and
  the Action-Center half of `shard_is_terminal` (`:220-233`) never evaluates.

---

## The edge-case table

| # | Case | How it is induced | Precondition | Expected result | False-failure trap |
|---|---|---|---|---|---|
| **E1** | Happy path, both endpoints | one `run_snippet_code_script` action, `endpoint_id_list` = [linux, windows], seeded target | both `CONNECTED`; scans produce ≥1 match each | **two** scan_ids, **four** per-scan targets, each target row-count == its source count; both shards kept | merge-settle race → `count_mismatch` on the first pass only (`xdr_consolidate.py:746`) |
| **E2** | Cooperative cancel (scanner's own) | `xdr_action_center.py cancel --hostname xdr-agent` ≥10s into a long worker phase | scan still in the **worker** phase, not compiling and not draining | terminal row `status="cancelled"`; consolidates via the lifecycle gate; pre-cancel rows all present in the target | cancel delivered during compile is deleted as stale; delivered during uploader drain is never polled |
| **E3** | Console-Cancel orphan | click Cancel in the Action Center UI (not scriptable) | matches count snapshotted **before** the click | action `ABORTED`; lifecycle frozen at `initiated`/`running`; no terminal row, no summary JSON | `wait_action` spins to `max_polls` — `ABORTED` is absent from both polling terminal sets |
| **E4** | Compressed abandoned cutoff (rider on E3) | CLI `--abandoned-after-hours 0.1 --quiet-secs 120 --scan-id <E3 sid>` | E3's newest row ≥360s old and **<7 days** old | ABANDONED log line names the *age*, then consolidates | lowering `abandoned_after_hours` alone gives `within_quiet_period`; through the playbook it always does |
| **E5** | Mixed: one host finished, one running | start Windows long-scan first, Linux short-scan second, run the playbook | Windows still running ~20 min after Linux's last row | Linux scan in `eligible_scan_ids`, Windows in `pending_scan_ids`; Windows target absent; Windows rows untouched | shard-level row counts drop for an unrelated, correct reason — assert per `scan_id` |
| **E6** | Sibling scans, one shard | two scans on **xdr-agent**: A finished, B running; consolidate A only | both in the same `_202608` shard | A's rows stripped, B's intact, shard **kept** with `kept shard … 1 of 2 scan(s) still pending` | the log line is CLI-only; through the pack this is invisible |
| **E7** | Concurrent mutation of a live shard | run E6's Apply **while** B's uploader is actively POSTing | B mid-scan, flushing matches | every B row present and B's own count monotonic; no `records_skipped` spike in B's summary | B's row count legitimately rises during the pass — compare row *identity*, not totals |
| **E8** | Lock and pass duration | one **dry** unscoped `YaraConsolidateStatus`, timed; then a scoped Apply while it runs | baseline shard census taken | dry pass completes well under 900s; a second Apply reports `lock_held_by_other_run` and deletes nothing | a dry run never takes the lock (`:841`) — the second pass must be an **Apply** to contend |
| **E9** | Gate B by injection (D1.3) | import `xdr_consolidate` directly, pass `action_state_for=lambda h: "ABORTED"` | E3's orphaned scan_id, still inside its abandoned cutoff | consolidates with `is_terminal=True` and **no** ABANDONED line | this is not a shipped path — record it as a demonstration, never as pack/CLI evidence |

**Not in the table:** a genuinely `failed` lifecycle row. See
[Cases that cannot be produced live](#cases-that-cannot-be-produced-live-and-why).

---

## Per-case detail

Throughout: `$WT` = this worktree root. Session preamble, required for **every** command —
there is no `.env` in this worktree, so both clients fail as `RuntimeError: Missing XDR
creds` (`xdr_action_center.py:51-61`, `xdr_lib.py:19-32`), which reads like an auth problem
and is a path problem:

```bash
export XDR_ENV_FILE=/Users/aymanmahmoud/Documents/Coding/Yara/.env
export XDR_CA_BUNDLE=/Users/aymanmahmoud/Documents/Coding/Yara/.claude/skills/xdr-yara-scan-test/scripts/xdr_ca_bundle.pem
export YARA_LOOKUP_SCHEMA_VER=3
```

The third export matters more than it looks. The **tooling** defaults to schema `"2"`
(`xdr_action_center.py:43`) while the **scanner** writes `"3"` (`xdr_yara_scanner.py:372`).
Without it, `--report` files every live dataset under "NEWER schema — never deleted by this
tool" and `--older-than-months` selects nothing. Same trap in the pack: `YaraReport` /
`YaraCleanup` take `schema_version` defaulting to `2` — always pass `schema_version=3`.

Two skill-script defects to work around before any scan (both verified in this worktree):

- **`--scanner` defaults to a file that does not exist.** `run_scan.py:22` resolves `repo`
  four levels up from `scripts/` = `$WT`, then defaults `--scanner` to
  `$WT/xdr_yara_scanner.py`. The scanner is at `$WT/xdr/xdr_yara_scanner.py`; `ls` on the
  root path returns *No such file or directory*. Same computation in `build_snippet.py:114`
  and `cancel_scan.py`. Pass `--scanner` explicitly to all three.
- **`run_scan.py` cannot scan a real folder.** `--seed-files` is `type=int, default=0`
  (`run_scan.py:28`) and `build_snippet.py:69` gates on `if seed_files is not None:` —
  `0 is not None`, so the seed prelude always runs and `build_snippet.py:97` sets
  `target_expr = "_TARGET"`, discarding `--scan-folder` entirely. A "we scanned
  `C:\Program Files`" claim made through `run_scan.py` is false: it scanned the 3–5 seeded
  files. For a real folder use `xdr_action_center.py run-scanner`, whose `--scanner`
  default is correct and which has no seed prelude.

Dataset names, derived not guessed. `_dataset_shard_suffix` (`xdr_yara_scanner.py:706-716`)
is slug + `sha1(raw_hostname).hexdigest()[:6]`; name assembly is `:4056-4066` with prefix
`yara_scanner` (`:396`), `_v3` (`:372`), monthly rotation from `run_id` (`:4043-4044`).
Reproduced independently here: `sha1("xdr-agent")[:6] = cd7e9b`,
`sha1("xdragent2")[:6] = 2fd370`. So:

```
yara_scanner_matches_v3_xdr_agent_cd7e9b_202608
yara_scanner_scans_v3_xdr_agent_cd7e9b_202608
yara_scanner_matches_v3_xdragent2_2fd370_202608
yara_scanner_scans_v3_xdragent2_2fd370_202608
```

**A scan on or after 2026-09-01 writes `_202609` datasets** — the month comes from the
endpoint's `run_id`, not from your clock. Every hard-coded `_202608` below must be
re-derived if the round slips past month end.

---

### E1 — Happy path, one action, two endpoints

**Why "two scan_ids" is the criterion and not a caveat.** `scan_id` is
`f"{hostname}_{run_id}_yara_{yara_hash[:12]}"` (`xdr_yara_scanner.py:2988`) with
`run_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")` computed on each agent at
`ScanConfig.__init__` (`:2864`). There is no override: `ScanConfig.__init__` takes no
`scan_id`, no `YARA_SCAN_ID` env var exists, and the `--options` allowlist
(`_VALID_OPTION_KEYS`, `:901-906`) has no such key. The comment at `:2982-2987` records
that a shared rule-hash `scan_id` was the *old* behaviour and was removed because it broke
multi-host correlation. One action can therefore cover both endpoints, but it can never
produce one scan.

That has a consequence Round 5 must state out loud: because each scan_id has exactly one
source shard, `_gate_scan`'s cross-host loop (`xdr_consolidate.py:918-951`) is always
entered with `len(srcs) == 1`. **E1 runs two independent single-host consolidations, not
one two-host consolidation.** The cross-host AND is covered offline by
`tests/test_consolidation.py:328-337`; claiming it live from E1 would be unearned.

No shipped CLI sends a multi-endpoint list — `run_scan.py:52` and `run-scanner` both pass
`[eid]` — but `run_snippet` takes a list (`xdr_action_center.py:193`,
`xdr_lib.py:119-124`):

```bash
python3 $WT/.claude/skills/xdr-yara-scan-test/scripts/check.py --hostname xdr-agent
python3 $WT/.claude/skills/xdr-yara-scan-test/scripts/check.py --hostname xdragent2
python3 - <<'PY'
import sys, base64; sys.path.insert(0, "$WT/xdr")
from xdr_action_center import XDRActionCenter
c = XDRActionCenter()
rules = base64.b64encode(open("$WT/test_rules.yar","rb").read()).decode()
code = c.build_scanner_snippet("$WT/xdr/xdr_yara_scanner.py", rules, scan_folder="default")
print(c.run_snippet(code, [c.endpoint_id("xdr-agent"), c.endpoint_id("xdragent2")], timeout_secs=3600))
PY
```

`$WT/test_rules.yar` is the right ruleset: **10 rules, zero `import` statements**
(measured), so nothing is skipped by the agent's libyara.

**Matches must be guaranteed, or E1 fails for the wrong reason.** A scan_id with zero
match rows never enters `all_groups`, the matches pass emits no plan, and
`yara_scanner_matches_v3_scan_<slug>` is simply never created — an assertion of "four
targets" then fails while the code behaved correctly. Either seed (the prelude writes
mimikatz / ransom-note / certutil strings to `decoy.txt` and, on Windows only, copies
`notepad.exe`/`calc.exe`, `build_snippet.py:69-97`), or verify a non-zero matches count
before consolidating.

Verification, using the same aggregation the gate itself uses (`xdr_consolidate.py:513`) so
that what you read is what it reads:

```
dataset = yara_scanner_matches_v3_xdr_agent_cd7e9b_202608
| comp count() as n, max(event_timestamp_ms) as newest, max(_insert_time) as srv_newest by scan_id
```

Repeat per named dataset. **Never use a `yara_scanner_matches*` wildcard for a before/after
comparison** — it spans shards *and* per-scan targets, and `_cleanup_verified_scan_rows`
(`:480-503`) strips a verified scan's rows from the source *after* the target verifies, so
mid-flight the wildcard reads a transient double count.

Expected afterwards — `target_name` slugifies `scan_id` to `[a-z0-9_]`, so `xdr-agent`
becomes `xdr_agent` (`:177-180`):

```
yara_scanner_{matches,scans}_v3_scan_xdr_agent_<run_id>_yara_<hash12>
yara_scanner_{matches,scans}_v3_scan_xdragent2_<run_id>_yara_<hash12>
```

`<hash12>` is identical on both hosts; `<run_id>` is not. **Both source shards are kept**,
and that is correct, not a miss: `to_delete = [ds for ds, sids in shard_scans.items() if
sids and sids <= verified]` (`:763`) deletes a shard only when *every* scan_id it holds is
verified, and both shards hold other scans. Expect `kept shard … N of M scan(s) still
pending consolidation` (`:765-767`) — and treat a *missing* shard as a Round 5 failure.

**E1's most likely false failure is the merge-settle race.** `xdr_consolidate.py:746` sleeps
`min(30, 2 + src_total // 500)` and then counts **once**, and `plan_consolidation`
(`:400-414`) demands exact equality. At 6,000 rows that is a 14-second wait; the scanner's
own measured `add_data` merge times are ~13s at 15k rows and ~31s at 77k rows
(`xdr_yara_scanner.py:341-347`), and this project's own live probe harness needed
`sleep(15)` plus `rows_in(tries=8, delay=6)` to count **9** rows reliably
(`simlib.py:99-110`). A short count yields `ok=False, reason="count_mismatch"`, sources
kept, `failed_count=1`, playbook task 8 "needs attention". **This is not data loss and must
never be adjudicated on a single pass** — re-run Apply; the second pass takes PATH A
(`:691-700`), finds the target already complete, and verifies.

---

### E2 — Cooperative cancel

There is no cancel API. The cancel is a *second* Action Center action delivering the
scanner's own entry point: `build_snippet.build(..., mode="cancel")` →
`xdr_yara_scanner.py:7543-7544` short-circuits to `_handle_cancel_request()`, which writes
`control/cancel.flag`. The running scan's watcher polls it at `CANCEL_POLL_SECS = 5`
(`:401`) and `_request_cancel` sets `cancel_requested = True`; the terminal row at `:7070`
then reads `cancelled` (`:7061-7069`).

```bash
python3 $WT/.claude/skills/xdr-yara-scan-test/scripts/run_scan.py \
  --hostname xdr-agent --scanner $WT/xdr/xdr_yara_scanner.py \
  --rules $WT/test_rules.yar --seed-files 20000 --timeout 900 &
sleep 15
python3 $WT/xdr/xdr_action_center.py cancel --hostname xdr-agent
```

**Two windows in which the cancel is silently ignored, both of which read as "cooperative
cancel is broken":**

1. **During rule compilation the flag is deleted as stale.** `_start_cancellation_watcher`
   removes a flag whose mtime `< self._process_started_at - CANCEL_STALE_TOLERANCE_SECS`
   (`:5371-5372`, tolerance `2.0` at `:409`). Its docstring (`:5364-5367`) claims a cancel
   delivered during the pre-scan compile phase "is deliberately preserved". **It is not:**
   `self._process_started_at = time.time()` is assigned at `:5307`, while
   `self.rules = self._load_or_compile_rules(...)` runs at `:5236` — *earlier in the same
   `__init__`*. The baseline is stamped after compilation finishes, so a mid-compile flag is
   older than it and is discarded. The scan runs to completion with `cancel_source=''`.
   `running.json` does not exist yet either, so `mode=cancel` reports `scanner running: no`.
   **This is a real defect in the scanner and should be filed as one**, not recorded as an
   E2 failure.
2. **During the uploader drain nothing polls the flag.** The watcher loops
   `while self.scan_active` (`:5390`); `scan_active = False` at `:7055`, the terminal row is
   emitted at `:7070`, and `lookup_uploader.stop(wait=True)` runs after — a drain budget of
   `min(600, max(150, batches*45))` (`:4539-4540`, constants `:339`, `:343`) with no
   watcher alive. A cancel arriving there is never read and the run reports `completed`.

Hence `--seed-files 20000` (a long worker phase) and `sleep 15` (past compile, well inside
the workers).

Verify three independent books, all of which exist for E2 and none of which exist for E3 —
that asymmetry is itself worth recording:

1. `dataset = yara_scanner_scans_v3_xdr_agent_cd7e9b_202608 | filter scan_id = "<SID>" | fields status, files_scanned, detections, event_timestamp_ms | sort desc event_timestamp_ms`
2. the `SCAN_RESULT` stdout line, `Scan cancelled by operator: N files scanned | M matches found`
3. `logs/scan_summary_<run_id>.json` — `outcome`, `matches`, `dataset_delivery`, and
   `delivery_shortfall`

**Do not read an empty `delivery_shortfall` as "every row is in the dataset".**
`_delivery_shortfall` computes `landed = records_added + records_updated + records_skipped`
(`xdr_yara_scanner.py:7464-7467`), but `records_skipped` is exactly the server *rejecting*
a row — the failure `_coerce_row` exists to fix (`xdr_consolidate.py:537`). If the dataset
count is below `detections` and the shortfall is empty, the loss is upstream of
consolidation; read `dataset_delivery.records_skipped` before blaming the merge.

**What E2 does and does not earn.** `shard_is_terminal` is a set-membership test and both
`"cancelled"` and `"completed"` are in `TERMINAL_LIFECYCLE` (`xdr_consolidate.py:50`), so
from `:934` onward E2 traverses byte-identical code to E1. E2 validates the **scanner's**
cancel path; it says nothing new about consolidation, and `tests/test_partial_scans_are_preserved.py:55-68`
already pins the consumer half in both copies. Record it as scanner evidence.

---

### E3 — Console-Cancel orphan

**Not scriptable, by design.** `actions_center/actions/abort|cancel` live under
`/api/webapp/` — the console's private, MFA-session backend
(`.claude/skills/xdr-action-center-api/references/public-api-map.md:38-57`;
`xdr/docs/topics/Scan_Cancellation.md:117-120`). E3 requires a human clicking Cancel on the
running action.

The kill is a `TerminateProcess`/signal kill of the payload: `_perform_enhanced_cleanup`
never runs, so no terminal row is written and no `scan_summary_<run_id>.json` exists
(`Scan_Cancellation.md:29-67`). The lifecycle freezes at `initiated` or `running`.

Note in passing that `xdr_yara_scanner.py:7740-7760` *does* install SIGTERM/SIGINT handlers
— inside a bare `try/except` that swallows the `ValueError` raised because the agent runs
scripts on a non-main thread (`Scan_Cancellation.md` §4). The handler is dead code under
Action Center. Do not expect it to soften E3.

**Capture the baseline before the click. It is the only book E3 gets:**

```
dataset = yara_scanner_matches_v3_xdragent2_2fd370_202608
| filter scan_id = "<WIN_SID>"
| fields _insert_time, event_timestamp_ms, rule, filename, file_sha256, match_count
| sort asc _insert_time
```

Expect the dataset count to sit **below** the endpoint's true findings by up to 499 rows or
30 seconds of work: matches batch at `LOOKUP_DATASET_BATCH_SIZE = 500` /
`LOOKUP_DATASET_FLUSH_SECS = 30` (`xdr_yara_scanner.py:335-336`) and a hard kill discards
the in-memory queue. **That gap is real, expected loss, not a consolidation defect** — the
snapshot *is* the definition of "the partial findings", and verifying against the
endpoint's local match count instead will always look like a failure.

**Expected trap:** after the click, `wait_action` will spin to `max_polls` (default 60 × 6s
= 360s) rather than returning. `ABORTED` is absent from both action-polling terminal sets —
`xdr_action_center.py:98-99` and `xdr_lib.py:148-149` list
`{COMPLETED_SUCCESSFULLY, FAILED, TIMEOUT, CANCELED, EXPIRED, COMPLETED_WITH_ERRORS,
COMPLETED_PARTIAL}` — while `xdr_consolidate.py:56-58` does carry it. Six minutes of
apparent hang is the poller, not the scan.

---

### E4 — Compressed abandoned cutoff (rider on E3)

**The rule, stated exactly.** The abandoned branch does **not** return; the quiet check sits
*outside* the `if not is_terminal:` block:

```
935        if not is_terminal:
937            abandoned = age_ms is not None and age_ms >= abandoned_after_secs * 1000
938            if abandoned or settled:
939                log(... "treating as ABANDONED, consolidating to preserve its findings")
946            else:
948                return "host_not_terminal"
949        if not newest_row_age_ok(newest, now_ms, quiet_secs) and not settled:
951            return "within_quiet_period"
```

So a non-terminal scan consolidates iff its newest row age ≥ **max(abandoned_after_secs,
quiet_secs)**. At the defaults `max(86400, 900) = 86400` and the quiet gate is never
binding, which is exactly why the collision only appears once you compress. Driving the real
`_gate_scan` reproduces it, including the case that surprises people:
`abandoned_after_hours=0` with `quiet_secs=900` still returns `within_quiet_period`.

```bash
python3 $WT/xdr/xdr_data_management.py --consolidate --scan-id <WIN_SID> \
    --abandoned-after-hours 0.1 --quiet-secs 120           # dry
python3 $WT/xdr/xdr_data_management.py --consolidate --scan-id <WIN_SID> \
    --abandoned-after-hours 0.1 --quiet-secs 120 --yes
```

`0.1` → 360s via `int(float(h) * 3600)` (`YaraConsolidateApply.py:29`,
`YaraConsolidateStatus.py:26`). Prefer it over `0.05`: the conversion truncates (`0.0833` →
**299**s), and anything under ~300s sits inside `SKEW_TOLERANCE_MS = 5*60*1000`
(`xdr_consolidate.py:78`).

**Three things that make E4 unrunnable, or make it lie, through the pack:**

- **The playbook cannot compress `quiet_secs` at all** (0 occurrences in the YAML). Through
  `!setPlaybook`, E4 reports `within_quiet_period` no matter what you pass — which looks
  identical to the abandoned path being broken.
- **`"0"` is truthy.** Both scripts gate on `if quiet_secs:` / `if row_ceiling:`
  (`YaraConsolidateStatus.py:21-26`, `YaraConsolidateApply.py:24-29`) and XSOAR passes
  strings. `quiet_secs="0"` yields a zero-second gate; `row_ceiling="0"` makes
  `source_total > 0` true for everything, so every scan is `row_ceiling_exceeded` →
  `blocked` → task 8 "needs attention". An **empty** string correctly falls through to the
  default.
- **Through the pack, E4 is observationally identical to E1.** After `:938` there is no
  `return` and no state change; control falls through to the same quiet check and the same
  `plan_consolidation`. The *only* difference anywhere in the system is the log line at
  `:939-947`, and `YaraConsolidateApply.py:75` filters the log to lines containing `"lock"`.
  **E4 must be run through the CLI or it is not evidence.**

**The `settled` backstop is the trap that invalidates a careless E4.**
`settled = ep_age_ms >= skew_backstop_secs * 1000` with
`DEFAULT_SKEW_BACKSTOP_SECS = 7*24*3600` (`:91`, evaluated at `:925`) satisfies **both**
gates — `:938` skips `host_not_terminal`, `:949` skips `within_quiet_period`. It measures
the **endpoint stamp alone** (`:923-924`), deliberately un-re-armable, so nothing you do
tenant-side resets it. The `_202608` shards currently hold Round-1..4 scan_ids stamped
around **2026-08-11**; as of 2026-08-20 those are **already settled**, and any "control" run
against one of them consolidates instantly with no gate evaluated at all. E4 must use a
scan_id created in this round, and must read the log *text*: the ABANDONED line says either
"newest row is %.1fh old" (the cutoff fired — what E4 claims) or "the endpoint has written
nothing for %.1f days (server-stamp backstop)" (the backstop fired — E4 proved nothing).

**The hazard E4 creates, which is the reason it is a rider and not a standing
configuration.** Matches shards have **no heartbeat** — their newest row is the last match
found — and scans shards heartbeat only every `SCANS_HEARTBEAT_SECS = 600`
(`xdr_yara_scanner.py:397`, emitted `:5493`), so a live scan's scans shard looks stale for
up to ~420 of every 600 seconds. With a 360s cutoff, a **running** scan crosses both
thresholds and gets consolidated and its shard deleted underneath it. That is precisely
what `tests/test_consolidation_defaults.py:89-100` exists to prevent at the default.
**Passing `--scan-id` is not optional here — it is the only barrier between a compressed
cutoff and live data loss** (`only_scan_ids` filters the scan set at `:658-659`).

---

### E5 — Mixed: one host finished, one still running

Start Windows first, confirm its `initiated` row (`xdr_yara_scanner.py:7091`) has landed,
then start Linux, then run the playbook.

```bash
# Windows: long, stretched by the CPU governor rather than by guessing file counts
python3 - <<'PY'
import sys, base64; sys.path.insert(0, "$WT/xdr")
from xdr_action_center import XDRActionCenter
c = XDRActionCenter()
rules = base64.b64encode(open("$WT/test_rules.yar","rb").read()).decode()
code = c.build_scanner_snippet("$WT/xdr/xdr_yara_scanner.py", rules, scan_folder="default",
        options="cpu_guarantee=budget,cpu_budget_pct=5,cpu_floor_pct=5")
print(c.run_snippet(code, [c.endpoint_id("xdragent2")], timeout_secs=7200))
PY

# Linux: short
python3 $WT/.claude/skills/xdr-yara-scan-test/scripts/run_scan.py \
  --hostname xdr-agent --scanner $WT/xdr/xdr_yara_scanner.py \
  --rules $WT/test_rules.yar --seed-files 0 --options cpu_guarantee=none --timeout 900
```

**Why `cpu_budget_pct` and not `cpu_headroom_pct`:** the agent pins payloads to 2 cores
(`xdr/docs/topics/CPU_Impact_Control.md:112-128`), so on an 8-core box the scanner is
already capped near 25% and a headroom target is unreachable from there — the governor does
nothing. A *fixed* 5% budget sits below that ceiling, so the proportional-sleep loop
genuinely engages and gives a multiplier on scan time instead of a guess.

**The binding timing constraint is the playbook's fixed `quiet_secs=900`.** The Linux scan's
newest row must be ≥900s old before it can consolidate, so **the Windows scan must still be
running roughly 17–20 minutes after the Linux scan's last row lands.** Set
`poll_interval_minutes=5` so the first GenericPolling recheck lands just past the window
rather than at the default 30 (`playbook:167`). `within_quiet_period` and
`host_not_terminal` are both classified *deferred*, not blocked
(`check_consolidation_status:809`), so they populate `pending_scan_ids` and route through
the waiting branch rather than failing the run.

Measured throughput for sizing: `xdr-agent` full default walk = **93,127 files / 108.5s** at
defaults, **65.8s** with `cpu_guarantee=none` (`ROUND1_RESULTS.md:21-22`); `xdragent2`
`C:\Program Files` = **1,721 files / 19.1s** (`:31`). **Windows whole-drive file counts on
this image are unverified** — measure the first run and adjust rather than assuming.

**Assertions — all at `scan_id` granularity, never at shard granularity.** The Windows
`_202608` shard already holds older completed scan_ids, and those are settled (see E4), so
an unscoped pass would legitimately strip their rows and drop the shard's total. That is the
code behaving correctly and the assertion failing:

1. Every `(_insert_time, rule, filename, file_sha256)` present at T0 for `<WIN_SID>` is
   present at T1 with the **same `_insert_time`**. A removed-and-reinserted row cannot carry
   its old server stamp.
2. Row count for `<WIN_SID>` is monotonically non-decreasing. "Byte-identical" is the wrong
   invariant and is unachievable — a live scan appends. The provable invariant is
   *append-only by the endpoint*: consolidation's only writes to a source are
   `remove_lookup_data` (`:717`, `:736`, `:753`) and `delete_dataset` (`:768`); the sole
   `add_lookup_data` goes to `target` (`:744`).
3. Both Windows shard datasets still appear in `get_datasets`.
4. `yara_scanner_matches_v3_scan_<slug(WIN_SID)>` is **absent**, while
   `…_scan_<slug(LINUX_SID)>` is **present**. This positive/negative pair is the cleanest
   single piece of E5 evidence.
5. `Yara.ConsolidateStatus.eligible_scan_ids == [LINUX_SID]`;
   `pending_scan_ids` contains `WIN_SID`; `Yara.ConsolidateApply.consolidated_scan_ids ==
   [LINUX_SID]`, `failed_count == 0`.

**Leave `abandoned_after_hours` at its default for E5.** It is the exact inverse of E4: a
compressed cutoff fires on the live Windows shard in the gap between heartbeats and destroys
the property E5 asserts.

**One free canary, and it is the most dangerous unverified assumption in the round.** The
playbook's own description admits it (`playbook:20-27`: the `isExists` conditions "have not
yet been exercised against a live run. Verify both on first use"). Task 2 branches `ready`
on `isExists Yara.ConsolidateStatus.eligible_scan_ids` (`:121`), task 6 feeds Apply from
that same list (`:262-266`), and task 7 branches on `isExists
Yara.ConsolidateApply.failed_scan_ids` (`:295`). If `isExists` is **truthy on an empty
list**, task 2 always routes `ready`, task 6 receives an empty `scan_id`, and
`argToList("") or None` gives `only_scan_ids = None` (`YaraConsolidateApply.py:19`) — a
**tenant-wide** sweep, write, row-strip and shard delete, reported as a clean success. The
tell is free: **if task 8 fires with an empty `failed_scan_ids`, `isExists` is truthy on
empty and task 6 has been running unscoped.** Check that on the very first playbook run,
before anything else. Related and also unverified: if XSOAR renders a blank input as the
literal `${inputs.row_ceiling}` rather than an empty string, `int(...)` raises and the whole
run goes red before task 8 — inspect the first run's rendered task arguments.

---

### E6 — Sibling scans in one shard

E5's two-host shape cannot produce the shard-survival property, because each host's shard
holds one of the round's scans. E6 is the shape the property actually needs: **two scans on
one host, in one month, sharing one shard** (`_dataset_shard_suffix` +
`_rot = self.scan_date[:6]`, `xdr_yara_scanner.py:4056-4066`).

Run scan A on `xdr-agent` to completion, start scan B on `xdr-agent` and leave it running,
then consolidate A alone:

```bash
python3 $WT/xdr/xdr_data_management.py --consolidate --scan-id <SID_A> --quiet-secs 60 --yes
```

Expected: A's rows stripped from the shard by `_cleanup_verified_scan_rows` (`:480-503`),
B's rows intact, the shard **kept**, and the log line
`kept shard yara_scanner_matches_v3_xdr_agent_cd7e9b_202608 — 1 of 2 scan(s) still pending
consolidation` (`:765-767`). That line is CLI-only (see E4), which is why E6 is specified as
a CLI case.

**Note the matches/scans asymmetry before adjudicating a re-run.**
`_cleanup_verified_scan_rows` is called only for `kind == "matches"` (`:752-753`); the scans
shard keeps its rows. A second Apply on an already-consolidated scan therefore reports
`consolidated_count=1` — the scans kind re-verifying via PATH A — while the matches kind
contributes nothing. Reading that as "it consolidated again" is wrong.

---

### E7 — Concurrent mutation of a shard a live agent is writing to

This is the one genuinely uncovered **safety** property, it is reachable by ordinary
operation, and it is in neither the five cases nor the 26 criteria.

D2.4 pins "consolidation is a single sequential writer **to its target**". Nothing pins
"consolidation is a concurrent *mutator of a source* that an endpoint is writing to" — yet
that is exactly what E6 does: `remove_lookup_data(shard, [{"scan_id": A}])` against the same
dataset scan B's `LookupUploader` is calling `add_lookup_data` on. The design doc asserts
`remove_data` is "**not concurrency-safe** — the caller must serialise, which the
consolidation lock already provides" (`Dataset_Management_Design.md:224`). **That is false
for this case:** the lock serialises consolidation passes against *each other*, never
against an agent. And same-dataset concurrent mutation is the precise failure the whole
sharding design exists to prevent — measured at **87% row loss** with 8 endpoints writing one
dataset, with no error raised to any writer (`Dataset_Management_Design.md:46`).

E7 is E6 with the Apply deliberately timed into B's flush activity. Assertions:

- Every row B wrote before the pass is present after it, with its original `_insert_time`.
- B's `scan_summary_<run_id>.json` shows no `records_skipped` spike and no
  `delivery_shortfall` attributable to the pass window.
- B's own count is monotonic. **B's count rising during the pass is expected** — compare row
  identity, not totals.

If E7 shows loss, it is a design finding, not a test failure, and it changes the guidance in
`Dataset_Management_Design.md:224`.

---

### E8 — Lock behaviour and pass duration

`YaraConsolidateApply.yml:67` sets `timeout: 900`. Whether an unscoped pass fits inside that
on this tenant is **unverified and currently unknown**, and the cost model says it is close:
`consolidate_all` runs four passes (`for ver in ("2","3"): for kind in ("matches","scans")`,
`:849-851`); the settle sleep is up to 30s *per scan* (`:746`); an XQL can take up to 180s
(`poll_secs=3 × max_polls=60`, `YaraConsolidateCommon.py:1429-1431`); deletes are ~60s each
at 12-wide. If the container is killed at 900s, `consolidate_all`'s
`finally: release_consolidation_lock` never runs, the marker persists for
`DEFAULT_LOCK_STALE_SECS = 2h` (`xdr_consolidate.py:101`), and every Apply in that window
reports "Skipped this pass — consolidation lock is held by another concurrent run"
(`YaraConsolidateApply.py:52-53`) — worded as benign concurrency and indistinguishable from
a stuck lock.

E8 is therefore two observations, both cheap:

1. Time one **dry, unscoped** `check_consolidation_status` (via `--consolidate` without
   `--yes`) end to end. Record the wall time against the 900s ceiling.
2. Contend the lock: start a scoped `--consolidate --yes`, and while it runs invoke
   `!YaraConsolidateApply scan_id="<other sid>"`. Expect `lock_held_by_other_run` and zero
   deletions. **A dry run never takes the lock** (`:841`), so the *first* pass must be a
   write pass or there is nothing to contend with.

Do not cite `yara_scanner_consolidation_runs.status = success` as evidence of anything. A
lock-held pass returns `failed_count = 0` (`:842-845`) and is therefore recorded as
`"success"` (`YaraConsolidateApply.py:52-54`), and `_RUNS_SCHEMA` has no
`lock_held_by_other_run` and no `deferred_count` field. "Merged everything", "nothing was
eligible", "scan_id typo" and "another run held the lock" are all `success` in that table.

---

### E9 — Gate B by injection (D1.3)

D1.3 says terminality is established two independent ways. It cannot be exercised through
any shipped path, for two reasons, and E9 exists to demonstrate the gate works *at all*
while making that unreachability the actual finding:

- No production caller supplies `action_state_for` (grep result above).
- `CoreApiClient` (`YaraConsolidateCommon.py:1424-1541`) exposes `xql`, `get_datasets`,
  `create_lookup_dataset`, `add_lookup_data`, `remove_lookup_data`, `delete_dataset` — no
  action-status method at all — and the pack's RBAC key is **Data Management + Query Center
  only** (`Packs/YaraDatasetManagement/README.md:226-232`), which deliberately lacks the
  Action Center scope such a call would need.

```python
import sys; sys.path.insert(0, "$WT/xdr")
import xdr_consolidate as C
from xdr_action_center import XDRActionCenter
c = XDRActionCenter()
state = {"xdragent2_2fd370": "ABORTED"}     # or c.action_status(<group_action_id>)
C.consolidate_all(c, only_scan_ids=["<WIN_SID>"], quiet_secs=60,
                  action_state_for=lambda h: state.get(h))
```

Note the wiring gotcha for anyone who later implements it properly: `action_state_for(host)`
is called with the **shard host token** — slug + 6-hex SHA1, e.g. `xdragent2_2fd370` — not
the hostname (`build_terminal_map:373` reading `parse_shard(...)["host"]`). Any real
implementation must map token → hostname → endpoint_id → group_action_id.

Expected contrast, and it *is* the evidence: with injection the scan is `is_terminal=True`
and no ABANDONED line appears; without it, the same scan_id reaches the same outcome only
once `abandoned_after_hours` is compressed, with the ABANDONED line. **Round 5's verdict on
D1.3 should be `fail` or `not_covered` on the shipped paths, not `pass` on the strength of
E9.** Round 4 recorded D1.3 as caught by mutation; mutating dead code proves the test fires,
not that the criterion holds.

---

## Cases that cannot be produced live, and why

### A genuinely `failed` lifecycle row. Do not schedule it.

The terminal row is written by `_emit_scan_row(_term_status, ...)` at
`xdr_yara_scanner.py:7070`, inside `_perform_enhanced_cleanup`, reached from `scan_system`'s
`finally`. `_emit_scan_row` has exactly three call sites — `:5493` (heartbeat), `:7070`
(terminal), `:7091` (`initiated`) — and **none is in `run()`'s exception handlers**. That
alone kills half the surface:

- **`:7784` (KeyboardInterrupt)** and **`:7993` (fatal in `run()`)** both execute *after*
  `scan_system`'s `finally` has already emitted the row with `scan_failed == False`.
  Setting `scanner.scan_failed = True` there arrives too late to change anything. `:7993` is
  additionally guarded by `if scanner is not None`, and every failure that can escape
  `scan_system` before the scanner exists writes **zero** rows.
- That leaves `:6170` (worker fatal) and `:7251` (critical error in scan execution) — the
  two `_mark_scan_failed` callers (`:5335-5338`). Both sit behind two absorbing layers.
  `scan_file` has its own catch-all returning `(False, reason)`, the worker's inner
  `except Exception` continues, and the per-target body has its own
  `except Exception → log_error → continue`. The only mechanical chain that reaches `:6170`
  requires breaking `sys.stderr` in the snippet prelude so that the error handler's own
  `stderr.write` raises — which tests a deliberately broken interpreter, not the product,
  and is not even deterministic.

**Failing YARA rules do not set it.** Compile failures are handled gracefully (logged to
`failed_rules/`, scan continues) and the run reports `completed`. Anyone expecting bad rules
to yield a `failed` row will silently record a second happy path.

**And verifying it from the summary JSON would be a guaranteed false pass.**
`run()` lines `7845-7877` — `get_current_stats_for_upload()`, `get_upload_statistics()`, the
stats dict, `upload_final_comprehensive_report()` — are **unguarded**, unlike the blocks at
`:7832`, `:7879`, `:7885` and `:7924`. A raise there lands at `:7993`, sets
`scan_failed = True`, and the `finally` derives `outcome="failed"` — but the dataset row was
already written `completed` at `:7070`. The operator sees `"Scan failed: …"` and
`scan_summary_<run_id>.json` says `failed`, while the `yara_scanner_scans` row the playbook
reads says `completed`. **That split-brain is a defect worth filing on its own**, and it is
the mirror image of this case: the one reliable way to get `failed` into the summary is the
one way to guarantee it never reaches the row.

**What to do instead.** The consumer half is already pinned offline —
`tests/test_partial_scans_are_preserved.py` covers `status="failed"` in *both* copies at
`shard_is_terminal`, case-insensitively, and end-to-end through `build_terminal_map`. The
uncovered half is the **producer**: `grep -rn "scan_failed" tests/` returns nothing for the
scanner. Cover it with a unit test (construct a scanner, call `_mark_scan_failed`, run
`_perform_enhanced_cleanup`, assert the row at `:7070` carries `status="failed"`), and pin
`xsiam/xsiam_yara_scanner.py` the same way. **D3.2 is a unit-test criterion, not a live
one, and Round 5 should say so rather than leaving it looking untested.**

If a live killed-payload terminal state is wanted, `run_snippet(..., timeout_secs=120)`
against a seeded folder large enough to outlast it produces a `TIMEOUT`/`EXPIRED` action.
Label it **Gate B / action-timeout**, not `failed`: a timeout kills the payload the same way
console Cancel does, so the lifecycle row stays at `running`.

### Console Cancel itself

Only `/api/webapp/*` can abort an action. E3 requires a human. There is no automation path
and there should not be one.

### The cross-host AND inside `_gate_scan`

`scan_id` is per-process (see E1), so a live pass never calls `_gate_scan` with more than one
source. `test_orchestration_defers_when_a_host_is_running`
(`tests/test_consolidation.py:328-337`) is the coverage; a live run cannot add to it.

### A shared `scan_id` across two hosts

Not constructible. And it would be vacuous: with both hosts under one scan_id and one still
running, the whole scan defers, nothing is written or deleted, and both shards end
identical — which tests the cross-host gate, not the "only the finished host's shard was
touched" property E5 is named for.

### Month rollover splitting a scan

Does not happen, and is worth stating so nobody spends an hour on it. The dataset name is
computed once in `LookupUploader.__init__` from `config.run_id` (`:4043-4066`), so a scan
crossing midnight on 31 August keeps writing `_202608`. The residual risk is
retention-only — retention protecting a still-live `_202608` shard on 1 September — and is
untestable before that date.

---

## Pre-flight

| # | Check | How | Why it matters |
|---|---|---|---|
| 1 | The three exports of the preamble are set | `echo $XDR_ENV_FILE $XDR_CA_BUNDLE $YARA_LOOKUP_SCHEMA_VER` | missing creds path reads as an auth failure; schema `2` misclassifies every live dataset |
| 2 | Both endpoints resolve and are `CONNECTED` | `check.py --hostname xdr-agent` / `xdragent2` | endpoint ids are **not** pinned in this document on purpose — resolve them, do not paste them |
| 3 | Baseline inventory captured | `xdr_data_management.py --report > baseline.txt` | the only before-picture of dataset count |
| 4 | No stale consolidation lock | `xql 'dataset = yara_scanner_consolidation_lock'` | a leftover row parks every **write** pass for up to 2h while Status keeps looking healthy |
| 5 | Per-shard scan census, **with endpoint ages** | `comp count() as n, max(event_timestamp_ms) as ep by scan_id` per named dataset | anything >7 days old is `settled` and consolidates unconditionally — see E4 |
| 6 | Pack credentials are real | `YaraConsolidateCommon.py:1419-1421` ships `replace_with_*`; `CoreApiClient.__init__` raises on them | confirm the *uploaded* copy was edited, not the repo copy |
| 7 | `python3 tools/gen_tracking.py --edition xdr --check` baseline recorded **before** the round starts | today: `file matches`, 10 findings, **2 pre-existing DRIFT** (round 2 claims 49 pass / 57 blocked, generated rows 0), **exit 1** | exit 1 is the current baseline, not a Round 5 regression — record it so any *new* finding afterwards is attributable |

**Rule 0, applying to every invocation in this round: always pass `scan_id` / `--scan-id`.**
Omitted, `only_scan_ids=None` sweeps the whole tenant (`:658-659` skipped), and Apply then
deletes every fully-verified source shard. It is the single barrier against the unscoped
sweep in E5's `isExists` canary, against E4's compressed cutoff reaching a live scan, and
against E5's shard-level assertion failing for an unrelated reason.

**Re-take the per-shard census before *and after* every case, not once per round.**
`_cleanup_verified_scan_rows` strips rows from live shards, so one case's Apply visibly
changes the next case's baseline — and once earlier cases have stripped a shard's other
scan_ids, a later case's shard becomes single-scan and *is* deleted, correctly but contrary
to "shards will be kept".

## Cleanup

`xdr/simulation/cleanup.py` does **not** apply — it matches `SIM_PREFIX = "yara_sim_"` only
(`simlib.py:17`), which is exactly the point: it can never touch a real scanner dataset, and
equally can never clean up a Round 5 artifact.

| Artifact | Removal |
|---|---|
| per-scan targets `yara_scanner_{matches,scans}_v3_scan_<slug>` | `xdr_action_center.py prune-datasets --name <ds> --yes` — `--name` bypasses the keep-guard but still enforces `YARA_OWNED_RE` (`:44`) |
| `yara_scanner_consolidation_lock` | `prune-datasets --name` **refuses it** (`YARA_OWNED_RE` matches only `yara_scanner_(matches\|scans)…`). Use `xdr_consolidate.release_consolidation_lock(client)` (`:167-174`) or `client.delete_dataset(..., force=True)` |
| `yara_scanner_consolidation_runs` | Same direct route — but **prefer keeping it**; it is the only cross-run audit trail |
| source shards, if a case deleted one | Not recoverable. There is no undelete on this tenant |
| seeded files on the endpoints (`$TMPDIR/yara_scan_test`) | `xdr_action_center.py list-dir`, then remove via a snippet |

---

## Where the evidence must be recorded

**`ROUND5_CRITERIA.md` — this file — is invisible to `tools/gen_tracking.py`.** The
generator globs `ROUND_DOC_RE = ^ROUND(\d+)_RESULTS\.md$` (`tools/gen_tracking.py:151`), so
only `ROUND5_RESULTS.md` is read. The E-numbered cases above are a test design; they are not
tracker input.

Two rules, both verified against the parser:

**1. Do not title a table of E- or D-numbered rows `## All criteria`.** The parser anchors on
a heading whose stripped text is exactly that string (`:152`, matched at `:531`), and every
pipe row beneath it must match `ID_ROW_RE = ^\|\s*` + backtick + `([A-Z]+-\d{3})` + backtick
+ `\s*\|` (`:127`) with exactly 5 cells `ID | Capability | Pri | Status | Evidence`
(`:566-573`). A row led by `E1` or `D1.1` raises
`FATAL: … row under '## All criteria' does not start with an \`ID\` cell` and the tool exits
**2** — a hard CI break, not a warning. Any *other* heading is fine and the round doc parses
cleanly: because `TEST_PLAN.md` defines no round 5 (`^# Round` matches 1, 2 and 3 only), a
round-5 doc with no `## All criteria` section produces a benign `[NOTE] … documents a round
TEST_PLAN.md does not define`, exactly as `ROUND4_RESULTS.md` already does. `PREFIX_ORDER =
("RULE","TRAV","PERF","STOR","DELI","LIFE")` (`:113`) also makes any new ID prefix a
`GeneratorBug` in `sort_key` (`:787-793`), so E-ids can never enter the tracker under any
heading.

**2. If Round 5 decides a plan capability, file *that* in a proper `## All criteria`
table.** Three plan IDs are directly in scope and should be adjudicated rather than left
carried-forward:

- `LIFE-024` — Scan-lifecycle rows in the `yara_scanner_scans` dataset (`TEST_PLAN.md:1287`)
- `LIFE-025` — Terminal lifecycle row emitted after workers drain but before uploaders stop
  (`:1298`)
- `LIFE-026` — Heartbeat lifecycle row and its independent thread (`:1309`)

Their rows need backticked ids, 5 cells, a status from
`("not_run","pass","fail","blocked","not_covered")` (`:105`), and the table must be the
**last** thing in the file — any non-blank, non-pipe line after it raises (`:539-546`). Each
id may be decided once across all round docs (`:578-582`). Expect a
`[DRIFT] … verdict is filed in round 5 … but the plan puts the criterion in round 3` until
`TEST_PLAN.md` is updated to match; that finding is the adjudication becoming visible, not a
failure.

A `| Status | … |` summary table at the top of `ROUND5_RESULTS.md` is read as a *claim*
(`read_round_claim`) and cross-checked against generated rows — but only for rounds the plan
defines, so a round-5 summary table is inert. Harmless; just do not expect it to prove
anything.

Finish with `python3 tools/gen_tracking.py --edition xdr --check` (0 = tracker matches,
1 = stale, 2 = unparseable) and then `--edition xdr` to write. `TEST_TRACKING.md` is
generated and must never be hand-edited.

### Per-case evidence, and which entry point may claim it

| Case | Records | Entry point that may claim it |
|---|---|---|
| E1 | D2.1, D2.2, D2.3, D2.6, D1.1, D1.5, D5.1, D6.1 | playbook or CLI (scoped) |
| E2 | scanner cancel path; **not** a consolidation criterion | any |
| E3 | the orphaned-`running` input for E4/E9; D3.3 baseline | console + XQL |
| E4 | D1.4 (abandoned cutoff) | **CLI only** — the log line is the evidence |
| E5 | D1.2, and the playbook's deferred/GenericPolling routing | playbook |
| E6 | the `kept shard … N of M` path; D2.2's non-destructive half | **CLI only** |
| E7 | new: concurrent mutation of a source shard | CLI + endpoint summary JSON |
| E8 | D4.1, D4.2, and the 900s automation-timeout question | CLI + pack |
| E9 | D1.3 — as a **demonstration of unreachability**, not a pass | out-of-band import |

Three adjudication rules, each of which exists because the failure mode is
indistinguishable from success:

- **Never adjudicate a `count_mismatch` on a single pass** (E1's settle race). Re-run Apply
  once first.
- **Never adjudicate the `failed` lifecycle status from `scan_summary_*.json`** — the
  split-brain above makes it a guaranteed false pass.
- **Never adjudicate the abandoned path through the pack** — the ABANDONED line is the only
  observable difference and both pack scripts discard it.

And one shape to recognise: after a matches consolidation verifies and its rows are stripped
from the shard, the scan_id disappears from `all_groups` entirely, so the next Status pass
reports `eligible_count=0, pending=[], blocked=[]` — **byte-identical to a mistyped scan_id,
a scan that never ran, and a wrong-month shard.** The disambiguator is `get_datasets`:
if `yara_scanner_matches_v3_scan_<slug>` exists, it is done; if it does not and everything
reads zero, it is a setup error.

---

## Unverified in this document, and flagged as such

- **Endpoint ids** for `xdr-agent` / `xdragent2` were not re-resolved while writing this;
  resolve them with `check.py` rather than pasting values from an earlier session.
- **Live dataset existence** — the four `_202608` names above are *derived* from
  `_dataset_shard_suffix` and reproduced arithmetically here; that they currently exist on
  the tenant was reported by an earlier pass, not re-queried for this document.
- **Windows whole-drive file count and scan duration** on `xdragent2` are unmeasured. Only
  `C:\Program Files` (1,721 files / 19.1s) and System32 throughput are on record.
- **`isExists` semantics on an empty list** in this XSOAR version — the playbook's own
  description says so (`:20-27`). E5's task-8 canary settles it.
- **Whether an unscoped pass fits in the 900s automation timeout** on this tenant. That is
  E8's first observation.
- **`gcloud` auth** in the working session was expired at the time of analysis, so any leg
  needing on-host log timing (E2's window, E7's writer-side confirmation) needs an
  interactive re-auth first. The XDR public API path is unaffected.
