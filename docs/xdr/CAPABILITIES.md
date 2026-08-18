# XDR Scanner — Capability Reference

`xdr_yara_scanner.py` **v3.3.0** · Cortex XDR edition (public-API delivery: Insert Parsed
Alerts + XQL lookup datasets). The XSIAM edition has its own:
[`docs/xsiam/CAPABILITIES.md`](../xsiam/CAPABILITIES.md).

## What this file is

A reference for what the scanner can do today, and the shape new capabilities get recorded
in. It exists for two jobs:

1. **Onboarding and support** — what exists, what controls it, what a flag actually changes.
2. **Test design** — every scan trial's success criteria are drawn from the *Observe* field
   below. A capability nobody can observe on a live scan cannot be a test criterion, which
   is why unobservable ones are marked rather than quietly listed as working.

Update it in the same commit that changes behaviour.

## How to read an entry

| Field | Meaning |
|---|---|
| **What** | What the capability does, and why it exists |
| **Control** | The constant, option key or env var that governs it, and its default |
| **Observe** | How to confirm it ran, on a live scan |
| **Source** | The function/class/constant implementing it |

Two markers flag work, not documentation:

- **⚠ CONTROL GAP** — no customer-reachable way to change it. See *How this edition is
  controlled* below: XDR has three control channels, so "not configurable" here means it
  is reachable through none of them.
- **⚠ OBSERVABILITY GAP** — the capability works but leaves no evidence trail.

## How this edition is controlled

This is the biggest practical difference from the XSIAM edition, and it is worth reading
before the entries: **XDR has a per-run override channel that XSIAM does not have at all.**

| Channel | Reaches | Changed by |
|---|---|---|
| Action Center `options` string | the ten keys in `_VALID_OPTION_KEYS` (line 771) | per run, no edit |
| Environment variables | `YARA_*` reads at module scope | per endpoint |
| Top-of-file `CONFIG_*` constants | everything else | edit before upload |

The ten per-run keys are `create_alerts`, `write_dataset`, `collect_files`,
`cpu_guarantee`, `cpu_headroom_pct`, `cpu_budget_pct`, `cpu_floor_pct`, `workers`,
`tenant_id`, `lookup_shard`. An `options` value overrides the matching constant, so fleet
defaults live in the file and one-off runs need no edit.

Four constants deliberately have **no** `options` equivalent and are rejected as unknown
keys if passed: `CONFIG_LOOKUP_ROTATION`, `CONFIG_ALERT_MAX_PER_SCAN`,
`CONFIG_HOST_CLEANUP`, `CONFIG_HOST_CLEANUP_KEEP` (rationale at lines 150-158). All four
are deployment-wide by nature — rotation decides dataset naming, the alert cap protects a
ceiling shared across concurrent scans, and host cleanup deletes files on the endpoint.
This is a deliberate design choice, not a gap.

Four further keys are **retired but still accepted** and translated rather than rejected,
so existing scheduled jobs keep running: `throttle_mode`, `cpu_high_threshold`,
`cpu_critical_threshold`, `max_pause_secs` (line 780). The old behaviour is deliberately
not preserved — it was measured to cost up to 65.9x scan time while protecting the host by
-3% to +1% versus not throttling at all.

## At a glance

| | Count |
|---|---|
| Capabilities catalogued | **456** |
| &nbsp;&nbsp;Rule Handling | 72 |
| &nbsp;&nbsp;Scan Targeting, Traversal & Skipping | 65 |
| &nbsp;&nbsp;Performance & Resource Management | 86 |
| &nbsp;&nbsp;Local Storage & Host Footprint | 70 |
| &nbsp;&nbsp;Delivery, Aggregation & Telemetry | 82 |
| &nbsp;&nbsp;Scan Lifecycle, Control & Error Handling | 81 |
| ⚠ Observability gaps | 24 |

**24 open observability gaps**, after triage — down from the 40 originally recorded (33 entries still carry an inline ⚠ marker).

The closed ones were never really broken. `setup_logging()` used to
remove every root handler and pin `WARNING`, so all 44 `logging.info(...)` calls in this
file reached nothing on any host — which is what made these capabilities untestable. Root
now carries an INFO `FileHandler` writing to `logs/diagnostics_<run_id>.log`, while stdout
stays clean (Action Center truncates stdout at 10,240 chars, which is why the original
suppression existed).

Re-deriving each *Observe* field against the new sink is outstanding work. Until that pass
runs, read a marked entry as "evidence exists in diagnostics_<run_id>.log, wording not yet
updated" rather than "unobservable".

> **Do not compare this total against the XSIAM file's.** That document lists 297
> capabilities and this one lists 456, but the two were enumerated with
> different granularity prompts — the difference is mostly how finely behaviour was split
> into entries, not how much each edition does. XDR is genuinely larger (7,785 lines vs
> 6,681, plus a lookup-dataset delivery subsystem XSIAM has no equivalent of), but nothing
> like the ratio these two numbers imply. Compare capabilities by name, never by count.

---

# Rule Handling

*From “operator supplies rules” to “compiled ruleset ready to match”.*

### Base64 YARA rule input decoding (yarafile parameter)

The only supported way to ship rules to the endpoint is a base64 blob passed as the `yarafile` argument; it is decoded once during ScanConfig.__init__ into `config.yara_rule`. There is no file-path or URL input mode anywhere in the script — the decoded text lives only in process memory and on disk only inside the failed_rules dumps (failed_rule_*.yar, skipped_rule_*.yar, raw_yara_content.yar).

- **Control:** Not configurable (call argument `yarafile` on run(), line 7095, and main(), line 7730; also positional argv[1] at line 7751) — default `-`
- **Observe:** logs/yara_processing_<run_id>.log contains 'Using YARA rules from provided parameter' (line 2798, written through ErrorLogger's own INFO FileHandler at 1513-1527, which survives setup_logging's WARNING pin). Corroborated by `rule_source`:"provided parameter" in the init_data payload logged to logs/system_<run_id>.log (line 7303) and `yarafile_provided` at line 7578.
- **Source:** `decode_yara_rules() lines 416-459; ScanConfig call sites lines 2796-2807; run() line 7095; main() line 7730`

### Base64 tolerance: b64: prefix, URL-safe alphabet, whitespace, auto-padding

Before decoding, the input is stripped of a leading `b64:` marker (case-insensitive), has all newlines/CRs/spaces removed, `-`/`_` translated to `+`/`/` (URL-safe base64), and is right-padded with `=` to a multiple of 4. TABS are not stripped, while base64.b64decode (validate=False) silently discards them — so padding computed from the tab-inclusive length can be wrong and a structurally intact blob fails with 'Base64 decode failed'. Input-dependent (only when the tab count leaves the real payload mis-aligned mod 4), so intermittent rather than deterministic.

- **Control:** Not configurable — default `-`
- **Observe:** On failure, logs/yara_processing_<run_id>.log gets 'DECODE_ERROR: Base64 decode failed: ...' (line 446) plus 'CRITICAL: Failed to decode YARA rules: ...' (line 2806), and the run aborts inside ScanConfig before any scanner object exists — no yara_scanner_scans_v3_<shard> 'initiated' row and no scan_summary_<run_id>.json.
- **Source:** `_b64_to_text() lines 399-413; called from decode_yara_rules line 441`

### Rule input size cap (50 MB of base64)

Any `yarafile` argument longer than 50,000,000 characters is rejected before decoding. This is a length check on the ENCODED string, so the effective decoded rule-pack ceiling is roughly 37 MB. It fires before the empty check, so an oversized input skips the INPUT_ERROR path — but it does NOT escape logging: the exception is caught by ScanConfig's own handler, which logs it.

- **Control:** Not configurable (bare literal `50_000_000`, line 430) — default `50000000 encoded chars`
- **Observe:** logs/yara_processing_<run_id>.log line 'CRITICAL: Failed to decode YARA rules: YARA rules input too large' (line 2806). The ValueError propagates out of ScanConfig, so no scan_summary_<run_id>.json and no yara_scanner_scans_v3_<shard> row are written for that run.
- **Source:** `decode_yara_rules() lines 430-431; ScanConfig except-branch lines 2805-2807`

### Empty / whitespace-only rule input rejection

A whitespace-only `yarafile` sets ErrorLogger.has_errors and raises before any decode is attempted. Reachability: a truly EMPTY string ('') is falsy at line 2797, so it takes the YARA_RULE fallback branch and dies with a different message — this branch is reachable only for input that is non-empty but blank after strip (e.g. ' '). The `not encoded_b64` half of the test is therefore dead from these call sites.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log line 'INPUT_ERROR: Empty YARA rules content provided' (line 437), followed by 'CRITICAL: Failed to decode YARA rules: Empty YARA rules content provided' (line 2806).
- **Source:** `decode_yara_rules() lines 433-438; ScanConfig branch line 2797`

### Decoded-content validation: must contain a 'rule' declaration

After decoding, the text must match `(?m)^\s*rule\s+\w+` at least once (case-insensitive) or the whole run aborts. This is the only structural validation applied to the submitted pack. Because `rule` must be the first token on the line, a pack containing ONLY `private rule` or `global rule` declarations fails this gate outright.

- **Control:** Not configurable (regex literal, line 449) — default `-`
- **Observe:** logs/yara_processing_<run_id>.log line "VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations" (line 456), plus the 'CRITICAL: Failed to decode YARA rules: ...' echo at line 2806.
- **Source:** `decode_yara_rules() lines 449-457`

### Rule text encoding fallback (UTF-8 then Latin-1 then replace)

Decoded rule bytes are turned into text by trying UTF-8, then Latin-1, then UTF-8 with errors='replace'. Latin-1 cannot raise UnicodeDecodeError on any byte sequence, so the 'replace' arm is unreachable for bytes input — the practical consequence is that a UTF-16 or otherwise non-UTF-8 rule file decodes into mojibake rather than erroring, then fails the 'rule' declaration check with a misleading message.

- **Control:** Not configurable — default `-`
- **Observe:** Same VALIDATION_ERROR line in logs/yara_processing_<run_id>.log (456). There is no positive discriminator: a genuinely rule-less pack aborts at the same line with the same text, and neither case writes failed_rules/raw_yara_content.yar (that dump only happens after a successful decode, inside _compile_yara_rules at 5629-5635).
- **Source:** `_ensure_text() lines 387-396; called from _b64_to_text line 411`

### Embedded YARA_RULE fallback (empty by default = hard abort)

If no `yarafile` argument is supplied (or it is the empty string), the scanner falls back to the module-level YARA_RULE constant, which ships EMPTY. The run then raises 'Default YARA_RULE is empty - must provide yarafile parameter' before decode is attempted. The constant exists so an operator can bake a fixed rule pack into their copy of the script and run it with no arguments.

- **Control:** YARA_RULE, line 336 (module-level raw string literal, edit-in-place, not env-reachable) — default `r"""""" (empty)`
- **Observe:** logs/yara_processing_<run_id>.log line 'Using YARA rules from default configuration' (line 2801) immediately followed by 'CRITICAL: Failed to decode YARA rules: Default YARA_RULE is empty - must provide yarafile parameter' (line 2806).
- **Source:** `ScanConfig lines 2800-2807; YARA_RULE definition line 336`

### rule_hash — SHA-256 of the decoded rule text

A SHA-256 is taken over the full decoded rule text and stored as config.rule_hash; its first 12 hex chars are embedded in scan_id (`<hostname>_<run_id>_yara_<hash12>`). config.rule_hash is assigned at line 2815 and read NOWHERE else in the file, so the only surviving use of the digest is the 12-char prefix inside scan_id — a full-hash comparison across hosts is impossible from the delivered data.

- **Control:** Not configurable — default `-`
- **Observe:** The `scan_id` field on every yara_scanner_matches_v3_<shard> row (line 3663) and yara_scanner_scans_v3_<shard> row (line 5222), the top-level `scan_id` key in logs/scan_summary_<run_id>.json (injected at line 2319), and logs/yara_processing_<run_id>.log line 'Scan ID: ... (rule hash: <12 chars>...)' (line 2817).
- **Source:** `ScanConfig lines 2809-2817`

### yara_processing_<run_id>.log — the rule-handling audit trail

ErrorLogger creates its OWN named logger (`error_logger_<id(self)>`) with its own INFO-level FileHandler and propagate=False, which is why rule-compilation detail survives even though setup_logging strips root handlers and pins WARNING. Its header records the Python version, the platform.platform() string, and yara.__version__ — that is the yara-python BINDING version, not libyara's YARA_VERSION, so it does not by itself identify the libyara build (only _yara_version_tag, used for the cache key and the cache sidecar, captures both).

- **Control:** Not configurable (path derived from config.logs_dir + run_id, lines 1493-1495) — default `<scanner_dir>/logs/yara_processing_<run_id>.log`
- **Observe:** The file itself; its first five lines are '=== YARA Processing Log ===', 'Python Version: ...', 'Platform: ...', 'YARA Version: ...', then a '=' rule (lines 1529-1533).
- **Source:** `ErrorLogger.__init__ lines 1491-1500; _setup_error_logger lines 1502-1539`

### ErrorLogger.close() — Windows file-handle release before cleanup

Closes and detaches the yara_processing FileHandler so end-of-run host cleanup can delete the file. It runs on every platform with no OS check; the reason it exists is Windows-specific — Windows refuses to delete an open file (WinError 32) while POSIX allows it, so the leak was invisible on Linux/macOS until host cleanup was added. Idempotent. Called from run()'s finally block, NOT from HostCleanup, and only when the run's outcome is "completed".

- **Control:** Not configurable — default `-`
- **Observe:** With CONFIG_HOST_CLEANUP != 'off' and outcome=="completed", <scanner_dir>/logs/yara_processing_<run_id>.log is actually gone after the run on Windows (removed by the logs_dir run_id sweep at lines 4956-4961, matching via _extract_run_id_from_log_name at 4580-4583); without the close it would remain and a 'host cleanup could not remove ...' line would appear via logging.warning (line 4985, log=logging.warning passed at 7704).
- **Source:** `ErrorLogger.close() lines 1541-1555; call site line 7698 (guarded by _outcome == "completed" at 7694); HostCleanup.run() lines 4914-4986`

### YARA module availability probe (per-agent libyara capability detection)

Before splitting, the scanner compiles a throwaway `import "<mod>" rule test { condition: true }` for each candidate module to learn what this agent's libyara actually supports. That is 8+ real yara.compile calls per probe pass — the cost is why the result is threaded through the rest of compilation rather than re-derived. Linux agents on yara 3.11.0 typically lack `dotnet`; `cuckoo` and `magic` are absent on most agent builds.

- **Control:** Not configurable (candidate list is a bare literal, line 5344) — default `['pe','elf','cuckoo','magic','hash','math','dotnet','time']`
- **Observe:** logs/yara_processing_<run_id>.log line 'Available YARA modules: <comma list>' (written at line 5609 through ErrorLogger, so it survives the WARNING pin; the duplicate at 5608 is logging.info and is dropped). On a cache HIT this line is NOT written — _load_or_compile_rules runs the probe at 5567 but never logs the result, so the module list is unavailable for cache-hit runs.
- **Source:** `_get_available_yara_modules() lines 5333-5363; probe compile line 5358; logging lines 5608-5609`

### Probe candidate set extended from the submitted rules' own imports

Any module name the submitted pack imports that is not in the hardcoded 8 is appended to the probe list and tested too. Without this, a module outside the hardcoded list was assumed unavailable no matter what libyara really supported, so _split_yara_rules stripped a perfectly good preamble import and every rule using it then died with 'undefined identifier'. The extractor regex `(?m)^\s*import\s+"?(\w+)"?` accepts quoted OR bare module names (`import "pe"` and `import pe`) but NOT single quotes.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log 'Available YARA modules:' line (5609) contains a module beyond the 8 defaults (e.g. `console`, `string`) when the pack imports one and libyara has it.
- **Source:** `_get_available_yara_modules() lines 5345-5348; _extract_imported_modules() lines 5430-5436 (regex line 5433)`

### Duplicate module probe on a fresh compile (wasted work)

**⚠ OBSERVABILITY GAP**  
_load_or_compile_rules calls _get_available_yara_modules to build the cache key, and then _compile_yara_rules calls it AGAIN for the compile itself. On any cache miss the 8+ probe compiles run twice per scan. Harmless but measurable on slow agents; disabling the cache removes the first call, so the duplication exists only when caching is ON.

- **Control:** RULE_CACHE_ENABLED, line 297 (env YARA_RULE_CACHE) — the first call sits inside its `if` at line 5565 — default `RULE_CACHE_ENABLED=True`
- **Observe:** UNOBSERVABLE: no artefact distinguishes one probe pass from two. Needed instead: time _load_or_compile_rules with YARA_RULE_CACHE=0 versus enabled-but-cold, or profile the process; `compile_seconds` in logs/scan_summary_<run_id>.json (line 7652) spans both passes and cannot separate them. To close it: Add one INFO line inside _get_available_yara_modules immediately before `return available` (line 5459): logging.info(f"YARA module probe: {len(test_modules)} candidates compiled, {len(available)} available"). Two of these lines in logs/diagnostics_<run_id>.log for one run proves the duplicate pass; one line means a cache HIT. (The real fix is to pass the modules computed at 5662 into _compile_yara_rules and drop the second probe — the log line is what makes either state visible.)
- **Source:** `_load_or_compile_rules line 5567 (inside the RULE_CACHE_ENABLED guard at 5565); _compile_yara_rules line 5607`

### Cuckoo-module absence warning

A special-cased warning fires when `cuckoo` is not among the available modules, because community packs import it heavily and its absence silently skips large numbers of rules. It is the only module singled out this way — `dotnet`, `magic` and `time` get no equivalent notice. It fires on every fresh compile, but never on a cache HIT (which returns from _load_or_compile_rules at 5587, before _compile_yara_rules is entered).

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log WARNING line 'YARA cuckoo module not available' (line 5613); also on stderr / the Action Center action output via the root lastResort handler from the logging.warning at line 5612 ('YARA cuckoo module not available - rules using it will be skipped').
- **Source:** `_compile_yara_rules lines 5611-5613`

### Preamble extraction and de-duplication (import/include hoisting)

Every line in the whole file whose stripped form starts with `import ` or `include ` is hoisted into a shared preamble, de-duplicated by that stripped text, and later prepended to EACH individual rule before that rule is compiled. The scan is over all lines, not just the file header, so an `import` line sitting inside a rule body or inside a block comment is hoisted too (and is not removed from the body). The preamble is joined with newlines and stripped at line 5869.

- **Control:** Not configurable — default `-`
- **Observe:** OBSERVABLE: logs/diagnostics_<run_id>.log carries `Found {N} unique import statements` (line 5915) — the count after de-duplication and after unavailable-module filtering. Cross-check the resolved preamble text itself in <scanner_dir>/failed_rules/failed_rule_<name>.yar, which writes it above the rule body (5837-5838). Residual gap: which imports were dropped as unavailable is only `Skipping unavailable module in preamble: {module}` at logging.debug (line 5907), below the INFO handler, so the drop list is still invisible.
- **Source:** `_split_yara_rules() lines 5798-5820; preamble returned line 5869; reattachment to each rule line 5689`

### Unavailable preamble imports are stripped from the shared preamble

A double-quoted `import "<mod>"` whose module is not available on this agent is dropped from the preamble instead of being passed to the compiler. This is what makes the rest of the pack compile on a module-poor agent — and it is also the direct cause of the 'inherited import' skip case, since the rule bodies still reference the module. The whole filter is gated on `available_modules is not None` (line 5804); the sole caller always passes it, so it is always active in practice. A dropped line is also not added to imports_seen, so duplicates are re-evaluated (harmless).

- **Control:** Not configurable — default `-`
- **Observe:** <scanner_dir>/failed_rules/skipped_rule_<rulename>_<module>.yar files appear, each carrying the header lines '// SKIPPED RULE - Module <mod> not available on this agent' and '// (import inherited from the file-level preamble)' (written at lines 5717-5718).
- **Source:** `_split_yara_rules() lines 5804-5812; caller passes available_modules at line 5618`

### `include` directives hoisted verbatim and never filtered

Lines starting with `include ` are collected into the preamble unconditionally — the availability filter at line 5805 only inspects `import "..."` matches, and an include line has no such match so it falls through to the append branch at 5813-5815. yara-python's compile(source=...) resolves `include` relative to the process CWD, so an include in a submitted pack will typically fail with 'could not open include file' on EVERY rule, turning the whole pack into compile failures.

- **Control:** Not configurable — default `-`
- **Observe:** Every rule lands in <scanner_dir>/failed_rules/failed_rule_*.yar with an '// Error: ...' header naming the include problem (line 5739); with valid_sources empty the run then aborts at line 5775 with 'FINAL_COMPILATION_ERROR: No valid YARA rules could be compiled out of N rules.' (5769-5771) and the stderr pair at 5772-5773.
- **Source:** `_split_yara_rules() lines 5802, 5813-5815`

### Rule boundary splitting into individually-compiled units

The pack is cut into individual rule blocks by scanning for lines matching `^\s*rule\s+\w+`; each block runs from its own declaration line up to the next declaration line (or EOF). Braces are never counted — the split is purely line-positional, which is why a `rule` keyword appearing at line-start inside a multi-line comment or a `meta:` string will start a bogus block and corrupt both it and its predecessor.

- **Control:** Not configurable (regex literal, line 5824) — default `-`
- **Observe:** logs/scan_summary_<run_id>.json `valid_rules` + `failed_rules` + `skipped_rules` (lines 7641-7643) should equal the true rule count; a mismatch (or a failed_rules/failed_rule_<garbage>.yar with a truncated body) proves a mis-split. failed_extractions is only counted, never persisted (5852-5853 is a logging.warning), so the counts are the only signal.
- **Source:** `_split_yara_rules() rule_starts scan lines 5822-5829; block extraction loop lines 5835-5857`

### `private rule` / `global rule` are not recognised as rule starts

The boundary regex at line 5824 requires `rule` as the first non-whitespace token, so `private rule Helper` and `global rule X` never register as split points. Consequence: a private helper that FOLLOWS a public rule is silently absorbed into that rule's block (and does compile, counted as one rule), but a private helper placed BEFORE the first plain `rule` — the idiomatic layout — is discarded entirely along with everything above the first declaration, and every rule referencing it then fails with 'undefined identifier'.

- **Control:** Not configurable — default `-`
- **Observe:** <scanner_dir>/failed_rules/failed_rule_<name>.yar whose '// Error:' line reads 'undefined identifier "<helper name>"', with no skipped_rule_* file for it (the reclassifier at 5408-5428 requires the undefined name to be in source_imported_modules, which a rule identifier never is) and no failed_rule file for the helper itself.
- **Source:** `_split_yara_rules() line 5824; block extraction lines 5835-5846`

### Everything before the first rule declaration is discarded (except imports)

**⚠ OBSERVABILITY GAP**  
Only hoisted import/include lines survive from the region above the first `rule` line. File-level comments, `private`/`global` rules, and any other preamble construct are dropped without a warning or a dump file — the text simply never enters any rule block, because each block starts at its own rule_starts index.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE: nothing records the discarded region. Needed instead: compare `total_rules_found` in the logs/system_<run_id>.log line 'YARA Rules loaded: N rules, M imports' (line 7339 — a naive UNANCHORED `rule\s+\w+` count at 7330, so it DOES count `private rule` and inline occurrences) against `valid_rules`+`failed_rules`+`skipped_rules` in logs/scan_summary_<run_id>.json (7641-7643) — a gap is the discarded material. To close it: In _split_yara_rules, right after the rule_starts loop (insert at line 5924, next to the existing `Found {N} rule start positions` info), emit: `if rule_starts:` compute `dropped = [l for l in lines[:rule_starts[0][0]] if l.strip() and not l.strip().startswith(('import ','include ','//'))]` and, when non-empty, `logging.info(f"Discarded {len(dropped)} non-import line(s) before the first rule declaration")`. That one line in logs/diagnostics_<run_id>.log turns the discard from an inferred count-gap into a direct measurement.
- **Source:** `_split_yara_rules() lines 5835-5846; raw count lines 7330-7339`

### Per-block re-validation before compile (_clean_rule_content)

**⚠ OBSERVABILITY GAP**  
Each extracted block is joined, stripped, and re-checked against `^\s*rule\s+\w+` before being accepted. Because the block was cut at exactly such a line and only leading whitespace was stripped, this check can never fail — the rejection branch and its 'doesn't start with rule keyword' warning are effectively unreachable dead code. The only live behaviour is the join+strip normalisation and the `if not rule_lines: return None` guard.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE (unreachable): the only signal would be the logging.warning at line 5297 plus the failed_extractions counter at 5852, neither of which can fire. Needed instead: nothing — this path has no live behaviour to test beyond the normalisation, which is implicit in every accepted rule body.
- **Source:** `_clean_rule_content() lines 5289-5299; caller line 5843`

### _is_valid_rule_structure — DEAD CODE

**⚠ OBSERVABILITY GAP**  
A full structural validator (checks for a `rule` line and a `condition:` line, with exception handling) that is defined and never called from anywhere in the file — confirmed by grep: the symbol appears only at its definition. Rules therefore go straight from the line-split to yara.compile with no structural pre-check, which is why malformed blocks surface as compile failures rather than as a clean 'missing condition' diagnosis.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE (dead): produces no artefact under any input; its internal logging is logging.debug (lines 5305, 5320, 5324, 5330), below even the WARNING pin. Needed instead: static confirmation — grep the file for the symbol.
- **Source:** `_is_valid_rule_structure() lines 5301-5331 (no call sites)`

### Per-rule namespace assignment (ns_<index>_<rulename>)

Every rule that compiles is stored in `valid_sources` under its own namespace key `ns_<i>_<display_name>` (i is the 1-based enumerate index), and the final ruleset is built from that dict. This is what makes duplicate rule names across a pack survive (unique i puts them in different namespaces instead of colliding), and it is also why a rule that references ANOTHER rule by identifier can never compile — the probe compile at 5690 hands yara only the shared preamble plus that one rule body.

- **Control:** Not configurable — default `-`
- **Observe:** Duplicate names: two distinct rows with the same `rule` value appear in yara_scanner_matches_v3_<shard> for the same file. Cross-rule references: failed_rules/failed_rule_<name>.yar with '// Error: ... undefined identifier "<other rule name>"'.
- **Source:** `valid_sources population line 5692; probe compile line 5690; combined compile line 5778`

### Every rule is compiled twice on a fresh compile

Each rule is first compiled alone (preamble + injected imports + rule body) purely to decide valid/failed/skipped — the resulting Rules object is discarded (line 5690 is a bare call with no assignment) — and every surviving source is then compiled AGAIN as part of one combined multi-namespace ruleset. This doubles the compile cost and is the main reason a ~500-rule pack takes roughly 90 seconds, which is in turn why the rule cache exists. Skipped rules are compiled zero times (they `continue` at 5676 / 5724, before line 5690).

- **Control:** Not configurable — default `-`
- **Observe:** logs/scan_summary_<run_id>.json fields `compile_source`:"fresh" (line 7651) and `compile_seconds` (line 7652, the full doubled cost); logs/system_<run_id>.log line 'Rule compile FRESH <n>s' (line 5599).
- **Source:** `probe compile line 5690 (discarded return value); combined compile line 5778; timing lines 5597-5599`

### Compile-time external variables (filepath, filename)

Every rule-facing yara.compile call declares the externals `filepath` and `filename` as empty strings: the module probes (5358), the per-rule probe compile (5690), and the combined compile (5778). Without the declaration, community rules whose conditions reference `filename` fail to compile at all; the empty values are placeholders replaced per file at match time. The cache-hit validation at line 5574 passes an equivalent HARDCODED literal dict instead of the constant — so adding a third external to YARA_COMPILE_EXTERNALS would not automatically be validated on a cache hit.

- **Control:** Not configurable (module-level dict YARA_COMPILE_EXTERNALS, lines 916-923) — default `{"filepath": "", "filename": ""}`
- **Observe:** A rule with `condition: filename matches /x/` is counted in logs/scan_summary_<run_id>.json `valid_rules` rather than appearing as failed_rules/failed_rule_*.yar with 'undefined identifier "filename"'.
- **Source:** `YARA_COMPILE_EXTERNALS lines 916-923; used at lines 5358, 5472 (cache key), 5690, 5778; hardcoded twin at line 5574`

### Per-file external population at match time

For each scanned file that passes the type/size gates, rules.match is called with `externals={"filepath": <full path>, "filename": <basename>}`, overriding the compile-time empties. Before this, filepath was always "", so filepath-keyed rules compiled but could never match. There is NO `timeout=` argument on the match call — a pathological rule/file pair can block a worker thread indefinitely.

- **Control:** Not configurable — default `-`
- **Observe:** A filename-keyed rule producing a row in yara_scanner_matches_v3_<shard> and an <scanner_dir>/alert/<rule>.txt entry for a file it could only have matched via the external.
- **Source:** `scan_file() match call lines 6153-6157 (gated by the not-a-regular-file check at 6139-6140 and the size check at 6142-6144)`

### Automatic injection of missing module imports per rule (MODULE_USAGE_PATTERNS)

Before compiling a rule alone, the scanner regex-scans it for module usage (e.g. `pe.`) using MODULE_USAGE_PATTERNS — an OrderedDict of 8 module→regex pairs — and prepends `import "<mod>"` for any module that is used, available on the agent, and not already imported by the rule or the preamble. This rescues rules that assumed a file-level import the split legitimately dropped, or that the author omitted. The regexes are naive `\b<mod>\.` patterns, so a literal string containing `pe.` triggers a harmless spurious import. A module NOT in the table (e.g. `console`) is never auto-imported even when libyara has it. The table's comment at 925-929 still claims it is shared with the skip-vs-fail decision, but line 5443 is now its ONLY consumer — the skip path was rewritten to classify from the real compile error.

- **Control:** Not configurable (MODULE_USAGE_PATTERNS, lines 930-939) — default `8 patterns: math, elf, pe, hash, time, dotnet, magic, cuckoo`
- **Observe:** logs/yara_processing_<run_id>.log INFO line "Auto-injected missing imports for rule '<name>': <modules>" (line 5687, through ErrorLogger, so it survives). Negative check for the table's coverage limit: a rule using `console.log` on a console-capable agent still lands in failed_rules/ with 'undefined identifier "console"'.
- **Source:** `_inject_missing_rule_imports() lines 5438-5455; MODULE_USAGE_PATTERNS lines 930-939 (sole consumer line 5443); call site lines 5679-5687`

### Skip classification case 1 — explicit inline import of an unavailable module

A rule whose own body contains an import line for a module missing on this agent is SKIPPED before compilation, not compiled and counted as failed. This keeps a module-poor agent (e.g. a Linux endpoint on yara 3.11.0 with no dotnet) from reporting a healthy pack as broken. The matcher is `^\s*import\s+"?(\w+)"?` applied per stripped line, so quotes are OPTIONAL here — `import dotnet` is caught as well as `import "dotnet"` (unlike the preamble filter at 5805, which requires double quotes).

- **Control:** Not configurable — default `-`
- **Observe:** <scanner_dir>/failed_rules/skipped_rule_<rulename>_<module>.yar whose first header line is '// SKIPPED RULE - Module <mod> not available' (line 5670) with NO '(import inherited...)' second line; count reflected in logs/scan_summary_<run_id>.json `skipped_rules` (7643) on a fresh compile.
- **Source:** `_rule_uses_unavailable_modules() lines 5365-5406, inline-import check lines 5382-5390; skip handling lines 5653-5677`

### Skip classification case 2 — REMOVED usage-regex heuristic (documented dead path)

The old case-2 test — matching a `<mod>.` usage regex against a rule body to decide it needed a stripped preamble import — was deleted and replaced by an in-code explanation of why. The heuristic could not distinguish a real module reference from the same characters inside a string literal, comment or meta value, and its source_imported_modules guard was computed over the WHOLE pack, so one `import "cuckoo"` anywhere opened the gate for every rule; a rule hunting the literal string "cuckoo.conf" was silently dropped. The function now always returns (False, None) after the inline-import check — and the `source_imported_modules` parameter is still accepted at line 5365 while being entirely unused inside the body.

- **Control:** Not configurable — default `-`
- **Observe:** A rule containing the literal string "cuckoo.conf" on a cuckoo-less agent now appears in logs/scan_summary_<run_id>.json `valid_rules` and produces matches, instead of a failed_rules/skipped_rule_<name>_cuckoo.yar file.
- **Source:** `_rule_uses_unavailable_modules() lines 5392-5405 (comment block) and line 5406 (unconditional `return False, None`)`

### Post-hoc module-missing reclassification from the compile error

When a rule fails to compile, the exception text is scanned for `undefined identifier "<name>"`; if that name was imported somewhere in the ORIGINAL source AND is genuinely unavailable on this agent, the rule is reclassified from FAILED to SKIPPED. All three conditions are required, which is what makes it safe for literal strings, and it needs no per-module table so it works for modules a future libyara adds. It short-circuits to None when source_imported_modules is empty (line 5422), so a pack with no imports at all can never be reclassified.

- **Control:** Not configurable — default `-`
- **Observe:** <scanner_dir>/failed_rules/skipped_rule_<name>_<module>.yar whose header contains the second line '// (import inherited from the file-level preamble)' (line 5718) — that line is what distinguishes this path from case 1, which writes only the single header line at 5670.
- **Source:** `_module_missing_from_compile_error() lines 5408-5428; except-branch call lines 5701-5703; skip handling lines 5704-5724`

### Skipped-rule source dumps

Every skipped rule's full body is written to failed_rules/skipped_rule_<rulename>_<module>.yar with a comment header naming the missing module and an ISO timestamp. Filenames carry NO run_id, so a re-run with different rules leaves the previous run's dumps in place and the directory mixes runs. The rule name and module name are used unsanitised in the filename. Both skip paths write, each wrapped in a bare try/except that swallows any write error.

- **Control:** Not configurable (path from config.failed_rules_dir, line 2742) — default `<scanner_dir>/failed_rules/`
- **Observe:** The .yar files themselves; cross-check their mtimes against the run's start time (the run_id prefix is a YYYYMMDD_HHMMSS timestamp) to tell this run's dumps from stale ones.
- **Source:** `case 1 lines 5664-5675; inherited-import case lines 5711-5723; failed_rules_dir creation lines 2742-2745`

### Failed-rule source dumps (with resolved preamble)

Each rule that genuinely fails to compile is written to failed_rules/failed_rule_<rulename>.yar with the error message, an ISO timestamp, AND the resolved shared preamble prepended above the body (only when the preamble is non-empty) — the only on-disk record of what the hoisted preamble resolved to. The body written is the ORIGINAL rule_content (line 5744), not the auto-import-injected version, so an injected `import` line does not appear in the dump and the file is not byte-identical to what yara was handed.

- **Control:** Not configurable (path from config.failed_rules_dir, line 2742) — default `<scanner_dir>/failed_rules/`
- **Observe:** The .yar files; `yara <file>` on a dev box reproduces the failure verbatim only when no imports were auto-injected for that rule.
- **Source:** `lines 5732-5746 (preamble write lines 5742-5743, body line 5744)`

### raw_yara_content.yar dump when the split yields zero rules

If splitting produces no rule blocks at all, the ENTIRE decoded rule text is written to failed_rules/raw_yara_content.yar with an explanatory header before the run aborts with ValueError. This is the escape hatch for diagnosing a pack that passed the decode-time 'contains a rule declaration' check but produced nothing splittable. Because the decode gate at 449 uses the same line-anchored regex as the splitter at 5824, the two mostly agree — the gap is packs whose only `rule\s+\w+` hits are not at line start.

- **Control:** Not configurable — default `<scanner_dir>/failed_rules/raw_yara_content.yar`
- **Observe:** Presence of that exact file, plus logs/yara_processing_<run_id>.log line 'COMPILATION_ERROR: No YARA rules found in provided content' (line 5628). The 'Saved raw YARA content to: ...' notice at line 5635 is logging.error, so it also reaches stderr / the Action Center output.
- **Source:** `lines 5625-5638`

### Compilation-error forensics (_analyze_compilation_error)

Every compile failure is classified into one of four categories — invalid_pe_field, syntax_error, undefined_identifier, duplicate_definition — each with a severity and canned remediation suggestions, plus extraction of the invalid field name or unexpected token, and (when the error text carries 'line N') the offending source line with flags for condition:/strings:/meta:, its length and its indentation. Unmatched errors keep error_category 'unknown'. The result is COMPUTED AND THROWN AWAY: the only consumer is the log call at 1655-1668, guarded by `hasattr(self.config, 'log_manager')`, and nothing in the file ever assigns config.log_manager (grep: no `config.log_manager =` anywhere) — so no artefact ever carries the analysis.

- **Control:** Not configurable — default `error_category='unknown', severity='medium'`
- **Observe:** OBSERVABLE: logs/scan_errors_<run_id>.log now carries `YARA rule compilation failed: {rule_name} \| data={…}` (emitted at 1723-1726, serialised at 2229-2236), where the payload contains error_message, error_type, error_line_number, rule_length_lines, compilation_failure_number and the full error_analysis dict (error_category, severity, suggestions, invalid_field/unexpected_token, problematic_line, line_analysis) built at 1615-1679. Note it lands in scan_errors_<run_id>.log, not diagnostics_<run_id>.log, and the data blob is truncated at 4000 chars. The plain-text fallback (rule body with `<-- ERROR HERE`) remains in yara_processing_<run_id>.log.
- **Source:** `_analyze_compilation_error() lines 1557-1621; sole (unreachable) consumer lines 1653-1668`

### Full failed-rule body echoed into the processing log with an error-line marker

For each compile failure, the whole rule body is written line-by-line into yara_processing_<run_id>.log at ERROR level with 3-digit line numbers, and the line number parsed out of yara's error message is marked with '<-- ERROR HERE'. On a pack where hundreds of rules fail this makes the processing log enormous — there is no cap on this echo, unlike the first-10 caps on the console warnings. The block also increments failed_rules_count (line 1626), which is what the first-10 console throttle at 5729 tests.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log blocks beginning '=== RULE COMPILATION FAILURE #N ===' (line 1628) containing the numbered body and the '<-- ERROR HERE' marker (line 1647).
- **Source:** `log_rule_compilation_error() lines 1623-1670; line echo lines 1644-1649`

### Compilation summary block with success rate

At the end of the per-rule loop, a summary block is written: total processed, valid compiled, failed skipped, a success-rate percentage, and (when anything failed) the failed_rules directory path. The 'Total rules processed' it prints is valid+failed only (line 1674) — SKIPPED rules are excluded, so a pack that was mostly skipped reports a 100% success rate here. It is called at 5749, before the all-skipped abort check at 5756, so it appears even on runs that then fail with zero valid rules.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log 'COMPILATION SUMMARY' block (lines 1675-1689). Cross-check its 'Total rules processed' against logs/scan_summary_<run_id>.json's valid_rules+failed_rules+skipped_rules (7641-7643) to see the exclusion.
- **Source:** `log_compilation_summary() lines 1672-1689; call site line 5749`

### First-10 throttle on skipped-rule warnings

Only the first 10 skipped rules produce a console/processing-log warning; skips 11 onward are counted but silent. The counter is shared across BOTH skip paths (inline import and post-hoc reclassification), so ten inline skips silence the reclassified ones too. The .yar dump file is written for EVERY skipped rule regardless of the cap — so the directory is the complete record and the log is only a sample.

- **Control:** Not configurable (bare literal `10`, lines 5659 and 5706) — default `10`
- **Observe:** Compare the count of <scanner_dir>/failed_rules/skipped_rule_*.yar files against the number of 'SKIP (module unavailable)' lines in logs/yara_processing_<run_id>.log (written at 5662-5663 and 5710) — they diverge past 10. The uncapped total is also in that log as 'Skipped N rules due to unavailable modules' (line 5754) and in logs/scan_summary_<run_id>.json `skipped_rules` (7643).
- **Source:** `lines 5659-5663 and 5706-5710; shared counter skipped_count declared line 5642`

### First-10 throttle on failed-rule console warnings

Only the first 10 compile failures emit a truncated (100-char) logging.warning; the full detail always goes to yara_processing_<run_id>.log and the .yar dump regardless. The cap is on the stderr-visible stream, which is what an Action Center operator sees. The test reads failed_rules_count AFTER log_rule_compilation_error has incremented it (5727 precedes 5729), so failures 1 through 10 inclusive are warned.

- **Control:** Not configurable (bare literal `10`, line 5729) — default `10`
- **Observe:** Action Center action stderr shows at most 10 'Failed rule <name>: ...' lines while <scanner_dir>/failed_rules/failed_rule_*.yar and the '=== RULE COMPILATION FAILURE #N ===' blocks continue past 10.
- **Source:** `lines 5729-5730; counter increment line 1626 reached via line 5727`

### Every-50-rules compile progress

A running tally (compiled i/N, valid, failed, skipped) is emitted every 50 rules through the compile loop. Two limits: it sits INSIDE the success branch after the probe compile and the valid-count bump at 5693, so it only fires when rule number i itself compiled cleanly (a skipped or failed rule at i=50 emits nothing), and it goes to logging.info, so on any real host it goes nowhere.

- **Control:** Not configurable (bare literal `50`, line 5695) — default `50`
- **Observe:** OBSERVABLE: logs/diagnostics_<run_id>.log carries `✓ Compiled {i}/{total} rules ({valid} valid, {failed} failed, {skipped} skipped)` every 50 rules (line 5791), plus the bracketing `Starting compilation of {N} YARA rules...` (5743) and `Compilation complete: {valid} valid, {failed} failed, {skipped} skipped` (5845). Requires a rule pack of at least 50 rules to emit at all.
- **Source:** `lines 5695-5696 (inside the try's success path, after line 5693)`

### Rule-health triage counters (valid / failed / skipped)

Three counters on ErrorLogger carry the entire rule-health story: valid_rules_count (compiled and loaded), failed_rules_count (genuine compile errors), skipped_rules_count (needs a module this agent lacks). The three-way split is the whole point — conflating skipped with failed makes a healthy pack on a module-poor agent look broken. Only valid and failed reach the lookup dataset; skipped exists only locally and on the returned result line. skipped_rules_count is assigned once at line 5748 (after the loop) so a mid-compile crash loses it, and it is also what the cache sidecar persists.

- **Control:** Not configurable — default `0/0/0`
- **Observe:** logs/scan_summary_<run_id>.json fields `valid_rules`, `failed_rules`, `skipped_rules` (lines 7641-7643); the `valid_rules`/`failed_rules` columns on every yara_scanner_scans_v3_<shard> row (lines 5234-5235); the SCAN_RESULT string returned to Action Center ('... N rules failed compilation \| M rules skipped (module unavailable) ...', built at lines 7512-7513 and used at 7533-7536).
- **Source:** `ErrorLogger lines 1498-1500; skipped persisted line 5748; scan row lines 5234-5235; summary lines 7641-7643; result line lines 7512-7536`

### skipped_rules is absent from the scans dataset schema

The yara_scanner_scans schema declares only valid_rules and failed_rules as numbers (lines 3929-3930). Because the lookup dataset's schema is fixed at creation and XDR silently SKIPS rows carrying unknown fields, the skipped count can never be queried from XQL — a fleet-wide 'which endpoints can't run this pack' question must be answered from local scan_summary JSONs or the returned result strings instead. Adding it would require bumping LOOKUP_SCHEMA_VERSION (line 290) to mint a new dataset.

- **Control:** Not configurable (scans_schema literal, lines 3915-3938); LOOKUP_SCHEMA_VERSION, line 290 (env YARA_LOOKUP_SCHEMA_VER) is the lever that would be needed to change it — default `LOOKUP_SCHEMA_VERSION="3"`
- **Observe:** XQL over yara_scanner_scans_v3_<shard> has no skipped column; the same run's logs/scan_summary_<run_id>.json does have `skipped_rules` (7643). That asymmetry is the confirmation.
- **Source:** `scans_schema lines 3915-3938 (valid/failed at 3929-3930); row build lines 5234-5235; summary line 7643`

### All-skipped vs all-failed abort messages are distinguished

When zero rules compile, the error message branches on `skipped_count and not failed_rules_count` (line 5761): if anything was skipped and nothing failed, it says 'No rules could run on this endpoint: all N rule(s) need YARA modules this agent's libyara build does not provide (available: ...)' and explicitly calls it an agent capability limit, not a syntax error. Otherwise it reports a plain compilation failure naming the input rule count. Both abort the scan by raising ValueError; they demand completely different operator responses.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log 'FINAL_COMPILATION_ERROR: ...' (line 5771) plus the same text on stderr as 'CRITICAL: YARA rule compilation failed: ...' (line 5772), followed by 'Valid rules: 0, Failed rules: N, Skipped: M' (line 5773) — that stderr pair is what the Action Center action output shows.
- **Source:** `lines 5756-5775`

### Combined-ruleset compile failure path

Even after every rule individually compiled, the final multi-namespace yara.compile can still fail (e.g. resource limits, or a duplicate identifier surfacing only in aggregate). That failure sets has_errors (5790), is logged as COMBINED_COMPILATION_ERROR (5791), and the original exception is re-raised bare (5792) — the scan aborts with a distinct marker from the per-rule failures, and the cache save at 5601 is never reached, so no .yarac is written for that ruleset.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log line 'COMBINED_COMPILATION_ERROR: <exception>' (line 5791) with a non-zero 'Valid rules compiled' already recorded above it in the COMPILATION SUMMARY block (written at 5749, before this point).
- **Source:** `lines 5777-5792`

### Rule-compilation disk cache

The compiled ruleset is persisted to disk with yara's rules.save() and reloaded with yara.load() on the next run, skipping the entire per-rule compile loop — and with it the module list log, the cuckoo warning, _debug_rule_analysis, and every failed_rules/skipped_rules dump. It exists because the scanner is a fresh process per Action Center action and a ~500-rule pack costs ~90s to compile every time.

- **Control:** RULE_CACHE_ENABLED, line 297 (env YARA_RULE_CACHE; '0'/'false'/'no'/'' disable) — default `enabled ("1")`
- **Observe:** <scanner_dir>/rule_cache/rules_<40-hex>.yarac plus its .meta.json sidecar; logs/scan_summary_<run_id>.json `compile_source`:"cache" with a small `compile_seconds`; logs/system_<run_id>.log line 'Rule cache HIT rules_<key>.yarac load=<n>s (valid=.. failed=.. skipped=..)' (lines 5582-5586).
- **Source:** `_load_or_compile_rules() lines 5559-5602; _rule_cache_dir() lines 5458-5461; RULE_CACHE_ENABLED line 297`

### Rule cache key composition

The SHA-256 cache key hashes five things in order: the format tag, the yara engine identity, YARA_COMPILE_EXTERNALS as sorted JSON, the sorted list of available modules, and the exact rule text. Because compilation is a pure function of exactly these, the key can never drift from what would actually be produced — no replay of the per-rule transform is needed. The filename uses the first 40 hex chars (5569), so two keys colliding in their first 40 chars would collide on disk.

- **Control:** Not configurable in composition; RULE_CACHE_FORMAT, line 298 (env YARA_RULE_CACHE_FORMAT) is the deliberate invalidation lever — default `RULE_CACHE_FORMAT="1"`
- **Observe:** The filename <scanner_dir>/rule_cache/rules_<40 hex>.yarac itself (built at line 5569); changing one byte of the rule pack, or moving to an agent with a different module set, produces a different filename on the next run.
- **Source:** `_rule_cache_key() lines 5463-5476 (five h.update calls, lines 5470-5475); path construction line 5569`

### yara engine identity tag in the cache key (_yara_version_tag)

The key includes a four-part tag: binding yara.__version__, libyara yara.YARA_VERSION, platform.system(), and platform.machine(), each defaulting to '?' if absent. libyara's YARA_VERSION drives the save/load serialization format; the binding version and platform tighten it so a 3.11-Linux bundle and a 4.1-Windows bundle can never collide on one key — critical in a mixed fleet where the same rule pack is pushed everywhere.

- **Control:** Not configurable — default `-`
- **Observe:** Two endpoints with different yara versions running the identical pack produce differently-named rules_*.yarac files; the .meta.json sidecar records the tag under its `yara` key (written at line 5512). This sidecar is the only artefact anywhere that reports libyara's YARA_VERSION — the yara_processing header reports only the binding version (1532).
- **Source:** `_yara_version_tag() lines 564-574; used at line 5471; recorded in the sidecar at line 5512`

### Cache-hit usability validation (load + externals probe)

A cache hit is not trusted on load alone. After yara.load() (5571), the bundle is exercised with `rules.match(data=b"", externals={"filepath":"","filename":""})` (5574) to prove it is usable AND still accepts the per-file externals the scanner overrides at match time. Any failure is caught there and falls back to a fresh compile rather than blowing up mid-scan on the first real file. The probe's externals are a hardcoded literal, not YARA_COMPILE_EXTERNALS, so a newly added external would not be covered.

- **Control:** Not configurable — default `-`
- **Observe:** logs/system_<run_id>.log line 'Rule cache miss/unusable, compiling fresh: <exception>' (line 5589) followed by 'Rule compile FRESH <n>s' (line 5599), with logs/scan_summary_<run_id>.json showing `compile_source`:"fresh" even though a .yarac file existed before the run.
- **Source:** `yara.load() line 5571; externals probe line 5574; except handler lines 5588-5589`

### Corrupt/unusable cache entries are deleted on the failing load

When a cache load or validation raises, both the .yarac and its .meta.json are removed before the fresh compile, so a poisoned entry cannot make every subsequent run pay the load-then-fail cost. OSError on the deletion is swallowed. The deletion is guarded on `cache_path and os.path.exists(cache_path)` (5590), so a failure raised BEFORE cache_path was assigned (e.g. inside the module probe at 5567 or the key build at 5568) deletes nothing.

- **Control:** Not configurable — default `-`
- **Observe:** The offending <scanner_dir>/rule_cache/rules_<key>.yarac is gone after the run and reappears (freshly saved by line 5601) with a new mtime; the 'Rule cache miss/unusable' line in logs/system_<run_id>.log (5589) names the reason.
- **Source:** `lines 5588-5595`

### Cache LRU touch on hit (os.utime)

A successful cache hit calls os.utime on the .yarac to refresh its mtime, because the prune step sorts by mtime and keeps the newest. Without this, a frequently-used ruleset would be evicted in favour of a recently-compiled one-off. OSError is swallowed (read-only filesystems). The sidecar is NOT touched, so prune's mtime ordering considers only the .yarac.

- **Control:** Not configurable — default `-`
- **Observe:** The mtime of <scanner_dir>/rule_cache/rules_<key>.yarac advances to the run time even though its content is unchanged, while its .meta.json sidecar mtime does NOT move — that asymmetry is the confirmation.
- **Source:** `lines 5575-5578; prune ordering line 5545`

### Counts sidecar (.meta.json) restored on a cache hit — and the skipped count lost there

A cache hit skips the per-rule loop entirely, so the valid/failed/skipped counters would all read 0 and the summary would report a ruleless scan. A sidecar JSON written at save time carries valid_rules, failed_rules, skipped, the yara tag and the format tag. On restore, _restore_cache_meta ASSIGNS valid_rules_count (5486) and failed_rules_count (5487) onto the ErrorLogger but only RETURNS the sidecar's `skipped` value (5488) — it never assigns error_logger.skipped_rules_count, whose sole assignment is the fresh-compile path at 5748. The caller consumes that return value for exactly one log line (5579, 5582-5586). Consequence: the SECOND run of the same pack (cache hit) writes "skipped_rules": 0 into scan_summary_<run_id>.json (7643) and drops the '\| N rules skipped (module unavailable)' clause from the Action Center result line (built 7512-7513, used 7534), while the first fresh-compile run of the identical pack reported the true number. The same blind spot exists in the comprehensive report, whose rule_compilation block sums only valid+failed (7002-7007) so compilation_success_rate reads 100% for a largely-skipped pack, and efficiency_score is computed off that same denominator (7027-7035); log_compilation_summary's total is valid+failed only too (1674).

- **Control:** RULE_CACHE_ENABLED, line 297 (env YARA_RULE_CACHE) gates whether the cache-hit path can be taken at all; the loss itself is not configurable — default `RULE_CACHE_ENABLED=True (env default "1")`
- **Observe:** <scanner_dir>/rule_cache/rules_<key>.yarac.meta.json (written 5508-5516, skipped persisted at 5511). Run the same all-`cuckoo` pack twice on one endpoint and compare scan_summary_<run_id>.json between the "compile_source":"fresh" run and the "cache" run: `valid_rules` is non-zero on both, but `skipped_rules` is the true N on the fresh run and 0 on the cache run. The true value survives in exactly one place on the cache run — logs/system_<run_id>.log 'Rule cache HIT rules_<key>.yarac load=..s (valid=.. failed=.. skipped=N)' (5582-5586) — so that line disagreeing with the summary is the confirmation.
- **Source:** `_restore_cache_meta() lines 5478-5497 (sidecar read 5484-5488; valid 5486, failed 5487, skipped only RETURNED at 5488); sidecar write lines 5508-5516 (skipped at 5511); sole consumer of the returned value lines 5579 and 5582-5586; the only assignment to skipped_rules_count is the fresh path at 5748; result-line build 7512-7513 used at 7534; summary field 7643; skipped-blind report block 7002-7007; efficiency_score 7027-7035; log_compilation_summary total 1674`

### Sidecar-missing fallback: recount from the loaded bundle

If the sidecar is absent or corrupt, valid_rules_count is recovered by iterating the loaded yara.Rules object (which yields exactly the compiled rules); if even that fails it falls back to a hardcoded 1. The recount is itself guarded on valid_rules_count being falsy (5492). Failed and skipped counts are lost in this path and read 0 — so a summary showing a plausible valid count with failed=0 AND skipped=0 on a cache hit may be a sidecar loss, not a clean pack.

- **Control:** Not configurable — default `fallback value 1`
- **Observe:** logs/scan_summary_<run_id>.json with `compile_source`:"cache", `failed_rules`:0 while <scanner_dir>/rule_cache/ has a .yarac with no matching .meta.json. `skipped_rules`:0 is NOT diagnostic on its own — it reads 0 on every cache hit because of the return-vs-assign defect in the sidecar-restore entry.
- **Source:** `_restore_cache_meta() except branch lines 5489-5497`

### Atomic cache save under a process-wide lock

The compiled bundle is saved to a randomised temp name (cache_path + pid + 32 random bits + .tmp, line 5504) and then os.replace'd into position (5507), under a module-level threading.Lock, so a partially-written .yarac can never be observed. The lock is per-process only — it does not coordinate two concurrent scanner processes on one host, which is why the temp name is randomised and why prune's temp sweep is age-gated. The sidecar write at 5515-5516 happens AFTER os.replace, so a crash between them leaves a .yarac with no sidecar. The whole save is best-effort; the temp is removed on failure.

- **Control:** Not configurable (_RULE_CACHE_LOCK, line 301) — default `-`
- **Observe:** logs/system_<run_id>.log line 'Rule cache save failed (non-fatal): <error>' (line 5519) when it cannot write; otherwise the .yarac plus .meta.json appear with the run's timestamp and no rules_*.tmp remains.
- **Source:** `_save_rule_cache() lines 5499-5525 (temp name 5504, save 5506, replace 5507, sidecar 5515-5516, prune 5517, cleanup 5520-5525); _RULE_CACHE_LOCK line 301`

### Cache pruning by file count and total bytes (LRU)

After every successful save the cache directory is bounded: .yarac files are sorted newest-first by mtime and everything past either the file-count limit or the cumulative byte limit is deleted along with its sidecar. Both limits are enforced in the same pass (5550), so whichever binds first wins. The whole function is wrapped in a bare except that swallows everything (5556-5557), and it runs INSIDE _save_rule_cache's try (5517) — so a prune exception is reported as a cache-save failure.

- **Control:** RULE_CACHE_MAX_FILES, line 299 (env YARA_RULE_CACHE_MAX); RULE_CACHE_MAX_BYTES, line 300 (env YARA_RULE_CACHE_MAX_MB, multiplied to bytes) — default `5 files / 256 MB`
- **Observe:** Count and total size of <scanner_dir>/rule_cache/rules_*.yarac after running six or more distinct rule packs — the oldest disappear together with their .meta.json.
- **Source:** `_prune_rule_cache() lines 5527-5557 (sort 5543-5545, limits 5550, deletion 5551-5555); constants lines 299-300`

### Orphaned cache temp sweep with a 1-hour age gate

The prune pass also removes rules_*.tmp files left behind by a crash between rules.save(tmp) and os.replace(). The age gate is deliberate: another per-action scanner process may have a save in flight, so only temps older than an hour are swept. Prune runs only inside a successful save, so a host that never saves — cache disabled, read-only disk, or always a cache hit (the normal steady state) — never sweeps.

- **Control:** Not configurable (bare literal `3600`, line 5539) — default `3600 seconds`
- **Observe:** Stale <scanner_dir>/rule_cache/rules_*.tmp files persist for the first hour and are gone after a later run whose save succeeds.
- **Source:** `_prune_rule_cache() lines 5531-5542; 3600 literal line 5539`

### compile_source / compile_seconds telemetry

The scanner records whether the ruleset came from cache or a fresh compile and how long that took, on the scanner object, and surfaces both in the machine-readable summary. This is the only way to attribute a slow scan start to compilation rather than to file discovery. Both are initialised at construction (5005-5006) and reset to "fresh"/0.0 at the top of _load_or_compile_rules (5563), so an exception during compilation leaves them at those defaults.

- **Control:** Not configurable — default `compile_source="fresh", compile_seconds=0.0`
- **Observe:** logs/scan_summary_<run_id>.json fields `compile_source` (line 7651) and `compile_seconds` (line 7652); corroborated by logs/system_<run_id>.log lines 'Rule cache HIT ... load=<n>s' (5582-5586) or 'Rule compile FRESH <n>s' (5599).
- **Source:** `initialised lines 5005-5006; reset line 5563; set lines 5580-5581 (cache) and 5598 (fresh); emitted lines 7651-7652`

### rule_cache survives end-of-run host cleanup

HostCleanup wipes evidence, alert and failed_rules directories plus this run's per-category logs, but does NOT touch <scanner_dir>/rule_cache — its removal list at lines 4967-4970 names only those three, and they are recreated empty at 4978-4982. That is what makes the cache useful across cleaned-up runs, and it also means an operator who believes 'cleanup removes our footprint' is leaving compiled rule bundles (from which rule identities are recoverable via yara.load) behind on every endpoint. The CUSTOMER CONFIG comment at lines 236-237 states this deliberately.

- **Control:** CONFIG_HOST_CLEANUP, line 238; CONFIG_HOST_CLEANUP_KEEP, line 239 — default `CONFIG_HOST_CLEANUP="off", KEEP="summary"`
- **Observe:** After a run with host cleanup enabled and outcome=="completed" (gate at 7694), <scanner_dir>/rule_cache/rules_*.yarac and .meta.json remain on disk while <scanner_dir>/failed_rules and <scanner_dir>/alert exist but are empty.
- **Source:** `HostCleanup.run() lines 4914-4986 (removal list 4967-4970, recreate 4978-4982, rule_cache absent throughout); constants lines 238-239; documented intent lines 236-237`

### failed_rules directory accumulates across runs

CleanupManager.initial_cleanup wipes alert_dir, evidence_dir and the output log at the start of every scan, but failed_rules_dir is NOT in its list (4646-4650) and not in its recreate list either (4666-4668) — despite HostCleanup's own comment at 4963-4966 asserting the scanner 'already wipes them wholesale at the START of the next run'. Since the dump filenames carry no run_id, stale failed_rule_*.yar and skipped_rule_*.yar files from earlier runs sit alongside the current run's and are easily misread as this run's output. raw_yara_content.yar is likewise never cleared and has a fixed name.

- **Control:** Not configurable — default `-`
- **Observe:** Run two scans with different rule packs; <scanner_dir>/failed_rules/ contains dumps from both. Distinguish by file mtime versus the run's start time (derivable from the run_id's YYYYMMDD_HHMMSS prefix) — there is no other discriminator.
- **Source:** `initial_cleanup() paths_to_clean lines 4646-4650 (failed_rules_dir omitted) and recreate list lines 4666-4668 (also omits it); dir creation line 2742; contradicting comment lines 4963-4966`

### Rule counts logged to the system log at initialisation

Immediately before the scanner is constructed, a naive count of `rule\s+\w+` and `import\s+` over the raw decoded text is logged with the total character length. Because these regexes are UNANCHORED re.findall calls (7330-7331), they count `private rule`, `global rule` and inline occurrences that the actual splitter rejects — comparing this number against the post-compile totals is the most direct way to detect rules lost to the splitter. The import count is equally loose (any 'import' followed by whitespace, anywhere).

- **Control:** Not configurable — default `-`
- **Observe:** logs/system_<run_id>.log line 'YARA Rules loaded: N rules, M imports' (line 7339) with a JSON `data=` payload containing total_rules_found, import_statements and rule_content_length (lines 7333-7337; serialised by LogManager._log at 2172-2178).
- **Source:** `lines 7330-7339`

### Per-rule metadata (meta and tags) parsed then discarded

**⚠ OBSERVABILITY GAP**  
_iter_hit_fields extracts a rule's tags list and meta dict from every match, and _write_alerts unpacks them into local variables at line 6370 — which are then never used anywhere in the function (grep: `tags`/`meta` appear nowhere else between 6100 and 6500). Nothing downstream carries rule meta or tags: not the alert_dir text file, not the yara_scanner_matches row (no meta/tags column in matches_schema, 3890-3913), not the XDR alert. A customer whose rules encode severity, author or reference in `meta:` loses all of it. It also contains `dict(getattr(hit, "meta", {}) or [])` — an `or []` where `or {}` was intended, harmless only because dict([]) succeeds.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE by design: no artefact carries meta/tags. Confirm negatively — a rule with `meta: author = "x"` produces a yara_scanner_matches_v3_<shard> row and an <scanner_dir>/alert/<rule>.txt entry with no trace of the author value, and XQL over the matches dataset has no meta or tags column.
- **Source:** `_iter_hit_fields() lines 1280-1296 (the `or []` at line 1296); unused unpack line 6370; matches_schema lines 3890-3913`

### Cached-hit dict ingestion path — REMOVED

`_serialize_matches()` was a complete JSON-serialisation helper for match objects — rule name, tags, meta, hex-encoded matched data — that was defined and never called. Its existence was the only reason `_iter_hit_fields` was dual-mode (dict or live Match), and with no producer of the dict form that consumer branch was unreachable too: dead code feeding a dead branch.

Both were removed. Unreachability was re-enumerated against this edition rather than inherited from the XSIAM finding, because the call sites differ: all four `_iter_hit_fields` callers iterate `matches`; `matches` has one binding, `self.rules.match(...)`; `_write_alerts` takes `matches` as a parameter but has a single caller passing that same local; and nothing outside the file imports the symbol.

The branch was not merely unused, it was unsafe. Its decode fallback was `hx.encode("utf-8", errors="ignore")` on anything `bytes.fromhex` rejected, so a non-hex string produced **wrong bytes silently** instead of raising, and every offset and matched-data field downstream would have been quietly corrupt.

- **Control:** Not configurable — default `-`
- **Observe:** N/A — the code no longer exists. `tests/test_hit_field_extraction.py` pins the surviving single-shape contract across both editions, including that a dict now raises rather than being silently decoded, and that the producer is gone.
- **Source:** removed; contract pinned by `tests/test_hit_field_extraction.py`

### _yara_callback — inert match callback

**⚠ OBSERVABILITY GAP**  
A callback is passed to every rules.match() call, but its body returns yara.CALLBACK_CONTINUE on both branches — the `if data.get("matches")` test changes nothing. It is a no-op hook that costs one Python call per rule evaluation per file. It is the natural insertion point for per-rule instrumentation or early abort, and currently does neither.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE (inert): identical behaviour with or without it. Needed instead: source inspection, or an instrumented build that counts invocations.
- **Source:** `_yara_callback() lines 6237-6241; wired in at line 6156`

### _debug_rule_analysis — rule-file structure analysis and brace-mismatch check

Runs on every fresh compile before the split (called at 5615): counts total lines, enumerates rule declarations with their 1-based line numbers, samples the first five and (only when there are more than 10, line 6482) the last five, counts `import ` lines, and totals opening versus closing braces, warning on a mismatch. A brace mismatch is the single most useful early signal that a pack is truncated — and it is almost entirely invisible in practice. It never runs on a cache hit.

- **Control:** Not configurable — default `-`
- **Observe:** OBSERVABLE: logs/diagnostics_<run_id>.log carries the full block between `=== YARA FILE ANALYSIS ===` (6595) and `=== END ANALYSIS ===` (6629): `Total lines: {N}` (6596), `Found {N} rule declarations` (6605), the first/last five ` Line {n}: rule {name}` samples (6613/6617), `Import statements: {N}` (6621) and `Total braces: {open} opening, {close} closing` (6625). On imbalance, `BRACE MISMATCH DETECTED!` (6628) still also reaches stderr and the Action Center output, and the size of the mismatch is now readable from the counts line immediately above it in the diagnostics log.
- **Source:** `_debug_rule_analysis() lines 6459-6498; warning at line 6496; call site line 5615`

### Rule identity in the delivered alert name

The XDR alert name is built as 'YARA Match: <rule> \| <basename> (#<8-hex path tag>) \| Host: <hostname>' — rule name plus an 8-char SHA-1 of the FULL file path (or the literal 'nopath' when no path is present). Identity is deliberately the (rule, file) finding, not the timestamp and not the string offset: timestamps made every re-scan mint new alerts, offsets made every string hit its own alert (measured as a 22x flood on one multi-string rule), and the path tag stops two per-user copies of the same-named dropper collapsing into one alert.

- **Control:** Not configurable in composition, but gated by CONFIG_CREATE_ALERTS, line 161, and UPLOAD_RESULTS, line 104 — with either off no alert is built — default `CONFIG_CREATE_ALERTS=True, UPLOAD_RESULTS=True`
- **Observe:** The `alert_name` on alerts landing via insert_parsed_alerts; re-running the same scan updates the existing alert rather than creating a duplicate.
- **Source:** `_alert_dict() lines 3292-3322 (path tag 3316, finding name 3322, rollup name 3320)`

### Per-rule storm rollup alert

Findings beyond CONFIG_ALERT_MAX_PER_SCAN are counted per RULE and, at scan end, emitted as one rollup alert per rule named 'YARA Match Storm: <rule> \| Host: <hostname>' saying how many further files that rule hit. Rule-level grouping is what keeps a noisy single rule from silently swallowing every other rule's findings — nothing goes unreported, and the lookup dataset still holds every suppressed finding in full. The per-scan finding cap is enforced against a de-duplicated (rule, filename) set that is itself bounded at 150,000 entries (line 3702), past which repeat findings can re-count.

- **Control:** CONFIG_ALERT_MAX_PER_SCAN, line 191 (<= 0 disables the cap) — default `500`
- **Observe:** Alerts whose alert_name starts 'YARA Match Storm:' (built at line 3320); `rollups` and `suppressed` counters inside the `alert_delivery` object of logs/scan_summary_<run_id>.json (fed from get_upload_stats at line 7655, keys declared at 3193-3194); logs/uploads_<run_id>.log line 'Queued N storm-rollup alert(s) covering M suppressed finding(s)' (lines 3526-3528).
- **Source:** `_queue_rollup_alerts() lines 3489-3528; suppression bookkeeping lines 3697-3710; rollup naming line 3320`

### Rule name as a first-class dataset column

Every finding row carries `rule` as a text column in yara_scanner_matches, alongside a JSON `string_ids` object giving TRUE uncapped per-string-identifier hit counts for that rule against that file. The string_ids census is what lets an analyst see which pattern inside a rule actually fired even when the offsets sample is truncated; `match_count` carries the true offset total and `truncated` (computed at 3660) flags when the sample is short.

- **Control:** CONFIG_LOOKUP_ROWS_PER_FINDING_MAX, line 199 (caps the offsets/strings sample, not string_ids; <= 0 disables the cap). Row delivery itself is gated by CONFIG_WRITE_DATASET, line 162. — default `50; CONFIG_WRITE_DATASET=True`
- **Observe:** XQL over yara_scanner_matches_v3_<shard>: the `rule`, `string_ids`, `match_count` and `truncated` columns on each row. A truncated finding also logs "Rule '...' matched ... at N offsets; embedded a sample of M ..." to logs/uploads_<run_id>.log (lines 3686-3691).
- **Source:** `matches_schema lines 3890-3913; row construction lines 3661-3684; string_ids accumulation line 3645; truncated flag line 3660`

### Per-rule detection tally and top_rules ranking

A per-rule detection counter is incremented under self.lock_counts on every match (6372-6374), giving both the unique-rule count and a ranked top-10. This is the only rule-level aggregate that reaches the summary artefact — useful to spot a single overly-broad rule dominating a scan. The tally counts Match objects (one per rule per file), not string hits, so a rule hitting one file 10,000 times counts once.

- **Control:** Not configurable (top-10 slice is a bare literal at line 7665; the log-side top-10 is a separate literal at line 6630, of which only the first 5 are rendered into the message text at 6633) — default `top 10`
- **Observe:** logs/scan_summary_<run_id>.json fields `unique_rules_triggered` (line 7640) and `top_rules` (line 7665, a list of [rule, count] pairs); also logs/alerts_<run_id>.log line 'Top detection rules: ...' with a `top_10_detections` payload (lines 6632-6638), emitted only when total_detections > 0 (6628).
- **Source:** `counter lines 6372-6374; final log lines 6628-6638; summary lines 7640, 7665`

### Per-rule alert text files in alert_dir

For every match, an <scanner_dir>/alert/<rulename>.txt file is appended under a lock with the matched path, SHA-256, creation time, a deliberately UNCAPPED per-string-ID hit census, and a capped sample of offsets with rendered data. The file name IS the rule name, so this directory is the fastest local answer to 'which rules fired on this host'. The rule name is used unsanitised as a filename, and unlike the dataset and alert channels this write sits outside the `if UPLOAD_RESULTS` guard — it always happens, making it the one match artefact that survives with alerts and datasets both disabled.

- **Control:** CONFIG_ALERT_OFFSETS_PER_FINDING_MAX, line 210 (caps the offset sample only; <= 0 means uncapped) — default `50`
- **Observe:** <scanner_dir>/alert/<rule>.txt files; each contains 'Total string hits: N' (line 6416), 'Hits per string ID: $a=..,$b=..' (lines 6417-6418) and 'Matched Strings (showing X of N):' (lines 6423-6424), plus an 'N further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=..)' notice when truncated (lines 6432-6438).
- **Source:** `_write_alerts() lines 6365-6457; alert-file write lines 6396-6442; cap constant line 210`

### Zero-valid-rules suppresses scheduled cleanup (diagnostic preservation)

In run(), the 'critical errors' condition is precisely has_errors AND valid_rules_count == 0 — a total rule-handling failure — and when it holds cleanup_manager.schedule_final_cleanup() is not called, so the failed_rules dumps and processing log survive for diagnosis. A partial failure (some rules valid) does NOT trigger it. CleanupManager.schedule_final_cleanup re-tests the same condition at 4687 and ORs in a second, unrelated error-log-ratio trigger at 4690-4693 — but BOTH are inert: its only call site (7493) is already guarded by `not has_critical_errors`, so the 4687 test is always False there, and the ratio branch is gated on `hasattr(self.config, 'log_manager')`, which is never true because nothing in the file ever sets config.log_manager. The whole suppression block at 4695-4702 is therefore unreachable.

- **Control:** Not configurable (both the has_errors test and the 0.5 error-ratio threshold are bare literals) — default `error-ratio threshold 0.5 (dead)`
- **Observe:** logs/system_<run_id>.log line 'Cleanup skipped due to critical YARA processing errors' (line 7496) — the run() path is the ONLY observable form. The CleanupManager-path message 'Critical errors detected - skipping cleanup to preserve diagnostic data' (4697-4700) can never be written (its hasattr guard fails), and the accompanying logging.info at 4701 is dropped by the WARNING pin.
- **Source:** `run() lines 7490-7496; CleanupManager.schedule_final_cleanup lines 4681-4702 (rule test 4685-4687, dead error-ratio test 4689-4693, unreachable suppression block 4695-4702); sole call site line 7493`

### yara-python match-API normalisation (libyara 3.x vs 4.x offset shim)

Every matched string from libyara is converted to a uniform (offset, string_id, data) tuple by _normalize_match_strings, which accepts three shapes: the 3-tuple (offset, id, data) that yara 3.11 returns (Linux agents); a 4.x StringMatch object with .identifier + .instances[], fanned out so EACH instance becomes its own (offset, sid, data) row (Windows/macOS agents on 4.1.0); and a final fallback reading .offset/.identifier/.matched_data-or-.data off a single object. This is what makes one rule produce identical alert text and identical offsets/string_ids detail on a 3.11.0 and a 4.1.0 agent. Note the sentinels: a missing offset degrades to -1 and a missing identifier to the literal 'unknown', so those two values in the artefacts are the signature of the fallback branch, not real match data. It runs via _iter_hit_fields, which is called four times per matched file (rules_matched log list 6184, alert write 6370, total_strings sum 6445, rules_triggered list 6452), so the normalisation cost is paid four times per hit file.

- **Control:** Not configurable — default `-`
- **Observe:** On a yara 3.11.0 Linux endpoint, <scanner_dir>/alert/<rule>.txt must show populated `String ID:` / `Offset:` / `Data:` triples (written at 6428-6430) and 'Hits per string ID: ...' (6417-6418), and the matches-dataset row for that (rule, file) must carry a non-empty `offsets` JSON array and a non-empty `string_ids` JSON object (built at 3677-3679) — XQL `dataset = yara_scanner_matches_v3_*`. Compare the same rule against the same file on a 4.1.0 endpoint: the shape must be identical. `Offset: -1` or `String ID: unknown` means the fallback branch (975-979) fired instead of a recognised API shape.
- **Source:** `_normalize_match_strings() lines 959-981 (3-tuple branch 963-966; 4.x StringMatch fan-out 968-973; bare-object fallback 975-979); _iter_hit_fields() (single live-Match shape); four callers 6184, 6370, 6445, 6452; alert-file triples 6428-6430; (off,sid,data)->(sid,off,data) conversion for the dataset at 6387; row fields 3677-3679`

### Rule splitter is comment-blind, string-blind and case-insensitive

Rule boundaries are found by running `re.match(r'^\s*rule\s+\w+', line, re.IGNORECASE)` over raw source lines (5824), with no awareness of /* */ block comments or string literals. Any line whose first non-space token is the word rule in any case starts a NEW rule unit — a commented-out rule wrapped in /* rule old_thing { … } */, or a header-comment line like `Rule Description: detects X`. The preceding real rule is then truncated at that line (losing its closing brace) and the bogus half is kept, because the only re-validation, _clean_rule_content (5289-5299), checks solely that the block still starts with the rule keyword (5296) and never checks brace balance. Both halves normally fail to compile, so a single stray line costs two rules. The case-insensitive match is what lets prose ('Rule Description') qualify.

- **Control:** Not configurable — default `-`
- **Observe:** <scanner_dir>/failed_rules/failed_rule_<name>.yar: the truncated real rule appears with a missing closing brace, and — the giveaway — a second file appears named after a word lifted from the comment prose (e.g. failed_rule_Description.yar, because the display name comes from `re.search(r'rule\s+(\w+)')` at 5650-5651 on the bogus block). Both dumps carry the '// FAILED RULE - Compilation Error' header and the resolved preamble (5732-5746). Corroborate with `failed_rules` in scan_summary_<run_id>.json (7641) exceeding the number of genuinely broken rules. UNOBSERVABLE: the cross-check 'Found N rule start positions' is a bare logging.info at 5829 on the ROOT logger, which setup_logging pins to WARNING (6966), so it is NOT in yara_processing_<run_id>.log.
- **Source:** `_split_yara_rules() lines 5794-5869 — boundary regex 5824, display-name capture 5825-5826, start/end slicing 5837-5842; _clean_rule_content() lines 5289-5299 (sole gate 5296, no brace check); per-rule name resolution at compile 5650-5651; failed-rule dump 5732-5746; unobservable count log 5829; setup_logging root pin 6954-6968 (setLevel at 6966)`

### Duplicate rule names and overlapping scan targets split the books asymmetrically (one alert, two dataset rows)

Each rule is compiled into its own namespace keyed `ns_<index>_<rulename>` (5692), so the index disambiguates and TWO rules sharing a name both compile and both fire on the same file. The two channels then disagree: the alert channel dedups on (rule, filename) via _seen_findings (3699-3703) so only ONE XDR alert is created, but add_match is invoked once per Match (6388) with no dedup, so the matches dataset gets TWO rows for that (rule, file), alert/<rule>.txt gets the same match block appended twice (6396-6442), and detection_counts / total_detections each count it twice (6372-6374) — propagating into the `matches` figure and the top_rules ranking in the summary. The identical asymmetry appears without duplicate rule names when scan_folder entries overlap (e.g. "C:\,C:\Users"): target validation dedups only on exact absolute path (`if ap not in valid`, 3001), never on containment, and no visited-path set exists anywhere, so the same file is enumerated and scanned once per overlapping target.

- **Control:** Not configurable (exact-path-only target dedup at 3001; the (rule, filename) dedup at 3699-3703 has no flag, only a 150,000-entry memory bound at 3702) — default `-`
- **Observe:** XQL `dataset = yara_scanner_matches_v3_*` filtered to one scan_id and counted per (rule, filename): any pair with >1 row while the tenant shows only one alert for it is this case. Locally, alert/<rule>.txt contains the same "YARA rule 'X' matched file: <path>" block twice for one file (6400), and scan_summary_<run_id>.json's `matches` (7639) exceeds the number of distinct (rule, file) findings.
- **Source:** `namespace key 5692; combined compile 5778; _write_alerts per-Match loop 6369 with counter bumps 6372-6374, add_match call 6388 and the un-deduped alert-file append 6396-6442; ResultsUploader.add_match -> lookup_uploader.add 3685 (LookupDatasetUploader.add 4065-4067 -> _enqueue 4073-4096, no dedup); alert-channel dedup _seen_findings 3699-3703 (init 3207-3209); exact-path-only target dedup 2996-3004 (test at 3001); per-target scan loop with no cross-target visited set 6842`

### Per-agent YARA/Python runtime banner in yara_processing_<run_id>.log — and its silent-failure mode

The first five lines ErrorLogger writes are a runtime banner: Python Version, Platform and YARA Version read straight from the live interpreter (1529-1533). This is the durable per-endpoint record of which yara-python binding this agent carries (3.11.0 on Linux agents vs 4.1.0 on Windows/macOS agents) and therefore local evidence for why a rule was skipped here but compiled fine there; the same three values also ride the init_data payload into system_<run_id>.log. The failure mode is the surprising part: if the FileHandler cannot be created (unwritable logs_dir, Windows lock, path too long), _setup_error_logger prints one line to stdout (1536) and returns the BARE ROOT logger (1537), which setup_logging pins to WARNING with no handlers — so the banner never runs and every subsequent error_logger.info (module list, auto-injected imports, compilation summary, skip lines) goes nowhere. yara_processing_<run_id>.log is then ABSENT, not empty, with no in-file trace of the substitution. Note libyara's own YARA_VERSION appears only via _yara_version_tag (564-574) in the cache key and .meta.json sidecar, not in this banner.

- **Control:** Not configurable — default `-`
- **Observe:** logs/yara_processing_<run_id>.log must open with '=== YARA Processing Log ===' followed by 'Python Version:', 'Platform:' and 'YARA Version:' — the YARA Version line is the assertion. Cross-check logs/system_<run_id>.log, whose 'YARA Scanner initialized successfully' entry (7341) carries python_version / yara_version / platform inside its data object (7300-7302), and the comprehensive report's system_info block (7009-7015). The fallback is detected by absence: yara_processing_<run_id>.log missing entirely while system_<run_id>.log exists, plus a bare 'Failed to setup error logger: <e>' line in the Action Center stdout.
- **Source:** `error_log_file path lines 1493-1495; _setup_error_logger lines 1502-1539 — banner writes 1529-1533, stdout print 1536, root-logger fallback `return logging.getLogger()` 1537; setup_logging root pin 6954-6968 (setLevel 6966); init_data platform/python_version/yara_version 7300-7302 emitted via log_manager.log_system 7341; system log path 2116; comprehensive-report system_info 7009-7015; ErrorLogger.close() 1541-1555`

---

# Scan Targeting, Traversal & Skipping

*Deciding what gets opened — and proving what didn’t.*

### Explicit scan scope via the scan_folder parameter (comma-separated multi-target)

scan_folder is the 2nd Action Center input / 2nd CLI positional. It is split on commas, so ONE run can cover several disjoint scopes ("C:\\Users,D:\\Shares"). A path that itself contains a comma cannot be expressed — it is split into two bogus targets (comment at 2993-2994 says to scan the parent instead).

- **Control:** scan_folder parameter (ScanConfig signature line 2683, stored line 2750; main() line 7730; sys.argv[2] line 7752, via _argv() lines 7748-7749). NOT an options-string key — it is absent from _VALID_OPTION_KEYS (lines 771-775) and _parse_options_string raises ValueError on unknown keys (lines 825-828). — default `None → default full-scope discovery`
- **Observe:** scan_summary_<run_id>.json field "scan_folder" (written line 7634); the "scan_folder" column on every lifecycle row (built line 5230) and every match row (built 3638, placed 3675) — note both carry the RAW comma-joined string or the literal "system", not the per-target path; system_<run_id>.log "SCAN SCOPE: Limited to specified targets: [...]" (built 7324, logged 7328); yara_processing_<run_id>.log "Scan limited to N folder(s): [...]" (3036-3037).
- **Source:** `ScanConfig.__init__ lines 2987-3037; run() line 7166; main() line 7733`

### Per-target directory validation with partial-failure tolerance

Each comma-separated entry is independently os.path.isdir-checked. Invalid entries are dropped and named in a warning rather than killing the run, so one typo in a scheduled multi-target scan still scans the other targets. Note the ordering: the all-invalid ValueError at 3005-3007 is raised BEFORE the invalid-entry warning at 3008-3011, so the warning appears only when at least one entry was valid.

- **Control:** Not configurable — default `-`
- **Observe:** yara_processing_<run_id>.log: "Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]" (lines 3009-3011). ErrorLogger owns its own INFO-level FileHandler with propagate=False (lines 1502-1539), so this genuinely lands on disk and survives (log retention keeps the last YARA_LOG_KEEP=10 runs, line 310).
- **Source:** `ScanConfig.__init__ lines 2997-3011; ErrorLogger lines 1488-1539`

### Hard failure when no requested scan folder is a valid directory

If every comma-separated entry fails isdir, ScanConfig raises ValueError before any scanning starts — the run aborts rather than silently falling back to a full-system scan.

- **Control:** Not configurable — default `-`
- **Observe:** The returned result string is the GENERIC "Scan failed: 0 files scanned \| 0 rules failed compilation \| 0 matches found \| Critical error occurred" (built 7599-7601) — it does NOT name the bad folder. The reason appears only on the process streams: stderr "YARA Scanner Critical Error: Critical scanner error: No valid scan directory among the specified scan folder(s): [...]" (7551-7555) and stdout "CRITICAL ERROR: ..." (7559). No scan_summary JSON is produced (the finally-block guard at 7615 requires log_manager, config and scanner to all be non-None, and the constructor raised before any of them existed). yara_processing_<run_id>.log exists — ErrorLogger is built at 2747, before the raise at 3006 — but does NOT contain the reason (the 7572 branch needs config, which is None).
- **Source:** `ScanConfig.__init__ lines 3005-3007; run() except block lines 7550-7603; summary guard line 7615`

### Scan-target quote stripping and whitespace trimming

Each entry is .strip() then .strip('"') then .strip("'"), so an operator pasting a quoted Windows path ("C:\\Users") into the Action Center field does not produce a target with literal quote characters. str.strip(ch) removes EVERY consecutive occurrence, so even ""C:\\Users"" is cleaned — but the order is fixed (double quotes first, then single), so a path wrapped in single quotes OUTSIDE double quotes ('"C:\\Users"') keeps its double quotes and fails isdir. Whitespace is stripped only in the first pass, so " C:\\Users " ends up with the spaces still attached.

- **Control:** Not configurable — default `-`
- **Observe:** yara_processing_<run_id>.log "Scan limited to N folder(s): [...]" (lines 3036-3037) shows the cleaned, absolute paths; a paste the stripping failed to clean shows up instead in the "Ignoring N specified scan folder(s)..." warning (3009-3011).
- **Source:** `ScanConfig.__init__ line 2995`

### Scan-target de-duplication and absolute-path normalisation

Every valid entry is converted with os.path.abspath and added only if not already present, so "C:\\Users,C:\\Users" walks once. Because abspath is used, a RELATIVE scan_folder resolves against the scanner process's current working directory, not against scanner_dir — the effective scope depends on how the agent launched the script. De-duplication is exact-string, so C:\\Users and C:\\users survive as two targets on Windows.

- **Control:** Not configurable — default `-`
- **Observe:** yara_processing_<run_id>.log "Scan limited to N folder(s): [...]" (lines 3036-3037) — compare N and the printed absolute paths against what was supplied.
- **Source:** `ScanConfig.__init__ lines 2998-3002`

### "default" sentinel selects full default-scope discovery

scan_folder is treated as scoped only when it is non-empty AND not the literal string "default" (case-insensitive), so "default"/"DEFAULT" is equivalent to leaving the field blank — the way to force a full-scope scan from a form that requires a value. The same test is repeated verbatim in run() to pick the scope log line.

- **Control:** Not configurable (literal comparison, line 2987; repeated line 7323) — default `-`
- **Observe:** system_<run_id>.log "SCAN SCOPE: Full system scan (light profile throttling enabled)" (line 7326) instead of the "Limited to specified targets" variant; yara_processing_<run_id>.log "Scanning default targets: [...]" (line 3043).
- **Source:** `ScanConfig.__init__ line 2987; run() lines 7323-7328`

### Config-time warning that a requested target sits under a platform skip path (case-blind, so mostly dormant on Windows and macOS)

After validation each target is probed (with a trailing separator appended) against self.skip_paths; hits are warned about, and if EVERY target is excluded an extra "this scan will scan 0 files" warning fires. Two limits: skip_paths is ONLY the platform directory list (win_skip_folder / lin_skip_directory / mac_skip_directory), never skip_path_fragments / skip_extensions / skip_filenames; and the probe compares a CASE-PRESERVED abspath against entries lowercased at construction (2923, 2975), so on Windows "C:\\ProgramData\\Cyvera\\".startswith("c:\\programdata\\cyvera") is False and the warning almost never fires, while on macOS it fires only for already-lowercase absolute entries such as /private/tmp/ (the 29 relative macOS fragments can never prefix-match an absolute path at all). Linux keeps its list case-preserved and works correctly. The runtime skip is unaffected — only this early warning is lost.

- **Control:** Not configurable — default `-`
- **Observe:** On Linux: yara_processing_<run_id>.log "N of M scan folder(s) sit under a platform skip-path and will yield no files: <path> (excluded by '<entry>')" (3026-3028) and "EVERY requested scan folder is excluded by the platform skip-list" (3030-3033). On Windows/macOS the test is NEGATIVE evidence: scan_folder=C:\\ProgramData\\Cyvera produces NO such line in yara_processing, yet the run's result string still carries "WARNING: ... EXCLUDED by the skip list" (7518-7524) and scan_summary_<run_id>.json still lists it in "excluded_targets" (7635) — because the runtime check at 6860 lowercases both sides.
- **Source:** `ScanConfig.__init__ lines 3016-3033; skip_paths built at 2925 / 2939 / 2976 / 2981; lowercasing at 2923 and 2975; runtime counterpart _is_special_file lines 6245-6248, 6285-6287`

### Dead hook: _discover_all_targets override branch

**⚠ OBSERVABILITY GAP**  
When no scan_folder is given, the code checks hasattr(self, "_discover_all_targets") and prefers it over _default_discover_targets. No such method exists anywhere in the file, so the branch is permanently dead — an unused extension point, not a behaviour.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE: the branch never executes and emits nothing. To confirm it is dead, grep the source — _discover_all_targets appears only at lines 3039 and 3040 (no def anywhere).
- **Source:** `ScanConfig.__init__ lines 3039-3042`

### Windows default scope = every logical drive returned to this process  <sub>windows</sub>

With no scan_folder, Windows discovery unions psutil.disk_partitions(all=False) mountpoints with the GetLogicalDrives() A–Z bitmask, keeping only roots that pass os.path.isdir. The bitmask reports removable media and any network drive mapped IN THIS LOGON SESSION, so an interactive full-scope run can walk a mapped share over the network — but the Cortex agent executes payloads as SYSTEM, whose session normally has no user drive mappings, so in agent-delivered scans this usually resolves to local fixed/removable drives only.

- **Control:** Not configurable — default `-`
- **Observe:** yara_processing_<run_id>.log "Light profile full-scope targets on Windows: ['C:\\\\', 'D:\\\\', ...]" (line 3095); the same list as 'targets'/'target_count' in the "Scan configuration established" statistics entry (6802-6813) and as 'scan_targets' in the "YARA Scanner initialization completed" system entry (7304, logged 7321).
- **Source:** `_default_discover_targets lines 3048-3095`

### Windows drive-root de-duplication via normcase  <sub>windows</sub>

Drives found by both psutil and the GetLogicalDrives bitmask are collapsed using os.path.normcase(os.path.normpath(root)), so C:\\ is not walked twice when both discovery mechanisms report it.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log "Scan configuration established" — 'target_count' (line 6806) equals the number of distinct drives, not the sum of both discovery passes.
- **Source:** `_default_discover_targets lines 3085-3091`

### Windows discovery fallbacks (A–Z probe, then C:\)  <sub>windows</sub>

If both psutil and the bitmask yield nothing, a brute A–Z os.path.isdir probe runs; if that also yields nothing the target list is hard-set to ['C:\\']. A locked-down host therefore always gets at least a C: scan rather than a silent zero-target run. Note the brute probe is byte-identical to the bitmask loop's isdir test, so it only helps when ctypes/psutil themselves raised.

- **Control:** Not configurable — default `['C:\\'] as last resort`
- **Observe:** statistics_<run_id>.log "Scan configuration established" showing targets=['C:\\'] with target_count=1 on a machine that has more than one drive; corroborate with yara_processing_<run_id>.log line 3095.
- **Source:** `_default_discover_targets lines 3076-3083 (A–Z probe), 3093-3094 (hard default)`

### Linux default scope depends on effective UID (root = whole filesystem)  <sub>linux</sub>

Running as root sets targets to ['/'] — the entire filesystem, one target. Non-root probes ['/home','/tmp','/opt','/usr/local','/var/tmp'] and keeps only those that exist, are directories and pass os.access R_OK. /tmp and /var/tmp are in the default non-root scope; /proc,/sys,/dev are handled later by the skip list, not here.

- **Control:** Not configurable — default `root → ['/']; non-root → subset of ['/home','/tmp','/opt','/usr/local','/var/tmp']`
- **Observe:** yara_processing_<run_id>.log "Light profile default scope on Linux: full filesystem" (3105) or "Light profile default scope on Linux using accessible full-scan targets: [...]" (3120-3122); also system_<run_id>.log "Running as: root\|non-root user on Linux" (line 7230).
- **Source:** `_default_discover_targets lines 3097-3122; run() line 7230`

### Linux non-root fallback to '/' when no probe target is readable  <sub>linux</sub>

If none of the five non-root candidates are readable, targets falls back to ['/'] with an explicit warning that many files will be inaccessible — a hardened container therefore still produces a walk, mostly of permission-denied skips.

- **Control:** Not configurable — default `['/']`
- **Observe:** yara_processing_<run_id>.log "Light profile default scope fell back to '/' on Linux - many files may be inaccessible" (3116-3118); corroborate with a large "No read permission" count in the skip_breakdown data blob of the "Skip reasons" statistics entry (6641-6646). NOTE the sibling reason "Permission denied" (scan_file line 6220) is a different gate (PermissionError from rules.match), not the access check.
- **Source:** `_default_discover_targets lines 3114-3118`

### macOS default scope depends on effective UID (root = whole filesystem, SIP still applies)  <sub>darwin</sub>

Root gets ['/'] plus an explicit note that SIP still restricts /System/. Non-root probes [~, /Applications, /Users/Shared, /usr/local, /opt] and keeps the readable ones. macOS is the only platform whose non-root default includes the user's home directory.

- **Control:** Not configurable — default `root → ['/']; non-root → subset of [~, '/Applications', '/Users/Shared', '/usr/local', '/opt']`
- **Observe:** yara_processing_<run_id>.log "Light profile default scope on macOS: full filesystem" (3132) + "Note: SIP restrictions still apply to /System/" (3133), or "...using accessible full-scan targets: [...]" (3141-3143); system_<run_id>.log "Running as: root\|non-root user on macOS" (line 7220).
- **Source:** `_default_discover_targets lines 3124-3148; run() line 7220`

### macOS non-root fallback to the home directory only  <sub>darwin</sub>

If none of the five non-root macOS candidates pass isdir+R_OK, the target list collapses to just os.path.expanduser("~") — the narrowest default scope of any platform. Unlike Linux's equivalent fallback this is logged at INFO, not WARNING.

- **Control:** Not configurable — default `[os.path.expanduser("~")]`
- **Observe:** yara_processing_<run_id>.log "Light profile default scope on macOS fell back to the user home directory only" (3146-3148).
- **Source:** `_default_discover_targets lines 3144-3148`

### Unknown platform yields an empty default target list

On any platform.system() that is not Windows/Linux/Darwin, _default_discover_targets returns [] and warns that manual target specification is required. Nothing else in ScanConfig supplies a target, so a default scan on such a host has no scope at all until _get_scan_targets' runtime fallback substitutes ['/'].

- **Control:** Not configurable — default `[]`
- **Observe:** yara_processing_<run_id>.log "Unknown platform - manual target specification required" (3152) followed by "Scanning default targets: []" (3043); then the substitution is visible as 'scan_targets': [] in the "YARA Scanner initialization completed" system entry (7304, logged 7321) while 'targets': ['/'] in the later "Scan configuration established" statistics entry (6805-6813).
- **Source:** `_default_discover_targets lines 3150-3152; log at 3043`

### Runtime scan-target fallback ladder (_get_scan_targets)

At scan time the scanner prefers config.scan_targets; only if that attribute is missing or the list is empty does it re-run Windows discovery or hard-default to ['/'] on any non-Windows host. Because ScanConfig always populates scan_targets and every known platform's discovery returns at least one entry, this ladder is reachable only on an unknown platform — where the result is a full '/' scan that the discovery code just declined to choose.

- **Control:** Not configurable — default `['/'] on non-Windows`
- **Observe:** OBSERVABLE: logs/diagnostics_<run_id>.log records exactly which rung fired — `Using configured scan targets: {targets}` (line 6635), `Using default Windows targets: {targets}` (line 6640), or `Using default Unix target: ['/']` (line 6643). No inference from the statistics/system-log mismatch is needed any more. Caveat: if the diagnostics FileHandler itself fails to open, setup_logging reverts to WARNING (7125-7126) and prints `Diagnostics log unavailable (…)`, which is the one case where these three lines vanish again.
- **Source:** `_get_scan_targets lines 6500-6512; call site scan_system line 6799`

### Non-root system-path advisory for requested targets  <sub>linux, darwin</sub>

Before the scan, if not root, each comma-separated requested folder is checked with startswith against a per-OS system-path list (macOS ['/System','/Library','/private/var/db'], other POSIX ['/etc','/boot','/var/log','/root']) and an advisory is logged. It is only advice — the scan still proceeds and accumulates permission skips. It re-parses the RAW scan_folder string, not config.scan_targets, so a relative or invalid entry is tested as typed.

- **Control:** Not configurable — default `-`
- **Observe:** system_<run_id>.log: "ERROR: System path scan requires elevated privileges" (7245) followed by the macOS Full-Disk-Access tip (7247) or the Linux 'run as root' tip (7249). Despite the "ERROR:" text it is written with log_system at INFO level, so it appears in system_<run_id>.log and NOT in scan_errors_<run_id>.log.
- **Source:** `run() lines 7236-7249; guarded by `platform.system() != "Windows"` at line 7215`

### Cancellable directory walk (_walk_cancellable) replacing os.walk

An explicit LIFO stack drives traversal so scan_active is checked before every directory AND between scandir entries; cancellation latency is bounded by one scandir instead of os.walk's unbounded internal recursion (docstring records 50s of extra exit time measured on C:\\). Because the stack is LIFO, directories are visited depth-first in reverse enumeration order, not in os.walk's order.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json "outcome":"cancelled" (derived 7617-7618, written 7633) with a small "duration_secs" (7636) delta after the cancel; a terminal lifecycle row with status="cancelled" and message="cancelled by operator (source=...)" (built 6748-6750, emitted 6757). Compare the row's event_timestamp_ms against the mtime of <scanner_dir>/control/cancel.flag (path built line 5069).
- **Source:** `_walk_cancellable lines 6005-6057; call site line 6871`

### Symlinked directories are enumerated but never descended into

entry.is_dir() follows symlinks, so a symlinked directory is reported in dirnames (matching os.walk), but its name is recorded in a `symlinked` set and is NOT pushed onto the traversal stack — the equivalent of os.walk(followlinks=False). This is the primary loop protection; _should_skip_junction covers only a handful of named paths.

- **Control:** Not configurable — default `-`
- **Observe:** Create a symlinked dir tree under the target with a uniquely-named rule-matching file inside; after the scan that file appears in NO alert/<rule>.txt (written at line 6396) and files_scanned in scan_summary_<run_id>.json (7637) does not grow by the symlinked tree's size.
- **Source:** `_walk_cancellable lines 6027, 6036-6040, 6054-6057`

### Traversal error tolerance (per-entry and per-directory)

A per-entry OSError (file vanished / unreadable stat) skips just that entry; PermissionError, NotADirectoryError, FileNotFoundError or any OSError on the scandir itself skips the whole directory. All of these are swallowed SILENTLY — an unreadable directory contributes nothing to files_skipped or skip_reasons, so an entire inaccessible subtree is invisible in the books.

- **Control:** Not configurable — default `-`
- **Observe:** Negative/derived evidence only: on a non-root Linux scan of '/', files_scanned + files_skipped in scan_summary_<run_id>.json (7637-7638) is far below the true file count, with no skip_reasons key to explain the gap. Nothing is logged for these — an unreadable directory is indistinguishable from an empty one.
- **Source:** `_walk_cancellable lines 6043-6045 (per-entry), 6046-6049 (per-directory)`

### Caller-side dirnames pruning is honoured

The generator reads dirnames AFTER the yield, so the caller's in-place `dirs[:] = ...` prune actually removes subtrees from the stack — the os.walk(topdown=True) contract. This is what makes the junction pruning at line 6889 effective.

- **Control:** Not configurable — default `-`
- **Observe:** Directly: put a rule-matching file inside a directory junction under the target and confirm it produces no alert/<rule>.txt entry (line 6396) and no yara_scanner_matches row, while a control copy outside the junction does. Directory-level pruning is counted NOWHERE — 'junction_skips' (6608) counts file-level skips only — so a count-based test cannot show this.
- **Source:** `_walk_cancellable lines 6018-6020 (docstring contract), 6053-6057 (post-yield stack extension); prune call site line 6889`

### Junction/symlink directory pruning during the walk

Every subdirectory name is passed through _should_skip_junction and pruned in place. It runs only for directories that survived the root-level skip check — the `continue` at 6887 on a skipped root bypasses the prune (and the file loop and the heartbeat at 6916) entirely.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log final metrics 'junction_skips' (line 6608) counts only FILE-level junction skips; directory pruning is not counted anywhere. Confirm indirectly by the absence of files from a pruned junction in alert/<rule>.txt (6396).
- **Source:** `scan_system line 6889; _should_skip_junction lines 520-537`

### Skip lists do NOT prune traversal — excluded subtrees are still fully enumerated

When _is_special_file(root) matches, the loop `continue`s WITHOUT pruning dirs, and the generator then pushes every subdirectory anyway. So a skipped tree such as C:\\Windows\\... or /proc is still scandir'd top to bottom; only the files are never queued. The comment at 6880-6882 says this is deliberate (it makes the skip accounting exact), but it means the walk cost of a large excluded tree is paid in full.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log: the skip_breakdown "Skipped directory" count (incremented 6886) grows to the full file count of the excluded subtree, and the per-target 'scan_time_seconds' (6921-6929) stays high even when files_found/files_scanned are near zero.
- **Source:** `scan_system lines 6875-6887 (comment 6876-6882); generator push at lines 6053-6057`

### Producer backpressure: files are blocked on, never dropped

_enqueue_scan_path loops on scan_queue.put(timeout=1.0) for as long as scan_active is set, so a saturated worker pool slows discovery instead of silently discarding files. It never sleeps for the governor here (the producer holds no unit of work), only for queue_backoff_secs. If put() raises anything other than Full the file is dropped, the error is logged, and the whole per-directory file loop breaks (6913-6914).

- **Control:** YARA_QUEUE_BACKOFF_SECS (line 2868); queue depth YARA_QUEUE_SIZE (line 2841) — default `queue_backoff_secs 0.25s; queue size max_workers*2, floored at 2 (max_workers default 2 → queue 4)`
- **Observe:** performance_<run_id>.log: "Scan queue saturated (N items) - backing off producer" (emitted on every 25th event, lines 6066-6070). The non-Full failure path is separately visible in scan_errors_<run_id>.log as "Failed to enqueue file for scanning: ..." with data {'file_path': ...} (line 6076).
- **Source:** `_enqueue_scan_path lines 6059-6078; call site line 6913`

### Per-directory heartbeat call during the walk (rate-limited to YARA_HEARTBEAT_SECS)

_maybe_heartbeat() is CALLED once per directory the walker finishes, but it emits only when SCANS_HEARTBEAT_SECS has elapsed since the last one — under a lock, so it cannot double-fire with the independent heartbeat thread. At the 600s default a whole scan shorter than 10 minutes produces no running row from here at all, and skipped roots bypass the call entirely (continue at 6887).

- **Control:** YARA_HEARTBEAT_SECS → SCANS_HEARTBEAT_SECS (line 307); gate at line 5257 — default `600 seconds`
- **Observe:** yara_scanner_scans_v3_<shard> rows with status="running", message="heartbeat" (emitted line 5261); <scanner_dir>/control/running.json (path line 5070) rewritten atomically (5180-5193) with its mtime advancing at most once per 600s.
- **Source:** `scan_system line 6916; _maybe_heartbeat lines 5249-5261; SCANS_HEARTBEAT_SECS line 307`

### The skip predicate runs at four separate points per scan

_is_special_file is evaluated on the requested TARGET (line 6860, for exclusion accounting only), on every walk ROOT (6875, bulk-skipping that directory's files), on every FILE during the walk (6907), and once more inside scan_file on the dequeued path (6129). The last is a re-check after the file has waited in the queue, so the same path is evaluated up to four times in one run.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown showing BOTH "Skipped directory" (walk-root grain, 6886) and "Special system file" (per-file grain, 6910 and 6130) keys in the same run.
- **Source:** `_is_special_file lines 6243-6363; call sites 6860, 6875, 6907, 6129`

### The scanner's own output log path is excluded from scanning

**⚠ OBSERVABILITY GAP**  
The first check in the skip predicate compares the normalised path against config.output_log (<scanner_dir>/logs/scanner_<run_id>.log), case-folded on Windows only. Nothing in the file ever WRITES that log — it is only constructed (2823), deleted by initial_cleanup (4649) and compared here — and the name embeds a microsecond-precision run_id, so the guard protects a file that cannot exist. The real logs are protected by the scanner_dir entries in the platform skip lists.

- **Control:** Path derived from YARA_SCANNER_DIR (line 835) via config.output_log (line 2823) — default `<scanner_dir>/logs/scanner_<run_id>.log`
- **Observe:** UNOBSERVABLE: the check returns True silently and would be counted only as a generic "Special system file". Exercising it requires creating that exact per-run filename mid-scan and confirming it never appears in alert/<rule>.txt.
- **Source:** `_is_special_file lines 6250-6256; output_log line 2823; only other uses 4649 and 4667`

### Filename skip list (OS metadata droppings)

Files whose lowercased basename is .ds_store, thumbs.db or desktop.ini are skipped on every platform, before the force-scan allowlist — so the carve-out cannot re-open them.

- **Control:** self.skip_filenames literal set, line 2872 — no env var, not an options key — default `{".ds_store", "thumbs.db", "desktop.ini"}`
- **Observe:** statistics_<run_id>.log skip_breakdown key "Special system file" (from 6130 or 6910); drop a rule that matches Thumbs.db content into the pack and confirm no alert/<rule>.txt entry for it.
- **Source:** `_is_special_file lines 6258-6261; set defined line 2872`

### Extension skip list (disk images and VM disks)

Any path ending in one of nine container/disk-image extensions is skipped, checked BEFORE the force-scan allowlist (comment 6266: "no point scanning a .iso"), so a .dmg inside a browser cache is still skipped. Matching is endswith on the lowercased path, not a real extension parse, so a DIRECTORY named foo.img is skipped too — which is deliberate for .sparsebundle.

- **Control:** self.skip_extensions literal set, lines 2869-2871 — no env var, not an options key — default `{.iso, .img, .dmg, .vmdk, .vhd, .vhdx, .qcow, .qcow2, .sparsebundle}`
- **Observe:** statistics_<run_id>.log skip_breakdown key "Special system file"; place a rule-matching payload inside a .img file in the target and confirm "matches": 0 in scan_summary_<run_id>.json (7639) for it.
- **Source:** `_is_special_file lines 6262-6263; set defined lines 2869-2871`

### Force-scan allowlist for browser caches (overrides all path-based skips)  <sub>darwin</sub>

If any of five fragments appears in the forward-slashed lowercased path, the predicate returns False immediately, defeating BOTH skip_path_fragments and the platform directory lists (filename/extension skips already ran). Every fragment is macOS-shaped ("/library/caches/google/chrome/" etc.), so on Windows and Linux — where browsers do not use a Library/Caches layout — it is inert in practice; the comment at 2890-2895 explains that the browser-cache fragments were simply removed from the skip list on those platforms instead.

- **Control:** self.force_scan_fragments literal tuple, lines 2896-2902 — read via getattr with a () default (6267) — default `(/library/caches/google/chrome/, /library/caches/chromium/, /library/caches/microsoft edge/, /library/caches/firefox/, /library/caches/com.apple.safari/)`
- **Observe:** On macOS (OfficeiMac): drop a rule-matching file under ~/Library/Caches/Google/Chrome/ and confirm a row in yara_scanner_matches_v3_<shard> with that filename — despite "/library/caches/" being in skip_path_fragments (2886) and both '/Library/Caches/' and 'Library/Caches/' being in mac_skip_directory (2951-2952).
- **Source:** `_is_special_file lines 6264-6268; tuple defined lines 2896-2902`

### Cross-platform path-fragment skip list (dev caches, Windows AppData temp/packages)

Fifteen "/fragment/" substrings are matched against the forward-slashed lowercased path: build/dependency caches (node_modules, __pycache__, .git, .svn, .hg, .venv, venv, .pytest_cache, .mypy_cache, .gradle, .yarn/cache, .npm), macOS /library/caches/, and two Windows ones (/appdata/local/temp/, /appdata/local/packages/). It applies on ALL platforms, so a Windows scan skips node_modules and a Linux scan skips /appdata/local/temp/. These fragments are NOT part of skip_paths, so they never trigger the config-time exclusion warning.

- **Control:** self.skip_path_fragments literal tuple, lines 2873-2889 — no env var, not an options key — default `the 15 fragments above`
- **Observe:** statistics_<run_id>.log skip_breakdown "Skipped directory" (when the walk root is inside one, 6886) and "Special system file" (per-file, 6910); scan a tree containing node_modules and confirm files_scanned in scan_summary_<run_id>.json excludes it.
- **Source:** `_is_special_file lines 6269-6278; tuple defined lines 2873-2889`

### Fragment matching also anchors at the path tail (bare-root fix)

Each fragment is tested both as a bounded "/frag/" substring AND as an endswith of the fragment with its trailing slash removed. Without the tail test, the directory that IS the excluded component ("...\\node_modules", which the walker yields with no trailing separator) closed no bounded form and matched nothing, so an operator explicitly targeting ...\\node_modules got 0 files and no exclusion warning. The comment at 6269-6275 records that the Darwin branch masked this locally.

- **Control:** Not configurable — default `-`
- **Observe:** Set scan_folder to a path ending in \\node_modules: the run result string gains "WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned: ..." (built 7518-7524, appended 7536) and scan_summary_<run_id>.json "excluded_targets" (7635) lists it. yara_processing will NOT warn — skip_path_fragments is not part of skip_paths.
- **Source:** `_is_special_file lines 6276-6278`

### Windows drive-letter exclusion list (present but permanently empty)  <sub>windows</sub>

**⚠ OBSERVABILITY GAP**  
The predicate splits the drive off the path and returns True if that letter is in config.win_skip_drive. The list is initialised to [] and never populated, with no env var or options key — a dormant control. Anyone editing it must use a LOWERCASE letter without the colon (e.g. "d"), because normalized_path was lowercased at 6246 and the colon is stripped at 6281.

- **Control:** self.win_skip_drive literal list, line 2909 — no env var, absent from _VALID_OPTION_KEYS (771-775) — default `[] (nothing excluded)`
- **Observe:** UNOBSERVABLE while empty: the branch never returns True. Populate it and confirm via the "Skipped directory" count in statistics_<run_id>.log skip_breakdown for that drive.
- **Source:** `_is_special_file lines 6280-6283; list defined line 2909`

### Windows folder-prefix skip list (vendor agent dirs + scanner's own dir)  <sub>windows</sub>

Seven prefixes, each normpath'd and lowercased at construction, are matched with startswith: ProgramData\\Cyvera, ProgramData\\Microsoft Defender, Program Files\\Palo Alto Networks, C:\\yara_scanner, C:\\$Recycle.Bin, C:\\System Volume Information, and self.scanner_dir. Both the hard-coded C:\\yara_scanner and the resolved scanner_dir are present, so a YARA_SCANNER_DIR override is still self-excluded. normpath strips the trailing separator, which is what lets the bare walk root match — but also means the prefix matches siblings like C:\\yara_scanner_old.

- **Control:** self.win_skip_folder literal list, lines 2910-2918, normalised at line 2923; scanner_dir entry from YARA_SCANNER_DIR (line 835) — default `the 7 entries above`
- **Observe:** statistics_<run_id>.log skip_breakdown "Skipped directory"; on a C:\\ default scan confirm no alert/<rule>.txt entry references C:\\ProgramData\\Cyvera or the scanner's own logs directory. Also settable as a target: scan_folder=C:\\ProgramData\\Cyvera lands in scan_summary "excluded_targets".
- **Source:** `_is_special_file lines 6285-6287; list defined lines 2910-2925`

### DEAD CODE: Windows wildcard pattern skip list never matches anything  <sub>windows</sub>

**⚠ OBSERVABILITY GAP**  
win_skip_patterns ("C:\\yara_scanner\\*", "C:\\*\\cyvera\\*") is split on backslashes into components INCLUDING the drive component "c:", but is matched against path_without_drive — os.path.splitdrive()[1], which by construction never contains "c:". The first component therefore always fails, ValueError is raised, every pattern is skipped and the branch falls through to `return False` (6312). "*" is also compared as a literal component name, not a glob. The list is completely inert; the C:\\yara_scanner case is saved only by win_skip_folder.

- **Control:** self.win_skip_patterns literal list, lines 2919-2922, lowercased at line 2924 — default `["C:\\yara_scanner\\*", "C:\\*\\cyvera\\*"] — both inert`
- **Observe:** UNOBSERVABLE by design. Demonstrate it by creating C:\\SomeDir\\Cyvera\\<rule-matching file> on thor — it IS scanned and produces a yara_scanner_matches_v3_<shard> row plus an alert/<rule>.txt entry, even though pattern 2 nominally covers it.
- **Source:** `_is_special_file lines 6289-6312; patterns defined lines 2919-2924`

### Linux directory skip list (pseudo-filesystems, agent root, scanner dir)  <sub>linux</sub>

Eleven trailing-slash prefixes: /sys/, /proc/, /dev/, /run/, /tmp/.X11-unix/, /var/run/, /lost+found/, /media/, /opt/yara_scanner/, /opt/traps/ (the Cortex XDR Linux agent install root, confirmed against the vendor guide in the comment at 2931-2935), plus the resolved scanner_dir. Matching stays case-sensitive because Linux filesystems normally are. /media/ is excluded, so removable media is NOT scanned on Linux even under a '/' root scan.

- **Control:** self.lin_skip_directory literal list, lines 2928-2938; scanner_dir entry from YARA_SCANNER_DIR (line 835) — default `the 11 entries above`
- **Observe:** statistics_<run_id>.log skip_breakdown "Skipped directory" on a root '/' scan; confirm zero alert/<rule>.txt references under /proc or /opt/traps. On xsoar, /opt/traps is root-only anyway — use the skip_breakdown count, not a du/ls comparison.
- **Source:** `_is_special_file lines 6314-6324; list defined lines 2928-2939`

### Linux bare-root equality match (walk-root fix)  <sub>linux</sub>

Each Linux entry carries a trailing "/", which plain startswith never matches against the BARE directory root the walker yields for the directory itself — only its contents. The added `normalized_path == skip_dir.rstrip("/")` test means /opt/yara_scanner itself is now skipped, not just everything under it. Before this, the scanner's own directory root was walked and enumerated.

- **Control:** Not configurable — default `-`
- **Observe:** Set scan_folder=/opt/yara_scanner: the result string carries "WARNING: 1 requested target(s) EXCLUDED by the skip list" (7518-7524) and scan_summary_<run_id>.json "excluded_targets" (7635) contains it. yara_processing also warns here (lines 3026-3028), because lin_skip_directory IS skip_paths and is case-preserved.
- **Source:** `_is_special_file lines 6317-6323 (comment 6318-6321, test 6322)`

### macOS skip list with three distinct match semantics  <sub>darwin</sub>

59 entries are interpreted by SHAPE, not uniformly: entries starting with "/" are absolute ANCHORS — 27 of them at runtime, counting the injected scanner_dir at 2971 and the seven /Applications/<app>.app/Contents/ trees, so "/system/" cannot match a user's ~/System/; the 3 RELATIVE entries containing ".app/" are BUNDLE SUFFIXES matched without a leading slash, so ".app/contents/frameworks/" matches any app name; the remaining 29 are FRAGMENTS matched at any depth via "/entry" plus a tail check. Order matters: startswith("/") is tested first, so the seven absolute /Applications/*.app/Contents/ entries take the anchor branch, not the bundle branch. The comment at 6337-6342 records that a bare startswith left the relative entries matching nothing at all.

- **Control:** self.mac_skip_directory literal list, lines 2942-2972, lowercased at line 2975 — default `59 entries — /System/, five /private/var/* trees, /private/tmp/, /dev/, /Volumes/, four Spotlight/fseventsd/Trash metadata dirs, both Palo Alto vendor dirs, /Library/{Developer,Caches,Logs}/, relative Library/{Containers,Caches,Group Containers,Metadata,Logs,Developer,Android,Python}/ and four Application Support vendors, dev-tool caches, three .app/Contents/{Frameworks,Resources,_CodeSignature} suffixes, SEVEN /Applications/<app>.app/Contents/ trees, and scanner_dir`
- **Observe:** statistics_<run_id>.log skip_breakdown "Skipped directory"; on OfficeiMac confirm no alert/<rule>.txt entry under /System/ or inside any .app/Contents/Frameworks/.
- **Source:** `_is_special_file lines 6326-6352 (anchor 6344-6346, bundle 6347-6349, fragment 6350-6352); list defined lines 2942-2976`

### macOS /Volumes/ exclusion removes all mounted external and network volumes  <sub>darwin</sub>

'/Volumes/' is an anchored entry in mac_skip_directory, so on macOS every mounted external disk, DMG and network share is excluded — even under a root '/' scan. This is the opposite of Windows, where GetLogicalDrives discovery deliberately INCLUDES removable and session-mapped drives.

- **Control:** Entry '/Volumes/' in self.mac_skip_directory, line 2945 — default `excluded`
- **Observe:** On OfficeiMac with an external volume mounted, set scan_folder=/Volumes/<name>: the result string reports it in the "EXCLUDED by the skip list" warning (7518-7524) and scan_summary_<run_id>.json lists it under "excluded_targets" (7635). The anchor test at 6345 matches both /Volumes and /Volumes/<name>.
- **Source:** `_is_special_file lines 6343-6346; entry at line 2945`

### macOS AppleDouble resource-fork file skip  <sub>darwin</sub>

After the directory list, any basename starting with "._" is skipped — the AppleDouble sidecar files that appear on non-HFS volumes. A second check for '.ds_store' follows it, which can never fire because skip_filenames already caught that name at 6260.

- **Control:** Not configurable (literal checks, lines 6355 and 6357) — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown "Special system file"; write ._payload containing rule-matching content into the target and confirm "matches": 0 in scan_summary_<run_id>.json for it.
- **Source:** `_is_special_file lines 6354-6358`

### Unknown platform has no directory skip list at all

**⚠ OBSERVABILITY GAP**  
The else-branch of the platform dispatch sets lin_skip_directory=[], mac_skip_directory=[] and skip_paths=set(), and _is_special_file's final else returns False. On any OS that is not Windows/Linux/Darwin only the output_log, filename, extension and cross-platform fragment checks apply — no vendor-directory or pseudo-filesystem protection, and no scanner-dir self-exclusion, on a host that _get_scan_targets will point at '/'.

- **Control:** Not configurable — default `empty lists`
- **Observe:** UNOBSERVABLE directly. Infer from statistics_<run_id>.log skip_breakdown containing no "Skipped directory" key at all, combined with the yara_processing line "Unknown platform - manual target specification required" (3152). To close it: Add one field to scan_config_data in scan_system (dict at lines 6934-6942, logged at 6945): `'platform_skip_paths': len(getattr(self.config, 'skip_paths', ()))` (optionally alongside `'platform': platform.system()`). That makes the "Scan configuration established" entry in statistics_<run_id>.log state the skip-list size directly on every run — 0 proves the unknown-platform branch, non-zero proves the platform list loaded — instead of requiring the negative inference from a missing skip_breakdown key.
- **Source:** `ScanConfig lines 2978-2981; _is_special_file lines 6362-6363`

### Scanner working-directory self-exclusion (all three platforms)

The resolved scanner_dir is injected into each platform's skip list — win_skip_folder 2917, lin_skip_directory 2937, mac_skip_directory 2971 — so the scanner never scans its own logs, alert/, evidence/, failed_rules/ or rule cache. Because the entry comes from _default_scanner_dir(), a YARA_SCANNER_DIR override is covered too; Linux and Windows additionally hard-code the default location (2930, 2914) so it stays excluded even under an override.

- **Control:** YARA_SCANNER_DIR (line 835, read by _default_scanner_dir lines 833-842); injected entries at 2917, 2937, 2971 — default `Windows C:\\yara_scanner, macOS /usr/local/yara_scanner, Linux /opt/yara_scanner`
- **Observe:** Set scan_folder to the scanner_dir: the result string carries the "EXCLUDED by the skip list" warning (7518-7524) and scan_summary_<run_id>.json "excluded_targets" (7635) names it. Also confirm alert/<rule>.txt never references files under scanner_dir on a full-scope scan with a broad rule.
- **Source:** `_default_scanner_dir lines 833-842; ScanConfig lines 2731, 2914, 2917, 2930, 2937, 2971`

### Per-platform case-folding policy in the skip predicate

Windows lowercases normalized_path up front (6246) and its lists are lowercased at construction (2923-2924); macOS compares the already-lowercased portable_path (6258) against a list lowercased at 2975, because APFS defaults to case-insensitive; Linux deliberately keeps normalized_path case-preserved (6248, comment 6315-6316). The cross-platform filename/extension/fragment checks are always case-insensitive because they all run off portable_path. Getting this wrong is what makes the config-time warning dormant on Windows/macOS.

- **Control:** Not configurable — default `-`
- **Observe:** Create mixed-case variants and compare which are excluded: on macOS a mixed-case ~/LIBRARY/Caches path is skipped; on Linux a mixed-case /Proc is NOT (and, being a real directory, is walked).
- **Source:** `_is_special_file lines 6245-6248, 6258, 6314-6317, 6326-6328; lowercasing at 2923-2924 and 2975`

### Junction / reparse-point detection (_is_junction_or_symlink)

**⚠ OBSERVABILITY GAP**  
On Windows it calls kernel32.GetFileAttributesW and tests FILE_ATTRIBUTE_REPARSE_POINT (0x400), which catches junctions that os.path.islink does not; on POSIX it is plain os.path.islink. Any exception, or attrs == -1 (the path is unreadable or missing), yields False — so an inaccessible reparse point is treated as a normal file.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE alone; visible only through its caller. See 'junction_skips' in the final statistics entry (line 6608) and in each per-interval progress entry (6582). To close it: Instrument the pruning site at line 7021 in scan_system: capture the removed entries before filtering, e.g. `pruned = [d for d in dirs if _should_skip_junction(os.path.join(root, d))]`, then `dirs[:] = [d for d in dirs if d not in pruned]` and, under `self.lock_counts`, `self.skip_reasons["Junction/symlink dir prune"] += len(pruned)` plus `self.junction_skip_count += len(pruned)`. That surfaces it in the skip_breakdown of the "Skip reasons" statistics entry (6774-6777) and in the existing junction_skips fields, no new file or field needed.
- **Source:** `_is_junction_or_symlink lines 480-492`

### Junction/symlink loop guard with narrow, hard-coded per-platform lists

_should_skip_junction returns True only when the path IS a link AND matches a short list: on Windows six legacy profile junction names (documents and settings, application data, local settings, my documents, default user, all users); on macOS links whose path starts /etc, /tmp or /var; on Linux only /proc/self/fd and /proc/self/task. Everything else that is a symlink is NOT skipped here — general loop protection comes from the walker not descending symlinked dirs (6054-6057), not from this function.

- **Control:** Not configurable (literal lists at lines 527-530, 533, 536) — default `see above`
- **Observe:** statistics_<run_id>.log skip_breakdown key "Junction/symlink skip" (incremented 6900) and final metric 'junction_skips' (6608); also 'junction_skips' in the per-interval progress entries (6582).
- **Source:** `_should_skip_junction lines 520-537; call sites 6889 (directories) and 6897 (files)`

### Junction file skip is counted on its own dedicated counter

A file rejected by _should_skip_junction increments files_skipped, skip_reasons["Junction/symlink skip"] AND a separate junction_skip_count — all under lock_counts — and it is counted BEFORE total_files_found/target_files_found are incremented (6904-6905), so junction-skipped files never appear in the per-target 'files_found' statistic.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log: compare 'files_found' in each per-target "Target scan completed" entry (6921-6929) against files_scanned+files_skipped in the final metrics (6602-6603) — the difference is the junction skips plus everything under skipped directory roots.
- **Source:** `scan_system lines 6897-6905; counter init line 5038`

### Real-path resolution with platform case normalisation (_get_real_path)

realpath() is taken for EVERY file that passes the earlier gates, then lowercased on Windows, lowercased on macOS only when _is_case_sensitive_fs() reports a case-insensitive volume, and left alone on Linux; any exception falls back to normpath of the original. On macOS this means _is_case_sensitive_fs runs per scanned file and each call CREATES, stats and deletes /tmp/CaSe_TeSt_YaRa_<pid> — a real filesystem write per file, on the one platform where the result is only used for a log field and a disabled dedup.

- **Control:** Not configurable — default `-`
- **Observe:** alerts_<run_id>.log: the 'real_path' field on the "YARA matches found in <file>" entry (logged via log_alert at 6175, field at 6179). On an error, real_path also appears in the scan_errors_<run_id>.log data blob (6226). On macOS the probe itself is observable with `sudo fs_usage \| grep CaSe_TeSt_YaRa` during a scan.
- **Source:** `_get_real_path lines 495-517; _is_case_sensitive_fs lines 462-477; call site line 6132`

### DORMANT: real-path de-duplication across junctions (track_real_paths is hard-wired off)

scan_file would consult self.scanned_real_paths under a lock and return the skip reason "Junction/symlink duplicate" for a path already scanned through a different link, then record it. config.track_real_paths is a bare literal False with no env var and no options key, so the set stays empty for the whole run — the same content reachable through two paths IS scanned twice, and the metrics 'unique_real_paths' (6583) and 'unique_paths_scanned' (6609) are structurally always 0.

- **Control:** self.track_real_paths bare literal, line 2860 — NOT customer-reachable (no env var, absent from _VALID_OPTION_KEYS 771-775) — default `False (dedup disabled)`
- **Observe:** statistics_<run_id>.log: 'unique_paths_scanned' = 0 in the final metrics (6609) and 'unique_real_paths' = 0 in every progress entry (6583) on every run; skip_breakdown never contains "Junction/symlink duplicate".
- **Source:** `scan_file lines 6132-6136, 6146-6148; flag at line 2860; metrics at 6583, 6609`

### File-existence gate at dequeue time

scan_file's first check is os.path.exists — a file that vanished between enumeration and dequeue is counted as a skip, not an error. On a busy host with a deep queue this is a routine, expected skip reason.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown key "File does not exist"; the same total rolls into files_skipped in scan_summary_<run_id>.json.
- **Source:** `scan_file lines 6100-6101; worker accounting lines 5886-5897`

### Read-permission gate with per-file permission diagnostics (unbounded, unthrottled)

os.access(R_OK) failure produces a skip plus a diagnostic dict (file mode, owner uid, scanner uid, and a 'requires_root' heuristic that is true when the owner is uid 0 OR the path starts /etc,/boot,/var/log,/root). Two costs follow per unreadable file. First, the dicts are appended to a lazily-created self.permission_denials list that is UNBOUNDED, mutated from every worker without a lock, and never read or serialised anywhere — pure retained memory. Second, the log line at 6117-6118 is NOT routed through _throttled_log the way every other high-frequency failure path in the scanner is (contrast ResultsUploader._throttled_log at 3371), so it emits once per occurrence: a non-root full-filesystem scan pays tens of thousands of log lines plus one retained dict each. The whole diagnostic block is wrapped in `except Exception: pass` (6124-6125), so if the os.stat itself fails nothing is logged or retained and the file is still skipped as "No read permission".

- **Control:** Not configurable — no throttle, no cap, no flag; the diagnostic block at 6103-6127 is unconditional. Only the destination is configurable: config.logs_dir (2733) with the scan-scoped system log name at 2116 on a plain non-rotating FileHandler (2142-2147). Whether the file survives the run is governed by CONFIG_HOST_CLEANUP (238, default "off") / CONFIG_HOST_CLEANUP_KEEP (239) and LOG_KEEP_SCANS (310). — default `Always on; permission_denials starts absent and grows one entry per denied file`
- **Observe:** statistics_<run_id>.log skip_breakdown key "No read permission"; per-file detail in system_<run_id>.log as "Permission denied: <path>" with the diagnostic blob appended as JSON by _log (2171-2178) (line 6118). To size the cost: `grep -c 'Permission denied:' <scanner_dir>/logs/system_<run_id>.log` must equal the "No read permission" value in skip_breakdown (6641-6646) and in file_processing.skip_breakdown of the comprehensive report (6989). The permission_denials list itself is UNOBSERVABLE — grep confirms its only references are 6120-6122, so its length can only be seen with a debugger or heap dump; the log-line count is the proxy.
- **Source:** `scan_file lines 6103-6127 (os.access gate 6103, permission_info 6109-6115, un-throttled log_system 6117-6118, write-only list 6120-6122, except-wrap 6124-6125, skip reason returned 6127); LogManager.log_system 2212-2214 → _log 2163-2187; contrast ResultsUploader._throttled_log 3371; worker-side skip accounting 5886-5897`

### Regular-file gate (devices, FIFOs, sockets never scanned)

After the skip predicate and real-path resolution, stat.S_ISREG(st.st_mode) must hold — so character/block devices, FIFOs and sockets that slipped past the directory skip lists are rejected rather than handed to libyara, which would block forever on a FIFO.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown key "Not a regular file". Exercise it with `mkfifo <target>/pipe` on xsoar and confirm the count increments and the scan still completes.
- **Source:** `scan_file lines 6138-6140`

### Maximum scanned file size cap

Files larger than max_file_bytes are skipped before rules.match. Setting the cap to 0 means NO SIZE CAP (the `if max_bytes and ...` guard short-circuits), and the minimum=0 guard exists because a negative value previously made max_file_bytes negative — every file failed the check and the scan reported success having scanned nothing.

- **Control:** YARA_MAX_MB env var on the endpoint, read in ScanConfig via _env_number (line 2828); byte conversion line 2829 — default `64 (MB)`
- **Observe:** statistics_<run_id>.log skip_breakdown key "File too large"; the configured value is echoed as 'max_file_size_mb' in the "Scan configuration established" statistics entry (line 6808) and as 'max_file_mb' in the initialization system entry (line 7307). An invalid or negative value is reported by logging.warning inside _env_number (lines 92-94 / 97-99), which runs during ScanConfig — BEFORE setup_logging strips handlers at 7290 — so it reaches stderr via the root logger's last-resort handler and appears in the Action Center's stderr, not in any scanner log file.
- **Source:** `scan_file lines 6142-6144; config lines 2825-2829; _env_number lines 70-101`

### Bounded skip-reason labels for per-file scan errors

Any exception during a file scan is converted to "Scan error (<ExceptionType>)" rather than str(exc). Both common error texts embed the absolute path, so the raw form made every errored file its own skip_reasons key — the docstring records 307,780 bytes of aggregate dict for 5,000 errored files, all of it serialised into the final report. The word "error" is kept in the label because the final stats count error reasons by that substring.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown keys of the form "Scan error (OSError)", "Scan error (Error)"; the aggregate rolls up into 'error_summary.scan_errors' in the "Scan completed successfully" system entry (substring match at 7466-7467, logged 7471-7474 — success path only). Per-file detail (path + message) is in scan_errors_<run_id>.log (6224-6227), and each one also writes a line to stderr (6223).
- **Source:** `_scan_error_reason lines 1236-1251; call site line 6228; substring consumer lines 7466-7467`

### Bulk skip accounting for an excluded directory root

When a walk root matches the skip predicate, len(files) is added to files_skipped and to skip_reasons["Skipped directory"] under lock_counts — but only if the directory actually contained files (guard at 6883). A bare `continue` used to touch no counter, so an entire skipped subtree vanished from the books and skip_rate read 0%. Because subdirectories are NOT pruned, each one later arrives as its own root and contributes its own files — the subtree is counted exactly once, not double-counted.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown key "Skipped directory" with a count matching the real file count of the excluded tree; 'skip_rate' in the final metrics (line 6607) becomes non-zero. The same total is included in files_skipped in scan_summary_<run_id>.json (7638).
- **Source:** `scan_system lines 6875-6887; counters at lines 5010-5011`

### Excluded-target recording: a requested target that the skip list swallows whole

Before walking, the target itself is run through _is_special_file; a hit is appended to scanner.excluded_targets and logged as an error. The walk still proceeds (each root is then individually skipped). Without this, scanning e.g. AppData\\Local\\Temp produced outcome="completed", 0 files scanned, exit code 0 — indistinguishable from an empty directory.

- **Control:** Not configurable — default `[] (empty)`
- **Observe:** THE definitive artefact: scan_summary_<run_id>.json field "excluded_targets" (line 7635). Also the result string gains "\| WARNING: N requested target(s) EXCLUDED by the skip list, nothing under them was scanned: ..." (first 3 named, built 7518-7524, appended 7536 — success path only), and scan_errors_<run_id>.log carries "Requested scan target is excluded by the skip list, so nothing under it will be scanned: <target>" with data {'target_path':..., 'reason':'skip_list'} (6862-6866).
- **Source:** `scan_system lines 6856-6866; list init line 5045; summary line 7635; result line 7518-7524, 7536`

### files_skipped on the wire: every scan-lifecycle row carries the skip count

Each lifecycle row — initiated, running heartbeats, and the terminal completed/cancelled/failed row — snapshots files_scanned and files_skipped under lock_counts, so skip volume is visible in XDR without waiting for the run to end. In practice "near real time" means the YARA_HEARTBEAT_SECS cadence (600s default), not continuous.

- **Control:** CONFIG_WRITE_DATASET (line 162) / write_dataset option (in _VALID_OPTION_KEYS line 772) gates emission (checked at 5207 and 3940); shard via CONFIG_LOOKUP_SHARD (line 186) / YARA_LOOKUP_SHARD (line 284); dataset name also carries LOOKUP_SCHEMA_VERSION (line 290, applied 3846) — default `write_dataset True; shard "endpoint"; schema version 3`
- **Observe:** XQL: `dataset = yara_scanner_scans_* \| filter run_id = "<run_id>"` — the files_skipped column (schema line 3927, populated line 5232) across the status progression. The resolved dataset name is yara_scanner_scans_v3_<shard> (built 3854) and is surfaced on config._scans_dataset (3859).
- **Source:** `_emit_scan_row lines 5204-5247; scans_schema lines 3915-3938; dataset naming 3838-3854`

### Skip-reason breakdown in the final statistics entry

At scan end, if anything was skipped, skip_reasons is sorted descending and the top 5 reasons go into the message line with the FULL breakdown dict attached as structured data. This is the only place the complete per-reason census is written.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log: line "Skip reasons: reason(count), ..." with data={'total_skipped': N, 'skip_breakdown': {...}} (6641-6646). NOT present in scan_summary_<run_id>.json (which carries only the files_skipped total, 7638) and NOT on any dataset row. The data blob is truncated at 4000 chars (2176-2177), so a run with many distinct "Scan error (...)" labels can lose the tail.
- **Source:** `_log_final_results lines 6641-6646`

### Derived skip metrics in the final results entry

skip_rate (% of processed files skipped), junction_skips, unique_paths_scanned and path_deduplication_ratio are computed and logged. Only ONE of the four is structurally dead: unique_paths_scanned reads scanned_real_paths, which stays empty because track_real_paths is False. path_deduplication_ratio is misnamed rather than dead — it is junction_skip_count / (files_scanned+files_skipped) * 100, so it tracks junction skips, not deduplication.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log, the "SCAN COMPLETED \| Time: ... \| Files: N scanned, M skipped \| Detections: ... \| Rate: ..." entry (6614-6619) with data keys 'skip_rate', 'junction_skips', 'unique_paths_scanned', 'path_deduplication_ratio' (6607-6610). On a FAILED run the label is "SCAN FAILED" and the same metrics go to scan_errors_<run_id>.log via log_error instead (6613, 6620-6624).
- **Source:** `_log_final_results lines 6598-6626`

### Skip breakdown in the comprehensive final report and the efficiency score

upload_final_comprehensive_report re-serialises dict(scanner.skip_reasons) under file_processing.skip_breakdown and — surprisingly — the skip rate DEDUCTS up to 20 points from a synthetic 'efficiency score', so a correctly-behaving scan of a heavily-excluded tree scores as less efficient (rule-compilation failures deduct a further 30). Despite the function name nothing is uploaded: it writes one statistics log entry and a logging.info line.

- **Control:** Not configurable — default `efficiency_score starts at 100`
- **Observe:** statistics_<run_id>.log: "COMPREHENSIVE SCAN REPORT \| Efficiency Score: NN.N/100" with the whole final_report_data dict attached (7038-7042). The LogManager data blob is truncated at 4000 chars (2176-2177), so on a real full-system scan the skip_breakdown is likely cut off — this entry carries far more than the dedicated "Skip reasons" entry does.
- **Source:** `upload_final_comprehensive_report lines 6971-7049; skip_breakdown line 6989; score lines 7027-7036; sole call site line 7476`

### Per-target discovery statistics

Each target records how many files the walk found and how long it took, including a files-per-second rate. 'files_found' counts only files that survived the junction check and reached the special-file test (incremented 6905), so files under a skipped directory root and junction-skipped files are NOT included — this number can be far below what is on disk.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log: "Target scan completed: <target>" with data {'target','files_found','scan_time_seconds','files_per_second'} — one entry per target (6921-6929). A target whose walk raised is logged instead as "Error scanning target <target>: ..." in scan_errors_<run_id>.log (6932) and produces NO statistics entry.
- **Source:** `scan_system lines 6918-6929`

### DEAD: total_files_found and files_per_target are computed then discarded

**⚠ OBSERVABILITY GAP**  
scan_system accumulates total_files_found across all targets and a files_per_target dict, and passes both into _perform_enhanced_cleanup — which never references either parameter. The aggregate discovery total is computed for the whole scan and never surfaced anywhere; only the per-target statistics entries survive.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE: nothing writes total_files_found. The per-target counts are recoverable by summing 'files_found' across the "Target scan completed" entries in statistics_<run_id>.log; surfacing the aggregate would need a new field in scan_summary_<run_id>.json.
- **Source:** `scan_system lines 6835-6836, 6904-6905, 6919, 6945; unused parameters at _perform_enhanced_cleanup line 6680`

### Skip counting happens in the worker, under lock_counts, at dequeue grain

Every reason returned by scan_file ("File does not exist", "No read permission", "Special system file", "Junction/symlink duplicate", "Not a regular file", "File too large", "Permission denied", "Scan error (…)") increments files_skipped and its own skip_reasons key under the shared lock. Walk-time skips ("Skipped directory", "Junction/symlink skip", "Special system file") are counted separately on the producer thread — so "Special system file" is the one label written from BOTH sides.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log skip_breakdown: the set of keys present tells you which gate fired; a "Special system file" count larger than the walk could account for indicates the scan_file re-check (6129-6130) is also firing. Note the walk-time skips are the only reasons whose grain is a directory's whole file list (6886).
- **Source:** `_worker lines 5886-5897; scan_file return points 6101, 6127, 6130, 6136, 6140, 6144, 6220, 6228; walk-time counters 6885-6886, 6899-6901, 6909-6910`

### Scan status transitions are effectively unobservable (and their uploader is never called)

set_status marks each phase (initializing / starting_workers / scanning / finishing / completed / interrupted / failed / error) but only assigns a field and calls logging.info. Its would-be uploader, upload_scan_status, is never invoked anywhere in the file — and would return immediately anyway because UPLOAD_NON_MATCH_DATA is False — so the phase, including the moment target enumeration begins, never reaches XDR or any file.

- **Control:** UPLOAD_NON_MATCH_DATA module constant, line 105 (bare literal, no env var) — moot, since nothing calls the uploader — default `False → status upload disabled`
- **Observe:** OBSERVABLE in logs/diagnostics_<run_id>.log — every transition emits `Scan status changed to: <status>` (xdr_yara_scanner.py:4531). A clean run reads initializing → starting_workers → scanning → finishing → completed; interrupted/error/failed appear on the abort paths. Note these statuses are still never transmitted anywhere — ScanStatusUploader.upload_scan_status has no caller — so the tenant-side equivalent remains the yara_scanner_scans_v3_<shard> lifecycle rows (initiated / running heartbeats / completed\|cancelled\|failed).
- **Source:** `ScanStatusUploader lines 4378-4455; dead gate at line 4395; set_status 4452-4455; call sites 6683, 6797, 6815, 6839, 6939, 7390, 7393, 7433, 7529`

### Mid-walk exception on a scan target silently abandons the rest of that tree and erases its per-target row

The per-target body of scan_system is wrapped in a try whose handler logs `Error scanning target <t>` and `continue`s. Because both `files_per_target[target] = target_files_found` and the `Target scan completed` statistics event sit AFTER the walk loop inside that same try (6919-6929), a failure anywhere in the traversal jumps past them: the target contributes no per-target row at all, while the files it already enqueued stay counted in files_scanned/files_skipped, and its remaining subtree is never visited. The handler does not set scan_failed and does not call _mark_scan_failed (unlike the outer critical handler at 6935-6939), so the run continues to the success path and reports `Scan completed successfully` / `SCAN COMPLETED SUCCESSFULLY` with scan_summary outcome="completed" — a partially-walked filesystem indistinguishable from a complete one in every summary artefact.

- **Control:** Not configurable — bare `except Exception: ... continue` at 6931-6933, no retry, no failure flag, no threshold — default `-`
- **Observe:** Count `Target scan completed:` entries in <scanner_dir>/logs/statistics_<run_id>.log — on a healthy, uncancelled run there is exactly one per element of the target list logged in the `Scan configuration established` entry ('targets'/'target_count', 6802-6813). Rule out a cancel first: the `if not self.scan_active: break` at 6843 also drops remaining targets. Fewer rows than target_count with outcome unchanged is the signature. The lost target names itself in <scanner_dir>/logs/scan_errors_<run_id>.log as `Error scanning target <path>: <exception>` (6932) — note the file is scan_errors_<run_id>.log, not errors_<run_id>.log (name built at 2113). Confirm the run still reads clean: `Scan completed successfully in ...` in system_<run_id>.log (7471-7474), `SCAN COMPLETED SUCCESSFULLY` in statistics_<run_id>.log (7478-7480), and "outcome": "completed" in scan_summary_<run_id>.json (derived 7617-7622, written 7632-7666) with no per-target field of any kind. The comprehensive report's scan_metadata.targets_scanned (6982) still lists the failed target, because self.scan_targets is assigned from the requested list before the walk (6800) — so that field claims a target that produced no row. To force it: make one target raise mid-walk (e.g. a target unmounted while the walk is in progress) alongside at least one healthy target.
- **Source:** `YaraScanner.scan_system: per-target loop 6842-6933; try opened 6850; walk 6871-6916; files_per_target assignment 6919; 'Target scan completed' statistics event 6921-6929; swallowing handler 6931-6933; outer critical handler that DOES mark failure 6935-6939; targets assigned to self.scan_targets 6800; success reporting 7471-7480 and 7533-7536; scan_summary outcome derivation 7617-7622 and write 7632-7666; caller's try around scan_system 7383-7394`

---

# Performance & Resource Management

*CPU governance, threading, queues, monitors.*

### CPU governor policy selector (headroom / budget / none)

Chooses which self-share policy bounds the scan. The governor measures only the scanner's OWN CPU share, never system load, so external load can shrink but never stall it — the opposite of the pre-3.x pause loop. "none" leaves CpuGovernor.enabled False, which disables both sampling and pacing entirely (low process priority still applies), so a policy=none run emits NO CPU_GOVERNOR telemetry at all.

- **Control:** CONFIG_CPU_GUARANTEE (line 174); env YARA_CPU_GUARANTEE (line 2712); options key cpu_guarantee (line 773); invalid value raises ValueError (lines 2713-2715) — default `headroom`
- **Observe:** scan_summary_<run_id>.json → "throttle_mode" (line 7648) and "cpu_governor"."policy" (line 7649); the same value in the throttle_mode column of every yara_scanner_scans_v3_* row (line 5239); posture string "cpu=headroom" in the returned SCAN_RESULT line (lines 2725-2730, 7536)
- **Source:** `CpuGovernor.__init__ (lines 1140-1155), ScanConfig (lines 2710-2715), YaraScanner.__init__ wiring (lines 5047-5053)`

### Headroom policy — always leave N% of the host free

Adaptive target: target = 100 - headroom_pct - max(0, others_pct), recomputed on every sample. A quiet machine yields a fast scan; a busy one shrinks the scanner instead of pausing it. `others` is derived as (system_pct - own_pct) and clamped at 0 (max(0.0,…) at 1175 and 1194), which is why external load can only pull the target down toward the floor, never below it.

- **Control:** CONFIG_CPU_HEADROOM_PCT (line 175); options key cpu_headroom_pct (line 773); assigned unvalidated at lines 2716-2717 — default `30`
- **Observe:** performance_<run_id>.log → CPU_GOVERNOR JSON lines carrying "target", "own", "others" (emitted at lines 6002-6003); the THROTTLE_CONFIG line records cpu_headroom_pct at startup (line 1099)
- **Source:** `CpuGovernor.compute_target (lines 1169-1179), CpuGovernor.update (lines 1181-1203)`

### Budget policy — fixed cap on the scanner's share

Ignores what everyone else is doing and holds the scan at a constant percentage of the whole machine. Predictable but wasteful on an idle host. The budget branch returns BEFORE the floor check, so cpu_floor_pct is inert under this policy and floor_hits never increments — a budget_pct below the floor is honoured as-is.

- **Control:** CONFIG_CPU_BUDGET_PCT (line 176); options key cpu_budget_pct (line 773); assigned at lines 2718-2719 — default `25`
- **Observe:** performance_<run_id>.log → CPU_GOVERNOR "target" stays constant across samples while "others" moves; scan_summary_<run_id>.json → cpu_governor.policy == "budget" and cpu_governor.floor_hits == 0
- **Source:** `CpuGovernor.compute_target budget branch (lines 1173-1174)`

### CPU floor — the anti-stall guarantee (headroom policy only)

When the headroom maths would drive the target below the floor, the target is pinned to floor_pct and a floor_hits counter increments (once per SAMPLE, so it is a sample count, not an event count). This is the structural reason the governor cannot reproduce the old 285s-of-347s stall: a saturated host slows the scan toward ~5% of the machine, it never stops it. It applies ONLY to the headroom policy — the budget branch returns first.

- **Control:** CONFIG_CPU_FLOOR_PCT (line 177); options key cpu_floor_pct (line 773); assigned at lines 2720-2721 — default `5`
- **Observe:** scan_summary_<run_id>.json → cpu_governor.floor_hits > 0 proves the floor engaged; CPU_GOVERNOR lines in performance_<run_id>.log show "target": 5.0 while "others" is high
- **Source:** `CpuGovernor.compute_target (lines 1175-1178), floor_hits init (line 1151), stats() (lines 1224-1233)`

### Process-CPU normalisation to a whole-machine share

psutil reports process CPU as a percentage of ONE core (a 4-thread scanner reads 400%), so the raw reading is divided by cpu_count before comparison with the target. Omitting this silently held the scanner to 1/N of the promised budget — the scan still completed and still reported success, just N times slower on bigger hosts. The denominator is os.cpu_count(), NOT the affinity mask, so on a Cortex-pinned Windows payload (measured 2 of 8 cores) the normalised "own" understates the share of the cores actually available.

- **Control:** Not configurable — the constructor's cpu_count argument is never passed at the call site (wiring at 5047-5053 omits it), so it falls back to os.cpu_count() at line 1146 — default `-`
- **Observe:** performance_<run_id>.log CPU_GOVERNOR "own" is a 0-100 whole-machine figure; cross-check against host_cores and cpu_affinity_count in the THROTTLE_CONFIG line (lines 1103-1104)
- **Source:** `CpuGovernor.normalise_own (lines 1157-1167), call in update (line 1193)`

### Sleep-ratio controller (proportional gain and runaway clamp)

An integrating controller: each sample adds GAIN x (own - target) to a persistent sleep_ratio, clamped to [0, RATIO_MAX]. RATIO_MAX=20 bounds the error term, but it does NOT by itself guarantee a ~5% duty floor: PACE_CAP_SECS caps each individual sleep at 1s, so the full 20:1 ratio is only realised for work chunks under ~50ms; a 2s match sleeps 1s, i.e. ~66% duty. The class comment on line 1137 still advertises the ~5% duty floor.

- **Control:** Not configurable — CpuGovernor.GAIN (line 1136) and RATIO_MAX (line 1137) are class-body literals with no env override — default `GAIN=0.05, RATIO_MAX=20.0`
- **Observe:** performance_<run_id>.log → CPU_GOVERNOR "ratio" field over time; scan_summary_<run_id>.json → cpu_governor.ratio at end of run
- **Source:** `CpuGovernor.update (lines 1196-1202)`

### Per-file proportional pacing (the actuator)

The only place the governor actually costs time: after each rules.match() on a file that got as far as matching, the worker sleeps work_secs x sleep_ratio, capped by PACE_CAP_SECS. Pacing AFTER the work (not gating before it) is what makes progress unconditional. Files rejected earlier in scan_file (missing, unreadable, special, junction-duplicate, non-regular, too large) never reach the pace call, so pacing is per-MATCH-ATTEMPT, not per-file-seen. The cap also defeats the docstring's claim (1208-1210) that the slowdown factor is stable regardless of file size.

- **Control:** Not configurable — CpuGovernor.PACE_CAP_SECS (line 1138) is a class-body literal — default `PACE_CAP_SECS=1.0`
- **Observe:** scan_summary_<run_id>.json → "total_paused_secs" (lines 7646-7647); total_paused_secs column on yara_scanner_scans_v3_* rows (line 5238); "cpu-slept Ns" in the SCAN_RESULT line returned to Action Center (line 7536)
- **Source:** `CpuGovernor.pace (lines 1205-1222), sole call site in scan_file (line 6161)`

### Governor sampling rate limit

CPU readings are refreshed at most once per interval no matter how many files stream past, so a scan of millions of tiny files does not pay a psutil call per file. Sampling is driven from the worker path (scan_file) and the blocked producer only — there is no dedicated governor thread — so a scan wedged on one huge file stops sampling and the ratio freezes at its last value. Two failure modes on the knob itself: it is read with a bare float() so a non-numeric value raises ValueError out of ScanConfig, and "0" is ACCEPTED (the `or 1.0` fallback only catches an empty string, and '0' is a truthy string), which disables the rate limit entirely — every scanned file then costs two psutil CPU reads.

- **Control:** config.throttle_check_interval_secs via env YARA_GOVERNOR_INTERVAL_SECS (lines 2866-2867, read with os.getenv + bare float(), NOT via _env_number — the only numeric knob in ScanConfig that bypasses that guard) — default `1.0`
- **Observe:** CPU_GOVERNOR lines in performance_<run_id>.log are spaced no closer than this interval (compare their "t" timestamps). With the var set to 0 they hit the 0.25-ratio/heartbeat emission cap instead of the sampling cap, and scan_rate_fps in scan_summary_<run_id>.json drops from the psutil overhead.
- **Source:** `YaraScanner._sample_governor (lines 5974-5979; interval gate 5977-5978), call sites at 6150 (worker) and 6073 (producer backoff)`

### Governor fail-open on unreadable CPU

If psutil raises while reading process or system CPU, the governor permanently disables itself for the rest of the run and the scan continues UNTHROTTLED rather than guessing — an explicit choice that a never-finishing scan is worse than a fast one. The same fail-open happens silently at construction: if psutil.Process() throws there, _governor_proc is None and _sample_governor returns immediately with no log line at all.

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → "CPU governor disabled - could not read CPU (...). Scan continues unthrottled." (lines 5985-5986); scan_summary_<run_id>.json shows total_paused_secs frozen at its pre-failure value and cpu_governor.ratio at its last value. The constructor variant is UNOBSERVABLE — it writes no line anywhere.
- **Source:** `YaraScanner._sample_governor except branch (lines 5983-5987), silent constructor path (lines 5056-5061, guard at 5974)`

### Governor telemetry: change-triggered plus heartbeat emission

A CPU_GOVERNOR line is written when the sleep ratio moves by >=0.25 OR when the heartbeat interval elapses. Change-only emission had produced a single line across a 15,516-file scan on an idle host — exactly the case a customer wants a time series for, so the heartbeat guarantees one. The heartbeat clock is only advanced by actual samples, so the cadence is a ceiling, not a promise: no sampling (idle workers, policy=none, a worker stuck inside one huge match) means no lines. The first sample always emits, because _last_governor_emit is None.

- **Control:** GOVERNOR_HEARTBEAT_SECS via env YARA_GOVERNOR_HEARTBEAT_SECS (line 322); the 0.25 ratio-change threshold is a bare literal (line 5997) — default `30 seconds; 0.25 ratio delta`
- **Observe:** performance_<run_id>.log → "CPU_GOVERNOR {…}" JSON lines, each with policy/target/own/others/ratio/slept_secs/floor_hits/t
- **Source:** `YaraScanner._sample_governor emission block (lines 5990-6003), CpuGovernor.stats() field list (lines 1224-1233)`

### psutil CPU sampler priming

psutil's first cpu_percent() call always returns 0.0, so both the process handle and the system-wide sampler are primed in the constructor (the system sampler twice — once beside the process priming, once in a later standalone block). Without priming the first governing window would run blind, and _log_progress would report 0.0% CPU forever.

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → the FIRST CPU_GOVERNOR line already carries a non-zero "own"/"others" pair on a busy host, and the first "System Resources \| CPU: …" line (LogManager.log_system_resources, lines 2254-2270, routed to the performance log by log_performance at 2270) has non-zero cpu_percent
- **Source:** `YaraScanner.__init__ priming (lines 5056-5061 and 5088-5091), reuse in _log_progress (lines 6528-6533)`

### THROTTLE_CONFIG startup header in the performance log

One JSON line written before scanning that records the whole resource posture — priority tier, governor policy and percentages, sample interval, platform, host_cores, cpu_affinity_count, cpu/io priority. It exists so a run's throttle behaviour can be interpreted from one file without cross-referencing others. It is emitted inside a bare try/except that swallows failures (1108-1109), so an absent line proves nothing on its own, and it is not necessarily the first line of the log — LogManager and other early writers can precede it.

- **Control:** Not configurable (emitted whenever a log_manager is passed to _apply_light_process_priority — the only caller does, line 7207) — default `-`
- **Observe:** performance_<run_id>.log → a line beginning "THROTTLE_CONFIG {"; with priority_tier == "standard" on every current build (the caller passes that literal at 7207)
- **Source:** `_apply_light_process_priority (lines 1090-1109)`

### Below-normal process priority and I/O priority demotion

Best-effort scheduler demotion so interactive work wins: BELOW_NORMAL_PRIORITY_CLASS on Windows, nice raised to at least 10 on POSIX (max(current,10) — never lowered below the inherited value), plus ionice best-effort class 7 on Linux only. Every call is wrapped so a failure can never fail the scan; each failure is recorded as a *_error key in the same log payload instead.

- **Control:** Not configurable at runtime — run() hardcodes throttle_mode="standard" (line 7207); the function's own default is "script" (line 1013) but no caller uses it — default `below_normal / nice=10 / best_effort:7 (io_priority key absent entirely on Windows and macOS)`
- **Observe:** system_<run_id>.log → "Applied process priority tuning" with data.cpu_priority and (Linux only) data.io_priority (logged at line 1091); performance_<run_id>.log THROTTLE_CONFIG carries the same two fields (lines 1105-1106)
- **Source:** `_apply_light_process_priority (lines 1026-1065), sole call site (line 7207)`

### DEAD CODE: idle-tier ("os") priority branch

**⚠ OBSERVABILITY GAP**  
A whole alternative tier — IDLE_PRIORITY_CLASS + PROCESS_MODE_BACKGROUND_BEGIN on Windows, nice 19 + IOPRIO_CLASS_IDLE on Linux — is fully implemented but unreachable: the only caller passes the literal "standard", so os_mode is never True. It was retired after measuring 252s vs 77s starvation on a saturated 8-core host (the rationale is in the comment at 7205-7206).

- **Control:** Not configurable — the only caller passes a literal (line 7207); the retired throttle_mode option is mapped away by migrate_throttle_option (lines 784, 787-797) before it can reach here — default `unreachable`
- **Observe:** UNOBSERVABLE: no artefact can ever show it, because the branch cannot execute. The tell would be data.cpu_priority == "idle" in system_<run_id>.log; confirming requires editing line 7207. What IS observable is the negative: THROTTLE_CONFIG priority_tier == "standard" on every run.
- **Source:** `_apply_light_process_priority os_mode flag (line 1024) and branches (lines 1030-1038, 1046-1047, 1058-1060)`

### CPU affinity capture (Cortex agent core pinning)

Records the process's allowed core set at startup. This matters because the Cortex XDR agent pins Windows payload processes to a SUBSET of cores (measured: 2 of 8), which changes what CPU percentages mean — and the governor divides by os.cpu_count(), not by this count, so without it throttle behaviour on Windows is inexplicable from the logs. Three outcomes: success records cpu_affinity + cpu_affinity_count; on macOS psutil has no cpu_affinity() so the AttributeError path records "unrestricted" and falls back to the host core count; any other Exception records cpu_affinity_error and leaves cpu_affinity_count absent.

- **Control:** Not configurable — default `-`
- **Observe:** system_<run_id>.log → "Applied process priority tuning" data.cpu_affinity / data.cpu_affinity_count (or data.cpu_affinity_error); also cpu_affinity_count in the THROTTLE_CONFIG line (line 1104)
- **Source:** `_apply_light_process_priority (lines 1078-1088)`

### host_cores recorded outside the affinity try-block

os.cpu_count() is captured BEFORE the affinity probe specifically because the governor's own-share maths is (process_cpu / cpu_count); when it lived inside the same try, every macOS run recorded host_cores=null and the CPU telemetry became uninterpretable. The rationale is spelled out in the comment at 1072-1076.

- **Control:** Not configurable — default `-`
- **Observe:** system_<run_id>.log priority-tuning data.host_cores (recorded at line 1077); THROTTLE_CONFIG "host_cores" (line 1103); also "cpu_count" inside the COMPREHENSIVE SCAN REPORT data blob in statistics_<run_id>.log (line 7014) — but that blob is JSON-truncated at 4000 chars (lines 2176-2178), so on a scan with a large skip_breakdown system_info.cpu_count can be cut off; the THROTTLE_CONFIG copy is the reliable one
- **Source:** `_apply_light_process_priority (line 1077), report field (line 7014)`

### Worker thread count and the auto (cores // 2) mode

Sets the scan thread pool. The old hard cap of 2 was removed but 2 remains the default because measurement said more is SLOWER on disk-bound work (8-core Linux, /usr, 93k files: 2 workers = 71s, 4 = 93s, 8 = 101s — recorded in the comment at 178-183). A value of 0 means auto = max(2, cores // 2) — and this only works via the constant/option: _env_number's minimum=1 rejects YARA_THREADS=0 and falls back to the constant, so an operator setting the env var to 0 gets 2 workers, not auto.

- **Control:** CONFIG_WORKERS (line 184); env YARA_THREADS (line 2838); options key workers (line 774); auto resolution at line 2839 — default `2`
- **Observe:** system_<run_id>.log → "YaraScanner initialized with N workers" (data.max_workers, lines 5093-5101) and one "Worker ScanWorker-N started" per thread (line 5877); init_data.max_workers in both the "YARA Scanner initialization completed" (7321) and "YARA Scanner initialized successfully" (7341) entries, field at line 7305; "worker_threads_used" in the COMPREHENSIVE SCAN REPORT (line 7015)
- **Source:** `ScanConfig (lines 2837-2839), thread spawn loop (lines 6818-6821)`

### Worker pool startup and naming

Threads are spawned as daemons named ScanWorker-1..N and the startup cost is timed separately, so a host where thread creation itself is slow is distinguishable from a slow scan.

- **Control:** Not configurable (daemon=True hardcoded, line 6819) — default `-`
- **Observe:** performance_<run_id>.log → "Worker thread startup completed in X.XX seconds" with data.worker_startup_time_seconds and data.workers_started (lines 6824-6827)
- **Source:** `scan_system (lines 6816-6827)`

### Bounded scan queue (the memory ceiling for file discovery)

The producer-consumer queue is bounded to workers x 2 by default — just 4 slots — which is what stops a full-system walk from materialising millions of paths in RAM. The tiny default means the walker spends most of a scan blocked in backpressure rather than racing ahead.

- **Control:** YARA_QUEUE_SIZE env var (lines 2840-2842); floor of 2 enforced twice (max(2, …) at 2840 plus _env_number minimum=2 at 2841) — default `max_workers * 2 (= 4 at default workers)`
- **Observe:** the "YARA Scanner initialization completed" entry in system_<run_id>.log → init_data.scan_queue_size (field at line 7306); live queue depth appears as "Queue: N" in every "Scan Progress" line in statistics_<run_id>.log (lines 2229-2232)
- **Source:** `ScanConfig (lines 2840-2842), Queue construction (line 5028)`

### Producer backpressure — block, never drop

When the queue is full the directory walker retries put() (1s timeout + queue_backoff_secs sleep) instead of discarding paths, so coverage is never silently lost. It is not literally forever: the retry loop is `while self.scan_active` (6061), so a cancel breaks it and _enqueue_scan_path returns False (6078), which aborts the current directory's file loop (6913-6914). The side effect is that the walker can be parked for long stretches, which is precisely why the dataset heartbeat had to be moved onto its own thread.

- **Control:** YARA_QUEUE_BACKOFF_SECS (line 2868); the put() timeout of 1.0s is a literal (line 6063) — default `0.25 seconds`
- **Observe:** performance_<run_id>.log → "Scan queue saturated (N items) - backing off producer"; correlate with a flat "Queue: 4" in statistics_<run_id>.log Scan Progress lines
- **Source:** `YaraScanner._enqueue_scan_path (lines 6059-6078), caller break at 6913-6914`

### Queue-saturation event counter with 1-in-25 log sampling

Counts every Full exception but logs only every 25th (n % 25 == 1, so the 1st, 26th, 51st…), giving a proportional trail without flooding the performance log. The counter itself is incremented without a lock — safe only because a single producer thread walks.

- **Control:** Not configurable (the 25 is a literal, line 6067) — default `-`
- **Observe:** performance_<run_id>.log → count the "Scan queue saturated" lines and multiply by 25 for an order-of-magnitude backpressure figure. The raw queue_full_events counter is never written to any artefact (init line 5064, increment 6066, read only by the sampling gate at 6067).
- **Source:** `YaraScanner._enqueue_scan_path (lines 6066-6071)`

### Governor sampling from the blocked producer

While backing off on a full queue the producer refreshes the CPU reading but deliberately does NOT pace — it holds no unit of work for a proportional sleep to be based on (the reason is stated in the comment at 6071-6072). This keeps the governor's readings (and therefore its telemetry) fresh during long stalls that would otherwise starve it of samples.

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → CPU_GOVERNOR lines continue at the heartbeat cadence during a stretch where "Scan queue saturated" lines are being emitted
- **Source:** `YaraScanner._enqueue_scan_path (lines 6071-6074)`

### Worker queue-get timeout and cooperative exit checks

Each worker blocks at most 5 seconds on the queue, so scan_active going false is observed within one timeout window even on an empty queue. This bounds cancel latency on the consumer side (the walker side is bounded separately by _walk_cancellable). A worker already inside rules.match() on a large file is NOT bounded by this — it finishes that file first.

- **Control:** Not configurable — 5.0 is a literal (line 5882); the named constant intended for this (WORKER_GET_TIMEOUT_SECS, line 132) is never read — default `5.0 seconds`
- **Observe:** system_<run_id>.log → "Worker ScanWorker-N stopped" entries with data.files_processed (lines 5927-5934) appear within ~5s of the "Cancellation requested (source=…)" entry (line 5125); performance_<run_id>.log "Worker cleanup: N stopped, M timed out in X.Xs" (lines 6724-6726)
- **Source:** `YaraScanner._worker loop (lines 5880-5885), stop log (lines 5927-5934)`

### DEAD CONSTANT: WORKER_GET_TIMEOUT_SECS

**⚠ OBSERVABILITY GAP**  
Documented as the queue.get timeout that allows graceful exit checks, but it is referenced nowhere — the worker hardcodes 5.0. Editing this constant changes nothing, and it disagrees with the real value by 2.5x, which is a live support trap.

- **Control:** WORKER_GET_TIMEOUT_SECS (line 132) — defined, never read — default `2.0 (inert)`
- **Observe:** UNOBSERVABLE: no artefact reflects it. To verify, grep the file for the symbol — it appears only at its definition; the real value in effect is the 5.0 literal at line 5882.
- **Source:** `Definition at line 132; actual timeout at line 5882`

### DEAD CONSTANT: CANCEL_DRAIN_DEADLINE_SECS

**⚠ OBSERVABILITY GAP**  
Advertised as the graceful cancel budget and exposed as YARA_CANCEL_DEADLINE_SECS, but never read anywhere in the file. The real cancel-path budgets come from the uploader drain scaling (ResultsUploader.stop / LookupDatasetUploader.stop) and the fixed worker join timeouts (5s each).

- **Control:** CANCEL_DRAIN_DEADLINE_SECS / env YARA_CANCEL_DEADLINE_SECS (line 312) — defined, never read — default `30 (inert)`
- **Observe:** UNOBSERVABLE: setting the env var changes no timing in any log. Actual cancel-to-exit timing is visible from the gap between the "Cancellation requested (source=…)" entry in system_<run_id>.log (line 5125) and "Enhanced cleanup completed in X.X seconds" (line 6767).
- **Source:** `Definition at line 312; no other reference in the file`

### Sentinel-based worker shutdown with bounded joins

One None sentinel per worker is pushed (1s timeout each, failures swallowed), then each thread is joined for 5s. Worst case shutdown is workers x 5s, and threads that miss their join are named and abandoned rather than blocking the run — the scan still finishes and still reports. A swallowed sentinel put (full queue) is why the join can time out at all.

- **Control:** Not configurable (put timeout 1.0 at line 6697; join timeout 5 at line 6710; the log line still advertises "max 30 seconds" at line 6701, which contradicts the real workers x 5s budget) — default `-`
- **Observe:** performance_<run_id>.log → "Worker cleanup: N stopped, M timed out in X.Xs" (lines 6724-6726); scan_errors_<run_id>.log → "Worker thread <name> did not finish - continuing anyway" and "Threads did not terminate: [...]" when M > 0 (lines 6713, 6721)
- **Source:** `_perform_enhanced_cleanup (lines 6695-6726)`

### Per-worker throughput logging every 100 files — and why its Error Rate is structurally 0.0%

Each worker emits a rolling average processing time and an error rate every 100 files it SCANNED. Three traps in the one log line. (1) files_processed advances only for successfully scanned files (5889-5891), so a heavily-skipped run never satisfies `files_processed % 100 == 0 and files_processed > 0` and emits no Worker Performance record at all. (2) The averaged timings come from worker_processing_times, appended in scan_file's finally for EVERY file including skips (6233) and trimmed to the last 100 (6234-6235) — so the average is a last-100-files figure over a different population than the counter beside it. (3) error_rate is (errors_encountered / files_processed) x 100, and errors_encountered increments in exactly one place: the worker loop's generic except at 5915, which fires only on a crash in the queue plumbing. Real per-file failures are RETURNED from scan_file as (False, reason) and counted into skip_reasons instead (5894-5896), so Error Rate reads 0.0% even on a scan where thousands of files raised yara.Error or OSError.

- **Control:** Not configurable (the 100-file cadence is a literal, line 5899) — default `-`
- **Observe:** performance_<run_id>.log → "Worker Performance \| ScanWorker-N \| Files: … \| Avg Time: …ms \| Error Rate: …%" with data.worker_id/files_processed/avg_processing_time_ms/error_rate_percent (message built at 2246-2252). The honest signals live elsewhere: statistics_<run_id>.log's "Skip reasons: …" record (6641-6646) whose data.skip_breakdown holds the real per-file failures, and system_<run_id>.log's "Worker <id> stopped" record (5927-5934) carrying files_processed and errors_encountered side by side for direct comparison.
- **Source:** `YaraScanner._worker (lines 5899-5905; counters init 5874-5875, scanned/skipped split and skip_reasons 5888-5896, the only errors_encountered increment 5915, stop record 5927-5934), scan_file failure return 6228, ring-buffer append/trim 6233-6235, LogManager.log_worker_performance (lines 2236-2252)`

### Per-worker timing ring buffer capped at 100 samples — and the end-of-run summary that reports its length as a file count

worker_processing_times keeps only the last 100 durations per worker, bounding memory on a multi-million-file scan. The consequence is a lying statistic: _log_final_results builds worker_summary with files_processed = len(that list) (6654), so the end-of-run summary reports at most 100 files per worker whether the worker handled 100 or 4 million, and avg_processing_time_ms is a last-100 average rather than the whole-scan mean it appears to be. It is the ONLY per-worker figure in that performance record, so there is no correct per-worker throughput anywhere in it.

- **Control:** Not configurable (the 100-sample bound is a bare literal in scan_file's finally block, lines 6234-6235) — default `100 samples`
- **Observe:** performance_<run_id>.log → "Worker performance summary: N workers processed files" record (lines 6657-6660), data.worker_details.<worker>.files_processed — a value pinned at exactly 100 confirms the trim is active; contrast with the truthful per-worker count in the "Worker ScanWorker-N stopped" entry in system_<run_id>.log (data.files_processed, lines 5927-5934, fed by the real counter at 5891) and with scan_summary_<run_id>.json files_scanned (line 7637) for the true total
- **Source:** `scan_file finally block (lines 6229-6235), summary construction (lines 6648-6655), log_performance call (lines 6657-6660)`

### Progress heartbeat thread (whole-scan progress telemetry)

A dedicated thread calls _log_progress on a fixed interval for the whole scan — it is now the ONLY caller of _log_progress. It exists because progress logging used to be an inline check in the discovery walk, which finishes long before the workers do; in the XSIAM twin, zero "Scan Progress" events had ever been recorded on any host under the inline-only design (docstring 6663-6671). Because the loop is `while not stop.wait(interval)`, the first tick is delayed a full interval, so a scan shorter than log_interval emits nothing.

- **Control:** config.log_interval via env YARA_PROGRESS_LOG_SECS (line 2850); clamped to >=1s because wait(0) would busy-spin and re-take lock_counts continuously (rationale in the comment at 2843-2849) — default `30 seconds`
- **Observe:** statistics_<run_id>.log → repeated "Scan Progress \| Files: … \| Detections: … \| Queue: N \| Rate: … files/sec" lines roughly every 30s (message built at 2229-2232)
- **Source:** `_progress_heartbeat (lines 6662-6678), thread start (lines 6829-6833), stop/join (lines 6731-6734)`

### Progress snapshot holds lock_counts across psutil calls

The entire _log_progress body — psutil CPU, memory, io_counters and net_io_counters reads plus the stats update — runs inside `with self.lock_counts`, the same lock every worker takes after each file. Every heartbeat therefore briefly blocks the whole pool; at the 30s default this is negligible, at a 1s interval it is a measurable throughput tax.

- **Control:** Not configurable (lock scope opens at line 6516); frequency governed by config.log_interval (line 2850) — default `-`
- **Observe:** Compare scan_rate_fps in scan_summary_<run_id>.json (line 7644) across runs with YARA_PROGRESS_LOG_SECS=30 vs =1 on the same target; the Scan Progress line cadence in statistics_<run_id>.log confirms which interval was in force
- **Source:** `YaraScanner._log_progress (lines 6514-6596)`

### Progress sampler reuses the primed psutil handle

_log_progress reuses the governor's long-lived Process object (falling back to its own primed _progress_proc) instead of constructing a fresh psutil.Process each tick, which would report 0.0% CPU forever. Latent until the progress heartbeat existed; now it would be the norm for every tick of the scan (rationale in the comment at 6522-6527).

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → "System Resources \| CPU: X.X% \| Memory: …MB \| Disk I/O: …MB \| Network: …MB" lines show non-zero CPU from the first tick (the handle was primed in __init__)
- **Source:** `YaraScanner._log_progress (lines 6528-6533)`

### Per-tick disk I/O guarded for macOS  <sub>darwin</sub>

process.io_counters() does not exist on macOS; unguarded it aborted the whole metrics block, zeroing memory and network too (which do work there) and logging an error every tick. It is now caught narrowly — AttributeError, NotImplementedError and psutil.AccessDenied — and disk_io_mb simply reports 0. AccessDenied also matters on hardened Windows/Linux hosts, though the zeroing consequence was macOS-specific.

- **Control:** Not configurable — default `disk_io_mb = 0 on macOS`
- **Observe:** performance_<run_id>.log on a macOS endpoint → "System Resources" lines with Disk I/O: 0.0MB but non-zero Memory and Network, and NO recurring "Error collecting system metrics" entry (line 6555) in scan_errors_<run_id>.log
- **Source:** `YaraScanner._log_progress (lines 6540-6545)`

### ETA and completion-time estimation

Derives current rate, a rolling average rate and an ETA from a total-files estimate of (scanned + skipped + queue_size x 2). Because the queue is only 4 deep, that estimate is essentially "work done so far + 8" — so the ETA is structurally optimistic and never converges. The 'average_rate' leg is additionally dead on a stock endpoint: it reads performance_history, which stays empty unless YARA_ENABLE_PERF_MONITOR is on.

- **Control:** Not configurable (estimate formula at line 6565; the 300s/5s window arithmetic at lines 2025-2026) — default `-`
- **Observe:** statistics_<run_id>.log → "Time Estimates \| ETA: … \| Rate: … files/sec \| Remaining: N files" (message built at lines 2284-2288); the same numbers appear as performance_summary.scan_estimates inside the COMPREHENSIVE SCAN REPORT (via get_current_stats_for_upload, line 2073) and the "SCAN COMPLETED" statistics entry. NOT in scan_summary_<run_id>.json — that record (lines 7632-7666) has no scan_estimates field.
- **Source:** `_log_progress (lines 6565-6596), StatisticsManager.calculate_time_estimates (lines 2006-2030)`

### Scan-lifecycle heartbeat thread (dataset 'running' rows)

An independent thread polls every HEARTBEAT_THREAD_POLL_SECS and emits a 'running' lifecycle row plus a running.json refresh once SCANS_HEARTBEAT_SECS has elapsed. It was split out from the walker loop precisely because _enqueue_scan_path backpressure could park the walker past the quiet period after which tooling treats a scan as abandoned (docstring 5264-5274). _last_heartbeat is primed to scan start (line 6773), so the first 'running' row is one full SCANS_HEARTBEAT_SECS (10 min) in — a shorter scan produces only 'initiated' and a terminal row.

- **Control:** SCANS_HEARTBEAT_SECS / env YARA_HEARTBEAT_SECS (line 307) gates emission; HEARTBEAT_THREAD_POLL_SECS / env YARA_HEARTBEAT_POLL_SECS (line 318) is the poll cadence — default `600s emission, 30s poll`
- **Observe:** yara_scanner_scans_v3_<shard>_<YYYYMM> rows with status="running", message="heartbeat", carrying live files_scanned / files_skipped / elapsed_secs / total_paused_secs (row fields at lines 5231-5238); and control/running.json under scanner_dir with a moving "updated_at" (lines 5188, 2734)
- **Source:** `_start_heartbeat_thread (lines 5263-5278), _heartbeat_worker (lines 5280-5286), _maybe_heartbeat (lines 5249-5261)`

### Heartbeat gate is lock-protected against duplicate rows

_maybe_heartbeat is called from BOTH the walker loop and the heartbeat thread, so the check-and-set on _last_heartbeat runs under _heartbeat_lock — otherwise two overlapping callers could both pass the gate and emit duplicate 'running' rows into the dataset. The lock covers only the gate; the marker write and row emission at 5260-5261 run unlocked, which is safe only because the gate already serialised entry.

- **Control:** Not configurable — default `-`
- **Observe:** yara_scanner_scans_v3_* → count rows with status="running" for one run_id; they should be spaced by SCANS_HEARTBEAT_SECS with no same-second pairs
- **Source:** `_heartbeat_lock init (line 5084), gate (lines 5255-5259), walker call site (line 6916), thread call site (line 5283)`

### Paused-seconds accounting on every lifecycle row

Every scans-dataset row snapshots cpu_governor.slept_total under lock_throttle alongside the file counters under lock_counts, so an operator can see the CPU promise being kept mid-scan rather than only at the end.

- **Control:** Not configurable — default `-`
- **Observe:** total_paused_secs column on yara_scanner_scans_v3_* rows, running and terminal (line 5238); "total_paused_secs" in scan_summary_<run_id>.json (lines 7646-7647); "cpu-slept Ns" in the SCAN_RESULT string (line 7536)
- **Source:** `_emit_scan_row (lines 5204-5247; counter snapshot 5213-5216, paused snapshot 5217-5218, field 5238), summary write (lines 7646-7647)`

### Vestigial lock_throttle

**⚠ OBSERVABILITY GAP**  
lock_throttle is created and taken in exactly one place, to read a single float that CpuGovernor already guards with its own lock. It is a leftover of the removed pause loop; it costs nothing but implies a pause-accounting critical section that no longer exists — and the comment above it still describes 'the pause loop'.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE: no artefact distinguishes it. The lock's only effect would be visible as contention, and it is taken at most once per lifecycle row. Removal would change no output.
- **Source:** `Lock creation (line 5022), only acquisition (lines 5217-5218), stale comment (lines 5210-5212)`

### Cancel-flag watcher poll thread

A daemon thread polls control/cancel.flag on a fixed cadence and drives the cooperative shutdown, reading the flag's JSON for a cancel source. Before starting it, a flag whose mtime predates process start (minus a coarse-FS tolerance) is removed so a stale flag from a previous run cannot kill a fresh scan, while a flag delivered during the slow rule-compile phase is deliberately preserved — the baseline is _process_started_at (line 5075), taken before rule compilation.

- **Control:** CANCEL_POLL_SECS / env YARA_CANCEL_POLL_SECS (line 311); CANCEL_STALE_TOLERANCE_SECS (line 319, bare literal — no env var, unlike its neighbours) — default `5 second poll; 2.0s mtime slack`
- **Observe:** system_<run_id>.log → "Removed stale cancel flag from a previous run" (line 5142) and/or "Cancellation requested (source=…)" (line 5125); scan_summary_<run_id>.json → outcome="cancelled" with "cancel_source" (lines 7617-7618, 7654)
- **Source:** `_start_cancellation_watcher (lines 5129-5150), _cancellation_watcher (lines 5152-5171), baseline (line 5075)`

### Stack-driven cancellable directory walk

os.walk is replaced by an explicit-stack scandir traversal so scan_active is checked before every directory and between entries. With os.walk, both workers stopped 4.45s after a cancel on C:\ but the process took a further 50s to exit inside the generator — and running.json went stale, making `cancel` report "scanner running: no" during a live scan. It also reproduces os.walk's followlinks=False semantics: symlinked dirs are listed under dirnames but not descended (6036-6040, 6054-6057), and dirnames is read AFTER the yield so caller-side pruning still works.

- **Control:** Not configurable — default `-`
- **Observe:** Wall-clock gap between the "Cancellation requested" entry in system_<run_id>.log (line 5125) and "Enhanced cleanup completed in X.X seconds" in the same log (line 6767); control/running.json is removed by _remove_running_marker AFTER cleanup returns (line 6946)
- **Source:** `YaraScanner._walk_cancellable (lines 6005-6057), call site (line 6871)`

### StatisticsManager background performance sampler

A 5-second-interval daemon thread building PerformanceSnapshot objects (process CPU, RSS, delta disk I/O, delta network, system CPU). It is OFF by default — the env flag defaults to "false" — so on a stock endpoint performance_metrics in every report is all zeros, current_performance is null, and the ETA's average_rate leg is dead.

- **Control:** config.enable_performance_monitoring via env YARA_ENABLE_PERF_MONITOR (lines 2851-2853); the 5s sleep is a literal (line 1885) — default `false (disabled)`
- **Observe:** statistics_<run_id>.log → "Performance monitoring thread started" (line 1868) vs "Performance monitoring disabled in light profile" (line 1863) — both reachable, since start_monitoring is called unconditionally from __init__ (line 1854) and again from run() (line 7367); when on, performance_<run_id>.log gains "Performance Snapshot \| CPU: … \| Memory: … \| Queue: … \| Workers: …" lines
- **Source:** `StatisticsManager.start_monitoring (lines 1860-1868), _monitoring_worker (lines 1870-1891), ScanConfig flag (lines 2851-2853)`

### Performance history ring buffer and peak/average metrics

Snapshots are held in a deque capped at 1000 (~83 minutes at the 5s cadence), and peak/avg CPU and memory are recomputed over the WHOLE retained window on every sample — an O(n) pass per tick that grows to 1000 elements, then stays flat.

- **Control:** Not configurable (maxlen=1000 literal, line 1787) — default `1000 snapshots`
- **Observe:** statistics_<run_id>.log → the COMPREHENSIVE SCAN REPORT entry's performance_summary.performance_metrics.peak_cpu_percent / peak_memory_mb / avg_* (non-zero only when perf monitoring is enabled), and the "COMPREHENSIVE STATISTICS SUMMARY" block's Performance Metrics JSON reporting samples_collected (line 2040). NOT in scan_summary_<run_id>.json — that record (7632-7666) has no performance_metrics field.
- **Source:** `deque init (line 1787), _update_performance_metrics (lines 1949-1965), log_comprehensive_stats (lines 2032-2059)`

### Sampled performance-detail logging (1 in 6 snapshots)

Only every sixth snapshot is written to the performance log — about one detailed line every 30 seconds at the 5s sampling rate — so enabling the monitor does not multiply log volume by six. But the test is len(performance_history) % 6, and that length stops changing once the deque saturates at maxlen=1000, so detailed snapshot logging silently ceases after roughly 83 minutes of monitoring (1000 % 6 == 4, so the gate never fires again).

- **Control:** Not configurable (the 6 is a literal, line 1882) — default `-`
- **Observe:** performance_<run_id>.log → "Performance Snapshot \|" lines spaced ~30s apart when YARA_ENABLE_PERF_MONITOR is on — and stopping altogether after ~83 minutes
- **Source:** `StatisticsManager._monitoring_worker (lines 1882-1883), _log_performance_details (lines 1967-1976)`

### Snapshot enrichment with live scanner counters

update_scanner_stats mutates the MOST RECENT snapshot in place with files_scanned, detections, queue_size and active_workers. When the performance monitor is disabled the history is empty, so this call silently does nothing — a data condition, not a flag check — which is why queue/worker figures in the final report read 0 on a default endpoint.

- **Control:** Gated in effect by the same YARA_ENABLE_PERF_MONITOR flag (lines 2851-2853) — the method itself has no gate, it simply no-ops on an empty deque (guard at line 1981) — default `no-op by default`
- **Observe:** the COMPREHENSIVE SCAN REPORT / "SCAN COMPLETED" entries in statistics_<run_id>.log → performance_summary.current_performance is null on a default run (produced by get_current_stats_for_upload, line 2074); with the monitor enabled it carries queue_size and active_workers. Never present in scan_summary_<run_id>.json.
- **Source:** `StatisticsManager.update_scanner_stats (lines 1978-1986), call site (lines 6561-6563), null field (line 2074)`

### SystemResourceMonitor thread (host-level resource sampling)

A second, separate monitoring thread sampling every 10s and writing a rich snapshot to the performance log every 45s: process CPU/RSS/threads/FDs plus system memory, disk usage, load averages and network deltas. Also disabled by default, and it is created inside scan_system rather than at construction — so when the flag is off the object is never built and its own 'disabled in light profile' branch (line 2416) is unreachable in practice.

- **Control:** config.enable_resource_monitoring via env YARA_ENABLE_RESOURCE_MONITOR (lines 2854-2856); monitoring_interval=10 and upload_interval=45 are literals (lines 2377-2378) — default `false (disabled)`
- **Observe:** system_<run_id>.log → "System resource monitoring started" (line 2423) when enabled; when on, performance_<run_id>.log gains "System resources - CPU: …%, Memory: …MB" every ~45s with a full nested data blob (lines 2579-2582). Absence of any such line is the only evidence of the disabled state; the positive evidence is resource_monitoring: false in the "All monitoring systems activated" record (lines 6785-6795).
- **Source:** `SystemResourceMonitor.__init__ (lines 2369-2411), start_monitoring (lines 2413-2423), _monitoring_worker (lines 2425-2446), instantiation gate (lines 6780-6782)`

### Resource alert thresholds (CPU / memory / disk)

Each 10s sample is checked against fixed thresholds and a breach is written as an ERROR-level entry plus retained in an alert history. The CPU threshold is compared against PROCESS cpu_percent, which psutil reports per-core — on a multi-core host a 2-thread scanner can read >90% without being anywhere near 90% of the machine (the governor normalises this; the alert path does not). The disk check reads '/' only (line 2475), so a full Windows D: drive is invisible.

- **Control:** Not configurable — alert_thresholds dict literals: cpu_percent 90 (line 2380), memory_percent 85 (line 2381), disk_usage_percent 95 (line 2382) — default `90 / 85 / 95`
- **Observe:** scan_errors_<run_id>.log → "RESOURCE ALERT: high_cpu - 93.4% exceeds threshold of 90%" with data.alert_type/current_value/threshold (message and payload at lines 2548-2557); the count also appears as resource_summary.alerts_triggered in the COMPREHENSIVE SCAN REPORT (via line 7025) and in the "Resource monitoring completed: N snapshots, M alerts" performance line (lines 2668-2673)
- **Source:** `_check_resource_alerts (lines 2522-2564)`

### Resource and alert history ring buffers

resource_history is capped at 360 samples (exactly one hour at the 10s cadence) and alert_history at 100, bounding the monitor's memory regardless of scan length. The summary then reports monitoring_duration_seconds as len(history) x monitoring_interval, which is capped at 3600 and therefore understates any scan longer than an hour.

- **Control:** Not configurable (maxlen literals, lines 2385-2386) — default `360 / 100`
- **Observe:** statistics_<run_id>.log COMPREHENSIVE SCAN REPORT → resource_summary.data_points_collected (capped at 360, line 2640) and monitoring_duration_seconds (capped at 3600, line 2639), reaching that report via upload_final_comprehensive_report line 7025; alerts_triggered from the alert deque; the same dict is echoed in performance_<run_id>.log by "Resource monitoring completed: …" (lines 2668-2673). NOT a field of scan_summary_<run_id>.json.
- **Source:** `deque init (lines 2385-2386), get_resource_summary (lines 2629-2659), stop_monitoring echo (lines 2668-2673)`

### Resource trend classification

Computes 'ten-minute' average CPU/memory and labels each as increasing/decreasing/stable using a crude endpoint slope over the retained window (thresholds: >2 for CPU, >5 MB for memory; needs >=5 samples, else both stay 'stable'). The recent_cutoff variable is computed and then never used — the next line filters on the presence of the 'process' key instead — so the "10min" averages actually span the whole retained history (up to an hour).

- **Control:** Not configurable (slope thresholds are literals at lines 2612/2614 and 2618/2620) — default `-`
- **Observe:** performance_<run_id>.log → the ~45s "System resources - CPU: …" entries carry data.trends.cpu_trend / memory_trend / cpu_avg_10min / memory_avg_10min / data_points
- **Source:** `_calculate_resource_trends (lines 2587-2627), unused cutoff (line 2593), unfiltered selection (line 2594)`

### Resource monitor stopped AFTER worker join, not at discovery end

The progress heartbeat, the resource monitor and the statistics monitor are all stopped only after the worker threads have drained the queue. Stopping them where cleanup begins (when file discovery ends) was cutting resource telemetry off for most of the real scan duration on a large scan — the reasoning is recorded in the comments at 6688-6692 and 6728-6730.

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → "Resource monitoring completed: N snapshots, M alerts" appears AFTER "Worker cleanup: …" (line 6724) in file order; the last "Scan Progress" line in statistics_<run_id>.log likewise post-dates discovery
- **Source:** `_perform_enhanced_cleanup ordering (comment lines 6688-6692; worker join 6708-6726; heartbeat stop 6728-6734; monitors stopped 6736-6741)`

### File-descriptor sampling every 1000 CLEAN scanned files  <sub>linux, darwin</sub>

When enabled, every 1000th scanned file triggers a num_fds() read and logs if FDs grew by more than 100 over the startup baseline or exceeded 900 absolute. Four traps. The counter sits AFTER the `if matches: … return True` branch at 6187 and after every early `return False`, so it advances only for files that were scanned AND did not match — on a storm scan or a heavily-skipped target the leak check effectively stops sampling, and a run with 0 files_scanned produces nothing. It is incremented from all workers without a lock, so the interval is approximate. Both 'warnings' are ordinary log_system INFO lines, not warnings. And both psutil reads sit inside nested bare `except Exception: pass` (6210-6211, 6213-6214), so any failure is silent.

- **Control:** self.fd_check_interval = 1000 (line 5000), a bare instance literal; gated by self.fd_monitoring_enabled from config.monitor_fd_usage (line 4998), which only the YARA_ENABLE_FD_MONITOR path sets; thresholds 100 and 900 are literals (lines 6201, 6206) — default `1000 clean files; +100 delta / 900 absolute thresholds`
- **Observe:** system_<run_id>.log → "FD usage increased by N (current: M)" (line 6203) and "WARNING: High FD usage: N" (line 6208). The number of SAMPLES is bounded by (files_scanned - files_that_matched) / 1000, so on a run whose scan_summary_<run_id>.json shows high `matches` relative to `files_scanned` the lines drop off sharply — that is the observable proof of the placement bias. On Windows, no lines regardless of the flag (guard at 6194).
- **Source:** `YaraScanner.__init__ (lines 4998-5001), the match return that shadows the block (line 6187), scan_file FD block (lines 6189-6214), clean-scan return (line 6216)`

### Startup file-descriptor limit probe  <sub>linux, darwin</sub>

On non-Windows hosts with FD monitoring enabled, the scanner shells out to `bash -c 'ulimit -n'` (5s timeout) and warns when the limit is below 8192, then records the baseline FD count that the in-scan sampler compares against. The bash dependency means a host without bash simply logs that the limit could not be determined — and it is this block, not ScanConfig, that decides whether in-scan FD sampling happens at all.

- **Control:** config.enable_fd_monitoring via env YARA_ENABLE_FD_MONITOR (lines 2857-2859); gate at line 7251; 8192 threshold literal (line 7261) — default `false (disabled)`
- **Observe:** system_<run_id>.log → "Current file descriptor limit: N" (line 7259), "Initial file descriptors in use: N" (line 7275), and on a tight host "WARNING: Low file descriptor limit (N)" plus "Consider running: ulimit -n 65536 …" (lines 7262-7263)
- **Source:** `run() FD setup block (lines 7251-7288)`

### FD monitoring flag plumbing (two-name handoff)  <sub>linux, darwin</sub>

YaraScanner reads config.monitor_fd_usage, an attribute that ScanConfig never defines — it is grafted onto the config object by run() before the scanner is constructed. The ordering (ScanConfig at 7164, FD block at 7251, scanner at 7343) is what makes it work; any refactor that constructs the scanner earlier silently disables FD sampling with no error, because __init__ falls back to getattr(..., False). A companion attribute config.initial_fd_count travels the same undeclared path, and without it the +100 delta is computed against 0.

- **Control:** config.monitor_fd_usage set at lines 7277 / 7279 / 7283 / 7288; read at line 4998; companion config.initial_fd_count set at 7276, read at 4999 — default `False`
- **Observe:** Presence of "Initial file descriptors in use: N" in system_<run_id>.log (line 7275) is the only proof the handoff happened; absence of any later "FD usage increased by" line despite a long scan indicates the flag never arrived
- **Source:** `run() (lines 7251-7288), YaraScanner.__init__ (lines 4998-4999)`

### Per-file size cap (bounds YARA memory and time per file)

Files larger than the cap are skipped before rules.match, which is the main protection against a multi-GB file monopolising a worker and its memory. A negative value used to make max_file_bytes negative so EVERY file failed the check and the scan reported success having scanned nothing — hence minimum=0, where 0 legitimately means no cap (max_file_bytes becomes 0 at 2829 and the `if max_bytes and …` guard at 6143 short-circuits).

- **Control:** YARA_MAX_MB env var (line 2828, with minimum=0 guard); derived max_file_bytes (line 2829) — default `64 MB`
- **Observe:** scan_summary_<run_id>.json → files_skipped (line 7638), plus "File too large" in data.skip_breakdown of the "Skip reasons" statistics entry (lines 6641-6646); init_data.max_file_mb in system_<run_id>.log (line 7307) and data.max_file_mb in the "YaraScanner initialized" entry (line 5097)
- **Source:** `ScanConfig (lines 2825-2829), enforcement in scan_file (lines 6142-6144)`

### Chunked hashing of matched files

SHA256 is computed in 1 MB chunks so hashing a large matched file never loads it into RAM. A second, older implementation (FileHasher) uses 4 KB blocks and is used only as the evidence-collection fallback when a hash was not already recorded during the scan.

- **Control:** Not configurable (chunk_size default 1024*1024 at line 984; 4096 literal at line 1469) — default `1 MB / 4 KB`
- **Observe:** scan_summary_<run_id>.json → matches > 0 with stable memory_mb in the "System Resources" lines of performance_<run_id>.log; file_mapping.txt (written at the ZIP root, line 4571) carries the resulting path \| SHA256 pairs
- **Source:** `_sha256_file (lines 984-993), FileHasher.calculate_sha256 (lines 1463-1474), fallback call site (lines 4513-4515)`

### Hash only on match (no full read per scanned file)

Content hashing happens exclusively inside the `if matches:` branch, so the common case — a file that does not match — is read once by libyara and never again. Hashing every scanned file would roughly double I/O on a full-system sweep. A hash failure is non-fatal: _calculate_match_sha256 logs and returns None, and the row/alert simply carries an empty file_sha256 (`file_sha256 or ""` at 3673).

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → "System Resources" Disk I/O growth stays proportional to bytes scanned; file_sha256 is populated only on rows in yara_scanner_matches_v3_* (line 3673) and in the alert log entries (lines 6181, 6450)
- **Source:** `scan_file (lines 6163-6166), _calculate_match_sha256 (lines 6080-6089)`

### Per-offset match detail is never retained in memory

The uploader deliberately keeps no per-offset records. The previous design built one dict per matched offset and held them for the whole scan — measured at 1,048,035 offsets producing ~15 GB RSS on one endpoint — to be serialized by a function whose only caller was never invoked, so the data was accumulated and then discarded. add_match now walks the offsets once, keeping only a capped sample plus an uncapped per-string-ID count dict — and that census (_string_id_counts, 3631/3645/3679) is itself unbounded per finding, so a rule with thousands of distinct string IDs still grows memory.

- **Control:** Not configurable — default `-`
- **Observe:** performance_<run_id>.log → "System Resources" memory_mb stays flat across a storm scan; the offsets still land in scanner_dir/alert/<rule>.txt, bundled as alerts/<rule>.txt in the evidence ZIP (line 4569) — but only a sample of them, because the render is capped at 50 by CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (applied at line 6421); only the per-string-ID census is complete
- **Source:** `ResultsUploader.__init__ note (lines 3166-3175); single-pass aggregation in add_match (lines 3639-3653)`

### Finding-dedup set bounded at 150,000 entries

The (rule, path) set that makes alerts idempotent within a scan stops growing at 150k entries to bound memory on a pathological scan. Past that point new findings are no longer added to the set — they are still counted and storm-capped, but a repeat of the same finding could pass the dedup check again and re-queue. The enclosing condition at 3697 also requires the upload thread to be alive, so with create_alerts=false none of this runs.

- **Control:** Not configurable (150000 literal, line 3702) — default `150,000 findings`
- **Observe:** scan_summary_<run_id>.json → alert_delivery.findings vs alert_delivery.suppressed (lines 7655-7656, via get_upload_stats at 3804-3808); a scan whose distinct findings exceed 150k is the only case where the bound can bite
- **Source:** `ResultsUploader.add_match (lines 3697-3710)`

### Local alert-file offset sampling

Only the first N matched offsets per (rule, file) are rendered into alert/<rule>.txt. The uncapped version produced a 220 MB local file on one endpoint, 98.6% of it from four Windows event logs (rationale at 198-208). The per-string-ID census above it is written in FULL and stays uncapped, because that census — not individual offsets — is what an analyst works from.

- **Control:** CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (line 210); 0 renders everything; no options key and no env var — default `50 offsets`
- **Observe:** scanner_dir/alert/<rule>.txt → "Matched Strings (showing 50 of 33118):" plus the trailing "N further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50)" note; the file is bundled as alerts/<rule>.txt in the evidence ZIP (line 4569)
- **Source:** `_write_alerts census (lines 6412-6419) and offset sampling (lines 6421-6438)`

### Dataset row payload sampling per finding

Caps how many offsets/strings are embedded in a single lookup row, bounding both the POST payload and the retry budget one pathological finding can consume — measured live, one rule hit an .evtx log at 33,118 offsets. match_count and truncated keep the true total queryable even though the sample is capped; string_ids carries the complete per-string census and is NOT capped (line 3679), so a rule with very many distinct string IDs can still produce a large row.

- **Control:** CONFIG_LOOKUP_ROWS_PER_FINDING_MAX (line 199); no options key and no env var — default `50 rows/offsets`
- **Observe:** yara_scanner_matches_v3_* rows → truncated=true with match_count >> the length of the offsets JSON array (fields at lines 3660, 3676-3680); uploads_<run_id>.log → "Rule 'X' matched … at N offsets; embedded a sample of 50 …" (lines 3686-3691)
- **Source:** `add_match cap read (line 3632), sampling (lines 3651-3653), truncated flag + row fields (lines 3660, 3676-3680), log (lines 3686-3691)`

### Structured log payload truncation

Every structured data blob attached to a log line is JSON-serialised and hard-truncated at 4000 characters, so a stray large payload cannot bloat the on-disk logs. The cost: the two richest diagnostics — the COMPREHENSIVE SCAN REPORT and the end-of-run comprehensive_final_stats — routinely exceed 4000 chars, so their nested fields are cut mid-JSON and cannot be parsed programmatically.

- **Control:** Not configurable (4000 literal, lines 2176-2177) — default `4000 characters`
- **Observe:** Any of the six logs under scanner_dir/logs (paths at lines 2110-2117) → a line ending "...(truncated)" after "\| data="; most reliably reproduced on the COMPREHENSIVE SCAN REPORT line in statistics_<run_id>.log. scan_summary_<run_id>.json is written by a different path (write_scan_summary, lines 2308-2340, json.dump at 2332) with NO cap, and is the parseable alternative.
- **Source:** `LogManager._log (lines 2171-2178)`

### DORMANT: real-path deduplication set

A symlink/junction dedup set and its lock exist and are wired into scan_file, but track_real_paths is hardcoded False, so the set never grows (saving memory on a full-system scan) and both guarded branches are dead. The consequence is that unique_real_paths and unique_paths_scanned are always 0 in the reports — even though _get_real_path(file_path) at 6132 still runs unconditionally, so the per-file syscall cost remains.

- **Control:** config.track_real_paths — hardcoded literal at line 2860, no constant, no env var, no options key — default `False (dormant)`
- **Observe:** statistics_<run_id>.log → "Scan Progress" data.metrics.unique_real_paths is 0 for the whole scan (field at line 6583), and the final results entry's unique_paths_scanned is 0 (line 6609) even on a run with junction_skips > 0
- **Source:** `ScanConfig (line 2860), guarded blocks in scan_file (lines 6133-6136, 6146-6148), unconditional realpath call (line 6132), reporting (lines 6583, 6609)`

### Compiled-rule disk cache (XDR edition only)

Persists the compiled ruleset with rules.save() and reloads it on a later run, skipping a ~90s per-rule compile loop that a per-action process otherwise repeats every time. On load it does a proof match against empty data with the per-file externals so a cross-version or externals-incompatible bundle fails HERE and falls back — and a failed cache file is deleted along with its sidecar (5590-5595) so the next run does not re-pay the same failure.

- **Control:** RULE_CACHE_ENABLED via env YARA_RULE_CACHE (line 297); RULE_CACHE_FORMAT via YARA_RULE_CACHE_FORMAT (line 298) — default `enabled; format tag "1"`
- **Observe:** scan_summary_<run_id>.json → "compile_source": "cache"\|"fresh" and "compile_seconds" (lines 7651-7652); system_<run_id>.log → "Rule cache HIT rules_<key>.yarac load=0.42s (valid=… failed=… skipped=…)" (lines 5582-5586), "Rule cache miss/unusable, compiling fresh: …" (line 5589) or "Rule compile FRESH 88.71s" (line 5599); cache files in scanner_dir/rule_cache/ (line 5459)
- **Source:** `_load_or_compile_rules (lines 5559-5602), _rule_cache_key (lines 5463-5476)`

### Rule-cache size bounds and LRU pruning

After each save the cache directory is pruned newest-first by both file count and total bytes, and save-temps orphaned by a crash are swept once they are older than an hour (age-gated so a concurrent per-action process's in-flight save is spared). Host cleanup deliberately never touches rule_cache — it is a cross-run performance cache, not this run's data. Pruning runs only inside a successful save (its sole call site is line 5517), so a cache that stops being written is never pruned again.

- **Control:** RULE_CACHE_MAX_FILES via env YARA_RULE_CACHE_MAX (line 299); RULE_CACHE_MAX_BYTES via YARA_RULE_CACHE_MAX_MB (line 300); the 3600s temp age-gate is a literal (line 5539) — default `5 files / 256 MB`
- **Observe:** Directory listing of scanner_dir/rule_cache/ — at most 5 rules_*.yarac files (each with a .meta.json sidecar), total under 256 MB; mtimes show the LRU touch applied on every cache HIT (os.utime at line 5576)
- **Source:** `_prune_rule_cache (lines 5527-5557), _save_rule_cache (lines 5499-5525, prune call at 5517)`

### Rule-cache counts sidecar restore

A cache HIT skips the per-rule loop entirely, so the valid/failed/skipped rule counts are restored from a .meta.json sidecar; if that sidecar is missing or broken the valid count is recovered by iterating the loaded yara.Rules object and skipped falls back to 0 (return 0 at 5497). Without it a cached run would report 0 rules loaded and read as a broken scan. Note the fallback recovers only valid_rules — failed stays at whatever the ErrorLogger holds and skipped shows 0 rather than the true value.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json → valid_rules / failed_rules / skipped_rules are non-zero on a run whose compile_source is "cache" (lines 7641-7643, 7651); the same counts appear in the "Rule cache HIT …" system-log line (lines 5582-5586)
- **Source:** `_restore_cache_meta (lines 5478-5497), sidecar write (lines 5508-5516)`

### Alert POST pacing against the shared rate limit

A minimum wall-clock gap is enforced between Insert Parsed Alerts POSTs (60 alerts every >=7s ~= 510/min) because the API returns HTTP 500 "Exceeding the rate limit" past ~600 alerts/min per API key, and unpaced batches fail with retries that burn the whole upload window. The pacing sleep happens on the uploader thread, not a scan worker, so it does not slow scanning. The gap is measured from the last POST ATTEMPT (timestamp set at 3419), so retries inside a batch also reset it.

- **Control:** ALERT_MIN_BATCH_INTERVAL via env YARA_ALERT_MIN_INTERVAL (line 120); ALERT_BATCH_SIZE via YARA_ALERT_BATCH, hard-clamped to 60 by min() (line 113); ALERT_FLUSH_SECS for partial batches (line 114) — default `7 seconds; 60 alerts per POST; 10s partial flush`
- **Observe:** uploads_<run_id>.log → "Upload worker thread started (batch=60)" (line 3238) and "Alert batch ok (N alerts, HTTP 200)" lines spaced >=7s apart (lines 3433-3434)
- **Source:** `_upload_alert_batch pacing (lines 3406-3410), worker batch loop (lines 3260-3286), flush helper (lines 3244-3258)`

### Backlog-scaled alert drain window

At shutdown the drain budget is computed from the actual pending count (batches x (interval + 8)), floored at ALERT_DRAIN_SECS and hard-capped at ALERT_DRAIN_MAX_SECS, and short-circuits the moment the queue empties. A flat window either wasted time on small scans or truncated storm scans. stop() is idempotent (guard at 3534-3536), so run()'s safety-net second call does not re-pay the window and logs nothing.

- **Control:** ALERT_DRAIN_SECS (line 115), ALERT_DRAIN_MAX_SECS (line 116) via YARA_ALERT_DRAIN_SECS / YARA_ALERT_DRAIN_MAX_SECS; join uses THREAD_CLEANUP_TIMEOUT (line 133) — default `min 60s, max 300s, 60s thread join`
- **Observe:** uploads_<run_id>.log → "Draining N pending alert(s) (~M batches, up to Xs)..." (lines 3556-3559) then "Alert delivery final: findings=… ok=… undelivered=… requeued=…" (lines 3595-3599); the same counters land in scan_summary_<run_id>.json alert_delivery (lines 7655-7656)
- **Source:** `ResultsUploader.stop (lines 3530-3604; idempotence guard 3534-3536, drain 3550-3562, join 3570-3575, undelivered accounting 3577-3592)`

### Rate-limit requeue with a global wall-clock budget

A batch that exhausts its retries specifically because it was rate-limited is put BACK on the queue rather than dropped, bounded by a process-wide delivery deadline so a permanently saturated key cannot loop forever. It cannot beat the shared server-side ceiling, only ride out transient saturation. Requeue is also refused once stop_upload_thread is set, so the final drain does not loop.

- **Control:** ALERT_REQUEUE_ENABLED via env YARA_ALERT_REQUEUE (line 126); ALERT_MAX_DELIVER_SECS via YARA_ALERT_MAX_DELIVER_SECS (line 127) — default `enabled; 900 second budget`
- **Observe:** uploads_<run_id>.log → "Alert batch rate-limited after 4 attempts; requeuing N alerts for a later window." (lines 3479-3481) and the final line's "requeued=N" (line 3599); scan_summary_<run_id>.json alert_delivery.requeued (grafted on by get_upload_stats, line 3807)
- **Source:** `_upload_alert_batch tail (lines 3475-3487), worker flush requeue (lines 3248-3258), deadline init (line 3240)`

### Backlog-scaled lookup drain budget and per-batch deadline

The dataset drain budget scales with pending rows (batches x per-batch seconds), floored at LOOKUP_DRAIN_TIMEOUT and capped, and each batch additionally refuses a RETRY it cannot finish before (budget - 20s). Without that inner deadline a hung add_data made 6 retries take ~6x the read timeout, so the daemon drain thread was killed mid-POST at exit and the batch was lost silently — counted neither sent nor failed. The first POST of a batch is always attempted regardless of the deadline, because the guard is `attempt > 0` (line 4199).

- **Control:** LOOKUP_DRAIN_TIMEOUT (line 257), LOOKUP_DRAIN_MAX_SECS (line 261), LOOKUP_DRAIN_PER_BATCH_SECS (line 262) via YARA_LOOKUP_DRAIN_SECS / _MAX_SECS / _PER_BATCH; read timeout from LOOKUP_POST_TIMEOUT (line 271) — default `min 150s, max 600s, 45s per batch, 120s read timeout`
- **Observe:** uploads_<run_id>.log → "Lookup drain: N rows pending (~M batches), budget Xs" (lines 4331-4333) and "Lookup batch deadline reached (N rows) after K attempts; stopping retries…" (lines 4201-4205); scan_summary_<run_id>.json dataset_delivery.undelivered (line 7657)
- **Source:** `LookupDatasetUploader.stop (lines 4315-4372; budget 4326-4333), _send_batch deadline (lines 4188-4205)`

### Lookup write jitter and per-target batch timers

Each add_data POST is preceded by a random 0-2s delay to decorrelate a fleet burst, and each dataset flushes on ITS OWN idle timer so a busy matches stream cannot starve the low-volume scans heartbeat. Big batches plus deferred partial flushes minimise the number of POSTs, each of which is one chance at the server-side clone-table race.

- **Control:** LOOKUP_WRITE_JITTER_SECS (line 255), LOOKUP_DATASET_FLUSH_SECS (line 254), LOOKUP_DATASET_BATCH_SIZE (line 253) via YARA_LOOKUP_WRITE_JITTER / _FLUSH_SECS / _BATCH; bound to the instance at lines 3865-3866 — default `2s jitter, 30s flush, 500 rows`
- **Observe:** uploads_<run_id>.log → "Lookup batch ok (N rows): added=…, updated=…, skipped=…" lines (lines 4226-4229); N at or below 500 confirms batching, and gaps between them reflect jitter+flush. The startup line at 4060 also echoes batch_size.
- **Source:** `_worker per-target timers (lines 4110-4130; size flush 4119-4120, idle flush 4124-4127), _send_batch jitter (lines 4179-4180)`

### Concurrent final flush of the two lookup datasets

At shutdown the matches and scans batches are flushed on separate threads because they are DIFFERENT datasets (so the same-dataset race cannot trigger) and each add_data POST is ~10s server-side — overlapping them roughly halves the shutdown drain instead of paying the two costs back to back. With one pending target it stays on the calling thread (fast path at 4143-4145), which is the common case.

- **Control:** Not configurable; the per-thread join uses the scaled _drain_budget, falling back to LOOKUP_DRAIN_TIMEOUT (line 4153) — default `-`
- **Observe:** uploads_<run_id>.log → two "Lookup batch ok" lines with near-identical timestamps just before "Lookup dataset worker stopped (batches=…, added=…, failures=…)" (lines 4154-4162)
- **Source:** `LookupDatasetUploader._worker final drain (lines 4138-4153)`

### Uploader threads are daemons with bounded joins

Both delivery threads are daemons, so a wedged uploader can never prevent process exit; each is joined for a bounded window and a miss is logged rather than waited out. The trade is that anything still in flight at exit dies with the process — which is why the undelivered counters are computed explicitly by draining the queue after the join.

- **Control:** THREAD_CLEANUP_TIMEOUT (line 133) for the alert thread; the scaled _drain_budget for the lookup thread (line 4342) — default `60s alert join`
- **Observe:** uploads_<run_id>.log → "Upload thread did not terminate within 60s timeout" or "Upload thread terminated successfully" (lines 3570-3575), and "Lookup uploader thread did not stop within Xs" (lines 4339-4346); scan_errors_<run_id>.log → "Lookup drain budget expired with N rows undelivered" (lines 4367-4369)
- **Source:** `thread creation (lines 3228, 4062), ResultsUploader.stop join (lines 3570-3575), LookupDatasetUploader.stop join (lines 4339-4346)`

### Tuning-knob parse guard with minimum validation

Every module-level numeric knob is read through a helper that falls back to the documented default on a parse failure AND on an out-of-range value. Both failure modes were real: an unguarded int('5s') raised at import time — before any logger existed, so the operator saw a dead action with no local log and no telemetry — and YARA_MAX_MB=-1 parsed fine and silently made the scanner scan nothing. The guard covers every numeric knob in the file EXCEPT one: YARA_GOVERNOR_INTERVAL_SECS (lines 2866-2867) still uses a bare float() and can raise inside ScanConfig.

- **Control:** _env_number (lines 70-101); each call site passes its own `minimum` — default `per-knob defaults`
- **Observe:** stderr of the Action Center action (root logger is pinned to WARNING and these module-level warnings fire before setup_logging, so they DO surface) → "Ignoring invalid YARA_THREADS='x' (expected a number) - using default 2" (lines 92-95) / "Ignoring out-of-range …" (lines 97-100); effective values for only three of the parsed knobs also appear in init_data in system_<run_id>.log (max_workers, scan_queue_size, max_file_mb — lines 7305-7307). The alert/lookup/heartbeat knobs have no artefact echo beyond their own log lines.
- **Source:** `_env_number (lines 70-101), the one unguarded exception (lines 2866-2867)`

### CPU percentage inputs are unvalidated (the clamp helper is dead)

cpu_headroom_pct / cpu_budget_pct / cpu_floor_pct go through a bare float() with no range check, so headroom=200 yields a negative target that collapses onto the floor, and floor=150 pins the target above any achievable own-share — which does not merely skew pacing, it silences it entirely, because (own - target) is then always negative and sleep_ratio clamps to 0 at line 1199. A _clamp_pct helper that would coerce these into 1..100 exists but is never called, as does _coerce_float. A non-numeric value raises ValueError out of ScanConfig instead of falling back.

- **Control:** Assignments at lines 2716-2721; unused _clamp_pct (lines 730-736) and unused _coerce_float (lines 739-745) — default `30 / 25 / 5, unclamped`
- **Observe:** performance_<run_id>.log → THROTTLE_CONFIG echoes whatever was supplied (e.g. cpu_headroom_pct: 200.0, fields at lines 1099-1101), and subsequent CPU_GOVERNOR lines show "target" pinned at the floor with floor_hits climbing in scan_summary_<run_id>.json → cpu_governor.floor_hits
- **Source:** `ScanConfig (lines 2716-2721); dead helpers (lines 730-736, 739-745)`

### Retired throttle options are translated, not rejected

throttle_mode / cpu_high_threshold / cpu_critical_threshold / max_pause_secs are still ACCEPTED in the options string so existing scripts and scheduled jobs keep running, but the old behaviour is deliberately not preserved — throttle_mode maps onto a cpu_guarantee policy (off→none, script→headroom, os→headroom), an unrecognised mode falls back to headroom (line 794), and the other three are dropped (795-796). Any other unknown key raises so operator typos fail loudly. An explicit cpu_guarantee in the same options string wins over the translated one, because of the `"cpu_guarantee" not in out` guard at 793.

- **Control:** _RETIRED_OPTION_KEYS (lines 781-783), _THROTTLE_MODE_MAP (line 784), migrate_throttle_option (lines 787-797), _VALID_OPTION_KEYS (lines 771-775) — default `off→none, script→headroom, os→headroom (unknown→headroom)`
- **Observe:** scan_summary_<run_id>.json → "throttle_mode" shows the TRANSLATED policy (e.g. "headroom") after passing options="throttle_mode=os" (line 7648); a bogus key instead returns the ValueError text as the action result (raised at lines 826-828)
- **Source:** `migrate_throttle_option (lines 787-797), _parse_options_string (lines 800-830), applied in run() (line 7137)`

### DEAD CONFIG: batch_size / performance_log_interval / statistics_upload_interval

**⚠ OBSERVABILITY GAP**  
Three plausible-looking tuning attributes are set on ScanConfig and never read anywhere in the file. An operator editing them to change batching or telemetry cadence will see no behavioural change; the real batching knob is LOOKUP_DATASET_BATCH_SIZE (bound to LookupDatasetUploader.batch_size at line 3865) and the real cadences are the literals inside the monitor threads (5s at 1885, 10s/45s at 2377-2378).

- **Control:** config.batch_size (line 2983), config.performance_log_interval (line 2984), config.statistics_upload_interval (line 2985) — assigned, never read — default `1000 / 120 / 60 (all inert)`
- **Observe:** UNOBSERVABLE: nothing in any log or dataset reflects them. Real batch size is visible as "Lookup batch ok (500 rows)" in uploads_<run_id>.log; real cadences from the spacing of "Performance Snapshot" / "System resources" lines.
- **Source:** `Assignments at lines 2983-2985; the only live batch_size is LookupDatasetUploader's own (line 3865)`

### DEAD CODE: _get_scanner_stats aggregate

**⚠ OBSERVABILITY GAP**  
A full aggregation of file counts, per-worker stats, performance metrics and resource-monitor summary — including the resource_alerts count — that no caller ever invokes. It is the richest resource snapshot in the file and it is never produced. Its intended consumer, ScanStatusUploader.upload_scan_status(scanner_stats), is itself dead.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE: never called, so nothing emits it. The closest live equivalents are scan_summary_<run_id>.json and the COMPREHENSIVE SCAN REPORT entry in statistics_<run_id>.log.
- **Source:** `YaraScanner._get_scanner_stats (lines 5936-5965) — no call site in the file`

### DEAD CODE: periodic scan-status upload

**⚠ OBSERVABILITY GAP**  
ScanStatusUploader carries a 60s upload interval and a full status payload (elapsed time, files/sec, current file) targeted at Insert Parsed Alerts, but the method has no caller and would return immediately anyway because UPLOAD_NON_MATCH_DATA is False. Scan-progress telemetry actually reaches the tenant only through the scans lookup dataset.

- **Control:** status_upload_interval (line 4389) and last_status_upload (line 4388) — inert; gated by UPLOAD_NON_MATCH_DATA (line 105) — default `60 (inert); UPLOAD_NON_MATCH_DATA=False`
- **Observe:** UNOBSERVABLE: no request is ever sent. Live progress telemetry is the status="running" heartbeat rows in yara_scanner_scans_v3_*.
- **Source:** `ScanStatusUploader.upload_scan_status (lines 4393-4450) — no call site; gate at line 4395`

### Scan phase tracking (initializing → … → completed)

A phase label is advanced through the run (initializing, starting_workers, scanning, finishing, completed/failed/error/interrupted) and is the closest thing to a live progress state machine — but set_status only assigns an attribute and calls logging.info, every call site runs after setup_logging has stripped the root handlers and pinned WARNING, and the attribute it sets is read only by the dead upload_scan_status. The state machine therefore has no live consumer at all.

- **Control:** Not configurable — default `-`
- **Observe:** OBSERVABLE — the full phase sequence is in logs/diagnostics_<run_id>.log, one `Scan status changed to: <phase>` line per transition (xdr_yara_scanner.py:4531): initializing → starting_workers → scanning → finishing → completed, with error / interrupted / failed on the abort paths. Timestamps on those lines give per-phase duration. The tenant-side view stays coarser — the lifecycle status column (initiated/running/completed/cancelled/failed) on yara_scanner_scans_v3_* — because no phase label is written into the dataset row; adding one would mean a new column in _emit_scan_row's row dict (5315+).
- **Source:** `ScanStatusUploader.set_status (lines 4452-4455), call sites (lines 6683, 6797, 6815, 6839, 6939, 7390, 7393, 7433, 7529)`

### Final efficiency score and comprehensive report

A composite 0-100 score docked by skip rate (x20) and rule-failure rate (x30), bundled with rate, per-target throughput, worker count, cpu_count and the resource summary. It penalises skipping — which is mostly the deliberate skip-list doing its job — so a healthy full-system scan scores lower than a narrow one.

- **Control:** Not configurable (weights are literals, lines 7030 and 7034) — default `starts at 100 (line 7027)`
- **Observe:** statistics_<run_id>.log → "COMPREHENSIVE SCAN REPORT \| Efficiency Score: 87.3/100" (lines 7039-7042). The score is in the message text and always readable; the nested data blob (file_processing, system_info.cpu_count, worker_threads_used, performance_summary, resource_summary) is JSON-truncated at 4000 chars (lines 2176-2178), so on a scan with a large skip_breakdown the later fields are cut off.
- **Source:** `upload_final_comprehensive_report (lines 6971-7049)`

### End-of-run performance summary lines

On completion the scanner writes an overall rate/detection/skip-rate block plus a per-worker breakdown, and the returned SCAN_RESULT string carries the governor's total sleep so the CPU promise is visible without opening any file. On a failed run the same block is written at ERROR level with failure_reasons and the label becomes SCAN FAILED — so it lands in scan_errors_<run_id>.log, not statistics_<run_id>.log.

- **Control:** Not configurable — default `-`
- **Observe:** statistics_<run_id>.log → "SCAN COMPLETED \| Time: … \| Files: … scanned, … skipped \| Detections: … \| Rate: X.XX files/sec" (message built 6613-6619, logged at 6626); on failure the same text with SCAN FAILED goes to scan_errors_<run_id>.log (6620-6624). performance_<run_id>.log → "Worker performance summary: N workers processed files" (lines 6657-6660); Action Center action result → "… \| cpu-slept 41s \| alerts=on dataset=on files=off cpu=headroom mode=scan" (lines 7533-7536)
- **Source:** `_log_final_results (lines 6598-6660), summary string (lines 7533-7536)`

### Both psutil monitors are OFF by default — every performance figure in the final report is structurally zero

enable_performance_monitoring and enable_resource_monitoring both default to false, so StatisticsManager's 5-second sampler thread never starts (start_monitoring takes the disabled branch at 1862-1864) and SystemResourceMonitor is never even constructed (scan_system sets self.resource_monitor = None at 6780 and only builds it under the flag at 6781-6782). The knock-on effects look like bugs but are not: performance_history stays empty so performance_metrics.peak_cpu_percent / avg_cpu_percent / peak_memory_mb are 0.0 and samples_collected is 0 (2040); update_scanner_stats becomes a silent no-op because it only mutates performance_history[-1] (1981), so the enrichment the progress heartbeat feeds it at 6561-6563 is discarded; scan_estimates['average_rate'] never leaves 0 because it is computed from performance_history (2025-2030); get_resource_summary() is never called, so the final report has no resource_summary key (gated at 7023-7025) and _get_scanner_stats has no resource_monitoring key (gated at 5958-5963); and the 1-in-6 'Performance Snapshot' lines never appear (1882-1883). Live CPU evidence on a default run comes only from the governor's telemetry and _log_progress's 'System Resources' line, which run regardless.

- **Control:** YARA_ENABLE_PERF_MONITOR (lines 2851-2853) and YARA_ENABLE_RESOURCE_MONITOR (lines 2854-2856), both read from os.getenv in ScanConfig.__init__ — customer-reachable env vars on the endpoint — default `false / false (both monitors off)`
- **Observe:** system_<run_id>.log: the 'All monitoring systems activated' record (lines 6785-6795) carries performance_monitoring: false and resource_monitoring: false in its data= JSON, and 'System resource monitoring started' (2423) is absent. statistics_<run_id>.log: 'Performance monitoring disabled in light profile' (1863) is present and 'Performance monitoring thread started' (1868) is absent; the COMPREHENSIVE STATISTICS SUMMARY block's Performance Metrics JSON shows samples_collected: 0 (2040) with the cpu/memory figures 0.0. performance_<run_id>.log contains no 'Performance Snapshot \|' line. The final-report statistics record has no resource_summary key. init_data in system_<run_id>.log also echoes performance_monitoring_enabled and resource_monitoring_enabled (lines 7309-7310).
- **Source:** `ScanConfig.__init__ flags 2851-2856; StatisticsManager.start_monitoring 1860-1868; _monitoring_worker 1870-1891; _log_performance_details gate 1882-1883; update_scanner_stats 1978-1986; calculate_time_estimates average_rate 2025-2030; log_comprehensive_stats 2032-2059; SystemResourceMonitor.start_monitoring 2413-2423; get_resource_summary 2629-2659; scan_system construction gate 6780-6782 and init_data record 6785-6795; _get_scanner_stats gates 5949-5963; final report gate 7023-7025; init_data echo 7309-7310`

### Per-file permission denials accumulate in an unbounded list that nothing ever reads

**⚠ OBSERVABILITY GAP**  
Every file failing the os.access(R_OK) check lazily creates self.permission_denials and appends a dict of file_path, file_mode, owner_uid, scanner_uid and requires_root — one entry per denied file, from all worker threads with no lock, and grep confirms no reader anywhere in the 7785-line file: it is never summarised, aggregated, logged as a total, written to scan_summary, or uploaded. On the scanner's default non-root scope (a non-root Linux/macOS full-scope run, or any Windows run over C:\ system directories) denials run to the hundreds of thousands, making this pure RSS growth with no product value. It stands out against the deliberately bounded structures beside it: _seen_findings is capped at 150000 (3702) and worker_processing_times is trimmed to its last 100 samples per worker on every file (6234-6235). Nothing would be lost by deleting the list — the log_system call two lines above already carries the identical dict.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE from any artefact: the list has no reader, so it never reaches a log, the summary JSON, or the wire. The per-file 'Permission denied: <path>' records in system_<run_id>.log (line 6118) with the same permission_info in their data= JSON are an exact proxy for the entry COUNT (one log line per appended entry), but confirming the memory growth itself needs external process RSS sampling — and the built-in psutil samplers are off by default, so the scanner's own memory_mb figures come only from _log_progress.
- **Source:** `YaraScanner.scan_file permission branch 6103-6127 (list created 6120-6121, appended 6122, log_system 6118); contrast _seen_findings cap 3702 and worker_processing_times trim 6234-6235; no reader (grep for permission_denials returns only 6120, 6121, 6122)`

### Unthrottled 'Permission denied' system-log line — one record per unreadable file

The same permission branch emits log_manager.log_system(f"Permission denied: {file_path}", permission_info) once per denied file with no _throttled_log bucket in front of it, unlike the upload paths which route everything through _throttled_log(bucket, msg, full=20, every=1000). log_system goes straight to the dedicated SYSTEM FileHandler at INFO, and _log appends the permission_info dict as JSON on the line (up to the 4000-char cap), so each denial costs roughly 200-300 bytes of disk. On a non-root full-filesystem scan that is one fat line per unreadable file in /proc, /etc, /root and other users' homes — system_<run_id>.log can grow to hundreds of megabytes purely from denials, on a host where the scanner has no size budget for its own logs.

- **Control:** Not configurable — no throttle bucket, no sampling, no flag — default `-`
- **Observe:** system_<run_id>.log: count lines matching 'Permission denied: ' — the count equals the number of unreadable files encountered, and each carries ' \| data={"file_mode":...,"owner_uid":...,"requires_root":...}'. Cross-check against scan_summary_<run_id>.json's files_skipped (7638) and the skip_breakdown key 'No read permission' (returned at 6127) in the statistics-log 'Skip reasons' record (6641-6646) — the two counts should match. Compare the file size of system_<run_id>.log to a root-privileged run of the same scope.
- **Source:** `YaraScanner.scan_file 6118 (log_system call) and the return at 6127; LogManager.log_system 2212-2214; LogManager._log payload serialisation and 4000-char cap 2171-2178; the SYSTEM logger is a dedicated INFO FileHandler on system_<run_id>.log (path 2116, handler setLevel(INFO) 2147, propagate=False 2155); contrast the uploader's _throttled_log 3371`

### Mislabelled resource-monitor telemetry: monitoring_duration_minutes is host uptime

monitoring_duration_minutes in every SystemResourceMonitor record is (time.time() - self.system_boot_time) / 60 where system_boot_time is psutil.boot_time() — it reports HOST UPTIME in minutes, so a 3-minute scan on a box up for a week reports ~10000. Nothing in the payload measures how long monitoring actually ran. The honest figure is the sibling monitoring_duration_seconds in the end-of-run summary, computed as data_points x monitoring_interval (line 2639). Only alert_count_last_hour applies a real time window (3600s over alert_history, lines 2574-2575).

- **Control:** Gated entirely on YARA_ENABLE_RESOURCE_MONITOR (lines 2854-2856, default false) — the payload does not exist on a default run. system_boot_time (2393), monitoring_interval 10 (2377) and the 3600s alert window (2574) are all bare literals: not configurable. — default `YARA_ENABLE_RESOURCE_MONITOR=false; monitoring_interval=10s`
- **Observe:** With YARA_ENABLE_RESOURCE_MONITOR=true, performance_<run_id>.log carries repeated 'System resources - CPU: x%, Memory: yMB' records (lines 2579-2582); their data= JSON contains monitoring_duration_minutes (built at line 2576) — compare it against `uptime` on the host and it will match uptime, not scan elapsed. The trustworthy figure is monitoring_duration_seconds in the single end-of-run 'Resource monitoring completed: N snapshots, M alerts' record (lines 2668-2673) and in the final report's resource_summary key (inserted at 7023-7025).
- **Source:** `SystemResourceMonitor.__init__ system_boot_time 2393, monitoring_interval 2377; _upload_resource_data 2566-2582 (alert_count_last_hour 2574-2575, monitoring_duration_minutes 2576); get_resource_summary monitoring_duration_seconds 2639`

### Per-tick 'Network: X MB' is the whole host's traffic since boot, not the scanner's uploads

The Network figure in the per-tick 'System Resources \| … \| Network: X MB' line, and the network_mb key inside the statistics-log 'Scan Progress' record's metrics block, is psutil.net_io_counters().bytes_sent + bytes_recv taken ABSOLUTE — no startup baseline subtraction, host-wide, and nothing to do with the scanner's own alert/lookup uploads. On a busy server it reads in the tens of gigabytes and never decreases, which reads as if the scanner were exfiltrating. It sits immediately beside disk_io_mb, which IS process-scoped and reports 0 on macOS. Worse, the same performance log expresses network two incompatible ways: SystemResourceMonitor's parallel network.sent_mb / recv_mb / total_mb DO subtract a baseline captured at init and are genuine deltas, as does StatisticsManager's PerformanceSnapshot.network_sent_mb / network_recv_mb.

- **Control:** Not configurable. The emitting heartbeat's cadence is YARA_PROGRESS_LOG_SECS (line 2850, clamped to >=1). — default `YARA_PROGRESS_LOG_SECS=30`
- **Observe:** performance_<run_id>.log: the 'System Resources \| … \| Network: X MB' lines (message built 2264-2270, Network segment 2267). Sanity test — note the first tick's Network value and compare against `cat /proc/net/dev` or `netstat -ib` host totals: it will match host cumulative traffic, and tick 1 will already be large rather than near zero. statistics_<run_id>.log: the 'Scan Progress' records (2229-2232) carry the same absolute number under data.metrics.network_mb (field at 6578). Contrast the resource monitor's flag-gated 'System resources - CPU:…' records, whose network.total_mb starts at ~0 and grows with the scan.
- **Source:** `YaraScanner._log_progress absolute counters 6547-6548 and the log call 6550; additional_metrics network_mb 6578 flowing into log_scan_progress 6586-6589; LogManager.log_system_resources 2254-2270 (Network segment 2267); LogManager.log_scan_progress 2217-2234; contrast SystemResourceMonitor baseline capture 2401 and delta computation 2477-2478 with the network payload block 2506-2508; contrast StatisticsManager baseline 1835 and delta 1913-1914; process-scoped disk_io guarded for macOS 6540-6545`

### Env vars outrank the options string for cpu_guarantee and workers (documented precedence is reversed)

run() resolves the compact options string over the explicit kwargs with `opts.get(key, current)` and documents 'options win' (comment at 7134-7136), but ScanConfig.__init__ then wraps os.getenv AROUND the already-picked value: cpu_guarantee becomes os.getenv('YARA_CPU_GUARANTEE', _guarantee) at 2711-2712, and workers becomes _env_number('YARA_THREADS', _cfg_workers, …) at 2838. A stale YARA_CPU_GUARANTEE or YARA_THREADS left on one endpoint therefore silently beats options="cpu_guarantee=budget,workers=8" from Action Center, and beats CONFIG_CPU_GUARANTEE / CONFIG_WORKERS too — making that one host behave differently from the rest of the fleet under a byte-identical invocation, with nothing in the result line to say why. Because run() already substitutes the CONFIG_* constants for None before parsing options (lines 7108-7132), the CONFIG_ fallbacks at 2710 and 2837 are unreachable in the run() path; env is the only thing above the options string.

- **Control:** YARA_CPU_GUARANTEE (line 2712) and YARA_THREADS (line 2838); the values they override are CONFIG_CPU_GUARANTEE (174) / CONFIG_WORKERS (184) and the options keys cpu_guarantee (picked at 7145) / workers (picked at 7149) — default `CONFIG_CPU_GUARANTEE = "headroom" (174); CONFIG_WORKERS = 2 (184)`
- **Observe:** scan_summary_<run_id>.json: throttle_mode (line 7648) reports config.cpu_guarantee — compare it against the options string echoed in the same file's posture field (injected at 2326, built at 2725-2730). system_<run_id>.log: the init_data record's max_workers (field 7305) versus the workers= value in the options string. The yara_scanner_scans rows carry the same pair, throttle_mode and posture, per row (lines 5239-5240), so the disagreement is visible tenant-side too. Test: invoke with options="cpu_guarantee=budget" on a host with YARA_CPU_GUARANTEE=none exported — posture reads cpu=none, throttle_mode is "none", and the result line's 'cpu-slept 0s' (7536) confirms the governor never engaged.
- **Source:** `ScanConfig.__init__ cpu_guarantee env wrap 2710-2712, workers env wrap 2837-2838; run() CONFIG_* substitution 7108-7132 and the _pick precedence comment and calls 7134-7151; posture string 2725-2730; scan_summary throttle_mode 7648; init_data max_workers 7305; scans-row throttle_mode/posture 5239-5240`

### Governor final state persisted as a structured cpu_governor block in the run summary

scan_summary_<run_id>.json carries a "cpu_governor" object straight from CpuGovernor.stats() — policy, target, own, others, ratio, slept_secs and floor_hits — the only durable per-run record of whether pacing actually engaged, what share of the machine the scanner was held to, and how often the anti-stall floor caught a target driven below floor_pct by external load (floor_hits > 0 means compute_target clamped). It survives even when the CPU_GOVERNOR heartbeat lines are absent from the performance log, which matters because that emission is change-or-heartbeat gated. Alongside it, total_paused_secs is the SAME underlying slept_total that the yara_scanner_scans rows and the result line's 'cpu-slept Ns' report, so all three can be reconciled — and it is written from the run() finally block, so it is present on cancelled and failed runs too.

- **Control:** Not configurable (always written). Its content depends on cpu_guarantee — YARA_CPU_GUARANTEE (2712) / options cpu_guarantee (7145) / CONFIG_CPU_GUARANTEE (174). — default `policy from CONFIG_CPU_GUARANTEE = "headroom"; the block is None only if scanner.cpu_governor is missing (ternary at 7649-7650)`
- **Observe:** scan_summary_<run_id>.json under scanner_dir/logs: the cpu_governor object and the sibling total_paused_secs. Reconcile the three reports of the same number: cpu_governor.slept_secs, total_paused_secs in the same file (7646-7647), total_paused_secs on every yara_scanner_scans row (5238), and 'cpu-slept Ns' in the action's returned result line (7536) — they must agree. floor_hits > 0 is the positive test for floor entry; ratio > 0 with slept_secs > 0 is the positive test that pacing actually ran.
- **Source:** `run() finally summary payload 7632-7666 (total_paused_secs 7646-7647, throttle_mode 7648, cpu_governor 7649-7650); CpuGovernor.stats 1224-1233; floor_hits increment in compute_target 1176-1178; slept_total accumulation 1220-1221; scans-row snapshot 5217-5218 and field 5238; result-line cpu-slept 7536; LogManager.write_scan_summary 2308-2340 (atomic os.replace at 2333)`

---

# Local Storage & Host Footprint

*Everything written to the machine being scanned.*

### Scanner working directory root (scanner_dir) and its platform defaults

Every artefact the scanner leaves on the host lives under one root: C:\yara_scanner (Windows), /usr/local/yara_scanner (macOS), /opt/yara_scanner (everything else). The root is created with makedirs(exist_ok=True) at ScanConfig construction (line 2735), before the YARA input is even decoded (2799), so a scan touches the disk before a single rule is compiled — and mode=cancel creates it too (os.makedirs of control/ at 855 creates the parent), so cancelling on a host that never scanned still plants the directory.

- **Control:** YARA_SCANNER_DIR, read at call time inside the module-level helper _default_scanner_dir (line 835) — customer-reachable as an endpoint env var; platform literals lines 838-842 — default `C:\yara_scanner \| /usr/local/yara_scanner \| /opt/yara_scanner`
- **Observe:** Directory exists on disk after any run: `ls -la /opt/yara_scanner` (or `dir C:\yara_scanner`). Also implicitly proven by scan_summary_<run_id>.json existing, since it is written under scanner_dir/logs.
- **Source:** `_default_scanner_dir lines 833-842; ScanConfig.scanner_dir line 2731; os.makedirs line 2735; _handle_cancel_request control-dir makedirs lines 852-857`

### Fixed subdirectory layout under scanner_dir (logs, control, alert, evidence, failed_rules — plus rule_cache)

ScanConfig unconditionally creates logs/, control/, alert/, evidence/ and failed_rules/ on every construction (2735-2737, 2744-2745), whether or not the scan will produce anything for them. rule_cache/ is created separately by _rule_cache_dir(), which _load_or_compile_rules calls on EVERY run whenever RULE_CACHE_ENABLED (the default) — so in a stock deployment six directories exist after any run, not five; rule_cache is only absent when YARA_RULE_CACHE is disabled. There is no way to relocate an individual subdirectory — only the whole root moves.

- **Control:** Not configurable individually (paths are bare literals joined to scanner_dir at lines 2733-2734, 2740-2742, 5459); only the root moves via YARA_SCANNER_DIR (line 835). rule_cache presence is gated by RULE_CACHE_ENABLED (line 297) — default `logs, control, alert, evidence, failed_rules always created; rule_cache created on every run with caching enabled (default)`
- **Observe:** `ls /opt/yara_scanner` shows logs, control, alert, evidence, failed_rules and rule_cache after any default run, including a run with 0 matches and 0 failed rules (alert/, evidence/, failed_rules/ will be empty but present). Set YARA_RULE_CACHE=0 to see the five-directory layout.
- **Source:** `lines 2733-2737 (logs, control), 2740-2745 (alert, evidence, failed_rules); _rule_cache_dir lines 5458-5461; call site _load_or_compile_rules line 5569`

### run_id — microsecond timestamp that names every per-run file

run_id = strftime('%Y%m%d_%H%M%S_%f') is generated once in ScanConfig and stamped into every log filename, the summary JSON, the evidence ZIP name and the scan_id. The 6-digit microsecond field is what makes two scans launched in the same second distinguishable, and log retention's regex depends on exactly that shape (\d{8}_\d{6}_\d{6}) — a run_id in any other format would be invisible to pruning and never deleted.

- **Control:** Not configurable — default `e.g. 20260817_142233_918274`
- **Observe:** Filenames under scanner_dir/logs all share one run_id suffix; scan_summary_<run_id>.json carries "run_id" as a field (line 2318), and the lookup dataset rows carry run_id/scan_date derived from it (matches rows 3664-3665, scans rows 5223-5224).
- **Source:** `ScanConfig.run_id line 2692; consumers at 1494 (yara_processing), 1702 (script_exceptions), 2111-2116 (six category logs), 2315 (summary JSON), 2816 (scan_id), 2823 (output_log), 2905 (evidence ZIP); retention regex line 4582`

### Six per-category structured log files (alerts / statistics / errors / performance / uploads / system)

LogManager opens six separate logging.FileHandlers in mode='w' at level INFO with propagate=False, one per LogType. Together with ErrorLogger's own yara_processing file they are the scanner's ONLY info-level observability: setup_logging (called at run() line 7290) strips root handlers and pins root to WARNING, so bare logging.info() reaches nothing, while log_system/log_alert/log_upload etc. land in these files. They are created even for a scan that finds nothing.

- **Control:** Not configurable (paths and mode are literals, lines 2110-2117, 2142-2146) — default `alerts_<run_id>.log, statistics_<run_id>.log, scan_errors_<run_id>.log, performance_<run_id>.log, uploads_<run_id>.log, system_<run_id>.log`
- **Observe:** All six exist under scanner_dir/logs after any run; system_<run_id>.log opens with 'Enhanced Log Manager initialized with standardized logging' (line 2129) and carries the 'Logging Summary \| Total Logs: N' line with per-type counts in its data blob (log_final_summary, lines 2296-2306). The same counts also appear inside the 'Scan completed successfully...' data payload in system_<run_id>.log as log_generation_stats (line 7463) — they are NOT a field of scan_summary_<run_id>.json.
- **Source:** `LogManager.__init__ lines 2103-2129; log_files 2110-2117; _setup_logger lines 2131-2161; log_final_summary 2296-2306; setup_logging 6954-6968 (invoked line 7290)`

### yara_processing_<run_id>.log — the rule-compilation audit trail

ErrorLogger opens its own FileHandler (mode='w', INFO) separate from LogManager's six, and it is written during ScanConfig construction (line 2747) — before LogManager exists (created at run() line 7180). It carries the Python/platform/YARA versions, the available-module list (written at 5609), the full text of every failed rule with the error line marked (1641-1651), and the compilation summary. It is the seventh log file and the one HostCleanup had to be taught to close on Windows.

- **Control:** Not configurable — default `logs/yara_processing_<run_id>.log`
- **Observe:** File under scanner_dir/logs opening with '=== YARA Processing Log ===' followed by Python Version / Platform / YARA Version (lines 1529-1532); contains 'COMPILATION SUMMARY' with 'Valid rules compiled' / 'Failed rules skipped' counts (1676-1680).
- **Source:** `ErrorLogger.__init__ lines 1491-1500; _setup_error_logger lines 1502-1539; close() lines 1541-1555; log_compilation_summary lines 1672-1689; available-module line written at 5609`

### script_exceptions_<run_id>.log — lazily created, so a clean run leaves no empty file

The exception log's FileHandler is created only on the FIRST log_exception() call, deliberately so a clean scan does not litter logs/ with a zero-byte file. There is exactly ONE call site (run()'s outer except, line 7577) and it is guarded by a local that is only bound at line 7208 — so a crash BEFORE that point (inside ScanConfig or LogManager construction, or the placeholder-credentials abort at 7188-7203) leaves no exception log either. Presence therefore proves something threw; absence does not prove nothing did.

- **Control:** Not configurable — default `logs/script_exceptions_<run_id>.log (absent on a clean run)`
- **Observe:** If present it opens with '=== SCRIPT EXCEPTION LOG INITIALIZED ===' (line 1736) and contains full tracebacks. Absence means either no exception reached run()'s outer handler, or the run died before line 7208 — cross-check outcome in scan_summary_<run_id>.json and the CRITICAL_ERROR line in scan_errors_<run_id>.log (7567).
- **Source:** `ExceptionLogger lines 1692-1746; _ensure_logger lazy gate lines 1707-1710; sole call site run() lines 7576-7581; local bound at 7208; config.exception_logger constructed 2748`

### scan_summary_<run_id>.json — the machine-readable per-run record, written atomically

One JSON per run written to logs/ via temp + os.replace so a reader never sees a half-file; on failure the temp is removed so no orphan is left (2336-2341). It is written in run()'s finally block AFTER both uploaders drain (7609-7612), so its alert_delivery / dataset_delivery counts are final rather than mid-flight. It carries delivery_shortfall — the single field that answers 'did this scan's findings actually land?' — which is deliberately kept local only, because the lookup datasets have a fixed schema and would silently drop the row.

- **Control:** Not configurable — default `logs/scan_summary_<run_id>.json, schema 'yara_scan_summary/v1'`
- **Observe:** The file itself. Verified fields: schema, run_id, scan_id, tenant_id, hostname, posture, matches_dataset/scans_dataset (2316-2327) plus outcome, files_scanned, files_skipped, matches, unique_rules_triggered, valid_rules/failed_rules/skipped_rules, compile_source ('cache'\|'fresh'), compile_seconds, delivery_shortfall, cpu_governor, top_rules, scanner_version, cancel_source, alert_delivery, dataset_delivery (7632-7666).
- **Source:** `LogManager.write_scan_summary lines 2308-2343; caller in run()'s finally lines 7615-7666 (finally opens at 7605; uploader drain 7609-7612)`

### Orphaned scan_summary *.tmp sweep at scan start

Before applying retention, _prune_old_scan_logs deletes any logs/scan_summary_*.tmp left by a process that died between the json.dump and the os.replace. It is safe only because it runs at scan START (from initial_cleanup, line 4670), before this run writes its own temp; the retention regex below anchors on .log/.json and would never match a .tmp.

- **Control:** Not configurable — default `Always on`
- **Observe:** No scan_summary_*.tmp files remain under scanner_dir/logs after a subsequent run (create one by hand and confirm the next scan removes it). No log line records the sweep, so disk state is the only evidence.
- **Source:** `_prune_old_scan_logs lines 4591-4599; invoked from initial_cleanup line 4670`

### Log retention — keep only the last N scans' logs and summaries

At scan start, logs are grouped by the run_id parsed from the filename and everything outside the newest N run_ids is deleted. Both .log and .json are pruned together (filter at 4603), so a run's summary dies with its logs. Files whose name does not carry a parseable run_id are skipped entirely (4606-4607) — they accumulate forever. LOG_KEEP_SCANS=0 does not mean 'keep nothing': max(1, ...) floors it at 1.

- **Control:** LOG_KEEP_SCANS from YARA_LOG_KEEP (line 310); floor applied line 4613 — default `10 scans`
- **Observe:** Count distinct run_id groups in scanner_dir/logs after >10 scans — never more than 11 (10 kept + current). The retention line is a bare logging.info (4634-4637) so it is UNOBSERVABLE in the structured logs: verify on disk instead.
- **Source:** `_extract_run_id_from_log_name lines 4580-4583; _prune_old_scan_logs lines 4585-4639; extension filter 4602-4604; unparseable skip 4606-4607; invoked from initial_cleanup line 4670`

### Current run is force-protected from retention

keep_run_ids.add(self.config.run_id) explicitly re-adds the running scan's run_id. This matters because ErrorLogger and LogManager have ALREADY created this run's seven log files by the time initial_cleanup runs (ScanConfig at 7164 → LogManager at 7180 → initial_cleanup at 7212), so with LOG_KEEP_SCANS=1 and no explicit protection a scan could delete its own live log files while their handlers were open.

- **Control:** Not configurable — default `Always on`
- **Observe:** Set YARA_LOG_KEEP=1 and run: the current run's seven files survive alongside exactly one prior run's set.
- **Source:** `line 4616; construction ordering in run() lines 7164 (ScanConfig→ErrorLogger 2747), 7180 (LogManager), 7212 (initial_cleanup)`

### Log-file deletion failures are tolerated, not fatal

**⚠ OBSERVABILITY GAP**  
Retention catches PermissionError separately from OSError and counts them; a Windows agent that still holds a previous run's log open (another scanner process) leaves the file behind and the scan continues. The warning goes through bare logging.warning, which reaches stderr only because root has no handlers (setup_logging strips them at 6963-6965) and Python's lastResort handler applies at WARNING.

- **Control:** Not configurable — default `Always on`
- **Observe:** UNOBSERVABLE: the 'Cannot remove log file' message uses bare logging.warning, not LogManager, so it reaches only stderr / the Action Center stderr capture and appears in none of the seven log files. To confirm on disk, count leftover run_id groups exceeding LOG_KEEP_SCANS. To close it: NEEDS_INSTR, and the minimal fix is a channel swap, not a new log line: in _prune_old_scan_logs replace the bare logging calls with the class's own helper - 4728 -> self._log(f"Cannot remove log file (in use): {path}"), 4731 -> self._log(f"Cannot remove log file {path}: {e}"), 4733-4736 -> self._log("Log retention applied: ..."), 4738 -> self._log(f"Log retention: {failed} log files could not be removed"). Since 7381 passes log_manager in, all four then land in logs/system_<run_id>.log. (Alternative, broader fix: move setup_logging(config) from 7461 to before cleanup_manager.initial_cleanup() at 7383 so the diagnostics handler exists during startup cleanup - that also closes every other pre-7461 logging.info.)
- **Source:** `lines 4627-4632 (PermissionError/OSError split), 4638-4639 (aggregate warning); setup_logging root strip 6963-6966`

### Structured log `data` payload capped at 4000 characters per line

Every log_* call that passes a dict gets it serialized as JSON onto the line (sort_keys, default=str) — this is what makes error types, counts and failure reasons survive into the file at all (they were previously accepted and silently dropped). The blob is truncated at 4000 chars with '...(truncated)' so one stray large payload cannot bloat the log file.

- **Control:** Bare literal 4000 in LogManager._log (line 2176) — not customer-reachable — default `4000 characters`
- **Observe:** Grep any per-category log for '...(truncated)'. The reliable producer is the comprehensive final report in statistics_<run_id>.log ('COMPREHENSIVE SCAN REPORT \| Efficiency Score', emitted at 7039-7042) whose payload nests scan metadata, skip_breakdown, detection_breakdown and performance_summary.
- **Source:** `LogManager._log lines 2163-2190; json.dumps 2173; cap 2176-2177`

### Upload-log volume suppression (_throttled_log buckets)

Per-match upload messages are bucketed: the first 20 in a bucket are written, then suppression kicks in and only a running count is emitted every 1000. Without this, a sustained upload failure on a match-heavy scan would write one log line per match (a placeholder-cred run produced ~36k identical lines / 10 MB, see 3197-3199). The suppression notice itself truncates the example message to 120 chars. level='error' routes to scan_errors_<run_id>.log, anything else to uploads_<run_id>.log.

- **Control:** Bare defaults full=20, every=1000 in the method signature (line 3371) — not customer-reachable — default `first 20, then every 1000`
- **Observe:** uploads_<run_id>.log / scan_errors_<run_id>.log contain lines of the form '[<bucket>] further similar messages suppressed; will summarize every 1000. Example: ...' and '[<bucket>] N occurrences so far; latest: ...'.
- **Source:** `ResultsUploader._throttled_log lines 3371-3386; routing line 3379; rationale comment 3197-3199`

### Progress-heartbeat writes to statistics AND performance logs on a fixed cadence for the whole scan

A dedicated thread calls _log_progress() every log_interval seconds for the entire scan, not just during file discovery — the inline-only version essentially never fired because enumeration finishes long before matching does. Each tick writes BOTH a 'Scan Progress' line to statistics_<run_id>.log AND a 'System Resources' line to performance_<run_id>.log (log_system_resources call at 6550), so it drives growth of both files, not just statistics. The interval is clamped to >=1s because it is a threading.Event.wait() argument and 0 would busy-spin.

- **Control:** config.log_interval from YARA_PROGRESS_LOG_SECS (line 2850) — default `30 seconds`
- **Observe:** Repeated 'Scan Progress \| Files: ... scanned, ... skipped \| Detections: ... \| Queue: ... \| Rate: ...' lines in statistics_<run_id>.log spaced ~30s apart, each paired with a 'System Resources \| CPU: ... \| Memory: ...MB \| Disk I/O: ... \| Network: ...' line in performance_<run_id>.log.
- **Source:** `log_interval line 2850; _progress_heartbeat lines 6662-6678; thread start lines 6829-6833; stop lines 6731-6734; _log_progress lines 6514-6597 (log_system_resources at 6550); LogManager.log_scan_progress lines 2217-2234; log_system_resources 2254-2270`

### config.output_log (scanner_<run_id>.log) — DEAD as a log file, but load-bearing as a path

ScanConfig builds logs/scanner_<run_id>.log and nothing anywhere opens it for writing — grep confirms only four consumers: the declaration (2823), initial_cleanup's delete attempt (4649), initial_cleanup's logs-dir recreation via os.path.dirname(output_log) (4667), and _is_special_file's self-exclusion compare (6250-6256). The self-exclusion check is therefore dead (the file never exists to be scanned), but the variable is NOT removable: 4667 is how logs_dir gets recreated after cleanup.

- **Control:** Not configurable — default `logs/scanner_<run_id>.log — never created`
- **Observe:** Confirm by absence: no scanner_*.log ever appears under scanner_dir/logs, on any platform, after any run (note scan_errors_<run_id>.log and system_<run_id>.log are different files).
- **Source:** `declaration line 2823; deletion attempt lines 4646-4657 (entry at 4649); logs-dir recreation via dirname line 4667; skip comparison lines 6250-6256; no writer anywhere in the file (grep: 2823, 4649, 4667, 6251, 6253 only)`

### initial_cleanup wipes the previous run's alert/ and evidence/ directories wholesale

At the start of every scan, alert_dir and evidence_dir are shutil.rmtree'd and recreated empty. This is the ONLY thing that removes a previous evidence ZIP, its file_mapping.txt and the previous alert .txt/.alert files — which is exactly why a host scanned once and never again keeps them forever (the gap HostCleanup exists to close). PermissionError is caught per-path and downgraded to a warning, and the whole method is wrapped so any other exception only warns 'Continuing with scan despite cleanup issues'.

- **Control:** Not configurable — default `Always on`
- **Observe:** Run twice: after the second scan, evidence/ contains only evidence_<host>_<new_run_id>.zip — the previous run's ZIP is gone. system_<run_id>.log records 'Initial cleanup completed' (log_manager call in run() at line 7213); the per-path 'Removed: <path>' lines and 'Initial cleanup completed successfully' inside the method itself are bare logging.info and UNOBSERVABLE.
- **Source:** `CleanupManager.initial_cleanup lines 4641-4679; paths_to_clean 4646-4650; rmtree 4659; recreate 4666-4668; outer except 4677-4679`

### failed_rules/ is NOT wiped by initial_cleanup — asymmetry with alert/ and evidence/

alert_dir and evidence_dir are in paths_to_clean; failed_rules_dir is not, and it is also absent from the recreate list (4666-4668). So per-rule .yar dumps survive across runs indefinitely. Because filenames are deterministic (failed_rule_<name>.yar), a repeat run overwrites the same rule's file — but if the customer changes rule packs, dumps for rules that no longer exist linger forever. Only HostCleanup (off by default) ever removes them.

- **Control:** Not configurable — failed_rules_dir is simply absent from paths_to_clean (lines 4646-4650) — default `Never pruned`
- **Observe:** Scan with pack A (produces failed_rule_X.yar), then scan with pack B (no rule X): failed_rules/failed_rule_X.yar is still there. A cache HIT makes this stickier still — the per-rule loop is skipped entirely (5565-5587), so no dumps are refreshed that run.
- **Source:** `paths_to_clean lines 4646-4650; recreate list 4666-4668 (also excludes failed_rules); HostCleanup._rm_tree(failed_rules_dir) line 4970`

### alert/<rule>.txt — one append-only text file per matching rule, uncapped in file count

Every (rule, file) finding appends a block to alert/<rule>.txt, opened and closed per finding under one global lock (lock_alert, line 5021), so a match-heavy scan serialises all alert writes through a single mutex. The number of such files equals the number of distinct rules that matched — there is no cap on that count, only on the offsets rendered inside each block. The filename comes straight from the compiled rule identifier, which YARA's grammar restricts to [A-Za-z0-9_], so no sanitising is needed. IOError/OSError on the write is swallowed into a log_error, so a failed alert write does not fail the scan.

- **Control:** Not configurable (path literal line 6396); per-block offset cap is CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (line 210) — default `-`
- **Observe:** Files under scanner_dir/alert named <rule>.txt, each containing "YARA rule '<rule>' matched file: <path>" blocks with 'File SHA256:' and 'File Creation Time:' lines; also carried into the evidence ZIP under alerts/. Write failures appear as 'Failed to write alert file: ...' in scan_errors_<run_id>.log.
- **Source:** `_write_alerts lines 6365-6457; alert path line 6396; lock_alert acquire 6397 (defined 5021); open/append line 6399; error handler 6440-6442`

### Alert offsets sampled per finding; per-string-ID census kept complete

Each alert block first writes an UNCAPPED census — 'Total string hits: N' and 'Hits per string ID: $a=12, $b=3' — then renders at most CONFIG_ALERT_OFFSETS_PER_FINDING_MAX individual offsets, followed by an explicit '<n> further offset(s) omitted' footer naming the constant and telling the analyst to re-run `yara -s`. The cap exists because the uncapped version produced a 220 MB alert file on one endpoint, 98.6% of it from four Windows event logs. 50 deliberately matches CONFIG_LOOKUP_ROWS_PER_FINDING_MAX so the local file and the dataset row show the same sample; <=0 renders everything.

- **Control:** CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (line 210); read at line 6421 — default `50`
- **Observe:** In alert/<rule>.txt: 'Matched Strings (showing 50 of 33118):' followed by 'further offset(s) omitted (CONFIG_ALERT_OFFSETS_PER_FINDING_MAX=50). Counts above are complete; re-run `yara -s` ...'. Cross-check the dataset row's truncated=true and match_count for the same finding (set at 3660/3676/3680) and the 'embedded a sample of N in the dataset row (truncated=true...)' line in uploads_<run_id>.log (3686-3691).
- **Source:** `lines 6406-6438 (census 6412-6419, cap read 6421, sample 6422-6431, footer 6432-6438); constant line 210; matching dataset cap CONFIG_LOOKUP_ROWS_PER_FINDING_MAX line 199`

### evidence/file_mapping.txt — path→SHA256 manifest with a host header, silently lossy on both edges

Written fresh (mode='w') at evidence-collection time. Carries a 6-line header block with hostname, OS and every IP address (4504-4510), then one 'path \| sha256' line per matched file. Two silent losses on the way in: (a) the loop only writes a row when os.path.exists() still holds at collection time (gate 4513), so a matched file deleted, moved or unmounted between the match and end-of-scan is dropped with no row, no counter and no log entry — the manifest can legitimately hold fewer rows than the scan reported matches, while the alert texts and dataset rows still name it; and (b) a row is written only if a hash is available (gate 4517). When a matched path has no cached hash (the scan-time hash raised) it is hashed a SECOND time here via FileHasher.calculate_sha256 — a separate implementation reading 4096-byte blocks, versus the scan path's 1 MiB chunks (984) — so 'matched files are hashed once' has exactly this exception, and that re-read happens during shutdown where it can stall on a large file. Row order is also non-deterministic: matched_files is a set (4470). This manifest is what makes the metadata-only ZIP useful and what makes duplicate-collapsing inside the ZIP lossless.

- **Control:** Not configurable (path line 2822). collect_files (default False, line 2707; read at 4529) controls only whether matched file BYTES are copied into the ZIP, not the manifest. — default `evidence/file_mapping.txt`
- **Observe:** File on disk under scanner_dir/evidence AND as file_mapping.txt at the root of the evidence ZIP (written at 4571). Count data rows (total lines minus the 6 header lines) and compare against the matched-file count in scan_summary_<run_id>.json / the 'YARA detection event' line count in alerts_<run_id>.log: a shortfall with no error line means files vanished mid-scan. A second-pass re-hash leaves no trace unless it fails, in which case FileHasher logs via the root logger ('Error calculating hash for ...', 1473) — UNOBSERVABLE on a real host, since setup_logging strips root handlers and pins WARNING; observing re-hashing directly would need a counter or a log_manager call at 4515-4516.
- **Source:** `path line 2822; EvidenceCollector.matched_files set 4470, add_matched_file 4486-4490; _process_matched_files lines 4501-4519 (header 4504-4510, existence gate 4513, cache lookup 4514, re-hash 4515-4516, hash gate 4517, row write 4519); FileHasher.calculate_sha256 lines 1464-1474 (4096-byte reads 1469, root-logger error 1473); scan-path hasher _sha256_file 984-993 via _calculate_match_sha256 6080-6089; ZIP inclusion line 4571; collect_files 2707 and 4529`

### Evidence ZIP creation and naming

A single DEFLATE ZIP named evidence_<hostname>_<run_id>.zip is written into evidence/. There is no size guard and no compression-level knob; with collect_files=true it contains full copies of matched files, so on a broad rule set it can be the single largest thing the scanner puts on the host.

- **Control:** Not configurable (path lines 2904-2906; ZIP_DEFLATED literal line 4531) — default `evidence/evidence_<hostname>_<run_id>.zip`
- **Observe:** The file itself — check its size with `ls -l`/`du`, and list members with `unzip -l`. Not referenced in scan_summary_<run_id>.json at all, so the disk is the only place to look; 'Evidence collection completed successfully' in system_<run_id>.log (7485) only proves collect_evidence() returned.
- **Source:** `evidence_zip lines 2904-2906; _create_evidence_zip lines 4521-4571; collect_evidence lines 4492-4499; success log 7485`

### Content-addressed evidence entries: matched_files/<sha256>

When collect_files is on, each matched file is stored under its SHA256 as the entry name rather than its original path. Original paths are recoverable only through file_mapping.txt, which is bundled in the same ZIP. A per-file write failure is logged and skipped without aborting the archive (4554-4555).

- **Control:** CONFIG_COLLECT_FILES (line 163), also reachable as the `collect_files` options key (line 772), the run() kwarg (7117-7118, 7144) and ScanConfig parse (2706-2707) — default `false (no file copies)`
- **Observe:** `unzip -l evidence_*.zip` shows entries named matched_files/<64-hex> when collect_files=true; absent entirely when false.
- **Source:** `entry name line 4549; gate line 4529; per-file failure handling 4554-4555`

### Evidence ZIP de-duplicates identical content across paths

Packaging iterates file_hashes and skips any hash already packaged, because the previous per-path loop wrote a full copy per path under the SAME arcname — zipfile only WARNS on a repeated arcname and stores the member anyway, so the archive silently carried N copies while a reader could only extract the first. Measured on the XSIAM twin: 22,918 matched paths held 22,213 distinct files — 705 redundant copies, 506 MB. A hash is marked packaged only AFTER a successful write (4553), so a path that vanished mid-scan does not block another path with the same content.

- **Control:** Not configurable (active whenever collect_files is on) — default `Always on when collect_files=true`
- **Observe:** system_<run_id>.log line 'Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped' with data {unique_files_packaged, duplicate_copies_skipped} — routed through LogManager specifically so this is observable (it used to be a logging.info that reached nothing). Note the line is emitted ONLY when duplicates_skipped > 0 (gate at 4556), so its absence on a dupe-free scan is expected.
- **Source:** `lines 4542-4561; post-write marking 4553; emit gate 4556; EvidenceCollector._log lines 4473-4484`

### Metadata-only evidence ZIP is the default (collect_files=false)

By default no matched file bytes are copied at all — the ZIP carries only the alert texts and file_mapping.txt, so a responder locates and fetches files by path/hash manually. This is the difference between a few KB and potentially gigabytes on the endpoint.

- **Control:** CONFIG_COLLECT_FILES (line 163); options key `collect_files` (line 772); ScanConfig parse lines 2706-2707 — default `false`
- **Observe:** system_<run_id>.log line 'Evidence: collect_files=false - packaging metadata only (no matched file copies)' with data {"collect_files": false} (4562-4564); and `unzip -l` showing no matched_files/ entries. The posture string in scan_summary_<run_id>.json (field "posture", written at 2326) carries 'files=off' (built at 2728).
- **Source:** `gate line 4529; else-branch _log lines 4562-4564; posture construction line 2728; posture into summary line 2326`

### Evidence ZIP bundles only alert/*.txt — .alert files are excluded by design

The ZIP loop filters on endswith('.txt'), which interacts with the scheduled cleanup script: once that task has renamed .txt → .alert, a later evidence collection would package nothing. Within one run the ordering is safe (collection at 7484 happens before scheduling at 7493), but a manual re-run after rotation silently yields an alerts-free ZIP.

- **Control:** Not configurable (literal filter line 4567) — default `-`
- **Observe:** `unzip -l evidence_*.zip` shows alerts/<rule>.txt entries. After the scheduled cleanup fires, scanner_dir/alert holds <rule>.alert files while the ZIP still holds the .txt copies taken earlier.
- **Source:** `lines 4566-4569; rename script lines 4757-4771; ordering evidence collect 7483-7487 before schedule 7489-7498`

### Evidence is collected on the fatal-failure path too

A scan that found matches and then died used to return immediately and produce no ZIP at all (verified: 1 match, alert text written, 0 zips). The failure branch now calls collect_evidence() best-effort before returning, because the alert texts and file_mapping are exactly what a responder needs from a partial run. It also emits the terminal 'failed' status first (7432-7435). Note this is the cooperative scan_failed branch; a crash caught by run()'s outer except (7550) does NOT collect evidence.

- **Control:** Not configurable — default `Always on (scan_failed branch)`
- **Observe:** After a forced fatal failure: evidence_<host>_<run_id>.zip exists AND system_<run_id>.log contains 'Evidence collected from failed scan' (7438); scan_summary_<run_id>.json outcome='failed' (derived 7619-7620).
- **Source:** `run() failure branch lines 7415-7447 (status 7432-7435, evidence 7436-7440); outer except path 7550-7603 (no evidence collection)`

### Cancelled scans produce NO evidence ZIP and NO cleanup scheduling — surprising asymmetry

run() returns early on scanner.cancel_requested (7397-7413), before collect_evidence() at 7484 and before schedule_final_cleanup() at 7493. So an operator-cancelled scan leaves alert/<rule>.txt files on disk permanently un-zipped and un-rotated, until the NEXT scan's initial_cleanup deletes them. The failure path was fixed to still collect evidence; the cancel path was not. The finally block still runs, so the summary JSON is written and delivery shortfall is reported.

- **Control:** Not configurable — default `-`
- **Observe:** Cancel a scan that has already matched: scanner_dir/alert holds <rule>.txt files, scanner_dir/evidence holds NO zip for that run_id, and scan_summary_<run_id>.json exists with outcome='cancelled' and cancel_source set (7617-7618, 7654). Contrast with the failed path, which does produce a ZIP.
- **Source:** `cancel early-return lines 7396-7413; evidence collection lines 7483-7487; cleanup scheduling lines 7489-7498; finally block 7605-7666`

### Runtime-generated cleanup script (cleanup_script.sh / .bat) in scanner_dir root

The script is generated from config.alert_dir at runtime rather than decoded from an embedded base64 blob. The blobs it replaced targeted c:\xdr-data\alert and /opt/xdr-data/alert, which never matched the real <scanner_dir>/alert — so scheduled cleanup had been renaming nothing at all. Generating from alert_dir keeps script and data in lock-step, including under a YARA_SCANNER_DIR override. On POSIX it is chmod 0755 (line 4746).

- **Control:** Not configurable (name literal lines 2819-2821; content generated lines 4748-4771) — default `cleanup_script.bat (Windows) / cleanup_script.sh (POSIX)`
- **Observe:** The file at the root of scanner_dir; `cat` it and confirm the cd target is the real alert dir. system_<run_id>.log records 'Cleanup script decoded and ready for scheduling' (4713-4714). Note the file is written only when at least one alert .txt exists (gate at 4704).
- **Source:** `cleanup_script path lines 2819-2821; _decode_cleanup_script lines 4739-4746; _get_cleanup_script_content lines 4748-4771; log line 4714`

### Alert rotation: .txt → .alert, executed by the scheduled task, not by the scan

The generated script's whole job is renaming alert/*.txt to *.alert one minute after the scan (Windows: `ren *.txt *.alert`; POSIX: a mv loop). Both variants `cd` into alert_dir and exit 0 cleanly if it is missing ('if errorlevel 1 exit /b 0' at 4761; '\|\| exit 0' at 4766) — which is why HostCleanup recreates the directory empty rather than leaving it deleted. Rotation is purely cosmetic; nothing in the scanner reads .alert files back, and the evidence ZIP filter only sees .txt.

- **Control:** Not configurable — default `Always, when scheduling succeeds`
- **Observe:** Wait ~1-2 min after a matching scan, then list scanner_dir/alert: files have become <rule>.alert. This is the artefact that proves the scheduled task actually ran, and it is only visible over SSH/on-box — no API surface shows it.
- **Source:** `lines 4757-4771 (Windows 4757-4763, POSIX 4764-4771)`

### Windows scheduled task 'CleanupScript' registered as SYSTEM  <sub>windows</sub>

schtasks /create /tn CleanupScript /tr <cleanup_script> /sc once /st <now+1min> /ru SYSTEM /f, run with shell=False and check=True. This is a persistent Task Scheduler entry created OUTSIDE scanner_dir; nothing in the scanner ever deletes it, and /f means each scan overwrites the same named task. A CalledProcessError is logged and re-raised (4788-4790) into schedule_final_cleanup's handler, which logs 'Failed to schedule cleanup' and re-raises again into run()'s guard at 7497.

- **Control:** Not configurable (task name and args are literals lines 4780-4785) — default `Task name 'CleanupScript', fires ~1 minute after scan end`
- **Observe:** `schtasks /query /tn CleanupScript` on the endpoint. system_<run_id>.log records 'Windows cleanup task scheduled successfully' (4719); the scheduled time is only in a bare logging.info (4787) — UNOBSERVABLE, read the task itself.
- **Source:** `_schedule_windows_cleanup lines 4773-4790; caller lines 4716-4719; re-raise chain 4788-4790 → 4729-4733 → 7497-7498`

### Linux (and any non-Windows/non-Darwin) systemd unit /etc/systemd/system/yara-cleanup.service — written, ENABLED, never removed  <sub>linux</sub>

A oneshot unit running as root is written outside scanner_dir, then daemon-reload + enable + start. Because it is `enable`d with WantedBy=multi-user.target, it re-runs the rename script on EVERY subsequent boot, forever, long after the scan is gone — and nothing in the scanner ever disables or deletes it. Missing systemd (FileNotFoundError) and non-root (PermissionError) are both caught and downgraded to warnings, and CalledProcessError is logged without re-raising, since the rename is cosmetic. Ownership is verified (st_uid must be 0) before the systemctl calls. Dispatch is the `else` branch at 4724, so this also fires on any platform that is neither Windows nor Darwin.

- **Control:** Not configurable (path and unit text literals lines 4795-4810) — default `/etc/systemd/system/yara-cleanup.service, enabled`
- **Observe:** `systemctl is-enabled yara-cleanup.service` and `ls -l /etc/systemd/system/yara-cleanup.service` on the endpoint. system_<run_id>.log records 'Linux cleanup service scheduled successfully' (4727) — note that message is emitted even when the helper internally warned-and-skipped (no exception propagates), so the log alone does not prove the unit exists.
- **Source:** `_schedule_linux_cleanup lines 4792-4832; ownership check 4815-4817; exception handling 4825-4832; caller lines 4724-4727 (the `else` branch)`

### macOS LaunchDaemon /Library/LaunchDaemons/com.yarascanner.cleanup.plist  <sub>darwin</sub>

On Darwin a RunAtLoad LaunchDaemon is written and launchctl-loaded — this replaced a bug where the code wrote a systemd unit on macOS and threw on every scan. Like the Linux unit it lives outside scanner_dir, persists across reboots (RunAtLoad re-fires the rename script at every boot), and is never unloaded or deleted by the scanner. PermissionError (non-root), missing launchctl and CalledProcessError are all caught as warnings/errors without re-raising.

- **Control:** Not configurable (label and plist path literals lines 4837-4838) — default `/Library/LaunchDaemons/com.yarascanner.cleanup.plist, label com.yarascanner.cleanup`
- **Observe:** `ls -l /Library/LaunchDaemons/com.yarascanner.cleanup.plist` and `launchctl list \| grep yarascanner`. system_<run_id>.log records 'macOS cleanup LaunchDaemon scheduled' (4723) — like the Linux case this is emitted even if the helper swallowed a PermissionError, so verify on disk.
- **Source:** `_schedule_macos_cleanup lines 4834-4865; plist body 4839-4854; exception handling 4860-4865; caller lines 4720-4723`

### Cleanup scheduling is gated on at least one alert .txt existing

_check_for_alerts lists alert_dir and requires any name ending '.txt'. A scan with zero matches never writes the cleanup script and never registers the scheduled task/unit/daemon — so on a clean fleet the scanner leaves no OS-level persistence at all. Scheduling is also only reached on the completed path (called from run() at 7493), so cancelled and failed runs never register it either.

- **Control:** Not configurable — default `Always on`
- **Observe:** Zero-match scan: no cleanup_script.* in scanner_dir root, no CleanupScript task / yara-cleanup.service / LaunchDaemon. system_<run_id>.log records 'No alerts found, skipping cleanup scheduling' (4706).
- **Source:** `_check_for_alerts lines 4735-4737; gate lines 4704-4708; sole caller run() lines 7489-7498`

### Cleanup scheduling is also skipped when diagnostics must be preserved

Two independent conditions abort scheduling to keep local diagnostic data: (a) the error logger has errors AND zero rules compiled, or (b) more than 50% of all LogManager entries were of type 'error'. The second is a ratio over the log-type counters, so a scan that logged mostly errors preserves its artefacts even if rules compiled fine. Condition (a) is additionally pre-checked by the caller at 7490, which skips the call entirely and logs a different message.

- **Control:** Not configurable (ratio literal 0.5 at line 4692) — default `error_ratio > 0.5 or (has_errors and valid_rules_count == 0)`
- **Observe:** system_<run_id>.log records 'Critical errors detected - skipping cleanup to preserve diagnostic data' with data {'preserve_logs': True} (4697-4700), or — when the caller's pre-check fires — 'Cleanup skipped due to critical YARA processing errors' (7496). Alert .txt files stay unrotated either way.
- **Source:** `schedule_final_cleanup lines 4681-4708; ratio 4690-4693; log_type counters LogManager lines 2189-2190; caller pre-check 7490-7496`

### control/cancel.flag — cooperative cancel signal written by mode=cancel

A separate, deliberately lightweight invocation (no logging/scan machinery) creates control/ and writes a JSON flag with requested_at_ms, source='xdr_action' and any tenant_id_override. It also reads control/running.json first and reports back whether a scan appears alive. Note this creates scanner_dir on a host that has never scanned, and it uses _default_scanner_dir() directly (852) while the watcher side resolves config.control_dir (5069) — so a YARA_SCANNER_DIR set for the scan must also be set for the cancel invocation or the flag lands in the wrong tree.

- **Control:** Not configurable; entry point is CONFIG_MODE='cancel' (line 160), the `cancel()` Action Center entry point (lines 7736-7738), or mode=cancel routed at 7154-7155 — default `control/cancel.flag`
- **Observe:** File at scanner_dir/control/cancel.flag containing {"requested_at_ms":..., "source":"xdr_action", "tenant_id_override":""}. The cancel invocation's own return string is 'Cancel signal delivered (<path>) \| scanner running: yes\|no \| scan_id=...' (884-887).
- **Source:** `_handle_cancel_request lines 845-887; scanner_dir resolution 852; write lines 874-882; return string 884-887; entry points lines 7154-7155, 7736-7738; watcher-side path YaraScanner.cancel_flag_path line 5069`

### control/running.json — atomically-refreshed liveness marker

Written via temp + os.replace so a cross-process cancel reader never sees a half file. Carries scan_id, run_id, PID, hostname, started_at, updated_at, status, files_scanned and detections, refreshed on every heartbeat (and once at watcher start, 5146). mode=cancel treats it as 'a scan is alive' only if updated within SCANS_HEARTBEAT_SECS*3 + 60 seconds. Removed in scan_system's finally block (6946) — but NOT by HostCleanup, which never touches control/.

- **Control:** Freshness window derives from SCANS_HEARTBEAT_SECS / YARA_HEARTBEAT_SECS (line 307); used at line 870 — default `control/running.json; freshness window 600*3+60 = 1860s`
- **Observe:** `cat /opt/yara_scanner/control/running.json` mid-scan shows live files_scanned/detections and a PID you can match with `ps`; the file is gone after the run. The cancel entry point's return line echoes scan_id from it.
- **Source:** `path line 5070; _write_running_marker lines 5173-5195; _remove_running_marker lines 5197-5202; first write 5146; refresh in _maybe_heartbeat line 5260; removal call line 6946; freshness check lines 865-870`

### Stale cancel-flag disambiguation by mtime, with coarse-filesystem tolerance

At scan start a pre-existing cancel.flag is removed ONLY if its mtime predates this process's start by more than CANCEL_STALE_TOLERANCE_SECS. A cancel delivered DURING the (potentially ~90s) rule-compilation phase has a newer mtime and is deliberately preserved so the watcher honours it once it starts. The 2s slack covers filesystems with coarse mtime granularity. Any exception while evaluating the flag is downgraded to a log_system line and the flag is left in place.

- **Control:** CANCEL_STALE_TOLERANCE_SECS = 2.0 (line 319) — a bare module literal, not env-reachable — default `2.0 seconds`
- **Observe:** system_<run_id>.log line 'Removed stale cancel flag from a previous run' (5142), or 'Could not evaluate pre-existing cancel flag: ...' (5144). Conversely, drop a flag during compile and confirm the scan still cancels.
- **Source:** `_start_cancellation_watcher lines 5129-5150; mtime test 5139-5142; except 5143-5144; constant line 319`

### An HONOURED cancel flag is left on disk — dead-comment hazard

_cancellation_watcher reads the flag, calls _request_cancel and breaks — it never deletes it (grep confirms os.remove(cancel_flag_path) exists only at 5141, the stale sweep). Its docstring claims 'The flag was cleared at scan start, so any flag present now is a fresh cancel', but scan start clears only STALE flags. Practical consequence: after a cancelled scan, control/cancel.flag persists — HostCleanup does not touch control/ either — until the next scan's mtime-based stale sweep removes it, so an operator inspecting the host sees a cancel flag sitting there indefinitely.

- **Control:** Not configurable — default `-`
- **Observe:** Cancel a scan, wait for it to finish, then `ls scanner_dir/control` — cancel.flag is still present while running.json is gone. Also survives a run with CONFIG_HOST_CLEANUP=always.
- **Source:** `_cancellation_watcher lines 5152-5171 (no os.remove); stale-only removal line 5141; misleading docstring 5155-5156; HostCleanup removal list 4967-4973 (no control_dir)`

### rule_cache/ — compiled-ruleset disk cache (XDR-only; the XSIAM twin has none)

yara-python rules.save()/load() persists the compiled bundle as rule_cache/rules_<key40>.yarac so a subsequent run with identical rules skips a ~90s per-rule compile loop entirely. The directory is created by _rule_cache_dir() on every run whenever caching is enabled, before the hit/miss decision. On a cache HIT the whole per-rule loop is skipped, which means failed_rules/ gets NO new .yar dumps that run and the rule counts have to be restored from the sidecar.

- **Control:** RULE_CACHE_ENABLED from YARA_RULE_CACHE (line 297) — default `enabled (disabled only when the var is explicitly 0/false/no/empty)`
- **Observe:** Files rule_cache/rules_<40hex>.yarac under scanner_dir. scan_summary_<run_id>.json fields compile_source ('cache' vs 'fresh') and compile_seconds (7651-7652). system_<run_id>.log line 'Rule cache HIT rules_xxx.yarac load=0.42s (valid=N failed=N skipped=N)' (5582-5586) or 'Rule compile FRESH 91.30s' (5599).
- **Source:** `_rule_cache_dir lines 5458-5461; _load_or_compile_rules lines 5559-5602; dir creation call 5569; constants lines 291-300`

### Rule-cache key composition (why a stale bundle can never load)

The cache key is sha256 over a format tag, the yara identity string (binding version / YARA_VERSION / platform.system() / platform.machine()), the declared externals JSON, the sorted available-module list, and the exact rule text. Because compilation is a pure function of those inputs the key cannot drift from what would actually be produced. Only the first 40 hex chars go into the filename (5569). This is what stops a 3.11-Linux bundle and a 4.1-Windows bundle colliding — directly relevant here, where Linux agents run 3.11.0 and Windows/macOS agents 4.1.0.

- **Control:** RULE_CACHE_FORMAT from YARA_RULE_CACHE_FORMAT (line 298) — bump to invalidate every cache fleet-wide — default `format '1'`
- **Observe:** Filename rule_cache/rules_<40hex>.yarac changes when rules, yara version or module availability change; bumping YARA_RULE_CACHE_FORMAT forces compile_source='fresh' in scan_summary_<run_id>.json and a new filename. The module list itself is recorded in yara_processing_<run_id>.log ('Available YARA modules: ...', line 5609), which is how you check the MODS: component.
- **Source:** `_rule_cache_key lines 5463-5476; filename truncation line 5569; _yara_version_tag lines 564-573; YARA_COMPILE_EXTERNALS lines 916-923; module probe _get_available_yara_modules 5333-5363`

### Rule-cache LRU pruning by file count AND total bytes

After each successful save, .yarac files are sorted newest-first by mtime and everything past RULE_CACHE_MAX_FILES or past the cumulative byte ceiling is deleted along with its .meta.json sidecar. The byte accumulator includes the file being tested (total += size before the comparison), so the entry that pushes the total over is the one removed. Whole function is wrapped in a bare except — pruning failure is silent. It only ever runs on the save path (5517), so a fleet that always hits the cache never prunes.

- **Control:** RULE_CACHE_MAX_FILES from YARA_RULE_CACHE_MAX (line 299); RULE_CACHE_MAX_BYTES from YARA_RULE_CACHE_MAX_MB (line 300) — default `5 files / 256 MB`
- **Observe:** `ls scanner_dir/rule_cache` never exceeds 5 rules_*.yarac; orphan .meta.json files are removed alongside. Verify by scanning with 6 distinct rule packs (each must MISS, so each triggers a save).
- **Source:** `_prune_rule_cache lines 5527-5557; sort 5545; accumulate-then-test 5547-5550; sidecar removal 5551-5555; bare except 5556-5557; sole invocation line 5517`

### Rule-cache atomic save with PID+random temp naming

rules.save() writes to '<cache_path>.<pid>.<8hex>.tmp' then os.replace()s it, under a module-level threading lock (_RULE_CACHE_LOCK). The PID+random suffix exists because Cortex runs a fresh process per action, so two concurrent per-action processes must not collide on one temp name (the lock only serialises threads inside ONE process). Save failure is best-effort (read-only or full disk just means no caching) and removes its own temp.

- **Control:** Not configurable (_RULE_CACHE_LOCK line 301) — default `Always on when caching enabled`
- **Observe:** system_<run_id>.log line 'Rule cache save failed (non-fatal): ...' on failure (5519); on success the .yarac and its .meta.json appear with no lingering .tmp beside them.
- **Source:** `_save_rule_cache lines 5499-5525; lock 5503; temp name line 5504; os.replace line 5507; sidecar 5508-5516; temp cleanup 5520-5525`

### Rule-cache orphan .tmp sweep, age-gated at 1 hour

Pruning also deletes rules_*.tmp files older than 3600s — orphans from a crash between rules.save(tmp) and os.replace(). The age gate is deliberate: a concurrent in-flight save from another per-action process must be spared. Like the rest of _prune_rule_cache it runs only after a successful save.

- **Control:** Bare literal 3600 (line 5539) — not customer-reachable — default `3600 seconds`
- **Observe:** Plant an old-mtime rules_x.tmp in rule_cache and confirm the next successful cache save (a fresh compile, not a HIT) removes it; a fresh one survives.
- **Source:** `lines 5532-5542; invoked only from _save_rule_cache line 5517`

### Rule-cache sidecar rules_<key>.yarac.meta.json restores rule counts on a HIT

Because a cache HIT skips the per-rule loop, valid/failed/skipped counts would otherwise read 0 in the scan summary. The sidecar carries valid_rules, failed_rules, skipped, the yara identity tag and the format. If the sidecar is missing or broken, the loader recovers the valid count by iterating the loaded yara.Rules object (it is iterable) — and only if valid_rules_count is still 0 — falling back to 1 if iteration fails, and returns 0 skipped.

- **Control:** Not configurable — default `one .meta.json per .yarac`
- **Observe:** scan_summary_<run_id>.json shows non-zero valid_rules/failed_rules/skipped_rules even when compile_source='cache' (7641-7643). Delete the sidecar by hand and re-run: valid_rules survives (recovered by iteration), failed_rules reads 0 and skipped_rules drops to 0. The HIT log line at 5583-5586 echoes all three.
- **Source:** `_restore_cache_meta lines 5478-5497; iteration fallback 5490-5497; sidecar write lines 5508-5516 (yara tag at 5512)`

### Corrupt / cross-version cache entries are self-healing (and probe-validated)

On a HIT the bundle is not just loaded — it is proved usable by running rules.match(data=b'', externals={'filepath':'','filename':''}), so an incompatible bundle (or one that no longer accepts the per-file externals the scanner overrides at match time) fails HERE and falls back rather than mid-scan. Any exception in the whole cache block deletes both the .yarac and its .meta.json and compiles fresh. A successful HIT also os.utime()s the file as an LRU touch.

- **Control:** Not configurable — default `Always on when caching enabled`
- **Observe:** system_<run_id>.log line 'Rule cache miss/unusable, compiling fresh: <error>' (5589); the offending .yarac and .meta.json disappear from rule_cache and scan_summary_<run_id>.json shows compile_source='fresh'. NOTE the same line is emitted for an ordinary first-run miss path failure, so pair it with the file disappearing.
- **Source:** `lines 5565-5595; probe match line 5574; utime line 5576; except + deletion lines 5588-5595`

### rule_cache is deliberately exempt from HostCleanup

HostCleanup removes this run's logs, alert/, evidence/ and failed_rules/ but explicitly never touches rule_cache — it is a cross-run performance cache, not this run's data, and is already self-capped by RULE_CACHE_MAX_FILES. So even 'keep=nothing' leaves rule_cache/ behind on the endpoint (as does control/).

- **Control:** Not configurable (absence from HostCleanup.run's removal list, lines 4967-4973) — default `Always preserved`
- **Observe:** With CONFIG_HOST_CLEANUP='always' and CONFIG_HOST_CLEANUP_KEEP='nothing', scanner_dir still contains rule_cache/ with its .yarac files after the run (and control/ with any cancel.flag).
- **Source:** `HostCleanup docstring lines 4917-4919; removal list lines 4967-4973; log-file loop 4956-4961 (logs_dir only); design comment lines 236-237`

### failed_rules/failed_rule_<name>.yar — full source dump per compilation failure

Every rule that fails to compile is dumped with a header carrying the error text and an ISO timestamp, plus the file-level preamble prepended (5742-5743) so the dump is independently re-compilable. One file per failed rule NAME, uncapped in count — a badly broken 500-rule pack writes 500 files; two failing rules sharing a name overwrite each other. Only the first 10 failures also produce a log warning (5729-5730); the .yar dumps have no such cap, and the write is wrapped in a bare except so a dump failure is silent.

- **Control:** Not configurable (path lines 5733-5736) — default `-`
- **Observe:** Files under scanner_dir/failed_rules named failed_rule_<rule>.yar, each starting '// FAILED RULE - Compilation Error'. Count them against scan_summary_<run_id>.json's failed_rules field (7641) and yara_processing_<run_id>.log's 'Failed rules skipped: N' (1680) plus 'Failed rules saved to: <dir>' (1687).
- **Source:** `lines 5726-5746; preamble prepend 5742-5743; log cap lines 5729-5730; silent except 5745-5746; summary references 1680/1687`

### failed_rules/skipped_rule_<name>_<module>.yar — module-unavailable dumps (two distinct write sites)

A rule needing a YARA module this agent's libyara lacks is SKIPPED, not failed, and dumped with a '// SKIPPED RULE - Module X not available' header. There are two independent write sites: the pre-compile static check (an explicit `import` of an unavailable module inside the rule block) and the post-compile error classifier (the module import was inherited from a stripped file-level preamble). The second variant's header adds '// (import inherited from the file-level preamble)' and says 'not available on this agent'. Directly relevant to Linux agents on yara 3.11.0.

- **Control:** Not configurable (paths lines 5665-5668 and 5712-5715) — default `-`
- **Observe:** Files under scanner_dir/failed_rules named skipped_rule_<rule>_<module>.yar. Grep the header to tell the two variants apart. Cross-check scan_summary_<run_id>.json's skipped_rules field (7643), yara_processing_<run_id>.log's 'Skipped N rules due to unavailable modules' (5754) and the result line's 'N rules skipped (module unavailable)' (7512-7513).
- **Source:** `pre-compile site lines 5653-5676 (header 5670); post-compile site lines 5698-5724 (header 5717-5718); counter persisted line 5748; yara_processing summary 5754; result-line surfacing lines 7509-7513`

### failed_rules/raw_yara_content.yar — whole-input dump when rule splitting yields nothing

If _split_yara_rules returns zero rules, the entire decoded YARA input is dumped to a single fixed-name file with an explanatory header before the ValueError is raised. Fixed name means it is overwritten each time rather than accumulating, and it can be large (the b64 input is capped at 50 MB at decode time, line 430 — the DECODED text can be larger still). The write is wrapped in a bare except, so a failure to dump is silent.

- **Control:** Not configurable (fixed name line 5630); input size ceiling 50_000_000 at line 430 — default `failed_rules/raw_yara_content.yar (only on split failure)`
- **Observe:** Presence of scanner_dir/failed_rules/raw_yara_content.yar starting '// RAW YARA CONTENT - Failed to split into individual rules'. yara_processing_<run_id>.log carries 'COMPILATION_ERROR: No YARA rules found in provided content' (5628). Because the ValueError propagates out of YaraScanner construction, expect outcome='failed' with 0 files scanned.
- **Source:** `lines 5625-5638; header 5632; silent except 5636-5637; size guard line 430`

### HostCleanup — opt-in end-of-run removal of this run's on-host working files

CleanupManager only ever cleans at the START of the NEXT scan, so a host swept once and never re-scanned keeps its logs, evidence ZIP and alert files forever. HostCleanup closes that gap: it runs once, in run()'s finally block, after delivery has fully drained (uploader stop at 7609-7612) and after the summary is written. Off by default precisely because it deletes files on a customer endpoint, and the whole block is isolated in its own try/except so a cleanup failure cannot mask the scan result.

- **Control:** CONFIG_HOST_CLEANUP (line 238) — deliberately NOT an options key (rejected as unknown by _parse_options_string, lines 825-828 against _VALID_OPTION_KEYS 771-775; rationale comment 150-158) — default `"off"`
- **Observe:** With it on: this run's seven log files and the alert/evidence/failed_rules contents are gone from scanner_dir immediately after the run, while other run_ids' logs remain. UNOBSERVABLE: the 'Host cleanup removed N path(s)' message is a bare logging.info (7705-7707) and LogManager's handlers are already closed by then — verify on disk instead.
- **Source:** `HostCleanup class lines 4868-4986; invocation lines 7693-7711; isolating except 7710-7711; constants lines 217-239`

### HostCleanup KEEP tiers (nothing / summary / evidence)

'summary' (default) keeps only scan_summary_<run_id>.json; 'evidence' additionally keeps the whole evidence directory; 'nothing' removes the summary too. Note the asymmetry: alert_dir and failed_rules_dir are rmtree'd unconditionally in ALL three tiers — 'evidence' spares only evidence_dir. An unrecognised KEEP value behaves like 'summary': it is never compared for equality except against 'evidence' and 'nothing', so anything else keeps the summary and wipes the rest.

- **Control:** CONFIG_HOST_CLEANUP_KEEP (line 239); VALID_KEEP tuple line 4883 (declared but never enforced in run()) — default `"summary"`
- **Observe:** After a cleaned run: keep='summary' → only scan_summary_<run_id>.json remains in logs/ for that run; keep='evidence' → evidence/*.zip also survives; keep='nothing' → no trace of the run_id anywhere (rule_cache/ and control/ still survive).
- **Source:** `lines 4967-4973; keep comparisons 4967 and 4972; VALID_KEEP 4883; constants lines 231-239`

### HostCleanup refuses to delete unless the summary JSON durably exists

run() returns immediately with nothing removed if summary_path is missing or is not a file. The summary is the audit record that this run happened and what it found; without it the scanner cannot even attest the run completed, so it declines to delete blind. Mirrors the verify-before-delete principle used in dataset consolidation. Note write_scan_summary always RETURNS the path even when the write failed (2343), so this check — os.path.isfile — is the thing that actually catches a failed write.

- **Control:** Not configurable — default `Always enforced`
- **Observe:** Make write_scan_summary fail (e.g. read-only logs dir): scanner_dir still holds this run's alert/evidence files even with CONFIG_HOST_CLEANUP='always', and scan_errors_<run_id>.log carries 'Failed to write scan summary JSON: ...' (2342).
- **Source:** `lines 4914-4929 (guard 4928-4929); write_scan_summary return-on-failure line 2343; failure log 2342`

### HostCleanup on_delivery gate — refuses when there is no delivery channel to verify

In 'on_delivery' mode cleanup proceeds only when _delivery_shortfall is empty. Crucially, if BOTH create_alerts and write_dataset are off, an empty shortfall means 'nothing was ever attempted', not 'everything landed' — treating that as safe would wipe the only copy of the findings, so it refuses. The same _shortfall value is computed once (7631) and shared with the summary JSON (7664) and the gate (7702) so the two can never disagree.

- **Control:** CONFIG_HOST_CLEANUP='on_delivery' (line 238); CONFIG_CREATE_ALERTS (161) / CONFIG_WRITE_DATASET (162) form the delivery_enabled flag (computed 7700-7701 from the PARSED config booleans) — default `-`
- **Observe:** scan_summary_<run_id>.json 'delivery_shortfall' field is the exact input. UNOBSERVABLE: the skip itself is reported via bare logging.info 'Host cleanup skipped: on_delivery has no delivery channel to verify (alerts and dataset writes are both off) - keeping the local copy' (7708-7709), which reaches no structured log because the handlers are already closed — so verify by disk state plus the summary's shortfall field.
- **Source:** `should_run lines 4890-4912 (delivery gate 4902-4909, shortfall gate 4910-4911); shared _shortfall line 7631 used at 7664 and 7702; skip log 7708-7709; _delivery_shortfall lines 7052-7092`

### HostCleanup runs only on outcome=='completed'

Scoped deliberately: a crash's delivery accounting is not trustworthy, and a cooperative-cancel's partial run is exactly what an operator would want to inspect afterwards rather than have wiped. So 'always' does not mean always — a failed or cancelled run keeps everything regardless of configuration. Because the log-handler closing (stop_logging / error_logger.close) sits INSIDE the same `if _outcome == "completed"` block, a failed/cancelled run also leaves its handlers open until the unconditional stop_logging at 7715.

- **Control:** Not configurable (literal outcome check line 7694) — default `-`
- **Observe:** Cancel a scan with CONFIG_HOST_CLEANUP='always': scan_summary_<run_id>.json shows outcome='cancelled' and all this run's logs/alerts remain on disk. No 'Host cleanup skipped' line is emitted either (the skip log at 7708 is inside the completed branch).
- **Source:** `outcome derivation lines 7617-7622; gate line 7694; handler close 7695-7698; unconditional stop_logging 7714-7715`

### HostCleanup closes log FileHandlers before deleting (Windows WinError 32)

log_manager.stop_logging() AND config.error_logger.close() are called immediately before cleanup, not left to the unconditional stop further down (7714-7715). Both hold per-category log files open for the whole run — LogManager for six categories, ErrorLogger separately for yara_processing, which is NOT one of LogManager's handlers. POSIX allows unlinking an open file; Windows refuses, so os.remove fails with WinError 32 and HostCleanup records it as an error in its errors list — i.e. the close is needed on every platform but only Windows suffers when it is missing. Verified live in two rounds: closing only LogManager's handlers fixed six of seven files; the seventh needed ErrorLogger.close(), which had never been called anywhere before. Consequence: HostCleanup's own messages cannot use log_manager and go through bare `logging` instead.

- **Control:** Not configurable — default `Always on the cleanup path`
- **Observe:** On a Windows agent with cleanup on: all seven of this run's log files are actually gone (before the fix, yara_processing_<run_id>.log survived). UNOBSERVABLE: errors surface only via the log=logging.warning callback passed at 7704 ('host cleanup could not remove <path>', emitted at 4984-4985), which reaches no structured log; confirm by disk listing.
- **Source:** `close calls lines 7695-7698 (rationale comment 7675-7692); ErrorLogger.close lines 1541-1555; LogManager.stop_logging lines 2345-2356; error surfacing 4984-4985 with log callback bound at 7704`

### HostCleanup recreates alert/evidence/failed_rules empty after wiping

After the rmtree pass the three directories are recreated empty, for two reasons: it matches initial_cleanup's invariant that they always exist, and it keeps the scheduled rename task — which cd's into alert_dir — exiting cleanly instead of hitting a missing directory. makedirs failures are swallowed. Note evidence_dir is recreated even in the keep='evidence' tier (where it was never removed), which is harmless because of exist_ok=True.

- **Control:** Not configurable — default `Always on the cleanup path`
- **Observe:** After a cleaned run, scanner_dir/alert, /evidence and /failed_rules exist and are empty (not absent); logs/ keeps only what the KEEP tier spared.
- **Source:** `lines 4975-4982 (loop 4978-4982)`

### HostCleanup identifies this run's logs the same way retention does

It instantiates a CleanupManager and reuses _extract_run_id_from_log_name rather than a second pattern, so the two mechanisms can never disagree about which files belong to which run, and a DIFFERENT run's logs (the LOG_KEEP_SCANS-retained history) are never touched. The summary file is excluded from that loop by basename (4958-4959) and handled separately per KEEP tier. Because the regex matches .log and .json, the summary would otherwise have been caught by the loop.

- **Control:** Not configurable — default `-`
- **Observe:** With 3 prior runs' logs present, run a cleaned scan: only the current run_id's files disappear; the 3 prior run_id groups are intact.
- **Source:** `lines 4951-4961 (CleanupManager instantiation 4955, name skip 4958-4959, match 4960); regex reuse line 4582`

### Scanner directory self-exclusion from the scan walk (per platform)

scanner_dir is injected into each platform's skip list so the scanner never scans its own logs, alert texts, evidence ZIP or rule cache — which would otherwise be a guaranteed self-match on any rule that looks for the strings it writes. Windows also carries hardcoded 'C:\yara_scanner\' (2914) and a 'C:\yara_scanner\*' pattern (2920) alongside the dynamic scanner_dir (2917), which is normpath+lowercased at 2923 and therefore has no trailing separator — so the Windows startswith at 6286 already covers the bare root. Linux (2937) and Darwin (2971) append with a trailing '/', so their matchers additionally compare against the bare root (6322, 6345), because a plain startswith never matched the directory os.walk yields for the directory itself — the scanner's own root used to be walked even though its contents were correctly skipped.

- **Control:** Not configurable (self-injection lines 2917, 2937, 2971) — default `Always on`
- **Observe:** statistics_<run_id>.log 'Skip reasons: ...' line with its skip_breakdown data (6641-6646) shows the exclusions; no alert ever names a path under scanner_dir. On a targeted scan of scanner_dir itself, the result line carries 'WARNING: N requested target(s) EXCLUDED by the skip list' (7521-7524) and scan_errors_<run_id>.log carries 'Requested scan target is excluded by the skip list...' (6862-6866); scan_summary_<run_id>.json carries excluded_targets (7635).
- **Source:** `Windows lines 2908-2925 (normalize 2923); Linux lines 2927-2939; Darwin lines 2941-2976; matcher lines 6280-6360 (bare-root tests 6322, 6345); excluded-target reporting lines 6856-6866 and 7514-7524`

### macOS case-sensitivity probe writes and deletes /tmp/CaSe_TeSt_YaRa_<pid> per scanned file  <sub>darwin</sub>

**⚠ OBSERVABILITY GAP**  
_get_real_path calls _is_case_sensitive_fs() on Darwin, and that function creates, writes, stats and removes a probe file in /tmp on every call — with NO caching or memoisation of any kind. _get_real_path has exactly one caller, scan_file line 6132, reached for every file that passed the exists / read-permission / _is_special_file gates, so a macOS scan performs one create + one existence check + one unlink in /tmp for essentially EVERY file it examines. This is host footprint outside scanner_dir entirely, and it is invisible in every log. The PID suffix keeps concurrent processes from colliding. The probe's RESULT is used (a False result lowercases the returned path at 503/513), but because nothing caches it a case-sensitive volume pays exactly the same per-file I/O cost as a case-insensitive one.

- **Control:** Not configurable (path literal line 467) — default `/tmp/CaSe_TeSt_YaRa_<pid>`
- **Observe:** UNOBSERVABLE: nothing in any of the seven log files records it. Confirm with `fs_usage -f filesys \| grep CaSe_TeSt_YaRa` (or dtrace) on the macOS endpoint during a scan, or by watching /tmp inode churn. There is no artefact left behind, since the probe is unlinked immediately (and any failure is swallowed by the bare except at 474-475, which reports 'not case-sensitive'). To close it: NEEDS_INSTR. Minimal: memoize + log once in _is_case_sensitive_fs - add a module-level cache (e.g. `_CASE_SENSITIVE_FS = None`) and, on the first Darwin evaluation, emit logging.info(f"Case-sensitivity probe (/tmp/CaSe_TeSt_YaRa_{os.getpid()}): case_sensitive={result}") plus logging.info on the except arm at 536-537 recording the probe failure before returning False. Because every caller path runs inside the scanner (after setup_logging at 7461), that line lands in logs/diagnostics_<run_id>.log. Ideally also add a `case_sensitive_fs` boolean to scan_summary so the decision is visible without reading the log.
- **Source:** `_is_case_sensitive_fs lines 462-477 (Darwin branch 466-475); _get_real_path Darwin branches lines 501-505 and 511-515; sole caller scan_file line 6132 (after gates at 6100, 6103, 6129)`

### Per-file size ceiling bounds how much the scanner reads off the disk

Files larger than max_file_bytes are rejected before yara.match, so they are never read. The env parser enforces minimum=0 specifically because a NEGATIVE value parsed fine and made max_file_bytes negative — every file then failed the size check and the scan reported success having scanned nothing. 0 legitimately means 'no size cap' (the falsy short-circuit at 2829 and the `if max_bytes` guard at 6143).

- **Control:** YARA_MAX_MB via _env_number (line 2828); byte conversion line 2829; enforced lines 6142-6144 — default `64 MB`
- **Observe:** statistics_<run_id>.log 'Skip reasons: ...' line whose skip_breakdown data carries the 'File too large' bucket (6641-6646), and the same bucket under file_processing.skip_breakdown in the 'COMPREHENSIVE SCAN REPORT' payload (6989). scan_summary_<run_id>.json carries only the aggregate files_skipped (7638) — it has NO skip_reasons field.
- **Source:** `lines 2825-2829; scan_file check lines 6142-6144; _env_number lines 70-101 (minimum rejection 96-100)`

### Matched files are hashed once: SHA256 computed per match, reused by evidence

scan_file hashes ONLY matched files (1 MB chunks via _sha256_file) rather than every scanned file, and hands the digest to both _write_alerts and evidence_collector.add_matched_file. _process_matched_files reuses that cached hash and re-reads (4 KB chunks, FileHasher) only for paths that somehow lack one. This is the difference between reading every file twice and reading only the tiny matched subset twice. A hash failure logs an error and yields None, in which case the alert block simply omits the 'File SHA256:' line and the path is dropped from file_mapping.txt. See the file_mapping.txt entry for the one case where a matched file really is hashed twice.

- **Control:** Not configurable (chunk sizes 1024*1024 line 984 and 4096 line 1469) — default `-`
- **Observe:** alert/<rule>.txt carries a 'File SHA256:' line (6402) and evidence/file_mapping.txt the same digest for the same path (4519) — identical values prove the hash was computed once and reused. The dataset row's file_sha256 (3673) is the same value again. Hash failures appear as 'Failed to hash matched file <path>: ...' in scan_errors_<run_id>.log (6085-6088).
- **Source:** `_calculate_match_sha256 lines 6080-6089; _sha256_file lines 984-993; reuse lines 6165-6173; fallback re-hash lines 4514-4518; FileHasher lines 1463-1474`

### Per-offset match detail is deliberately NOT retained in memory

ResultsUploader used to build one dict per matched offset and hold them all for the whole scan — measured at 1,048,035 offsets → ~15 GB RSS on one endpoint — to be serialized by save_results(), whose only caller (upload_results) is never invoked, so the data was accumulated and then discarded. Streaming it to disk was considered and rejected: alert_dir/<rule>.txt already records the offsets (subject to the CONFIG_ALERT_OFFSETS_PER_FINDING_MAX sample), so a second copy would duplicate an already-large artefact. What IS retained per finding is bounded: a capped offsets/strings sample plus an uncapped per-string-id COUNT dict. This is a host-footprint capability expressed as an absence.

- **Control:** Not configurable — default `-`
- **Observe:** Process RSS during a match-heavy scan (psutil / Task Manager); 'System Resources \| CPU: ... \| Memory: N MB' lines in performance_<run_id>.log every log_interval (emitted from _log_progress at 6550, NOT gated by any monitor flag), and additionally 'Performance Snapshot \| ... Memory: NMB' lines when YARA_ENABLE_PERF_MONITOR is on (1969-1976). No results file of any kind appears under scanner_dir.
- **Source:** `ResultsUploader.__init__ comment lines 3166-3175; add_match aggregation lines 3609-3654 (capped sample 3651-3653, uncapped id counts 3645)`

### Resource-monitor sampling histories are ring-buffered (memory, not disk)

StatisticsManager allocates a 1000-entry performance-snapshot deque unconditionally (1787) but only fills it when YARA_ENABLE_PERF_MONITOR is on (start_monitoring returns early at 1861-1863). SystemResourceMonitor — which owns the 360-sample resource deque and the 100-entry alert deque — is only CONSTRUCTED when YARA_ENABLE_RESOURCE_MONITOR is on (6780-6782), so those two buffers do not exist at all by default. All three are bounded, so a multi-hour scan cannot grow them without limit.

- **Control:** YARA_ENABLE_PERF_MONITOR (lines 2851-2853) and YARA_ENABLE_RESOURCE_MONITOR (lines 2854-2856); maxlens are bare literals at 1787 and 2385-2386 — default `both monitors false; maxlen 1000 / 360 / 100`
- **Observe:** With the defaults, performance_<run_id>.log is NOT empty — it still receives the '=== Performance Monitoring Started ===' banner (1842), one 'System Resources \| ...' line per progress heartbeat (6550), worker-startup/cleanup lines (6824, 6724) and the worker-performance summary (6657). Turning YARA_ENABLE_PERF_MONITOR on adds 'Performance Snapshot \| CPU: ... (system ...%) \| Memory: ...' lines (1969-1976); turning YARA_ENABLE_RESOURCE_MONITOR on adds 'System resource monitoring started/worker started' lines and a resource_summary block in the COMPREHENSIVE SCAN REPORT payload (7023-7025). scan_summary_<run_id>.json has NO performance_metrics field — that block lives in the log payloads (7462) and the report.
- **Source:** `performance_history line 1787; start_monitoring gate lines 1860-1868; logger wiring to LogManager's PERFORMANCE file lines 1816-1821; resource_history/alert_history lines 2385-2386; config flags lines 2851-2859; resource_monitor construction lines 6780-6782; report resource_summary 7023-7025`

### Final comprehensive report lands only in statistics_<run_id>.log — and is cut at 4000 chars, losing scan_metadata / system_info / rule_compilation first

upload_final_comprehensive_report assembles the richest single record a run produces (scan_metadata, file_processing with skip_breakdown, detection_results with detection_breakdown + top_10_rules, rule_compilation, system_info, performance_summary, optional resource_summary, efficiency_score) and hands the whole dict to log_manager.log_statistics as the structured `data` payload — there is no separate report file, so this log line IS the report. LogManager._log serialises it with json.dumps(..., sort_keys=True) and cuts the string at 4000 chars. Because keys are sorted ALPHABETICALLY, not in build order, the tail discarded is system_info (the agent's python_version / yara_version), then scan_metadata (hostname, targets_scanned, start/end times), then rule_compilation — while detection_results, efficiency_score and file_processing sort early and survive. The one-line header 'COMPREHENSIVE SCAN REPORT \| Efficiency Score: NN.N/100' is outside the payload and always survives intact.

- **Control:** Not configurable — the 4000 limit is a bare literal in LogManager._log (line 2176) — default `4000 chars`
- **Observe:** grep '...(truncated)' logs/statistics_<run_id>.log; the surviving line is 'COMPREHENSIVE SCAN REPORT \| Efficiency Score: ... \| data={...}'. Confirm the loss by checking the JSON blob ends mid-key and contains no "system_info" / "scan_metadata" keys, even though the same values are present in the init_data payload in system_<run_id>.log. The same cap applies to the comprehensive_final_stats payload attached to both the 'Scan completed successfully in ...' system record and the 'SCAN COMPLETED SUCCESSFULLY in ...' statistics record.
- **Source:** `upload_final_comprehensive_report def 6971, report built 6974-7017, performance_summary 7019-7021, resource_summary 7023-7025, efficiency_score 7027-7036, log_statistics call 7038-7042 (header text 7040); LogManager.log_statistics 2196-2198; LogManager._log 2163-2190 with json.dumps(sort_keys=True) at 2173 and the cut at 2176-2177; comprehensive_final_stats 7454-7469 emitted at 7471-7474 and 7478-7481`

### alerts_<run_id>.log carries TWO structured records per matched file, and is the only artefact holding the junction-resolved real_path

Every matched file produces two INFO records in alerts_<run_id>.log, not one. scan_file emits 'YARA matches found in <path>' carrying file_path, real_path (the resolved/normalised path — recorded nowhere else on the host, not in the alert texts, not in scan_summary), file_size from the stat already taken, file_sha256, file_creation_time, match_count and rules_matched[]. _write_alerts separately emits 'YARA detection event: N rules triggered in <basename>' carrying rules_triggered[], total_string_matches (string-hit grain, unlike total_detections which is file x rule finding grain), a detections[] array (one entry per rule, each re-stat-ing the file for file_size and reporting 0 if it has vanished) and detection_timestamp. Both records are written regardless of delivery: create_alerts=false and write_dataset=false suppress the XDR channels but not these lines. Both pass through the 4000-char cap, and because keys are sorted alphabetically the big detections[] array sorts second and eats the budget, so rules_triggered / total_string_matches at the tail are what get cut on a heavy match.

- **Control:** Not configurable — create_alerts (line 2703) and write_dataset (line 2705) gate delivery channels only, not these log records — default `-`
- **Observe:** grep -c 'YARA matches found in' and grep -c 'YARA detection event' in logs/alerts_<run_id>.log — both should equal the number of DISTINCT matched files (not the finding count). Cross-check total_string_matches in the second record against total_detections in scan_summary_<run_id>.json to see the two grains differ. Both records land: LogManager's per-category loggers are named loggers at INFO with propagate=False, so setup_logging's root-handler stripping does not affect them.
- **Source:** `YaraScanner.scan_file match branch 6163-6187 with log_alert 6175-6186; YaraScanner._write_alerts 6365-6384 (detection_data built 6376-6383, appended 6384) and log_alert 6444-6457 (payload 6448-6456); LogManager.log_alert 2192-2194; _setup_logger 2131-2157 (INFO at 2147, propagate=False at 2155); cap 2176-2177 with sort_keys at 2173`

### Runtime fingerprint (embedded Python, platform, yara binding version) written at the head of yara_processing_<run_id>.log before any rule work

ErrorLogger writes a banner the instant its FileHandler opens — '=== YARA Processing Log ===', 'Python Version: <sys.version>', 'Platform: <platform.platform()>', 'YARA Version: <yara.__version__ or Unknown>' — which happens in ScanConfig.__init__ before rules are decoded or compiled, so the fingerprint survives a run that aborts on bad rule input. The same triple is repeated into system_<run_id>.log inside the init_data payload, which is emitted TWICE with identical content under two different messages ('YARA Scanner initialization completed' and 'YARA Scanner initialized successfully'). This is what decides whether a customer rule's module imports can compile on that endpoint at all — agent-embedded interpreters and libyara builds differ per platform.

- **Control:** Not configurable — default `-`
- **Observe:** Lines 2-4 of logs/yara_processing_<run_id>.log. Also init_data.python_version / init_data.platform / init_data.yara_version in logs/system_<run_id>.log — appearing twice, on both 'YARA Scanner initialization completed' and 'YARA Scanner initialized successfully'. The libyara version proper (yara.YARA_VERSION, distinct from the binding version) is NOT in any log: it is captured only inside _yara_version_tag, which feeds the rule-cache key and the 'yara' field of rule_cache/rules_<key>.yarac.meta.json — read that sidecar to recover it.
- **Source:** `ErrorLogger.error_log_file 1493-1495; _setup_error_logger 1502-1539 with the banner at 1529-1532 (separator 1533); run() init_data 7296-7319 emitted at 7321 and again at 7341; _yara_version_tag 564-573 consumed at 5471 (cache key) and 5512 (sidecar meta)`

### Resolved tenant/credential/posture block and scan-target validation warnings — written to yara_processing_<run_id>.log and nowhere else

Immediately after the runtime banner, ScanConfig.__init__ writes the resolved configuration into the same audit file via the raw ErrorLogger logger: 'XDR API Key/ID: Using default embedded credential', 'XDR API URL: <resolved>', 'Tenant ID: <derived or overridden>', 'YARA Scanner VERSION <v> (released <date>)', 'Runtime posture: alerts=on/off dataset=on/off files=on/off cpu=... mode=...', 'Default XDR alert severity: ...', a light-profile line, and after rule decoding 'Scan ID: <hostname>_<run_id>_yara_<12 hex> (rule hash: <12 hex>...)'. The placeholder-credential abort message (DEFAULT_XDR_API_* still 'replace_with_*') and the scan-target validation warnings all land here too: 'Ignoring N specified scan folder(s) that are not valid directories', 'N of M scan folder(s) sit under a platform skip-path and will yield no files: <path> (excluded by ...)', and 'EVERY requested scan folder is excluded by the platform skip-list - this scan will scan 0 files'. This is the file that answers 'which tenant did this agent point at, with which ruleset, and why did it scan zero files'.

- **Control:** Not configurable (the file is always written). The values it reports come from create_alerts 2703 / write_dataset 2705 / collect_files 2707 via the posture string 2725-2730, and the tenant_id override at 2723 resolved at 2773. — default `-`
- **Observe:** logs/yara_processing_<run_id>.log — grep 'XDR API URL', 'Tenant ID', 'Runtime posture', 'Scan ID:' for the config block; grep 'EVERY requested scan folder' / 'sit under a platform skip-path' / 'Ignoring' to explain a 0-files scan. The scan_id also appears in scan_summary_<run_id>.json, but the rule-hash / posture / tenant lines appear in no other artefact.
- **Source:** `placeholder-credential error 2775-2781; config block 2783-2793; scan_id + rule hash 2809-2817; posture string 2725-2730; tenant derivation 2773; scan-target validation 2995-3037 (invalid-folder warning 3008-3011, skip-path warning 3024-3028, all-excluded warning 3029-3033, 'Scan limited to N folder(s)' 3036-3037)`

### StatisticsManager bypasses LogManager and writes raw, multi-line blocks into statistics_/performance_<run_id>.log

StatisticsManager grabs LogManager's underlying logger objects directly (log_manager.loggers[LogType.STATISTICS] / [PERFORMANCE]) and calls .info() on them, skipping LogManager._log entirely. One of those writes is MULTI-LINE: log_comprehensive_stats dumps 'Performance Metrics:', 'Time Estimates:' and 'Worker Summary:' as json.dumps(..., indent=2) inside a '='x60 banner titled COMPREHENSIVE STATISTICS SUMMARY. The logging Formatter prefixes only the first physical line of each record, so statistics_<run_id>.log is NOT line-oriented — every other record in that file is one line with a ' \| data={...}' suffix, and any per-line parser breaks on this block. The Worker Summary here is also the only artefact carrying per-worker error_rate_percent and avg_processing_time_ms. The 'Performance Snapshot \| CPU: ... \| Queue: ... \| Workers: ...' lines and the '=== Statistics Manager Initialized/Stopped ===' / '=== Performance Monitoring Started/Ended ===' markers reach the same two files by the same bypass.

- **Control:** Not configurable — default `-`
- **Observe:** logs/statistics_<run_id>.log — grep -n 'COMPREHENSIVE STATISTICS SUMMARY' and read the following physical lines; only the first carries a '[timestamp] [INFO]' prefix. Per-worker error rates: the 'Worker Summary: {' JSON block in that same section. Bookend markers '=== Statistics Manager Initialized ===' (statistics log) and '=== Performance Monitoring Started ===' / '=== Performance Monitoring Ended ===' (performance log) confirm the monitor ran for the whole scan.
- **Source:** `StatisticsManager.__init__ logger capture 1816-1821 and init markers 1839-1842; _log_performance_details 1967-1976; log_comprehensive_stats 2032-2059 (worker_summary with error_rate_percent 2043-2051, indent=2 dumps 2056-2058); stop_monitoring 2079-2090 (log_comprehensive_stats + both markers at 2088-2090); LogManager._setup_logger formatter 2149-2153`

### Logging counters under-report by construction, and yara_processing_<run_id>.log is missing from log_files_created

upload_stats['total_logs'] and ['by_type'] are incremented only inside LogManager._log, but StatisticsManager (statistics/performance markers, the COMPREHENSIVE STATISTICS SUMMARY block, every Performance Snapshot) and ErrorLogger (the whole yara_processing audit trail) write through the raw logger objects, bypassing the counter. So the log_generation_stats embedded in the end-of-run 'Scan completed successfully in ...' system record and the 'SCAN COMPLETED SUCCESSFULLY in ...' statistics record, and the 'Logging Summary \| Total Logs: N' record written at stop_logging, all report fewer records than the files actually contain. log_files_created is derived from LogType, which has exactly six members, so yara_processing_<run_id>.log is absent from the inventory even though every run produces it — as are script_exceptions_<run_id>.log and scan_summary_<run_id>.json.

- **Control:** Not configurable — default `-`
- **Observe:** logs/system_<run_id>.log — the 'Logging Summary \| Total Logs: N' record and its log_files_created list (six paths, no yara_processing). Compare N against `wc -l` across alerts_/statistics_/scan_errors_/performance_/uploads_/system_<run_id>.log: the files hold strictly more lines. The same log_generation_stats dict appears in the 'Scan completed successfully in ...' system record and the 'SCAN COMPLETED SUCCESSFULLY in ...' statistics record. Treat these counts as a floor, never as a completeness check.
- **Source:** `upload_stats init 2123-2126; the only increment site, LogManager._log 2189-2190; get_upload_statistics 2292-2294; log_final_summary 2296-2306 with log_files_created derived from LogType at 2301; log_files map 2110-2117 (six entries); LogType 1303-1310; ErrorLogger.error_log_file 1493-1495; stop_logging call 2345-2351; consumed in run() at 7452 and 7454-7481`

### Evidence ZIP is produced on every completed scan, including zero-match runs — its existence proves nothing

collect_evidence() has no match-count gate anywhere, so file_mapping.txt is rewritten and evidence_<hostname>_<run_id>.zip is created on every scan that reaches either of its two call sites — the success path (7484) and the cooperative fatal-failure branch (7437). A zero-match run therefore yields a ZIP containing exactly one member: a header-only file_mapping.txt (Hostname / OS / IP Addresses, then the 'Original Path \| SHA256 Hash' header and no rows) — no alerts/ entries, since the ZIP only pulls alert/*.txt and there are none. An operator cannot infer 'matches were found' from the ZIP's presence or byte count; only its member list and the manifest's row count answer that. What the ZIP's ABSENCE does mean: the run was cancelled (early return at 7397-7413, before both call sites) or crashed into run()'s outer except (7550).

- **Control:** Not configurable — no gate on match count at either call site (7437, 7484) or in collect_evidence (4492-4499) — default `-`
- **Observe:** unzip -l <scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip — a zero-match run lists file_mapping.txt only; a matching run additionally lists alerts/<rule>.txt entries (and matched_files/<sha256> entries when collect_files=true). Cross-check the manifest row count against scan_summary_<run_id>.json rather than trusting ZIP existence.
- **Source:** `collect_evidence 4492-4499; call sites in run() at 7437 (scan_failed branch) and 7484 (success path); header-only manifest written at 4503-4510 with rows only inside the loop 4512-4519; _create_evidence_zip 4521-4571 (collect_files gate 4529-4564, alert/*.txt sweep 4566-4569, file_mapping added 4571)`

---

# Delivery, Aggregation & Telemetry

*Alerts, lookup datasets, and how delivery is accounted for.*

### Master upload kill-switch (UPLOAD_RESULTS)

A single module-level literal gates BOTH XDR delivery channels: the ResultsUploader thread start (3213), the LookupDatasetUploader dataset-create + thread start (3940), and the add_match call site inside _write_alerts (6386). Set False and the scan still writes every local artefact but sends nothing — and because it is a bare literal (not env-backed), it is not reachable from the endpoint at run time.

- **Control:** UPLOAD_RESULTS (line 104) — bare module literal, NOT customer-reachable at run time — default `True`
- **Observe:** uploads_<run_id>.log contains 'Lookup dataset worker started' (4100) and, once matches exist, 'Queued finding alert: …' (3736); with it off you get only 'Lookup dataset uploads disabled (write_dataset=false, UPLOAD_RESULTS off, or XDR URL not configured)' (3944) and 'Alert delivery final: findings=0 queued=0 …' (3595). scan_summary_<run_id>.json then shows alert_delivery.alerts_queued=0 and dataset_delivery.queued=0.
- **Source:** `UPLOAD_RESULTS (104); ResultsUploader.__init__ gate (3213); LookupDatasetUploader.__init__ gate (3940-3946); _write_alerts add_match call (6386-6394)`

### Insert Parsed Alerts channel enable (create_alerts)

create_alerts alone gates the XDR alert channel; when false the upload thread is never started, and add_match's alert block is skipped because it tests upload_thread.is_alive() (3697). Dataset writes are unaffected — the two channels are independently switchable, which is how a fleet can populate dashboards without generating incidents.

- **Control:** CONFIG_CREATE_ALERTS (line 161); options key 'create_alerts' (_VALID_OPTION_KEYS, 772); run() kwarg (7096) — default `True`
- **Observe:** config.posture string 'alerts=on'/'alerts=off' (built 2725-2730) echoed in the returned SCAN_RESULT line (7536) and in scan_summary_<run_id>.json.posture (2326). With it on, uploads_<run_id>.log carries 'Queued finding alert: rule=…' (3736) and 'Alert batch ok (N alerts, HTTP 200)' (3433); with it off neither appears and alert_delivery.alerts_queued stays 0.
- **Source:** `ScanConfig.create_alerts (2702-2703); ResultsUploader.__init__ gate (3213); add_match alert gate (3697)`

### Lookup dataset channel enable (write_dataset)

write_dataset gates dataset creation, the uploader thread, AND _emit_scan_row — so turning it off silently removes the entire scan-lifecycle telemetry stream (initiated/running/completed rows), not just match rows. Nothing else emits those rows. The gate also requires _xdr_configured(), so a placeholder URL disables it just as effectively.

- **Control:** CONFIG_WRITE_DATASET (line 162); options key 'write_dataset' (772); run() kwarg (7096) — default `True`
- **Observe:** uploads_<run_id>.log line 'Lookup dataset uploads disabled (write_dataset=false, UPLOAD_RESULTS off, or XDR URL not configured)' (3944-3946) — this one IS reachable, because LookupDatasetUploader takes log_manager as a constructor argument (3827). Plus config.posture 'dataset=off' and an all-zero dataset_delivery object in scan_summary_<run_id>.json.
- **Source:** `ScanConfig.write_dataset (2704-2705); LookupDatasetUploader.__init__ gate (3940-3946); YaraScanner._emit_scan_row gate (5206-5208)`

### Alert batching into one insert_parsed_alerts POST

The upload worker accumulates StandardLogEntry objects and POSTs them as a LIST under request_data.alerts (3403), turning thousands of per-match POSTs into a handful. The env value is hard-clamped by min(60, …) because XDR rejects more than 60 alerts per call — raising YARA_ALERT_BATCH above 60 silently does nothing.

- **Control:** ALERT_BATCH_SIZE = min(60, _env_number("YARA_ALERT_BATCH", 60, cast=int, minimum=1)) (line 113) — env var, customer-reachable — default `60 (hard ceiling 60)`
- **Observe:** uploads_<run_id>.log repeated 'Alert batch ok (N alerts, HTTP 200)' lines (3433-3434) where N<=60, and 'Alert batch failed (HTTP …)' / 'Alert batch network error: …' on failure (3451, 3465). Batch size is inferable only from N.
- **Source:** `ALERT_BATCH_SIZE (113); _upload_worker batch accumulation (3241-3270); _upload_alert_batch payload build (3403)`

### Partial alert batch idle flush

When the queue goes quiet for a full second the worker's get() raises Empty; if the current batch is older than this interval it is POSTed anyway so a slow-trickle scan does not hold alerts hostage until the end. The timer is anchored on the last flush (last_flush, set at 3242/3270/3276), not the last enqueue, so a steady trickle still flushes on cadence.

- **Control:** ALERT_FLUSH_SECS = _env_number("YARA_ALERT_FLUSH_SECS", 10, minimum=0) (line 114) — default `10 seconds`
- **Observe:** uploads_<run_id>.log 'Alert batch ok (N alerts …)' with N well below 60 appearing roughly every 10s on a low-match scan (timestamps come from LogManager's formatter, ms resolution, 2149-2152).
- **Source:** `ALERT_FLUSH_SECS (114); _upload_worker Empty branch (3271-3280); last_flush anchors (3242, 3270, 3276)`

### Alert POST pacing against the ~600 alerts/min ceiling

Before every alert POST the worker sleeps out the remainder of a minimum inter-POST interval measured from the last POST's monotonic timestamp (3408-3410). 60 alerts every >=7s is ~510/min, deliberately under XDR's shared per-API-key ceiling; without it over-fast batches get HTTP 500 'Exceeding the rate limit' and their retries eat the delivery window. _last_alert_post is refreshed after each POST attempt, including failed ones (3419), and the pacing sleep is paid once per _upload_alert_batch call, not per retry.

- **Control:** ALERT_MIN_BATCH_INTERVAL = _env_number("YARA_ALERT_MIN_INTERVAL", 7, minimum=0) (line 120) — default `7 seconds`
- **Observe:** Timestamps of consecutive 'Alert batch ok' lines in uploads_<run_id>.log are >=7s apart even when the queue is saturated.
- **Source:** `ALERT_MIN_BATCH_INTERVAL (120); pacing sleep (3406-3410); self._last_alert_post set after each POST (3419); initialised (3201)`

### Alert batch retry ladder with exponential backoff + jitter

Retryable HTTP statuses (408/429/500/502/503/504) and requests.Timeout/ConnectionError are retried up to a per-batch cap, sleeping BASE*2^(attempt-1) capped at MAX, multiplied by a uniform 0.5–1.0 jitter factor. Non-retryable statuses and unexpected exceptions drop the whole batch immediately and charge every alert in it to failed_uploads (3457, 3471).

- **Control:** MAX_RETRIES_PER_ITEM (line 107), BASE_BACKOFF_SECS (128), MAX_BACKOFF_SECS (129) — all bare literals, not env-backed — default `4 attempts; 1.0s base; 30.0s ceiling`
- **Observe:** uploads_<run_id>.log 'Alert batch failed (HTTP 5xx). Body: … Retry 2/4 in 1.8s.' (3451-3453) or 'Alert batch network error: … Retry 3/4 in 3.2s.' (3465-3467); terminal failure goes to scan_errors_<run_id>.log as 'Alert batch abandoned after 4 attempts (N alerts lost)' (3486, level defaults to error).
- **Source:** `_exp_backoff_delay (540-545); _upload_alert_batch retry loop (3414-3473); abandonment (3484-3487)`

### Retry-After header honoured on alert throttling

When XDR returns a Retry-After header on a retryable status, its value is parsed as float seconds and used verbatim in place of the computed backoff (and in place of the rate-limited cooldown). A non-numeric header resets delay to None and falls back to backoff rather than erroring.

- **Control:** Not configurable — no env var or constant; the header name is a literal at 3442 — default `-`
- **Observe:** uploads_<run_id>.log retry line ('Alert batch failed (HTTP …) … Retry n/4 in Xs.') shows a delay that matches the server header rather than the 1/2/4/8s backoff ladder.
- **Source:** `_upload_alert_batch Retry-After parse (3441-3447); consumed at 3448-3453`

### Rate-limit classification from status code OR response body

A batch is flagged rate-limited when the status is 429 OR the response body contains the substring 'rate limit' (3439) — XDR signals its alert ceiling with HTTP 500 plus that text, so status-only detection would miss it. A rate-limited retry waits at least 2x the pacing interval instead of the ordinary backoff, and a transport error explicitly resets the flag (3463) so a network blip is not mistaken for throttling.

- **Control:** Not configurable (body-substring match is hardcoded at 3439) — default `-`
- **Observe:** uploads_<run_id>.log retry line carries the '[rate-limited]' marker (3452). The delay is >=2*ALERT_MIN_BATCH_INTERVAL (>=14s at defaults) ONLY when the response carried no numeric Retry-After header — a Retry-After value overrides the cooldown entirely.
- **Source:** `last_rate_limited (3439); longer cooldown (3448-3450); reset on transport error (3463); requeue consumer (3477)`

### Requeue rate-limited alert batches for a later window

A batch that exhausts its retries BECAUSE it was rate-limited is not dropped: _upload_alert_batch returns 'requeue' and the worker's flush() puts every entry back on the queue. Bounded by a global wall-clock delivery deadline set once when the worker starts (3240), and disabled once stop_upload_thread is set, so a permanently saturated API key cannot loop forever. A requeue put that itself fails charges that one alert to failed_uploads (3257).

- **Control:** ALERT_REQUEUE_ENABLED = env YARA_ALERT_REQUEUE (line 126); ALERT_MAX_DELIVER_SECS = env YARA_ALERT_MAX_DELIVER_SECS (line 127) — default `enabled; 900 seconds`
- **Observe:** scan_summary_<run_id>.json alert_delivery.requeued > 0 (added by get_upload_stats, 3807); uploads_<run_id>.log 'Alert batch rate-limited after 4 attempts; requeuing N alerts for a later window.' (3479-3481) and the requeued= field of the 'Alert delivery final:' line (3599).
- **Source:** `ALERT_REQUEUE_ENABLED/ALERT_MAX_DELIVER_SECS (126-127); deadline set (3240); requeue decision (3477-3482); worker requeue loop (3248-3257)`

### HTTP 2xx with a JSON `false` body counted as a failure

insert_parsed_alerts can answer 200 with a bare JSON boolean false. The code parses the body and, only when it is a bool, uses it as the success verdict — so a false reply charges the batch to failed_uploads and returns 'dropped' instead of being silently counted as delivered. Any non-bool body (dict, list) or an unparseable body (exception swallowed at 3426-3427) is treated as success.

- **Control:** Not configurable — default `-`
- **Observe:** scan_errors_<run_id>.log 'XDR Insert Parsed Alerts returned false' (3430, error level) with alert_delivery.failed_uploads incremented in scan_summary_<run_id>.json.
- **Source:** `_upload_alert_batch reply check (3420-3431)`

### Backlog-scaled end-of-scan alert drain

stop() computes a drain window from the actual pending count (ceil(pending/ALERT_BATCH_SIZE) batches x (pacing+8s)), floored at ALERT_DRAIN_SECS and hard-capped at ALERT_DRAIN_MAX_SECS so a dead API cannot hang shutdown. Crucially stop_upload_thread stays False until 3564, after this window, so rate-limited batches can still requeue while draining; the loop short-circuits the moment the queue empties (3561).

- **Control:** ALERT_DRAIN_SECS env YARA_ALERT_DRAIN_SECS (line 115); ALERT_DRAIN_MAX_SECS env YARA_ALERT_DRAIN_MAX_SECS (line 116) — default `60s minimum, 300s cap`
- **Observe:** uploads_<run_id>.log 'Draining N pending alert(s) (~M batches, up to Xs)...' (3557-3559) followed by 'Upload worker thread stopped' (3290) and 'Upload thread terminated successfully' (3575). The Draining line only appears when qsize()>0 at stop time (3552).
- **Source:** `ResultsUploader.stop (3530-3607); drain window (3550-3562); batches/drain_secs math (3553-3555)`

### Alert thread join timeout

After the sentinel is queued (3566), stop() joins the upload thread with a fixed timeout and logs whether it terminated. A thread still alive after this is abandoned (it is a daemon, 3228), which is exactly the case that makes the leftover accounting below approximate rather than exact.

- **Control:** THREAD_CLEANUP_TIMEOUT (line 133) — bare literal — default `60 seconds`
- **Observe:** uploads_<run_id>.log 'Upload thread did not terminate within 60s timeout' (3573) vs 'Upload thread terminated successfully' (3575).
- **Source:** `THREAD_CLEANUP_TIMEOUT (133); join (3570-3575)`

### Honest leftover accounting for undelivered alerts

After the join, anything still on the queue is counted as 'undelivered' so a stranded backlog cannot read as 100% delivered. When the thread is confirmed dead the queue is drained item-by-item for an exact count (sentinels excluded); when it is still alive the count is approximated as qsize()-1 to discount the sentinel.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json alert_delivery.undelivered; scan_errors_<run_id>.log 'N alert(s) undelivered within the drain budget (shared rate-limit ceiling) — the yara_scanner_matches dataset holds the complete record' (3601-3604).
- **Source:** `ResultsUploader.stop leftover block (3579-3592); undelivered error log (3600-3604)`

### Alert delivery books (upload_stats fields)

Eight counters are kept in upload_stats, not one: total_matches is offset-grain (incremented per matched string at 3643, parity with dataset match_count), findings is file x rule grain, alerts_queued includes rollups, and suppressed/rollups/undelivered separate 'deliberately not sent' from 'tried and failed'. successful_uploads/failed_uploads are credited per-alert (n at a time) so batch-level outcomes stay match-accurate. A ninth field, requeued, exists only on the get_upload_stats() copy (from _requeued_total).

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json alert_delivery object (populated via get_upload_stats at 7655); uploads_<run_id>.log 'Alert delivery final: findings=… queued=… ok=… failed=… undelivered=… suppressed=… rollups=… requeued=…' (3595-3599).
- **Source:** `upload_stats init (3187-3196); _requeued_total (3203); get_upload_stats adds 'requeued' (3804-3808); final line (3594-3599)`

### Alert grain is one alert per (rule, file) finding, deduped within scan

Alerts are emitted per FINDING, not per matched offset; a within-scan set of (rule, filename) keys suppresses repeats. The dedup set stops growing past a hardcoded 150,000 entries to bound memory — past that the key is not recorded, so pathological scans can re-alert on a finding already seen.

- **Control:** Not configurable (150000 is a bare literal in the method body at 3702) — default `150000 tracked findings`
- **Observe:** scan_summary_<run_id>.json alert_delivery.findings vs .total_matches divergence; one XDR alert per rule+file rather than per offset (alert_name built at 3322). uploads_<run_id>.log has one 'Queued finding alert: rule=…, file=…, hits=N' line per finding (3736-3738).
- **Source:** `_findings_lock (3207); _seen_findings (3208); dedup + cap (3699-3710)`

### Alert storm cap per scan

Once the per-scan finding count reaches the cap, further per-finding alerts stop being queued; they are tallied per rule into _suppressed_by_rule and reported at scan end via rollups. Protects the shared per-API-key ceiling. Set <= 0 to disable. Deliberately has NO options-string equivalent — it can only be changed by editing the constant.

- **Control:** CONFIG_ALERT_MAX_PER_SCAN (line 191) — NOT in _VALID_OPTION_KEYS (771-775), so an options string carrying it raises ValueError in _parse_options_string (guard 825, raise 826-828) — default `500 findings`
- **Observe:** scan_summary_<run_id>.json alert_delivery.suppressed > 0 and .findings capped at the constant; uploads_<run_id>.log 'Alert delivery final: findings=… suppressed=… rollups=…' (3595-3599).
- **Source:** `CONFIG_ALERT_MAX_PER_SCAN (191); cap check (3704-3707); _suppressed_by_rule init (3209)`

### Per-rule storm rollup alerts at scan end

Before the final drain, one synthetic alert per rule is queued summarizing how many findings that rule had suppressed, ordered by suppression count descending (3498). Its alert_name deliberately omits the file so repeat storms update one XDR alert per (rule, host) rather than piling up. The rollup entry carries data['rollup']=True (3512), which is what switches _alert_dict to the storm naming.

- **Control:** Not configurable directly (fires only when CONFIG_ALERT_MAX_PER_SCAN, line 191, suppresses something) — default `-`
- **Observe:** XDR alert named 'YARA Match Storm: <rule> \| Host: <host>' (3320); scan_summary_<run_id>.json alert_delivery.rollups; uploads_<run_id>.log 'Queued N storm-rollup alert(s) covering M suppressed finding(s)' (3525-3528).
- **Source:** `_queue_rollup_alerts (3489-3528); rollup naming branch (3317-3320); called from stop() (3539-3543)`

### Alert identity: rule + basename + 8-char path hash + host

alert_name is 'YARA Match: <rule> \| <basename> (#<sha1(fullpath)[:8]>) \| Host: <host>'. XDR aggregates on alert_name, so this keeps re-scans idempotent (same finding updates one alert) while the path hash prevents two same-named files in different directories collapsing into one. An empty path falls back to the literal tag 'nopath'.

- **Control:** Not configurable — default `-`
- **Observe:** Alert names in the XDR console / XQL over alerts; the '#xxxxxxxx' tag differs for identical basenames at different paths.
- **Source:** `_alert_dict path resolution + tag (3310-3316); alert_name (3322)`

### Alert wire payload shape and placeholder network fields

Each alert dict carries exactly eleven keys: product='YARA Scanner', vendor='Custom', local_ip (first non-loopback IPv4 of the host, else 127.0.0.1), local_port=65535, remote_ip='127.0.0.1', remote_port=65535, event_timestamp (ms, from the log entry's timestamp), severity, alert_name, alert_description (a JSON STRING), action_status='Reported'. The ports/remote_ip are required-but-meaningless placeholders — the payload self-declares this via network_fields_are_placeholders inside the description (3348). The IPv4 pick requires a '.' and a non-'127.' prefix (3336), so an IPv6-only host falls back to 127.0.0.1.

- **Control:** Not configurable — default `-`
- **Observe:** XQL over the alerts table: action_local_ip / action_remote_port=65535, alert_source vendor 'Custom', product 'YARA Scanner'.
- **Source:** `alert dict (3352-3365); host_ipv4 selection (3334-3338); event_timestamp_ms (3297, from standard_log.timestamp)`

### alert_description JSON envelope

The description field is a json.dumps'd object with nine keys: source='yara_scanner', tenant_id, scan_id, hostname, os_info, ip_address, message, network_fields_are_placeholders, and the full match_data dict (filename, rule, match_count, first offset, up to 3 'string_id@offset' samples, first rendered matched string, dateOfScan, file_sha256, file_creation_time). This is the only place the per-alert forensic sample reaches XDR — everything richer lives in the lookup dataset. Note file_size and scan_folder are dataset-only; they never reach the alert.

- **Control:** Not configurable (the 3-sample cap is a bare literal at 3649) — default `3 hit samples, 1 rendered string`
- **Observe:** Parse alert_description JSON on any yara_scanner alert; match_data.matches_sample has at most 3 entries.
- **Source:** `alert_description (3340-3350); match_data assembled in add_match (3721-3731); _hit_samples cap (3649-3650)`

### Alert severity mapping

The alert's XDR severity is derived from data['threat_level'] if present, else the scan's alert_severity, mapped critical/high->High, medium->Medium, low/info->Low, with anything unrecognised falling to 'Low'. No code path anywhere sets threat_level (the string appears only at the read site, 3332), so in practice every alert takes the run's alert_severity. The dataset row computes its severity separately from alert_severity only (3657-3659).

- **Control:** alert_severity — an Action Center entry-point parameter of main() (7730); validated by _parse_alert_severity (906-913) — default `"low" -> XDR severity Low`
- **Observe:** Alert severity column in the XDR console; on the endpoint, yara_processing_<run_id>.log line 'Default XDR alert severity: low' (written at 2790 through ErrorLogger's own INFO FileHandler, 1513-1527).
- **Source:** `severity_map (3324-3332); _parse_alert_severity (906-913); dataset-row severity (3657-3659)`

### Throttled upload logging buckets

Every repetitive upload log goes through a per-bucket counter: the first 20 messages print, message 21 prints a one-time 'further similar messages suppressed' notice, then only every 1000th prints a running count. Added because a placeholder-credential run produced ~36k identical 'Invalid URL' lines (10 MB). Bucket names are stable and greppable: alert_upload_ok, alert_upload_retry, alert_upload_err, alert_requeue, alert_build_err, queued_match, queue_full, added_matches, rollup_err. Note _rl_counters is a plain dict mutated without a lock, but only the single uploader thread calls _throttled_log.

- **Control:** Not configurable (full=20, every=1000 are default parameters of the method at 3371) — default `20 full, then every 1000`
- **Observe:** uploads_<run_id>.log / scan_errors_<run_id>.log contain lines like '[alert_upload_retry] 3000 occurrences so far; latest: …' (3386) and the one-shot '[bucket] further similar messages suppressed; will summarize every 1000.' (3383-3384).
- **Source:** `_throttled_log (3371-3386); _rl_counters (3200)`

### Lookup dataset naming: prefix + schema version + shard + monthly rotation

Dataset names are assembled as yara_scanner_matches_v<ver>[_<shard>][_<YYYYMM>] and the same for _scans. All four segments are independent knobs. The resolved pair is stamped back onto the config object as _matches_dataset/_scans_dataset (3857-3861, before any gate), which is how the scan-summary JSON can name the literal dataset an analyst must query instead of leaving them to guess the slugified hostname and month. That stamp-back sits in a bare try/except, so a config object refusing attribute assignment silently leaves both summary fields empty — cross-check the uploader's thread-start log line in that case. Dashboards are expected to fan back in with a yara_scanner_matches* wildcard.

- **Control:** LOOKUP_DATASET_PREFIX (306, literal); LOOKUP_SCHEMA_VERSION env YARA_LOOKUP_SCHEMA_VER (290); shard (284 / CONFIG_LOOKUP_SHARD 186 / lookup_shard run parameter); rotation (CONFIG_LOOKUP_ROTATION 216 / env YARA_LOOKUP_ROTATION read at 3851) — default `yara_scanner_matches_v3_<hostslug>_<hash>_<YYYYMM>`
- **Observe:** scan_summary_<run_id>.json fields matches_dataset and scans_dataset (2324-2325), beside "schema": "yara_scan_summary/v1" (2317) — use those names verbatim in XQL; uploads_<run_id>.log 'Lookup dataset upload thread starting (datasets: yara_scanner_matches_v3_…, yara_scanner_scans_v3_…; batch_size: 500)' (4058-4061) is the fallback cross-check.
- **Source:** `name assembly (3845-3854); write-back to config (3855-3861); LogManager.write_scan_summary record (2316-2327, names at 2324-2325); thread-start log (4056-4061)`

### Per-writer lookup dataset sharding

THE fix for XDR's add_data concurrency limitation: add_data stages each write through a per-write BigQuery clone table, so two writers on the SAME dataset race with a transient HTTP 500 '<dataset>_clone was not found'. Sharding by endpoint gives each host its own dataset, so no two writers ever collide. Accepts endpoint/host/hostname/auto as per-host, none/shared/off/'' as the legacy shared dataset, and any other literal as a forced shard label. The config value is lowercased before matching, so 'Endpoint' works, and config.lookup_shard wins over the env var (the env is only the fallback at 3838).

- **Control:** CONFIG_LOOKUP_SHARD (line 186); options key 'lookup_shard' (774); env YARA_LOOKUP_SHARD via LOOKUP_DATASET_SHARD (284), used only when config.lookup_shard is empty — default `"endpoint" (per-host)`
- **Observe:** scan_summary_<run_id>.json matches_dataset ends in the host slug + 6-hex hash; XQL 'dataset = yara_scanner_matches_v3_*' shows one dataset per endpoint.
- **Source:** `CONFIG_LOOKUP_SHARD (186); LOOKUP_DATASET_SHARD (284); shard resolution (3838-3844); ScanConfig.lookup_shard (2691)`

### Shard label slugification with collision-proof hash

An arbitrary shard label is lowercased, non-alphanumerics collapsed to underscores, trimmed to 32 chars, defaulted to 'host' if empty, prefixed 'h_' if it does not start with a letter (XDR requires lowercase [a-z0-9_] starting with a letter), then suffixed with the first 6 hex of sha1 of the ORIGINAL label — so two hosts that slugify identically or get truncated to the same string still land in different datasets.

- **Control:** Not configurable (32-char cap and 6-hex hash are literals at 582 and 585) — default `-`
- **Observe:** scan_summary_<run_id>.json matches_dataset suffix, e.g. '…_xdragent2_a1b2c3'.
- **Source:** `_dataset_shard_suffix (576-586)`

### Monthly lookup dataset rotation

add_data merge time scales with the DATASET's total size, not the payload, so an unrotated dataset eventually outlives any client read timeout and goes permanently write-dead. Monthly rotation appends _<YYYYMM> derived from the run_id's date prefix (falling back to today's date when run_id is absent), bounding size and therefore merge time forever. The len(scan_date) >= 6 guard at 3852 means a malformed run_id silently disables rotation rather than producing a truncated suffix.

- **Control:** CONFIG_LOOKUP_ROTATION (line 216) — NOT an options key; env YARA_LOOKUP_ROTATION takes precedence (3851) — default `"monthly"`
- **Observe:** scan_summary_<run_id>.json matches_dataset ends in the current YYYYMM; a scan run in a new month creates a new dataset (uploads_<run_id>.log 'Lookup dataset '<name>' created (schema fields: 22)', 4023-4026).
- **Source:** `CONFIG_LOOKUP_ROTATION (216); rotation suffix (3851-3852); scan_date derivation (3833-3834)`

### Lookup schema version tag in the dataset name

XDR lookup datasets have a FIXED schema set at creation and SILENTLY SKIP rows carrying unknown fields — so a schema change can never be applied in place. The version is baked into the dataset name instead; bumping it creates a fresh dataset with the new shape while old-version datasets stay queryable under the same wildcard.

- **Control:** LOOKUP_SCHEMA_VERSION = os.environ.get("YARA_LOOKUP_SCHEMA_VER", "3") (line 290) — env var, customer-reachable — default `"3"`
- **Observe:** '_v3' segment in scan_summary_<run_id>.json matches_dataset; a schema mismatch shows up as dataset_delivery.records_skipped > 0 in the same file and 'skipped=N' in the 'Lookup batch ok' line (4227-4228).
- **Source:** `LOOKUP_SCHEMA_VERSION (290); _ver in name assembly (3846)`

### Explicit dataset pre-creation (get_datasets probe then add_dataset)

Despite the class docstring at 3812-3825 still claiming implicit creation, creation is a hard prerequisite: add_data answers HTTP 400 'Dataset not found' otherwise. Both datasets are probed with xql/get_datasets at startup and created with xql/add_dataset if absent. The probe tolerates every failure mode (non-2xx, unparseable body, network error) by falling through to attempt add_dataset anyway, and accepts BOTH the documented 'dataset_name' key and the 'Dataset Name' key XDR actually returns.

- **Control:** Not configurable; DEFAULT_TIMEOUT_SECS (line 106) bounds both calls — default `20s timeout`
- **Observe:** uploads_<run_id>.log: 'Lookup dataset '<name>' already exists - will append rows' (4002-4004) or 'Lookup dataset '<name>' created (schema fields: 22)' (4023-4026), or on an unreachable tenant 'get_datasets probe error: …; will attempt add_dataset anyway.' (3994-3998).
- **Source:** `_ensure_datasets (3951-3954); _ensure_one (3956-4054); XDR_GET_DATASETS_PATH/XDR_ADD_DATASET_PATH (597-598)`

### add_dataset 'already exists' error body treated as success

XDR reports an existing dataset as HTTP 500 with reply.err_extra containing 'already exists'. That body is parsed and treated as success rather than an error, so a get_datasets probe that missed the dataset does not produce a spurious failure log or a false 'add_data will fail' warning. The check is on the body only — it runs for ANY non-2xx status, not just 500, so a 400/409 carrying the same err_extra would also be accepted.

- **Control:** Not configurable — default `-`
- **Observe:** uploads_<run_id>.log 'Lookup dataset '<name>' already exists (reported via add_dataset 500) - will append rows' (4042-4045).
- **Source:** `_ensure_one already_exists branch (4028-4046)`

### Matches dataset row schema (22 fields on the wire)

One row per (rule, file) finding, declared as XDR types text/number/bool: tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, rule, filename, file_size, file_sha256, file_creation_time, scan_folder, match_count, offsets, strings, string_ids, truncated, severity, event_timestamp_ms, date_of_scan. offsets/strings/string_ids are JSON-encoded TEXT because XDR lookup datasets have no array or nested column type.

- **Control:** Not configurable in place — the shape is pinned by LOOKUP_SCHEMA_VERSION (290) — default `-`
- **Observe:** XQL: dataset = yara_scanner_matches_v3_* \| fields rule, filename, match_count, truncated, string_ids.
- **Source:** `matches_schema (3890-3913); row construction in add_match (3661-3684)`

### Scans lifecycle row schema (22 fields on the wire)

One row per lifecycle transition or heartbeat: tenant_id, scan_id, run_id, scan_date, hostname, os_info, os_type, ip_address, status, scan_folder, files_scanned, files_skipped, detections, valid_rules, failed_rules, scan_rate_fps, elapsed_secs, total_paused_secs, throttle_mode, posture, event_timestamp_ms, message. Note throttle_mode actually carries config.cpu_guarantee (5239) — the field name is a legacy from the retired throttle design.

- **Control:** Not configurable in place — pinned by LOOKUP_SCHEMA_VERSION (290) — default `-`
- **Observe:** XQL: dataset = yara_scanner_scans_v3_* \| fields status, files_scanned, scan_rate_fps, total_paused_secs, message.
- **Source:** `scans_schema (3915-3937); row construction in _emit_scan_row (5220-5243)`

### Scan lifecycle row emission (initiated / running / completed / cancelled / failed)

Five terminal-or-transitional statuses are written to the scans dataset. 'initiated' fires at the top of scan_system (6778), 'running' on heartbeat (5261), and exactly one of completed/cancelled/failed is chosen in _perform_enhanced_cleanup (6748-6757). Volatile counters are snapshotted under the same locks their writers use (lock_counts, lock_throttle) so a row is a consistent instant rather than a torn read.

- **Control:** Not configurable; suppressed entirely when write_dataset is false (CONFIG_WRITE_DATASET, 162; gate at 5207) — default `-`
- **Observe:** XQL: dataset = yara_scanner_scans_v3_<shard>* \| filter run_id = "<run_id>" — expect one 'initiated', N 'running', one terminal row.
- **Source:** `_emit_scan_row (5204-5247); initiated (6778); terminal status choice (6748-6757)`

### Terminal lifecycle row emitted BEFORE the uploaders are stopped

Ordering is load-bearing: the terminal row is emitted at 6757 after workers have drained (counts final) but before results_uploader.stop() and lookup_uploader.stop() at 6761/6763, otherwise the row would be enqueued onto an already-dead uploader and counted as 'dropped' by _enqueue's liveness check. This is why a dashboard sees a terminal row at all.

- **Control:** Not configurable — default `-`
- **Observe:** The scans-dataset terminal row exists AND scan_summary_<run_id>.json dataset_delivery.dropped is 0; if ordering broke, scan_errors_<run_id>.log would show 'Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)' (4083-4086, log_error).
- **Source:** `_perform_enhanced_cleanup ordering (6746-6765)`

### Scans-dataset heartbeat cadence

A 'running' lifecycle row plus a refreshed liveness marker are emitted no more often than the heartbeat interval, gated by a check-and-set under a lock so the two callers (walker loop and heartbeat thread) cannot both pass and emit a duplicate row. The first heartbeat waits a full interval because _last_heartbeat is primed to scan start (6773).

- **Control:** SCANS_HEARTBEAT_SECS = env YARA_HEARTBEAT_SECS (line 307) — default `600 seconds`
- **Observe:** XQL on yara_scanner_scans_v3_* filtered to status='running' — rows ~10 minutes apart with message='heartbeat' (5261). On the endpoint, <scanner_dir>/control/running.json updated_at advances on the same cadence.
- **Source:** `SCANS_HEARTBEAT_SECS (307); _maybe_heartbeat (5249-5261); _heartbeat_lock (5084); _last_heartbeat primed (6773)`

### Independent heartbeat thread (decoupled from the directory walker)

A dedicated daemon thread polls _maybe_heartbeat on its own cadence, exiting when scan_active goes False (5281). Before this the heartbeat fired only once per directory finished by the walker — and _enqueue_scan_path blocks (rather than dropping files) when the scan queue saturates, so a big directory on a throttled host could park the walker and stall the dataset heartbeat past the window a consolidation tool uses to declare a scan abandoned. The poll interval only needs to be comfortably below the heartbeat interval; it does not itself gate emission.

- **Control:** HEARTBEAT_THREAD_POLL_SECS = env YARA_HEARTBEAT_POLL_SECS (line 318) — default `30 seconds`
- **Observe:** 'running' rows continue arriving in yara_scanner_scans_v3_* at a steady 600s cadence even while files_scanned in those rows barely moves.
- **Source:** `HEARTBEAT_THREAD_POLL_SECS (318); _start_heartbeat_thread (5263-5278); _heartbeat_worker (5280-5286); started at (6777)`

### running.json liveness marker for cross-process cancel

An atomically-written (tmp + os.replace) JSON marker under control/ carrying scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections. It is first written when the cancel watcher starts (5146) and refreshed on every heartbeat (5260). mode=cancel reads it WITHOUT starting the scan machinery and calls a scan 'running' if updated_at is within SCANS_HEARTBEAT_SECS*3+60 seconds. Removed in scan_system's finally (6946).

- **Control:** Not configurable directly; freshness window derives from SCANS_HEARTBEAT_SECS (307), computed at 870 — default `1860s freshness window`
- **Observe:** <scanner_dir>/control/running.json on the endpoint during a scan; the cancel entry point's returned string 'Cancel signal delivered (<path>) \| scanner running: yes \| scan_id=…' (884-887).
- **Source:** `_write_running_marker (5173-5195); first write (5146); heartbeat refresh (5260); _remove_running_marker (5197-5202) called at 6946; _handle_cancel_request (845-887)`

### Lookup batch size (rows per add_data POST)

Rows accumulate per target dataset and POST at this count. 500 is a measured sweet spot: bigger payloads (e.g. 1000) make the add_data call slow enough that the API GATEWAY returns 502 or read-times-out under concurrent fleet load, losing whole batches. Fewer POSTs is also fewer chances to hit the clone-table race.

- **Control:** LOOKUP_DATASET_BATCH_SIZE = env YARA_LOOKUP_BATCH (line 253) — default `500 rows`
- **Observe:** uploads_<run_id>.log 'Lookup batch ok (500 rows): added=500, updated=0, skipped=0' (4226-4229); the effective value is also echoed once in 'Lookup dataset upload thread starting (… batch_size: 500)' (4058-4061), which IS reachable because LookupDatasetUploader receives log_manager in its constructor. scan_summary_<run_id>.json dataset_delivery.batches_sent.
- **Source:** `LOOKUP_DATASET_BATCH_SIZE (253); self.batch_size (3865); flush trigger (4119-4120)`

### Per-target lookup flush timers

Each destination dataset carries its OWN last_flush anchor (set when a batch first starts accumulating, 4116-4117), so a busy matches stream cannot starve the low-volume scans-heartbeat batch behind it. The idle interval is deliberately long so a short scan emits a single end-of-scan POST per dataset instead of a trickle of collision opportunities.

- **Control:** LOOKUP_DATASET_FLUSH_SECS = env YARA_LOOKUP_FLUSH_SECS (line 254) — default `30 seconds`
- **Observe:** uploads_<run_id>.log shows interleaved 'Lookup batch ok' lines for both the matches and scans datasets, the scans one never lagging behind a large matches backlog. Observability limit: that line (4226-4229) does NOT name the target dataset, so the two streams can only be told apart by row count/order or from the XQL rows themselves.
- **Source:** `LOOKUP_DATASET_FLUSH_SECS (254); per-target last_flush (4102, 4116-4117, 4126); idle sweep (4121-4127)`

### Pre-write jitter before every add_data POST

Each POST is preceded by a uniform random sleep in [0, jitter]. Many endpoints POST at Job start and again as they finish; spreading those synchronized writes is described in-source as the single biggest client-side lever against the add_data race (retries only mop up the remainder). Set to 0 to disable. The sleep is paid once per _send_batch call, outside the retry loop (4179 precedes the while at 4195), so retries are spread only by _lookup_backoff_delay.

- **Control:** LOOKUP_WRITE_JITTER_SECS = env YARA_LOOKUP_WRITE_JITTER (line 255) — default `2 seconds`
- **Observe:** Sub-second-resolution timestamps in uploads_<run_id>.log: the gap between 'Lookup dataset worker started' (4100) and the first 'Lookup batch ok' varies run-to-run within the jitter window.
- **Source:** `LOOKUP_WRITE_JITTER_SECS (255); jitter sleep (4179-4180)`

### Full-jitter backoff for add_data retries (distinct from the alert ladder)

Lookup retries use a DIFFERENT backoff from the alert channel: a uniform pick in [0.2, max(0.4, min(6.0, BASE_BACKOFF_SECS*2^attempt))]. Correlated exp*0.5..1 backoff makes a herd of colliding scanners retry in step and keep colliding; full jitter decorrelates them so retries eventually thread through the clone race. The 6.0s ceiling keeps many retries inside the drain window.

- **Control:** Not configurable (cap=6.0 is a default parameter of _lookup_backoff_delay at 548; BASE_BACKOFF_SECS at line 128 feeds it) — default `cap 6.0s, base 1.0s`
- **Observe:** uploads_<run_id>.log 'Lookup batch failed (HTTP 500). Body: … Retry 2/6 in 3.4s.' (4235-4238) or 'Lookup batch network error: … Retry 2/6 in 2.2s.' (4297-4299) with visibly non-doubling delays.
- **Source:** `_lookup_backoff_delay (548-555); retry-status branch (4232-4240); network-error branch (4295-4300)`

### add_data retry cap

A batch gets at most this many POST attempts against retryable statuses (408/429/500/502/503/504) and connect-phase errors. Exhausting the loop charges one send_failure and logs the batch as lost with its row count; the message reports the actual `attempt` reached, so a deadline break shows fewer than the cap. Note the dataset-recreate retry (4265) and the deadline break (4205) also consume/short-circuit the same budget.

- **Control:** LOOKUP_ADD_DATA_MAX_RETRIES = env YARA_LOOKUP_RETRIES (line 256) — default `6 attempts`
- **Observe:** scan_errors_<run_id>.log 'Lookup batch abandoned after 6 attempt(s) (500 rows lost)' (4311-4313); scan_summary_<run_id>.json dataset_delivery.send_failures.
- **Source:** `LOOKUP_ADD_DATA_MAX_RETRIES (256); loop bound (4195); abandonment (4308-4313)`

### Split connect/read timeouts for add_data

add_data uses a (5, 120) tuple rather than a scalar: fail fast on connect, stay patient on the read. A read timeout below the real server merge time is catastrophic — every POST 'fails' client-side while the server may still commit, retries re-run the full merge and can duplicate rows, and a grown dataset goes into total write outage (observed live: 500 of 36,106 rows landed). 120s is chosen to exceed the largest merge a monthly-rotated dataset can grow into.

- **Control:** LOOKUP_POST_TIMEOUT = (5, _env_number("YARA_LOOKUP_READ_TIMEOUT", 120, minimum=0)) (line 271) — only the read half is env-tunable; the 5s connect is a literal — default `5s connect, 120s read`
- **Observe:** uploads_<run_id>.log 'Lookup batch network error: … Read timed out. (read timeout=120) … Retry n/6 in Xs.' (4297-4299) appearing no sooner than ~120s after the batch started. A FIRST read timeout takes this generic line; the dedicated read-timeout message only appears once the attempt cap is hit.
- **Source:** `LOOKUP_POST_TIMEOUT (271); requests.post timeout arg (4208)`

### Read-timeout attempt cap and the 'rows_unconfirmed' verdict

Read timeouts are counted separately from connect errors. A read timeout means the server was mid-merge when the client hung up, so the rows often land anyway and a blind retry risks duplicating the entire batch. Once read_timeouts reaches the cap the batch stops retrying and its row count is added to rows_unconfirmed — an explicit third state meaning 'fate unknown', neither added nor lost. It does NOT increment send_failures, so a fully unconfirmed run reports send_failures=0, which is why delivery_shortfall counts it separately. Connect-phase errors never reached the server and keep the full retry budget.

- **Control:** LOOKUP_TIMEOUT_MAX_ATTEMPTS = env YARA_LOOKUP_TIMEOUT_ATTEMPTS (line 276) — default `2 attempts (i.e. one retry)`
- **Observe:** scan_summary_<run_id>.json dataset_delivery.rows_unconfirmed > 0; uploads_<run_id>.log 'Lookup batch read-timed-out 2x (500 rows); the server merge may have committed anyway - stopping retries to avoid duplicate rows (counted as rows_unconfirmed).' (4289-4293).
- **Source:** `LOOKUP_TIMEOUT_MAX_ATTEMPTS (276); ReadTimeout branch (4282-4294)`

### Per-batch wall-clock deadline so the drain cannot be killed mid-POST

Each _send_batch computes a deadline of (drain budget - 20s) and refuses any RETRY that could not finish within one read timeout of it. Without this, six retries at the read timeout exceed the drain join budget, the daemon drain thread is killed at process exit, and the batch is lost SILENTLY — counted neither sent nor failed. The `attempt > 0` guard guarantees at least one POST regardless of how the knobs are tuned. Breaking out here falls through to the accounted send_failures path at 4308.

- **Control:** Derived from LOOKUP_DRAIN_TIMEOUT (257) / LOOKUP_DRAIN_MAX_SECS (261) / LOOKUP_POST_TIMEOUT (271); the -20s margin and the 1.0s floor are literals at 4190 — default `budget-20s, minimum 1.0s`
- **Observe:** uploads_<run_id>.log 'Lookup batch deadline reached (N rows) after M attempts; stopping retries so the drain exits within budget.' (4201-4204) followed by the accounted 'Lookup batch abandoned after M attempt(s) (N rows lost)' error (4311-4313) rather than silence.
- **Source:** `deadline computation (4188-4190); refusal check (4196-4205)`

### add_data response row accounting with dual key names

The 2xx body is parsed for added/updated/skipped counts, accepting BOTH the documented keys ('added'/'updated'/'skipped') and the space-separated names XDR actually returns ('rows added'/'rows updated'/'rows skipped'). A parse failure degrades to 0/0/0 while still counting the batch as sent — so a batch can show batches_sent+1 with records_added 0. 'skipped' is the tell-tale for schema drift, since XDR silently skips rows carrying unknown fields.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json dataset_delivery.{records_added,records_updated,records_skipped}; uploads_<run_id>.log 'Lookup batch ok (N rows): added=…, updated=…, skipped=…' (4226-4229).
- **Source:** `response parsing (4210-4219); stats update under _stats_lock (4220-4224)`

### Concurrent final drain of the two lookup datasets

At shutdown, if both the matches and scans batches are pending they are flushed on separate daemon threads rather than sequentially. The matches and scans datasets are DIFFERENT datasets, so overlapping them cannot trigger the same-dataset clone race, and since each add_data POST is ~10s server-side this roughly halves the shutdown drain. With one or zero pending targets it stays sequential.

- **Control:** Join timeout comes from the scaled _drain_budget, falling back to LOOKUP_DRAIN_TIMEOUT (line 257) when stop() never ran (4153) — default `-`
- **Observe:** uploads_<run_id>.log shows two 'Lookup batch ok' lines with overlapping timestamps at end of scan, then 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)' (4155-4162).
- **Source:** `concurrent drain (4138-4153); worker-stopped line (4154-4162)`

### Backlog-scaled lookup drain budget

stop() sizes the drain from the actual queued row count: ceil(rows/batch_size) batches x per-batch seconds, floored at LOOKUP_DRAIN_TIMEOUT and capped at LOOKUP_DRAIN_MAX_SECS so a dead API cannot hang shutdown. The same budget is used for the thread join (4342) AND for each batch's internal deadline (4189). Rationale: the datasets are THE record, so a storm scan's ~70-batch backlog should get the time the math requires while a normal 1-2 POST scan does not wait around.

- **Control:** LOOKUP_DRAIN_TIMEOUT env YARA_LOOKUP_DRAIN_SECS (257); LOOKUP_DRAIN_MAX_SECS env YARA_LOOKUP_DRAIN_MAX_SECS (261); LOOKUP_DRAIN_PER_BATCH_SECS env YARA_LOOKUP_DRAIN_PER_BATCH (262) — default `150s minimum, 45s per batch, 600s cap`
- **Observe:** uploads_<run_id>.log 'Lookup drain: N rows pending (~M batches), budget Xs' (4331-4333, only emitted when pending_rows > 0, 4330); on overrun 'Lookup uploader thread did not stop within Xs' (4344-4346).
- **Source:** `budget computation (4326-4329); join (4339-4346); reused as batch deadline (4189)`

### Honest leftover accounting for undelivered dataset rows

Rows still queued when the drain budget expires are counted into 'undelivered' so that queued should balance against added+updated+skipped+unconfirmed+undelivered rather than silently reading as delivered. Exact count when the thread is confirmed dead (queue drained item by item, sentinels excluded); qsize()-1 approximation otherwise.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json dataset_delivery.undelivered; scan_errors_<run_id>.log 'Lookup drain budget expired with N rows undelivered (counted in dataset_delivery.undelivered)' (4367-4369).
- **Source:** `leftover block (4347-4369)`

### Dropped-row accounting when the lookup worker is not alive

_enqueue checks the worker thread's liveness before every put; if it never started or has died, the row is counted as 'dropped' and ONE error is logged (further drops suppressed by a _drop_logged latch). This is the path that makes a lost terminal lifecycle row diagnosable rather than invisible. The counters are guarded by _stats_lock because _enqueue runs on the scan worker threads — bare += from N threads loses updates.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json dataset_delivery.dropped > 0; scan_errors_<run_id>.log 'Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)' (4083-4086).
- **Source:** `_enqueue (4073-4096); _stats_lock (3868); _drop_logged latch (4081-4082)`

### Lookup delivery books (upload_stats fields)

Nine counters: queued, batches_sent, records_added, records_updated, records_skipped, send_failures, dropped, rows_unconfirmed, undelivered. The last three are the honest-accounting additions — 'dropped' means never queued, 'undelivered' means queued but never attempted, 'rows_unconfirmed' means attempted with unknown outcome. The class's own get_upload_stats() accessor is never called; both consumers (7074, 7657) read .upload_stats directly, so unlike the alert channel there is no extra derived field.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json dataset_delivery object; uploads_<run_id>.log 'Lookup dataset worker stopped (batches=…, added=…, updated=…, skipped=…, failures=…)' (4155-4162) — note that line omits dropped/rows_unconfirmed/undelivered, so the JSON is the only complete view.
- **Source:** `upload_stats init (3869-3879); worker-stopped line (4154-4162); get_upload_stats defined-but-unused (4374-4375)`

### Per-finding dataset row cap and the `truncated` flag

Offsets are folded into ONE row per (rule, file); only up to this many offsets/strings are embedded as a JSON sample. An unanchored short pattern can hit tens of thousands of times inside one file (measured live: 33,118 offsets from one rule against one .evtx log) — under the old per-offset grain that single finding could consume a whole scan's upload budget before other findings got a turn. match_count still carries the TRUE total and truncated=true marks the sampling, so the real number stays queryable. <=0 disables the cap.

- **Control:** CONFIG_LOOKUP_ROWS_PER_FINDING_MAX (line 199) — NOT an options key; edit-the-constant only — default `50 offsets per finding`
- **Observe:** XQL: dataset = yara_scanner_matches_v3_* \| filter truncated = true \| fields rule, filename, match_count — plus uploads_<run_id>.log "Rule '<rule>' matched <file> at N offsets; embedded a sample of 50 in the dataset row (truncated=true; full detail retained in local results)." (3686-3691).
- **Source:** `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX (199); _row_cap (3632); sampling (3651-3653); truncated computation (3660); row fields (3676-3680)`

### Uncapped per-string-ID census on the wire

While offsets are sampled, the string_ids field carries a COMPLETE dict of {string_identifier: hit_count} across every offset, JSON-encoded into a text column. This is the deliberate design split: which string in the rule fired and how many times survives in full, because that is what an analyst triages from; individual offsets are the part that gets sampled.

- **Control:** Not configurable (always full) — default `-`
- **Observe:** XQL: dataset = yara_scanner_matches_v3_* \| fields string_ids — e.g. {"$ext2": 12, "$note1": 3}; sum of its values equals match_count.
- **Source:** `_string_id_counts init (3631); accumulation (3645); row field (3679); matches_schema entry (3908)`

### Local alert-file offset sampling (mirrors the dataset sample)

alert/<rule>.txt writes a complete 'Hits per string ID' census and 'Total string hits', then renders at most this many individual offsets, followed by an explicit '<N> further offset(s) omitted' note naming the constant. Ported from the XSIAM edition where the unbounded version produced a 220 MB file on one endpoint, 98.6% of it from four Windows event logs. The default deliberately matches the dataset row cap so the local file and the row show the same sample; <=0 renders everything.

- **Control:** CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (line 210) — NOT an options key — default `50 offsets`
- **Observe:** <scanner_dir>/alert/<rule>.txt (path built at 6396; alert_dir = <scanner_dir>/alert, 2740) line 'Matched Strings (showing 50 of 33118):' (6423-6424) and the omission note naming CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (6432-6438).
- **Source:** `CONFIG_ALERT_OFFSETS_PER_FINDING_MAX (210); census (6406-6419); sampling + omission note (6421-6438)`

### scan_summary_<run_id>.json — the machine-readable delivery record

One atomically-written (tmp + os.replace) JSON per run, written in run()'s finally block AFTER both uploaders drain (7609-7612) so the delivery counts are final. Carries schema='yara_scan_summary/v1', identity (run_id, scan_id, tenant_id, hostname, os_info, ip_address), the resolved matches_dataset/scans_dataset names, posture, outcome, scan counters, cpu_governor stats, compile_source/compile_seconds, scanner_version, cancel_source, and the two full delivery books plus delivery_shortfall and top_rules. A half-written temp is cleaned up on failure (2337-2341), and orphaned temps from a killed process are swept at the next scan's start (4594-4599).

- **Control:** Not configurable (path is <scanner_dir>/logs/scan_summary_<run_id>.json, 2315) — default `-`
- **Observe:** The file itself; system_<run_id>.log line 'Scan summary written: scan_summary_<run_id>.json' (2334).
- **Source:** `LogManager.write_scan_summary (2308-2343); call site with the full payload (7632-7666)`

### delivery_shortfall — the single 'did this land?' verdict

Computes, per enabled channel, queued-minus-landed: alerts_queued minus successful_uploads, and dataset queued minus (added+updated+skipped). Deliberately counts rows_unconfirmed as NOT delivered — 'may have committed' is not evidence, and over-reporting success is the failure mode this exists to prevent. Returns "" when everything landed. It is called up to TWICE per run — once for the result line (7544 completed / 7409 cancelled) and once inside the finally block (7631), where the single value is reused for the host-cleanup gate (7702) so those two can never disagree. Explicitly must never be added to a dataset row (fixed schema silently skips unknown fields).

- **Control:** Not configurable — default `"" when complete`
- **Observe:** scan_summary_<run_id>.json delivery_shortfall (7664); when non-empty, scan_errors_<run_id>.log 'DELIVERY INCOMPLETE — <shortfall>' on the completed path (7547) or 'DELIVERY INCOMPLETE - <shortfall>' on the cancelled path (7412) — note the em dash vs hyphen difference when grepping.
- **Source:** `_delivery_shortfall (7052-7092); summary field (7664); finally-block computation reused by the cleanup gate (7631, 7702)`

### Delivery shortfall surfaced on the Action Center result line

The shortfall string is appended to the returned SCAN_RESULT summary on the completed path (7544-7548) and the operator-cancelled path (7409-7413). Without it a total delivery outage (bad key, revoked permission, unreachable tenant) showed undelivered=0, outcome=completed and no error log — the operator's only clue was one line in the upload log. The cancelled path is called out in-source as the case that most needed it. It is NOT appended on the fatal-failure path (7442-7448) or the critical-error path (7599-7601), so a failed scan's result line never carries a delivery verdict.

- **Control:** Not configurable — default `-`
- **Observe:** The Action Center action's returned text (printed by the CLI path as 'SCAN_RESULT: …', 7772): 'Scan completed: … \| alerts: 12 of 40 NOT delivered — findings are complete in the local logs on this endpoint' (suffix built at 7092).
- **Source:** `completed path (7544-7548); cancelled path (7409-7413)`

### Host cleanup gated on confirmed delivery

End-of-run deletion of this run's artefacts is refused unless delivery is verifiable: mode 'on_delivery' requires an empty shortfall AND at least one delivery channel enabled (both channels off means an empty shortfall would mean 'nothing was ever attempted', not 'everything landed'). Cleanup also runs only when outcome=='completed' (7694), and only if the summary JSON was durably written (4928) — a missing summary means the run cannot even be attested, so it deletes nothing. mode 'always' bypasses the shortfall gate entirely (4899-4900).

- **Control:** CONFIG_HOST_CLEANUP (line 238) and CONFIG_HOST_CLEANUP_KEEP (239) — neither is an options key — default `"off" / "summary"`
- **Observe:** Presence/absence of files under <scanner_dir>/logs, /alert and /evidence after the run. UNOBSERVABLE: the reason string — it goes to logging.info/logging.warning (7705-7711) after log_manager.stop_logging() at 7696 has closed the structured handlers, and setup_logging (6963-6966) strips root handlers and pins root to WARNING, so only 'Host cleanup failed: …' (7711) could reach stderr. Confirm by listing the endpoint directory instead.
- **Source:** `HostCleanup.should_run (4890-4912); HostCleanup.run summary-exists guard (4914-4929); gate call site (7693-7711)`

### Placeholder-credential pre-flight abort

If DEFAULT_XDR_API_KEY / _ID / _URL are still 'replace_with_*' (or blank) AND either delivery channel is enabled, the run aborts BEFORE scanning and returns an explanatory SCAN_ABORTED string. Without it a perfect scan finds matches and drops 100% of them with 'No scheme supplied' errors. Deliberately tests the PARSED booleans on config, not the raw run() args, because an options string passes the truthy non-empty string "false".

- **Control:** DEFAULT_XDR_API_KEY/ID/URL (lines 136-138); creds_placeholder detection (2767-2770) — default `placeholders present in the shipped script`
- **Observe:** Action Center result text begins 'SCAN ABORTED — XDR API credentials are not set' (7190); scan_errors_<run_id>.log carries the same message (7198) and yara_processing_<run_id>.log carries the longer 'XDR API CREDENTIALS NOT SET …' error written at config time (2776-2781). The __main__ path exits 1 because 'scan aborted' is in the failure prefix list (7776).
- **Source:** `creds_placeholder (2767-2770); abort in run() (7188-7203); exit-code classification (7774-7778)`

### XDR auth mode: per-request HMAC (Advanced) or plain key (Standard), auto-probed

Advanced auth builds a fresh 32-byte nonce + millisecond timestamp + sha256(key+nonce+timestamp) signature PER HTTP ATTEMPT — headers must never be reused across retries, and every call site rebuilds them inline. 'auto' probes xql/get_datasets with Advanced then Standard and caches the winner in the module global _RESOLVED_AUTH_TYPE; a network error during the probe returns 'advanced' WITHOUT caching (700) so detection retries later — which on an unreachable tenant means one probe (and one unthrottled log line) per HTTP attempt. Notably uses os.urandom rather than the `secrets` module because the Cortex agent's script sandbox rejects that import.

- **Control:** XDR_AUTH_TYPE = (os.environ.get("XDR_AUTH_TYPE") or "auto").strip().lower() (line 333) — env var, customer-reachable — default `"auto" (falls back to advanced)`
- **Observe:** uploads_<run_id>.log 'XDR auth type detected: advanced' (704), 'XDR auth probe inconclusive; defaulting to advanced' (709), or — on an unreachable tenant — repeated 'XDR auth probe (advanced) network error: …' (699), once per attempt because _probe_auth_type logs directly rather than through _throttled_log.
- **Source:** `XDR_AUTH_TYPE (333); _advanced_auth_headers (645-661); _standard_auth_headers (664-670); _probe_auth_type (678-710); build_xdr_headers (713-723)`

### Tenant identity tagging on every alert and every row

tenant_id is stamped into every matches row (3662), every scans row (5221), and every alert_description (3342). It is derived by regex from the API hostname (api-<tenant>.xdr.) unless explicitly overridden, and NEVER raises — it returns 'unknown' rather than letting a labeling failure break a scan.

- **Control:** CONFIG_TENANT_ID (line 185); options key 'tenant_id' (774); derived from XDR_API_URL otherwise — default `"" -> derived from the API URL`
- **Observe:** XQL: dataset = yara_scanner_matches_v3_* \| fields tenant_id; scan_summary_<run_id>.json tenant_id (2320); yara_processing_<run_id>.log 'Tenant ID: <id>' (2786).
- **Source:** `CONFIG_TENANT_ID (185); _derive_tenant_id (748-765); assignment (2773); consumers (3342, 3662, 5221)`

### Idempotent endpoint URL construction

Four builders append the fixed public-API path to the configured base URL, but first check whether the base ALREADY ends with that path — so a customer who pastes the full insert_parsed_alerts URL into DEFAULT_XDR_API_URL still gets a valid endpoint instead of a doubled path. An empty base returns "", which is what produces the 'No scheme supplied' failure mode elsewhere. Paths are deliberately kept out of the customer-editable config block (589-594).

- **Control:** Not configurable — XDR_INSERT_PARSED_ALERTS_PATH (595), XDR_LOOKUPS_ADD_DATA_PATH (596), XDR_GET_DATASETS_PATH (597), XDR_ADD_DATASET_PATH (598) — default `/public_api/v1/alerts/insert_parsed_alerts, /public_api/v1/xql/lookups/add_data, /public_api/v1/xql/get_datasets, /public_api/v1/xql/add_dataset`
- **Observe:** The resolved URL appears in every failure message that echoes the requests exception, e.g. 'Lookup batch network error: … with url: /public_api/v1/xql/lookups/add_data' in uploads_<run_id>.log; yara_processing_<run_id>.log 'XDR API URL: <base>' (2785) shows the configured base. Delivery success itself is the positive signal.
- **Source:** `_build_xdr_insert_alerts_url (601-608); _build_xdr_lookups_add_data_url (611-618); _build_xdr_get_datasets_url (621-628); _build_xdr_add_dataset_url (631-638)`

### uploads_<run_id>.log — the delivery observability artefact

LogManager gives the UPLOAD category its own logging.FileHandler at INFO with propagate=False, so delivery logging survives setup_logging's stripping of root handlers and its WARNING pin. This is why upload-channel behaviour is observable at all while bare logging.info calls elsewhere in the file are not. Structured `data` dicts passed to any log_* call are JSON-serialized onto the line and truncated at 4000 chars. CAVEAT: nothing logged from inside ResultsUploader.__init__ reaches this file, because its log_manager is None until 5025.

- **Control:** Not configurable (path is <scanner_dir>/logs/uploads_<run_id>.log; six LogManager categories, plus a seventh file yara_processing_<run_id>.log owned separately by ErrorLogger, 1493-1527) — default `-`
- **Observe:** The file itself; every alert/lookup batch outcome, drain budget, auth probe and final delivery line lands here (mode="w", so it is per-run, 2145).
- **Source:** `log_files map (2110-2117); _setup_logger propagate=False (2131-2161); _log data blob + 4000 cap (2163-2190); LogType enum (1303-1310); setup_logging (6954-6968)`

### CPU governor telemetry heartbeat (CPU_GOVERNOR lines)

Governor state is emitted to the performance log on a meaningful ratio change (>=0.25) OR on a fixed heartbeat, whichever comes first. Change-only emission had produced a single line across a 15,516-file scan because an idle host never moved the ratio — and a steady un-throttled scan is exactly the evidence a customer wants, so the heartbeat guarantees a usable time series without a line per sample. Sampling itself is additionally gated by config.throttle_check_interval_secs (5977), which caps how often the heartbeat check can even run.

- **Control:** GOVERNOR_HEARTBEAT_SECS = env YARA_GOVERNOR_HEARTBEAT_SECS (line 322) — default `30 seconds`
- **Observe:** performance_<run_id>.log lines beginning 'CPU_GOVERNOR {' with a JSON payload including 'ratio' and 't' (6002-6003); the same stats object is embedded in scan_summary_<run_id>.json.cpu_governor (7649-7650).
- **Source:** `GOVERNOR_HEARTBEAT_SECS (322); emission logic (5990-6003); sample gate (5977); summary field (7649-7650)`

### DEAD CODE: CircuitBreaker class is never instantiated

A fully implemented closed/open/half_open circuit breaker exists with allow/on_success/on_failure and its own threshold and reset-timeout constants, but no code anywhere constructs one. Both delivery channels rely purely on bounded retries plus backoff instead, so a permanently failing endpoint is re-hammered every batch rather than short-circuited. The two constants are therefore inert (consumed only as __init__ defaults at 1423).

- **Control:** CIRCUIT_FAILURE_THRESHOLD (line 130), CIRCUIT_RESET_TIMEOUT_SECS (line 131) — defined, consumed only as CircuitBreaker.__init__ defaults — default `5 consecutive failures; 40s open`
- **Observe:** Nothing — no artefact ever reflects circuit state. Confirm by grep: 'CircuitBreaker' appears only at its definition (1420) and nowhere else in the 7785-line file.
- **Source:** `CircuitBreaker (1420-1457); constants (130-131)`

### DEAD CODE: ResultsUploader.upload_results() is never called

A second, older shutdown path exists that waits on the queue for ALERT_DRAIN_SECS, stops the thread, and logs a success-rate percentage computed against total_matches (offset grain) rather than alerts_queued — a ratio that would be meaningless even if it ran. stop() is the live path. The class docstring records the same about save_results(), whose absence is why per-offset detail is no longer accumulated in memory (it once reached ~15 GB RSS for 1,048,035 offsets).

- **Control:** Not configurable — default `-`
- **Observe:** Nothing — 'UPLOAD STATISTICS' (3788), 'Upload success rate' (3795) and 'Upload thread stopped successfully' (3785) never appear in uploads_<run_id>.log on any run; their absence is the confirmation. Note 3785 differs by one word from the LIVE path's 'Upload thread terminated successfully' (3575) — an easy misread.
- **Source:** `upload_results (3746-3802); dead-path note in class docstring (3164-3175)`

### DEAD CODE: ScanStatusUploader.upload_scan_status() is never called and is double-gated off

**⚠ OBSERVABILITY GAP**  
A periodic scan-status uploader exists that would POST a StandardLogEntry.to_dict() straight at insert_parsed_alerts (a shape that endpoint does not accept — it expects request_data.alerts). It is unreachable twice over: no call site exists, and its first line returns early because UPLOAD_NON_MATCH_DATA is False. The object IS constructed (5024) and set_status() is called at NINE points, but set_status only assigns a string and emits an unobservable logging.info — the real lifecycle telemetry is _emit_scan_row.

- **Control:** UPLOAD_NON_MATCH_DATA (line 105) — bare literal; status_upload_interval=60 (4389) and last_status_upload (4388) are also dead — default `False`
- **Observe:** UNOBSERVABLE: set_status only writes via logging.info (4455), which reaches nothing after setup_logging strips root handlers and pins root to WARNING (6963-6966). To observe scan status use the yara_scanner_scans_v3_* lifecycle rows or <scanner_dir>/control/running.json instead.
- **Source:** `ScanStatusUploader (4378-4455); early-return gate (4395-4396); set_status (4452-4455); construction (5024); set_status call sites (6683, 6797, 6815, 6839, 6939, 7390, 7393, 7433, 7529)`

### DORMANT: _build_xdr_parsed_alert single-alert payload builder

Wraps one alert dict in the full request_data.alerts envelope, documented as 'kept for compatibility'. Nothing calls it — every real POST goes through _upload_alert_batch, which builds the same envelope from a list (3403). Useful as the canonical single-alert shape for manual API testing, not as a live code path.

- **Control:** Not configurable — default `-`
- **Observe:** Nothing on a live scan — it emits no traffic. Verify by grep: the symbol appears only at its definition (3367).
- **Source:** `_build_xdr_parsed_alert (3367-3369)`

### DEAD BRANCH: 'Upload queue full' / 'Lookup dataset queue full' handlers

Both channels' queues are constructed unbounded (Queue() with no maxsize, at 3184 and 3862), so the timeout=1.0 on put() can never expire and neither queue-full message can be produced by backpressure. Both except blocks catch bare Exception around more than the put, however, so they ARE reachable by other failures — the alert one wraps create_standard_log (3713-3733), and its message would then misattribute the cause. This is a deliberate trade: the queues cannot shed load, so a match storm is bounded by the alert cap and the per-finding row cap rather than by backpressure, and memory grows with the backlog instead.

- **Control:** Not configurable (no maxsize is passed) — default `unbounded`
- **Observe:** The strings 'Upload queue full - skipping alert for finding' (3740) and 'Lookup dataset queue full - dropping record' (4096) should never appear in uploads_/scan_errors_<run_id>.log; if one does, read it as 'an exception inside the enqueue block', not as backpressure. Note the scan_queue (a different queue) IS bounded by config.scan_queue_size (5028).
- **Source:** `upload_queue = Queue() (3184); lookup queue = Queue() (3862); handlers (3739-3741, 4092-4096); contrast scan_queue maxsize (5028)`

### Log retention across runs (delivery diagnostics window)

Old runs' per-category logs AND their scan_summary JSONs are pruned to the most recent N scans at startup, keyed on the run_id parsed out of the filename (regex at 4582 matches both .log and .json). The current run's id is always retained on top of the N (4616), and the floor is max(1, N) (4613). The default was raised from 2 because that wiped delivery diagnostics too aggressively under frequent scans — this is what determines how far back a support engineer can reconstruct delivery history on an endpoint.

- **Control:** LOG_KEEP_SCANS = env YARA_LOG_KEEP (line 310) — default `10 scans`
- **Observe:** Count of scan_summary_*.json files under <scanner_dir>/logs after several runs; logging.warning 'Cannot remove log file (in use): …' (4629) is the only failure signal that reaches stderr. UNOBSERVABLE: the 'Log retention applied: kept last N scans …' summary at 4634-4637 is a logging.info call and reaches nothing — list the directory instead.
- **Source:** `LOG_KEEP_SCANS (310); _extract_run_id_from_log_name (4580-4583); _prune_old_scan_logs (4585-4639); called from initial_cleanup (4670)`

### Comprehensive final report (statistics log only, never uploaded)

Despite the name upload_final_comprehensive_report sends nothing over the network: it assembles scan_metadata, file_processing (with skip_breakdown), detection_results (with top_10_rules), rule_compilation, system_info, performance_summary, resource_summary and a derived efficiency_score, and writes the whole thing as structured data on ONE statistics-log line. The efficiency score starts at 100 and deducts up to 20 points for skip rate and up to 30 for rule-compilation failure rate, floored at 0.

- **Control:** Not configurable — default `efficiency_score starts at 100`
- **Observe:** statistics_<run_id>.log line 'COMPREHENSIVE SCAN REPORT \| Efficiency Score: NN.N/100 \| data={…}' (7039-7042). CAVEAT: _log truncates the serialized data blob at 4000 chars (2176-2177), so this report is almost certainly TRUNCATED on a real scan — treat the JSON as partial. The accompanying logging.info duplicate at 7044 is UNOBSERVABLE (root pinned to WARNING).
- **Source:** `upload_final_comprehensive_report (6971-7049); efficiency math (7027-7036); log call (7038-7042); call site (7476)`

### Options-string surface for delivery knobs (and what is deliberately excluded)

Exactly ten keys are accepted in the Action Center options string; of the delivery-relevant ones that means create_alerts, write_dataset, tenant_id and lookup_shard. CONFIG_LOOKUP_ROTATION, CONFIG_ALERT_MAX_PER_SCAN, CONFIG_LOOKUP_ROWS_PER_FINDING_MAX, CONFIG_ALERT_OFFSETS_PER_FINDING_MAX and the host-cleanup pair have NO options equivalent by design — rotation decides dataset naming (mixing rotated and unrotated runs splits a host's history), and the alert cap protects a ceiling shared across every concurrent scan. Unknown keys raise ValueError (guard 825, raise 826-828) so operator typos fail loudly; retired throttle_* keys are accepted and translated instead of rejected (825, 787-797).

- **Control:** _VALID_OPTION_KEYS (lines 771-775); _RETIRED_OPTION_KEYS (781-783); CONFIG_OPTIONS (240) — default `CONFIG_OPTIONS = ""`
- **Observe:** Passing e.g. 'lookup_rotation=none' raises ValueError from _parse_options_string at 7137 — which runs BEFORE ScanConfig (7164) and LogManager (7180), so nothing is logged: the exception escapes run() to the __main__ handler, printing the traceback to stderr with exit 1 (7780-7785). A valid 'lookup_shard=wave1' shows up in scan_summary_<run_id>.json matches_dataset.
- **Source:** `_VALID_OPTION_KEYS (771-775); _parse_options_string (800-830); migrate_throttle_option (787-797); _pick application (7142-7151)`

### records_skipped counted as DELIVERED in the delivery verdict

_delivery_shortfall's dataset arm treats landed = records_added + records_updated + records_skipped, but 'skipped' is exactly XDR's answer for rows it silently refused because they carry fields the existing lookup dataset's fixed schema does not know about — the failure LOOKUP_SCHEMA_VERSION exists to avoid. A schema-drifted or pre-existing older dataset can therefore return added=0/skipped=500 for every batch, delivery_shortfall stays "", the Action Center result line reads as a clean success and outcome is "completed"; if CONFIG_HOST_CLEANUP="on_delivery" the HostCleanup gate then passes and deletes the only surviving copy of findings that were never stored.

- **Control:** Not configurable (the summing is hard-coded at 7076-7078). Interacts with LOOKUP_SCHEMA_VERSION (line 290) and CONFIG_HOST_CLEANUP (line 238) / CONFIG_HOST_CLEANUP_KEEP (line 239). — default `-`
- **Observe:** scan_summary_<run_id>.json: dataset_delivery.records_skipped > 0 with records_added == 0 while delivery_shortfall is "" and outcome == "completed" (dataset_delivery written at 7657, outcome 7633). Corroborate with the per-batch line in uploads_<run_id>.log: "Lookup batch ok (N rows): added=0, updated=0, skipped=N" (4226-4229). records_skipped is not reflected anywhere in the shortfall string, so it must be read directly.
- **Source:** `_delivery_shortfall dataset arm (7072-7087; landed sum 7076-7078, lost 7079); _send_batch 2xx response parse and stats credit (4210-4229); scan summary fields 7657, 7664, 7633; HostCleanup.should_run gate (4890-4912; shortfall check 4910-4911)`

### Lookup dataset re-created mid-scan when it disappears under the writer

On an add_data HTTP 400 whose body contains "not found", _send_batch calls _ensure_one() again for that dataset (picking matches_schema or scans_schema by target name) and retries the SAME batch, bounded by a per-batch recreate_attempted flag so a genuinely broken add_dataset cannot loop. This exists because _ensure_datasets runs only once at startup: when an external consolidation/pruning pass deletes a still-in-progress scan's dataset (measured live), every remaining POST for the rest of the run would otherwise fail. The recreate 'continue' consumes one of LOOKUP_ADD_DATA_MAX_RETRIES.

- **Control:** Not configurable — no flag or env var guards the recreate; the retry it triggers is drawn from LOOKUP_ADD_DATA_MAX_RETRIES (line 256, YARA_LOOKUP_RETRIES). The retryable status set is only (408,429,500,502,503,504) at line 4232 — any other non-2xx, including a 400 WITHOUT "not found", counts one send_failure and returns immediately (4267-4273). — default `LOOKUP_ADD_DATA_MAX_RETRIES = 6`
- **Observe:** uploads_<run_id>.log: "Lookup batch failed (HTTP 400, dataset not found) - '<dataset>' appears to have been deleted mid-scan; recreating and retrying this batch once." (4254-4258), then either "Lookup dataset '<name>' created (schema fields: 22)" (4023-4026) or "Lookup dataset '<name>' already exists - will append rows" (4002-4004), followed by "Lookup batch ok (N rows)..."; on failure, scan_errors_<run_id>.log gets "Dataset recreation failed: <e>" (4264). Provoke it live by deleting the shard dataset while a scan is mid-flight.
- **Source:** `_send_batch recreate branch (4242-4265; recreate_attempted init 4193, condition 4250-4251, _ensure_one call 4261, schema pick 4259); _ensure_one (3956-4054); startup-only _ensure_datasets (3951-3954) invoked from __init__ (3940-3941)`

### Endpoint IP identity resolved by NAME lookup — and its failure text is shipped as the IP

get_system_info takes the hostname from socket.gethostname() and derives ip_addresses by calling socket.getaddrinfo(hostname, None) — a name resolution, not interface enumeration — so the tenant sees whatever DNS/hosts maps the name to. Entries beginning '127.' are dropped with no fallback while IPv6 results are kept, so ip_addresses[0] can be an IPv6 address, and a host resolving only to loopback yields an EMPTY list (ip_address then becomes "Unknown" in the uploaders/LogManager, "" in the scans row). On any exception the whole list becomes the single string "Unable to determine IP address: <error>", written verbatim as the ip_address column of both lookup datasets, into every StandardLogEntry, into scan_summary_<run_id>.json and into the evidence manifest header. Only the alert channel is insulated: _alert_dict picks the first dotted non-loopback entry for local_ip and falls back to 127.0.0.1.

- **Control:** Not configurable — no env var, option or parameter overrides the resolved address. — default `-`
- **Observe:** jq .ip_address logs/scan_summary_<run_id>.json (2323); XQL `dataset = yara_scanner_scans_v3_* \| fields ip_address` for this run_id (row field 5228) and the same column on matches rows (3669); the "IP Addresses: ..." header line in evidence/file_mapping.txt, which joins the WHOLE list so the failure sentence appears in full (4507). A resolution failure shows up as prose in those fields, not as an error line.
- **Source:** `get_system_info (371-384; 127.* filter 380, except-branch sentinel 384); ScanConfig consumption 2688; ip_addresses[0] consumers 1777, 2107, 2374, 3178, 4385, 5228; whole-list consumers 4507, 6978, 7299; alert IPv4 pick with 127.0.0.1 fallback 3334-3338`

### file_creation_time is empty on every Linux match, by design  <sub>windows, darwin</sub>

_get_file_creation_time_iso runs once per MATCHED file (reusing the stat the scanner already took) and returns an ISO-8601 UTC timestamp from st_ctime on Windows or st_birthtime where the platform exposes it (macOS). On Linux neither branch applies and the function falls off the end returning None, which becomes "" in the matches dataset row and omits the 'File Creation Time:' line from alert/<rule>.txt. Any exception also returns None, so a null can never be read as 'this file has no birth time'. The Windows branch deliberately uses st_ctime — creation time on Windows but CHANGE time on POSIX — which is why POSIX is not allowed to fall through to it.

- **Control:** Not configurable. — default `-`
- **Observe:** file_creation_time populated in yara_scanner_matches_v3_* rows from Windows/macOS endpoints and empty from Linux ones (row field 3674); presence/absence of the "File Creation Time: <iso>" line in alert/<rule>.txt (6403-6404); the file_creation_time key in the alerts_<run_id>.log detection entry (6451, per-detection 6382).
- **Source:** `_get_file_creation_time_iso (996-1010; Windows st_ctime 1004-1005, st_birthtime 1007-1008, implicit None on Linux); call site scan_file 6163-6164 (passes the existing stat `st`); consumers _write_alerts 6403-6404 and add_match lookup_record 3674; local detection dict 6382, alert log 6451`

### os_info is a hand-maintained string whose macOS name table stops at Darwin 24

get_os_info composes the os_info value used by every channel from platform.system()/release()/machine(). On Darwin it maps only Darwin majors 21-24 to marketing names ('macOS 15 (Sequoia)' … 'macOS 12 (Monterey)') and anything newer falls back to 'macOS (Darwin 25.x.y) [arm64]', so a newer macOS silently loses its product name in dashboards. On Linux it emits 'Linux <kernel release> [arch]' — the KERNEL, never the distro, so no row anywhere distinguishes Ubuntu from RHEL. On Windows it emits platform.release() ('11', '2022'), not the 10.0.x build. The coarse os_type column is the only stable field for segmentation; os_info is a human string.

- **Control:** Not configurable (the mac_names dict is a literal inside the function at 356-361). — default `-`
- **Observe:** os_info in yara_scanner_matches_v3_* rows (3667) and yara_scanner_scans_v3_* rows (5226), in scan_summary_<run_id>.json (2322), in every structured log entry via StandardLogEntry, and in the "OS:" header of evidence/file_mapping.txt (4506). Compare against the os_type column (3668 / 5227) for the segmentation-safe value. On the lab macOS 15.1 endpoint expect "macOS 15 (Sequoia) [arm64]"; on the Ubuntu 20.04 lab VM expect "Linux 5.4.0-216-generic [x86_64]" with no distro name.
- **Source:** `get_os_info (348-368; mac_names table 356-361, unknown-major fallback 362, Linux kernel-only 364-365, Windows release 366-367); consumed via get_system_info 374/382 into ScanConfig 2688; row fields 3667, 5226; os_type companion 3668, 5227; summary 2322; evidence header 4506`

### scan_folder column carries the operator's RAW input string, or the literal "system"

Both the matches row and every scans-lifecycle row set scan_folder from str(config.scan_folder or 'system'), and config.scan_folder is the untouched run parameter exactly as typed. So a multi-target run stores the whole comma-separated string in one text column ("C:\\Users,D:\\Shares"), quotes and stray whitespace included; entries ScanConfig validated away as non-directories still appear there; the case-normalised absolute paths actually walked (config.scan_targets) appear on the wire nowhere at all; and a default full-scope run is indistinguishable from an explicit scan of a folder literally named 'system'. An XQL filter on scan_folder must use substring matching, not equality.

- **Control:** The scan_folder run parameter (run() signature 7095, stored verbatim at 2750); the 'default' sentinel branch at 2987 selects full scope. Not otherwise configurable. — default `None → rendered as the literal string "system" on the wire`
- **Observe:** scan_folder in yara_scanner_matches_v3_* (3675, sourced 3638) and yara_scanner_scans_v3_* (5230). The resolved target list is NOT on the wire and NOT in scan_summary either — scan_summary_<run_id>.json's scan_folder field is the same raw string (7634); the resolved absolute paths appear only in yara_processing_<run_id>.log's "Scan limited to N folder(s): ['...']" line (3036-3037) and in system_<run_id>.log's init_data.scan_targets (7304) / "SCAN SCOPE: Limited to specified targets: [...]" (7324). Invalid entries leave "Ignoring N specified scan folder(s) that are not valid directories..." in yara_processing (3009-3011).
- **Source:** `ScanConfig.scan_folder 2750; target validation 2987-3037 (strip/dedupe 2995-3002, abspath 3000, scan_targets 3035); add_match _scan_folder 3638 and lookup_record 3675; _emit_scan_row 5230; summary 7634; scope logging 3036-3037, 7304, 7324`

### Alert channel's startup narration is unreachable — uploads log never records whether alerts are on

**⚠ OBSERVABILITY GAP**  
ResultsUploader.__init__ sets self.log_manager = None and then decides the channel and starts the worker thread inside that same __init__, while the real LogManager is only attached afterwards by YaraScanner (two statements later, after the blocking LookupDatasetUploader construction). So "Parsed-alerts upload disabled (create_alerts=false)", "XDR_API_URL not configured - real-time match upload disabled", "Starting real-time upload thread..." and "Real-time upload thread started successfully" are all guarded by a log_manager provably None at that moment and reach nothing; "Upload worker thread started (batch=N)" runs on the new worker thread and races the same assignment. Consequence: uploads_<run_id>.log holds no record of whether the alert channel started or why it was skipped, and a create_alerts=false run leaves the channel entirely unmentioned. The sibling LookupDatasetUploader takes log_manager as a constructor argument and DOES log its disabled state.

- **Control:** Not configurable (construction-order bug, not a knob). The gated decision itself is config.create_alerts (checked 3213) and UPLOAD_RESULTS. — default `-`
- **Observe:** UNOBSERVABLE: the startup/disable lines — grep uploads_<run_id>.log for "Parsed-alerts upload disabled" / "Starting real-time upload thread" and they are absent even on runs where they should fire. Earliest alert-channel evidence is the first "Alert batch ok (N alerts, HTTP 200)" (3433-3434) or a throttled failure line; the end-of-run "Alert delivery final: findings=... queued=..." (3596) also lands. To confirm intended state instead, read `alerts=on\|off` in config.posture (2725-2729), surfaced in yara_processing_<run_id>.log's "Runtime posture:" line (2789) and scan_summary's posture field (2326). Making the startup lines observable needs log_manager passed into ResultsUploader.__init__ (as LookupDatasetUploader already does) or _start_upload_thread deferred until after the attach.
- **Source:** `ResultsUploader.__init__ self.log_manager = None 3181, channel decision 3212-3216, _start_upload_thread 3218-3232 (worker start 3228-3229); _upload_worker first line 3237-3238; late attach YaraScanner.__init__ 5017 (construct) / 5018 (blocking lookup pre-create) / 5025 (attach); contrast LookupDatasetUploader.__init__ signature 3827 and disabled-state log 3940-3946`

### Both uploader worker loops swallow unexpected exceptions and keep running

The lookup dataset worker and the alert upload worker each wrap their loop body in a bare `except Exception: ... continue`, so a persistent bug cannot silently kill delivery for the rest of the scan — which matters most for the lookup thread, because the terminal lifecycle row still has to travel through it. The failure therefore surfaces as a REPEATING log line rather than as missing rows, and because the loops never exit, `dropped` in dataset_delivery stays 0: the thread is still alive, so _enqueue's not-alive drop path never fires.

- **Control:** Not configurable. — default `-`
- **Observe:** scan_errors_<run_id>.log: repeating "Lookup worker loop error (continuing): <e>" (4134-4135) for the dataset thread and "Upload worker unexpected error: <Type>: <msg>" — a bare type name when str(e) is empty (3282-3285) — for the alert thread. Cross-check that scan_summary's dataset_delivery.dropped is 0 while these repeat, and that the terminal lifecycle row (completed/failed/cancelled) still appears in yara_scanner_scans_v3_*. Contrast the thread-death path, which logs "Lookup uploader thread not alive - dropping rows for <dataset> (further drops suppressed)" exactly once and increments dropped (4076-4087).
- **Source:** `LookupDatasetUploader._worker catch-all 4131-4136; ResultsUploader._upload_worker catch-all 3281-3286 (bare-type formatting 3283); _enqueue not-alive drop path 4076-4087 and queue-put failure path 4092-4095`

### Condition-only (no-strings) rule matches reach NEITHER delivery channel

add_match early-gates both delivery arms on match_count — the number of matched STRING instances — so a rule firing on its condition alone (filesize, pe./hash./math. conditions, uint16(0)==0x5A4D) yields match_count == 0 and is dropped from the lookup dataset row AND the alert queue. Locally the finding still counts: _write_alerts increments detection_counts and total_detections before either gate and appends a header-only block to alert/<rule>.txt with no explanation of why the rule fired.

- **Control:** Not configurable — both gates are bare `match_count > 0` literals in add_match (3656, 3697). — default `-`
- **Observe:** Divergence between scan_summary_<run_id>.json matches / unique_rules_triggered (non-zero, from scanner.total_detections and detection_counts at 7639-7640) and zero rows for that rule in yara_scanner_matches_v3_* plus zero alerts. Locally, alert/<rule>.txt has the "YARA rule '<r>' matched file: <path>" header and the separator with no "Matched Strings" block (6400-6406), and alerts_<run_id>.log's detection event shows total_string_matches=0 with match_count 0 in its detections list (6445-6455). Reproduce with a rule whose condition is `filesize > 0`.
- **Source:** `ResultsUploader.add_match match_count accumulation 3625/3639-3653, dataset gate 3656, alert gate 3697; YaraScanner._write_alerts counters 6372-6374 and `if strings:` block 6406-6438; local alert header 6399-6405; detection log 6444-6457`

### An exception while building one alert dict silently shrinks the batch

_upload_alert_batch builds each alert inside a per-item try; a failure logs into the throttled "alert_build_err" bucket and that alert is dropped from the `alerts` list, after which all delivery accounting is credited against n = len(alerts). The dropped alert is counted neither successful nor failed — but it was already counted in alerts_queued at enqueue time, so its only trace is the residual in _delivery_shortfall's alert arm (alerts_queued - successful_uploads). If the batch is otherwise perfect the operator sees "alerts: 1 of N NOT delivered" on the result line with no matching failure line anywhere. If every alert in a batch fails to build, n == 0 and the function returns "dropped" without ever POSTing.

- **Control:** Not configurable; the log line's volume is bounded by the throttled-bucket mechanism (_throttled_log, 3371-3386). — default `-`
- **Observe:** grep "alert build error (skipping one)" in uploads_<run_id>.log (3399 — routed through _throttled_log, so occurrences are summarised, not one line each). Reconcile scan_summary_<run_id>.json's alert_delivery block: alerts_queued vs successful_uploads + failed_uploads; a positive residual with no "Alert batch failed" line is this case, and delivery_shortfall reads "alerts: X of N NOT delivered".
- **Source:** `_upload_alert_batch build loop 3394-3402 (per-item try 3396-3399, n = len(alerts) 3400, empty-batch return 3401-3402); per-alert crediting 3429/3432/3457 (all `+= n`); alerts_queued increments 3522 and 3735; upload_stats keys 3187-3196; _delivery_shortfall alert arm 7063-7069`

---

# Scan Lifecycle, Control & Error Handling

*Phases, cancellation, outcomes, failure paths.*

### Action Center scan entry point (main) — only 3 operator inputs

Cortex XDR's "Run by entry point" turns each function parameter into an input field, so main() deliberately exposes ONLY yarafile / scan_folder / alert_severity and forwards to run() with everything else left at its default (None). Every other behaviour knob therefore comes from the CONFIG_* constants baked into the uploaded copy of the script — an operator cannot change workers, CPU policy, alerting or dataset writing from the Action Center form at all. main() does NOT pass mode/options either, so the Action Center scan form cannot even use CONFIG_OPTIONS overrides per-run.

- **Control:** CONFIG_* block, lines 160-240 (edit-and-re-upload); no options/mode parameter exposed on this entry point (main signature 7730) — default `alert_severity="low"; all other knobs = their CONFIG_* constant`
- **Observe:** scan_summary_<run_id>.json "posture" field (e.g. "alerts=on dataset=on files=off cpu=headroom mode=scan", built at ScanConfig 2725-2730) and the same string appended to the SCAN_RESULT line (7536); logs/system_<run_id>.log "YARA Scanner initialization completed" (7321) data blob carries max_workers/scan_queue_size/max_file_mb.
- **Source:** `main() 7730-7733; run() signature 7095-7098; CONFIG fallbacks 7109-7132; posture built 2725-2730`

### Action Center cancel entry point (cancel, zero inputs)

A second, separate Action Center entry point that calls run(mode="cancel"). It exists because main() has no mode field — cancelling is a distinct script invocation on the endpoint, not a signal to the running process. run() reaches the short-circuit after resolving CONFIG_* fallbacks and parsing the options string (7109-7151), so an options typo still aborts a cancel invocation, but it returns before ScanConfig, LogManager, priority tuning or rule compilation.

- **Control:** Not configurable (the function IS the entry point); mode short-circuit at 7154-7155 — default `-`
- **Observe:** Return string "Cancel signal delivered (<scanner_dir>/control/cancel.flag) \| scanner running: yes\|no \| scan_id=…" (884-887) in the Action Center result; the file <scanner_dir>/control/cancel.flag appears on disk.
- **Source:** `cancel() 7736-7738; run() mode short-circuit 7153-7155; _handle_cancel_request 845-887`

### CLI entry point — five ordered positional arguments

Running the file directly maps argv[1..5] to yarafile, scan_folder, alert_severity, mode, options. Unlike the Action Center entry points this DOES expose mode and the options string, so the CLI is the only supported way to pass per-run key=value overrides. Any blank/whitespace argument is treated as unset and falls back to the CONFIG_* constant.

- **Control:** argv assignments 7751-7755; _argv() treats empty/whitespace strings as None (7748-7749) — default `alert_severity defaults to "low" when argv[3] is blank; mode/options fall back to CONFIG_MODE / CONFIG_OPTIONS`
- **Observe:** stdout line "SCAN_RESULT: …" (7772); process exit code (7778); scan_summary_<run_id>.json reflects the resolved knobs ("posture", "throttle_mode").
- **Source:** `__main__ block 7741-7785; _argv 7748-7749; argv assignments 7751-7755; run() call 7757-7763`

### SCAN_RESULT stdout line on the CLI path

The CLI prints "SCAN_RESULT: " + the run() return string and flushes. Without it the direct-execution path was completely silent (the only printer was the footer that build_scanner_snippet appends), so a customer validating the script or a scheduled task got no output at all. The prefix is identical to the snippet path so downstream parsing is the same either way.

- **Control:** Not configurable — default `-`
- **Observe:** stdout of the process: a single line beginning "SCAN_RESULT: ".
- **Source:** `7765-7773 (result_text 7765, comment 7766-7771, print 7772, flush 7773)`

### Exit code derived by string-matching the result line

Exit status is not derived from scanner state but from lowercase prefix matching on the returned text: exit 1 only if the result starts with "scan failed", "cancel failed" or "scan aborted", or if the string is empty; anything else exits 0. Consequence: an operator-cancelled scan ("Scan cancelled by operator: …") and a completed scan that delivered NOTHING ("Scan completed: … \| alerts: 500 of 500 NOT delivered") both exit 0.

- **Control:** Not configurable — literal prefix list at 7776 — default `exit 0`
- **Observe:** Process exit code from the CLI/scheduled-task invocation, compared against the SCAN_RESULT text.
- **Source:** `7774-7778 (low= 7774, is_success 7775-7777, prefix literals 7776, sys.exit 7778)`

### Startup-exception exit path (exit 1 with traceback)

Any exception escaping the __main__ block itself is caught here, written to stderr with a full traceback, and exits 1. Two real causes: _parse_alert_severity rejecting argv[3] (906-913), and — the surprising one — an options-string ValueError, because _parse_options_string runs at 7137, OUTSIDE run()'s try (which opens at 7163), so it is never converted into a "Scan failed:" result line. This is the only failure path that produces no scanner logs at all, because it can fire before ScanConfig creates the logs directory.

- **Control:** Not configurable — default `-`
- **Observe:** stderr lines "Critical startup error: …" + "Full traceback:"; exit code 1; NO logs/*_<run_id> files and no scan_summary JSON created.
- **Source:** `7780-7785; feeders: _parse_alert_severity 906-913 (called 7753) and _parse_options_string 800-830 (called at 7137, above run()'s try at 7163)`

### run() — the full internal API with every behaviour knob

run() is the real implementation and takes 15 parameters — the 3 Action Center inputs plus 12 behaviour kwargs (mode, options, create_alerts, write_dataset, collect_files, the four cpu_* knobs, workers, tenant_id, lookup_shard). Operators are explicitly told not to call it through the Action Center; it exists so the CLI, tests and the delivery snippet can drive every knob without editing constants.

- **Control:** Signature 7095-7098; CONFIG_* fallback for each None at 7109-7132 — default `Every kwarg None → its CONFIG_* constant`
- **Observe:** scan_summary_<run_id>.json "posture" / "throttle_mode" (7648) and logs/system_<run_id>.log initialization data blob (7321).
- **Source:** `run() 7095-7132`

### Options string parsing with loud rejection of unknown keys

The compact "key=value,key=value" options string is parsed into a dict; a chunk without "=" or an unrecognised key raises ValueError, so an operator typo aborts the run instead of silently doing nothing. Only ten keys are accepted — CONFIG_LOOKUP_ROTATION, CONFIG_ALERT_MAX_PER_SCAN, CONFIG_HOST_CLEANUP and CONFIG_HOST_CLEANUP_KEEP have NO options equivalent and are rejected as unknown by design. The parse happens at 7137, BEFORE run()'s try block (7163), so the ValueError escapes run() entirely rather than being converted into a result line.

- **Control:** _VALID_OPTION_KEYS 771-775; parser 800-830; CONFIG_OPTIONS 240 supplies a fleet-wide default string — default `CONFIG_OPTIONS = "" (no options)`
- **Observe:** On a typo the exception propagates OUT of run(). CLI: stderr "Critical startup error: Unknown option '<k>'. Valid keys: …" + "Full traceback:", exit 1 (from the __main__ handler at 7780-7785). Action Center main()/cancel(): the entry point raises and the action reports the Python traceback. No ScanConfig, so NO per-run log files and NO scan_summary JSON.
- **Source:** `_parse_options_string 800-830 (unknown-key raise 825-828); _VALID_OPTION_KEYS 771-775; call site 7137 vs run()'s try at 7163`

### Retired throttle_* options accepted and translated, not rejected

throttle_mode / cpu_high_threshold / cpu_critical_threshold / max_pause_secs are still accepted by the parser and then silently translated: throttle_mode off→cpu_guarantee=none, script→headroom, os→headroom; the other three are dropped. Existing scripts and scheduled jobs keep running, but the OLD behaviour is deliberately NOT preserved — a job that asked for "os" now gets the headroom governor. The translation only injects cpu_guarantee when the options string does not already carry one (793), so an explicit cpu_guarantee in the same string wins over throttle_mode.

- **Control:** _RETIRED_OPTION_KEYS 781-783; _THROTTLE_MODE_MAP 784; migrate_throttle_option 787-797 — default `unmapped/unknown mode value → "headroom" (794)`
- **Observe:** scan_summary_<run_id>.json "throttle_mode" (7648, = config.cpu_guarantee) shows the TRANSLATED value (headroom/budget/none), never the word passed in; same value in the yara_scanner_scans_v3_* dataset row's throttle_mode column (_emit_scan_row row dict, 5239).
- **Source:** `migrate_throttle_option 787-797; applied at 7137`

### Options string overrides explicit kwargs and CONFIG constants

After migration, each of the ten knobs is re-picked from the parsed options dict via _pick(), so an options entry beats both the kwarg the caller passed and the CONFIG_* constant. Precedence is therefore options > kwarg > CONFIG_*, and values arrive as raw strings that ScanConfig coerces later (which is why the placeholder-credential check reads config.create_alerts, not the raw arg — "false" is a truthy string).

- **Control:** _pick 7139-7151 — default `-`
- **Observe:** scan_summary_<run_id>.json "posture" reflects the final resolved values; ScanConfig coercion visible in logs/yara_processing_<run_id>.log "Runtime posture: …" (2789).
- **Source:** `_pick 7139-7151; boolean coercion in ScanConfig 2702-2707 (_parse_bool_arg); cpu_* coercion 2710-2721`

### mode=cancel short-circuit before any scanner initialisation

run() lowercases/strips mode and, when it equals "cancel", returns _handle_cancel_request() immediately — before ScanConfig, LogManager, priority tuning or rule compilation. A cancel invocation therefore creates no run_id, no log files and no dataset rows; the only trace it leaves is the flag file itself. It does still resolve the CONFIG_* fallbacks and parse the options string first (7109-7151), and tenant_id from options/CONFIG is forwarded into the flag.

- **Control:** CONFIG_MODE 160 (deployment-wide default mode); mode kwarg / argv[4] — default `CONFIG_MODE = "scan"`
- **Observe:** <scanner_dir>/control/cancel.flag exists with keys requested_at_ms/source/tenant_id_override (876-880); NO new logs/*_<run_id>.log files are produced by the cancel invocation.
- **Source:** `7153-7155; _handle_cancel_request 845-887`

### Cancel flag file — cooperative cross-process cancellation

Cancellation is file-based, not signal-based: the cancel invocation writes JSON {requested_at_ms, source:"xdr_action", tenant_id_override} to <scanner_dir>/control/cancel.flag, and the running scan's watcher thread picks it up. This works because each Action Center run is a separate process; there is no IPC channel to the live scan. The running scan resolves the same path independently from config.control_dir (5069), so YARA_SCANNER_DIR must match on both invocations.

- **Control:** Path from _default_scanner_dir() 833-842 (YARA_SCANNER_DIR env override at 834-837); flag name hardcoded at 859; scan-side path 5069 via control_dir 2734 — default `C:\yara_scanner\control\cancel.flag / /usr/local/yara_scanner/control/cancel.flag (Darwin) / /opt/yara_scanner/control/cancel.flag`
- **Observe:** The file <scanner_dir>/control/cancel.flag; then scan_summary_<run_id>.json "cancel_source" (7654) = the flag's source value, and "outcome":"cancelled" (7618).
- **Source:** `_handle_cancel_request 845-887 (flag write 874-880); cancel_flag_path 5069; _cancellation_watcher 5152-5171`

### Cancel reports liveness from running.json rather than the process table, on a window scaled to the heartbeat

The cancel result line says whether a scan appears to be running by reading control/running.json and checking that updated_at is newer than SCANS_HEARTBEAT_SECS*3 + 60 — 1860s (~31 min) at the 600s default. It never inspects processes, so a scan whose heartbeat has stalled reports "scanner running: no" while still burning CPU, and a crashed scan that left the marker behind reports "yes" for up to 31 minutes. The window is coupled to the row-cadence knob: raising YARA_HEARTBEAT_SECS to 3600 to cut dataset volume silently widens the liveness window past three hours; setting 60 collapses it to 240s. Any exception reading the marker is swallowed and reported as running=False (871-872). The marker's payload (scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections) is the only cross-process progress view of a live scan, and it is deleted at end of scan, so a missing file cannot be distinguished from a clean finish.

- **Control:** SCANS_HEARTBEAT_SECS 307 (env YARA_HEARTBEAT_SECS); window formula at 870 — default `600s heartbeat → liveness window 1860s`
- **Observe:** The cancel invocation's returned text "\| scanner running: yes\|no \| scan_id=…" (884-887); cross-check <scanner_dir>/control/running.json (updated_at vs wall clock, and whether its pid still exists — payload written at 5182-5192, atomic os.replace 5193).
- **Source:** `_handle_cancel_request 862-872 (marker read), 884-887 (result line); _write_running_marker 5173-5195; refresh gate _maybe_heartbeat 5255-5260`

### Cancel failure modes return an error string (never raise)

If the control directory cannot be created or the flag cannot be written, _handle_cancel_request returns "Cancel failed: …" instead of raising — which is exactly the prefix the CLI exit-code check looks for, so a failed cancel exits 1 while a successful one exits 0.

- **Control:** Not configurable — default `-`
- **Observe:** Returned text starting "Cancel failed: cannot create control dir …" (857) or "Cancel failed: cannot write …" (882); CLI exit code 1.
- **Source:** `854-857, 874-882; exit-code prefix 7776`

### Stale cancel-flag eviction at scan start (with compile-phase preservation)

At scan start the watcher deletes a pre-existing cancel.flag ONLY if its mtime predates this process's construction time minus 2s of filesystem slack. A cancel delivered DURING the (potentially ~90s) rule-compilation phase has a newer mtime and is deliberately kept, so it is honoured the moment the watcher starts — the surprising part is that the baseline is process construction, not scan start.

- **Control:** CANCEL_STALE_TOLERANCE_SECS 319 (bare literal, not env-reachable; its only reader is 5140); baseline _process_started_at 5075 — default `2.0s tolerance`
- **Observe:** logs/system_<run_id>.log line "Removed stale cancel flag from a previous run" (5142), or "Could not evaluate pre-existing cancel flag: …" (5144); absence of the flag file afterwards.
- **Source:** `_start_cancellation_watcher 5129-5150 (staleness test 5138-5144); _process_started_at 5075`

### Cancel watcher polling thread

A daemon thread named CancelWatcher polls for the flag every CANCEL_POLL_SECS while the scan is active and cancellation has not already been requested, reads the flag's "source" field for attribution (defaulting to "action_center" if the JSON is unreadable), and calls _request_cancel. Poll errors are logged and the loop continues, so a transient stat failure does not disable cancellation.

- **Control:** CANCEL_POLL_SECS 311 (env YARA_CANCEL_POLL_SECS) — default `5s`
- **Observe:** logs/system_<run_id>.log "Cancellation requested (source=xdr_action)" (5125); logs/scan_errors_<run_id>.log "Cancel watcher error: …" (5170) on failure; thread name CancelWatcher (5148).
- **Source:** `_start_cancellation_watcher 5147-5150 (thread creation/start); _cancellation_watcher 5152-5171`

### Idempotent cancel request — first source wins

_request_cancel takes a lock, returns immediately if cancellation is already requested, then sets cancel_requested / cancel_source / scan_active=False. So if a SIGTERM and a flag arrive together, whichever landed first owns the recorded source. It is deliberately NOT used by the signal handler.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json "cancel_source" (7654) — one value only; logs/system_<run_id>.log single "Cancellation requested (source=…)" line (5125).
- **Source:** `_request_cancel 5113-5127; _cancel_lock 5079`

### SIGTERM/SIGINT routed into the graceful cancel path

run() installs a signal handler that sets scanner.cancel_source="signal:<n>", cancel_requested=True and scan_active=False BARE — no lock, no logging — to stay async-signal-safe; the watcher and main loop then drive the normal graceful shutdown. A hard Action Center abort that delivers a signal therefore still drains uploaders and writes the summary. Both the whole block and each individual signal.signal() call are wrapped in try/except, so a platform without the signal or a non-main thread silently skips it.

- **Control:** Not configurable — signal names hardcoded at 7356 — default `SIGTERM and SIGINT, when present on the platform`
- **Observe:** scan_summary_<run_id>.json "cancel_source":"signal:15" (or :2) with "outcome":"cancelled"; matching terminal row status=cancelled in the yara_scanner_scans_v3_* dataset (emitted 6757).
- **Source:** `7343-7364 (scanner constructed 7343, handler 7351-7354, install loop 7356-7362, outer guard 7348/7363-7364)`

### Cancellation is a SUCCESS outcome, and returns early from run()

After scan_system returns, a cancel_requested run logs "Scan cancelled by operator" and returns a result line immediately — skipping upload_final_comprehensive_report, evidence collection, cleanup scheduling and the terminal "completed" status. Because the cancel branch returns before the completed branch, a cancelled scan never gets an evidence ZIP from run() (only the failed branch collects evidence explicitly). The terminal dataset row IS still written, from inside _perform_enhanced_cleanup with status=cancelled.

- **Control:** Not configurable — default `-`
- **Observe:** SCAN_RESULT "Scan cancelled by operator: N files scanned \| M matches found \| <posture>" (7399-7402); scan_summary_<run_id>.json "outcome":"cancelled"; NO evidence/evidence_<host>_<run_id>.zip and no "Evidence collection completed successfully" line (7485) in system_<run_id>.log; but a yara_scanner_scans_v3_* row with status=cancelled does exist (6748-6757).
- **Source:** `7397-7413 (log 7398, result line 7399-7402, return 7413); terminal row from _perform_enhanced_cleanup 6746-6757`

### Delivery-shortfall reporting on the cancelled path

A cancelled scan can still have lost findings in transit; the early return used to bypass the shortfall check entirely, so the one outcome where partial results matter most never told the operator anything failed to land. The counters are already settled here because _perform_enhanced_cleanup stops both uploaders before scan_system returns.

- **Control:** Not configurable — default `-`
- **Observe:** SCAN_RESULT gets " \| alerts: X of Y NOT delivered; dataset rows: N of M NOT confirmed (K unconfirmed) — findings are complete in the local logs on this endpoint" appended (7411); logs/scan_errors_<run_id>.log "DELIVERY INCOMPLETE - …" — note ASCII HYPHEN here (7412), unlike the em dash on the completed path (7547); scan_summary_<run_id>.json "delivery_shortfall" (7664).
- **Source:** `7405-7413 (shortfall computed 7409, append 7411, log 7412); _delivery_shortfall 7052-7092`

### running.json liveness marker — write, heartbeat refresh, removal

An atomically written (temp + os.replace) marker carrying scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections. Written once at scan start (from _start_cancellation_watcher), refreshed on each heartbeat, and removed in scan_system's finally after cleanup. All writes are swallowed by a bare except, so a read-only control dir silently disables cancel-liveness reporting without failing the scan. Only ever written with status="running" — the "finishing" phase is reported via ScanStatusUploader, not here.

- **Control:** Not configurable (path derives from control_dir 2734, marker path 5070) — default `<scanner_dir>/control/running.json`
- **Observe:** The file itself during a scan (updated_at advancing); its ABSENCE after a clean finish. A leftover running.json after the process exits means the run died before scan_system's finally reached 6946.
- **Source:** `_write_running_marker 5173-5195 (payload 5182-5192, os.replace 5193); _remove_running_marker 5197-5202; write call sites 5146 and 5260; removal 6946`

### CANCEL_DRAIN_DEADLINE_SECS — dead constant

**⚠ OBSERVABILITY GAP**  
A module-level, env-reachable knob documented as the "graceful cancel budget" that is defined and never read anywhere in the file. Setting YARA_CANCEL_DEADLINE_SECS on an endpoint changes nothing; the real post-cancel budgets are the uploader drain windows.

- **Control:** CANCEL_DRAIN_DEADLINE_SECS 312 (env YARA_CANCEL_DEADLINE_SECS) — DEAD, no reader — default `30`
- **Observe:** UNOBSERVABLE: no artefact changes when set. To confirm it is dead, grep the file for the symbol — line 312 is its only occurrence.
- **Source:** `312 (definition only)`

### Scan phase ordering in scan_system

Fixed sequence: record scan start (6771-6773) → start cancel watcher, which evicts a stale flag and writes running.json (6775) → start heartbeat thread (6777) → emit "initiated" lifecycle row (6778) → build resource monitor if enabled (6780-6782) → resolve targets (6799) → start N worker threads (6818-6821) → start progress-heartbeat thread (6829-6833) → walk targets enqueuing files → finally: _perform_enhanced_cleanup (6945) → remove running marker (6946) → _log_final_results (6947). Rule compilation happens EARLIER still, in YaraScanner.__init__, so a compile failure aborts before any lifecycle row is emitted.

- **Control:** Not configurable — default `-`
- **Observe:** yara_scanner_scans_v3_* dataset rows in order: initiated → running(heartbeat)… → completed/cancelled/failed; logs/system_<run_id>.log banner sequence "=== ENHANCED SYSTEM SCAN INITIATED ===" (6784) → "=== ACTIVE SCANNING PHASE STARTED ===" (6840) → "=== ENHANCED CLEANUP AND FINALIZATION ===" (6682).
- **Source:** `scan_system 6769-6947; rules compiled in YaraScanner.__init__ 5007`

### Scan-lifecycle rows in the yara_scanner_scans dataset

_emit_scan_row appends one row per lifecycle transition (initiated / running heartbeat / completed / cancelled / failed) with 22 fields including files_scanned, files_skipped, detections, scan_rate_fps, elapsed_secs, total_paused_secs, throttle_mode, posture and a free-text message. Counters are snapshotted under lock_counts and lock_throttle so the row is a consistent instant. The row is silently skipped entirely when write_dataset is off, or when the uploader object does not exist.

- **Control:** CONFIG_WRITE_DATASET 162 / options write_dataset; guard at 5206-5208 — default `CONFIG_WRITE_DATASET = True`
- **Observe:** XQL: dataset = yara_scanner_scans_v3_* filtered on run_id — rows with status initiated/running/completed/cancelled/failed. Row failures land in logs/scan_errors_<run_id>.log as "Failed to emit scan-lifecycle row: …" (5247).
- **Source:** `_emit_scan_row 5204-5247 (row dict 5220-5243, snapshots 5213-5218); scans_schema 3915-3938`

### Terminal lifecycle row emitted after workers drain but before uploaders stop

The terminal row's status is derived inside _perform_enhanced_cleanup — cancelled if cancel_requested, else failed if scan_failed, else completed — and is emitted AFTER the worker join (so counts are final) and BEFORE the uploaders are stopped (so it actually gets sent). The failed message is the first three failure_reasons joined, falling back to "scan failed" if the list is empty (6753).

- **Control:** Not configurable — default `-`
- **Observe:** yara_scanner_scans_v3_* row with status in {completed,cancelled,failed} and message "scan completed" / "cancelled by operator (source=…)" / the joined failure reasons.
- **Source:** `6746-6757 (status derivation 6748-6756, emit 6757); worker join loop above at 6708-6721 (performance log 6724-6726); uploader stop below at 6759-6763`

### Heartbeat lifecycle row and its independent thread

A dedicated HeartbeatWorker thread polls every HEARTBEAT_THREAD_POLL_SECS and calls _maybe_heartbeat, which emits a "running" row plus a running.json refresh at most once per SCANS_HEARTBEAT_SECS. The thread exists because _maybe_heartbeat used to be called ONLY from the directory-walker loop — a walker parked in _enqueue_scan_path's backpressure loop stalled the heartbeat past the quiet period the consolidation tooling uses to declare a scan abandoned. The check-and-set is under _heartbeat_lock so the walker and the thread cannot both emit a duplicate row. _last_heartbeat is seeded to scan start (6773) so the first heartbeat waits a full interval.

- **Control:** SCANS_HEARTBEAT_SECS 307 (env YARA_HEARTBEAT_SECS) gates emission; HEARTBEAT_THREAD_POLL_SECS 318 (env YARA_HEARTBEAT_POLL_SECS) is only the poll cadence — default `600s emission cadence; 30s poll`
- **Observe:** yara_scanner_scans_v3_* rows with status="running", message="heartbeat", ~600s apart; control/running.json updated_at advancing on the same cadence. Thread failures land in scan_errors_<run_id>.log as "Heartbeat worker error: …" (5285).
- **Source:** `_maybe_heartbeat 5249-5261 (gate 5257, marker write 5260, row 5261); _start_heartbeat_thread 5263-5278; _heartbeat_worker 5280-5286; _heartbeat_lock 5084; seed 6773; walker-side call 6916`

### Progress-heartbeat thread spanning the whole scan

A ProgressHeartbeat daemon thread calls _log_progress every config.log_interval for the entire scan, not just during file discovery. The inline-only version almost never fired — enumeration is fast while content matching in the workers is what takes minutes — and on the XSIAM twin zero "Scan Progress" events had ever been recorded on any host. The interval is clamped to >=1s because wait(0) would busy-spin and re-take lock_counts continuously. _log_progress also calls log_system_resources unconditionally (6550), so per-process CPU/memory telemetry lands even with resource monitoring disabled.

- **Control:** config.log_interval 2850 (env YARA_PROGRESS_LOG_SECS, clamped min 1) — default `30s`
- **Observe:** logs/statistics_<run_id>.log lines "Scan Progress \| Files: … \| Detections: … \| Queue: … \| Rate: … files/sec" (LogManager.log_scan_progress 2217, message 2229-2232) recurring every ~30s, plus "System Resources \| CPU: … \| Memory: … \| Disk I/O: … \| Network: …" lines in performance_<run_id>.log (LogManager.log_system_resources 2254, message 2264-2268). Heartbeat failures: scan_errors_<run_id>.log "Progress heartbeat error: …" (6678).
- **Source:** `_progress_heartbeat 6662-6678; _log_progress 6514-6596 (log_system_resources call 6550, log_scan_progress call 6586-6589); thread start 6829-6833; stop 6731-6734`

### Shutdown sequence in _perform_enhanced_cleanup

Ordered teardown: set status "finishing" (6683) → push one None sentinel per worker with a 1s put timeout each (6695-6699) → join each worker with a 5s timeout (6710) → stop the progress heartbeat (6731-6734) → stop resource/stats monitoring (6736-6740) → scan_active=False (6743) → emit terminal row (6757) → stop both uploaders with wait=True (6759-6763). The monitoring stop was deliberately moved AFTER the worker join: discovery finishing is not the workers finishing, and stopping the monitor early cut resource telemetry off for most of a large scan's real duration. Note cleanup_total_time is computed at 6744, i.e. BEFORE the terminal row and the uploader drain, so the "Enhanced cleanup completed in N.N seconds" figure excludes the drain that usually dominates it.

- **Control:** Not configurable (join timeout is a literal 5 at 6710, despite the log line at 6701 saying "max 30 seconds") — default `5s per worker join`
- **Observe:** logs/system_<run_id>.log "=== ENHANCED CLEANUP AND FINALIZATION ===" (6682) then "Enhanced cleanup completed in N.N seconds" (6767); logs/performance_<run_id>.log "Worker cleanup: X stopped, Y timed out in Z.Zs" (6725); scan_errors_<run_id>.log "Threads did not terminate: [...]" (6721) when a worker hangs.
- **Source:** `_perform_enhanced_cleanup 6680-6767`

### Worker-thread join timeout is non-fatal

A worker that does not finish within 5s is logged and abandoned — the scan continues to completion and still reports success. Because workers are daemon threads (6819), a stuck worker cannot block process exit either, so a file that hangs libyara produces a "completed" outcome with a quietly lower files_scanned.

- **Control:** Not configurable (literal timeout=5 at 6710) — default `5s`
- **Observe:** logs/scan_errors_<run_id>.log "Worker thread ScanWorker-N did not finish - continuing anyway" (6713) and "Threads did not terminate: [...]" (6721); performance_<run_id>.log "Worker cleanup: … timed out in …" (6725).
- **Source:** `6708-6725; daemon=True at 6819`

### Second, idempotent uploader stop in run()'s finally block

run()'s finally calls results_uploader.stop(wait=True) and lookup_uploader.stop(wait=True) again as a safety net after _perform_enhanced_cleanup already stopped them. Both stop() methods guard on a _stop_done flag and return immediately, so the safety net does not re-pay a full drain window (which could otherwise add minutes to every scan).

- **Control:** Not configurable; drain budgets: ALERT_DRAIN_SECS 115 / ALERT_DRAIN_MAX_SECS 116, LOOKUP_DRAIN_TIMEOUT 257 / LOOKUP_DRAIN_MAX_SECS 261 / LOOKUP_DRAIN_PER_BATCH_SECS 262 — default `alerts: min 60s, backlog-scaled, capped 300s; lookups: min 150s, 45s/batch, capped 600s`
- **Observe:** logs/uploads_<run_id>.log has exactly ONE "Alert delivery final: …" line (3596) and one "Lookup drain: …" line (4332) per run; scan_summary_<run_id>.json alert_delivery (7655) / dataset_delivery (7657) blocks.
- **Source:** `_stop_done init 3210 / guards 3534-3536; init 3880 / guards 4319-4321; finally-block calls 7609-7612`

### scan_summary_<run_id>.json — the machine-readable per-run record

Written in run()'s finally block AFTER both uploaders drain, so delivery counts are final. Atomic (temp + os.replace) with the temp removed on failure. Carries 33 fields: a 10-field base record (schema, run_id, scan_id, tenant_id, hostname, os_info, ip_address, matches_dataset, scans_dataset, posture) merged with 23 run fields (outcome, scan_folder, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, total_paused_secs, throttle_mode, cpu_governor, compile_source, compile_seconds, scanner_version, cancel_source, alert_delivery, dataset_delivery, delivery_shortfall, top_rules). It is written only when log_manager, config AND scanner are all non-None (7615).

- **Control:** Not configurable; path logs/scan_summary_<run_id>.json built at 2315 — default `schema "yara_scan_summary/v1" (2317)`
- **Observe:** The file <scanner_dir>/logs/scan_summary_<run_id>.json itself; logs/system_<run_id>.log "Scan summary written: scan_summary_<run_id>.json" (2334); on failure scan_errors_<run_id>.log "Failed to write scan summary JSON: …" (2342) and "scan summary write failed: …" (7713).
- **Source:** `write_scan_summary 2308-2343 (base record 2316-2327); call site 7615-7666 (dict literal 7632-7666)`

### Outcome derivation for the summary (cancelled > failed > completed)

outcome is derived by precedence in run()'s finally: cancel_requested → "cancelled"; else scan_failed → "failed"; else "completed". "completed" is the DEFAULT, which is why the critical-error handler explicitly sets scanner.scan_failed=True before returning — otherwise a crash produced a summary claiming success.

- **Control:** Not configurable — default `"completed"`
- **Observe:** scan_summary_<run_id>.json "outcome" (7633); cross-check against the terminal yara_scanner_scans_v3_* row status (derived independently at 6748-6756 — the two can disagree if the crash happened after cleanup).
- **Source:** `7617-7622; crash marks failed at 7596-7597`

### Duration fallback chain in the summary

duration_secs prefers scan_total_time (only set on the fully successful path, 7449), falls back to time.time() - scan_start_time, and is None if the run died before scan_start_time existed. So a summary with "duration_secs": null identifies a pre-scan failure (bad rules, bad scan folder; the placeholder-credential path aborts even earlier and writes no summary at all).

- **Control:** Not configurable — default `None`
- **Observe:** scan_summary_<run_id>.json "duration_secs" (7636) and "scan_rate_fps" (7644-7645, which is 0 when duration is None/0).
- **Source:** `fallback chain 7623-7625; duration_secs field 7636; scan_rate_fps 7644-7645; scan_total_time set at 7449`

### _delivery_shortfall — the single "did the findings land?" answer

Compares queued vs landed per channel: alerts (alerts_queued - successful_uploads) and dataset rows (queued - records_added - records_updated - records_skipped). It deliberately counts read-timeout batches (rows_unconfirmed) as NOT delivered because "the server may have committed them" is not evidence. Wrapped in two separate try/excepts so a missing uploader can never break the result line. On the completed path it is computed ONCE in the finally block (7631) and reused for the HostCleanup gate (7702), so the summary and the deletion decision can never disagree — but the cancelled path computes its own copy at 7409.

- **Control:** Gated per channel by config.create_alerts / config.write_dataset (constants 161-162) — default `"" when everything landed`
- **Observe:** scan_summary_<run_id>.json "delivery_shortfall" (7664; "" = clean); same text appended to SCAN_RESULT (7546); logs/scan_errors_<run_id>.log "DELIVERY INCOMPLETE — …" (7547, em dash).
- **Source:** `_delivery_shortfall 7052-7092 (dataset formula 7076-7078); single computation 7631; reuse 7702; separate cancel-path computation 7409`

### Success result line composition (skipped rules, excluded targets, cpu-slept, posture)

The completed result line is assembled from five deliberate additions: failed_rules_count, a "N rules skipped (module unavailable)" clause (skipped rules are not failures but did not run either, so a mostly-skipped pack no longer reads clean), total matches, governor sleep seconds, the posture string, and a WARNING naming up to 3 requested targets the skip list excluded wholesale — because "0 files scanned" is otherwise indistinguishable from an empty directory.

- **Control:** Not configurable — default `-`
- **Observe:** SCAN_RESULT text: "Scan completed: N files scanned \| X rules failed compilation \| Y rules skipped (module unavailable) \| Z matches found \| cpu-slept Ns \| <posture> \| WARNING: K requested target(s) EXCLUDED by the skip list, nothing under them was scanned: …"; the same excluded list in scan_summary_<run_id>.json "excluded_targets" (7635).
- **Source:** `_skipped 7512-7513; _excluded 7518-7524; summary string 7533-7536; shortfall append 7544-7547; excluded_targets recorded at 6860-6866, initialised 5045`

### Excluded-target detection at two different layers

A requested target that matches the skip list is flagged twice: at config time (a warning naming each folder and the skip fragment that excludes it, plus a louder "EVERY requested scan folder is excluded" line when nothing survives) and again at walk time via scanner.excluded_targets, which is what reaches the result line and the summary. The two use DIFFERENT tests — config time prefix-matches config.skip_paths (3018-3023), walk time calls _is_special_file(target) (6860) — so they can disagree; the walk-time list is the one a tool should read.

- **Control:** Platform skip lists: win_skip_folder 2910-2925, lin_skip_directory 2928-2939, mac_skip_directory 2942-2976; skip_paths set at 2925 / 2939 / 2976 (empty at 2981 on other platforms) — default `-`
- **Observe:** scan_summary_<run_id>.json "excluded_targets" array (7635); logs/yara_processing_<run_id>.log "N of M scan folder(s) sit under a platform skip-path and will yield no files: …" (3026-3028) / "EVERY requested scan folder is excluded by the platform skip-list…" (3030-3033); logs/scan_errors_<run_id>.log "Requested scan target is excluded by the skip list, so nothing under it will be scanned: …" (6862-6866).
- **Source:** `config-time 3016-3033; walk-time 6860-6866`

### Fatal-failure path — status, evidence, and result line

When scan_failed is set, run() logs a failure_data block (first 20 reasons), best-effort emits status "failed", best-effort collects evidence, and returns a "Scan failed: …" line. Evidence collection on this path was added because a scan that FOUND matches and then died produced no ZIP at all (verified live: 1 match, alert text written, 0 zips) even though the alert texts and file_mapping are exactly what a responder needs from a partial run. Neither best-effort step can change the returned line.

- **Control:** Not configurable — default `-`
- **Observe:** evidence/evidence_<hostname>_<run_id>.zip exists after a failed run; logs/system_<run_id>.log "Evidence collected from failed scan" (7438) or scan_errors "Evidence collection failed after fatal failure: …" (7440); scan_errors_<run_id>.log "Scan stopped due to fatal failures" (7423) with the failure_reasons array; SCAN_RESULT "Scan failed: N files scanned \| X rules failed compilation \| Y matches found \| Fatal failures: N" (7442-7446).
- **Source:** `7415-7446 (failure_data 7416-7422, log 7423, status 7432-7435, evidence 7436-7440, result 7442-7446)`

### _mark_scan_failed — the only way scan_failed becomes true mid-scan

Sets scan_failed, appends a reason under lock_failures, and drops scan_active — which also terminates the walker, the workers and the heartbeat thread. It has exactly two callers: a worker's outer fatal handler (5921) and the scan_system target-loop's critical exception handler (6938). Per-file scan errors do NOT reach it; they become skip_reasons entries instead. run()'s KeyboardInterrupt (7388) and critical-error (7597) handlers set scan_failed directly, bypassing this method, so failure_reasons and scan_active are handled separately there.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json "outcome":"failed"; logs/scan_errors_<run_id>.log "SCAN FAILED \| Time: … \| Files: … \| Detections: … \| Rate: …" (message built 6613-6619, logged with failure_reasons 6621-6624); terminal yara_scanner_scans_v3_* row status=failed with the joined reasons as message (6752-6757).
- **Source:** `_mark_scan_failed 5103-5108; callers 5921 and 6938; direct scan_failed sets bypassing it at 7388 and 7597`

### Per-file error classification with a BOUNDED skip-reason key

scan_file returns (False, reason) for every non-scan; the exception branch runs the exception through _scan_error_reason, which returns "Scan error (<ExceptionType>)". Returning str(exc) made every errored file its own aggregate key because both common messages embed the absolute path — measured at 307,780 bytes of skip_reasons for 5,000 errored files, shipped to the tenant. The specific message and path are still logged per file. "error" stays in the label because the final report counts error reasons by that substring (7466-7467).

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json has no skip breakdown, but logs/statistics_<run_id>.log "Skip reasons: …" with skip_breakdown data (6641-6646), and the COMPREHENSIVE SCAN REPORT's file_processing.skip_breakdown — keys should read "Scan error (OSError)" etc., never a path. Per-file detail in scan_errors_<run_id>.log "Error scanning file <path>: …" (6224-6227).
- **Source:** `_scan_error_reason 1236-1251; call at 6228; other reasons 6101, 6127, 6130, 6136, 6140, 6144; aggregation in _worker 5893-5896`

### Worker error tiers — per-file error vs fatal worker error

Inside the queue loop, an exception whose text is non-empty and does not contain "Empty" is counted, logged to stderr and scan_errors, and the loop CONTINUES. Only an exception escaping the whole while-loop calls _mark_scan_failed and kills the scan. Every worker also logs a stop record with files_processed, errors_encountered and average processing time in its finally block, so the record appears even for a fatally-failed worker.

- **Control:** Not configurable (queue get timeout is a literal 5.0 at 5882 — the module constant WORKER_GET_TIMEOUT_SECS at 132 has no reader anywhere) — default `-`
- **Observe:** logs/scan_errors_<run_id>.log "Worker ScanWorker-N error: <Type>: <msg>" (5914, non-fatal) vs "Worker ScanWorker-N fatal error: …" (5919-5920); logs/system_<run_id>.log "Worker ScanWorker-N started" (5877) and "Worker ScanWorker-N stopped" (5927-5934) with its counters.
- **Source:** `_worker 5871-5934 (non-fatal branch 5909-5916 with stderr at 5913 and log at 5914, fatal branch 5918-5921, finally 5922-5934)`

### KeyboardInterrupt during the scan is a FAILURE, not a cancel

Ctrl+C raised out of scan_system is caught separately and sets scan_active=False (7387), scan_failed=True (7388) with reason "Scan interrupted by user" (7389) plus status "interrupted" (7390) — it does NOT set cancel_requested. So an interactive interrupt produces outcome="failed", takes the failed branch (evidence collected, "Scan failed:" result line, exit 1), unlike a flag-based or SIGINT-handled cancel. The installed SIGINT handler normally converts Ctrl+C into the cancel path first, so this branch only fires when handler installation failed or the interrupt lands where the handler cannot.

- **Control:** Not configurable — default `-`
- **Observe:** scan_summary_<run_id>.json "outcome":"failed" with "cancel_source":null (7654); logs/system_<run_id>.log "Scan interrupted by user (Ctrl+C)" (7386); SCAN_RESULT "Scan failed: …"; exit 1.
- **Source:** `7385-7390; signal handler 7351-7354`

### Critical-error handler — stderr/stdout dump, 2-second sleep, and marker

Any exception escaping the whole run() body (i.e. from inside the try at 7163) writes the message, type and full traceback to BOTH stderr (with a literal "SCAN_STATUS: ERROR" marker line) and stdout, sleeps 2 seconds (to let the agent's output collector flush), logs to log_manager if it exists, sets error_logger.has_errors, records the exception via ExceptionLogger, sets scanner.scan_failed so the finally block derives outcome="failed", and returns a "Scan failed: …\| Critical error occurred" line. It guards on `scanner is not None` rather than `'scanner' in locals()` because the latter is always true (scanner is initialised to None at 7161). Each of log_manager / config.error_logger / exception_logger is separately guarded, so an early failure produces far fewer artefacts than a late one.

- **Control:** Not configurable — default `-`
- **Observe:** stderr containing "YARA Scanner Critical Error:" (7553), "Error Type:" (7554), "SCAN_STATUS: ERROR" (7556); logs/script_exceptions_<run_id>.log with context main_function_critical_error — ONLY if the failure happened after exception_logger was assigned at 7208; scan_errors_<run_id>.log "CRITICAL_ERROR: …" (7567) only if log_manager exists (assigned 7180); yara_processing_<run_id>.log "CRITICAL_ERROR: …" (7574); scan_summary_<run_id>.json "outcome":"failed" only if scanner exists.
- **Source:** `7550-7603 (stderr 7553-7557, stdout 7559-7562, sleep 7564, log_manager 7566-7570, error_logger 7572-7574, exception_logger 7576-7581, scan_failed 7596-7597, return 7599-7603)`

### Rule-decode failure aborts before any scanning

decode_yara_rules rejects input >50 MB, empty input, base64 that will not decode, and decoded text containing no `rule` declaration — each raising ValueError out of ScanConfig.__init__, which surfaces as run()'s critical-error path. This is the earliest failure that still produces a log file, because ErrorLogger is constructed at 2747, before rule decoding at 2795-2807. But log_manager (7180) and exception_logger (7208) do not exist yet, so yara_processing is the ONLY log written — no scan_errors, no script_exceptions, no summary.

- **Control:** Size cap literal 50_000_000 at 430 (not configurable) — default `-`
- **Observe:** logs/yara_processing_<run_id>.log with INPUT_ERROR (437) / DECODE_ERROR (446) / VALIDATION_ERROR (455 sets has_errors; the message is logged in the same branch) and "CRITICAL: Failed to decode YARA rules: …" (2806); stderr "YARA Scanner Critical Error: Critical scanner error: …"; SCAN_RESULT "Scan failed: 0 files scanned \| 0 rules failed compilation \| 0 matches found \| Critical error occurred".
- **Source:** `decode_yara_rules 416-458; _b64_to_text 399-413; ScanConfig call 2795-2807; ErrorLogger constructed 2747`

### Invalid scan_folder handling — per-entry validation, whole-run abort only if nothing is valid

scan_folder accepts a comma-separated list; each entry is stripped of surrounding quotes and validated with os.path.isdir independently, duplicates are collapsed via abspath, invalid entries are logged as a warning and dropped, and only an entirely invalid list raises ValueError (killing the run). Deliberate: a typo in one folder of a scheduled multi-target scan must not kill the run, but it must be loud.

- **Control:** Not configurable — default `scan_folder None/"default" → platform target discovery (3038-3043)`
- **Observe:** logs/yara_processing_<run_id>.log "Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]" (3009-3011) and "Scan limited to N folder(s): [...]" (3036-3037); total failure produces SCAN_RESULT "Scan failed: … Critical error occurred" and NO scan_summary at all (scanner is still None at the 7615 guard).
- **Source:** `2987-3037 (requested split 2995, validation 2996-3004, all-invalid raise 3005-3007, warning 3008-3011)`

### Rule-compilation failure classification (split / none-found / all-failed / all-skipped / combined)

Five distinct fatal compile outcomes, each with its own message: split failure (SPLIT_ERROR), no rules extracted (COMPILATION_ERROR, plus the raw content dumped to failed_rules/raw_yara_content.yar), all rules failed ("No valid YARA rules could be compiled out of N rules."), the important distinction of all rules SKIPPED for missing libyara modules ("This is an agent capability limit, not a rule syntax error."), and a final combined-compile failure (COMBINED_COMPILATION_ERROR) if yara.compile(sources=…) itself fails after every individual rule passed. All raise out of YaraScanner.__init__ into run()'s critical handler.

- **Control:** Not configurable; module detection MODULE_USAGE_PATTERNS 930-939 — default `-`
- **Observe:** logs/yara_processing_<run_id>.log lines SPLIT_ERROR (5622) / COMPILATION_ERROR (5628) / FINAL_COMPILATION_ERROR (5771) / COMBINED_COMPILATION_ERROR (5791); stderr "CRITICAL: YARA rule compilation failed: …" (5772) plus "Valid rules: X, Failed rules: Y, Skipped: Z" (5773); failed_rules/raw_yara_content.yar on the none-found path (5630).
- **Source:** `split 5617-5623; none-found 5625-5638; all-failed / all-skipped 5757-5775; combined 5789-5792`

### Per-rule compile artefacts written to failed_rules/

Each rule that cannot compile is saved as failed_rules/failed_rule_<name>.yar with the error text, date and the preamble prepended; each rule skipped for an unavailable module is saved as failed_rules/skipped_rule_<name>_<module>.yar — from TWO separate branches: a pre-compile module scan (5664-5674) and a post-compile-error module inference for imports inherited from a stripped preamble (5711-5723). All writes are wrapped in bare try/except so a read-only directory never affects the scan. Only the first 10 of each kind are also logged (5729-5730).

- **Control:** failed_rules_dir 2742 (fixed <scanner_dir>/failed_rules, created 2744-2745) — default `-`
- **Observe:** Files under <scanner_dir>/failed_rules/ — failed_rule_*.yar and skipped_rule_*_<module>.yar; counts in scan_summary_<run_id>.json "failed_rules" (7641) / "skipped_rules" (7643); "Failed rules saved to: <dir>" in yara_processing_<run_id>.log (1687).
- **Source:** `skipped (pre-compile) 5664-5674; skipped (inherited import) 5711-5723; failed 5732-5746; skipped_rules_count persisted 5748; compilation summary 5749`

### Rule-cache hit restores counts from a sidecar (and validates before trusting)

On a cache hit the whole per-rule loop is skipped, so valid/failed/skipped counts would read 0 — a .meta.json sidecar restores them, with a fallback that counts the loaded yara.Rules object if the sidecar is missing or broken. The cache is also proved usable before acceptance: the bundle must load AND accept a zero-byte match with the per-file externals (5573), so a cross-version or corrupt bundle fails here and falls back to a fresh compile instead of dying mid-scan. On any load failure the cache file and sidecar are deleted (5590-5595). A hit also touches the file's mtime for LRU (5575).

- **Control:** RULE_CACHE_ENABLED 297 (env YARA_RULE_CACHE), RULE_CACHE_FORMAT 298, RULE_CACHE_MAX_FILES 299, RULE_CACHE_MAX_BYTES 300; cache dir <scanner_dir>/rule_cache (5458-5461) — default `enabled; format "1"; 5 files / 256 MB`
- **Observe:** scan_summary_<run_id>.json "compile_source":"cache"\|"fresh" (7651) and "compile_seconds" (7652); logs/system_<run_id>.log "Rule cache HIT rules_<key>.yarac load=N.NNs (valid=… failed=… skipped=…)" (5581-5585) or "Rule cache miss/unusable, compiling fresh: …" (5588-5589) or "Rule compile FRESH N.NNs" (5599); files under <scanner_dir>/rule_cache/ (rules_*.yarac + .meta.json).
- **Source:** `_load_or_compile_rules 5559-5600 (cache branch gated at 5565); _restore_cache_meta 5478-5497; _save_rule_cache 5499-5525; _prune_rule_cache 5527-5557; _rule_cache_dir 5458-5461`

### setup_logging strips the root logger — every logging.info in the file is dead

**⚠ OBSERVABILITY GAP**  
setup_logging closes and removes ALL root handlers and pins the level to WARNING. Because no handler is left, WARNING/ERROR records fall through to Python's lastResort handler and still reach stderr, but every logging.info() call in the module — including the entire CleanupManager status trail and host-cleanup's success line — produces nothing on any host. Structured logging must go through LogManager (which owns its own per-category FileHandlers, _setup_logger 2131-2155 with propagate=False at 2155) or ErrorLogger (whose yara_processing handler is set to INFO with propagate=False, so ITS info calls do survive).

- **Control:** Not configurable — default `root level WARNING, zero handlers`
- **Observe:** UNOBSERVABLE for root-logger info-level calls: nothing is written anywhere. To observe those code paths, use the LogManager files (system_/scan_errors_/statistics_<run_id>.log), the ErrorLogger file (yara_processing_<run_id>.log), or the on-disk side effects; only logging.warning/error text appears, on stderr.
- **Source:** `setup_logging 6954-6968; called at 7290; ErrorLogger's independent INFO FileHandler 1502-1528; LogManager._setup_logger 2131-2155`

### ScanStatusUploader.set_status — a lifecycle state machine that emits nothing

**⚠ OBSERVABILITY GAP**  
set_status is called at NINE sites covering eight distinct statuses (initializing, starting_workers, scanning, finishing, error ×2, interrupted, failed, completed) but only assigns a field and calls logging.info. Its consumer, upload_scan_status, is gated behind UPLOAD_NON_MATCH_DATA (hardcoded False) and is never called anywhere in the file. The entire status channel is therefore dormant — the observable lifecycle is the yara_scanner_scans dataset rows, not this.

- **Control:** UPLOAD_RESULTS 104 / UPLOAD_NON_MATCH_DATA 105 (both module literals, not env-reachable); gate at 4395 — default `UPLOAD_NON_MATCH_DATA = False`
- **Observe:** UNOBSERVABLE: set_status only calls logging.info (4455), which setup_logging silences. To observe scan phase, read the yara_scanner_scans_v3_* dataset rows or the "===" banners in logs/system_<run_id>.log. To make it observable one would need UPLOAD_NON_MATCH_DATA=True and an actual call to upload_scan_status.
- **Source:** `set_status 4452-4455; upload_scan_status 4393-4450 (no callers — verified by grep); call sites 6683, 6797, 6815, 6839, 6939, 7390, 7393, 7433, 7529`

### ResultsUploader.upload_results — dead finalisation path

**⚠ OBSERVABILITY GAP**  
A complete second shutdown/drain implementation (flat ALERT_DRAIN_SECS wait, sentinel, join, upload-statistics logging) that is never invoked; the live path is stop(). Its own docstring elsewhere notes that save_results()'s only caller was this method, which is why the per-offset in-memory accumulation (measured ~15 GB RSS on one endpoint) was pure waste and got removed.

- **Control:** ALERT_DRAIN_SECS 115 (env YARA_ALERT_DRAIN_SECS) — read at 3755 but this reader never runs — default `60s`
- **Observe:** UNOBSERVABLE: it never executes, so "FINALIZING UPLOAD PROCESS" (3748-3749) / "UPLOAD STATISTICS" (3788) never appear in uploads_<run_id>.log. Their absence, alongside the present "Alert delivery final: …" line (3596), confirms stop() is the live path.
- **Source:** `upload_results 3746-3801 (no callers — verified by grep); live path stop() 3530-3607; dead-accumulation note 3168-3175`

### CircuitBreaker class — defined, never instantiated

**⚠ OBSERVABILITY GAP**  
A full closed/open/half_open breaker with a failure threshold and reset timeout, plus two module constants configuring it, exists in the file and is never constructed anywhere. Upload resilience is actually handled by per-batch retry counts (MAX_RETRIES_PER_ITEM 107, LOOKUP_ADD_DATA_MAX_RETRIES 256), requeue budgets and backoff helpers instead.

- **Control:** CIRCUIT_FAILURE_THRESHOLD 130, CIRCUIT_RESET_TIMEOUT_SECS 131 — both bare literals, consumed only by this unused class's default arguments (1423) — default `5 failures / 40s`
- **Observe:** UNOBSERVABLE: no artefact. Confirmed by grep — the only occurrence of the name besides the class statement is its own __init__ default line; there is no `CircuitBreaker(` construction.
- **Source:** `CircuitBreaker 1420-1457; constants 130-131`

### Dead/unused lifecycle constants and config attributes

Several knobs are set and never read: WORKER_GET_TIMEOUT_SECS (the worker uses a literal 5.0 at 5882), config.batch_size=1000 (LookupDatasetUploader has its own unrelated self.batch_size at 3865), config.performance_log_interval=120, config.statistics_upload_interval=60, config.light_profile=True, and config.track_real_paths=False — the last of which permanently disables the junction/symlink duplicate-suppression code in scan_file, so "Junction/symlink duplicate" can never appear as a skip reason and unique_real_paths is always 0. (The separate "Junction/symlink skip" reason at 6900 IS live — do not confuse the two.)

- **Control:** WORKER_GET_TIMEOUT_SECS 132; batch_size 2983; performance_log_interval 2984; statistics_upload_interval 2985; light_profile 2693; track_real_paths 2860 — none env-reachable — default `as listed above`
- **Observe:** For track_real_paths: logs/statistics_<run_id>.log "Skip reasons: …" never contains "Junction/symlink duplicate", and the Scan Progress metrics show 'unique_real_paths': 0 throughout (set at 6583). The rest are UNOBSERVABLE — no reader exists (verified by grep).
- **Source:** `132, 2693, 2860, 2983-2985; dormant reads at 6133-6136 and 6146-6148`

### Unreachable branches: ScanConfig mode=cancel and _discover_all_targets

**⚠ OBSERVABILITY GAP**  
Two dead branches. ScanConfig validates and stores mode=="cancel" (2699-2701), but run() short-circuits to _handle_cancel_request at 7154 before ever constructing a ScanConfig, so the branch can only be reached by importing the class directly. Separately, ScanConfig.__init__'s default-target fallback checks hasattr(self, "_discover_all_targets") — a method that does not exist anywhere in this file — so the check is always False and _default_discover_targets always runs. This hasattr lives in ScanConfig, NOT in YaraScanner._get_scan_targets (6500-6512), whose own fallback is a different, live code path.

- **Control:** Not configurable — default `-`
- **Observe:** UNOBSERVABLE (unreachable). For the target branch, logs/yara_processing_<run_id>.log always shows "Scanning default targets: [...]" (3043) produced via _default_discover_targets (3042).
- **Source:** `ScanConfig mode 2699-2701; hasattr check 3039-3042 inside ScanConfig.__init__; _default_discover_targets 3045; unrelated YaraScanner._get_scan_targets 6500-6512`

### logs/scanner_<run_id>.log — declared, cleaned, self-excluded, never written

config.output_log names a per-run log file that nothing ever writes to. It is only referenced by initial_cleanup (which deletes it at 4649 and recreates its parent directory at 4667) and by _is_special_file (which excludes it from scanning, 6251-6253). An operator looking for "the scanner log" by that name will always find it missing.

- **Control:** output_log 2823 (fixed name, not configurable) — default `<scanner_dir>/logs/scanner_<run_id>.log`
- **Observe:** The file never exists after a run — the real per-run logs are alerts_/statistics_/scan_errors_/performance_/uploads_/system_<run_id>.log (LogManager) plus yara_processing_<run_id>.log (ErrorLogger) and scan_summary_<run_id>.json.
- **Source:** `2823; referenced only at 4649, 4667, 6251, 6253 (grep for output_log returns exactly these five lines)`

### upload_final_comprehensive_report and the efficiency score

On the successful path only, a large nested report (scan_metadata, file_processing with skip_breakdown, detection_results with top_10_rules, rule_compilation with success rate, system_info, plus performance_summary always and resource_summary only when a resource_monitor exists) is assembled and written to the statistics log with a heuristic efficiency score = 100 - skip_rate*20 - rule_failure_rate*30. Despite the name it uploads nothing — it is a local log entry. The floor at 0 is applied only to the report's efficiency_score FIELD (7036); the log line's own number (7040) is un-floored and can read negative.

- **Control:** Not configurable — default `score starts at 100 (7027)`
- **Observe:** logs/statistics_<run_id>.log line "COMPREHENSIVE SCAN REPORT \| Efficiency Score: NN.N/100" (7039-7042) with the full report as its JSON data blob. On failure, scan_errors_<run_id>.log "Error generating comprehensive final report: …" (7048). Not produced on the cancelled or failed paths (both return before 7476).
- **Source:** `upload_final_comprehensive_report 6971-7049; performance_summary 7019-7021; resource_summary 7023-7025; score 7027-7036; called 7476`

### _log_final_results — terminal statistics record and its failure variant

Always runs in scan_system's finally (even after a cancel or fatal failure). Emits either a "SCAN COMPLETED" statistics record or, when scan_failed, a "SCAN FAILED" ERROR record carrying the full failure_reasons list, plus a top-10 detection-rules record (only when total_detections > 0, gated at 6628), a skip-reason breakdown (only when files_skipped > 0, gated at 6640), and an unconditional per-worker performance summary.

- **Control:** Not configurable — default `-`
- **Observe:** logs/statistics_<run_id>.log "SCAN COMPLETED \| Time: … \| Files: … \| Detections: … \| Rate: … files/sec" (message 6613-6619, logged 6626) OR logs/scan_errors_<run_id>.log "SCAN FAILED \| …" with failure_reasons (6621-6624); "Top detection rules: …" in alerts_<run_id>.log (6632-6638); "Skip reasons: …" in statistics_<run_id>.log (6642-6646); "Worker performance summary: N workers processed files" in performance_<run_id>.log (6657-6660).
- **Source:** `_log_final_results 6598-6660; call 6947`

### Log retention across runs (keep last N scans) plus orphan-temp sweep

initial_cleanup prunes logs_dir to the newest LOG_KEEP_SCANS run_ids (always keeping the current run, 4614), matching both .log and .json summaries by the run_id embedded in the filename via a strict regex. It also sweeps orphaned scan_summary_*.tmp files left by a process that died mid-atomic-write — safe here because it runs at scan START, before this run writes its own temp. The old default of 2 wiped diagnostics too aggressively under frequent scans.

- **Control:** LOG_KEEP_SCANS 310 (env YARA_LOG_KEEP, minimum 0 but floored to 1 at 4611) — default `10 scans`
- **Observe:** Count of distinct run_ids present in <scanner_dir>/logs/ after a scan; the "Log retention applied…" line (4634-4637) uses logging.info and is silenced, but failures surface as logging.warning on stderr: "Cannot remove log file (in use): <path>" (4629), "Cannot remove log file <path>: <e>" (4632), "Log retention: N log files could not be removed" (4639).
- **Source:** `_prune_old_scan_logs 4585-4639; called 4670; run_id regex 4580-4583; tmp sweep 4593-4599`

### initial_cleanup — previous run's alert/evidence wiped at scan start

Before scanning, alert_dir and evidence_dir are removed wholesale (plus the never-written output_log), then recreated empty along with logs_dir. A PermissionError on any path is logged and the scan continues — deliberately, since cleanup failure must not block a scan. This is why alert/ and evidence/ hold only the CURRENT run's data and cannot be relied on as history. failed_rules/ is NOT wiped here, so it accumulates across runs until HostCleanup or a fresh compile overwrites entries.

- **Control:** Not configurable; paths alert_dir 2740 / evidence_dir 2741 / output_log 2823 — default `always runs (called unconditionally in scan mode at 7212)`
- **Observe:** alert/ and evidence/ empty at the start of a run; logs/system_<run_id>.log "Initial cleanup completed" (7213 — this comes from run(), NOT from initial_cleanup, whose own "Initial cleanup completed successfully" at 4675 is logging.info and silenced); stderr warnings "Cannot remove <path> - may be in use" (4661 branch) when a file is locked.
- **Source:** `initial_cleanup 4641-4679; called 7212-7213`

### schedule_final_cleanup gating (critical errors / error ratio / no alerts)

The post-run .txt→.alert rename task is scheduled only if none of three gates trip: error_logger.has_errors with zero valid rules; an error-log ratio above 50% of all log records; or no .txt files in alert_dir. The second gate reads config.log_manager — an attribute never assigned anywhere on ScanConfig — so hasattr is always False and the error-ratio gate is completely dead. The same dead attribute also kills every self.config.log_manager.log_system() status line inside this method. run() applies the first gate again itself before calling.

- **Control:** Not configurable (0.5 ratio literal at 4692) — default `-`
- **Observe:** logs/system_<run_id>.log "Cleanup task/service scheduled successfully" (7494) or "Cleanup skipped due to critical YARA processing errors" (7496) — BOTH from run(), which is the only observable pair; presence of <scanner_dir>/cleanup_script.bat\|.sh. UNOBSERVABLE: "No alerts found, skipping cleanup scheduling" (4706) and the per-platform "…cleanup task scheduled successfully" lines (4719/4723/4727) all route through the never-assigned config.log_manager, and their logging.info twins are silenced — the only proof of the no-alerts path is the ABSENCE of cleanup_script plus an empty alert/ dir.
- **Source:** `schedule_final_cleanup 4681-4732; _check_for_alerts 4735-4737; run()-side gate 7489-7498`

### Cleanup script generated from the real alert dir (path-drift fix)

The rename script is generated at runtime from config.alert_dir instead of the old hardcoded base64 blobs, which targeted c:\xdr-data\alert / /opt/xdr-data/alert and therefore renamed nothing on any real deployment. Windows gets a .bat with `cd /d "<alert_dir>"` + `ren *.txt *.alert`; POSIX gets a bash loop, chmod 755'd at 4745-4746.

- **Control:** Not configurable; cleanup_script path 2819-2821 (cleanup_script.bat on Windows, cleanup_script.sh otherwise) — default `<scanner_dir>/cleanup_script.bat (Windows) or <scanner_dir>/cleanup_script.sh`
- **Observe:** Read <scanner_dir>/cleanup_script.bat\|.sh and confirm the cd path equals <scanner_dir>/alert; after the scheduled task fires, alert/*.txt become alert/*.alert.
- **Source:** `_decode_cleanup_script 4739-4746; _get_cleanup_script_content 4748-4771 (Windows branch 4757-4763, POSIX branch 4764-4771)`

### Platform-specific cleanup scheduling and its non-fatal failure modes

Windows creates a one-shot schtasks entry named CleanupScript running as SYSTEM one minute out; Linux writes /etc/systemd/system/yara-cleanup.service (verifying it exists and is root-owned) then daemon-reload/enable/start; macOS writes and launchctl-loads /Library/LaunchDaemons/com.yarascanner.cleanup.plist — added because the old code wrote a systemd unit on Darwin and threw on every scan. Missing systemctl/launchctl or a non-root user is logged and skipped ("cosmetic only"), never fatal. Only the Windows branch re-raises (4789-4790); Linux/macOS CalledProcessError is logged and swallowed, so schedule_final_cleanup's own re-raise path (4732) can only ever fire on Windows.

- **Control:** Not configurable — default `-`
- **Observe:** Windows: `schtasks /query /tn CleanupScript`. Linux: /etc/systemd/system/yara-cleanup.service. macOS: /Library/LaunchDaemons/com.yarascanner.cleanup.plist. Failures appear on stderr via logging.warning/error ("Linux cleanup scheduling requires root - skipping (cosmetic only)" 4830, "macOS cleanup scheduling requires root…" 4861, "launchctl not found - skipping macOS cleanup scheduling" 4863); run() also logs "Error scheduling cleanup: …" to scan_errors_<run_id>.log (7498).
- **Source:** `_schedule_windows_cleanup 4773-4790; _schedule_linux_cleanup 4792-4832; _schedule_macos_cleanup 4834-4865`

### End-of-run host cleanup — opt-in deletion of this run's working files

Runs once, in run()'s finally, ONLY when outcome=="completed" (7694) — a crash's delivery accounting is untrustworthy and a cancelled run's partial output is exactly what an operator would want to inspect. Three modes: off (default), on_delivery (requires an empty delivery_shortfall AND at least one delivery channel enabled), always. Three keep tiers control what survives. rule_cache is never touched, and OTHER runs' retained logs (LOG_KEEP_SCANS history) are never touched either — selection is by this run's run_id only (4960).

- **Control:** CONFIG_HOST_CLEANUP 238 and CONFIG_HOST_CLEANUP_KEEP 239 — deliberately NOT reachable via the options string (rejected as unknown keys by 825-828) — default `"off" / "summary"`
- **Observe:** Which files remain under <scanner_dir> after a completed run: with keep=summary, this run's logs/*_<run_id>.log are gone, logs/scan_summary_<run_id>.json survives, other runs' retained logs survive, and alert/, evidence/, failed_rules/ are recreated EMPTY (4978-4982). Errors surface on stderr via logging.warning "host cleanup could not remove …" (4985, log=logging.warning passed at 7704) / "Host cleanup failed: …" (7711); the success count uses logging.info (7705-7707) and is UNOBSERVABLE.
- **Source:** `HostCleanup 4868-4986; should_run 4890-4912; run 4914-4986 (this-run log selection 4956-4961, dir wipes 4967-4970, keep=nothing 4972-4973); call site 7693-7711`

### Host cleanup refuses to run without a durable summary, and when there is no delivery channel

Three safety gates, not two. run() returns immediately unless summary_path is an existing file (4928) — the audit record that the run happened; a missing summary means the run cannot be attested, so nothing is deleted. on_delivery with BOTH create_alerts and write_dataset off is refused (4901-4909), because an empty shortfall would then mean "nothing was ever attempted", not "everything landed". And an unrecognised CONFIG_HOST_CLEANUP value is treated as off rather than guessed (4896-4898).

- **Control:** Same as host cleanup (CONFIG_HOST_CLEANUP 238, CONFIG_HOST_CLEANUP_KEEP 239) — default `-`
- **Observe:** Rewrite the Observe field as: "OBSERVABLE in logs/diagnostics_<run_id>.log - the skip reason is emitted by logging.info('Host cleanup skipped: %s' % _reason) at line 7887, and root INFO is file-backed by setup_logging (7113-7121). grep diagnostics_<run_id>.log for 'Host cleanup skipped:' to get should_run's exact refusal (4987 off / 4989-4990 unknown value / 5000-5001 no delivery channel / 5003 delivery incomplete). Note the line is emitted only when CONFIG_HOST_CLEANUP != 'off' (elif at 7886), and that the affirmative counterpart 'Host cleanup removed N path(s)' (7883-7885) is NOT reliably readable on POSIX because HostCleanup.run has already unlinked diagnostics_<run_id>.log itself (5050-5053 matching the run_id regex at 4681) - for the affirmative case, use the surviving scan_summary JSON plus the presence/absence of artefacts under <scanner_dir>."
- **Source:** `should_run 4890-4912 (off gate 4894-4895, unknown-value 4896-4898, always 4899-4900, no-channel 4901-4909, shortfall 4910-4911); summary-existence check 4927-4929; caller 7699-7709`

### Log handlers closed BEFORE host cleanup because Windows refuses to delete open files

Immediately before HostCleanup runs, log_manager.stop_logging() (7695-7696) AND config.error_logger.close() (7697-7698) are called. LogManager holds six per-category FileHandlers and ErrorLogger separately holds yara_processing — which nothing in the codebase had ever closed before ErrorLogger.close() was added. POSIX allows unlinking an open file; Windows fails with WinError 32 and HostCleanup silently records it in its errors list. Verified in two rounds on a real Windows agent: closing only LogManager's handlers fixed six of the seven files. Consequently host cleanup's own messages must use the plain logging module — LogManager is already shut down.

- **Control:** Not configurable — default `-`
- **Observe:** On Windows with CONFIG_HOST_CLEANUP on: absence of logs/*_<run_id>.log INCLUDING yara_processing_<run_id>.log afterwards. If the ordering regressed, the leftover file plus a stderr "host cleanup could not remove …[WinError 32]…" (4985) is the signature.
- **Source:** `7694-7698; ErrorLogger.close 1541-1555; LogManager.stop_logging 2345-2356`

### stop_logging idempotence and the final logging summary

stop_logging guards on a _stopped flag (2347-2349), writes a "Logging Summary \| Total Logs: N" record with per-category counts and the file paths, then closes and removes every handler. It is called from up to three places per run (host-cleanup pre-step at 7696, the unconditional finally call at 7715, and __del__ at 2358-2363), so the guard is what prevents a second summary line and a double close.

- **Control:** Not configurable — default `-`
- **Observe:** logs/system_<run_id>.log final line "Logging Summary \| Total Logs: N" (2304-2306) with logs_by_type and log_files_created (2301) in its data blob — exactly one per run.
- **Source:** `stop_logging 2345-2356; log_final_summary 2296-2306; __del__ 2358-2363; _stopped init 2127; calls 7696, 7715`

### Monitoring lifecycle and its stop-once guards

StatisticsManager starts its own monitoring thread in __init__ (1854) and again via an explicit start_monitoring() call in run() (7367); both are no-ops when enable_performance_monitoring is false (the default), and start_monitoring skips if a thread is already alive. StatisticsManager.stop_monitoring is guarded by a _stopped flag (2081-2083) and is invoked from _perform_enhanced_cleanup, run()'s finally and __del__. SystemResourceMonitor is only constructed when enable_resource_monitoring is true — and ITS stop_monitoring (2661-2673) has NO _stopped guard, it is simply only called once.

- **Control:** YARA_ENABLE_PERF_MONITOR 2851-2853, YARA_ENABLE_RESOURCE_MONITOR 2854-2856, YARA_ENABLE_FD_MONITOR 2857-2859 (all env vars read at ScanConfig time) — default `all three "false"`
- **Observe:** logs/statistics_<run_id>.log "Performance monitoring disabled in light profile" (1863, default) vs "Performance monitoring thread started" (1868) then "=== Statistics Manager Stopped ===" (2089); logs/system_<run_id>.log "System resource monitoring disabled in light profile" (2416) vs "System resource monitoring started" (2423); the COMPREHENSIVE SCAN REPORT gains a 'resource_summary' block only when a resource_monitor exists (7023-7025).
- **Source:** `StatisticsManager class 1770, __init__ start call 1854, start_monitoring 1860-1868, stop_monitoring 2079-2090, _stopped init 1814; SystemResourceMonitor class 2366, __init__ start call 2411, start_monitoring 2413-2423, stop_monitoring 2661-2673; construction gate 6780-6782; run() call 7367`

### File-descriptor monitoring setup block (POSIX only, off by default)  <sub>linux, darwin</sub>

When enabled, run() shells out to `bash -c 'ulimit -n'` with a 5s timeout, warns below 8192, primes psutil num_fds and sets config.monitor_fd_usage — which YaraScanner reads at construction (4998). Every failure inside sets monitor_fd_usage=False and continues. On Windows the flag is unconditionally false (7288). In-scan the check fires once per 1000 files, but the counter only advances on files that scanned WITHOUT a match — a matching file returns at 6187 before the FD block — so on a match-heavy scan the interval is longer than 1000 scanned files.

- **Control:** YARA_ENABLE_FD_MONITOR 2857-2859; check interval literal fd_check_interval=1000 at 5000 — default `disabled`
- **Observe:** logs/system_<run_id>.log "Current file descriptor limit: N" (7259-7260 region), "WARNING: Low file descriptor limit (N)" (7262), "Initial file descriptors in use: N" (7275), then during the scan "FD usage increased by N (current: M)" (6202-6204) / "WARNING: High FD usage: N" (6207-6209).
- **Source:** `7251-7288; scanner-side 4998-5001 and 6189-6212`

### Non-root privilege advisories and system-path warning  <sub>linux, darwin</sub>

On POSIX, run() logs whether it is root, gives macOS-specific SIP/Full Disk Access guidance, and — if any requested scan folder starts with a known privileged prefix (/System, /Library, /private/var/db on macOS; /etc, /boot, /var/log, /root on Linux) while not root — logs "ERROR: System path scan requires elevated privileges". It is advisory only: the scan proceeds and will simply skip unreadable files as "No read permission". The check parses the raw scan_folder string (7242-7243), so it never fires for a default full-system scan where scan_folder is None.

- **Control:** Not configurable; prefix lists at 7238 (Darwin) and 7240 (Linux) — default `-`
- **Observe:** logs/system_<run_id>.log "Running as: root\|non-root user on macOS" (7220) / "…on Linux" (7230), "WARNING: Not running as root - some system files may be inaccessible" (7225/7233), "ERROR: System path scan requires elevated privileges" (7245) and "Either run as root or choose a different scan path" (7249); correlate with the "No read permission" entry in the skip_breakdown of statistics_<run_id>.log (reason set at 6127).
- **Source:** `7215-7249; per-file permission handling 6103-6127`

### Invalid numeric env var falls back to the documented default with a warning

_env_number wraps every module-level and ScanConfig numeric knob so a deployer typo cannot kill the scanner at import time — before ScanConfig, LogManager or anything that could report why the action failed, which previously produced a dead action with no local log and no telemetry. It also rejects values that PARSE but are unusable via `minimum`: YARA_MAX_MB=-1 was a valid int that made max_file_bytes negative, so every file failed the size check and the scan reported "completed" having scanned nothing. Applied at 28 call sites (23 at module scope, 5 inside ScanConfig).

- **Control:** _env_number 70-101; applied to 28 knobs including YARA_MAX_MB 2828, YARA_THREADS 2838, YARA_QUEUE_SIZE 2841, YARA_PROGRESS_LOG_SECS 2850, YARA_QUEUE_BACKOFF_SECS 2868, YARA_LOG_KEEP 310 — default `per-knob; on bad input the documented default is used`
- **Observe:** stderr (via the logging lastResort handler, since the module-scope ones fire at import before setup_logging) "Ignoring invalid <VAR>=… (expected a number) - using default …" (91-93) or "Ignoring out-of-range <VAR>=… (minimum …) - using default …" (96-98); then confirm the effective value in scan_summary_<run_id>.json / the system_<run_id>.log init data blob (7321).
- **Source:** `_env_number 70-101`

### ExceptionLogger — lazily created, so a clean run leaves no empty file

The script_exceptions log file and its handler are only created on the FIRST log_exception() call, so successful runs leave no zero-byte file in logs/. In practice its only caller in the whole file is run()'s critical-error handler (7577), which means the file's mere existence is a reliable signal that the run hit a top-level crash — but the converse does not hold: a crash before exception_logger is assigned at 7208 leaves no file either.

- **Control:** Not configurable; path 1701-1703 — default `file not created`
- **Observe:** Presence of logs/script_exceptions_<run_id>.log; its content begins "=== SCRIPT EXCEPTION LOG INITIALIZED ===" followed by "=== EXCEPTION #1 ===", "Context: main_function_critical_error" (1754) and a full traceback.
- **Source:** `ExceptionLogger 1692-1768; _ensure_logger 1707-1746; log_exception 1748-1763; only caller 7577`

### XDR auth-type probe on first use (auto), with caching and no-cache-on-network-error

When XDR_AUTH_TYPE is "auto", the first header build probes get_datasets with Advanced then Standard and caches the winner in a module global. A network error returns "advanced" WITHOUT caching (698-700), so a later attempt re-probes; an inconclusive probe (both non-2xx) caches "advanced" (707). An unconfigured/placeholder URL also short-circuits to a cached "advanced" (688-690). Headers must be rebuilt per HTTP attempt because Advanced embeds a per-request nonce+timestamp that must not be replayed on retries.

- **Control:** XDR_AUTH_TYPE 333 (env XDR_AUTH_TYPE: auto\|advanced\|standard); cache global _RESOLVED_AUTH_TYPE 334 — default `"auto"`
- **Observe:** logs/uploads_<run_id>.log "XDR auth type detected: advanced\|standard" (704), or "XDR auth probe (advanced\|standard) network error: …" (699), or "XDR auth probe inconclusive; defaulting to advanced" (709).
- **Source:** `_probe_auth_type 678-710; build_xdr_headers 713-723; _RESOLVED_AUTH_TYPE 334`

### Evidence collection on the successful path (and what a metadata-only ZIP contains)

On the completed path only, collect_evidence writes evidence/file_mapping.txt (host header plus path\|sha256 for every matched file that still exists) and builds evidence_<hostname>_<run_id>.zip. With collect_files=false (the default) the matched files are NOT copied — the ZIP carries only file_mapping.txt plus every alert/*.txt — so a responder locates files by path/hash instead. With collect_files=true, entries are content-addressed under matched_files/<sha256> and deduplicated by hash (measured on the twin: 22,918 paths → 22,213 distinct files, 705 redundant copies, 506 MB). Exceptions are caught by run() and logged, never fatal.

- **Control:** CONFIG_COLLECT_FILES 163 / options collect_files; evidence_zip path 2904-2906; file_mapping path 2822 — default `CONFIG_COLLECT_FILES = False`
- **Observe:** evidence/evidence_<hostname>_<run_id>.zip and its member list (alerts/*.txt added 4566-4569 + file_mapping.txt added 4571, plus matched_files/<sha256> only when collect_files=true); logs/system_<run_id>.log "Evidence: collect_files=false - packaging metadata only (no matched file copies)" (4563-4564) or "Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped" (4557-4561, emitted ONLY when at least one duplicate was skipped, gate 4556), and "Evidence collection completed successfully" (7485); failures in scan_errors_<run_id>.log "Error collecting evidence: …" (7487).
- **Source:** `collect_evidence 4492-4499; _process_matched_files 4501-4519; _create_evidence_zip 4521-4571; EvidenceCollector._log routes to LogManager 4473-4484; call 7483-7487`

### Remaining-thread join in the successful path

After cleanup scheduling, run() re-checks scanner.scan_threads and joins any still-alive worker with a 2s timeout each. This is a second, weaker join on top of _perform_enhanced_cleanup's 5s-per-thread pass; it does not affect the outcome or the result line either way. It uses the always-true `'scanner' in locals()` idiom (7500) rather than the `scanner is not None` guard used in the critical handler — harmless here only because this line is unreachable unless scanner exists.

- **Control:** Not configurable (literal timeout=2 at 7505) — default `2s per thread`
- **Observe:** logs/system_<run_id>.log "Waiting for N remaining threads to terminate" (7503) followed by "=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===" (7507).
- **Source:** `7500-7505; banner 7507`

### Terminal "completed" status emission is best-effort and last

Just before building the success result line, status_uploader.set_status("completed") is called inside a try/except that logs failure rather than propagating — because without it the last value emitted on a successful run was "finishing", indistinguishable from a scan hung mid-shutdown. Since the status channel itself is dormant (set_status only assigns a field and calls a silenced logging.info), the real terminal signal is the dataset row emitted earlier in _perform_enhanced_cleanup.

- **Control:** Not configurable — default `-`
- **Observe:** logs/scan_errors_<run_id>.log "Could not emit terminal scan status: …" (7531) on failure — which is the ONLY thing this block can produce; the authoritative terminal signal is the yara_scanner_scans_v3_* row with status=completed (emitted 6757).
- **Source:** `7528-7531 (set_status 7529); failed-path equivalent 7432-7435; dataset row 6746-6757`

### Run identity: run_id, scan_id and their propagation

run_id is a microsecond-resolution timestamp set at ScanConfig construction and is the join key for every per-run artefact (all log filenames, the summary filename, the log-retention regex, HostCleanup's file selection). scan_id is <hostname>_<run_id>_yara_<rulehash12> — the rule-hash-only scan_id it replaced collided across hosts and runs sharing a ruleset, which broke multi-host correlation in XDR. ScanStatusUploader independently OVERWRITES its own copy with a second-resolution <hostname>_<timestamp> at 4390, so that dormant channel would not have matched anyway.

- **Control:** Not configurable; run_id 2692, scan_id 2816 — default `run_id format %Y%m%d_%H%M%S_%f`
- **Observe:** scan_summary_<run_id>.json "run_id"/"scan_id" (2318-2319); every logs/*_<run_id>.log filename; yara_scanner_scans_v3_* and yara_scanner_matches_v3_* rows' run_id/scan_id columns; control/running.json scan_id (5183); yara_processing_<run_id>.log "Scan ID: … (rule hash: …)" (2817).
- **Source:** `run_id 2692; scan_id block 2807-2817 (assignment 2816); retention regex 4580-4583; HostCleanup selection 4955-4961`

### Scanner version self-identification

__version__/__release_date__ are written into the summary JSON and logged into the yara_processing log at config time, so a shared copy of the file always identifies which build an endpoint actually ran — behaviour differs between releases and support requests need it. The version is NOT carried on any dataset row (neither scans_schema 3915-3938 nor the matches schema has a version column), so fleet-wide version auditing must read the summary files, not XQL.

- **Control:** __version__ 29, __release_date__ 30 — default `3.3.0 / 2026-08-17`
- **Observe:** scan_summary_<run_id>.json "scanner_version" (7653); logs/yara_processing_<run_id>.log "YARA Scanner VERSION 3.3.0 (released 2026-08-17)" (2787-2788).
- **Source:** `29-30; summary field 7653; log line 2787-2788`

### "Scan configuration established" — resolved target list logged under a non-canonical scan_id

Once per run, right after target resolution, scan_system writes an 8-field record (scan_id, os_info, targets, target_count, max_workers, max_file_size_mb, yara_rules_count, failed_rules_count) into statistics_<run_id>.log. The surprise is its scan_id: minted inline as <hostname>_%Y%m%d_%H%M%S (no microseconds, no rule-hash suffix), so it does NOT equal config.scan_id (<hostname>_<run_id>_yara_<hash12>, 2816) that every alert, dataset row and scan_summary carries — an operator correlating this record to dataset rows by scan_id finds nothing. It is also the only artefact that pairs the target list with max_file_size_mb and the valid/failed rule counts, and it reflects YaraScanner._get_scan_targets' result rather than config.scan_targets. A second shadow scan_id of the same shape is minted in ScanStatusUploader.__init__ (4390), but reaches no artefact: its only consumer upload_scan_status (4393) is never called and would early-return on UPLOAD_NON_MATCH_DATA=False anyway (gate 4395, constant 105).

- **Control:** Not configurable — the record is always emitted; the inline scan_id is a bare f-string at 6803 — default `-`
- **Observe:** grep "Scan configuration established" <scanner_dir>/logs/statistics_<run_id>.log — the whole payload is on the line as `\| data={...}` (LogManager._log 2163 serialises dicts to JSON, capped at 4000 chars 2176-2177). Compare its data.scan_id against scan_summary_<run_id>.json and the yara_scanner_scans_v3_* rows: they will differ. statistics_<run_id>.log has its own FileHandler with propagate=False (_setup_logger 2131-2155), so it survives setup_logging's root-handler stripping.
- **Source:** `scan_config_data 6802-6811 (inline scan_id 6803), log_statistics call 6813; LogManager.log_statistics 2196; canonical scan_id ScanConfig 2816; targets resolved 6799 via _get_scan_targets 6500-6512; ScanStatusUploader shadow scan_id 4390; dead upload_scan_status 4393-4450 (gate 4395)`

### "All monitoring systems activated" — the run's monitoring and delivery switch record (and why performance_metrics is all zeros)

Emitted once at the top of scan_system, right after the INITIATED banner and before target discovery, this system-log record is the only artefact capturing the effective switch positions for the run: statistics_monitoring (a hard-coded literal True at 6788, and misleading — StatisticsManager.start_monitoring early-returns unless enable_performance_monitoring is on), performance_monitoring, resource_monitoring, match_upload_enabled (the module-level UPLOAD_RESULTS kill-switch), worker_threads and cpu_guarantee. It has SIX fields — there is no cache_enabled field here (nor anywhere: grep for cache_enabled finds nothing in the file). Because both monitoring flags default to false, the default record reads performance_monitoring=false / resource_monitoring=false, and the downstream consequence is that the performance_metrics block in comprehensive_final_stats and in the comprehensive report is all zeros with samples_collected=0. That is the documented default, not a sampling failure.

- **Control:** YARA_ENABLE_PERF_MONITOR (2851-2853) and YARA_ENABLE_RESOURCE_MONITOR (2854-2856) env vars, read at ScanConfig.__init__ on the endpoint; UPLOAD_RESULTS module literal 104; worker_threads = config.max_workers (2838-2839); cpu_guarantee via YARA_CPU_GUARANTEE / cpu_guarantee option (2710-2712). The record itself is not configurable. — default `performance_monitoring=false, resource_monitoring=false, statistics_monitoring=true (literal), match_upload_enabled=true`
- **Observe:** grep "All monitoring systems activated" <scanner_dir>/logs/system_<run_id>.log and read the `\| data={...}` JSON. Cross-check the zeros: performance_metrics is initialised to zeros at 1803-1809 and surfaced via get_current_stats_for_upload (2061) into comprehensive_final_stats (7454-7469, logged to system_ at 7471-7474 and to statistics_ at 7478-7481); samples_collected comes from log_comprehensive_stats' perf_summary (2035-2041, count at 2040). On a run where nothing else is logged this is the only proof of which optional subsystems were on.
- **Source:** `record 6785-6795 (statistics_monitoring 6788, performance_monitoring 6789, resource_monitoring 6790, match_upload_enabled 6791, worker_threads 6792, cpu_guarantee 6793); ScanConfig flags 2851-2856; UPLOAD_RESULTS 104; StatisticsManager.start_monitoring gate 1860-1868; performance_metrics zeros 1803-1809; log_comprehensive_stats 2032-2041; get_current_stats_for_upload 2061; comprehensive_final_stats 7454-7481; resource_monitor construction gate 6780-6782; SystemResourceMonitor's own gate 2413-2416`

### Boolean environment toggles fail in opposite directions and have no shared parser

Numeric env vars go through one shared helper (_env_number, 70-101), and option values through _clamp_pct (730) / _coerce_float (739) — but there is NO boolean equivalent, so each toggle rolls its own test, and the two styles fail-safe in OPPOSITE directions. RULE_CACHE_ENABLED (297) and ALERT_REQUEUE_ENABLED (126) use `not in ("0","false","no","")`, so any unrecognised value ("flase", "disable", "off") leaves the feature ON; the three ScanConfig monitoring toggles (2851-2859) use `in ("1","true","yes","on")`, so the same value leaves them OFF. Concretely: setting a toggle to "off" disables monitoring but does NOT disable the rule cache. Nothing warns on an unrecognised value, so a mistyped toggle is undiagnosable from the value itself — only from the downstream behaviour.

- **Control:** YARA_ALERT_REQUEUE 126, YARA_RULE_CACHE 297 (permissive style); YARA_ENABLE_PERF_MONITOR 2851-2853, YARA_ENABLE_RESOURCE_MONITOR 2854-2856, YARA_ENABLE_FD_MONITOR 2857-2859 (strict style). All are module-scope or ScanConfig-scope os.environ reads, i.e. customer-reachable env vars on the endpoint. — default `YARA_ALERT_REQUEUE=1, YARA_RULE_CACHE=1, YARA_ENABLE_PERF_MONITOR=false, YARA_ENABLE_RESOURCE_MONITOR=false, YARA_ENABLE_FD_MONITOR=false`
- **Observe:** Monitoring toggles: init_data's performance_monitoring_enabled / resource_monitoring_enabled fields (7309-7310) in system_<run_id>.log (grep "YARA Scanner initialization completed", 7321), plus the "All monitoring systems activated" record (6785-6795). Rule cache: grep "Rule cache HIT" (5581-5585) / "Rule compile FRESH" (5599) in system_<run_id>.log, the compile_source field ("cache"\|"fresh") in scan_summary_<run_id>.json (7651), and — the firmest signal, since a cold cache logs FRESH either way — whether <scanner_dir>/rule_cache/rules_<key>.yarac exists after the run, because _rule_cache_dir() (5458-5461) is only ever reached from inside a RULE_CACHE_ENABLED branch (5565, 5600). No artefact reports the raw env string.
- **Source:** `ALERT_REQUEUE_ENABLED 126 (used 3477); RULE_CACHE_ENABLED 297 (used 5565, 5600); ScanConfig strict toggles 2851-2859; _env_number 70-101; _clamp_pct 730; _coerce_float 739`

### Strictly validated operator inputs that abort the run by raising (alert_severity, mode, cpu_guarantee)

Three inputs reject anything outside a closed vocabulary by raising ValueError, which aborts the run before any scanning. _parse_alert_severity accepts only low/medium/high; mode only scan/cancel; cpu_guarantee only headroom/budget/none. On the Action Center path all three raise from inside ScanConfig.__init__, so they land in run()'s critical-error handler and the operator sees "Scan failed: 0 files scanned \| 0 rules failed compilation \| 0 matches found \| Critical error occurred" plus a traceback dumped to both stdout and stderr — never a stated reason in the result line itself. Contrast _parse_bool_arg (create_alerts/write_dataset/collect_files), which also raises but accepts a wide vocabulary: true/1/yes/y/on and false/0/no/n/off.

- **Control:** alert_severity (CLI argv[3] / run() kwarg); mode (argv[4] / CONFIG_MODE 160); cpu_guarantee (options string, or YARA_CPU_GUARANTEE env at 2712, falling back to CONFIG_CPU_GUARANTEE 174) — default `alert_severity "low" (2695, and the argv[3] fallback at 7753); mode "scan" (2699); cpu_guarantee CONFIG_CPU_GUARANTEE = "headroom" (174)`
- **Observe:** stderr carries "YARA Scanner Critical Error: Critical scanner error: Invalid <arg> '<value>'. Use …" (7553), "Error Type: ValueError" (7554) and "SCAN_STATUS: ERROR" (7556); stdout carries "CRITICAL ERROR: …" (7559) and the traceback. NO scan_summary_<run_id>.json is written — the finally block requires log_manager, config AND scanner all non-None (7615), and ScanConfig raised before scanner existed, so there is no logs/ evidence beyond yara_processing. On the CLI path _parse_alert_severity runs at argv[3] BEFORE run() is called (7753), so the outer startup handler prints "Critical startup error: …" and the process exits 1 (7780-7785).
- **Source:** `_parse_bool_arg 890-903 (wide vocabulary 898-901, raise 903); _parse_alert_severity 906-913 (raise 913); ScanConfig: alert_severity 2694-2695, mode raise 2699-2701, bool args 2702-2707, cpu_guarantee 2710-2715 (env read 2712, raise 2713-2715); run() critical handler 7550-7603 (error_summary 7599-7601); summary guard 7615; CLI parse 7753; startup handler 7780-7785`

### init_data initialisation disclosure record — emitted twice, includes the tenant API URL

A single 22-field dict (hostname, os_info, ip_addresses, platform, python_version, yara_version, rule_source, scan_targets, max_workers, scan_queue_size, max_file_mb, scanner_profile, the two monitoring flags, upload_enabled, the three credential SOURCE labels, xdr_api_url, default_alert_severity, match_only_upload_mode, logging_format) is logged as "YARA Scanner initialization completed" (7321) and then again, byte-identical, as "YARA Scanner initialized successfully" 20 lines later (7341). So system_<run_id>.log holds two copies of the resolved knob set AND two copies of the tenant API URL per run. It is nonetheless the most complete single record of what a run actually resolved to, and the only place the credential provenance appears. There is no cache_enabled field in it.

- **Control:** Not configurable — both emissions are unconditional — default `-`
- **Observe:** grep -c "YARA Scanner initialization completed" and grep -c "YARA Scanner initialized successfully" in <scanner_dir>/logs/system_<run_id>.log each return 1 for the same payload. Use xdr_api_key_source / xdr_api_id_source / xdr_api_url_source (7312-7314; all initialised to "default" at 2755/2758/2761) to tell whether embedded credentials or the built-in defaults were in play, and xdr_api_url (7315) to confirm which tenant the run would have delivered to. Because LogManager._log caps the serialised data blob at 4000 chars (2176-2177), the long python_version string can push the tail of the dict into "...(truncated)" — check the end of the line before concluding a field is absent.
- **Source:** `init_data construction 7296-7319 (monitoring flags 7309-7310, credential sources 7312-7314, xdr_api_url 7315, match_only_upload_mode 7317); first emission 7321; second emission 7341; source attrs ScanConfig 2755/2758/2761; blob cap LogManager._log 2176-2177`

---

# Control gaps — capabilities the customer cannot tune

Verified by hand against the pinned source. Most of the gaps this file originally
recorded have since been closed; they are listed as **Closed** rather than deleted,
because knowing a knob was recently added is as useful as knowing one is missing.

### Closed

| Was | Now |
|---|---|
| No `force_scan_never_under` at all — the force-scan allowlist had no backstop and could walk onto mounted media | Ported from XSIAM, with the trailing-separator probe. A Time Machine volume no longer gets scanned once per backup snapshot. |
| `CONFIG_LOOKUP_ROWS_PER_FINDING_MAX` a bare literal | `YARA_LOOKUP_ROWS_PER_FINDING` |
| Alert directory total unbounded | `YARA_ALERT_DIR_MAX_MB` (default 256, 0 = off). Degrades detail past the ceiling and keeps counts complete. |
| Every skip list hardcoded, no override of any kind | `YARA_EXTRA_SKIP_PATHS` — comma-separated, **additive only**, normalised to bounded `/x/` component matching. |

### Still open

**The built-in skip entries cannot be removed.** `YARA_EXTRA_SKIP_PATHS` only adds — a
replace-style knob would let one typo silently drop the Cortex agent paths. A site that
genuinely needs to scan inside a default-skipped directory still has no supported way to.

**The evidence ZIP total is still unbounded.** The alert directory now has a ceiling; the
evidence ZIP does not. Content-addressed and metadata-only by default, so the exposure is
narrower, but a collection-enabled run against a noisy ruleset has no byte budget.

**Governor internals are fixed (deliberate).** `GAIN`, `RATIO_MAX` and `PACE_CAP_SECS` are
control-loop tuning, not policy; the policy knobs above them are exposed through both env
vars and `options` keys.

---

# Where XDR and XSIAM diverge on control

Verified against both pinned sources. Useful when a fix lands on one edition and the
question is whether the twin needs it.

| Control | XDR | XSIAM |
|---|---|---|
| Worker count | Honoured — `YARA_THREADS` / `options workers` | Honoured (the `min(2, ...)` clamp was removed) |
| Log retention | `YARA_LOG_KEEP`, default 10 | `YARA_LOG_KEEP`, default 10 |
| Per-finding row/offset cap | `YARA_LOOKUP_ROWS_PER_FINDING` | `YARA_MAX_MATCH_SAMPLES` + `YARA_MAX_ALERT_OFFSETS` |
| Alert directory ceiling | `YARA_ALERT_DIR_MAX_MB` | `YARA_ALERT_DIR_MAX_MB` |
| Extra skip paths | `YARA_EXTRA_SKIP_PATHS` | `YARA_EXTRA_SKIP_PATHS` |
| `force_scan_never_under` | present, consulted before force-scan | present, consulted before force-scan |
| **Per-run overrides** | **Ten `options` keys**, no script edit | **None** — three declared inputs only |
| **Rule cache** | 4 env knobs (297-300) | removed from this edition |

Only the last two rows still differ. The `options` channel is the larger of the two and
the main remaining reason a knob is easier to reach on XDR than on XSIAM: everything else
in this table now behaves identically across the editions, so a fix or a tuning value
carries over without translation.

---

# Observability status

Every entry once marked ⚠ OBSERVABILITY GAP was re-triaged against the current source.
"Unobservable" turned out to conflate three different problems with three different
fixes, which is why they are separated here rather than counted as one number.

| Outcome | Count | Meaning |
|---|---|---|
| Closed | 10 | Evidence exists. The capability was always observable once root logging had a disk sink; only the wording was stale. |
| Needs instrumentation | 7 | Runs, records nothing anywhere. Real work, listed below with what would close each. |
| Unverified-dead | 18 | Believed unreachable — **not deleted, and not safe to delete on this evidence.** See the warning below. |

## Needs instrumentation

These execute and leave no trace at any log level. Each line names the minimal
change that would make the capability assertable on a live scan.

- **Duplicate module probe on a fresh compile (wasted work)** — Add one INFO line inside _get_available_yara_modules immediately before `return available` (line 5459): logging.info(f"YARA module probe: {len(test_modules)} candidates compiled, {len(available)} available"). Two of these lines in logs/diagnostics_<run_id>.log for one run proves the duplicate pass; one line means a cache HIT. (The real fix is to pass the modules computed at 5662 into _compile_yara_rules and drop the second probe — the log line is what makes either state visible.)
- **Everything before the first rule declaration is discarded (except imports)** — In _split_yara_rules, right after the rule_starts loop (insert at line 5924, next to the existing `Found {N} rule start positions` info), emit: `if rule_starts:` compute `dropped = [l for l in lines[:rule_starts[0][0]] if l.strip() and not l.strip().startswith(('import ','include ','//'))]` and, when non-empty, `logging.info(f"Discarded {len(dropped)} non-import line(s) before the first rule declaration")`. That one line in logs/diagnostics_<run_id>.log turns the discard from an inferred count-gap into a direct measurement.
- **Unknown platform has no directory skip list at all** — Add one field to scan_config_data in scan_system (dict at lines 6934-6942, logged at 6945): `'platform_skip_paths': len(getattr(self.config, 'skip_paths', ()))` (optionally alongside `'platform': platform.system()`). That makes the "Scan configuration established" entry in statistics_<run_id>.log state the skip-list size directly on every run — 0 proves the unknown-platform branch, non-zero proves the platform list loaded — instead of requiring the negative inference from a missing skip_breakdown key.
- **Junction / reparse-point detection (_is_junction_or_symlink)** — Instrument the pruning site at line 7021 in scan_system: capture the removed entries before filtering, e.g. `pruned = [d for d in dirs if _should_skip_junction(os.path.join(root, d))]`, then `dirs[:] = [d for d in dirs if d not in pruned]` and, under `self.lock_counts`, `self.skip_reasons["Junction/symlink dir prune"] += len(pruned)` plus `self.junction_skip_count += len(pruned)`. That surfaces it in the skip_breakdown of the "Skip reasons" statistics entry (6774-6777) and in the existing junction_skips fields, no new file or field needed.
- **Log-file deletion failures are tolerated, not fatal** — NEEDS_INSTR, and the minimal fix is a channel swap, not a new log line: in _prune_old_scan_logs replace the bare logging calls with the class's own helper - 4728 -> self._log(f"Cannot remove log file (in use): {path}"), 4731 -> self._log(f"Cannot remove log file {path}: {e}"), 4733-4736 -> self._log("Log retention applied: ..."), 4738 -> self._log(f"Log retention: {failed} log files could not be removed"). Since 7381 passes log_manager in, all four then land in logs/system_<run_id>.log. (Alternative, broader fix: move setup_logging(config) from 7461 to before cleanup_manager.initial_cleanup() at 7383 so the diagnostics handler exists during startup cleanup - that also closes every other pre-7461 logging.info.)
- **macOS case-sensitivity probe writes and deletes /tmp/CaSe_TeSt_YaRa_<pid> per scanned file** — NEEDS_INSTR. Minimal: memoize + log once in _is_case_sensitive_fs - add a module-level cache (e.g. `_CASE_SENSITIVE_FS = None`) and, on the first Darwin evaluation, emit logging.info(f"Case-sensitivity probe (/tmp/CaSe_TeSt_YaRa_{os.getpid()}): case_sensitive={result}") plus logging.info on the except arm at 536-537 recording the probe failure before returning False. Because every caller path runs inside the scanner (after setup_logging at 7461), that line lands in logs/diagnostics_<run_id>.log. Ideally also add a `case_sensitive_fs` boolean to scan_summary so the decision is visible without reading the log.
- **Alert channel's startup narration is unreachable - uploads log never records whether alerts are on** — NEEDS_INSTR. Minimal: give ResultsUploader.__init__ a `log_manager=None` parameter and pass self.log_manager at the 5112 construction site (mirroring LookupDatasetUploader at 5113), then drop the now-redundant late attach at 5120. Cheaper one-line alternative that needs no signature change: replace the guarded calls at 3290-3291, 3296-3297, 3300-3301, 3307-3308 with plain logging.info(...) - construction at 5112 happens after setup_logging (7461), so those records land in logs/diagnostics_<run_id>.log.

## Unverified-dead — do not delete on this evidence

These are believed unreachable. They were **not** removed, and the list should not be
acted on as-is.

A triage pass classified them, then an independent adversarial pass tried to refute
each one and overturned 6 of 32 — including `_yara_callback`, which is wired into the
only `rules.match()` call and is the hottest function in the process, and
`lock_throttle`, which is taken from two threads on every scan-lifecycle row.

A single manual spot-check of the SURVIVORS then found another false positive:
"unnamed-rule fallback naming" was marked dead with instructions to delete the
`else f"rule_{i}"` arms, but `rule { condition: true }` parses to `name=None`, the
name regex fails against that body, and an unnamed rule is a YARA SyntaxError — so the
fallback fires on exactly the compile-failure path where naming the offending rule
matters most. Deleting it would make a malformed pack report a failure with no name.

The methodological reason both passes missed it: they hunted for CALLERS, which is the
right test for "is this function ever invoked" and the wrong one for a dead BRANCH
inside a live function. Reachability of a branch is settled by constructing the input
that drives execution down it, not by grepping for references.

Anything below needs that branch-level check before removal:

- _is_valid_rule_structure — DEAD CODE
- Dead hook: _discover_all_targets override branch
- The scanner's own output log path is excluded from scanning
- Windows drive-letter exclusion list (present but permanently empty)
- DEAD CODE: Windows wildcard pattern skip list never matches anything
- DEAD: total_files_found and files_per_target are computed then discarded
- DEAD CODE: idle-tier ("os") priority branch
- DEAD CONSTANT: WORKER_GET_TIMEOUT_SECS
- DEAD CONSTANT: CANCEL_DRAIN_DEADLINE_SECS
- DEAD CONFIG: batch_size / performance_log_interval / statistics_upload_interval
- DEAD CODE: _get_scanner_stats aggregate
- DEAD CODE: periodic scan-status upload
- Per-file permission denials accumulate in an unbounded list that nothing ever reads
- DEAD CODE: ScanStatusUploader.upload_scan_status() is never called and is double-gated off
- CANCEL_DRAIN_DEADLINE_SECS - dead constant
- ResultsUploader.upload_results - dead finalisation path
- CircuitBreaker class - defined, never instantiated

---

# Provenance

Enumerated across six dimensions, then adversarially re-verified entry by entry against an
immutable snapshot of the scanner (v3.3.0, 7,785 lines, sha256 `4ced74193d228e42`).

The re-verification was not routine. The original enumeration read the scanner from the
repository working tree while a parallel session switched branches underneath it, so
different agents saw two different versions of the file (7,785 vs 7,781 lines, differing by
~300 lines). The re-verification pass against the pinned snapshot corrected
**407 line references** and **33 substantive claims**, and dropped
9 entries as duplicates or unfounded — which is the measure of how much of the
first pass was unreliable.

The lesson, recorded because it will recur: in a repository whose working tree is shared
with another session, **the filesystem is not a stable source of truth**. Pin the version
(`git show <ref>:<path>`, or a read-only snapshot) before enumerating anything against it.

Of 456 entries, 455 were confirmed line-by-line against the pinned file.

---

*Keep this current in the same commit that changes behaviour — a stale capability
reference is worse than none, because it is trusted.*
