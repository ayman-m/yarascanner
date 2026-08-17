# XSIAM Scanner — Capability Reference

`xsiam_yara_scanner.py` **v4.4.0** · Cortex XSIAM edition (HTTP Log Collector delivery).
The XDR edition has its own file: [`XDR_CAPABILITIES.md`](XDR_CAPABILITIES.md).

## What this file is

A reference for what the scanner can do today, and the shape new capabilities get recorded
in. It exists for two jobs:

1. **Onboarding and support** — what exists, what controls it, what a flag actually changes.
2. **Test design** — every scan trial's success criteria are drawn from the *Observe* field
   below. A capability nobody can observe on a live scan cannot be a test criterion, which
   is why unobservable ones are marked rather than quietly listed as working.

Derived by enumerating the source directly, then auditing the result three ways
(completeness, accuracy, observability). Update it in the same commit that changes behaviour.

## How to read an entry

| Field | Meaning |
|---|---|
| **What** | What the capability does, and why it exists |
| **Control** | The constant or env var that governs it, and its default |
| **Observe** | How to confirm it ran, on a live scan |
| **Source** | The function/class/constant implementing it |

Two markers flag work, not documentation:

- **⚠ CONTROL GAP** — no customer-reachable flag. The Action Center form carries only the
  script's three declared inputs, so a customer changes behaviour by editing a top-of-file
  constant before upload, or setting an env var on the endpoint. Anything else is not
  customer-controllable however configurable it looks in code.
- **⚠ OBSERVABILITY GAP** — the capability works but leaves no evidence trail.

## At a glance

| | Count |
|---|---|
| Capabilities catalogued | **271** |
| &nbsp;&nbsp;Rule Handling | 40 |
| &nbsp;&nbsp;Scan Targeting, Traversal & Skipping | 44 |
| &nbsp;&nbsp;Performance & Resource Management | 44 |
| &nbsp;&nbsp;Local Storage & Host Footprint | 34 |
| &nbsp;&nbsp;Delivery, Aggregation & Telemetry | 48 |
| &nbsp;&nbsp;Scan Lifecycle, Control & Error Handling | 61 |
| ⚠ Control gaps (verified) | 24 |
| ⚠ Observability gaps | 40 |

The 40 observability gaps are listed in full at the end of this file. Only 4 are marked inline — those are the ones whose *Observe* field names a
dead `logging.info` call outright. The rest were found by checking whether the stated
evidence actually reaches a handler, which the entry text alone does not reveal.

---

# Rule Handling

*From “operator supplies rules” to “compiled ruleset ready to match”.*

### Base64-only rule input

The `yarafile` entry-point argument is treated as base64 text, never as a path or plain YARA. Decoding is lenient: an optional `b64:` prefix is stripped, all whitespace/newlines removed, URL-safe alphabet translated (`-`→`+`, `_`→`/`), and missing `=` padding is re-added.

- **Control:** main(yarafile=...) / argv[1]; no env var — default `None — with no argument the embedded `YARA_RULE` constant is used instead`
- **Observe:** `logs/yara_processing_<run_id>.log` line `Using YARA rules from provided parameter` (vs `...from default configuration`). Passing plain-text YARA fails: base64.b64decode silently discards non-alphabet chars, so it surfaces as `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations` (verified by executing decode_yara_rules on plain text).
- **Source:** ``_b64_to_text` (line 359), `decode_yara_rules` (559), `ScanConfig.__init__` (2723-2731)`

### Rule input size cap

Rejects a rules blob larger than 50,000,000 characters of base64 before any decode work is attempted.

- **Control:** hardcoded literal `50_000_000` in decode_yara_rules — default `50,000,000 characters`
- **Observe:** Raises `ValueError("YARA rules input too large")` from ScanConfig construction; surfaces as the `Critical startup error:` stderr block and exit code 1 (no run_id / logs dir content, because it fires before ErrorLogger emits anything else).
- **Source:** ``decode_yara_rules` (566-567)`

### Typed rule-input rejection codes

Three distinct pre-compile input failures, each written with its own prefix token so a test can assert which one occurred: empty input, base64 decode failure, and content that contains no `rule` declaration.

- **Control:** not configurable — default `always on`
- **Observe:** `logs/yara_processing_<run_id>.log` contains exactly one of `INPUT_ERROR: Empty YARA rules content provided`, `DECODE_ERROR: Base64 decode failed: ...`, `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations`. Each also sets `error_logger.has_errors = True`.
- **Source:** ``decode_yara_rules` (569-604)`

### Empty embedded ruleset guard

The script ships with an empty embedded ruleset; if no `yarafile` is supplied the run aborts rather than scanning with zero rules.

- **Control:** module constant `YARA_RULE = r""""""` (line 294) — default `empty string`
- **Observe:** `ValueError: Default YARA_RULE is empty - must provide yarafile parameter`, logged as `CRITICAL: Failed to decode YARA rules: ...` in `yara_processing_<run_id>.log`, then re-raised out of ScanConfig.
- **Source:** ``ScanConfig.__init__` (2727-2729)`

### Comment- and string-aware pack parser

All rule/import/include discovery runs off a hand-written top-level tokenizer that tracks brace depth, double-quoted strings (with backslash escapes), `//` line comments and `/* */` block comments. A `rule` keyword inside a comment, inside a string literal, or inside a rule body is therefore never mistaken for a rule declaration.

- **Control:** not configurable — default `always on`
- **Observe:** Compare the `Found N rule start positions` count (compile path) and the `total_rules_found` field of the `YARA Rules loaded: N rules, M imports` system log/event against a pack deliberately containing `// rule fake` and a string `"rule decoy"` — the decoys must not be counted.
- **Source:** ``_iter_yara_top_level_words` (376), `_get_yara_top_level_statements` (451)`

### private / global rule modifier capture

When a rule is declared `private rule X` or `global rule X`, the extracted block starts at the modifier keyword, not at `rule`, so the modifier survives into the compiled source.

- **Control:** not configurable — default `always on`
- **Observe:** For a pack with `private rule X`, the block written to `failed_rules/failed_rule_X.yar` (or the compiled namespace source) retains the `private` keyword. `_clean_rule_content`'s guard regex `^\s*(?:(?:private\|global)\s+)*rule\s+\w+` accepts it rather than logging `Rule X doesn't start with 'rule' keyword`.
- **Source:** ``_get_yara_top_level_statements` (466-470, modifier_start), `_clean_rule_content` (4309)`

### Pack splitting into preamble + individual rules

A multi-rule pack is split into a shared preamble (import/include statements) and one text block per rule; each rule is then compiled on its own as `preamble + "\n\n" + rule`. This is what makes one broken rule non-fatal to the rest of the pack.

- **Control:** not configurable — default `always on`
- **Observe:** `yara_processing_<run_id>.log` compilation summary shows `Total rules processed` > 1 with `Valid rules compiled` and `Failed rules skipped` split; the artifacts under `failed_rules/` are per rule, and the final ruleset still compiles.
- **Source:** ``_split_yara_rules` (4625), `_compile_yara_rules` loop (4498-4522)`

### Duplicate import de-duplication in the preamble

**⚠ OBSERVABILITY GAP**  
Identical import statement texts appearing multiple times across the pack are emitted once into the shared preamble.

- **Control:** not configurable — default `always on`
- **Observe:** Not durably logged (`Found N unique import statements` is a `logging.info` and the root logger is quieted to WARNING). Observe indirectly: a pack repeating `import "pe"` in 100 rules still compiles, and the `import_statements` count in the `YARA Rules loaded: N rules, M imports` system event counts the raw statements while the compiled preamble holds one.
- **Source:** ``_split_yara_rules` imports_seen (4629-4658)`

### include statements passed through verbatim

`include "..."` is recognised as a top-level statement and copied into the preamble unchanged — the module-availability filter only inspects `import "..."`, so includes are never stripped and are resolved (or not) by libyara relative to the process CWD.

- **Control:** not configurable — default `always on`
- **Observe:** A pack with an `include` line: the include text appears in the preamble block written at the top of any `failed_rules/failed_rule_*.yar` artifact; if the included file is absent, every rule fails compile with libyara's `can't open include file` and `Failed rules skipped` equals the rule count.
- **Source:** ``_get_yara_top_level_statements` (481-487), `_split_yara_rules` (4630-4658 else branch)`

### Rule block sanity check

**⚠ OBSERVABILITY GAP**  
Each extracted block must match `^\s*(?:(?:private\|global)\s+)*rule\s+\w+` before it is queued for compilation; otherwise it is dropped from the extraction with no compile attempt. Braces are never rewritten or balanced.

- **Control:** not configurable — default `always on`
- **Observe:** stderr carries `Rule <name> doesn't start with 'rule' keyword` (a `logging.warning`, which reaches stderr via the last-resort handler since setup_logging leaves the root logger at WARNING with no handlers). The rule appears in neither `valid` nor `failed` counters.
- **Source:** ``_clean_rule_content` (4309-4323), `_split_yara_rules` (4670-4690)`

### Unnamed-rule fallback naming

A rule whose name token does not match `^[A-Za-z_]\w*$` gets a positional placeholder name (`rule_<n>` at split time, `rule_<i>` at compile time) so it can still be reported and written to disk.

- **Control:** not configurable — default `always on`
- **Observe:** Placeholder names appear as `Rule Name: rule_7` in a `=== RULE COMPILATION FAILURE #n ===` block and as the filename `failed_rules/failed_rule_rule_7.yar`.
- **Source:** ``_get_yara_top_level_statements` (461-465), `_split_yara_rules` (4662), `_compile_yara_rules` (4500-4501)`

### Agent module-availability probe  <sub>all (result varies by agent build/OS)</sub>

Before compiling, the scanner probes this agent's libyara by compiling a throwaway `import "<mod>" rule test { condition: true }` for each candidate module. The candidate set is the standard probe list UNION every module actually imported by the submitted pack, so a module outside the hardcoded list is still detected correctly.

- **Control:** hardcoded probe list `['pe','elf','cuckoo','magic','hash','math','dotnet','time']` plus source-derived imports — default `the 8 modules above + whatever the pack imports`
- **Observe:** First-class line in `logs/yara_processing_<run_id>.log`: `Available YARA modules: pe, elf, hash, math, ...`. Differs by endpoint — the module set is a property of the agent's embedded libyara build, so the same pack on Windows vs Linux agents can produce different lists.
- **Source:** ``_get_available_yara_modules` (4325), `_extract_imported_modules` (4394)`

### cuckoo-availability callout

A dedicated warning is emitted when the `cuckoo` module in particular is missing, because it is the most common module absent from agent libyara builds.

- **Control:** not configurable — default `always checked`
- **Observe:** `yara_processing_<run_id>.log`: `YARA cuckoo module not available`; stderr also carries `YARA cuckoo module not available - rules using it will be skipped`.
- **Source:** ``_compile_yara_rules` (4438-4440)`

### Unavailable preamble imports stripped

Imports in the shared preamble naming modules the agent lacks are removed from the preamble, so the remaining rules are not all killed by one unsupported import at the top of the file.

- **Control:** not configurable (driven by the probe result) — default `always on when available_modules is known`
- **Observe:** Indirect: with a pack whose header is `import "cuckoo"` on an agent lacking cuckoo, rules that never reference cuckoo still compile and count as valid. The preamble block reproduced at the top of any `failed_rules/failed_rule_*.yar` no longer contains the stripped import.
- **Source:** ``_split_yara_rules` (4636-4650)`

### Pre-compile skip for rules importing missing modules

A rule carrying its own `import "<mod>"` for an unavailable module is skipped before compilation — counted as skipped, never as failed — and its text is preserved on disk.

- **Control:** not configurable — default `always on`
- **Observe:** `failed_rules/skipped_rule_<rulename>_<module>.yar`, whose header is `// SKIPPED RULE - Module '<mod>' not available` plus an ISO date. Log line (first 10 only): `Skipping rule 'X': uses unavailable module 'Y'` in `yara_processing_<run_id>.log` and on stderr.
- **Source:** ``_rule_uses_unavailable_modules` (4358), `_compile_yara_rules` (4504-4530)`

### Post-compile reclassification of inherited-import failures

When a rule inherits `import "<mod>"` from a stripped preamble, libyara reports `undefined identifier "<mod>"`. This is reclassified from compile-failure to skip only when all three hold: yara reported that identifier undefined, the name was imported somewhere in the RAW source, and the module is genuinely unavailable. A rule merely containing the literal string "cuckoo.conf" is therefore not mis-skipped.

- **Control:** not configurable — default `always on`
- **Observe:** `failed_rules/skipped_rule_<rulename>_<module>.yar` with the distinguishing header `// (import inherited from the file-level preamble)`; log line `Skipping rule 'X': needs unavailable module 'Y' (inherited from a file-level import)`. Test criterion: such a rule must NOT appear in `failed_rules_count` nor produce a `failed_rule_*.yar`.
- **Source:** ``_module_missing_from_compile_error` (4367-4392), `_compile_yara_rules` (4533-4562)`

### Automatic import injection from module usage

If a rule body references `math.`, `elf.`, `pe.`, `hash.`, `time.`, `dotnet.`, `magic.` or `cuckoo.` but neither the rule nor the preamble imports that module, and the module IS available, the import is prepended to the rule before compiling.

- **Control:** hardcoded `module_usage_patterns` OrderedDict (math, elf, pe, hash, time, dotnet, magic, cuckoo) — default `always on for available modules only`
- **Observe:** `yara_processing_<run_id>.log`: `Auto-injected missing imports for rule 'X': pe, hash` — logged for every occurrence, not capped.
- **Source:** ``_inject_missing_rule_imports` (4405-4431), call site (4512-4520)`

### Per-rule trial compile then namespaced whole-pack compile

Every rule is compiled individually (result discarded) to isolate failures, then all survivors are compiled together via `yara.compile(sources={...})` with one namespace per rule, keyed `ns_<index>_<rulename>`. Rules are compiled twice in total.

- **Control:** not configurable — default `always on`
- **Observe:** `Successfully built ruleset with N rules` (plus ` (M failed)` / ` (K skipped - missing modules)` suffixes); on a large pack, compile wall-time is visible as the gap between the `running.json` marker being written with status `compiling` and the first worker start.
- **Source:** ``_compile_yara_rules` (4518-4521, 4607-4618)`

### Duplicate rule names survive

Because each rule gets its own namespace, two rules with the same name both compile and both can fire — a consequence of the per-rule namespacing, and the opposite of a single whole-pack compile, which errors with `duplicated identifier`.

- **Control:** not configurable — default `always on`
- **Observe:** Verified locally against yara 4.5.4: whole-pack compile of two `rule dup` blocks raises `line 2: duplicated identifier "dup"`, while `sources={'ns_1_dup':..., 'ns_2_dup':...}` compiles. On a live scan both fire and `detection_counts` merges them under one name, so `unique_rules_triggered` in `scan_summary_<run_id>.json` counts the name once while `matches` counts both hits.
- **Source:** ``_compile_yara_rules` valid_sources key `f"ns_{i}_{display_name}"` (4520)`

### Duplicate-name caveat in the rule-source map

The rule-source map used to explain condition-only matches is a dict keyed by lowercased rule name, so with duplicate names the LAST occurrence in the source wins as the explanation text.

- **Control:** not configurable — default `always on`
- **Observe:** Verified: `_build_yara_rule_source_map` on a two-`dup` pack returns a single key `dup`. Visible in the `Condition Match Details:` block of `alert/<rule>.txt`, which will quote evidence from the later duplicate.
- **Source:** ``_build_yara_rule_source_map` (500-510), `YaraScanner.__init__` (4203)`

### Compile-time externals declaration

Four external variables are declared at every compile (including the module probe compiles), so community rules referencing them compile instead of erroring with an undefined identifier.

- **Control:** module constant `YARA_COMPILE_EXTERNALS` — default ``{"filepath": "", "filepath_lower": "", "filename": "", "filename_lower": ""}` — all empty strings`
- **Observe:** A rule whose condition uses `filename_lower` compiles (counts toward `Valid rules compiled`) rather than producing an `undefined_identifier` entry in the compilation-failure block.
- **Source:** ``YARA_COMPILE_EXTERNALS` (821-827), passed at 4351, 4518, 4609`

### Per-file externals at match time  <sub>all (normalised path separator differs: Windows `\` vs POSIX `/`)</sub>

For each scanned file the same four externals are populated with real values — the normalised path, its lowercase form, the basename, and its lowercase form — and passed to `rules.match()`.

- **Control:** not configurable — default `derived per file via os.path.normpath / os.path.basename`
- **Observe:** A rule with `condition: filename_lower == "eicar.com"` matches on a live scan. Platform-visible: `os.path.normpath` yields backslash-separated paths on Windows and forward-slash on Linux/macOS, so path-shaped external comparisons must be written per platform.
- **Source:** ``_build_yara_match_externals` (830-842), call site `self.rules.match(filepath=..., externals=...)` (4894-4898)`

### Non-short-circuiting match callback

A match callback is installed that returns `yara.CALLBACK_CONTINUE` on every invocation, so evaluation never stops at the first matching rule — all rules are evaluated against every file.

- **Control:** not configurable — default `always on`
- **Observe:** One file matching three rules produces three entries in `_write_alerts`, three `alert/<rule>.txt` files, three `yara_match` upload events, and `total_detections` incremented by 3.
- **Source:** ``_yara_callback` (4989-4993), passed as `callback=` at 4897`

### Condition-only (no-strings) rule support

A rule that matches on condition alone with no string instances still produces a full finding, with a generated human-readable explanation assembled from the rule's meta (purpose/severity/scope/author), its tags, and static analysis of its original source text — it flags an `uint16(0) == 0x5A4D` MZ/PE header check, extracts the function names from `pe.imports("lib","func")` calls, and notes generic `pe.` usage.

- **Control:** not configurable — default `always on when a match carries zero strings`
- **Observe:** `alert/<rule>.txt` contains a `Condition Match Details:` block instead of `Matched Strings`; the uploaded `yara_match` event has `match_scope: "rule"`, `offset: ""`, `match_count: 1`, `string_match_count: 0`, and the `string` field carrying the generated summary; the message reads `YARA rule-only match: rule 'X' in <file>`.
- **Source:** ``_summarize_condition_only_match` (512-557), `_write_alerts` (5124-5132), `ResultsUploader.add_match` is_rule_only_match (3337-3345, 3392)`

### Per-rule compilation-failure diagnostics

Each failing rule gets a categorised diagnosis: `invalid_pe_field` (with the offending field name extracted), `syntax_error` (with the `unexpected <token>` fragment), `undefined_identifier`, or `duplicate_definition`, each with a severity and fixed suggestion list, plus the line number parsed out of libyara's `line N` message and an analysis of that line (contains condition:/strings:/meta:, length, indentation).

- **Control:** not configurable — default `always on per failed rule`
- **Observe:** `yara_processing_<run_id>.log`: a `=== RULE COMPILATION FAILURE #<n> ===` block naming the rule, the error, the error type, and the full rule text numbered line-by-line with `<-- ERROR HERE` on the offending line. The same structure is emitted as a webhook error event with `error_analysis`, `error_line_number`, `rule_length_lines`, `compilation_failure_number` fields.
- **Source:** ``ErrorLogger._analyze_compilation_error` (1235-1299), `ErrorLogger.log_rule_compilation_error` (1301-1348)`

### failed_rules/ artifact directory  <sub>all (path differs per OS as listed)</sub>

Every rule that fails to compile is written out as a standalone `.yar` file containing an error header, an ISO timestamp, the shared preamble, and the rule text — so the operator can reproduce the failure with a local `yarac`. Skipped rules and an un-splittable raw blob land in the same directory.

- **Control:** `<scanner_dir>/failed_rules`; scanner_dir from env `YARA_SCANNER_DIR` — default ``C:\yara_scanner\failed_rules` (Windows), `/opt/yara_scanner/failed_rules` (Linux), `/usr/local/yara_scanner/failed_rules` (macOS)`
- **Observe:** On-disk files: `failed_rule_<name>.yar` (header `// FAILED RULE - Compilation Error` + `// Error: ...`), `skipped_rule_<name>_<module>.yar`, `raw_yara_content.yar`. All writes are best-effort inside `try/except: pass` — absence of a file is not proof the rule compiled; the counters are the authority.
- **Source:** ``ScanConfig.failed_rules_dir` (2698-2701), write sites 4522-4529, 4547-4560, 4564-4576, 4470-4479`

### failed_rules/ is never pruned

`initial_cleanup` deletes only alert_dir, evidence_dir and the output log, and the log-retention pass only touches `logs/`. Artifacts under `failed_rules/` accumulate across every scan on the endpoint and carry no run_id in their names.

- **Control:** not configurable — default `unbounded accumulation`
- **Observe:** Run twice with different broken packs: both runs' `failed_rule_*.yar` remain. Test criterion: never assert on directory contents alone to attribute a failure to the current run — cross-check the timestamp in the file header and the `run_id` counters.
- **Source:** ``CleanupManager.initial_cleanup` paths_to_clean (4004-4008), `_prune_old_scan_logs` (3948, logs_dir only)`

### Un-splittable pack forensics

If splitting yields zero rules (content decoded and contained a `rule` token but no extractable block), the entire raw decoded content is dumped for inspection before the run aborts.

- **Control:** not configurable — default `always on`
- **Observe:** `failed_rules/raw_yara_content.yar` prefixed `// RAW YARA CONTENT - Failed to split into individual rules`; `yara_processing_<run_id>.log` carries `COMPILATION_ERROR: No YARA rules found in provided content`.
- **Source:** ``_compile_yara_rules` (4462-4481)`

### Split-stage failure isolation

An exception thrown by the splitter itself is caught, recorded with its own prefix, and re-raised as a wrapped ValueError so it is distinguishable from a compile failure.

- **Control:** not configurable — default `always on`
- **Observe:** `yara_processing_<run_id>.log`: `SPLIT_ERROR: Failed to split YARA rules: <exc>`.
- **Source:** ``_compile_yara_rules` (4448-4456)`

### Three-way valid / failed / skipped accounting

Rule outcomes are booked in three separate counters: `valid_rules_count` (compiled), `failed_rules_count` (genuine compile errors), `skipped_rules_count` (agent's libyara lacks a required module). Skipped is deliberately kept out of failed so an all-skipped pack cannot read as a clean `0 rules failed compilation`.

- **Control:** not configurable — default `all start at 0`
- **Observe:** `scan_summary_<run_id>.json` fields `valid_rules`, `failed_rules`, `skipped_rules`; the `SCAN_RESULT:` line ends with `... \| N rules failed compilation \| K rules skipped (module unavailable) \| ...` (the skipped clause appears only when K > 0).
- **Source:** ``ErrorLogger.__init__` (1187-1194), publication at `_compile_yara_rules` (4583-4585), summary write (6591-6593), result line (6438-6462)`

### Compilation summary block

A fixed-format summary is written at the end of the compile phase with total processed, valid, failed, a success-rate percentage, and (when anything failed) the path to the failed-rules directory. Note the `total_rules_processed` here is valid+failed only — skipped rules are excluded from that total and from the success rate.

- **Control:** not configurable — default `always written`
- **Observe:** `yara_processing_<run_id>.log` block delimited by `====` lines with `COMPILATION SUMMARY`, `Total rules processed: N`, `Valid rules compiled: N`, `Failed rules skipped: N`, `Success rate: X.X%`, and `Skipped N rules due to unavailable modules` immediately after it when applicable.
- **Source:** ``ErrorLogger.log_compilation_summary` (1350-1368), (4587-4588)`

### All-skipped vs all-failed fatal distinction

When nothing compiled, the fatal error message distinguishes 'this agent's libyara cannot run these rules' (skips but no failures, and the available module list is quoted) from 'these rules are broken'. Both abort the scan.

- **Control:** not configurable — default `always on`
- **Observe:** stderr: `CRITICAL: YARA rule compilation failed: No rules could run on this endpoint: all N rule(s) need YARA modules this agent's libyara build does not provide (available: ...). This is an agent capability limit, not a rule syntax error.` followed by `Valid rules: 0, Failed rules: 0, Skipped: N`; same text as `FINAL_COMPILATION_ERROR:` in `yara_processing_<run_id>.log`.
- **Source:** ``_compile_yara_rules` (4590-4606)`

### Combined-compile failure reporting

If the individually-validated rules nevertheless fail when compiled together as one namespaced ruleset, the error is recorded separately and re-raised unchanged.

- **Control:** not configurable — default `always on`
- **Observe:** `yara_processing_<run_id>.log`: `COMBINED_COMPILATION_ERROR: <exc>` — distinct from `FINAL_COMPILATION_ERROR`, and the only path where valid_rules_count > 0 yet no scan runs.
- **Source:** ``_compile_yara_rules` (4620-4623)`

### Rule-pack hash and scan_id derivation

The decoded rule text is SHA-256 hashed; the full digest is kept as `rule_hash` and its first 12 hex chars are embedded in a scan_id of the form `<hostname>_<run_id>_yara_<hash12>`, so the ruleset stays identifiable while every host and every re-run gets a distinct scan_id.

- **Control:** not configurable — default `sha256 of the UTF-8 decoded rule text; 12-char prefix in scan_id`
- **Observe:** `yara_processing_<run_id>.log`: `Scan ID: <host>_<run_id>_yara_<hash12> (rule hash: <hash12>...)`. `scan_summary_<run_id>.json` carries both `scan_id` and full `rule_hash`. Every uploaded event carries `scan_id`. Test criterion: two hosts running the identical pack must share the hash12 segment and differ in the rest.
- **Source:** ``ScanConfig.__init__` (2735-2744), summary record (2148-2153)`

### Rule/import census at initialization

Independently of compilation, the decoded pack is counted for rule declarations, import statements, and total character length, and reported as an initialization fact.

- **Control:** not configurable — default `always emitted`
- **Observe:** System log + webhook event `YARA Rules loaded: N rules, M imports` with data `{total_rules_found, import_statements, rule_content_length}` in `logs/system_<run_id>.log`. This is the pre-compile count — comparing it against `valid_rules` in the summary JSON is the direct measure of pack attrition.
- **Source:** ``main` (6196-6206)`

### Brace-balance sanity check

**⚠ OBSERVABILITY GAP**  
A structural pre-flight counts `{` and `}` across the whole pack and warns if they are unequal (a common symptom of a truncated paste or a lost rule tail). Advisory only — it does not block compilation.

- **Control:** not configurable — default `always run`
- **Observe:** stderr line `BRACE MISMATCH DETECTED!` (a `logging.warning`). The accompanying per-line detail (`Total lines`, `Found N rule declarations`, first/last rule names with line numbers, `Total braces: X opening, Y closing`) is `logging.info` and is suppressed — setup_logging pins the root logger at WARNING with no handlers, so INFO from the compile path is written nowhere.
- **Source:** ``_debug_rule_analysis` (5224-5265), `setup_logging` (5882-5896)`

### Console-noise caps on rule diagnostics

Only the first 10 skipped rules and the first 10 failed rules produce a console/warning line; the per-50-rule compile progress line is emitted at INFO and therefore suppressed. Full detail always goes to the yara_processing log and to failed_rules/.

- **Control:** hardcoded thresholds (`skipped_count <= 10`, `failed_rules_count <= 10`, `i % 50 == 0`) — default `10 skipped / 10 failed warnings; progress every 50 rules (suppressed)`
- **Observe:** With a 30-broken-rule pack: exactly 10 `Failed rule <name>: <first 100 chars>` lines on stderr, but 30 `=== RULE COMPILATION FAILURE #n ===` blocks in `yara_processing_<run_id>.log` and 30 `failed_rule_*.yar` files. Test criterion: never count stderr lines to get a rule tally.
- **Source:** ``_compile_yara_rules` (4508, 4524, 4536, 4557)`

### Rule-count propagation into scan telemetry

Compilation results are carried into the live and final telemetry surfaces: the scanner-init system event, each `scan_status` event, the scan-configuration statistics event, and the comprehensive final report (where a rule failure rate also subtracts up to 30 points from a computed `efficiency_score`).

- **Control:** not configurable — default `always emitted when telemetry uploads are on (UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA both True by default)`
- **Observe:** `YaraScanner initialized with N workers` event data `{valid_rules, failed_rules}`; `scan_status` event fields `valid_rules_count` / `failed_rules_count`; `Scan configuration established` statistics event fields `yara_rules_count` / `failed_rules_count`; `comprehensive_final_report` block `rule_compilation: {valid_rules_loaded, failed_rules_skipped, total_rules_processed, compilation_success_rate}` plus `efficiency_score`. Note: none of these carry `skipped_rules_count` — only the SCAN_RESULT line and `scan_summary_<run_id>.json` do.
- **Source:** `(4293-4299), `ScanStatusUploader.upload_scan_status` (3533-3537), `scan_system` (5735-5739), `upload_final_comprehensive_report` (5929-5936, 5964-5967)`

### Diagnostic-preserving cleanup suppression  <sub>all (script is .bat on Windows, .sh elsewhere)</sub>

The scheduled post-scan cleanup (which renames `alert/*.txt` to `*.alert`) is skipped entirely when the run had errors and compiled zero valid rules, so the diagnostic state is left intact.

- **Control:** not configurable — default `suppression triggers on `error_logger.has_errors and valid_rules_count == 0` (also on a >50% error-log ratio)`
- **Observe:** `logs/system_<run_id>.log`: `Critical errors detected - skipping cleanup to preserve diagnostic data`, and no `cleanup_script.bat` / `cleanup_script.sh` is written under scanner_dir.
- **Source:** ``CleanupManager.schedule_final_cleanup` (4039-4058)`

### YARA runtime version banner  <sub>all (values are the per-agent embedded Python/libyara build)</sub>

The processing log opens with the interpreter and engine identity: Python version, full platform string, and `yara.__version__` (or `Unknown` when the attribute is absent) — the ground truth for why a module probe or a rule syntax behaves differently on one endpoint than another.

- **Control:** not configurable — default `always written as the first four lines`
- **Observe:** Head of `logs/yara_processing_<run_id>.log`: `=== YARA Processing Log ===`, `Python Version: ...`, `Platform: ...`, `YARA Version: ...`. Also duplicated in the `scanner_initialization` event data as `yara_version` / `python_version`, and in the final report's `system_info`.
- **Source:** ``ErrorLogger._setup_error_logger` (1222-1226), `main` init_data (6169-6170)`

---

# Scan Targeting, Traversal & Skipping

*Deciding what gets opened — and proving what didn’t.*

### Explicit scan folder parameter

The `scan_folder` entry-point argument restricts the scan to operator-named directories instead of the whole machine. Any value other than the literal "default" (case-insensitive) switches the run into limited scope.

- **Control:** main(yarafile, scan_folder, alert_severity) -> ScanConfig.scan_folder; gate is `if self.scan_folder and self.scan_folder.lower() != "default"` (line 2945) — default `None (no argument) -> whole-machine default discovery`
- **Observe:** system log line `SCAN SCOPE: Limited to specified targets: [...]` (line 6191) vs `SCAN SCOPE: Full system scan (light profile throttling enabled)`; `scan_targets` in the `scanner_initialization` event (line 6172); `scan_folder` and `scan_targets` keys in logs/scan_summary_<run_id>.json
- **Source:** `ScanConfig.__init__ lines 2707, 2945-2975; main() lines 6190-6195`

### Comma-separated multi-target list

One `scan_folder` value may carry several locations separated by commas, so a single run covers multiple scopes/partitions (e.g. "C:\\Users,D:\\Shares" or "/opt/data, /srv/www"). Each entry is whitespace-stripped and stripped of surrounding double/single quotes, empty entries dropped.

- **Control:** `self.scan_folder.split(",")` with `p.strip().strip('"').strip("'")` (line 2950) — default `not configurable; always applied when scan_folder != "default"`
- **Observe:** info log `Scan limited to N folder(s): [...]` (line 2968) where N > 1; `target_count` in the `Scan configuration established` statistics event (line 5734); one `Scanning target i/N: <path>` system line per entry (line 5786); `scan_targets` array in scan_summary_<run_id>.json
- **Source:** `ScanConfig.__init__ lines 2945-2969`

### Per-target validation with independent rejection

Each requested target is tested with `os.path.isdir(p)`; valid ones are converted with `os.path.abspath` and de-duplicated (`if ap not in valid`), invalid ones are collected and reported. Invalid entries do not abort the run — the scan proceeds with the survivors.

- **Control:** not configurable (ScanConfig.__init__ validation block) — default `always on`
- **Observe:** warning log `Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]` (line 2964); the surviving list appears in `Scan limited to N folder(s)`
- **Source:** `ScanConfig.__init__ lines 2952-2966`

### Hard failure when no requested target is valid

If every comma-separated entry fails the isdir test, ScanConfig raises ValueError rather than silently falling back to a full-machine scan — a typo'd path cannot turn into an unintended whole-disk walk.

- **Control:** `raise ValueError(f"No valid scan directory among the specified scan folder(s): {requested}")` (line 2961) — default `always on`
- **Observe:** main() returns the `Scan failed: ... \| Critical error occurred` line and stderr carries `SCAN_STATUS: ERROR`; no scan_summary JSON with outcome=completed is produced
- **Source:** `ScanConfig.__init__ lines 2960-2962; main() except block lines 6466-6543`

### Windows whole-machine default target discovery  <sub>windows</sub>

With no scan_folder (or "default"), Windows targets are every fixed mount: `psutil.disk_partitions(all=False)` mountpoints normalised to a trailing-backslash root, then every bit set in `kernel32.GetLogicalDrives()` as `<L>:\\`, then a bare A-Z isdir probe if both failed. Results are de-duplicated with `os.path.normcase(os.path.normpath(root))`, and fall back to `["C:\\"]` if nothing is discovered.

- **Control:** not configurable (ScanConfig._default_discover_targets) — default `all detected drive roots; fallback `["C:\\"]``
- **Observe:** info log `Light profile full-scope targets on Windows: ['C:\\', 'D:\\', ...]` (line 3027); same list as `targets`/`target_count` in the `Scan configuration established` event and as `scan_targets` in scan_summary_<run_id>.json
- **Source:** `ScanConfig._default_discover_targets lines 2980-3027`

### Linux default target discovery (privilege-aware)  <sub>linux</sub>

As root the default scope is the single target `/`. As non-root it is the readable subset of `["/home", "/tmp", "/opt", "/usr/local", "/var/tmp"]`, each filtered by `os.path.exists` + `os.path.isdir` + `os.access(target, os.R_OK)`; if none survive it falls back to `/` with a warning.

- **Control:** not configurable; branch on `os.geteuid() == 0` — default `root: ["/"]; non-root: readable subset of the five paths above`
- **Observe:** info log `Light profile default scope on Linux: full filesystem` (root, line 3037) or `Light profile default scope on Linux using accessible full-scan targets: [...]` (line 3052), or the warning `Light profile default scope fell back to '/' on Linux - many files may be inaccessible` (line 3048)
- **Source:** `ScanConfig._default_discover_targets lines 3029-3054`

### macOS default target discovery (privilege-aware)  <sub>macos</sub>

As root the default scope is `/` (with an explicit note that SIP still restricts /System/). As non-root it is the readable subset of `[expanduser("~"), "/Applications", "/Users/Shared", "/usr/local", "/opt"]`; if none are readable it falls back to the user home directory alone.

- **Control:** not configurable; branch on `os.geteuid() == 0` — default `root: ["/"]; non-root: readable subset of the five paths above; fallback [expanduser("~")]`
- **Observe:** info logs `Light profile default scope on macOS: full filesystem` + `Note: SIP restrictions still apply to /System/` (lines 3064-3065), or `Light profile default scope on macOS using accessible full-scan targets: [...]` (line 3073), or `Light profile default scope on macOS fell back to the user home directory only` (line 3078)
- **Source:** `ScanConfig._default_discover_targets lines 3056-3080`

### Unknown-platform target fallback

**⚠ OBSERVABILITY GAP**  
On a platform that is neither Windows, Linux nor Darwin, default discovery returns an empty target list; the scanner-side getter then substitutes `["/"]` (or Windows discovery on Windows) so the run still has a target rather than scanning nothing.

- **Control:** not configurable (`_default_discover_targets` else-branch; `YaraScanner._get_scan_targets` fallback) — default `discovery: []; _get_scan_targets fallback: ["/"]`
- **Observe:** warning log `Unknown platform - manual target specification required` (line 3084) plus `Using default Unix target: ['/']` via logging.info (line 5278)
- **Source:** `ScanConfig._default_discover_targets lines 3082-3084; YaraScanner._get_scan_targets lines 5267-5279`

### Excluded-target warning (requested target wholly skipped)

Before walking each target, the target path itself is run through `_is_special_file()`. If the operator explicitly asked for a path that the skip lists exclude wholesale (e.g. `%AppData%\Local\Temp`), the target is recorded in `self.excluded_targets` so the result line says "policy excluded this" instead of reporting an indistinguishable clean zero.

- **Control:** not configurable; `if self._is_special_file(target): self.excluded_targets.append(target)` (line 5794) — default `always on`
- **Observe:** error-log event `Requested scan target is excluded by the skip list, so nothing under it will be scanned: <path>` with data `{'reason': 'skip_list'}` (line 5796); the returned SCAN_RESULT line gains ` \| WARNING: N requested target(s) EXCLUDED by the skip list, nothing under them was scanned: ...` (lines 6444-6450, capped at the first 3 names + " ..."); `excluded_targets` array in scan_summary_<run_id>.json (line 6585)
- **Source:** `YaraScanner.scan_system lines 5790-5800; main() lines 6440-6463; line 4270 (`self.excluded_targets = []`)`

### Non-root system-path pre-flight advisory  <sub>linux, macos</sub>

When not running as root, requested scan folders are checked against privileged roots — `['/System', '/Library', '/private/var/db']` on macOS, `['/etc', '/boot', '/var/log', '/root']` on Linux — and an advisory is logged. It is advisory only: the scan still runs and simply hits permission errors per file.

- **Control:** not configurable; `system_paths` literals at lines 6072-6074, matched against the comma-split scan_folder — default `always evaluated on non-root Linux/macOS`
- **Observe:** system log lines `ERROR: System path scan requires elevated privileges` plus `Either run as root (sudo) or grant Full Disk Access` / `Either run as root or choose a different scan path` (lines 6079-6083); separately a `privilege_status` webhook event with `{'running_as_root': false, 'recommended_action': 'run_as_sudo'}` (lines 6086-6100)
- **Source:** `main() lines 6070-6100`

### Cancellable explicit-stack directory walk

`_walk_cancellable` replaces `os.walk`: an explicit LIFO stack drives traversal, with `self.scan_active` checked before every directory pop and between every scandir entry, so cancellation latency is bounded by a single `os.scandir` call instead of os.walk's unbounded generator recursion. Contract matches os.walk(topdown=True) — it yields `(dirpath, dirnames, filenames)` and the caller may prune `dirnames` in place, because the stack is extended only after the yield.

- **Control:** not configurable — default `always used for traversal`
- **Observe:** on a cooperative cancel (control/cancel.flag), the run reaches its terminal state promptly: `status_uploader.set_status("cancelled")`, the SCAN_RESULT line begins `Scan cancelled (source=...)`, and scan_summary_<run_id>.json has `outcome: "cancelled"`. Measure wall time from flag write to process exit — the XDR-edition regression this replaced was a ~50s post-cancel tail
- **Source:** `YaraScanner._walk_cancellable lines 5537-5588; call site line 5802`

### Symlinked directories listed but never recursed

During scandir, a directory entry that is also a symlink is recorded in a `symlinked` set; it appears in the yielded `dirnames` (so callers see it) but is not pushed onto the traversal stack. This is the equivalent of `os.walk(followlinks=False)` and prevents symlink-loop traversal.

- **Control:** not configurable — default `always on (no follow-links option exists)`
- **Observe:** create a directory symlink pointing at a tree with a known-matching file, inside an otherwise clean scan folder; the file must not be scanned twice and the loop must not hang. Files under the link contribute nothing to `files_scanned` in the final `SCAN COMPLETED \| ... Files: N scanned` statistics line
- **Source:** `YaraScanner._walk_cancellable lines 5560, 5567-5570, 5584-5588`

### Unreadable directory entry demoted to a file

If `entry.is_dir()` raises OSError while classifying a scandir entry, the entry is appended to `filenames` rather than dropped, so it flows through the normal per-file error path and is accounted for instead of vanishing silently.

- **Control:** not configurable — default `always on`
- **Observe:** such an entry produces a per-file skip with a bounded `Scan error (<ExceptionType>)` / `File does not exist` / `No read permission` key in the `skip_breakdown` of the `comprehensive_final_report` event and in the `Skip reasons: ...` statistics line
- **Source:** `YaraScanner._walk_cancellable lines 5573-5576`

### Unreadable directory tolerated, subtree abandoned

`PermissionError`, `FileNotFoundError`, `NotADirectoryError` and any other `OSError` raised by `os.scandir` on a directory cause that directory to be skipped (`continue`) without aborting the walk — a permission-denied system directory cannot kill a full-machine scan.

- **Control:** not configurable — default `always on`
- **Observe:** a non-root Linux/macOS full-scan completes (SCAN COMPLETED statistics line) despite unreadable roots; note that these directories produce NO skip_reasons entry, so their files are invisible in the books — a deliberate asymmetry worth asserting
- **Source:** `YaraScanner._walk_cancellable lines 5577-5580`

### Junction / reparse-point detection  <sub>all (different implementation on Windows)</sub>

`_is_junction_or_symlink(path)` identifies redirection points: on Windows it calls `kernel32.GetFileAttributesW` and tests `FILE_ATTRIBUTE_REPARSE_POINT (0x400)` (so junctions, not just symlinks, are caught); on every other platform it is `os.path.islink(path)`.

- **Control:** not configurable — default `always on`
- **Observe:** file-level hits increment `junction_skips` in the `Scan Progress` statistics event metrics and `junction_skips` / `path_deduplication_ratio` in the final statistics line data (lines 5375-5377)
- **Source:** `_is_junction_or_symlink lines 625-637`

### Per-platform problematic-junction skip list  <sub>all (list differs per platform)</sub>

`_should_skip_junction` only skips a reparse point when its path matches a platform list, so ordinary user symlinks are still followed. Windows: any path containing `documents and settings`, `application data`, `local settings`, `my documents`, `default user`, `all users` (lowercased substring). macOS: paths starting with `/etc`, `/tmp`, `/var`. Linux: paths starting with `/proc/self/fd`, `/proc/self/task`.

- **Control:** literal lists inside `_should_skip_junction` (lines 672-682); not configurable — default `the six Windows names / three macOS prefixes / two Linux prefixes above`
- **Observe:** file hits are counted under skip reason `Junction/symlink skip` in `skip_breakdown` and increment `junction_skip_count`; on Windows, scanning `C:\Users\<u>` must not descend the legacy `Application Data` junction (no duplicate matches from the same real file)
- **Source:** `_should_skip_junction lines 665-682`

### Directory-level junction pruning during the walk

After each yielded directory, `dirs[:] = [d for d in dirs if not _should_skip_junction(os.path.join(root, d))]` prunes matching junction subdirectories in place, which the stack-based walk respects. Note this prune is silent — pruned subtrees contribute nothing to any counter.

- **Control:** not configurable — default `always on`
- **Observe:** absence of any file path under a pruned junction in alerts_<run_id>.log / evidence file_mapping, with no corresponding increase in `files_skipped` (contrast with the file-level junction skip, which is counted)
- **Source:** `YaraScanner.scan_system line 5822`

### File-level junction skip, counted

Each candidate file is tested with `_should_skip_junction(path)` before it is counted as found; a hit increments `files_skipped`, `skip_reasons["Junction/symlink skip"]` and `junction_skip_count`, and the file is never enqueued (it does not count toward `total_files_found` either).

- **Control:** not configurable — default `always on`
- **Observe:** `Junction/symlink skip` key in the `Skip reasons: ...` statistics line (line 5411) and in `file_processing.skip_breakdown` of the `comprehensive_final_report` event (line 5917); `junction_skips` in `Scan Progress` metrics
- **Source:** `YaraScanner.scan_system lines 5830-5835`

### Real-path deduplication (present but disabled)  <sub>all (case folding differs: Windows always lowercases, macOS lowercases only when `_is_case_sensitive_fs()` is False, Linux preserves case)</sub>

`scan_file` can resolve each file with `_get_real_path()` (realpath + platform-appropriate case folding) and refuse a path whose real target was already scanned, returning `"Junction/symlink duplicate"`. The feature is gated on `config.track_real_paths`, which is hardcoded False in this edition, so the dedup set stays empty.

- **Control:** `self.track_real_paths = False` (line 2782) — hardcoded, no env var — default `False (deduplication OFF)`
- **Observe:** negative assertion: `unique_real_paths` in `Scan Progress` metrics and `unique_paths_scanned` in the final statistics data are always 0, and `Junction/symlink duplicate` never appears in `skip_breakdown`. If either becomes non-zero the flag was flipped
- **Source:** `ScanConfig line 2782; YaraScanner.scan_file lines 4874-4890; _get_real_path lines 640-662; counters lines 4262, 5350, 5376`

### Skip by file extension (disk-image containers)

**⚠ CONTROL GAP**  
`skip_extensions` is a set matched with `portable_path.endswith(ext)` against the lowercased, forward-slash-normalised path — whole container images are never opened, on any platform.

- **Control:** `self.skip_extensions` (line 2790); not configurable — default `{".iso", ".img", ".dmg", ".vmdk", ".vhd", ".vhdx", ".qcow", ".qcow2", ".sparsebundle"}`
- **Observe:** skip reason `Special system file` in `skip_breakdown` (the walk-loop attribution for any `_is_special_file` hit at file level); drop a 1-byte `test.iso` containing a matching string into the scan folder and assert zero matches for it
- **Source:** `ScanConfig line 2790-2792; YaraScanner._is_special_file lines 5014-5015; walk-loop attribution lines 5840-5844`

### Skip by exact filename

**⚠ CONTROL GAP**  
`skip_filenames` is matched against `os.path.basename(portable_path)` (lowercased), an exact-equality check rather than a substring or extension match.

- **Control:** `self.skip_filenames` (line 2793); not configurable — default `{".ds_store", "thumbs.db", "desktop.ini"}`
- **Observe:** skip reason `Special system file` in `skip_breakdown`; macOS additionally re-checks `.ds_store` in its own branch (line 5111)
- **Source:** `ScanConfig line 2793; _is_special_file lines 5011-5013`

### Skip by bounded path fragment

**⚠ CONTROL GAP**  
`skip_path_fragments` are build/VCS/cache directory names in bounded `/name/` form, matched two ways: as a substring anywhere in the path, OR via `portable_path.endswith(fragment.rstrip("/"))` so that the excluded directory when it IS the walk root (which arrives with no trailing separator) also matches. Comparison is on the lowercased forward-slash `portable_path`, so it is case-insensitive and separator-agnostic on all platforms.

- **Control:** `self.skip_path_fragments` tuple (line 2794); not configurable — default `("/node_modules/", "/__pycache__/", "/.git/", "/.svn/", "/.hg/", "/.venv/", "/venv/", "/.pytest_cache/", "/.mypy_cache/", "/.gradle/", "/.yarn/cache/", "/.npm/", "/library/caches/", "/appdata/local/temp/", "/appdata/local/packages/")`
- **Observe:** pointing scan_folder directly at e.g. `...\node_modules` triggers the excluded-target WARNING on the SCAN_RESULT line and `excluded_targets` in scan_summary JSON (this is exactly the bare-root case the tail match fixes); inside a larger scan, files under those directories land in `skip_reasons["Skipped directory"]`
- **Source:** `ScanConfig lines 2794-2810; _is_special_file lines 5034-5043`

### Browser caches deliberately NOT skipped

**⚠ CONTROL GAP**  
The four browser cache/profile fragments that used to be in `skip_path_fragments` (Chrome/Edge `User Data\Default\Cache`, `/mozilla/firefox/profiles/`, `/cache2/`) were removed on purpose: browser caches and profile directories are common malware staging areas, so skipping them was a detection blind spot.

- **Control:** absence of those entries in `skip_path_fragments` (documented at lines 2811-2817) — default `browser caches are scanned`
- **Observe:** place a matching test file under `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache` (Windows) or `~/.mozilla/firefox/<profile>/cache2` (Linux) and assert a match is reported in alerts_<run_id>.log and the `yara_match` events
- **Source:** `ScanConfig comment block lines 2811-2817 (contrast with the fragment tuple above)`

### Browser force-scan allowlist (macOS carve-out)  <sub>macos (fragments are macOS paths; the mechanism is platform-independent)</sub>

**⚠ CONTROL GAP**  
`force_scan_fragments` re-opens browser caches that the broad `/library/caches/` fragment and the macOS skip directories would otherwise bury. It is evaluated BEFORE the category skips and returns False (scan it). Matching is against `portable_path + "/"` so a directory root also matches, ensuring the directory is not pruned before its files are considered. Filename/extension skips above it still apply. Safari coverage is best-effort under TCC / Full Disk Access.

- **Control:** `self.force_scan_fragments` tuple (line 2823); not configurable — default `("/library/caches/google/chrome/", "/library/caches/chromium/", "/library/caches/microsoft edge/", "/library/caches/firefox/", "/library/caches/com.apple.safari/")`
- **Observe:** on macOS, plant a matching file under `~/Library/Caches/Google/Chrome/` and assert it produces a `yara_match` event and an alert-log entry, while a sibling under `~/Library/Caches/SomethingElse/` produces none
- **Source:** `ScanConfig lines 2819-2829; _is_special_file lines 5016-5033`

### Boundary skips the force-scan allowlist cannot override  <sub>all (paths are POSIX-shaped; effective on macOS/Linux)</sub>

**⚠ CONTROL GAP**  
`force_scan_never_under` is checked first: if the probe path contains any of these mount-boundary fragments, the allowlist is not applied at all. These exist to keep the scanner on this host (a Time Machine disk under /Volumes/ holds one browser-cache tree per snapshot), so the carve-out cannot turn into an unbounded walk over mounted, removable or network media.

- **Control:** `self.force_scan_never_under` tuple (line 2835); not configurable — default `("/volumes/", "/media/", "/mnt/", "/net/")`
- **Observe:** a browser-cache path under `/Volumes/<disk>/...` must still be skipped — assert no matches and no scanned files from that path even though the same relative path scans fine in the user's home; `/Volumes/` is also an anchor entry in `mac_skip_directory`
- **Source:** `ScanConfig lines 2830-2840; _is_special_file lines 5030-5033`

### Windows skip folders with component-boundary matching  <sub>windows</sub>

**⚠ CONTROL GAP**  
`win_skip_folder` holds absolute directory roots (vendor security agents, recycle bin, system volume information, the scanner's own dir). Each entry is lowercased and normalised at construction with a trailing-separator strip guarded by `len(p) <= 3` so a drive root is not reduced to a bare drive letter. Matching is `normalized_path == skip_folder or normalized_path.startswith(skip_folder + "\\")` — whole path components, so `c:\yara_scanner` does not swallow `c:\yara_scanner_backup\evil.dll`.

- **Control:** `self.win_skip_folder` (lines 2848-2888); the scanner's own directory comes from `YARA_SCANNER_DIR` — default `C:\ProgramData\Cyvera, C:\ProgramData\Microsoft Defender, C:\Program Files\Palo Alto Networks, C:\Program Files (x86)\Palo Alto Networks, C:\Program Files\Cyvera, C:\Program Files (x86)\Cyvera, C:\yara_scanner\, C:\$Recycle.Bin, C:\System Volume Information, plus self.scanner_dir`
- **Observe:** during a `C:\` scan, no file under those roots appears in alerts or file_mapping; the skipped subtrees are counted as `skip_reasons["Skipped directory"]`. Regression check: create `C:\yara_scanner_backup\<matching file>` and assert it IS still scanned
- **Source:** `ScanConfig lines 2846-2888; _is_special_file lines 5045-5058`

### Windows skip-drive mechanism  <sub>windows</sub>

Before the folder check, the target's drive letter (`os.path.splitdrive(...)[0].rstrip(":")` on the lowercased path) is tested against `win_skip_drive`, allowing whole volumes to be excluded. The list ships empty, so no drive is excluded by default.

- **Control:** `self.win_skip_drive = []` (line 2847); not configurable via env — default `[] (no drives skipped)`
- **Observe:** negative assertion: every discovered drive root in `Light profile full-scope targets on Windows: [...]` also appears with a non-zero `files_found` in its `Target scan completed` statistics event (unless genuinely empty)
- **Source:** `ScanConfig line 2847; _is_special_file lines 5046-5048`

### Linux skip directories  <sub>linux</sub>

**⚠ CONTROL GAP**  
`lin_skip_directory` holds absolute prefixes, each carrying a trailing "/". Matching is `normalized_path == skip_dir.rstrip("/") or normalized_path.startswith(skip_dir)`, so the bare directory root that the walk yields matches as well as its contents. Comparison stays on the case-preserved path because Linux filesystems are typically case-sensitive.

- **Control:** `self.lin_skip_directory` (lines 2891-2901); the scanner's own directory comes from `YARA_SCANNER_DIR` — default `/sys/, /proc/, /dev/, /run/, /tmp/.X11-unix/, /var/run/, /lost+found/, /media/, /opt/yara_scanner/, /opt/traps/, plus normpath(scanner_dir)+"/"`
- **Observe:** a root-privileged `/` scan produces zero scanned files under /proc and /sys; those directories' files land in `skip_reasons["Skipped directory"]` in the final `Skip reasons: ...` line and `file_processing.skip_breakdown`
- **Source:** `ScanConfig lines 2890-2901; _is_special_file lines 5060-5071`

### macOS skip directories with three matching semantics  <sub>macos</sub>

**⚠ CONTROL GAP**  
`mac_skip_directory` entries are all lowercased at construction (APFS is case-insensitive by default) and matched against the lowercased `portable_path` under three different rules chosen by the entry's shape: entries starting with "/" are ANCHORS (equality with the trailing slash stripped, or startswith) so `/System/` cannot match a user's `~/System/`; entries containing ".app/" are BUNDLE SUFFIXES matched as a plain substring with no leading separator, so `.app/Contents/Frameworks/` matches any application name; everything else is a FRAGMENT matched as `"/" + entry` anywhere in the path or via `endswith("/" + entry.rstrip("/"))` for the bare-root case.

- **Control:** `self.mac_skip_directory` (lines 2904-2938); the scanner's own directory comes from `YARA_SCANNER_DIR` — default `anchors: /System/, /private/var/{folders,db,root,vm,log}/, /private/tmp/, /dev/, /Volumes/, /.Spotlight-V100/, /.DocumentRevisions-V100/, /.fseventsd/, /.TemporaryItems/, /.Trashes/, /Library/Application Support/PaloAltoNetworks/Traps/, /Library/Logs/PaloAltoNetworks/Cortex XDR/, /Library/Developer/, /Library/Caches/, /Library/Logs/, /Applications/{Xcode,Android Studio,Docker,VMware Fusion,PyCharm CE,WebStorm,iMovie}.app/Contents/, scanner_dir; bundle suffixes: .app/Contents/Frameworks/, .app/Contents/Resources/, .app/Contents/_CodeSignature/; fragments: Library/Containers/, Library/Caches/, Library/Application Support/{Google,JetBrains,Code,Slack}/, Library/{Developer,Android,Python,Logs,Metadata,Group Containers}/, PycharmProjects/, WebstormProjects/, node_modules/, .venv/, venv/, __pycache__/, .pytest_cache/, .mypy_cache/, .gradle/, .android/, .dart_tool/, build/, dist/, .git/, .svn/, .idea/, .vscode/`
- **Observe:** a home-directory scan reports `skip_reasons["Skipped directory"]` covering `~/Library/Containers` and any `node_modules`, while a deliberately created `~/System/<matching file>` IS still scanned (anchor semantics); a matching file placed in any `Foo.app/Contents/Resources/` is skipped regardless of app name
- **Source:** `ScanConfig lines 2903-2938; _is_special_file lines 5073-5106`

### macOS AppleDouble and .DS_Store file skip  <sub>macos</sub>

After the directory checks, the macOS branch skips any basename starting with `._` (AppleDouble resource forks) and the exact name `.ds_store`.

- **Control:** literals in `_is_special_file` (lines 5108-5112); not configurable — default `always on for `._*` and `.ds_store``
- **Observe:** skip reason `Special system file` in `skip_breakdown`; no `._`-prefixed path ever appears in alerts_<run_id>.log
- **Source:** `_is_special_file lines 5108-5112`

### No directory skipping on unrecognised platforms  <sub>all (non-Windows/Linux/macOS)</sub>

**⚠ CONTROL GAP**  
`_is_special_file`'s final else-branch returns False, so on a platform that is not Windows/Linux/Darwin only the cross-platform checks (filename, extension, path fragments, force-scan rules, own log file) apply — there is no per-platform directory skip list.

- **Control:** `else: return False` (line 5117); ScanConfig sets `lin_skip_directory = []` and `mac_skip_directory = []` on that branch (lines 2940-2942) — default `no platform directory skips`
- **Observe:** negative test: skip_breakdown contains no `Skipped directory` entries attributable to platform lists
- **Source:** `ScanConfig lines 2940-2942; _is_special_file lines 5116-5117`

### Self-skip of the scanner's own directory and log file  <sub>all (path and case handling differ)</sub>

Two mechanisms keep the scanner from scanning its own artefacts: `self.scanner_dir` is appended to whichever platform skip list applies (covering logs/, control/, alert/, evidence/, failed_rules/ beneath it), and `_is_special_file` short-circuits on an exact match with `config.output_log` (`logs/scanner_<run_id>.log`), lowercased first on Windows.

- **Control:** `YARA_SCANNER_DIR` env var overrides the root; `self.output_log = os.path.join(self.logs_dir, f"scanner_{self.run_id}.log")` (line 2751) — default `scanner_dir = `C:\yara_scanner` (Windows), `/usr/local/yara_scanner` (macOS), `/opt/yara_scanner` (Linux)`
- **Observe:** a whole-machine scan reports zero scanned files under the scanner directory — no alert or evidence entry ever names a path under it, and no rule matches the scanner's own YARA rule text sitting in alert/*.txt
- **Source:** `ScanConfig lines 2676-2702, 2751, 2858, 2900, 2933; _is_special_file lines 5002-5008`

### Vendor security-agent path exclusions  <sub>all (different roots per platform)</sub>

**⚠ CONTROL GAP**  
Each platform excludes the endpoint-security vendor's own install/log roots so the scanner does not fight the agent it runs under: Windows enumerates the real Cyvera / Palo Alto Networks / Microsoft Defender install roots (deliberately as anchored roots, not a `cyvera` fragment, so an attacker-created `C:\Users\Public\cyvera` is NOT a blind spot); Linux excludes `/opt/traps/`; macOS excludes the Traps support directory and the Cortex XDR log directory.

- **Control:** entries inside `win_skip_folder` / `lin_skip_directory` / `mac_skip_directory`; not configurable — default `Windows: ProgramData\Cyvera, ProgramData\Microsoft Defender, Program Files[ (x86)]\Palo Alto Networks, Program Files[ (x86)]\Cyvera. Linux: /opt/traps/. macOS: /Library/Application Support/PaloAltoNetworks/Traps/, /Library/Logs/PaloAltoNetworks/Cortex XDR/`
- **Observe:** no path under those roots in alerts_<run_id>.log or evidence file_mapping during a full-machine scan; regression check on Windows — create `C:\Temp\cyvera\<matching file>` and assert it IS scanned and matched
- **Source:** `ScanConfig lines 2848-2878 (Windows, with the rationale comment), 2894-2899 (Linux), 2909-2912 (macOS)`

### Maximum file size cap

Files larger than the cap are not read: `if max_bytes and st.st_size > max_bytes: return False, "File too large"`. A value of 0 legitimately means "no size cap" (max_file_bytes becomes 0, which is falsy and disables the check); a negative value is rejected by `_env_number(minimum=0)` and falls back to the default, because a negative cap previously made every file fail the check while the scan still reported success.

- **Control:** `YARA_MAX_MB` env var -> `self.max_file_mb`; `self.max_file_bytes = max_file_mb * 1024 * 1024 if max_file_mb else 0` — default `64 (MB)`
- **Observe:** `max_file_size_mb` in the `Scan configuration established` statistics event (line 5736) and `max_file_mb` in the `scanner_initialization` event (line 6175); skip reason `File too large` in `skip_breakdown` / the `Skip reasons: ...` line. A bad value logs `Ignoring out-of-range YARA_MAX_MB=... (minimum 0) - using default 64`
- **Source:** `ScanConfig lines 2753-2757; _env_number lines 61-88; YaraScanner.scan_file lines 4884-4886`

### Non-regular-file rejection

After the size stat, `stat.S_ISREG(st.st_mode)` gates the match call, so FIFOs, device nodes, sockets and similar are never handed to libyara (reading them can block indefinitely).

- **Control:** not configurable — default `always on`
- **Observe:** skip reason `Not a regular file` in `skip_breakdown`; on Linux, scanning a folder containing a named pipe completes rather than hanging
- **Source:** `YaraScanner.scan_file lines 4880-4882`

### Existence and read-access pre-checks  <sub>all (scanner_uid recorded only on non-Windows)</sub>

Before any stat/match, `scan_file` checks `os.path.exists` and `os.access(file_path, os.R_OK)`. A permission failure additionally captures a permission record (mode, owner uid, scanner uid, and whether the path looks root-owned or under /etc, /boot, /var/log, /root) into `self.permission_denials` and a system log entry.

- **Control:** not configurable — default `always on`
- **Observe:** skip reasons `File does not exist` and `No read permission` in `skip_breakdown`; per-file `Permission denied: <path>` system log entries carrying `requires_root`, `owner_uid`, `file_mode` (lines 4851-4860)
- **Source:** `YaraScanner.scan_file lines 4842-4869`

### Second-line skip check inside the worker

`scan_file` re-runs `_is_special_file(file_path)` after the queue hand-off, so a path that was enqueued before a skip rule applied (or reached the queue by any other route) is still refused at scan time and reported as `Special system file`.

- **Control:** not configurable — default `always on`
- **Observe:** `Special system file` appearing in `skip_breakdown` from the worker path (distinguishable in the local logs from the walk-loop attribution, which increments the same key at line 5843)
- **Source:** `YaraScanner.scan_file lines 4871-4872; walk-loop counterpart lines 5840-5844`

### Bulk attribution of a skipped directory's files

When a walk root is excluded, the directory's file count is added in one shot: `self.files_skipped += len(files)` and `self.skip_reasons["Skipped directory"] += len(files)`. Subdirectories are NOT pruned — each arrives as its own root and contributes its own files, so a whole subtree is counted exactly once with no double-count. A bare `continue` here previously left skipped subtrees unaccounted for, making files_scanned + files_skipped irreconcilable and skip_rate read 0%.

- **Control:** not configurable — default `always on`
- **Observe:** `Skipped directory` key in `file_processing.skip_breakdown` and in the `Skip reasons: ...` statistics line; `skip_rate` in the final metrics (line 5374) should be non-zero on any full-machine scan
- **Source:** `YaraScanner.scan_system lines 5808-5820`

### Skip accounting and breakdown reporting

Every skip lands in `self.files_skipped` plus a labelled bucket in `self.skip_reasons` (a defaultdict(int)), incremented under `lock_counts`. The breakdown is emitted live and at the end, and `skip_rate` is computed as files_skipped / (files_scanned + files_skipped).

- **Control:** not configurable; live emission cadence is `YARA_PROGRESS_LOG_SECS` — default `progress interval 30 (seconds), clamped to >= 1`
- **Observe:** `Scan Progress \| Files: N scanned, M skipped \| ...` statistics events every interval (line 2043); `Skip reasons: <reason>(count), ...` statistics line with full `skip_breakdown` data at the end (lines 5408-5413); `file_processing.skip_breakdown` in the `comprehensive_final_report` event; `files_skipped` in scan_summary_<run_id>.json
- **Source:** `YaraScanner lines 4225-4226, 4716-4724; _log_final_results lines 5365-5413; LogManager.log_scan_progress lines 2026-2047; upload_final_comprehensive_report lines 5913-5919`

### Bounded per-file error labels in the skip breakdown

A per-file scan exception becomes the label `Scan error (<ExceptionType>)` rather than `str(exc)`. Both common error texts embed the absolute path, so raw messages made every errored file its own skip_reasons key — measured at 307,780 bytes for 5,000 errored files shipped to the tenant. The exception type is preserved so genuinely different failures stay distinguishable, and the word "error" is kept because the final report counts error reasons by that substring.

- **Control:** `_scan_error_reason(exc)`; not configurable — default `always on`
- **Observe:** `skip_breakdown` keys are of the form `Scan error (OSError)` / `Scan error (Error)` — cardinality stays small regardless of file count; `error_summary.scan_errors` in the completion summary sums every key containing "error" (line 6313). Full path and message remain in scan_errors_<run_id>.log
- **Source:** `_scan_error_reason lines 935-950; used at line 4980; consumed at line 6313`

### Per-target progress and throughput reporting

Each target is announced before it is walked and summarised after, with the file count discovered under it and the elapsed time. `files_per_target` is carried into cleanup. Note `target_files_found` counts files that survived the junction check but is incremented BEFORE the `_is_special_file` test, so it is a discovery count, not a scanned count.

- **Control:** not configurable — default `always on`
- **Observe:** system log `Scanning target i/N: <path>` with `{'target_index', 'target_path'}` (line 5785); critical statistics event `Target scan completed: <path>` with `files_found`, `scan_time_seconds`, `files_per_second` (lines 5852-5860)
- **Source:** `YaraScanner.scan_system lines 5776-5860`

### Scan-configuration disclosure event

Before workers start, the resolved targeting configuration is emitted as one statistics event and one webhook statistics_summary: the final target list, its length, worker count, the size cap, and rule counts.

- **Control:** not configurable — default `always emitted`
- **Observe:** statistics event `Scan configuration established` with `{'targets': [...], 'target_count': N, 'max_workers', 'max_file_size_mb', 'yara_rules_count', 'failed_rules_count'}` (lines 5730-5745); mirrored by the `scanner_initialization` event's `scan_targets` (line 6172) and by `scan_targets` in scan_summary_<run_id>.json
- **Source:** `YaraScanner.scan_system lines 5727-5745; main() lines 6164-6195`

### No-drop enqueue under backpressure

**⚠ CONTROL GAP**  
`_enqueue_scan_path` blocks with a 1s timeout and retries while `scan_active`, rather than dropping a discovered file when workers are saturated — traversal output and worker input cannot silently diverge. It only returns False on a genuine queue exception or on cancellation, and that False breaks the current directory's file loop.

- **Control:** queue size `YARA_QUEUE_SIZE` (default max_workers * 2, minimum 2, floor 2); backoff `YARA_QUEUE_BACKOFF_SECS` — default `queue size 4 with the default 2 workers; backoff 0.25 (seconds)`
- **Observe:** performance log `Scan queue saturated (N items) - backing off producer`, emitted on every 25th event (`queue_full_events % 25 == 1`, line 4811); reconcile `files_found` per target against `files_scanned + files_skipped` at the end
- **Source:** `YaraScanner._enqueue_scan_path lines 4803-4820; ScanConfig lines 2763-2765, 2789; call site line 5846`

### Case-folding policy for path matching  <sub>all (policy differs per platform)</sub>

Path comparison is deliberately case-folded per platform. `_is_special_file` lowercases the whole path on Windows and builds a lowercased forward-slash `portable_path` used by the cross-platform and macOS checks; the Linux branch stays on the case-preserved path. Skip lists are pre-folded at construction to match (`win_skip_folder` via `.lower()`, `mac_skip_directory` via a list comprehension). A separate `_is_case_sensitive_fs()` probe (writes and re-stats a temp file) governs macOS real-path folding.

- **Control:** not configurable — default `Windows and macOS case-insensitive matching; Linux case-sensitive`
- **Observe:** on Windows, `C:\PROGRAMDATA\CYVERA` and `C:\programdata\cyvera` are both skipped; on Linux, `/opt/Traps/` is NOT skipped while `/opt/traps/` is — assert via presence/absence in the alert log or the per-target files_found delta
- **Source:** `_is_special_file lines 4997-5010; ScanConfig lines 2885-2888, 2935-2938; _is_case_sensitive_fs lines 600-622; _get_real_path lines 640-662`

---

# Performance & Resource Management

*CPU governance, threading, queues, monitors.*

### CPU governor policy selection

Bounds the scanner's own CPU share rather than pausing on system CPU. Three policies: "headroom" (adaptive, leave a fixed share of the host free), "budget" (fixed ceiling on own share), "none" (disabled). Anything other than headroom/budget leaves `self.enabled = False`.

- **Control:** `CPU_GUARANTEE = (os.environ.get("YARA_CPU_GUARANTEE", "headroom").strip().lower() or "headroom")` (module constant, line 285); passed as `policy=` into `CpuGovernor(...)` in `YaraScanner.__init__` — default `"headroom"`
- **Observe:** performance_<run_id>.log / performance-type events contain `CPU governor \| policy=headroom target=..% own=..% others=..% ratio=..`, with the same fields as structured data (`policy`, `target`, `own`, `others`, `ratio`, `slept_secs`, `floor_hits`). Also echoed once at scan start in the system event "All monitoring systems activated" under key `cpu_policy`.
- **Source:** `class CpuGovernor; CPU_GUARANTEE; CpuGovernor.__init__ (`self.enabled = self.policy in ("headroom", "budget")`)`

### Headroom policy target computation

Under "headroom", the target own-share is `100 - headroom_pct - others`, where `others = max(0, system_pct - own)`. External load shrinks the scanner's own target instead of stopping it, which is what makes the governor structurally unable to stall.

- **Control:** `CPU_HEADROOM_PCT = _env_number("YARA_HEADROOM... (YARA_CPU_HEADROOM_PCT)", 30, minimum=0)` -> `headroom_pct` — default `30 (percent of host left free)`
- **Observe:** `target` in the `CPU governor \|` performance line: on an idle host with default 30 it sits near 70; drive unrelated load up and `others` rises while `target` falls by the same amount within one sample interval.
- **Source:** `CpuGovernor.compute_target; CpuGovernor.update (`others = max(0.0, float(system_pct) - own)`); CPU_HEADROOM_PCT`

### Budget policy fixed ceiling

Under "budget" the target is a constant share of the whole machine, independent of what other processes are doing — `compute_target` returns `self.budget_pct` and never consults `others`.

- **Control:** `CPU_BUDGET_PCT = _env_number("YARA_CPU_BUDGET_PCT", 25, minimum=0)`; active only when `CPU_GUARANTEE` is "budget" — default `25 (percent of host)`
- **Observe:** `CPU governor \| policy=budget target=25.0%` — `target` stays fixed for the whole scan while `others` varies. `floor_hits` stays 0 in this policy (the floor branch is only in the headroom path).
- **Source:** `CpuGovernor.compute_target (`if self.policy == "budget": return self.budget_pct`)`

### CPU floor and floor_hits counter

In headroom mode, when external load would push the computed target below the floor, the target is clamped to the floor and a counter increments — the scanner always keeps a minimum share, so it can never be starved to a stall by other load.

- **Control:** `CPU_FLOOR_PCT = _env_number("YARA_CPU_FLOOR_PCT", 5, minimum=0)` -> `floor_pct` — default `5 (percent of host)`
- **Observe:** `floor_hits` in the governor stats dict attached to the `CPU governor \|` performance event; `target` pinned at 5.0 while `others` is high. Reproduce by loading the host to >65% with unrelated work under default headroom=30.
- **Source:** `CpuGovernor.compute_target (`if target < self.floor_pct: self.floor_hits += 1; return self.floor_pct`); CpuGovernor.stats`

### Own-CPU normalisation across cores

psutil reports process CPU as a percentage of one core (a 2-thread scanner reads up to 200%). `normalise_own` divides by `cpu_count` so the governor's "own" is a share of the whole machine; without it the scanner would silently hold itself to 1/N of the configured budget.

- **Control:** `cpu_count` argument, defaulted to `os.cpu_count() or 1` — not exposed as an env var — default `os.cpu_count() (guard: `if self.cpu_count <= 0: return raw_pct`)`
- **Observe:** `own` in the `CPU governor \|` line should never exceed 100 and should be roughly `sum(per-core usage)/cores`. Cross-check against the concurrent `System Resources \| CPU: x%` performance line, which reports the raw (un-normalised) per-core process figure — on an N-core box the governor's `own` should be about 1/N of it.
- **Source:** `CpuGovernor.normalise_own; CpuGovernor.update (`own = self.normalise_own(own_raw_pct)`)`

### Proportional sleep-ratio controller (GAIN, RATIO_MAX)

Each sample adjusts the sleep ratio by `GAIN * (own - target)` and clamps it to [0, RATIO_MAX]. The ratio is the multiplier applied to work time to get sleep time; RATIO_MAX 20 is roughly a 5% duty floor and bounds a runaway error term.

- **Control:** Class constants, not configurable: `GAIN = 0.05`, `RATIO_MAX = 20.0` — default `GAIN 0.05, RATIO_MAX 20.0; `sleep_ratio` starts at 0.0`
- **Observe:** `ratio` field in the `CPU governor \|` performance events — 0.0 on an unloaded host (no pacing at all), climbing in 0.05-per-error-point steps as `own` exceeds `target`, never above 20.0.
- **Source:** `CpuGovernor.GAIN, CpuGovernor.RATIO_MAX, CpuGovernor.update (`ratio = self.sleep_ratio + (self.GAIN * error)`; `max(0.0, min(self.RATIO_MAX, ratio))`)`

### pace() — post-work proportional sleeping with a per-call cap

Sleeps `work_secs * sleep_ratio`, capped at PACE_CAP_SECS per call, and accumulates the total. Proportional sleeping keeps the slowdown factor stable across file sizes and machine speeds; the cap keeps any single pause short so cancellation and shutdown stay responsive. Returns 0.0 immediately when disabled or ratio is 0.

- **Control:** `PACE_CAP_SECS = 1.0` class constant, not configurable — default `1.0 s maximum per pace() call`
- **Observe:** `slept_secs` in the governor stats dict (cumulative pacing time for the run). Wall-clock scan duration vs. `files_scanned` will diverge from an unthrottled baseline in proportion to it.
- **Source:** `CpuGovernor.pace (`secs = min(self.PACE_CAP_SECS, max(0.0, float(work_secs) * ratio))`; `self.slept_total += secs`)`

### pace() call site is AFTER the YARA match, not before

The governor samples immediately before `rules.match()` and paces immediately after it, using the measured duration of that match. This is the fix for the old design, which gated BEFORE the work on a system-CPU threshold and could park indefinitely without ever doing any work.

- **Control:** not configurable (control flow in scan_file) — default `n/a`
- **Observe:** Every scanned file makes forward progress even under heavy external load: `files_scanned` in the periodic "Scan Progress" statistics events keeps rising while `ratio` is non-zero. A run that stalls with 0 files scanned and a non-zero ratio would be a regression.
- **Source:** `YaraScanner.scan_file: `self._sample_governor()` / `_work_started = time.time()` / `matches = self.rules.match(...)` / `self.cpu_governor.pace(time.time() - _work_started)``

### Governor sampling cadence (rate limit)

`_sample_governor()` is called on every file (and on every queue-full backoff) but only re-reads CPU once the configured interval has elapsed, so psutil is not sampled per file.

- **Control:** `self.throttle_check_interval_secs = _env_number("YARA_CPU_SAMPLE_SECS", 0.5, minimum=0)` in ScanConfig — default `0.5 seconds`
- **Observe:** Frequency of `CPU governor \|` performance lines is bounded by this interval combined with the emit policy below; with a debug build, `last_governor_sample` advances at most every 0.5 s. minimum=0 is deliberate — a negative value would make the check always true and sample psutil on every file.
- **Source:** `YaraScanner._sample_governor (`if (now - self.last_governor_sample) < self.config.throttle_check_interval_secs: return`); ScanConfig.throttle_check_interval_secs`

### Governor fail-open when CPU cannot be read

If psutil raises while reading process or system CPU, the governor disables itself permanently for the run and the scan continues unthrottled — deliberately preferring a fast scan over guessing. Also fails open at construction: if `psutil.Process()` priming raises, `_governor_proc` is None and `_sample_governor` returns immediately.

- **Control:** not configurable — default `fail-open (enabled=False on error)`
- **Observe:** One performance log line: `CPU governor disabled - could not read CPU (<err>). Scan continues unthrottled.` and no further `CPU governor \|` lines for the rest of the run.
- **Source:** `YaraScanner._sample_governor `except Exception as e: self.cpu_governor.enabled = False ...`; YaraScanner.__init__ `except Exception: self._governor_proc = None``

### psutil CPU-reading priming

psutil's first `cpu_percent(interval=None)` on a new Process always returns 0.0, so the scanner primes both the process handle and the system-wide reading once at construction and reuses the long-lived handle, ensuring the governor's first real sample is meaningful.

- **Control:** not configurable — default `always on`
- **Observe:** The first `CPU governor \|` line of a run reports a non-zero `own` on a busy scan (a regression would show `own=0.0` on the first sample). Same pattern is used for the progress heartbeat's `_progress_proc`.
- **Source:** `YaraScanner.__init__ (`self._governor_proc = psutil.Process(); self._governor_proc.cpu_percent(interval=None); psutil.cpu_percent(interval=None)`)`

### Governor telemetry emission policy (change threshold + heartbeat)

A governor line is emitted when the sleep ratio moves by >= 0.25 since the last emission OR when the heartbeat interval has elapsed since the last emission — change-only emission produced a single line for a whole scan on an idle host, which is exactly the case a customer wants evidence for.

- **Control:** `GOVERNOR_HEARTBEAT_SECS = _env_number("YARA_GOVERNOR_HEARTBEAT_SECS", 30, minimum=0)`; the 0.25 change threshold is hardcoded — default `30 seconds; change threshold 0.25`
- **Observe:** On an idle host you should see a steady ~1 `CPU governor \|` performance event per 30 s for the scan's duration, even with `ratio=0.0`. Count events over a known scan duration to verify.
- **Source:** `YaraScanner._sample_governor (`changed = ... abs(s_["ratio"] - self._last_governor_emit) >= 0.25`; `heartbeat = (now - self._last_governor_emit_at) >= GOVERNOR_HEARTBEAT_SECS`)`

### Governor sampling during producer backpressure

When the scan queue is full the producer calls `_sample_governor()` on each backoff iteration, so CPU readings and the ratio keep updating during phases where no file is being matched by the producer thread.

- **Control:** not configurable — default `always on (subject to the sampling rate limit)`
- **Observe:** `CPU governor \|` lines continue to appear interleaved with `Scan queue saturated (...)` lines on a scan where discovery outruns the workers.
- **Source:** `YaraScanner._enqueue_scan_path (`except Full: ... self._sample_governor(); time.sleep(self.config.queue_backoff_secs)`)`

### Worker thread pool with a hard cap of 2

**⚠ CONTROL GAP**  
Scan workers are `ScanWorker-N` daemon threads. The configured worker count is clamped to at most 2 regardless of request or core count (`max(1, min(2, configured_workers))`); the pre-clamp default is 1 on <=2-core hosts, else 2.

- **Control:** `configured_workers = _env_number("YARA_THREADS", default_workers, cast=int, minimum=1)`; `self.max_workers = max(1, min(2, configured_workers))` — default `1 worker if `os.cpu_count() <= 2`, otherwise 2; hard ceiling 2 even if YARA_THREADS is larger`
- **Observe:** System event "YaraScanner initialized with N workers" with `max_workers` in its data; init event data `max_workers`; "All monitoring systems activated" `worker_threads`; per-tick `active_workers` in Scan Progress events; thread names ScanWorker-1/ScanWorker-2 in "Worker <name> started/stopped" system events; `worker_threads_used` in the final summary payload.
- **Source:** `ScanConfig.__init__ (`default_workers = 1 if cpu_count <= 2 else 2`); YaraScanner.scan_system (`for i in range(self.config.max_workers): threading.Thread(target=self._worker, name=f"ScanWorker-{i+1}", daemon=True)`)`

### Worker startup timing event

Time to spawn all worker threads is measured and reported as a critical (direct-send, not queued) performance event.

- **Control:** not configurable — default `always emitted`
- **Observe:** Performance event `Worker thread startup completed in X.XX seconds` with data `{worker_startup_time_seconds, workers_started}`; sent via `log_performance_critical` so it lands even if the async queue is backlogged.
- **Source:** `YaraScanner.scan_system (`worker_startup_time = time.time() - worker_start_time`; `log_performance_critical`)`

### Bounded scan queue

**⚠ CONTROL GAP**  
File paths are handed to workers through a `Queue` with a fixed maxsize, which is what makes memory usage independent of directory size — discovery cannot race ahead and buffer a whole filesystem's worth of paths.

- **Control:** `self.scan_queue_size = max(2, _env_number("YARA_QUEUE_SIZE", self.max_workers * 2, cast=int, minimum=2))` — default ``max_workers * 2` (i.e. 4 with 2 workers, 2 with 1 worker); floor 2`
- **Observe:** `scan_queue_size` in the initialization event data; `queue_size` field in every Scan Progress statistics event (and in the flattened progress payload) — it must never exceed the configured size.
- **Source:** `ScanConfig.scan_queue_size; YaraScanner.__init__ (`self.scan_queue = Queue(maxsize=self.config.scan_queue_size)`)`

### Producer backpressure on a full queue (never drops files)

`_enqueue_scan_path` blocks with a 1 s put timeout and retries in a loop rather than dropping paths: on `Full` it counts the event, samples the governor, sleeps the backoff interval and retries, exiting only if `scan_active` goes false.

- **Control:** `self.queue_backoff_secs = _env_number("YARA_QUEUE_BACKOFF_SECS", 0.25, minimum=0)`; put timeout 1.0 s is hardcoded — default `0.25 s backoff per retry`
- **Observe:** Performance log line `Scan queue saturated (N items) - backing off producer`, emitted on the 1st, 26th, 51st... full event (`if self.queue_full_events % 25 == 1`). Correlate with `queue_size` sitting at the configured maximum in Scan Progress events.
- **Source:** `YaraScanner._enqueue_scan_path; `self.queue_full_events` counter; ScanConfig.queue_backoff_secs`

### Worker get timeout / graceful exit checks

Workers block on `scan_queue.get(timeout=5.0)` so the `while self.scan_active` condition and the `None` sentinel are re-evaluated regularly instead of blocking forever on an empty queue; `Empty` simply continues the loop.

- **Control:** hardcoded 5.0 s in `_worker`. (The module constant `WORKER_GET_TIMEOUT_SECS = 2.0` governs the statistics uploader's queue, not the scan workers.) — default `5.0 s`
- **Observe:** After discovery ends, workers exit within roughly one timeout of the sentinel being posted; visible as "Worker ScanWorker-N stopped" system events shortly after "Initiating worker thread cleanup".
- **Source:** `YaraScanner._worker (`fp = self.scan_queue.get(timeout=5.0)`; `except Empty: continue`); WORKER_GET_TIMEOUT_SECS (line 130) used at line 3619`

### Sentinel-based worker shutdown with bounded joins

**⚠ CONTROL GAP**  
Cleanup posts one `None` sentinel per worker (1 s put timeout each), then joins each thread with a 5 s timeout, counting successes and timeouts and continuing regardless — a stuck worker cannot hang the run.

- **Control:** not configurable (per-thread join timeout 5 s, sentinel put timeout 1 s) — default `5 s per worker join`
- **Observe:** System events "Initiating worker thread cleanup" and "Waiting for workers to terminate (max 30 seconds)"; performance event `Worker cleanup: N stopped, M timed out in X.Xs`; if any thread survives, an error event `Threads did not terminate: [names]`.
- **Source:** `YaraScanner._perform_enhanced_cleanup (`for _ in range(self.config.max_workers): self.scan_queue.put(None, timeout=1.0)`; `t.join(timeout=5)`)`

### Per-worker throughput reporting every 100 files

Each worker emits its own throughput/error-rate line every 100 successfully processed files, computed from its rolling processing-time list.

- **Control:** hardcoded `files_processed % 100 == 0` — default `every 100 files per worker`
- **Observe:** Performance event `Worker Performance \| ScanWorker-N \| Files: X \| Avg Time: Y.Yms \| Error Rate: Z.Z%` with data `{worker_id, files_processed, avg_processing_time_ms, error_rate_percent}`.
- **Source:** `YaraScanner._worker; LogManager.log_worker_performance`

### Per-worker processing-time ring buffer

Per-file processing durations are recorded per worker and trimmed to the last 100 entries, so the averages stay recent and the structure cannot grow with the file count.

- **Control:** hardcoded cap of 100 samples per worker — default `100`
- **Observe:** Worker exit system event "Worker <id> stopped" carries `average_processing_time_ms` derived from at most the last 100 files; also aggregated into the final worker-performance summary (`files_processed` per worker capped at 100 there).
- **Source:** `YaraScanner.scan_file `finally:` (`self.worker_processing_times[worker_id].append(processing_time)`; `if len(...) > 100: ... [-100:]`)`

### Process priority lowering (CPU and I/O)  <sub>all (branches differ: Windows / Linux / macOS)</sub>

Best-effort priority de-prioritisation at startup so interactive user activity wins: Windows sets BELOW_NORMAL_PRIORITY_CLASS; POSIX raises nice to at least 10 (never lowers an already-higher nice, via `max(int(current_nice), 10)`); Linux additionally sets ionice to best-effort class, level 7. Every step is individually try/except'd and records an `*_error` key instead of failing the scan.

- **Control:** not configurable — applied unconditionally in main() — default `Windows: below_normal; Linux/macOS: nice=max(current,10); Linux only: ionice best_effort:7`
- **Observe:** System event "Applied light profile process priority tuning" whose data contains `cpu_priority` ("below_normal" or "nice=10") and, on Linux, `io_priority: "best_effort:7"` — or `cpu_priority_error`/`io_priority_error`. Cross-check live with Task Manager priority column (Windows) or `ps -o ni` / `ionice -p` (Linux).
- **Source:** `_apply_light_process_priority(); called in main() right after LogManager construction`

### Optional performance monitor (StatisticsManager background thread)  <sub>all (io_counters skipped on Darwin: `if platform.system() == "Darwin": self.initial_io_counters = None`)</sub>

A daemon thread sampling process CPU, RSS, disk and network counters every 5 s into a bounded history, updating peak/average metrics and logging a detail line every 6th sample (~30 s). Off by default.

- **Control:** `ENABLE_PERF_MONITOR = _env_bool("YARA_ENABLE_PERF_MONITOR", False)` (module constant, meant to be edited in the uploaded script — Action Center cannot set env vars) -> `config.enable_performance_monitoring` — default `False (disabled)`
- **Observe:** When off: statistics log line "Performance monitoring disabled in light profile" and `performance_monitoring_enabled: false` in the initialization event and in "All monitoring systems activated". When on: "Performance monitoring thread started" plus periodic `CPU: x% \| ...\| Queue: n \| Workers: n` performance-log details, and `peak_cpu_percent`/`avg_cpu_percent`/`peak_memory_mb` in the statistics summary.
- **Source:** `StatisticsManager.start_monitoring / _monitoring_worker (`time.sleep(5)`, `len(self.performance_history) % 6 == 0`); performance_history = deque(maxlen=1000)`

### Optional system resource monitor (SystemResourceMonitor)  <sub>all (io_counters skipped on Darwin; `psutil.getloadavg()` guarded by hasattr; `num_fds` guarded by hasattr)</sub>

A separate daemon thread snapshotting process and host-wide CPU/memory/disk/network/load every 10 s, keeping bounded history, raising threshold alerts, computing 10-minute trends, and uploading a flattened snapshot every 45 s. Off by default; the object is not even constructed when disabled.

- **Control:** `ENABLE_RESOURCE_MONITOR = _env_bool("YARA_ENABLE_RESOURCE_MONITOR", False)` -> `config.enable_resource_monitoring`. Cadences are hardcoded: `monitoring_interval = 10`, `upload_interval = 45`, `alert_thresholds = {cpu_percent: 90, memory_percent: 85, disk_usage_percent: 95}`, `resource_history = deque(maxlen=360)`, `alert_history = deque(maxlen=100)` — default `False (disabled); 10 s sample, 45 s upload, 90/85/95% alert thresholds`
- **Observe:** When off: system event "System resource monitoring disabled in light profile" and `resource_monitoring_enabled: false` in the init event. When on: "System resource monitoring started", then `system_resources` events roughly every 45 s carrying the flattened dashboard fields `proc_cpu_percent`, `sys_cpu_percent`, `proc_memory_mb`, plus a terminal `resource_monitoring_summary` event with `data_points_collected`, `cpu_stats` min/max/avg/current and `alerts_triggered`. Stopped after the worker join (`stop_monitoring`, 5 s join).
- **Source:** `class SystemResourceMonitor; YaraScanner.scan_system (`if self.config.enable_resource_monitoring: self.resource_monitor = SystemResourceMonitor(...)`)`

### Optional file-descriptor monitor  <sub>linux, macos (explicitly skipped on Windows)</sub>

Non-Windows only. At startup checks `ulimit -n` and records the baseline FD count; during scanning, every 1000 files it re-reads `num_fds()` and warns when usage has grown by more than 100 over baseline or exceeds 900 absolute. Off by default; when off `config.monitor_fd_usage` is explicitly set False, which is the flag `YaraScanner.fd_monitoring_enabled` reads.

- **Control:** `ENABLE_FD_MONITOR = _env_bool("YARA_ENABLE_FD_MONITOR", False)` -> `config.enable_fd_monitoring`; in-scan cadence `self.fd_check_interval = 1000`; thresholds 100 (delta), 900 (absolute), 8192 (low-ulimit warning) — default `False (disabled); 1000-file check interval`
- **Observe:** When on (Linux/macOS): system events "Current file descriptor limit: N" and "Initial file descriptors in use: N"; possibly a `resource_limit_warning` event with `{current_limit, recommended_limit: 65536, impact}` when ulimit < 8192; then `FD usage increased by N (current: M)` / `WARNING: High FD usage: N` system events mid-scan. Absence of all of these is the correct observation on Windows or with the toggle off.
- **Source:** `main() `if platform.system() != "Windows" and config.enable_fd_monitoring:` block (sets `config.initial_fd_count`, `config.monitor_fd_usage`); YaraScanner.__init__ `self.fd_monitoring_enabled = getattr(config, 'monitor_fd_usage', False)`; YaraScanner.scan_file FD block`

### Progress heartbeat thread

A dedicated `ProgressHeartbeat` daemon thread calls `_log_progress()` on a timed interval for the WHOLE scan, not just the discovery loop. This exists because progress used to be checked inline in the os.walk loop, which almost never runs long enough to cross the interval — confirmed live that zero "Scan Progress" events were ever recorded under the old approach.

- **Control:** interval = `self.log_interval` (below); thread is always started — default `always on`
- **Observe:** System/statistics stream contains repeated `Scan Progress \| Files: ... \| Queue: n \| Rate: r files/sec` events at the configured cadence across the whole run, including during the post-discovery drain phase. A run longer than `log_interval` with zero Scan Progress events is a failure.
- **Source:** `YaraScanner._progress_heartbeat; started in scan_system (`threading.Thread(target=self._progress_heartbeat, name="ProgressHeartbeat", daemon=True)`)`

### Progress heartbeat interval and its clamp

The heartbeat waits on an Event with this interval. Clamped to >= 1 s because `Event.wait(0)` (or negative) returns immediately, which would turn the heartbeat into a busy-spin that re-takes `lock_counts` continuously and floods the unbounded webhook queue. To effectively disable progress logging you set a large interval, not 0.

- **Control:** `self.log_interval = max(1, _env_number("YARA_PROGRESS_LOG_SECS", 30, cast=int, minimum=1))` — default `30 seconds (chosen over 120: a 15,589-file Windows scan's active phase is well under 120 s and produced zero samples at 120)`
- **Observe:** Time between consecutive `Scan Progress` statistics events ≈ 30 s; count of progress events over a known scan duration ≈ duration/30. Setting YARA_PROGRESS_LOG_SECS=0 must still yield ~1 s spacing, not a flood.
- **Source:** `ScanConfig.log_interval; `while not self._progress_heartbeat_stop.wait(self.config.log_interval)``

### Progress heartbeat lifetime spans the worker drain

The heartbeat is stopped only AFTER the worker-thread join in cleanup (with a 2 s join), not when file discovery ends — on a large scan those moments can be minutes apart, and stopping early cut telemetry off for most of the real scan.

- **Control:** not configurable (2 s join timeout) — default `stopped after worker join`
- **Observe:** Scan Progress events continue after the last "Scanning target N/N" system event and stop only around the `Worker cleanup: ...` performance event. The same ordering applies to resource/statistics monitors, which are stopped after the join too.
- **Source:** `YaraScanner._perform_enhanced_cleanup (`self._progress_heartbeat_stop.set()` placed after the join loop; `join(timeout=2)`)`

### Progress snapshot contents (capacity/backpressure telemetry)  <sub>all (disk_io_mb stays 0 on macOS — `process.io_counters()` raises AttributeError there and is caught so memory/network still report)</sub>

Each heartbeat tick reports files scanned/skipped, detections, live queue depth, instantaneous scan rate, live worker count, and process CPU / RSS / cumulative disk I/O / cumulative network volume, plus elapsed time and junction-skip counters.

- **Control:** not configurable — default `emitted every log_interval`
- **Observe:** Statistics event `Scan Progress \| ...` with `queue_size`, `scan_rate_files_per_sec`, top-level `active_workers` (flattened for the "Capacity vs Backpressure" widget) and `metrics: {cpu_percent, memory_mb, disk_io_mb, network_mb, active_workers, elapsed_seconds, eta_seconds, junction_skips, unique_real_paths}`; plus a companion performance event `System Resources \| CPU: x% \| Memory: yMB \| Disk I/O: zMB \| Network: wMB`.
- **Source:** `YaraScanner._log_progress; LogManager.log_scan_progress; LogManager.log_system_resources`

### Long-lived primed handle for progress metrics

`_log_progress` reuses one primed `psutil.Process` handle (`self._progress_proc`) instead of constructing a fresh one each tick, because a fresh Process object's first `cpu_percent()` always returns 0.0 — which would have made every progress tick report 0% CPU now that the heartbeat fires for the whole scan.

- **Control:** not configurable — default `always on`
- **Observe:** `cpu_percent` in Scan Progress `metrics` and in the `System Resources \|` line is non-zero from the second tick onward on an active scan. A series of all-zero cpu_percent values is the regression signature.
- **Source:** `YaraScanner._log_progress (`process = getattr(self, "_progress_proc", None) ... process.cpu_percent(interval=None) # prime; discard the 0.0`)`

### Liveness-marker refresh from the heartbeat thread

Each heartbeat tick also refreshes the running.json liveness marker. This is done from the timed thread because the discovery loop's `_enqueue_scan_path` blocks while the queue is saturated, so one huge directory could hold the marker past its staleness window and make a live scan look dead to `cancel`.

- **Control:** `RUNNING_MARKER_REFRESH_SECS = 30.0` (self-rate-limited), `RUNNING_MARKER_STALE_SECS = 180.0` — default `refresh 30 s, stale after 180 s`
- **Observe:** mtime/content of `<scanner_dir>/control/running.json` advancing at ~30 s intervals during a scan, including while `Scan queue saturated` lines are being emitted; file removed at cleanup (`_remove_running_marker`).
- **Source:** `YaraScanner._progress_heartbeat (`self._maybe_refresh_running_marker()`); RUNNING_MARKER_REFRESH_SECS / RUNNING_MARKER_STALE_SECS`

### ETA and rate estimation

Each progress tick recomputes current rate, average rate and an ETA against a rolling total-files estimate (`files_scanned + files_skipped + queue_size * 2`) and emits a separate time-estimates event when an ETA exists.

- **Control:** not configurable — default `computed every log_interval`
- **Observe:** Statistics event `Time Estimates \| ETA: H:MM:SS \| Rate: r files/sec \| Remaining: n files` with data `{eta_seconds, estimated_completion, current_rate_files_per_sec, files_remaining}`; `eta_seconds` also appears inside the Scan Progress `metrics`.
- **Source:** `StatisticsManager.calculate_time_estimates; YaraScanner._log_progress; LogManager.log_time_estimates`

### Scan-rate reporting in the terminal artefacts

Throughput is reported at four levels: per-tick (progress), per-target, at scan end, and in the on-disk summary — all as files/second derived from the same counters.

- **Control:** not configurable — default `always emitted`
- **Observe:** (1) `scan_rate_files_per_sec` in each Scan Progress event; (2) `files_per_second` per target in the per-target completion data; (3) `average_scan_rate` in the final statistics event `SCAN COMPLETED \| Time: ... \| Rate: X.XX files/sec`; (4) `scan_rate_fps` in `<scanner_dir>/logs/scan_summary_<run_id>.json`; (5) `scan_rate_files_per_second` in periodic `scan_status` events.
- **Source:** `YaraScanner._log_progress; YaraScanner.scan_system per-target block; YaraScanner._log_final_results (`'average_scan_rate': self.files_scanned / total_time`); main() write_scan_summary `"scan_rate_fps"`; ScanStatusUploader status_data`

### No per-offset retention in memory (uploader)

The match uploader deliberately keeps no local copy of per-offset detail. It previously built one dict per matched offset and held them all for the whole scan — measured at 1,048,035 offsets producing ~15 GB RSS on one endpoint — for a serialization that never happened.

- **Control:** not configurable (design property) — default `n/a`
- **Observe:** Process RSS stays flat on a storm scan: `memory_mb` in successive Scan Progress `metrics` should not trend upward with detection count. Compare `total_detections` growth against `memory_mb` over the run.
- **Source:** `ResultsUploader.__init__ comment block and the absence of any per-offset accumulator; YaraScanner.scan_file emits one aggregated finding per (rule, file)`

### Per-finding network payload cap

All string offsets for a given (rule, file) are folded into ONE upload item carrying a capped sample, instead of one queued item per matched offset (measured: 36,213 items in one match-upload backlog under the old shape). Bounds both queue depth and per-request size.

- **Control:** `MAX_MATCH_SAMPLES_PER_FINDING = _env_number("YARA_MAX_MATCH_SAMPLES", 50, cast=int, minimum=1)` — note minimum=1: 0 or negative falls back to the default, because its consumer is `if len(sample) < CAP` — default `50 samples per finding`
- **Observe:** Match rows in the tenant carry at most 50 offset samples per (rule, file); `total_matches` in the ResultsUploader books (`match_delivery` in scan_summary_<run_id>.json) equals the number of findings, not the number of offsets.
- **Source:** `MAX_MATCH_SAMPLES_PER_FINDING; ResultsUploader.add_match`

### On-disk alert offset sampling (host disk footprint)

`alert/<rule>.txt` renders a complete, uncapped per-string-ID census but samples the individual offsets. Measured before this cap: one rule against C:\Windows\System32 produced 2,433,386 offsets and a 220 MB file on the scanned host.

- **Control:** `MAX_ALERT_OFFSETS_PER_FINDING = _env_number("YARA_MAX_ALERT_OFFSETS", 50, cast=int)` then `max(0, ...)`; 0 disables the cap (renders everything) — default `50 offsets rendered per finding`
- **Observe:** In `<scanner_dir>/alert/<rule>.txt`: the lines `Total string hits: N`, `Hits per string ID: ...` (complete), `Matched Strings (showing 50 of N):`, and a trailing `N further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=50)` note. Measure the file size against the hit count.
- **Source:** `MAX_ALERT_OFFSETS_PER_FINDING; YaraScanner._write_alerts (`shown = strings if cap <= 0 else strings[:cap]`)`

### Matched-file copying off by default (disk write amplification)

The evidence ZIP does not carry copies of matched files unless explicitly enabled — copying is charged entirely to the scanned host's disk (a System32 scan produced a 2.8 GB archive). file_mapping.txt (path + SHA256) and the alert texts are still packaged, so a responder can still locate any matched file.

- **Control:** `COLLECT_MATCHED_FILES = _env_bool("YARA_COLLECT_MATCHED_FILES", False)`; read per-run as `getattr(self.config, "collect_matched_files", COLLECT_MATCHED_FILES)` — default `False`
- **Observe:** Size and contents of `<scanner_dir>/evidence/evidence_<hostname>_<run_id>.zip` — no `matched_files/` members when off. When on, entries are content-addressed `matched_files/<sha256>` and duplicate hashes are skipped (`duplicates_skipped` counted), so identical files collapse to one blob.
- **Source:** `COLLECT_MATCHED_FILES; EvidenceCollector._create_evidence_zip`

### Chunked hashing, matched files only

SHA256 is computed with 1 MiB reads and only for files that actually matched, so a full-file read is not paid on every scanned file and hashing memory is bounded regardless of file size.

- **Control:** `_sha256_file(path, chunk_size=1024*1024)` — chunk size not exposed as a knob — default `1 MiB chunks; invoked only from the match path`
- **Observe:** Process RSS is unaffected by the size of matched files (`memory_mb` in progress metrics); `disk_io_mb` rises only in proportion to matched-file bytes, not scanned-file bytes.
- **Source:** `_sha256_file; YaraScanner._calculate_match_sha256, called inside `if matches:` in scan_file`

### Maximum scanned file size

Files larger than the cap are skipped before `rules.match()` runs, bounding the per-file memory and time cost of a YARA scan. `minimum=0` is deliberate — 0 means "no size cap", while a negative value would previously make every file fail the check and the scan report success having scanned nothing.

- **Control:** `self.max_file_mb = _env_number("YARA_MAX_MB", 64, cast=int, minimum=0)`; `self.max_file_bytes = self.max_file_mb * 1024 * 1024 if self.max_file_mb else 0` — default `64 MB (0 = uncapped)`
- **Observe:** `max_file_mb` in the initialization event data and in the scan-configuration statistics event; skip reason `"File too large"` counted in `skip_reasons` and reflected in `files_skipped` in Scan Progress and in scan_summary_<run_id>.json.
- **Source:** `ScanConfig.max_file_mb/max_file_bytes; YaraScanner.scan_file (`if max_bytes and st.st_size > max_bytes: return False, "File too large"`)`

### Bounded in-memory metric histories

All rolling metric stores are fixed-capacity deques, so monitoring cannot grow memory over a long scan: 1000 performance snapshots, 360 resource snapshots (~1 h at 10 s), 100 alerts.

- **Control:** hardcoded: `deque(maxlen=1000)`, `deque(maxlen=360)`, `deque(maxlen=100)` — default `1000 / 360 / 100`
- **Observe:** `data_points_collected` in the `resource_monitoring_summary` event never exceeds 360; `monitoring_duration_seconds` there is derived as `len(resource_history) * monitoring_interval`, so it saturates at 3600 s on longer scans.
- **Source:** `StatisticsManager.performance_history; SystemResourceMonitor.resource_history / alert_history`

### Opportunistic upload batching (network cost control)

Uploads are batched as NDJSON: a worker blocks for the first event then drains whatever is already queued behind it, up to an event and byte cap, and sends immediately — no linger timer, so a 3-match scan sends a batch of 3 with no added latency while a storm scan fills 500-event requests. Measured: 23,223 findings at ~756 ms/POST unbatched would need ~4.9 hours and 97% never shipped.

- **Control:** `UPLOAD_BATCH_MAX_EVENTS = _env_number("YARA_UPLOAD_BATCH_MAX_EVENTS", 500, cast=int)` clamped `max(1, ...)`; `UPLOAD_BATCH_MAX_BYTES = _env_number("YARA_UPLOAD_BATCH_MAX_BYTES", 4*1024*1024, cast=int)` clamped `max(64*1024, ...)` — default `500 events, 4 MiB per request (floors: 1 event, 64 KiB)`
- **Observe:** Request counts in `uploads_<run_id>.log`, and the delivery books in scan_summary_<run_id>.json (`match_delivery`, `telemetry_delivery`): total events delivered divided by requests sent should approach 500 under load and equal the event count on a quiet scan.
- **Source:** `UPLOAD_BATCH_MAX_EVENTS / UPLOAD_BATCH_MAX_BYTES; _collect_batch(queue_obj, first_item, max_events, max_bytes)`

### Backlog-proportional shutdown drain budget

Each of the four independent drain points scales its shutdown wait to its own queue depth instead of using a flat window — a flat window either dropped a heavy scan's backlog or wasted time on a light one. The per-site ceiling is deliberately low (a previous 300 s cap let sites max out back-to-back and exceed the Action Center script timeout, killing the process mid-drain and losing everything queued).

- **Control:** `DRAIN_MIN_SECS = _env_number("YARA_DRAIN_MIN_SECS", 15)`, `DRAIN_PER_ITEM_SECS = _env_number("YARA_DRAIN_PER_ITEM_SECS", 0.3)`, `DRAIN_MAX_SECS = _env_number("YARA_DRAIN_MAX_SECS", 60)` — default `15 s floor, 0.3 s/item, 60 s per-site ceiling (4 sites => 240 s worst case)`
- **Observe:** Upload-log line `Waiting for N pending standardized log uploads (max Ns)...`; the `undelivered` counter in the ResultsUploader books (items still queued when the window expired, never attempted) inside scan_summary_<run_id>.json.
- **Source:** `_compute_drain_budget(pending_items) = `min(DRAIN_MAX_SECS, max(DRAIN_MIN_SECS, pending_items * DRAIN_PER_ITEM_SECS))`; used in LogManager.stop_logging and the uploader stop paths; THREAD_CLEANUP_TIMEOUT = 60 for the subsequent joins`

### Per-run log/summary retention on the endpoint

**⚠ CONTROL GAP**  
Before each scan, artefacts from all but the most recent N runs are removed from the logs directory — .log files plus `scan_summary_<run_id>.json` and orphaned `.json.tmp` files — so repeated scans do not accumulate unbounded disk on the host. The current run's id is always retained.

- **Control:** `self._prune_old_scan_logs(keep_scans=2)` called from `initial_cleanup()`; not env-configurable — default `keep 2 most recent runs (plus the current one)`
- **Observe:** Contents of `<scanner_dir>/logs/` after several runs: at most 3 run_ids' worth of `alerts_/statistics_/scan_errors_/performance_/uploads_/system_/yara_processing_/script_exceptions_/scanner_*.log` and `scan_summary_*.json`. Also: `initial_cleanup()` deletes the whole alert and evidence directories before each run.
- **Source:** `CleanupManager._prune_old_scan_logs / _extract_run_id_from_log_name / initial_cleanup`

### Uploader/log threads are all daemon threads with bounded joins

Every background thread in the process (2 scan workers, progress heartbeat, cancel watcher, log webhook worker, three uploader workers, and the two optional monitors) is a daemon thread joined with an explicit timeout, so no thread can keep the Action Center payload process alive past its own shutdown sequence.

- **Control:** `THREAD_CLEANUP_TIMEOUT = 60` for uploader/webhook joins; 5 s for scan workers and monitors; 2 s for the heartbeat — default `60 s uploader joins; 5 s worker/monitor joins; 2 s heartbeat join`
- **Observe:** Upload-log warnings `Upload thread did not terminate within 60s timeout` / `WARNING: Webhook thread did not terminate within 60s` if a join times out; otherwise the run's terminal events land and the process exits. Thread inventory is visible in the resource monitor's `thread_count` field when that monitor is enabled.
- **Source:** `THREAD_CLEANUP_TIMEOUT; the six `threading.Thread(target=..., daemon=True)` call sites (lines 1541, 1842, 2268, 3160, 3605, 5751) plus the heartbeat and cancel-watcher threads`

---

# Local Storage & Host Footprint

*Everything written to the machine being scanned.*

### Scanner working directory (platform default + override)  <sub>all (path differs per OS)</sub>

All scanner artefacts are written under one root directory created at startup. The root is chosen per-platform, and a single env var overrides it for every consumer (both the scan path and the standalone cancel path resolve it identically).

- **Control:** env YARA_SCANNER_DIR (read in ScanConfig.__init__ and in _default_scanner_dir(); blank/whitespace value is ignored) — default `Windows: C:\yara_scanner \| macOS (Darwin): /usr/local/yara_scanner \| everything else (Linux): /opt/yara_scanner`
- **Observe:** Directory exists on the host after a run: `dir C:\yara_scanner` / `ls -la /opt/yara_scanner`. It is created unconditionally by `os.makedirs(self.scanner_dir, exist_ok=True)` even for a scan that matches nothing. Setting YARA_SCANNER_DIR=/tmp/yaratest and re-running moves every artefact there.
- **Source:** `ScanConfig.__init__ (self.scanner_dir); _default_scanner_dir()`

### Four fixed subdirectories: logs/, alert/, evidence/, failed_rules/

ScanConfig creates a fixed subdirectory layout under scanner_dir at construction time. logs/ holds every per-run text log plus the summary JSON; alert/ holds one text file per triggered rule; evidence/ holds file_mapping.txt and the evidence ZIP; failed_rules/ holds the .yar source of rules that failed or were skipped at compile time.

- **Control:** not configurable (hardcoded os.path.join(self.scanner_dir, ...) names) — default `logs, alert, evidence, failed_rules — all created with os.makedirs(..., exist_ok=True)`
- **Observe:** All four exist after any run, even a clean one: `ls /opt/yara_scanner` shows logs alert evidence failed_rules. alert/ and evidence/ are empty until a match; failed_rules/ is empty unless a rule failed or was skipped.
- **Source:** `ScanConfig.__init__: self.logs_dir, self.alert_dir, self.evidence_dir, self.failed_rules_dir; `for directory in [self.alert_dir, self.evidence_dir, self.failed_rules_dir]: os.makedirs(directory, exist_ok=True)``

### control/ subdirectory for cooperative-cancel state

A fifth subdirectory holding the two cross-process cancellation files (cancel.flag, running.json). Created best-effort inside a try/except so a permission failure here does not abort the scan; also created independently by the cancel entry point, which does not initialise the rest of the scanner.

- **Control:** not configurable (self.control_dir = os.path.join(self.scanner_dir, "control")) — default `<scanner_dir>/control`
- **Observe:** `ls /opt/yara_scanner/control` during a live scan shows running.json; after a `cancel()` invocation it also shows cancel.flag. If creation fails, cancel() returns the literal string `Cancel failed: cannot create control dir <path>: <err>`.
- **Source:** `ScanConfig.__init__ (self.control_dir, wrapped in try/except); _handle_cancel_request()`

### Six per-category run logs in logs/

LogManager opens one dedicated file logger per LogType category, each stamped with the run_id, so a run's alerts, statistics, errors, performance data, upload activity and system messages are separated into six greppable files.

- **Control:** not configurable (LogManager.log_files dict is hardcoded) — default `logs/alerts_<run_id>.log, statistics_<run_id>.log, scan_errors_<run_id>.log, performance_<run_id>.log, uploads_<run_id>.log, system_<run_id>.log — run_id is datetime.now().strftime("%Y%m%d_%H%M%S_%f")`
- **Observe:** `ls /opt/yara_scanner/logs/*_<run_id>.log` returns exactly these six files after any run. Line format is `[YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] message` (logging.Formatter with datefmt="%Y-%m-%d %H:%M:%S"). Tailing uploads_<run_id>.log live is the low-latency way to watch delivery.
- **Source:** `LogManager.__init__ (self.log_files); LogManager._setup_logger`

### YARA-processing audit log (rule compilation trail)

A separate logger records the rule-compilation audit trail: which ruleset source was used, the available-module list, per-rule compile failures, and the COMPILATION SUMMARY block (total/valid/failed/success rate, and the failed_rules_dir pointer when anything failed).

- **Control:** not configurable — default `logs/yara_processing_<run_id>.log, opened mode="w", level INFO`
- **Observe:** grep for `COMPILATION SUMMARY` in logs/yara_processing_<run_id>.log; it prints `Total rules processed:`, `Valid rules compiled:`, `Failed rules skipped:`, `Success rate:` and, only when failures exist, `Failed rules saved to: <failed_rules_dir>`.
- **Source:** `ErrorLogger.__init__ / ErrorLogger._setup_error_logger / ErrorLogger.log_compilation_summary`

### Lazy script-exception log (no zero-byte file on clean runs)

Script-level exceptions get their own log file, but the FileHandler is only constructed on the first log_exception() call, so a run with no exceptions leaves no empty file behind in logs/.

- **Control:** not configurable — default `logs/script_exceptions_<run_id>.log, created on demand only, mode="w", level ERROR`
- **Observe:** On a clean run the file is absent from logs/. When it exists, its first lines are the banner `=== SCRIPT EXCEPTION LOG INITIALIZED ===`, Python version, platform, then `[timestamp] [EXCEPTION] ...` entries.
- **Source:** `ExceptionLogger.__init__ / ExceptionLogger._ensure_logger`

### Per-run log files, truncating, no rotation and no size cap

Every scanner-owned log handler is a plain logging.FileHandler opened with mode="w" and a run_id-stamped filename — logs never append across runs and there is no RotatingFileHandler or byte cap. Unbounded growth within a single run is bounded only by the run itself and by the retention pass on the next run.

- **Control:** not configurable — default `mode="w", encoding="utf-8", no maxBytes/backupCount anywhere in the file`
- **Observe:** Run twice and compare: each run produces a fresh set of *_<run_id>.log files; no single log file is ever reopened or rolled. Total logs/ size grows only by the number of retained runs (see retention entry).
- **Source:** `LogManager._setup_logger, ErrorLogger._setup_error_logger, ExceptionLogger._ensure_logger — all `logging.FileHandler(..., mode="w")``

### Reserved scanner_<run_id>.log path, self-excluded from scanning  <sub>all (case-folded comparison on Windows only)</sub>

ScanConfig reserves logs/scanner_<run_id>.log as self.output_log. No handler writes to it in this edition, but it is load-bearing for footprint in two ways: initial_cleanup deletes it if present and re-creates its parent directory, and the skip logic explicitly refuses to scan that exact path (case-folded on Windows) so the scanner cannot scan its own output.

- **Control:** not configurable — default `logs/scanner_<run_id>.log (path only)`
- **Observe:** The file does not appear in logs/ after a run. Its exclusion is observable by pointing a scan at logs/ — that path is never counted in files_scanned.
- **Source:** `ScanConfig.__init__ (self.output_log); CleanupManager.initial_cleanup (paths_to_clean); YaraScanner._is_special_file (scanner_log_path comparison)`

### Per-rule alert text file (alert/<rule>.txt)

Every (rule, file) finding appends a human-readable block to one text file named after the triggering rule, so one file accumulates every file that rule matched during the run. Each block carries the rule name, matched path, SHA256, file creation time and an 80-char separator. Writes are serialised under a lock and flushed per block.

- **Control:** not configurable (path is os.path.join(self.config.alert_dir, f"{rule}.txt"); open mode "a") — default `alert/<rule_name>.txt`
- **Observe:** `ls /opt/yara_scanner/alert/` after a matching scan lists one .txt per triggered rule (count should equal `unique_rules_triggered` in scan_summary). Each block begins `YARA rule '<rule>' matched file: <path>` followed by `File SHA256:` and `File Creation Time:` lines. An I/O failure here is logged as `Failed to write alert file: <err>` to scan_errors_<run_id>.log.
- **Source:** `YaraScanner._write_alerts (alert_path, self.lock_alert)`

### Uncapped per-string-ID census in the alert text

Before any offsets are rendered, the alert file writes the complete hit count and a full per-string-ID histogram for the finding. This is deliberately never capped — it costs one line regardless of match volume, and it is what makes capping the offsets below safe.

- **Control:** not configurable (always written when the match has strings) — default `always on`
- **Observe:** In alert/<rule>.txt look for the two lines `Total string hits: <N>` and `Hits per string ID: $a=12, $b=3, ...` (sorted by ID; a match with no string ID renders as `$?`). Sum of the census values equals Total string hits, and equals the true match count even when offsets below are truncated.
- **Source:** `YaraScanner._write_alerts (id_counts loop; `f.write(f"Total string hits: {len(strings)}\n")`)`

### Offset cap in the alert text (MAX_ALERT_OFFSETS_PER_FINDING)

Caps how many individual String ID / Offset / Data triples are rendered per (rule, file) finding into alert/<rule>.txt. Exists because uncapped rendering produced a 220 MB file on a scanned Windows host from 2,433,386 offsets. 0 means no cap (restores render-everything); negative values are clamped to 0 by max(0, ...).

- **Control:** env YARA_MAX_ALERT_OFFSETS (constant MAX_ALERT_OFFSETS_PER_FINDING) — default `50`
- **Observe:** The alert text always states the ratio: `Matched Strings (showing 50 of 2433386):`. When truncated it also writes `<N> further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=50). Counts above are complete; re-run \`yara -s\` against this file for every offset.` Measure the effect by setting YARA_MAX_ALERT_OFFSETS=0 and comparing alert/ file sizes.
- **Source:** `MAX_ALERT_OFFSETS_PER_FINDING; YaraScanner._write_alerts (`cap = MAX_ALERT_OFFSETS_PER_FINDING; shown = strings if cap <= 0 else strings[:cap]`)`

### Condition-only match detail in the alert text

A rule that fires on its condition alone (no string hits — e.g. filesize/hash/module conditions) would otherwise write an empty block. Instead the alert file renders a generated explanation of why the condition matched, derived from the rule's meta, tags and source.

- **Control:** not configurable — default `always on when a match carries zero strings`
- **Observe:** In alert/<rule>.txt, a match with no strings renders `Condition Match Details:` followed by the summary text between 40-dash rules. The same text is sent as fallback_detail on the uploaded finding, so the local file and the tenant row agree.
- **Source:** `YaraScanner._write_alerts (condition_only_detail branch); _summarize_condition_only_match`

### Matched-bytes rendering (UTF-16 LE / UTF-8 / hex fallback)

Matched string data written to the alert file is decoded for human reading rather than dumped raw: wide (UTF-16 LE) matches are detected by the every-other-byte-NUL pattern and decoded, plain ASCII/UTF-8 is decoded, and anything non-printable or binary falls back to a hex string. Without this, wide matches left embedded NUL bytes that break Notepad.

- **Control:** not configurable — default `always on`
- **Observe:** In alert/<rule>.txt the `Data:` line of a wide-string match reads as clean text with no interleaved nulls; a binary match's `Data:` line is an even-length hex string. Open the file in Notepad on Windows — it renders without null artefacts.
- **Source:** `_render_match_data(); called from YaraScanner._write_alerts`

### evidence/file_mapping.txt (path -> SHA256 manifest)

A single manifest listing every matched file path with its SHA256, prefixed by a host header (hostname, OS, IP addresses). Hashes already computed during the scan are reused; any missing hash is computed here. This manifest is what makes the not-copying-files default non-lossy — a responder can locate or pull any matched file by path or hash on demand.

- **Control:** not configurable (self.file_mapping = os.path.join(self.evidence_dir, "file_mapping.txt"); rewritten mode "w" each run) — default `evidence/file_mapping.txt`
- **Observe:** `cat /opt/yara_scanner/evidence/file_mapping.txt` — header block (`Hostname:`, `OS:`, `IP Addresses:`), then the column header `Original Path \| SHA256 Hash` and one `path \| hash` line per matched file that still exists on disk. Line count should equal the number of distinct matched paths.
- **Source:** `EvidenceCollector._process_matched_files; FileHasher.calculate_sha256`

### Evidence ZIP (evidence_<hostname>_<run_id>.zip)

One deflate-compressed archive per run, written into evidence/. It always contains file_mapping.txt at the archive root and every alert/*.txt under an alerts/ prefix; matched file copies under matched_files/ are added only when the copy toggle is on. It is produced on the normal completion path and, best-effort, on the fatal-failure path.

- **Control:** not configurable (name is f"evidence_{self.hostname}_{self.run_id}.zip"; compression zipfile.ZIP_DEFLATED) — default `evidence/evidence_<hostname>_<run_id>.zip`
- **Observe:** `unzip -l /opt/yara_scanner/evidence/evidence_*_<run_id>.zip` — expect `file_mapping.txt` plus one `alerts/<rule>.txt` per triggered rule. Note the ZIP is written even on a zero-match scan (it then contains only the header-only file_mapping.txt). system_<run_id>.log records `Evidence collection completed successfully`; the failure path records `Evidence collected from failed scan`.
- **Source:** `ScanConfig.__init__ (self.evidence_zip); EvidenceCollector.collect_evidence / _create_evidence_zip; main() failure branch calling scanner.evidence_collector.collect_evidence()`

### Matched-file copy toggle (COLLECT_MATCHED_FILES)

Controls whether the evidence ZIP carries copies of the matched files themselves. Off by default because copying is charged entirely to the scanned host's disk — a C:\Windows\System32 scan produced a 2.8 GB archive on the lab host. With it off, only metadata (paths + SHA256 + alert texts) is packaged. A per-config attribute of the same name overrides the module constant if present.

- **Control:** env YARA_COLLECT_MATCHED_FILES (constant COLLECT_MATCHED_FILES); read via getattr(self.config, "collect_matched_files", COLLECT_MATCHED_FILES) — default `False`
- **Observe:** With the default, the ZIP has no matched_files/ entries and the root logger records `Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only (paths + SHA256 + alert texts, no matched file copies)`. Set YARA_COLLECT_MATCHED_FILES=true and re-run: `unzip -l` now shows matched_files/<sha256> entries and the archive size jumps to roughly the byte total of the matched set.
- **Source:** `COLLECT_MATCHED_FILES; EvidenceCollector._create_evidence_zip (copy_files branch)`

### Content-addressed dedupe of packaged matched files

When file copying is on, each matched file is stored under its SHA256 as the archive name (matched_files/<sha256>), so N paths holding identical bytes collapse to one blob. A hash is only marked packaged after a successful write, so a path that vanished mid-scan does not block a same-content sibling. This is correctness, not just size: zipfile only warns on a duplicate arcname and writes the member anyway, so readers could otherwise only ever see the first copy.

- **Control:** not configurable (active whenever COLLECT_MATCHED_FILES is on) — default `always on when copying`
- **Observe:** `unzip -l` shows entry names that are bare 64-char hex, and the entry count is <= the file_mapping.txt line count. When any duplicate was collapsed, the root logger prints `Evidence ZIP: <N> unique file(s) packaged, <M> duplicate copy(ies) skipped`. A copy failure is logged as `Error adding file to zip <path>: <err>`.
- **Source:** `EvidenceCollector._create_evidence_zip (packaged_hashes set, duplicates_skipped counter)`

### scan_summary_<run_id>.json — machine-readable per-run summary

One JSON file per run in logs/, written for tools rather than humans, so a follow-up action, the test skill or customer automation reads one file instead of grepping six logs. Carries a fixed identity header (schema, edition, run_id, scan_id, rule_hash, hostname, os_info, ip_address, scanner_version) plus the run body: outcome, failure_reasons, scan_folder, scan_targets, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, and the two delivery books match_delivery and telemetry_delivery.

- **Control:** not configurable — default `logs/scan_summary_<run_id>.json, schema "yara_scan_summary/v1", edition "xsiam", scanner_version 4.4.0`
- **Observe:** `cat /opt/yara_scanner/logs/scan_summary_<run_id>.json \| jq .outcome` returns exactly one of completed / cancelled / failed. It is written in main()'s finally block AFTER the uploaders drain (so delivery counts are final) and BEFORE stop_logging(), so system_<run_id>.log carries the matching line `Scan summary written: scan_summary_<run_id>.json`. A write failure appears as `Failed to write scan summary JSON: <err>` in scan_errors_<run_id>.log.
- **Source:** `LogManager.write_scan_summary; call site in main()'s finally block`

### Atomic summary write with temp cleanup

The summary is dumped to <path>.tmp and moved into place with os.replace, so a concurrent reader never sees a half-written file; if the dump raises (e.g. disk full mid-write) the temp is removed rather than left behind. This matters most because the console's Cancel button hard-kills the payload, making this local file the only surviving evidence of what the run had done.

- **Control:** not configurable — default `temp suffix ".tmp", moved into place with os.replace`
- **Observe:** Watch logs/ during shutdown: scan_summary_<run_id>.json.tmp exists only momentarily. Any surviving .json.tmp indicates a failed dump — and is swept by the retention pass on the next run.
- **Source:** `LogManager.write_scan_summary (`tmp = path + ".tmp"` ... `os.replace(tmp, path)`; except branch os.remove(tmp))`

### Log/summary retention across runs (keep last 2 scans)

**⚠ CONTROL GAP**  
At scan start, logs/ is pruned so only the newest N run_ids survive, plus the current run which is always added to the keep set. Retention is anchored on the run_id embedded in the filename, and covers .log, scan_summary_*.json and orphaned .json.tmp files on the same pass — matching only .log left summaries accumulating on the endpoint forever.

- **Control:** not configurable at runtime; keep_scans is a parameter defaulted at the call site: self._prune_old_scan_logs(keep_scans=2), clamped by max(1, int(keep_scans)) — default `2 previous scans (plus the current run)`
- **Observe:** Run the scanner three times and list logs/: only two run_id generations remain besides the in-progress one. The root logger prints `Log retention applied: kept last 2 scans (<N> run IDs including current), removed <M> log files`, and files it could not delete produce `Cannot remove log file (in use): <path>` plus a trailing `Log retention: <F> log files could not be removed`.
- **Source:** `CleanupManager._prune_old_scan_logs; CleanupManager._extract_run_id_from_log_name (regex `_(\d{8}_\d{6}_\d{6})\.(?:log\|json\|json\.tmp)$`)`

### Initial cleanup at scan start (alert/ and evidence/ wiped)

Before scanning, the previous run's alert directory and evidence directory are deleted outright (shutil.rmtree) along with the reserved output_log file, then re-created empty. This is why only ONE run's alert texts and evidence ZIP ever exist on the host at a time — unlike logs/, which keeps two generations. Failures are non-fatal: a PermissionError is warned about and the scan continues.

- **Control:** not configurable — default `paths_to_clean = [alert_dir, evidence_dir, output_log]; always runs, called from main() immediately after CleanupManager construction`
- **Observe:** Note the evidence ZIP filename from run 1, run the scan again, and confirm it is gone: evidence/ contains only run 2's ZIP. The root logger prints `Starting initial cleanup of old data...`, one `Removed: <path>` per entry, then `Initial cleanup completed successfully` (or `Some cleanup operations failed - continuing with scan`). system_<run_id>.log carries `Initial cleanup completed`.
- **Source:** `CleanupManager.initial_cleanup; call site in main()`

### failed_rules/ artefacts are never retention-managed

Compile-time rule artefacts are written as .yar files into failed_rules/ and, unlike alert/ and evidence/, that directory is NOT in paths_to_clean and is not covered by the logs retention regex — so these files accumulate across every run until removed by hand. Three kinds are written: raw_yara_content.yar (the whole ruleset, when it could not be split into individual rules at all), failed_rule_<name>.yar (compilation error, with the error and date in comment headers, preamble included), and skipped_rule_<name>_<module>.yar (rule needs a libyara module this agent lacks). All writes are best-effort inside try/except.

- **Control:** not configurable — default `failed_rules/raw_yara_content.yar, failed_rules/failed_rule_<display_name>.yar, failed_rules/skipped_rule_<display_name>_<module>.yar`
- **Observe:** `ls /opt/yara_scanner/failed_rules/` grows monotonically across runs. Each file's first lines identify its kind: `// FAILED RULE - Compilation Error` + `// Error: ...`, `// SKIPPED RULE - Module '<m>' not available`, or `// RAW YARA CONTENT - Failed to split into individual rules`. Cross-check the count against failed_rules/skipped_rules in scan_summary_<run_id>.json.
- **Source:** `YaraScanner rule-compilation loop (debug_file, failed_rule_path, skipped_rule_path); CleanupManager.initial_cleanup's paths_to_clean, which omits failed_rules_dir`

### Cleanup script generated on disk (.bat / .sh)  <sub>all (content and extension differ Windows vs POSIX)</sub>

When alerts exist, a small cleanup script is written to the scanner_dir root. It is generated from the ACTUAL alert_dir path at runtime (a previous embedded-base64 version targeted paths this edition never creates, so the scheduled rename renamed nothing). The Windows form guards with `if errorlevel 1 exit /b 0` after the cd, because batch does not abort on a failed cd and a bare wildcard rename would otherwise run in whatever directory the task started in. The POSIX form is chmod 0755.

- **Control:** not configurable (self.cleanup_script = os.path.join(self.scanner_dir, "cleanup_script.bat" if is_windows else "cleanup_script.sh")) — default `<scanner_dir>\cleanup_script.bat on Windows, <scanner_dir>/cleanup_script.sh elsewhere`
- **Observe:** After a matching scan, `type C:\yara_scanner\cleanup_script.bat` shows `cd /d "C:\yara_scanner\alert"`, `if errorlevel 1 exit /b 0`, `ren *.txt *.alert`. On POSIX, `cat /opt/yara_scanner/cleanup_script.sh` shows the `cd "<alert_dir>" \|\| exit 0` loop and `ls -l` shows mode 0755. system_<run_id>.log records `Cleanup script decoded and ready for scheduling`. The file persists on the host after the run.
- **Source:** `CleanupManager._decode_cleanup_script / _get_cleanup_script_content; ScanConfig.__init__ (self.cleanup_script)`

### .txt -> .alert rotation performed by the scheduled cleanup

The scheduled script's only job is to rename every alert/*.txt to *.alert. This is what marks a run's alert texts as consumed/rotated so the NEXT run's _check_for_alerts (which tests only for .txt) and the next evidence ZIP (which packages only .txt) do not pick them up — though note initial_cleanup wipes the whole alert directory at the next scan start anyway.

- **Control:** not configurable — default `rename *.txt -> *.alert in alert_dir`
- **Observe:** After a matching scan wait past the scheduled time and list alert/: files have flipped extension from <rule>.txt to <rule>.alert. On Windows, `schtasks /query /tn CleanupScript /v` showing Last Result 0 is the confirmation the rename actually ran (this path previously reported Last Result = 1 with the wrong hardcoded directory).
- **Source:** `CleanupManager._get_cleanup_script_content (`ren *.txt *.alert` / `mv "$file" "${file%.txt}.alert"`)`

### Windows scheduled cleanup task (CleanupScript)  <sub>windows</sub>

On Windows the cleanup script is registered as a one-shot scheduled task running as SYSTEM, one minute in the future, force-overwriting any existing task of the same name.

- **Control:** not configurable (schtasks /create /tn CleanupScript /tr <cleanup_script> /sc once /st <now+1min> /ru SYSTEM /f) — default `task name "CleanupScript", /sc once, /ru SYSTEM, /f`
- **Observe:** `schtasks /query /tn CleanupScript /v /fo LIST` on the endpoint after a matching scan — shows Task To Run pointing at C:\yara_scanner\cleanup_script.bat, Run As User SYSTEM, Next Run Time = scan time + 1 min. The root logger prints `Windows cleanup task scheduled for HH:MM`; system_<run_id>.log records `Windows cleanup task scheduled successfully`. The task registration persists on the host after the run.
- **Source:** `CleanupManager._schedule_windows_cleanup`

### Linux systemd cleanup unit (yara-cleanup.service)  <sub>linux (this branch is also taken on macOS — see the macOS entry)</sub>

On non-Windows the scanner writes a systemd unit to /etc/systemd/system/yara-cleanup.service (Type=oneshot, User=root, ExecStart=/bin/bash <cleanup_script>, WantedBy=multi-user.target), verifies the file exists and is root-owned, then daemon-reload / enable / start. Because it is enabled with an [Install] section, this leaves a persistent, boot-activated unit on the host, not just a one-shot.

- **Control:** not configurable (service_path hardcoded to /etc/systemd/system/yara-cleanup.service) — default `unit name yara-cleanup.service; enabled and started immediately`
- **Observe:** `systemctl status yara-cleanup.service` and `systemctl is-enabled yara-cleanup.service` on the endpoint after a matching scan; `cat /etc/systemd/system/yara-cleanup.service` shows the generated unit with ExecStart=/bin/bash /opt/yara_scanner/cleanup_script.sh. Root logger prints `Linux cleanup service created and started`; system_<run_id>.log records `Linux cleanup service scheduled successfully`.
- **Source:** `CleanupManager._schedule_linux_cleanup`

### macOS has no working scheduled-cleanup path  <sub>macos</sub>

schedule_final_cleanup branches only on `platform.system() == "Windows"` versus everything else, so on Darwin it calls _schedule_linux_cleanup — which writes a systemd unit to /etc/systemd/system and shells out to systemctl. On macOS this fails; the exception is logged and re-raised, then caught by main()'s wrapper so the scan still returns its result line. Consequence: on macOS the .txt -> .alert rotation never happens, and cleanup_script.sh is still written and chmod'ed 0755.

- **Control:** not configurable — default `n/a — behaviour of the else-branch`
- **Observe:** On a macOS endpoint with matches: cleanup_script.sh exists in /usr/local/yara_scanner, alert/*.txt files stay .txt, no launchd job is created, and scan_errors_<run_id>.log carries `Failed to schedule cleanup: <err>` / `Error scheduling cleanup: <err>` while the scan itself still reports a normal summary line.
- **Source:** `CleanupManager.schedule_final_cleanup (`if platform.system() == "Windows": ... else: self._schedule_linux_cleanup()`)`

### Cleanup scheduling is suppressed on critical errors or zero alerts

Two guards stop the scheduler from ever touching the host: (1) critical errors — error_logger.has_errors with valid_rules_count == 0, or an error log ratio above 50% of all log events — preserve diagnostic data by skipping cleanup entirely; (2) no alert .txt files present means there is nothing to rotate, so nothing is scheduled. main() re-checks the critical-error condition independently before calling schedule_final_cleanup.

- **Control:** not configurable (error_ratio threshold 0.5 hardcoded) — default `error_ratio > 0.5 or (has_errors and valid_rules_count == 0) => skip; empty alert dir => skip`
- **Observe:** A zero-match scan leaves NO scheduled task / systemd unit and logs `No alerts found, skipping cleanup scheduling` to system_<run_id>.log. A scan where every rule failed to compile logs `Critical errors detected - skipping cleanup to preserve diagnostic data` (with data {'preserve_logs': True}) and `Cleanup skipped due to critical YARA processing errors`.
- **Source:** `CleanupManager.schedule_final_cleanup; CleanupManager._check_for_alerts; the has_critical_errors re-check in main()`

### control/cancel.flag — cooperative cancel signal file

The zero-input cancel() entry point writes a small JSON flag file that a running scan polls for. It deliberately does not initialise logging, compile rules or touch the collector. This is the supported alternative to the console's Cancel button, which hard-kills the payload (queued findings lost, no summary written).

- **Control:** not configurable (path <scanner_dir>/control/cancel.flag); poll cadence env YARA_CANCEL_POLL_SECS, floored by max(0.5, ...) — default `poll every 5s; flag body {"requested_at_ms": <epoch ms>, "source": "action_center"}`
- **Observe:** `cat /opt/yara_scanner/control/cancel.flag` right after invoking cancel(). The cancel entry point returns the line `Cancel signal delivered (<flag_path>) \| scanner running: yes\|no \| scan_id=<id>`. On the scanning side, system_<run_id>.log records `Cancellation requested (source=action_center)` and scan_summary_<run_id>.json ends with outcome "cancelled".
- **Source:** `_handle_cancel_request(); cancel(); YaraScanner._cancellation_watcher; CANCEL_POLL_SECS`

### Stale cancel-flag detection and removal

At scan start a pre-existing cancel.flag is deleted only if its mtime predates this process's start (minus a small tolerance for coarse filesystem mtime resolution). A cancel delivered DURING rule compilation has a newer mtime and is preserved, so the watcher honours it the moment it starts — the naive delete-anything-pre-existing version silently lost cancels issued while a large ruleset compiled. The anchor timestamp is captured at module import, before ScanConfig and rule compilation.

- **Control:** not configurable (CANCEL_STALE_TOLERANCE_SECS; _PROCESS_STARTED_AT captured at import) — default `CANCEL_STALE_TOLERANCE_SECS = 2.0`
- **Observe:** Leave a stale cancel.flag on the host and start a scan: system_<run_id>.log records `Removed stale cancel flag from a previous run` and the file is gone from control/, while the scan proceeds normally. Deliver a cancel during compilation instead and the flag survives and takes effect.
- **Source:** `YaraScanner._start_cancellation_watcher; _PROCESS_STARTED_AT; CANCEL_STALE_TOLERANCE_SECS`

### control/running.json liveness marker (atomic, refreshed)

A live scan writes and periodically refreshes a JSON liveness marker so a separate cancel invocation can tell a running scan from a dead one. Written via temp + os.replace so a cross-process reader never sees a half-written file. Refresh is rate-limited inside the writer (not by callers) and is driven from the cancellable walk, so it does not go stale while the producer is deep in a directory tree. Body: scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections.

- **Control:** not configurable (RUNNING_MARKER_REFRESH_SECS, RUNNING_MARKER_STALE_SECS) — default `refresh every 30.0s; a marker older than 180.0s is treated as dead by the cancel reader`
- **Observe:** `cat /opt/yara_scanner/control/running.json` during a scan — updated_at advances at least every 30s and files_scanned climbs. cancel() reports `scanner running: yes` while the marker is fresh, `no` once it is older than 180s or removed. running.json.tmp should never be observable for more than an instant.
- **Source:** `YaraScanner._write_running_marker / _maybe_refresh_running_marker; RUNNING_MARKER_REFRESH_SECS; RUNNING_MARKER_STALE_SECS; _handle_cancel_request's staleness read`

### Control-file teardown at end of scan

During enhanced cleanup the scanner consumes the cancel flag (only if a cancel was actually acted on, so it cannot also cancel the NEXT scan) and unconditionally removes the running marker, so a later cancel invocation correctly reports no scan running. Both removals are best-effort inside try/except.

- **Control:** not configurable — default `cancel.flag removed only when cancel_requested is true; running.json always removed`
- **Observe:** After any run completes, `ls /opt/yara_scanner/control/` shows neither running.json nor cancel.flag. Run cancel() against an idle host and it answers `scanner running: no \| scan_id=n/a`. Verify the no-double-cancel property by cancelling one scan and immediately starting another — the second runs to completion.
- **Source:** `YaraScanner._perform_enhanced_cleanup (`if getattr(self, "cancel_requested", False): self._clear_cancel_flag()` / `self._remove_running_marker()`); _clear_cancel_flag; _remove_running_marker`

### Scanner never quarantines, moves or deletes scanned files

The scanner's only writes to the scanned filesystem are inside its own working directory (plus the scheduled-task/systemd registration). Matched files are read for hashing and, optionally, copied into the ZIP — never renamed, moved, quarantined or deleted. This is what makes the offset cap safe: the file is still in place, so `yara -s <rules> "<path>"` regenerates every offset on demand.

- **Control:** not configurable — default `always — there is no os.rename/shutil.move anywhere targeting a scanned path`
- **Observe:** Compare a matched file's path, mtime and hash before and after a scan: unchanged and still present. The alert text states the recovery route in-line: `re-run \`yara -s\` against this file for every offset.` Every os.remove/shutil.rmtree in the file targets only logs_dir contents, alert_dir, evidence_dir, output_log, cancel.flag or running.json.
- **Source:** `Absence of any move/quarantine call; MAX_ALERT_OFFSETS_PER_FINDING comment block; CleanupManager.initial_cleanup's paths_to_clean`

### Scanner working directory is excluded from its own scan  <sub>all (matcher differs: case-folded component match on Windows, case-preserved on Linux, case-folded on macOS)</sub>

**⚠ CONTROL GAP**  
The scanner's own directory is inserted into every platform's skip list so the artefacts it writes are never re-scanned (which would otherwise grow findings on its own alert texts and evidence ZIP). Matching is component-anchored, not prefix-based: a bare startswith() also swallowed siblings like C:\yara_scanner_backup\evil.dll, turning any similarly-named directory into a permanent blind spot. Each list also matches the BARE directory root os.walk yields, not only its contents.

- **Control:** not configurable (self.scanner_dir appended to win_skip_folder / lin_skip_directory / mac_skip_directory) — default `Windows also carries the literal "C:\\yara_scanner\\"; Linux also carries "/opt/yara_scanner/"; every platform appends the resolved scanner_dir`
- **Observe:** Point a scan directly at the scanner_dir: the result line carries `WARNING: 1 requested target(s) EXCLUDED by the skip list, nothing under them was scanned: <path>` and scan_summary_<run_id>.json lists it under excluded_targets, with 0 files scanned for that target. Create a sibling <scanner_dir>_backup with a matching file and confirm it IS scanned.
- **Source:** `ScanConfig.__init__ (win_skip_folder / lin_skip_directory / mac_skip_directory entries built from self.scanner_dir); YaraScanner._is_special_file component-anchored matching; YaraScanner.excluded_targets`

---

# Delivery, Aggregation & Telemetry

*What leaves the endpoint, and how it is accounted for.*

### HTTP Collector NDJSON transport

Every event that leaves the endpoint goes out over one code path: an HTTPS POST to the XSIAM HTTP Collector with the collector key in a bare `Authorization` header and `Content-Type: text/plain`, body = UTF-8 NDJSON. Nothing else (no XDR API, no lookup dataset) is used.

- **Control:** API_ENDPOINT / API_KEY module globals, seeded from DEFAULT_API_ENDPOINT / DEFAULT_API_KEY at ScanConfig.__init__ (a console deployer edits those two constants). Request timeout DEFAULT_TIMEOUT_SECS. — default `DEFAULT_API_ENDPOINT = "http_collector_api", DEFAULT_API_KEY = "http_collector_key" (both placeholders); DEFAULT_TIMEOUT_SECS = 20 (LogManager's async batch path overrides it to timeout=10)`
- **Observe:** Collector-side: rows arrive in the HTTP Collector dataset with source="yara_scanner". Endpoint-side: <scanner_dir>/logs/uploads_<run_id>.log carries every batch result line; the scanner_initialization event's data.api_endpoint echoes the endpoint actually used, and data.webhook_key_source / webhook_endpoint_source read "default".
- **Source:** `_post_ndjson(), _get_webhook_endpoint(), DEFAULT_API_KEY/DEFAULT_API_ENDPOINT, ScanConfig.__init__ (self.webhook_key_source)`

### NDJSON-only multi-event encoding (JSON array is unsafe)

A batch is serialized as one JSON object per line joined by \n — never as a JSON array. The collector answers HTTP 200 {"error":"false"} to an array and then silently discards every event in it, so an array encoding produces invisible total data loss with a clean success in the books.

- **Control:** Not configurable — hardcoded in _ndjson_body(). — default `NDJSON, "\n".join(json.dumps(i.to_dict(), ensure_ascii=False))`
- **Observe:** Compare the scanner's own success counters against rows actually queryable in the dataset for one scan_id: NDJSON gives ok-count == row-count. A regression to array encoding shows successful_uploads > 0 in uploads_<run_id>.log and scan_summary's match_delivery, with zero matching rows in the tenant.
- **Source:** `_ndjson_body(); the WARNING comment block above UPLOAD_BATCH_MAX_EVENTS`

### Opportunistic (non-timer) batching with event and byte caps

Each uploader worker blocks for one event, then non-blockingly drains whatever is already queued behind it into a single POST, up to an event cap and an approximate byte cap. There is deliberately no linger timer, so a 3-match scan sends a batch of 3 immediately while a storm scan self-fills 500-event requests. Measured basis: 23,223 findings at ~756 ms/POST unbatched = ~4.9 h, of which 97% were never sent.

- **Control:** UPLOAD_BATCH_MAX_EVENTS (env YARA_UPLOAD_BATCH_MAX_EVENTS), UPLOAD_BATCH_MAX_BYTES (env YARA_UPLOAD_BATCH_MAX_BYTES); clamped afterwards to max(1, …) and max(64*1024, …). — default `500 events, 4 * 1024 * 1024 bytes (4 MB)`
- **Observe:** uploads_<run_id>.log lines "YARA match batch uploaded: N event(s) (HTTP 2xx)" — N is the realized batch size. Divide total findings by the number of such lines to confirm batching is engaging; a heavy scan should show N approaching 500, a quiet one N=1-3 with no added latency.
- **Source:** `_collect_batch(), UPLOAD_BATCH_MAX_EVENTS, UPLOAD_BATCH_MAX_BYTES, ResultsUploader._upload_worker / WebhookUploader._upload_worker / LogManager._webhook_worker`

### Approximate byte accounting for batch sizing

The byte cap is enforced on an estimate: each appended item adds len(json.dumps(item.to_dict())) to a running total, and any item that fails to serialize is charged a flat 1024 bytes rather than aborting the batch. The first item is always included regardless of size, so one oversized event can exceed the cap by its own size.

- **Control:** UPLOAD_BATCH_MAX_BYTES — default `4 MB cap; 1024-byte fallback charge per unserializable item`
- **Observe:** Inspect request sizes at the collector or on the wire: batches stay near but can overshoot the cap by at most one event. A finding carrying an unusually large matched string is the case to test.
- **Source:** `_collect_batch() (`approx += len(json.dumps(nxt.to_dict(), ensure_ascii=False))`, `except Exception: approx += 1024`)`

### Bounded retry with jittered exponential backoff

A failed batch is retried in-process on transient conditions only: HTTP 408/429/500/502/503/504 and requests.Timeout / requests.ConnectionError. Any other non-2xx is a hard failure with no retry. Delay is BASE_BACKOFF_SECS * 2^(attempt-1), ceilinged, multiplied by uniform jitter in [0.5, 1.0).

- **Control:** MAX_RETRIES_PER_ITEM, BASE_BACKOFF_SECS, MAX_BACKOFF_SECS — none env-overridable. — default `MAX_RETRIES_PER_ITEM = 2, BASE_BACKOFF_SECS = 1.0, MAX_BACKOFF_SECS = 30.0`
- **Observe:** uploads_<run_id>.log: "Batch upload failed (HTTP 503). Retrying in 0.7s (attempt 1/2, 500 event(s))." and "Batch upload network error (ConnectionError). Retrying in …". Exhaustion prints "YARA match batch exhausted retries (N event(s) not delivered)". Point the endpoint at a 503-returning URL to force it.
- **Source:** `_exp_backoff_delay(), ResultsUploader._upload_batch(), WebhookUploader._process_standard_batch()`

### Circuit breaker on the telemetry channel

WebhookUploader (telemetry/logs uploader) is guarded by a CircuitBreaker: after N consecutive failures it opens, and while open every batch is put back on the queue untouched followed by a 2 s sleep — no POST is attempted and no counters move. After the reset timeout it goes half_open and lets exactly one batch probe; failure re-opens it, success closes it. Counting happens AFTER the allow() check specifically so re-queued events are not counted repeatedly (an earlier bug showed total=31/failed=6 when nothing had landed). Note: the match channel (ResultsUploader) has NO circuit breaker — it retries per batch only.

- **Control:** CIRCUIT_FAILURE_THRESHOLD, CIRCUIT_RESET_TIMEOUT_SECS — not env-overridable. — default `CIRCUIT_FAILURE_THRESHOLD = 5, CIRCUIT_RESET_TIMEOUT_SECS = 40`
- **Observe:** With a dead collector, telemetry POSTs stop entirely for ~40 s windows while the queue grows; the per-type `total` in WebhookUploader.get_upload_statistics() (and scan_summary's telemetry_delivery) stays flat during an open window rather than inflating, and undelivered rises at shutdown.
- **Source:** `CircuitBreaker.allow/on_success/on_failure, WebhookUploader._process_standard_batch() (`if not self._circuit.allow(): … time.sleep(2.0)`)`

### Match finding grain: one upload item per (rule, file)

The findings channel emits exactly ONE event per (rule, file) finding, no matter how many string offsets matched. The original design queued one upload per matched offset — measured 33,118 rows from one rule against one .evtx, and a 36,213-item backlog here. Per-offset detail is not retained in memory at all; the local alert file is the full record.

- **Control:** Not configurable (structural in ResultsUploader.add_match). — default `1 event per (rule, file)`
- **Observe:** Query the dataset for type="yara_match" and a given scan_id: row count must equal the number of distinct (rule_id, file_name) pairs, and each row's match_count carries the offset total. uploads_<run_id>.log logs "Added N local result entries for rule 'X' in file: Y (1 upload item, K of N sampled)".
- **Source:** `ResultsUploader.add_match(), YaraScanner._write_alerts() (`self.results_uploader.add_match(...)` once per match object)`

### match_count vs sampled offsets/strings and the truncated flag

Each yara_match event carries the true total hit count (match_count) alongside a capped parallel sample of offsets and rendered strings, plus a boolean `truncated` set when match_count exceeds the sample length. offsets and strings are JSON-encoded strings (json.dumps of a list), positionally aligned.

- **Control:** MAX_MATCH_SAMPLES_PER_FINDING (env YARA_MAX_MATCH_SAMPLES), floored at minimum=1 — 0 or negative falls back to the default because its consumer is `if len(sample) < CAP`, so 0 would disable sampling entirely (the opposite of MAX_ALERT_OFFSETS_PER_FINDING, where 0 means "no cap"). — default `50`
- **Observe:** Scan a file that matches a rule far more than 50 times: the row shows match_count=<large>, truncated=true, and exactly 50 entries in each of offsets and strings. Under 50 hits: truncated=false and len(offsets)==match_count.
- **Source:** `MAX_MATCH_SAMPLES_PER_FINDING, ResultsUploader.add_match() (`truncated = match_count > len(_offsets_sample)`, `'offsets': json.dumps(_offsets_sample)`)`

### Uncapped per-string-ID census in the finding (match_ids)

Alongside the sampled offsets, every finding carries a complete, uncapped histogram of which string identifier in the rule fired and how many times, JSON-encoded — the detail an analyst actually works from, at one line's cost regardless of offset count. Condition-only hits key the census under an empty string.

- **Control:** Not configurable — deliberately uncapped. — default `Always present as data.match_ids`
- **Observe:** On a noisy rule, match_ids parses to e.g. {"$a": 21044, "$b": 3}; the sum of its values equals match_count even when truncated=true. Its local twin is the "Hits per string ID:" line in <scanner_dir>/alerts/<rule>.txt.
- **Source:** `ResultsUploader.add_match() (`_match_id_counts`, `'match_ids': json.dumps(_match_id_counts)`); YaraScanner._write_alerts() id_counts block`

### yara_match event payload shape (incl. dashboard-flattened aliases)

The findings event is type="yara_match", message "YARA match: rule 'R' in F (N string hit(s))" (or "YARA rule-only match: …"), with data carrying: filename, rule, the flattened dashboard aliases file_name and rule_id, threat_level, string (first rendered hit), offset (first offset), match_scope, match_count, offsets, strings, match_ids, truncated, string_match_count (raw YARA string-instance count), dateOfScan (uploader construction time, UTC ISO), file_sha256, file_creation_time.

- **Control:** threat_level comes from the alert_severity entry-point argument via config.alert_severity (validated low\|medium\|high by _parse_alert_severity). — default `alert_severity = "low"`
- **Observe:** XQL on type="yara_match": every listed field must be non-null for a string match; file_name/rule_id must mirror filename/rule (the "Yara Matches" dashboard queries only the flattened names). dateOfScan is identical across every finding of one run.
- **Source:** `ResultsUploader.add_match() data dict; _parse_alert_severity(); _render_match_data()`

### Condition-only match representation

A rule that fires on its condition with no string instances still produces a finding: the empty match list is replaced by a single synthetic entry carrying a human-readable condition summary, match_scope is "rule" instead of "string", offset is "" and the message says "YARA rule-only match".

- **Control:** Not configurable. — default `Fallback text "Condition-only YARA match; no string instances were produced." when no summary could be derived`
- **Observe:** Run a rule whose condition is e.g. `filesize > 0` with no strings: the row has match_scope="rule", match_count=1, string_match_count=0, offset="", and data.string holding the condition summary. Locally, alerts/<rule>.txt shows a "Condition Match Details:" block instead of offsets.
- **Source:** `_summarize_condition_only_match(), ResultsUploader.add_match() (`is_rule_only_match`, `'match_scope'`), YaraScanner._write_alerts() fallback_detail`

### One merged alert event per matched file

A matched file produces exactly ONE alert event, not two. _write_alerts used to emit "YARA detection event: N rules triggered" while scan_file emitted "YARA matches found in …" for the same file — measured 47,460 of 72,484 rows (65%) at 2.07 events per finding, mostly that duplication. _write_alerts now returns the detail and scan_file emits the union: file_path, real_path, file_size, file_sha256, file_creation_time, match_count (rule count), rules_matched, rules_triggered (retained alias), total_string_matches, detections[] (per-rule rows with rule_name/file_path/match_count/file_size/sha/creation time), detection_timestamp.

- **Control:** Not configurable. — default `1 alert event per matched file`
- **Observe:** XQL type="alert" for one scan_id: count must equal the number of distinct matched file paths (not findings). Each row carries both rules_matched and rules_triggered with identical arrays; grep alerts_<run_id>.log for "YARA matches found in" — no "YARA detection event" line should exist.
- **Source:** `YaraScanner.scan_file() log_manager.log_alert(...) block; YaraScanner._write_alerts() return dict + its explanatory comment`

### Six categorized event types from the log channel

LogManager mirrors every message to a per-category file AND (except one category) to the collector as an event whose `type` is the category name: alert, statistics, error, performance, system. LogType.UPLOAD is written to file but deliberately NEVER uploaded, so upload bookkeeping cannot feed back into the upload channel.

- **Control:** Gated by UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and a non-empty API_ENDPOINT and a live webhook thread. — default `UPLOAD_RESULTS = True, UPLOAD_NON_MATCH_DATA = True`
- **Observe:** XQL `type in ("alert","statistics","error","performance","system")` returns rows; `type="upload"` returns none, while <scanner_dir>/logs/uploads_<run_id>.log is non-empty on the host.
- **Source:** `LogType enum, LogManager._log_with_webhook() (`and log_type != LogType.UPLOAD`), LogManager.log_files dict`

### StandardLogEntry envelope on every event

Every event on every channel shares one envelope: type, hostname, os_info, ipAddress, timestamp (epoch float), timestamp_iso (UTC ISO-8601), scan_id, uploader_version, source, plus optional message, level, data. Empty message/level/data are omitted rather than sent as nulls.

- **Control:** Not configurable. — default `uploader_version = "enhanced_v2", source = "yara_scanner", level = "INFO"`
- **Observe:** Every row for a scan_id has source="yara_scanner" and uploader_version="enhanced_v2"; timestamp_iso parses as UTC. Filtering the dataset on source is the reliable way to isolate this scanner's traffic.
- **Source:** `StandardLogEntry.__init__ / to_dict(), create_standard_log()`

### Per-run scan_id correlation key

All events from one run share a scan_id of the form <hostname>_<run_id>_yara_<rule_hash[:12]>, where run_id is a microsecond timestamp. It is unique per RUN, not per ruleset — the earlier "yara_<hash>" form made every host in a fleet and every re-run report under one identical id, silently merging a fleet into a single scan for any consumer grouping by scan_id.

- **Control:** Derived: config.hostname, config.run_id (datetime %Y%m%d_%H%M%S_%f), sha256 of the decoded rule text. — default `e.g. WINSERVER01_20260817_101500_123456_yara_9f2c1ab34de0`
- **Observe:** Two runs on the same host with the same rules must yield two distinct scan_ids in the dataset; the trailing 12 hex chars are stable for a given ruleset. scan_summary_<run_id>.json echoes both scan_id and the full rule_hash.
- **Source:** `ScanConfig.__init__ (`self.scan_id = f"{self.hostname}_{self.run_id}_yara_{yara_hash[:12]}"`, `self.rule_hash`)`

### Critical-path synchronous send with async fallback

Once-per-scan dashboard-critical signals bypass the batch queue: they POST a single event synchronously as application/json (not NDJSON) so they are not stuck behind an existing backlog, and only fall back to the async queue if that send fails. A raised exception is logged as an explicit duplicate-risk warning — the request may have landed — consistent with the scanner's honest-books-over-exactly-once stance. If no async thread exists to fall back to, the event is counted as failed and logged as dropped.

- **Control:** Timeout DEFAULT_TIMEOUT_SECS; used by log_statistics_critical (per-target completion) and log_performance_critical (worker startup). — default `DEFAULT_TIMEOUT_SECS = 20`
- **Observe:** "Target scan completed: <path>" (type="statistics") and "Worker thread startup completed in Xs" (type="performance") land in the tenant while a long scan is still running and its queue is deep. On failure, uploads_<run_id>.log shows "Critical log immediate send failed (HTTP …) - falling back to async queue" or "… raised <Err> … (may deliver a duplicate if the request actually landed)".
- **Source:** `LogManager._log_critical(), log_statistics_critical(), log_performance_critical()`

### scan_status lifecycle events

A dedicated type="scan_status" event is emitted on every status transition, carrying scan_id, scan_status, scan_start_time, current_time, elapsed_time_seconds, elapsed_time_formatted and, when stats are supplied, files_scanned/files_skipped/detections_found/current_file/scan_targets/valid_rules_count/failed_rules_count/scan_rate_files_per_second. The observed vocabulary is: starting (initial), initializing, starting_workers, scanning, finishing, then a terminal value — completed, cancelled, interrupted, error, or failed. Terminal status is emitted late in main(), after the summary and delivery books settle, so a dashboard can distinguish a finished scan from one hung in shutdown.

- **Control:** Requires UPLOAD_RESULTS, UPLOAD_NON_MATCH_DATA, API_ENDPOINT, and webhook_uploader wired in by main(); otherwise set_status only mutates local state. — default `Initial scan_status = "starting"`
- **Observe:** XQL type="scan_status" for a scan_id ordered by timestamp must end on a terminal value — never on "finishing". A cooperative cancel must produce "cancelled"; a crash produces "error" then "failed".
- **Source:** `ScanStatusUploader.upload_scan_status()/set_status(); call sites in scan_system(), _perform_enhanced_cleanup(), main()`

### scanner_initialization event

A priority-queued type="scanner_initialization" event carrying the full run configuration: hostname, os_info, ip_addresses, platform, python_version, yara_version, rule_source, scan_targets, max_workers, scan_queue_size, max_file_mb, scanner_profile, performance/resource monitoring flags, upload_enabled, webhook_key_source, webhook_endpoint_source, api_endpoint, default_alert_severity, telemetry_upload_enabled, logging_format.

- **Control:** Not configurable; the same dict is also logged as a system event "YARA Scanner initialization completed". — default `scanner_profile = "light", logging_format = "standardized"`
- **Observe:** Exactly one type="scanner_initialization" row per scan_id, and it is the cheapest way to confirm the effective knob values (workers, max_file_mb, monitoring toggles) a run actually used.
- **Source:** `main() init_data + create_standard_log(log_type='scanner_initialization'), _queue_standard_upload(..., priority=True)`

### statistics_summary checkpoints with per-type rate limiting

WebhookUploader.upload_statistics_summary emits type="statistics_summary" events (phases: "initialization", "scan_configuration"), but only if the per-data-type minimum interval has elapsed — a coarse rate limiter shared by all types that route through _should_upload/_mark_uploaded.

- **Control:** WebhookUploader.upload_intervals dict; not env-overridable. — default `performance 30 s, statistics 60 s, system_resource 45 s, worker_stats 120 s, time_estimates 60 s; unknown types 60 s`
- **Observe:** Two statistics_summary emissions less than 60 s apart yield one row — visible as a missing "scan_configuration" phase row on a very fast scan.
- **Source:** `WebhookUploader.upload_statistics_summary(), _should_upload(), _mark_uploaded(), self.upload_intervals`

### scan_completion_summary event with honest outcome

A priority-queued terminal summary carrying scan_duration_seconds/_formatted, files_processed/scanned/skipped, total_detections, unique_rules_triggered, performance_metrics, webhook_upload_stats, log_generation_stats, error_summary{compilation_errors, scan_errors}, plus outcome ("completed"\|"cancelled") and cancel_source when cancelled. The message text switches to "Scan cancelled by operator after …(partial results)" so telemetry cannot contradict the Action Center result line. A critical crash emits the same type with data.status="critical_error", error_message and error_type at level ERROR.

- **Control:** Not configurable. — default `outcome = "completed" unless scanner.cancel_requested`
- **Observe:** XQL type="scan_completion_summary": exactly one row per run; data.outcome must agree with the SCAN_RESULT line and with scan_summary_<run_id>.json's outcome. Cancel a scan and confirm outcome="cancelled" plus a non-empty cancel_source.
- **Source:** `main() comprehensive_final_stats block; the except-branch create_standard_log(log_type='scan_completion_summary')`

### comprehensive_final_report event and efficiency score

A separate priority-queued type="comprehensive_final_report" carrying scan_metadata (incl. targets_scanned and ISO start/end), file_processing (incl. skip_breakdown and processing_rate), detection_results (breakdown, top_10_rules, detection_rate_percent), rule_compilation (valid/failed/success rate), system_info (platform, python_version, yara_version, cpu_count, worker_threads_used), plus performance_summary, resource_summary and upload_summary when available. It also computes efficiency_score = 100 - skip_rate*20 - rule_failure_rate*30, floored at 0.

- **Control:** Not configurable. — default `efficiency_score starts at 100`
- **Observe:** One type="comprehensive_final_report" row per run, message "Comprehensive scan report - Efficiency Score: X/100"; data.upload_summary embeds the telemetry delivery books at that moment. Mirrored to statistics_<run_id>.log as "COMPREHENSIVE SCAN REPORT \| Efficiency Score: …".
- **Source:** `upload_final_comprehensive_report()`

### Scan-progress telemetry on a whole-scan heartbeat  <sub>all — but metrics.disk_io_mb is always 0 on macOS: psutil Process.io_counters() does not exist there and is caught (AttributeError/NotImplementedError/AccessDenied)</sub>

type="statistics" progress events carrying files_scanned, files_skipped, total_detections, queue_size, scan_rate_files_per_sec, a top-level flattened active_workers (the dashboard's "Capacity vs Backpressure" widget filters on the top-level column) and a nested metrics dict with cpu_percent, memory_mb, disk_io_mb, network_mb, active_workers, elapsed_seconds, eta_seconds, junction_skips, unique_real_paths. Driven by a dedicated heartbeat thread spanning the whole scan (discovery AND the worker drain afterwards) — checking only inside the discovery walk produced zero progress events on every host tested.

- **Control:** config.log_interval (env YARA_PROGRESS_LOG_SECS), clamped to >= 1 s. — default `30 seconds (was 120; a 15,589-file Windows scan's active phase is shorter than 120 s and produced no samples at all)`
- **Observe:** XQL type="statistics" with message starting "Scan Progress \|": a scan longer than 30 s must yield >= 1 row, and active_workers must be readable as a top-level field, not only under metrics.
- **Source:** `LogManager.log_scan_progress(), YaraScanner._progress_heartbeat(), YaraScanner._log_progress(), ScanConfig.log_interval`

### Time-estimate telemetry

When an ETA is computable, a type="statistics" event carrying eta_seconds, estimated_completion (ISO), current_rate_files_per_sec and files_remaining is emitted alongside each progress tick.

- **Control:** Piggybacks on the progress heartbeat interval (config.log_interval); rate limiter key 'time_estimates' = 120 s applies only to the statistics_summary path, not this one. — default `Emitted every log_interval (30 s) when eta_seconds is truthy`
- **Observe:** XQL type="statistics" message starting "Time Estimates \|". Absence on a short scan is expected (no ETA yet).
- **Source:** `LogManager.log_time_estimates(), YaraScanner._log_progress() (`if eta_seconds:`)`

### Worker performance telemetry

**⚠ CONTROL GAP**  
Each worker emits a type="performance" event every 100 files processed with worker_id, files_processed, avg_processing_time_ms and error_rate_percent; on exit it emits a type="system" "Worker <id> stopped" event with files_processed, errors_encountered and average_processing_time_ms; and at the end of the scan a single aggregated "Worker performance summary" performance event carries worker_details for all workers.

- **Control:** Hardcoded every-100-files cadence; worker count is config.max_workers. — default `max_workers = max(1, min(2, YARA_THREADS or (1 if cpu_count<=2 else 2))) — hard-capped at 2`
- **Observe:** XQL type="performance" message starting "Worker Performance \| ScanWorker-": expect floor(files_processed/100) rows per worker. Also visible in performance_<run_id>.log.
- **Source:** `YaraScanner._worker() (`if files_processed % 100 == 0`), LogManager.log_worker_performance(), YaraScanner._log_final_results() worker_summary block`

### CPU governor telemetry

The CPU governor emits a type="performance" event carrying policy, target, own, others and ratio, on a meaningful change in the throttle ratio OR on a heartbeat — change-only emission produced a single line across a whole scan on an idle host, which is exactly the case a customer wants evidence for.

- **Control:** GOVERNOR_HEARTBEAT_SECS (env YARA_GOVERNOR_HEARTBEAT_SECS); emission also triggers on \|ratio delta\| >= 0.25. Sampling cadence is config.throttle_check_interval_secs (env YARA_CPU_SAMPLE_SECS). Policy/targets: CPU_GUARANTEE, CPU_HEADROOM_PCT, CPU_BUDGET_PCT, CPU_FLOOR_PCT. — default `GOVERNOR_HEARTBEAT_SECS = 30, YARA_CPU_SAMPLE_SECS = 0.5; CPU_GUARANTEE = "headroom", headroom 30%, budget 25%, floor 5%`
- **Observe:** XQL type="performance" message starting "CPU governor \| policy=": on a scan longer than 30 s there must be recurring rows even when nothing changes. If CPU cannot be read the governor disables itself and emits "CPU governor disabled - could not read CPU (…). Scan continues unthrottled." exactly once.
- **Source:** `YaraScanner._sample_governor(), CpuGovernor.stats(), GOVERNOR_HEARTBEAT_SECS`

### system_resource_snapshot and resource_monitoring_summary events  <sub>all — process io_read_mb/io_write_mb are forced to 0 on macOS (platform.system() == 'Darwin' guard); load_avg is (0,0,0) where psutil.getloadavg is unavailable (Windows on older psutil)</sub>

When resource monitoring is enabled, a background thread samples every 10 s and uploads a type="system_resource_snapshot" every 45 s carrying nested process/system/network/efficiency blocks, computed trends (cpu_trend, memory_trend, cpu_avg_10min, memory_avg_10min, data_points), alert_count_last_hour, monitoring_duration_minutes, and four flattened dashboard fields — proc_cpu_percent, proc_memory_mb, sys_cpu_percent, sys_memory_used_percent (the widgets filter on these exact top-level names). At shutdown a priority type="resource_monitoring_summary" carries data_points_collected, cpu_stats/memory_stats min-max-avg-current, alerts_triggered and last_alert_time.

- **Control:** ENABLE_RESOURCE_MONITOR (env YARA_ENABLE_RESOURCE_MONITOR) → config.enable_resource_monitoring; SystemResourceMonitor.monitoring_interval and .upload_interval are hardcoded. — default `ENABLE_RESOURCE_MONITOR = False (so neither event type is emitted by default); monitoring_interval = 10 s, upload_interval = 45 s`
- **Observe:** With the flag left at its default, XQL type="system_resource_snapshot" must return ZERO rows — that absence is the correct default-state assertion. Flip it on and expect one row per ~45 s plus one resource_monitoring_summary at the end.
- **Source:** `ENABLE_RESOURCE_MONITOR, SystemResourceMonitor._monitoring_worker/_upload_resource_data/stop_monitoring()`

### Resource threshold alerts as error events  <sub>all (disk usage is measured on '/' via psutil.disk_usage('/'))</sub>

Each resource sample is checked against thresholds; a breach emits a type="error" event "RESOURCE ALERT: <kind> - X% exceeds threshold of Y%" with alert_type, current_value and threshold, and is appended to a bounded alert history (maxlen 100) that later feeds alerts_triggered in the resource summary.

- **Control:** SystemResourceMonitor.alert_thresholds; not env-overridable. Only active when resource monitoring is enabled. — default `cpu_percent 90, memory_percent 85, disk_usage_percent 95`
- **Observe:** XQL type="error" message starting "RESOURCE ALERT:" — none by default since the monitor is off.
- **Source:** `SystemResourceMonitor._check_resource_alerts(), self.alert_thresholds, self.alert_history (deque maxlen=100)`

### privilege_status event  <sub>linux, macos only — never emitted on Windows</sub>

On non-Windows hosts a type="privilege_status" event reports running_as_root and a recommended_action, at level WARNING when not root. Emitted regardless of whether a system path was requested; the accompanying "System path scan requires elevated privileges" text goes out as system/error log events.

- **Control:** Not configurable. — default `data.platform is hardcoded to 'linux' even on macOS; recommended_action = 'run_as_sudo' when not root`
- **Observe:** XQL type="privilege_status" for a Linux/macOS scan; zero rows on Windows.
- **Source:** `main() (`if platform.system() != "Windows": … log_type='privilege_status'`)`

### resource_limit_warning event  <sub>linux, macos only</sub>

On non-Windows hosts with FD monitoring enabled, the scanner shells out for `ulimit -n` and, if the limit is below 8192, emits a type="resource_limit_warning" event at level WARNING carrying current_limit, recommended_limit and an impact string.

- **Control:** ENABLE_FD_MONITOR (env YARA_ENABLE_FD_MONITOR) → config.enable_fd_monitoring. — default `ENABLE_FD_MONITOR = False; threshold 8192, recommended_limit 65536`
- **Observe:** XQL type="resource_limit_warning" — zero rows by default and on Windows. system_<run_id>.log carries "Current file descriptor limit: N" when enabled.
- **Source:** `main() ulimit block (`log_type='resource_limit_warning'`), ENABLE_FD_MONITOR`

### Match-channel delivery accounting (successful / failed / undelivered)

ResultsUploader keeps four counters: total_matches (NB: incremented per matched OFFSET, not per upload item), successful_uploads and failed_uploads (both per EVENT — a rejected 500-event batch counts 500 failures, not 1), and undelivered — items still sitting in the queue when the drain window expired, i.e. never attempted. Undelivered exists so that "0 failed" cannot read as fully delivered while items sit stranded.

- **Control:** Not configurable. — default `All four start at 0`
- **Observe:** uploads_<run_id>.log final line: "Match delivery final: matches=N ok=A failed=B undelivered=C"; if C>0 a matching error line is also written. The same dict is embedded verbatim as match_delivery in scan_summary_<run_id>.json.
- **Source:** `ResultsUploader.upload_stats dict, _upload_batch() (`+= n`), stop() leftover-drain block`

### Telemetry-channel delivery accounting (per type + undelivered)

WebhookUploader keeps per-event-type total/successful/failed (a mixed batch credits each event against its own type) and, at read time, an undelivered count equal to the current queue depth. undelivered was previously computed, logged and discarded, so telemetry_delivery could not be balanced and a total delivery outage read as a clean run.

- **Control:** Not configurable. — default `defaultdict of {total:0, successful:0, failed:0}; success_rate_percent derived`
- **Observe:** get_upload_statistics() returns {summary:{total_uploads, successful_uploads, failed_uploads, undelivered, success_rate_percent}, by_type:{…}, queue_size}. Observable as telemetry_delivery in scan_summary_<run_id>.json, as data.upload_summary inside comprehensive_final_report, and in the uploads log line "WebhookUploader stopped. Success rate: X% (N telemetry item(s) undelivered at shutdown)".
- **Source:** `WebhookUploader.upload_stats, _process_standard_batch() by_type accounting, get_upload_statistics(), stop_uploader()`

### Log-channel delivery accounting

LogManager tracks total_logs, successful_uploads, failed_uploads and a by_type breakdown across the six LogType categories, and emits them at shutdown as a type="system" event with log_files_created listing the six on-disk paths.

- **Control:** Not configurable. — default `by_type initialized to 0 for all six LogType values`
- **Observe:** XQL type="system" message starting "Logging Summary \| Total Logs:" with data.webhook_successful_uploads / webhook_failed_uploads / logs_by_type / log_files_created. Note the success-rate denominator is total_logs, which includes the never-uploaded UPLOAD category, so 100% is not expected.
- **Source:** `LogManager.upload_stats, log_final_summary(), get_upload_statistics()`

### Backlog-proportional shutdown drain window

Each queue gets a drain budget scaled to its own backlog rather than a flat timeout: budget = clamp(pending * per-item, min, max). A flat window was either too short for a storm scan (a 12 s scan's own "scan completed" event needed ~250 s to reach the collector) or wastefully long for a light one. The max is a PER-SITE cap and there are FOUR sequential drain sites (LogManager.webhook_queue plus three uploader queues), so a worst case is ~4 x 60 s = 240 s — deliberately kept inside a normal Action Center script timeout after an earlier 300 s cap let sites run back-to-back until the agent killed the process mid-drain, losing everything queued.

- **Control:** DRAIN_MIN_SECS (YARA_DRAIN_MIN_SECS), DRAIN_PER_ITEM_SECS (YARA_DRAIN_PER_ITEM_SECS), DRAIN_MAX_SECS (YARA_DRAIN_MAX_SECS); thread join capped by THREAD_CLEANUP_TIMEOUT. — default `DRAIN_MIN_SECS = 15, DRAIN_PER_ITEM_SECS = 0.3, DRAIN_MAX_SECS = 60, THREAD_CLEANUP_TIMEOUT = 60`
- **Observe:** uploads_<run_id>.log announces each window before waiting: "Waiting for N pending match uploads (max Ms)...", "Waiting for N pending telemetry uploads (max Ms)...", "Waiting for N pending standardized log uploads (max Ms)...". Time the gap between the last finding and process exit against N*0.3 clamped to [15,60].
- **Source:** `_compute_drain_budget(), ResultsUploader.stop(), WebhookUploader.stop_uploader(), LogManager.stop_logging(), ResultsUploader.upload_results()`

### Shutdown ordering that protects end-of-run events

The findings uploader is stopped inside _perform_enhanced_cleanup, but the telemetry uploader is deliberately NOT — main() still queues comprehensive_final_report and scan_completion_summary through it after scan_system() returns, and stopping it early silently dropped those. It is stopped in main()'s finally block, after all queuing is done and before the scan summary JSON is written (so the delivery counts in the JSON are final) and before stop_logging (so the "summary written" line still reaches the logs). Both uploader stops are idempotent, so main()'s safety-net second call does not re-pay a full drain window.

- **Control:** Not configurable. — default `Order: results_uploader.stop(wait=True) → webhook_uploader.stop_uploader() → write_scan_summary() → log_manager.stop_logging()`
- **Observe:** Both comprehensive_final_report and scan_completion_summary must be present in the tenant for a normal run. Calling stop twice must not produce a second "Waiting for N pending …" line in uploads_<run_id>.log.
- **Source:** `YaraScanner._perform_enhanced_cleanup() (comment: "webhook_uploader is intentionally NOT stopped here"), main() finally block, ResultsUploader.stop() `_stop_done` guard, WebhookUploader.stop_uploader() `_stop_done` guard`

### Delivery shortfall surfaced on the operator's result line

The string main() returns (and prints as SCAN_RESULT) names match-channel loss explicitly: " \| WARNING: L of Q finding upload(s) NOT delivered (failed=F, undelivered=U) - local logs hold the complete record". The denominator is deliberately ok+failed+undelivered (UPLOAD ITEMS), not total_matches (OFFSETS) — mixing them understates loss by the average offsets-per-finding factor, thousands on a noisy rule. Separately, telemetry-channel failures append " \| Upload errors: N", and a stdout WARNING block is printed when telemetry failures are non-zero.

- **Control:** Not configurable. — default `Both clauses absent when nothing was lost`
- **Observe:** Point API_ENDPOINT at a black hole and read the Action Center result / stdout SCAN_RESULT line: it must carry both the "Upload errors" and the "NOT delivered" clauses rather than reading as a clean success.
- **Source:** `main() `shortfall` block and `upload_errors` block; sys.stdout WARNING block; ported from the XDR edition's _delivery_shortfall()`

### Result line honesty: cancelled verb, skipped rules, excluded targets

The same result line refuses three other flavours of false-clean. A cancelled run says "Scan cancelled (source=…)" instead of "Scan completed" (caught in testing: a cancel truncating a scan at 1,669 of 4,000 files still returned "Scan completed"). Rules skipped for a missing libyara module are reported separately from failed rules. A requested target wholly excluded by the skip list is named, because "0 files scanned" is otherwise indistinguishable from an empty directory.

- **Control:** Not configurable. — default `Format: "<verb>: N files scanned \| R rules failed compilation[ \| S rules skipped (module unavailable)] \| M matches found[upload errors][shortfall][ \| WARNING: K requested target(s) EXCLUDED …]" (first 3 excluded targets listed, then " ...")`
- **Observe:** Run against a target on the skip list (e.g. an AppData\Local\Temp path) and check the SCAN_RESULT line names it; cancel a scan and check the verb. excluded_targets is also a first-class key in scan_summary_<run_id>.json.
- **Source:** `main() `_verb` / `_skipped_txt` / `_excl_txt` blocks; YaraScanner.excluded_targets appended in scan_system()`

### scan_summary_<run_id>.json with both delivery books  <sub>all (path differs by OS)</sub>

One machine-readable per-run summary written atomically (tmp + os.replace, temp removed on failure) to <scanner_dir>/logs/. Carries schema "yara_scan_summary/v1", edition "xsiam", run_id, scan_id, rule_hash, hostname, os_info, ip_address, scanner_version, then outcome (completed\|cancelled\|failed), failure_reasons, scan_folder, scan_targets, excluded_targets, duration_secs, files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, and crucially match_delivery + telemetry_delivery — the two delivery books. It is the only surviving evidence when the console's Cancel hard-kills the payload.

- **Control:** Path is <scanner_dir>/logs/scan_summary_<run_id>.json; scanner_dir = C:\yara_scanner (Windows), /usr/local/yara_scanner (macOS), /opt/yara_scanner (Linux), overridable by YARA_SCANNER_DIR. — default `Written on every run that got as far as constructing a scanner; outcome defaults to "completed" only when neither cancel_requested nor scan_failed is set`
- **Observe:** Read the file on the host after a run and assert outcome agrees with the SCAN_RESULT line, and that match_delivery.successful_uploads + failed + undelivered equals the number of (rule,file) findings. A crash in main() sets scan_failed so the JSON says "failed" rather than contradicting the result line.
- **Source:** `LogManager.write_scan_summary(), main() finally block summary dict, _default_scanner_dir()`

### Credential placeholder detection and early abort

Before anything is scanned, main() rejects placeholder or malformed collector credentials: endpoint empty, equal to the fixed placeholder sentinel, or not starting with "http"; key empty or equal to its sentinel. It returns "SCAN ABORTED - XSIAM HTTP Collector credentials are not set…". The sentinels are separate constants from DEFAULT_API_KEY/DEFAULT_API_ENDPOINT precisely because the deployment guide has editors overwrite the DEFAULTs, so a "still equals DEFAULT" test could never detect a placeholder once edited. Without this, every POST fails, the scan "completes" with nothing ingested, and the failure is visible only in endpoint logs.

- **Control:** _PLACEHOLDER_API_KEY / _PLACEHOLDER_API_ENDPOINT; the check is skipped entirely when UPLOAD_RESULTS is False (local-only scan). — default `_PLACEHOLDER_API_KEY = "http_collector_key", _PLACEHOLDER_API_ENDPOINT = "http_collector_api"`
- **Observe:** Run the unedited script: the Action Center result and stdout read "SCAN_RESULT: SCAN ABORTED - …Nothing was scanned.", the process exits 1, and scan_errors_<run_id>.log carries the same text. No files are scanned and no events are sent.
- **Source:** `main() `_ep_bad`/`_key_bad` block; __main__ exit-code guard (`_rt.startswith("scan aborted")`)`

### Result printing and exit-code contract

main()'s return value is printed as "SCAN_RESULT: <text>" on stdout — previously it was computed, used for the exit code and thrown away, so a direct run reported nothing at all. The prefix matches the Action Center snippet footer so downstream parsing is identical on both paths. Exit is 0 unless the text starts with "scan failed", "scan aborted" or "cancel failed" (case-insensitive), or is empty.

- **Control:** Not configurable. — default `exit 0 on success, 1 on the three failure prefixes / empty result / startup exception`
- **Observe:** `python3 xsiam_yara_scanner.py <rules_b64> <folder>; echo $?` — one SCAN_RESULT line and the matching code. A placeholder-credential run must exit 1, not 0.
- **Source:** `__main__ block (`print("SCAN_RESULT: " + result_text)`, `is_success`)`

### Cancel entry point and its delivery guarantee  <sub>all (control dir under the platform scanner_dir)</sub>

cancel() (zero-input, plus `cancel` as argv[1]) writes <scanner_dir>/control/cancel.flag and reports whether a scan looks alive from control/running.json. It deliberately does not initialize logging, compile rules or touch the collector. Its value on this dimension: a cooperative cancel unwinds the scan, drains its queues and writes scan_summary_<run_id>.json, whereas the console's Cancel button hard-kills the payload — queued findings lost, no summary, no terminal event.

- **Control:** CANCEL_POLL_SECS (env YARA_CANCEL_POLL_SECS, floored at 0.5), RUNNING_MARKER_STALE_SECS, RUNNING_MARKER_REFRESH_SECS, CANCEL_STALE_TOLERANCE_SECS. — default `CANCEL_POLL_SECS = 5, RUNNING_MARKER_REFRESH_SECS = 30, RUNNING_MARKER_STALE_SECS = 180, CANCEL_STALE_TOLERANCE_SECS = 2.0`
- **Observe:** cancel() returns "Cancel signal delivered (<path>) \| scanner running: yes\|no \| scan_id=…". Then, on the cancelled run: a type="scan_status" row with scan_status="cancelled", a scan_completion_summary with outcome="cancelled" and cancel_source, and a scan_summary JSON with outcome="cancelled" — none of which appear after a console hard-kill.
- **Source:** `cancel(), _handle_cancel_request(), YaraScanner._cancellation_watcher()/_write_running_marker(), main() `_was_cancelled` handling`

### Throttled upload logging

Upload-path log messages are rate-limited per bucket: the first N of a bucket are emitted in full, then one suppression notice, then a running count every M occurrences. This keeps a sustained collector outage or a very match-heavy scan from ballooning the endpoint's own log files with one line per event, while still surfacing that something is wrong and how much.

- **Control:** _throttled_log(full=…, every=…) defaults; buckets in use: upload_ok, upload_retry, upload_err, upload_neterr. — default `full = 20, every = 1000`
- **Observe:** With a dead collector, uploads_<run_id>.log shows 20 full errors, then "[upload_err] further similar messages suppressed; will summarize every 1000. Example: …", then "[upload_err] 1000 occurrences so far; latest: …".
- **Source:** `ResultsUploader._throttled_log(), call sites in _upload_batch()`

### Bounded skip-reason labels in shipped aggregates

Per-file scan errors are collapsed to "Scan error (<ExceptionType>)" before entering skip_reasons, because both common error texts embed the absolute path (yara.Error 'could not open file "<path>"', OSError '[Errno 2] …: <path>'). skip_reasons is serialized whole into the final report and a statistics event, so raw messages meant unbounded payload growth — measured at 307,780 bytes for 5,000 errored files. The exception type is kept so distinct failures stay distinguishable, and the word "error" is kept because the final report counts error reasons by that substring.

- **Control:** Not configurable. — default `Label format: "Scan error (PermissionError)", "Scan error (OSError)", …`
- **Observe:** comprehensive_final_report.data.file_processing.skip_breakdown (and the "Skip reasons:" statistics event) must contain a small fixed set of keys with no filesystem paths in them, regardless of how many files errored. Per-file detail with the real message and path is still in scan_errors_<run_id>.log.
- **Source:** `_scan_error_reason(), YaraScanner.scan_file() return, upload_final_comprehensive_report() skip_breakdown`

### Matched-data rendering for the wire

Matched bytes are rendered to printable text before going into the event (and into the local alert file): UTF-16 LE when the byte pattern looks wide (YARA wide-string matches otherwise carry embedded NULs into the payload and break editors), else UTF-8, else lowercase hex for binary blobs.

- **Control:** Not configurable. — default `utf-16-le → utf-8 → .hex()`
- **Observe:** Match a wide (UTF-16) string: the row's data.string and the strings sample read as clean text with no \x00, while a binary match renders as an even-length hex string.
- **Source:** `_render_match_data(), used by ResultsUploader.add_match() and YaraScanner._write_alerts()`

### Local alert file as the uncapped offset record

The on-host counterpart to the sampled network representation: <scanner_dir>/alerts/<rule>.txt records, per matched file, the SHA256, creation time, a COMPLETE and uncapped "Hits per string ID" census, then a capped render of individual offsets with an explicit omission footer naming the knob and telling the responder to re-run `yara -s` for the rest. Rendering every offset previously produced a 220 MB file on a live Windows endpoint (2,433,386 offsets, 98.6% from four Windows event logs).

- **Control:** MAX_ALERT_OFFSETS_PER_FINDING (env YARA_MAX_ALERT_OFFSETS), clamped to >= 0, where 0 means NO CAP (the inverse of MAX_MATCH_SAMPLES_PER_FINDING's 0-handling). — default `50 — chosen to match MAX_MATCH_SAMPLES_PER_FINDING so the local file and the yara_match row show the same sample`
- **Observe:** On a noisy rule: alerts/<rule>.txt shows "Total string hits: 21047", a complete per-ID census, "Matched Strings (showing 50 of 21047):", and "20997 further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=50)…". Cross-check the census against the row's match_ids — they must agree.
- **Source:** `MAX_ALERT_OFFSETS_PER_FINDING, YaraScanner._write_alerts() (`cap = MAX_ALERT_OFFSETS_PER_FINDING`, `shown = strings if cap <= 0 else strings[:cap]`)`

### No in-memory retention of per-offset detail

ResultsUploader keeps no local copy of per-offset match data. It used to build one dict per matched offset and hold them for the whole scan — measured 1,048,035 offsets → ~15 GB RSS on one endpoint — to be serialized by a save_results() that was never actually called, so the data was accumulated and then discarded. Streaming it to disk was considered and rejected because _write_alerts already records every offset.

- **Control:** Not configurable. — default `Zero retention; only aggregate counters are kept`
- **Observe:** Scan a file that produces hundreds of thousands of offsets and watch process RSS (the system_resource_snapshot proc_memory_mb field, or psutil on the host): it must stay flat rather than tracking offset count. No per-offset JSON artefact exists under <scanner_dir>.
- **Source:** `ResultsUploader.__init__ leading comment; add_match() building only _offsets_sample/_strings_sample/_match_id_counts`

### Six per-category log files as the local delivery record  <sub>all (logs dir differs by OS via _default_scanner_dir())</sub>

Every run writes six run-scoped text logs under <scanner_dir>/logs/: alerts_<run_id>.log, statistics_<run_id>.log, scan_errors_<run_id>.log, performance_<run_id>.log, uploads_<run_id>.log, system_<run_id>.log — opened in mode "w" with a fixed "[ts.ms] [LEVEL] message" format and propagate=False. uploads_<run_id>.log is the one that never leaves the host, making it the authoritative account of what delivery actually did.

- **Control:** config.logs_dir under scanner_dir (YARA_SCANNER_DIR override); filenames keyed on config.run_id. — default `Formatter "[%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s", datefmt "%Y-%m-%d %H:%M:%S", level INFO`
- **Observe:** List <scanner_dir>/logs/ after a run: six files plus scan_summary_<run_id>.json, all sharing one run_id. The paths are also echoed in the "Logging Summary" system event's data.log_files_created.
- **Source:** `LogManager.log_files dict, LogManager._setup_logger()`

### Upload channels can be disabled independently

Two module-level switches gate delivery: UPLOAD_RESULTS gates everything (with it False the placeholder-credential abort is also skipped, giving a genuinely local-only scan), and UPLOAD_NON_MATCH_DATA gates telemetry/log/status events only, leaving findings uploading. A missing/empty API_ENDPOINT independently prevents any uploader thread from starting.

- **Control:** UPLOAD_RESULTS, UPLOAD_NON_MATCH_DATA — plain module constants, no env override. — default `Both True`
- **Observe:** scanner_initialization data.upload_enabled and data.telemetry_upload_enabled echo the two flags. With UPLOAD_RESULTS False, uploads_<run_id>.log ends with "Upload disabled - N matches saved locally"; with API_ENDPOINT empty it logs "API_ENDPOINT not configured - real-time match upload disabled".
- **Source:** `UPLOAD_RESULTS, UPLOAD_NON_MATCH_DATA, ResultsUploader._start_upload_thread(), LogManager.__init__ / _log_with_webhook(), WebhookUploader.__init__, ScanStatusUploader.upload_scan_status()`

### Queue-full handling on the findings channel

Queueing a finding uses a 1.0 s put timeout; if the queue cannot accept it the finding's network representation is dropped with an explicit log line rather than blocking the scan thread. The queues themselves are unbounded Queue() instances, so this fires only under pathological conditions — but the drop is logged, never silent.

- **Control:** Not configurable (put timeout=1.0). — default `Unbounded Queue(); 1.0 s put timeout on the match channel, 1.0 s (0.1 s when priority=True) on the telemetry channel`
- **Observe:** uploads_<run_id>.log line "Upload queue full - skipping real-time upload for finding". Its presence means findings exist locally (in alerts/<rule>.txt) with no corresponding tenant row.
- **Source:** `ResultsUploader.add_match() (`self.upload_queue.put(standard_log, timeout=1.0)` / except branch), WebhookUploader._queue_standard_upload()`

---

# Scan Lifecycle, Control & Error Handling

*Phases, cancellation, outcomes, failure paths.*

### Scan entry point main(yarafile, scan_folder, alert_severity)

The scan entry point Action Center calls. Three inputs: base64/plain YARA rule text, a comma-separated list of scan folders (or None/'default' for platform default targets), and an alert severity. Returns a single result string; never raises to the caller (all exceptions are caught and turned into a 'Scan failed: ... Critical error occurred' string).

- **Control:** Signature is fixed (Action Center derives the input list from it). alert_severity default 'low'; scan_folder default None; yarafile default None (then module constant YARA_RULE must be non-empty, else ValueError). — default `main(yarafile=None, scan_folder=None, alert_severity="low")`
- **Observe:** Action Center 'Run by entry point' shows exactly 3 inputs; the returned string is the result line (CLI prints it as 'SCAN_RESULT: <line>'). Also visible as the run_id-stamped log set under <scanner_dir>/logs/.
- **Source:** `def main(yarafile=None, scan_folder=None, alert_severity="low") (line ~6008)`

### Cancel entry point cancel() — zero inputs

Second Action Center entry point that requests a cooperative cancel of a running scan on the same endpoint. Deliberately zero-input (not a `mode` param on main()) so main()'s 3-input contract is unchanged; it does no logging setup, no rule compilation and no collector traffic — it only writes the flag and reads the liveness marker.

- **Control:** not configurable — default `n/a`
- **Observe:** Returns 'Cancel signal delivered (<flag path>) \| scanner running: yes\|no \| scan_id=<id>' in the Action Center result; <scanner_dir>/control/cancel.flag appears on disk containing {requested_at_ms, source:'action_center'}.
- **Source:** `def cancel() -> _handle_cancel_request()`

### CLI dispatch and exit-code contract

Direct execution maps argv[1..3] to main()'s three inputs; argv[1] == 'cancel' (case-insensitive) routes to cancel() instead. The result string is printed with the same 'SCAN_RESULT: ' prefix the Action Center snippet footer uses, then the process exits 0 on success and 1 when the result starts with 'scan failed', 'scan aborted' or 'cancel failed' (case-insensitive), or when the result is empty. A startup exception exits 1.

- **Control:** not configurable — default `alert_severity_arg = "low" when argv[3] absent`
- **Observe:** stdout line 'SCAN_RESULT: ...' plus `echo $?` / %ERRORLEVEL%.
- **Source:** `if __name__ == "__main__" block; is_success = bool(result_text) and not (_rt.startswith(...))`

### Cancel flag file (control/cancel.flag)  <sub>all (path differs by OS)</sub>

Cooperative cancel channel: a JSON flag file the running scan polls for. It exists because the console's own Cancel button hard-kills the payload process (no flush, no summary, no terminal event); the flag lets the scan unwind, drain its queues and write its summary.

- **Control:** Directory from ScanConfig.control_dir = <scanner_dir>/control; scanner_dir from env YARA_SCANNER_DIR, else platform default — default `C:\yara_scanner\control\cancel.flag (Windows), /usr/local/yara_scanner/control/cancel.flag (macOS), /opt/yara_scanner/control/cancel.flag (Linux)`
- **Observe:** File exists after cancel(); contains requested_at_ms and source. It is removed by the scan once acted on. Cancel-side failures return 'Cancel failed: cannot write <path>: ...'.
- **Source:** `_handle_cancel_request(); YaraScanner.cancel_flag_path; _default_scanner_dir()`

### Running marker (control/running.json) and liveness reporting

Atomically written liveness marker (temp file + os.replace) that the cancel entry point reads to say whether a scan is alive. Written with status 'compiling' in YaraScanner.__init__ BEFORE rule compilation, then 'running' when the watcher starts, refreshed during the scan, and deleted in _perform_enhanced_cleanup. Payload: scan_id, run_id, pid, hostname, started_at, updated_at, status, files_scanned, detections.

- **Control:** RUNNING_MARKER_REFRESH_SECS (refresh cadence), RUNNING_MARKER_STALE_SECS (age beyond which cancel() reports 'scanner running: no'). Neither is env-overridable. — default `RUNNING_MARKER_REFRESH_SECS = 30.0; RUNNING_MARKER_STALE_SECS = 180.0`
- **Observe:** cat <scanner_dir>/control/running.json during a scan — updated_at advances at least every 30s and status goes compiling -> running; the file is gone after a normal finish. cancel()'s result line reports 'scanner running: yes' and echoes scan_id from it. NOTE: a crash during rule compilation leaves the 'compiling' marker behind (only _perform_enhanced_cleanup removes it).
- **Source:** `_write_running_marker(), _maybe_refresh_running_marker(), _remove_running_marker(); staleness compare in _handle_cancel_request()`

### Running-marker refresh from two independent sites

The marker is refreshed both from the discovery loop (per directory) and from the timed progress-heartbeat thread. The discovery loop can block inside _enqueue_scan_path while the scan queue is saturated, which alone could let the marker go stale on a live scan and make cancel() report 'scanner running: no'. Refresh is self-rate-limited in _maybe_refresh_running_marker, not by callers.

- **Control:** RUNNING_MARKER_REFRESH_SECS; heartbeat tick = config.log_interval (env YARA_PROGRESS_LOG_SECS) — default `30.0s refresh; log_interval 30s (clamped to >= 1)`
- **Observe:** Saturate the queue (large directory, low YARA_QUEUE_SIZE) and confirm running.json's updated_at still advances and cancel() still reports 'scanner running: yes'.
- **Source:** `_progress_heartbeat() -> self._maybe_refresh_running_marker(); scan_system() discovery loop -> self._maybe_refresh_running_marker()`

### Stale cancel-flag protection anchored at module import

At watcher start, a pre-existing cancel.flag is deleted ONLY if its mtime predates process start minus a tolerance. The anchor is _PROCESS_STARTED_AT, captured at module import (before ScanConfig and rule compilation), so a cancel delivered DURING a long rule compile has a newer mtime and is preserved and honoured; the naive 'delete any pre-existing flag' version silently lost it.

- **Control:** CANCEL_STALE_TOLERANCE_SECS (mtime slack for coarse filesystems); anchor not configurable — default `CANCEL_STALE_TOLERANCE_SECS = 2.0; _PROCESS_STARTED_AT = time.time() at import`
- **Observe:** system_<run_id>.log line 'Removed stale cancel flag from a previous run' for a genuinely old flag; conversely, drop a flag while a big ruleset compiles and the scan still ends cancelled. Failure to evaluate logs 'Could not evaluate pre-existing cancel flag: ...'.
- **Source:** `_start_cancellation_watcher(); self._process_started_at = _PROCESS_STARTED_AT in YaraScanner.__init__`

### Cancellation watcher thread and poll cadence

Daemon thread named 'CancelWatcher' that polls for cancel.flag while the scan is active, reads the flag's 'source' field, and calls _request_cancel(source). The sleep is inside the try block so a bad poll interval cannot silently kill the thread; on error it logs and retries after 1.0s. The interval is floored so a negative value cannot raise in time.sleep() and 0 cannot busy-spin.

- **Control:** env YARA_CANCEL_POLL_SECS, floored: CANCEL_POLL_SECS = max(0.5, _env_number("YARA_CANCEL_POLL_SECS", 5)) — default `5 seconds (hard floor 0.5s)`
- **Observe:** Time from writing cancel.flag to the system log line 'Cancellation requested (source=action_center)' is <= poll interval; thread name 'CancelWatcher' in any thread dump. Watcher errors appear as 'Cancel watcher error: ...' in scan_errors_<run_id>.log.
- **Source:** `_cancellation_watcher(); _start_cancellation_watcher() thread name="CancelWatcher", daemon=True`

### _request_cancel — idempotent, first-source-wins, thread-safe

Single funnel for cancellation from any thread: under _cancel_lock it sets cancel_requested=True, records cancel_source, and clears scan_active. Clearing scan_active is the one action that unwinds both the producer walk and the workers. A second call is a no-op, so the first source is what gets reported.

- **Control:** not configurable — default `cancel_requested=False, cancel_source="" at start`
- **Observe:** system log 'Cancellation requested (source=<source>)' appears exactly once; the result line and telemetry both carry that same source.
- **Source:** `YaraScanner._request_cancel(self, source, log=True)`

### Bounded cancellation latency in directory traversal (_walk_cancellable)

os.walk replacement driven by an explicit stack, checking scan_active before every directory and between entries, so cancellation latency is bounded by ONE scandir call rather than by os.walk's internal recursion. Contract matches os.walk(topdown=True) — yields (dirpath, dirnames, filenames) and honours in-place pruning of dirnames because the stack is extended after the yield; symlinked directories are listed but not recursed (followlinks=False). PermissionError/FileNotFoundError/NotADirectoryError/OSError on a directory are skipped; an entry whose is_dir() raises OSError is classified as a file so the per-file error path reports it.

- **Control:** not configurable — default `n/a`
- **Observe:** Cancel a scan of a deep tree and measure wall time from the flag write to process exit; compare against 'Scan terminated by external signal' in the system log and the running.json removal.
- **Source:** `YaraScanner._walk_cancellable(self, target)`

### Worker-side cancellation and drain

**⚠ CONTROL GAP**  
Each worker loops `while self.scan_active`, taking paths with a 5.0s queue timeout (Empty -> continue). Cancellation drops scan_active so workers exit their loop; at shutdown one None sentinel per worker is also pushed so idle workers wake immediately. Each worker logs a 'Worker <id> stopped' event with files_processed, errors_encountered and average_processing_time_ms.

- **Control:** config.max_workers (env YARA_THREADS), hard-clamped to at most 2; queue get timeout is hardcoded 5.0s in _worker (module constant WORKER_GET_TIMEOUT_SECS=2.0 is used by the webhook uploader, not here) — default `max_workers = max(1, min(2, YARA_THREADS or (1 if cpu_count<=2 else 2)))`
- **Observe:** system_<run_id>.log 'Worker ScanWorker-N started' / 'Worker ScanWorker-N stopped' pairs with their data payloads; performance log 'Worker cleanup: X stopped, Y timed out in Z s'.
- **Source:** `YaraScanner._worker(); _perform_enhanced_cleanup() sentinel loop `for _ in range(self.config.max_workers): self.scan_queue.put(None, timeout=1.0)``

### Worker join with bounded timeout

Shutdown joins each worker thread with a 5s timeout, counts successful vs timed-out joins, names any thread that did not terminate, and continues regardless — a stuck worker cannot hang the run. main() later re-joins any still-alive scan thread with timeout=2 before returning.

- **Control:** not configurable (5s per-thread join, 2s final re-join) — default `t.join(timeout=5); later t.join(timeout=2)`
- **Observe:** performance_<run_id>.log 'Worker cleanup: N stopped, M timed out in T s'; error log 'Worker thread <name> did not finish - continuing anyway' and 'Threads did not terminate: [...]'.
- **Source:** `_perform_enhanced_cleanup(); main()'s remaining_threads block`

### Cancel-flag consumption and marker removal at shutdown

During cleanup, the cancel flag is deleted ONLY if this run actually acted on a cancel (cancel_requested), so it cannot also cancel the NEXT scan; the running marker is removed unconditionally so cancel() correctly reports no scan running afterwards.

- **Control:** not configurable — default `n/a`
- **Observe:** After a cancelled run: control/cancel.flag gone, control/running.json gone. After a normal run: running.json gone, and any flag written after cleanup survives for the next scan.
- **Source:** `_perform_enhanced_cleanup(): `if getattr(self, "cancel_requested", False): self._clear_cancel_flag()` then `self._remove_running_marker()`; _clear_cancel_flag(), _remove_running_marker()`

### Backlog-proportional shutdown drain

Every queue drain window is sized from the pending backlog rather than a flat timeout: min(DRAIN_MAX, max(DRAIN_MIN, pending * DRAIN_PER_ITEM)). There are FOUR independent drain sites (LogManager.webhook_queue plus the three uploader classes' upload_queue), drained sequentially, so DRAIN_MAX_SECS is a per-site cap, not a total (4 x 60s worst case).

- **Control:** env YARA_DRAIN_MIN_SECS / YARA_DRAIN_PER_ITEM_SECS / YARA_DRAIN_MAX_SECS — default `DRAIN_MIN_SECS=15, DRAIN_PER_ITEM_SECS=0.3, DRAIN_MAX_SECS=60`
- **Observe:** uploads_<run_id>.log 'Waiting for N pending match uploads (max Xs)...' and 'Waiting for N pending standardized log uploads (max Xs)...'; the announced max scales with N.
- **Source:** `_compute_drain_budget(pending_items); used in ResultsUploader.stop() and LogManager.stop_logging()`

### Honest undelivered accounting after the drain window

Whatever is still queued when the drain window expires is counted as 'undelivered' (never attempted) rather than silently dropped, distinct from 'failed_uploads' (attempted and rejected). If the upload thread is dead the queue is fully drained and counted exactly; otherwise the queued count minus the sentinel is used.

- **Control:** not configurable — default `upload_stats = {'total_matches':0,'successful_uploads':0,'failed_uploads':0,'undelivered':0}`
- **Observe:** uploads_<run_id>.log 'Match delivery final: matches=… ok=… failed=… undelivered=…', plus an error line 'N match upload(s) undelivered within the drain window'; same numbers appear in scan_summary's match_delivery block and on the result line's shortfall warning.
- **Source:** `ResultsUploader.stop(); get_upload_stats()`

### Idempotent uploader stop

ResultsUploader.stop() is guarded by _stop_done so main()'s finally-block safety net does not re-pay a full drain window after _perform_enhanced_cleanup already stopped it. webhook_uploader is deliberately NOT stopped in cleanup — main() still queues comprehensive_final_report and scan_completion_summary after scan_system() returns; it is stopped only in main()'s finally.

- **Control:** not configurable — default `_stop_done = False`
- **Observe:** Exactly one 'Match delivery final: ...' line per run in uploads_<run_id>.log; the comprehensive_final_report and scan_completion_summary events still arrive at the collector after scan end.
- **Source:** `ResultsUploader.stop(self, wait=True) `if self._stop_done: return`; comment block in _perform_enhanced_cleanup`

### scan_status lifecycle values and the terminal status

Non-terminal phases emitted in order: 'initializing' -> 'starting_workers' -> 'scanning' -> 'finishing'. A terminal value is always emitted after the summary and delivery books have settled: 'completed' or 'cancelled' on the normal path, 'failed' on the fatal-failure path, 'error' on an exception inside scan_system or around scan_system in main, 'interrupted' on KeyboardInterrupt. Initial in-memory value before any emission is 'starting'. The terminal emission is wrapped in try/except so it can never mask the result line.

- **Control:** not configurable; suppressed entirely if UPLOAD_RESULTS/UPLOAD_NON_MATCH_DATA are off or API_ENDPOINT is empty, or before main() wires webhook_uploader onto the status uploader — default `scan_status = "starting"`
- **Observe:** A scan_status event per transition in the collector (type='scan_status', message='Scan status: <value>'), and the local line 'Scan status changed to: <value>' via the root logger. Test criterion: every run ends with exactly one terminal value in {completed, cancelled, failed, error, interrupted}.
- **Source:** `ScanStatusUploader.set_status()/upload_scan_status(); set_status calls at lines 5621/5725/5747/5773/5870/6254/6257/6278/6457`

### scan_status event payload

Each scan_status event carries scan_id, scan_status, scan_start_time (UTC ISO), current_time, elapsed_time_seconds, elapsed_time_formatted; when scanner_stats are supplied it also carries files_scanned, files_skipped, detections_found, current_file, scan_targets, valid_rules_count, failed_rules_count and scan_rate_files_per_second.

- **Control:** not configurable — default `scanner_stats is None on every current set_status() call, so only the six base fields are emitted today`
- **Observe:** Query the collector for type='scan_status' and check data.elapsed_time_seconds increases across the phase sequence.
- **Source:** `ScanStatusUploader.upload_scan_status(self, scanner_stats=None)`

### Outcome classification (completed / cancelled / failed)

One precedence rule decides the run's outcome for the summary JSON: cancel_requested -> 'cancelled'; else scan_failed -> 'failed'; else 'completed'. The main-level except handler sets scanner.scan_failed = True and appends 'Critical scanner error: <Type>' precisely so a crash cannot be recorded as 'completed'.

- **Control:** not configurable — default `outcome defaults to 'completed' only when neither flag is set`
- **Observe:** scan_summary_<run_id>.json 'outcome' field; it must agree with the SCAN_RESULT verb and with the terminal scan_status event.
- **Source:** `main() finally-block: `if getattr(scanner,"cancel_requested",False): _outcome="cancelled" elif getattr(scanner,"scan_failed",False): _outcome="failed" else: _outcome="completed"``

### Outcome agreement in end-of-scan telemetry

The scan_completion_summary event's message and its data.outcome are derived from the same cancel flag as the result line, so a cancelled run reports 'Scan cancelled by operator after <elapsed> (partial results)' with outcome='cancelled' plus cancel_source, instead of 'completed successfully'. The statistics log line mirrors it ('SCAN CANCELLED BY OPERATOR after ...' vs 'SCAN COMPLETED SUCCESSFULLY in ...').

- **Control:** not configurable — default `outcome='completed' when not cancelled`
- **Observe:** Collector event type='scan_completion_summary': data.outcome, data.cancel_source, message text; statistics_<run_id>.log final line.
- **Source:** `main(): _was_cancelled / _completion_msg / comprehensive_final_stats['outcome']`

### scan_completion_summary metrics block

Priority-queued end-of-run telemetry carrying scan_duration_seconds, scan_duration_formatted, files_processed (scanned+skipped), files_scanned, files_skipped, total_detections, unique_rules_triggered, performance_metrics, webhook_upload_stats, log_generation_stats, error_summary{compilation_errors, scan_errors} plus outcome/cancel_source.

- **Control:** not configurable; requires UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA — default `UPLOAD_RESULTS = True, UPLOAD_NON_MATCH_DATA = True`
- **Observe:** One collector event of type 'scan_completion_summary' per run; error_summary.scan_errors is the count of skip_reasons whose key contains 'error'.
- **Source:** `main(): comprehensive_final_stats -> create_standard_log(log_type='scan_completion_summary', ...) queued with priority=True`

### Fatal worker failure path

An unhandled exception escaping a worker's inner loop calls _mark_scan_failed(reason), which under lock_failures sets scan_failed=True, appends the reason to failure_reasons, and clears scan_active (stopping the whole scan). A fatal error inside scan_system's target loop does the same and additionally sets status 'error'. main() then logs 'Scan stopped due to fatal failures' with failure_count, the first 20 failure_reasons, files_scanned, files_skipped and detections, and returns a 'Scan failed: ...' result line.

- **Control:** not configurable — default `scan_failed=False, failure_reasons=[]`
- **Observe:** scan_errors_<run_id>.log 'Worker <id> fatal error: ...' and 'Scan stopped due to fatal failures'; result line begins 'Scan failed:'; summary outcome='failed' with the reasons in failure_reasons; exit code 1 on CLI.
- **Source:** `YaraScanner._mark_scan_failed(); _worker()'s outer except; scan_system()'s except; main()'s `if scanner.scan_failed:` block`

### Evidence and terminal telemetry survive a fatal failure

The fatal-failure branch no longer returns immediately: it first emits terminal status 'failed' and then runs evidence_collector.collect_evidence(), each in its own try/except, so a scan that FOUND matches and then died still produces its evidence ZIP (alert texts + file_mapping) and still tells the dashboard how it ended. Both are best-effort — a failing scan must still return its result line.

- **Control:** not configurable — default `n/a`
- **Observe:** After forcing a fatal failure with at least one match: an evidence_<hostname>_<run_id>.zip exists under <scanner_dir>/evidence, a terminal scan_status='failed' event is present, and system log shows 'Evidence collected from failed scan' (or the error line 'Evidence collection failed after fatal failure: ...' / 'Could not emit terminal status after failure: ...').
- **Source:** `main(): try: scanner.status_uploader.set_status("failed") / try: scanner.evidence_collector.collect_evidence()`

### Critical-error path in main()

Any exception escaping the main body is caught and turned into a result string; it also writes a machine-greppable 'SCAN_STATUS: ERROR' plus the full traceback to stderr and a 'CRITICAL ERROR' block to stdout, sleeps 2s, logs CRITICAL_ERROR to the error channel, flips error_logger.has_errors, records the exception via ExceptionLogger, queues a priority scan_completion_summary with data.status='critical_error' and the error type, and marks the scanner failed so the summary JSON says 'failed'.

- **Control:** not configurable — default `n/a`
- **Observe:** stderr contains 'SCAN_STATUS: ERROR'; collector has a scan_completion_summary with data.status='critical_error'; <scanner_dir>/logs/script_exceptions_<run_id>.log exists (created lazily, only when an exception is logged); result line ends 'Critical error occurred'.
- **Source:** `main()'s outer `except Exception as e:` block`

### KeyboardInterrupt handling  <sub>all (interactive/CLI runs)</sub>

Ctrl+C around scan_system() is treated as an abnormal stop, not a clean finish: scan_active=False, scan_failed=True, failure_reasons gets 'Scan interrupted by user', and status 'interrupted' is emitted; execution then falls into the fatal-failure branch.

- **Control:** not configurable — default `n/a`
- **Observe:** system log 'Scan interrupted by user (Ctrl+C)'; scan_status='interrupted' event; summary outcome='failed' with that reason; result line 'Scan failed: ...'.
- **Source:** `main(): `except KeyboardInterrupt:` around scanner.scan_system()`

### Guaranteed finalisation order in main()'s finally block

Regardless of outcome the finally block runs, in this order: stop stats monitoring -> results_uploader.stop(wait=True) -> webhook_uploader.stop_uploader() -> write scan_summary_<run_id>.json -> log_manager.stop_logging(). The summary is written AFTER the uploaders drain (so delivery counts are final) and BEFORE stop_logging (so the 'Scan summary written' line still reaches the logs). A failure in the block is reported to stderr as 'Error during final cleanup: ...'.

- **Control:** not configurable — default `n/a`
- **Observe:** Timestamps: uploads_<run_id>.log 'Match delivery final' precedes the summary file mtime, which precedes the 'Logging Summary \| ...' line in system_<run_id>.log.
- **Source:** `main()'s `finally:` block`

### scan_summary_<run_id>.json artefact

One machine-readable JSON per run, written atomically (tmp + os.replace, temp removed on failure) into the logs directory. It is the only surviving evidence when the console's Cancel button hard-kills the payload. Guarded by `'scanner' in locals() and scanner is not None`, so a run that dies before YaraScanner is constructed (e.g. rule compilation failure) produces no summary.

- **Control:** Path = <scanner_dir>/logs/scan_summary_<run_id>.json; run_id = datetime '%Y%m%d_%H%M%S_%f' — default `n/a`
- **Observe:** File presence and contents; system log line 'Scan summary written: scan_summary_<run_id>.json' or the error 'Failed to write scan summary JSON: ...' / 'Scan summary write failed: ...'.
- **Source:** `LogManager.write_scan_summary(summary); called from main()'s finally block`

### scan_summary field contract

Header fields written by write_scan_summary: schema='yara_scan_summary/v1', edition='xsiam', run_id, scan_id, rule_hash (full sha256 of the decoded rule text), hostname, os_info, ip_address, scanner_version. Body fields supplied by main(): outcome, failure_reasons (list), scan_folder (raw parameter), scan_targets, excluded_targets, duration_secs (rounded to 2dp, or null), files_scanned, files_skipped, matches, unique_rules_triggered, failed_rules, valid_rules, skipped_rules, scan_rate_fps, match_delivery (ResultsUploader books: total_matches/successful_uploads/failed_uploads/undelivered) and telemetry_delivery (WebhookUploader summary block). Serialised with default=str, ensure_ascii=False, indent=2.

- **Control:** not configurable — default `skipped_rules defaults to 0; scan_rate_fps 0 when duration is unknown/zero`
- **Observe:** Parse the JSON and assert every key above exists; cross-check outcome vs SCAN_RESULT verb, matches vs the result line's match count, and match_delivery against the 'Match delivery final' log line.
- **Source:** `LogManager.write_scan_summary() record dict + main()'s log_manager.write_scan_summary({...}) call`

### Duration derivation for the summary

duration_secs prefers scan_total_time (measured around scan_system), falls back to time.time() - scan_start_time when the run died before that was computed, and is null when even scan_start_time was never set — so a crashed run reports an honest duration or none, never a fabricated 0.

- **Control:** not configurable — default `None`
- **Observe:** Kill a run mid-scan via the fatal path and confirm duration_secs is a plausible partial elapsed value, not 0 and not absent.
- **Source:** `main() finally: `_dur = (scan_total_time if 'scan_total_time' in locals() else (time.time() - scan_start_time) if 'scan_start_time' in locals() else None)``

### Operator result line composition

The returned string is assembled as: '<verb>: <files_scanned> files scanned \| <failed_rules> rules failed compilation[ \| <n> rules skipped (module unavailable)] \| <matches> matches found[ \| Upload errors: <n>][ \| WARNING: <n> of <m> finding upload(s) NOT delivered (failed=…, undelivered=…) - local logs hold the complete record][ \| WARNING: <n> requested target(s) EXCLUDED by the skip list, nothing under them was scanned: a, b, c ...]'. The verb is 'Scan completed' or 'Scan cancelled (source=<source>)'.

- **Control:** not configurable — default `Optional segments are omitted when their counters are zero/empty; excluded targets list is truncated to the first 3 with ' ...'`
- **Observe:** The Action Center result field / 'SCAN_RESULT: ' stdout line. Each optional segment is individually testable (cancel, module-skipped rules, failed uploads, undelivered findings, excluded target).
- **Source:** `main(): _verb / _skipped_txt / upload_errors / shortfall / _excl_txt -> `summary = (f"{_verb}: ...")``

### Cancelled runs never report 'Scan completed'

A cancelled run stopped early by request, so its file/match counts are a partial view; the result verb switches to 'Scan cancelled (source=...)' and names the source. (Regression caught in testing: a cancel that truncated a scan at 1,669 of 4,000 files still returned 'Scan completed'.)

- **Control:** not configurable — default `n/a`
- **Observe:** Result line starts with 'Scan cancelled (source=action_center)'; cross-check summary outcome='cancelled' and terminal scan_status='cancelled'.
- **Source:** `main(): `if getattr(scanner, "cancel_requested", False): _verb = f"Scan cancelled (source={...})"``

### Match-channel delivery shortfall on the result line

Separate from the telemetry uploader's 'Upload errors', the findings channel's own loss is surfaced: lost = failed_uploads + undelivered over a denominator of ok+failed+undelivered (upload ITEMS — one per rule/file finding — deliberately not total_matches, which counts offsets). Read after results_uploader.stop(wait=True), so the values are settled; the whole computation is wrapped in try/except and degrades to an empty string.

- **Control:** not configurable — default `omitted when lost == 0`
- **Observe:** Point the collector at an unreachable endpoint, produce matches, and confirm the ' \| WARNING: N of M finding upload(s) NOT delivered (failed=…, undelivered=…)' segment appears and matches the summary's match_delivery block.
- **Source:** `main()'s `shortfall` block using scanner.results_uploader.get_upload_stats()`

### Telemetry upload-error surfacing

If the webhook (telemetry) uploader recorded failed uploads, the result line gains ' \| Upload errors: <n>' (or ' \| Upload errors: unknown' if the stats read itself fails), and stdout gets a two-line WARNING that the scan completed but some results may not have been uploaded.

- **Control:** not configurable — default `omitted when failed_uploads == 0`
- **Observe:** stdout 'WARNING: N upload operations failed'; result-line segment; same number in summary telemetry_delivery.failed_uploads.
- **Source:** `main(): upload_stats['summary']['failed_uploads'] blocks`

### Excluded-target detection  <sub>all (skip lists differ per OS)</sub>

**⚠ CONTROL GAP**  
A scan target the operator explicitly requested but which the skip list excludes wholesale is recorded in scanner.excluded_targets and logged as an error, because otherwise the run reports 0 files scanned, outcome 'completed' and exit 0 — indistinguishable from an empty directory (real case: scanning AppData\Local\Temp).

- **Control:** Driven by the platform skip lists (win_skip_folder / lin_skip_directory / mac_skip_directory / skip_path_fragments) in ScanConfig — default `excluded_targets = []`
- **Observe:** scan_errors_<run_id>.log 'Requested scan target is excluded by the skip list...' with data {'target_path','reason':'skip_list'}; the result line's EXCLUDED warning; summary field excluded_targets.
- **Source:** `scan_system(): `if self._is_special_file(target): self.excluded_targets.append(target)``

### Per-file outcome classification and skip reasons

scan_file returns (scanned: bool, reason: str) for every file and the worker folds the reason into the aggregate skip_reasons counter. Reason strings: 'File does not exist', 'No read permission', 'Special system file', 'Junction/symlink duplicate', 'Not a regular file', 'File too large', 'Permission denied', 'Scanned and matched', 'Scanned but not matched', plus 'Skipped directory' and 'Junction/symlink skip' counted in the discovery loop.

- **Control:** Size gate from config.max_file_bytes (env YARA_MAX_MB, minimum=0 where 0 means no cap); duplicate detection from config.track_real_paths — default `YARA_MAX_MB = 64; track_real_paths = False`
- **Observe:** statistics_<run_id>.log 'Skip reasons: reason(count), ...' with data.skip_breakdown; the same dict appears in the comprehensive_final_report's file_processing.skip_breakdown. files_scanned + files_skipped must reconcile.
- **Source:** `YaraScanner.scan_file() return values; _worker()'s skip_reasons accumulation; scan_system()'s directory-level counters`

### Bounded skip reason for per-file scan errors

A per-file exception is bucketed as 'Scan error (<ExceptionTypeName>)' instead of str(exc). Both common error texts embed the absolute path (yara.Error 'could not open file "<path>"', OSError '[Errno 2] ...: <path>'), which made every errored file its own skip_reasons key — unbounded growth shipped to the tenant, measured at 307,780 bytes for 5,000 errored files. The exception type keeps genuinely different failures distinguishable, and the word 'error' is retained because the final report counts error reasons by that substring.

- **Control:** not configurable — default `n/a`
- **Observe:** skip_breakdown keys are of the form 'Scan error (OSError)' with a count, and the key count stays small; the per-file message and path still appear once per file in scan_errors_<run_id>.log as 'Error scanning file <path>: ...' plus a stderr line 'File scan error: <path> - ...'.
- **Source:** `_scan_error_reason(exc); scan_file()'s `except Exception as e: return False, _scan_error_reason(e)``

### Per-file error tolerance in the worker loop

A non-fatal exception inside the worker's per-item body is logged (to stderr and the error channel), increments that worker's errors_encountered, and the loop continues — one bad file cannot end the scan. Empty (queue timeout) is skipped silently. Only an exception escaping the loop itself is treated as fatal.

- **Control:** not configurable — default `n/a`
- **Observe:** scan_errors_<run_id>.log 'Worker <id> error: <Type>: <msg>' lines while files_scanned keeps rising; the worker's final 'Worker <id> stopped' event reports errors_encountered.
- **Source:** `YaraScanner._worker() inner `except Exception as e:` (continue) vs outer `except Exception` (_mark_scan_failed)`

### Permission-denied diagnostics  <sub>all (uid fields POSIX-only)</sub>

When a file fails os.access(R_OK) the scanner records a diagnostic with file_path, file_mode (octal), owner_uid, scanner_uid (None on Windows) and requires_root (owner is uid 0 or path under /etc, /boot, /var/log, /root), appends it to scanner.permission_denials, and returns skip reason 'No read permission'.

- **Control:** not configurable — default `n/a`
- **Observe:** system_<run_id>.log 'Permission denied: <path>' with that data payload; skip_breakdown['No read permission'] count. requires_root/scanner_uid are meaningful only on POSIX.
- **Source:** `scan_file()'s `if not os.access(file_path, os.R_OK):` block`

### Env-var guard: numeric tuning knobs fail safe

**⚠ CONTROL GAP**  
_env_number parses a numeric env override and falls back to the documented default (with a logged warning) when the value does not parse OR is below an explicit minimum. Range checking exists because parsing is not validation: YARA_MAX_MB=-1 parsed fine, made max_file_bytes negative, and every file failed the size check — a scan that reported 'completed' having scanned nothing.

- **Control:** Per-knob minimum argument; applies to YARA_MAX_SAMPLES/YARA_MAX_MB/YARA_THREADS/YARA_QUEUE_SIZE/YARA_PROGRESS_LOG_SECS/YARA_CPU_* /YARA_DRAIN_* /YARA_CANCEL_POLL_SECS/YARA_UPLOAD_BATCH_* /YARA_MAX_ALERT_OFFSETS/YARA_QUEUE_BACKOFF_SECS — default `Falls back to each knob's shipped default`
- **Observe:** Set e.g. YARA_MAX_MB=-1 or YARA_THREADS=abc and look for the root-logger warning 'Ignoring invalid <NAME>=... - using default ...' / 'Ignoring out-of-range <NAME>=... (minimum ...) - using default ...' (stderr at WARNING level after setup_logging); then confirm the scan still scans files.
- **Source:** `def _env_number(name, default, cast=float, minimum=None)`

### Env-var guard: boolean toggles fail safe

_env_bool accepts 1/true/yes/on and 0/false/no/off (case-insensitive, trimmed); anything else warns and falls back to the constant's literal default, so a malformed toggle cannot crash the scanner at import time. The literal in source is what a console deployer edits; the env var is an automation-only override.

- **Control:** YARA_ENABLE_RESOURCE_MONITOR, YARA_ENABLE_PERF_MONITOR, YARA_ENABLE_FD_MONITOR, YARA_COLLECT_MATCHED_FILES — default `ENABLE_RESOURCE_MONITOR=False, ENABLE_PERF_MONITOR=False, ENABLE_FD_MONITOR=False, COLLECT_MATCHED_FILES=False`
- **Observe:** Warning line 'Ignoring invalid <NAME>=... (expected true/false) - using default ...'; the effective values appear in the scanner_initialization event's performance_monitoring_enabled / resource_monitoring_enabled fields.
- **Source:** `def _env_bool(name, default)`

### Post-parse clamping of lifecycle knobs

**⚠ CONTROL GAP**  
Several knobs are clamped after parsing so a legal-but-unusable value cannot break the run: CANCEL_POLL_SECS floored at 0.5 (0 would busy-spin, negative would raise inside time.sleep and silently kill the watcher); log_interval floored at 1 (Event.wait(0) would busy-spin and flood the unbounded webhook queue); scan_queue_size floored at 2; max_workers clamped to max(1, min(2, ...)); UPLOAD_BATCH_MAX_EVENTS >= 1 and UPLOAD_BATCH_MAX_BYTES >= 64KB.

- **Control:** YARA_CANCEL_POLL_SECS, YARA_PROGRESS_LOG_SECS, YARA_QUEUE_SIZE, YARA_THREADS, YARA_UPLOAD_BATCH_MAX_EVENTS/BYTES — default `5s poll, 30s progress, queue = max_workers*2, workers 1-2, 500 events / 4 MiB`
- **Observe:** Set YARA_PROGRESS_LOG_SECS=0 and YARA_THREADS=99 and confirm the scanner_initialization event still reports max_workers<=2 and that progress events arrive about once a second rather than continuously.
- **Source:** `CANCEL_POLL_SECS = max(0.5, ...); self.log_interval = max(1, ...); self.max_workers = max(1, min(2, configured_workers)); UPLOAD_BATCH_MAX_* clamps`

### alert_severity input validation

alert_severity is parsed and validated to one of 'low', 'medium', 'high' (case-insensitive, trimmed); anything else raises ValueError. From main() that surfaces through the critical-error path as a 'Scan failed: ... Critical error occurred' result; None falls back to 'low'.

- **Control:** main()/CLI argv[3] — default `'low'`
- **Observe:** Run with alert_severity='urgent': result line reports the critical error and stderr carries the ValueError traceback. On a valid run the value appears in the scanner_initialization event as default_alert_severity and in yara_processing_<run_id>.log ('Default alert severity: ...').
- **Source:** `_parse_alert_severity(value, arg_name); ScanConfig.__init__; __main__ argv parsing`

### scan_folder validation and multi-target contract

scan_folder accepts a comma-separated list so one run can cover multiple scopes/partitions. Entries are trimmed of whitespace and surrounding quotes, validated independently with os.path.isdir, de-duplicated after abspath; invalid entries are skipped LOUDLY, and if NONE are valid ScanConfig raises ValueError('No valid scan directory among the specified scan folder(s): [...]'). Empty or the literal 'default' selects platform default target discovery.

- **Control:** main() parameter scan_folder — default `None / 'default' -> _default_discover_targets()`
- **Observe:** yara_processing_<run_id>.log 'Scan limited to N folder(s): [...]' and the warning 'Ignoring N specified scan folder(s) that are not valid directories on this endpoint: [...]'; scan_targets in the summary JSON and in the scanner_initialization event; an all-invalid list returns the critical-error result line.
- **Source:** `ScanConfig.__init__ scan_folder block`

### Placeholder-collector-credential abort

Before any scanning, if UPLOAD_RESULTS is on and the endpoint is empty / equals the shipped placeholder / does not start with 'http', or the key is empty / equals the placeholder, the run aborts immediately with a 'SCAN ABORTED - XSIAM HTTP Collector credentials are not set...' string. The placeholder sentinels are separate constants from DEFAULT_API_KEY/DEFAULT_API_ENDPOINT precisely because deployers overwrite the latter in place.

- **Control:** DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (edited in source), UPLOAD_RESULTS toggle — default `DEFAULT_API_KEY='http_collector_key', DEFAULT_API_ENDPOINT='http_collector_api', UPLOAD_RESULTS=True — i.e. an unedited script aborts`
- **Observe:** Result line begins 'SCAN ABORTED'; the same text is in scan_errors_<run_id>.log; nothing is scanned; CLI exit code 1.
- **Source:** `main(): _ep_bad/_key_bad check with _PLACEHOLDER_API_ENDPOINT/_PLACEHOLDER_API_KEY`

### Rule-compilation fatal errors terminate the run before scanning

Compilation failures raise out of YaraScanner.__init__ and land in main()'s critical-error path. Three distinct fatal cases: split failure ('Failed to split YARA rules: ...'), no rules found in the content (raw content dumped to <scanner_dir>/failed_rules/raw_yara_content.yar), and no valid sources. The last deliberately distinguishes 'all N rule(s) need YARA modules this agent's libyara build does not provide ... an agent capability limit, not a rule syntax error' from 'No valid YARA rules could be compiled out of N rules.'

- **Control:** not configurable — default `n/a`
- **Observe:** stderr 'CRITICAL: YARA rule compilation failed: <msg>' plus a 'Valid rules: X, Failed rules: Y, Skipped: Z' line; yara_processing_<run_id>.log SPLIT_ERROR / COMPILATION_ERROR / FINAL_COMPILATION_ERROR entries; no scan_summary JSON is written on this path (YaraScanner never bound).
- **Source:** `YaraScanner._compile_yara_rules()`

### Module-skipped rules counted separately from failures

Rules the agent's libyara cannot run (missing module) are counted in error_logger.skipped_rules_count rather than failed_rules_count, and published on the error logger so main() can surface them; without it a pack whose rules mostly never ran reads as a clean '0 rules failed compilation'.

- **Control:** not configurable — default `skipped_rules_count = 0`
- **Observe:** Result-line segment ' \| N rules skipped (module unavailable)'; summary fields skipped_rules / failed_rules / valid_rules; yara_processing log 'Skipped N rules due to unavailable modules' and 'Compilation complete: V valid, F failed, S skipped'.
- **Source:** `ErrorLogger.skipped_rules_count; `error_logger.skipped_rules_count = skipped_count` in _compile_yara_rules(); main()'s _skipped_txt`

### Privilege detection and privilege_status telemetry  <sub>linux, macos (skipped on Windows); note the event's data.platform is hardcoded 'linux' even on macOS</sub>

On non-Windows the scanner reads os.geteuid() and logs whether it runs as root, with platform-specific guidance: on macOS it notes SIP may restrict /System and advises sudo / Full Disk Access; on Linux it advises running with sudo. If not root and any requested scan folder starts with a known privileged path — macOS ['/System','/Library','/private/var/db'], Linux ['/etc','/boot','/var/log','/root'] — it logs 'ERROR: System path scan requires elevated privileges' with the platform-appropriate remedy. A privilege_status event is queued with data {platform:'linux', running_as_root, recommended_action:'run_as_sudo'\|'none'} at level WARNING when not root. Windows performs no privilege detection.

- **Control:** not configurable — default `n/a`
- **Observe:** system_<run_id>.log 'Running as: root\|non-root user on Linux\|macOS' and the WARNING/TIP lines; collector event type='privilege_status' with data.running_as_root.
- **Source:** `main()'s `if platform.system() != "Windows":` block; create_standard_log(log_type='privilege_status', ...)`

### File-descriptor limit preflight and FD monitoring  <sub>linux, macos only</sub>

On non-Windows, when FD monitoring is enabled, the scanner reads `ulimit -n` via a 5s-timeout subprocess, logs the limit, and if it is below 8192 warns and queues a resource_limit_warning event {current_limit, recommended_limit:65536, impact}. It also records the process's starting num_fds as the baseline and sets config.monitor_fd_usage; during scanning every 1000 files it warns when FDs grew by more than 100 or exceed 900. Disabled entirely on Windows (monitor_fd_usage=False).

- **Control:** ENABLE_FD_MONITOR (env YARA_ENABLE_FD_MONITOR) -> config.enable_fd_monitoring; check interval fd_check_interval — default `ENABLE_FD_MONITOR=False; fd_check_interval=1000 files`
- **Observe:** system_<run_id>.log 'Current file descriptor limit: N', 'Initial file descriptors in use: N', 'FD usage increased by N (current: M)', 'WARNING: High FD usage: N'; collector event type='resource_limit_warning'.
- **Source:** `main()'s `if platform.system() != "Windows" and config.enable_fd_monitoring:` block; scan_file()'s fd_monitoring_enabled block`

### Light-profile process priority tuning at startup  <sub>windows / linux / macos (ionice Linux-only)</sub>

Best-effort de-prioritisation applied right after LogManager construction so user activity wins on a busy host: Windows sets BELOW_NORMAL_PRIORITY_CLASS; POSIX raises nice to at least 10; Linux additionally sets ionice to best-effort class, level 7. Every step is individually try/except'd and records either a value or an error string.

- **Control:** not configurable — default `always attempted`
- **Observe:** system_<run_id>.log 'Applied light profile process priority tuning' with data {'cpu_priority':'below_normal'\|'nice=10', 'io_priority':'best_effort:7'} or the *_error keys; verifiable out-of-band with `ps -o ni` / Task Manager priority.
- **Source:** `_apply_light_process_priority(log_manager); called from main() after LogManager`

### Progress heartbeat spanning the whole scan  <sub>all (disk_io_mb stays 0 on macOS — psutil has no io_counters there, guarded so the rest of the block still reports)</sub>

A dedicated daemon thread ('ProgressHeartbeat') calls _log_progress() every log_interval for the WHOLE scan — including the time workers spend draining scan_queue after discovery ends — because the previous inline check in the discovery walk almost never crossed the interval and produced zero 'Scan Progress' events on any host. It is stopped only AFTER the worker join, so telemetry covers the real scan duration, and it exits early if scan_active drops.

- **Control:** config.log_interval (env YARA_PROGRESS_LOG_SECS, clamped >= 1) — default `30 seconds`
- **Observe:** Recurring scan progress entries in statistics/performance logs and the corresponding collector events (files_scanned, files_skipped, detections, queue size, scan rate, cpu_percent, memory_mb, disk_io_mb, network_mb, active_workers, elapsed_seconds, eta_seconds, junction_skips, unique_real_paths); heartbeat failures log 'Progress heartbeat error: ...'.
- **Source:** `YaraScanner._progress_heartbeat(); thread start in scan_system(); stop+join(timeout=2) in _perform_enhanced_cleanup()`

### Producer backpressure instead of dropping files

_enqueue_scan_path blocks on a full scan queue (1s put timeout, sleep queue_backoff_secs, retry) rather than dropping the file, counts queue_full_events, samples the CPU governor while waiting, and logs a saturation line on every 25th event. It returns False when scan_active is cleared (cancel) or on an unexpected enqueue error, which breaks the discovery loop for that directory.

- **Control:** config.scan_queue_size (env YARA_QUEUE_SIZE, min 2), config.queue_backoff_secs (env YARA_QUEUE_BACKOFF_SECS, min 0) — default `scan_queue_size = max_workers*2 (i.e. 4 with 2 workers); queue_backoff_secs = 0.25`
- **Observe:** performance_<run_id>.log 'Scan queue saturated (N items) - backing off producer' (every 25th event); scan_errors log 'Failed to enqueue file for scanning: ...' with file_path.
- **Source:** `YaraScanner._enqueue_scan_path()`

### Final results log with failure-aware label

After cleanup, _log_final_results emits either a statistics or an error entry (label 'SCAN COMPLETED' vs 'SCAN FAILED') carrying total_time_seconds, files_scanned, files_skipped, total_detections, average_scan_rate, detection_rate, skip_rate, junction_skips, unique_paths_scanned and path_deduplication_ratio; on failure it also attaches failure_reasons. It additionally logs top detection rules (top 10, top 5 named inline), the skip-reason breakdown, and a per-worker performance summary.

- **Control:** not configurable — default `n/a`
- **Observe:** statistics_<run_id>.log 'SCAN COMPLETED \| Time: ... \| Files: ... \| Detections: ... \| Rate: ...' (or the same line in scan_errors_<run_id>.log prefixed 'SCAN FAILED'); 'Skip reasons: ...'; 'Top detection rules: ...'; performance log 'Worker performance summary: N workers processed files'.
- **Source:** `YaraScanner._log_final_results(total_time); called from scan_system()'s finally`

### scan_system finally-block guarantee

Whatever happens in the target loop, scan_system's finally always runs _perform_enhanced_cleanup (sentinels, worker join, heartbeat stop, cancel-flag/marker handling, monitor stop, results uploader drain) and then _log_final_results, so no exception path can skip worker shutdown or the final books.

- **Control:** not configurable — default `n/a`
- **Observe:** Force an exception inside the target loop and confirm the system log still shows '=== ENHANCED CLEANUP AND FINALIZATION ===', 'Enhanced cleanup completed in X seconds' and a final results line.
- **Source:** `scan_system()'s `finally:` -> _perform_enhanced_cleanup(...) ; _log_final_results(scan_total_time)`

### Comprehensive final report event

A priority-queued 'comprehensive_final_report' with scan_metadata (hostname, os_info, ip_addresses, duration, UTC start/end ISO timestamps, targets_scanned), file_processing (scanned/skipped/processed, skip_breakdown, processing rate), detection_results (totals, unique rules, breakdown, top 10, detection rate %), rule_compilation (valid/failed/total/success rate), system_info (platform, python, yara version, cpu_count, worker_threads_used), plus performance_summary, optional resource_summary, upload_summary and an efficiency_score (100 minus skip_rate*20 minus rule_failure_rate*30, floored at 0). Entirely wrapped in try/except so a reporting failure cannot fail the run.

- **Control:** resource_summary present only when ENABLE_RESOURCE_MONITOR is on — default `ENABLE_RESOURCE_MONITOR=False, so resource_summary is normally absent`
- **Observe:** Collector event type='comprehensive_final_report' with message 'Comprehensive scan report - Efficiency Score: X/100'; identical statistics_<run_id>.log line; on failure 'Error generating comprehensive final report: ...'.
- **Source:** `def upload_final_comprehensive_report(scanner, total_scan_time)`

### Cleanup scheduling gated on rule-processing health

Post-scan self-cleanup is scheduled only when NOT (error_logger.has_errors and valid_rules_count == 0) — i.e. a run where nothing could compile keeps its artefacts on the endpoint for diagnosis. Scheduling failures are caught and logged, never fatal.

- **Control:** not configurable — default `scheduled on any run with at least one valid rule`
- **Observe:** system_<run_id>.log 'Cleanup task/service scheduled successfully' vs 'Cleanup skipped due to critical YARA processing errors'; or scan_errors 'Error scheduling cleanup: ...'.
- **Source:** `main(): `has_critical_errors = (error_logger.has_errors and error_logger.valid_rules_count == 0)` -> cleanup_manager.schedule_final_cleanup()`

### Per-run identity: run_id, scan_id, rule_hash

run_id is a microsecond timestamp ('%Y%m%d_%H%M%S_%f') that stamps every artefact filename; scan_id is '<hostname>_<run_id>_yara_<rule_hash[:12]>' so it is unique per RUN (the older hash-only form made every host in a fleet and every re-run report under one identical scan_id, silently merging them for any consumer grouping by scan_id) while still identifying the ruleset; rule_hash is the full sha256 of the decoded rule text.

- **Control:** not configurable — default `n/a`
- **Observe:** Every event carries scan_id; log files are <category>_<run_id>.log; scan_summary_<run_id>.json carries run_id, scan_id and rule_hash. Two runs on one host must produce two distinct scan_ids.
- **Source:** `ScanConfig.__init__: self.run_id, self.rule_hash, self.scan_id; LogManager.log_files`

### Six per-run category logs plus two lazy diagnostic logs  <sub>all (path differs by OS)</sub>

Every run opens six file loggers in <scanner_dir>/logs, all suffixed with run_id and opened in mode='w' with a millisecond timestamp format: alerts, statistics, scan_errors, performance, uploads, system. Two further logs are per-run: yara_processing_<run_id>.log (rule compilation audit trail, always created) and script_exceptions_<run_id>.log (created lazily on the first logged exception, so clean runs leave no zero-byte file). The UPLOAD category is deliberately never forwarded to the collector, to avoid upload-about-uploads recursion.

- **Control:** Directory from YARA_SCANNER_DIR/logs — default `C:\yara_scanner\logs, /usr/local/yara_scanner/logs (macOS), /opt/yara_scanner/logs (Linux)`
- **Observe:** ls the logs directory after a run; expect 7 files on a clean run and an 8th (script_exceptions_) only when something threw.
- **Source:** `LogManager.log_files dict + _setup_logger(); ErrorLogger.error_log_file; ExceptionLogger.exception_log_file and _ensure_logger()`

### Logging summary at shutdown

stop_logging drains the webhook queue on the backlog-proportional budget, stops the thread (join THREAD_CLEANUP_TIMEOUT), emits a 'Logging Summary' line with total logs, successful/failed webhook uploads, success rate, per-type counts and the log-file map, then closes all handlers. It is idempotent (_stopped guard) and also invoked from __del__.

- **Control:** THREAD_CLEANUP_TIMEOUT — default `THREAD_CLEANUP_TIMEOUT = 60`
- **Observe:** Last lines of system_<run_id>.log: 'Logging Summary \| Total Logs: N \| Webhook Uploads: X successful, Y failed \| Success Rate: Z%'.
- **Source:** `LogManager.stop_logging(), log_final_summary(), THREAD_CLEANUP_TIMEOUT`

### Artefact retention across runs (bounded observability window)

**⚠ CONTROL GAP**  
initial_cleanup prunes per-run artefacts to the latest N run_ids (always keeping the current run): the matcher covers .log, scan_summary_<run_id>.json and orphaned .json.tmp files, so summaries are retention-managed rather than accumulating forever and half-written temps are swept. Files locked/in use are counted as failures, not fatal.

- **Control:** CleanupManager._prune_old_scan_logs(keep_scans=2), floored at 1 — default `keep_scans = 2 (plus the current run)`
- **Observe:** Root-logger info 'Log retention applied: kept last N scans (M run IDs including current), removed X log files' and warnings 'Cannot remove log file (in use): ...'. Test criterion: after 4 runs only the newest 2 run_ids' summaries/logs remain.
- **Source:** `CleanupManager._prune_old_scan_logs(); _extract_run_id_from_log_name() regex `_(\d{8}_\d{6}_\d{6})\.(?:log\|json\|json\.tmp)$``

### Root-logger quieting during a scan

setup_logging suppresses root-logger output below WARNING so categorized LogManager output is the record and stdout stays quiet during a scan; WARNING/ERROR records still reach stderr through Python's default handler so an interactive operator sees fatal issues.

- **Control:** not configurable — default `root level raised to WARNING`
- **Observe:** A CLI run prints essentially nothing to stdout until the final 'SCAN_RESULT: ' line, while env-var warnings and critical errors still appear on stderr.
- **Source:** `def setup_logging(config)`

### Scanner working-directory selection (shared by both entry points)  <sub>windows / macos / linux (different defaults)</sub>

The scan and the cancel path resolve the same scanner directory, so cancel() targets the right control directory even under a non-default deployment: YARA_SCANNER_DIR (trimmed, if non-empty) else a platform default. ScanConfig creates scanner_dir, logs, control, alert, evidence and failed_rules subdirectories; control-dir creation is best-effort (try/except) while the others are not.

- **Control:** env YARA_SCANNER_DIR — default `Windows C:\yara_scanner; macOS /usr/local/yara_scanner; Linux/other /opt/yara_scanner`
- **Observe:** Directory tree exists after a run; cancel()'s returned flag path matches it. Set YARA_SCANNER_DIR and confirm both the scan artefacts and the cancel flag move together.
- **Source:** `_default_scanner_dir(); ScanConfig.__init__ scanner_dir/logs_dir/control_dir/alert_dir/evidence_dir/failed_rules_dir`

---

# Control gaps — capabilities the customer cannot tune

Verified directly against source. These are ranked by how likely a real deployment is to
need them, not by how hard they are to add.

### `YARA_THREADS` is accepted and then discarded

The knob is read, range-validated, and overwritten:

```python
configured_workers = _env_number("YARA_THREADS", default_workers, cast=int, minimum=1)
self.max_workers = max(1, min(2, configured_workers))
```

A customer setting `YARA_THREADS=8` on a 32-core server silently gets **2**. The variable
is listed in the Deployment Guide's tuning table. This is the worst category of gap — a
control that exists, is documented, accepts input, and does nothing, failing silently at
both ends. Either honour it (with a sane ceiling) or remove it and document the cap.

### Every skip list is hardcoded — no override of any kind

`skip_extensions`, `skip_filenames`, `skip_path_fragments`, `force_scan_fragments`,
`force_scan_never_under`, and all three per-platform lists (`win_skip_folder`,
`lin_skip_directory`, `mac_skip_directory`) are Python literals inside `ScanConfig` —
mid-file, not in the top-of-file config block where a customer would look.

This is the largest practical gap. A customer running a non-Cortex EDR, a large build-
artifact tree, or an unusual mount layout has **no supported way to add a skip path**. We
added `/opt/traps` for the Cortex agent; a site running CrowdStrike or SentinelOne cannot
do the same for theirs without editing the script's internals.

### Total footprint is unbounded

`MAX_ALERT_OFFSETS_PER_FINDING` caps offsets **per finding**, but nothing caps the alert
directory total or the evidence ZIP total. Per-finding bounds say nothing about the sum, so
a noisy ruleset on a small endpoint disk has no ceiling. A per-rule or per-scan byte budget
would close it.

### Log retention is a method default

`_prune_old_scan_logs(keep_scans=2)` — retention is fixed at two runs, set in a signature
default rather than a constant.

### Governor internals are fixed (deliberate)

`GAIN`, `RATIO_MAX`, `PACE_CAP_SECS` are `CpuGovernor` class constants. Recorded for
completeness, but correct as-is: these are control-loop tuning, not policy, and the policy
knobs above them (`CPU_GUARANTEE`, `CPU_HEADROOM_PCT`, `CPU_BUDGET_PCT`, `CPU_FLOOR_PCT`)
are exposed. Changing them without understanding the loop would destabilise pacing.

---

# Known issues in this inventory

Raised by three independent audits of the enumeration. Recorded rather than silently fixed,
because each is a work item.

### The root logger is silent — most `logging.info` evidence does not exist

`setup_logging()` removes every root handler and pins the level to `WARNING`. All 41
`logging.info(...)` calls in the file therefore reach nothing, on any host. Any capability
whose only stated evidence is an info-level log is **untestable as written** — that is what
the ⚠ OBSERVABILITY GAP marker means above.

Two such cases were fixed while writing this file (the evidence-ZIP dedupe and the
metadata-only packaging line, both now routed through `LogManager`). The rest remain.

### Observability gaps (40)

*Capability exists; nothing on a live scan proves it ran.*

- CROSS-CUTTING: every `logging.info(...)` in this file reaches nothing. `setup_logging()` (5882-5896) removes all root handlers and pins the root level at WARNING, and before it runs the root logger is already at its default WARNING with no handlers. WARNING/ERROR still surface on stderr via basicConfig/lastResort; INFO does not, anywhere. The rules dimension noted this for `_debug_rule_analysis` but the other five dimensions kept writing observe notes against root-logger INFO lines. Every entry below inherits this defect.
- rules, "Comment- and string-aware pack parser": the whole test is anchored on comparing the `Found N rule start positions` count — a `logging.info` at line 4663. Nothing writes it. (The `total_rules_found` half of the comparison, from main()'s `YARA Rules loaded` system event, does work.)
- rules, "Per-rule trial compile then namespaced whole-pack compile": `Successfully built ruleset with N rules (M failed) (K skipped - missing modules)` is `logging.info(success_msg)` at 4611-4618. Never written to any log file or stderr.
- traversal, "Unknown-platform target fallback": `Using default Unix target: ['/']` is `logging.info` at 5278. Unobservable. (The `Unknown platform - manual target specification required` half is an error_logger warning and does land in yara_processing_<run_id>.log.)
- storage, "Initial cleanup at scan start": `Starting initial cleanup of old data...`, one `Removed: <path>` per entry, and `Initial cleanup completed successfully` are all `logging.info` (4002-4014, 4029). Only the PermissionError warnings and `Some cleanup operations failed` reach stderr. The system-log line `Initial cleanup completed` (main, 6030) is the only durable signal.
- storage and lifecycle, "Log/summary retention across runs": `Log retention applied: kept last N scans (M run IDs including current), removed X log files` is `logging.info` at 3991-3995. Unobservable. Only the `Cannot remove log file (in use)` / `Log retention: F log files could not be removed` warnings reach stderr — and `_prune_old_scan_logs` runs from `initial_cleanup()` before `setup_logging`, so even those depend on basicConfig having been installed by an earlier module-level `logging.warning`.
- storage, "Matched-file copy toggle (COLLECT_MATCHED_FILES)": `Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only (...)` is `logging.info` at 3913-3916. Unobservable; the ZIP contents are the only real signal.
- storage, "Content-addressed dedupe of packaged matched files": `Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped` is `logging.info` at 3926-3930. Unobservable. (`Error adding file to zip <path>: <err>` is logging.error and does reach stderr.)
- storage, "Windows scheduled cleanup task (CleanupScript)": `Windows cleanup task scheduled for HH:MM` is `logging.info` at 4147, and the paired `Windows cleanup task scheduled successfully` sits behind the dead `config.log_manager` guard (4076-4077). Only `schtasks /query` on the endpoint and main()'s `Cleanup task/service scheduled successfully` (6363) are observable.
- storage, "Linux systemd cleanup unit": `Linux cleanup service created and started` is `logging.info` at 4183, and `Linux cleanup service scheduled successfully` is behind the same dead guard (4080-4081). Only `systemctl status` and main()'s generic success line are observable.
- lifecycle, "scan_status lifecycle values and the terminal status": "the local line `Scan status changed to: <value>` via the root logger" — `logging.info` at 3560. Unobservable locally; only the uploaded `scan_status` events exist, and those additionally require UPLOAD_RESULTS + UPLOAD_NON_MATCH_DATA + a non-empty API_ENDPOINT + `webhook_uploader` having been wired on by main().
- storage/rules, cleanup-suppression system-log lines: `Critical errors detected - skipping cleanup to preserve diagnostic data` (with `{'preserve_logs': True}`) and `No alerts found, skipping cleanup scheduling` (4053-4065) are both inside `if hasattr(self.config, 'log_manager')`, which is permanently False — and their `logging.info` twins are suppressed. Neither ever appears in system_<run_id>.log. The only durable evidence of suppression is main()'s `Cleanup skipped due to critical YARA processing errors` and the absence of the scheduled task/unit.
- performance, "Governor sampling cadence (rate limit)": the stated test is "with a debug build, `last_governor_sample` advances at most every 0.5s". There is no debug build and nothing exposes `last_governor_sample` — no log line, no event field. The only real handle on the sampling rate is the emission cadence, which is separately governed by the 0.25 change threshold and GOVERNOR_HEARTBEAT_SECS.
- rules / 'Rule input size cap': the observe note says it "surfaces as the `Critical startup error:` stderr block and exit code 1 (no run_id / logs dir content, because it fires before ErrorLogger emits anything else)". Both halves fail. ScanConfig is constructed inside main()'s try, so a ValueError('YARA rules input too large') is caught by main()'s `except Exception` and surfaces as 'YARA Scanner Critical Error: Critical scanner error: ...' plus 'SCAN_STATUS: ERROR' on stderr, returning 'Scan failed: 0 files scanned \| ... \| Critical error occurred'. 'Critical startup error:' only covers exceptions escaping main() in the __main__ block. And ErrorLogger is constructed BEFORE the decode (line ~2704), so logs/yara_processing_<run_id>.log already exists with its 4-line banner plus 'CRITICAL: Failed to decode YARA rules: YARA rules input too large'.
- rules / 'Unnamed-rule fallback naming': `Rule Name: rule_7` in a compilation-failure block and the filename failed_rules/failed_rule_rule_7.yar cannot be produced. _clean_rule_content's guard regex `^\s*(?:(?:private\|global)\s+)*rule\s+\w+` drops any block without a name (logging 'Rule rule_N doesn't start with...'), so every block reaching _compile_yara_rules matches `rule\s+(\w+)` and display_name is always the real name - the `f"rule_{i}"` fallback at line ~4479 is dead. The placeholder only ever appears in the suppressed logging.warning text.
- rules / 'Comment- and string-aware pack parser': it instructs comparing the `Found N rule start positions` count against total_rules_found. That line is a logging.info in _split_yara_rules (line ~4661) and the root logger is at WARNING with no handlers (setup_logging, 5882-5896) - it is written nowhere, exactly as the doc itself notes for 'Found N unique import statements'. Only the total_rules_found half of the comparison is observable.
- rules / 'Rule-count propagation into scan telemetry': `scan_status` event fields valid_rules_count / failed_rules_count never appear. ScanStatusUploader.upload_scan_status(scanner_stats=None) only adds that block `if scanner_stats:`, and every one of the 9 call sites goes through set_status(), which calls upload_scan_status() with no argument - as the lifecycle 'scan_status event payload' entry correctly states. Only the six base fields are ever emitted.
- performance / 'Scan-rate reporting in the terminal artefacts', item (5): `scan_rate_files_per_second` in 'periodic scan_status events'. Same root cause - it is only set inside the `if scanner_stats:` branch, which is never taken. Additionally scan_status is emitted on lifecycle transitions only (starting/initializing/starting_workers/scanning/finishing/terminal), never on a timer, so 'periodic' is doubly wrong. Items (1)-(4) are fine.
- delivery / 'One merged alert event per matched file': the test criterion "XQL type='alert' for one scan_id: count must equal the number of distinct matched file paths" is off by one on any scan with detections. There are two log_alert() call sites: the per-file event in scan_file (line 4922) and the 'Top detection rules: ...' summary in _log_final_results (line 5399), which also lands as type='alert'. The grep of alerts_<run_id>.log for 'YARA matches found in' is the reliable half.
- delivery / 'Upload channels can be disabled independently': neither uploads-log line can be observed. 'Upload disabled - N matches saved locally' lives in ResultsUploader.upload_results(), which is dead code - it has no caller anywhere in the file (the class's own docstring says so). 'API_ENDPOINT not configured - real-time match upload disabled' is emitted from _start_upload_thread() guarded by `if self.log_manager:`, but log_manager is still None during ResultsUploader.__init__ (YaraScanner assigns results_uploader.log_manager only on the next-but-one statement, line ~4238), so it is silently discarded - as are 'Starting real-time upload thread...' and 'Real-time upload thread started successfully'. The scanner_initialization upload_enabled / telemetry_upload_enabled half of the entry is fine.
- delivery / 'Queue-full handling on the findings channel': 'Upload queue full - skipping real-time upload for finding' cannot fire from queue pressure. self.upload_queue = Queue() is unbounded (the entry says so itself), so put(..., timeout=1.0) never raises Full; the message is printed from a broad `except Exception` that in practice only catches a serialization failure. Same for the telemetry channel's unbounded queue.
- rules / 'Diagnostic-preserving cleanup suppression': the named trigger cannot produce the named log line. main() computes the identical `has_critical_errors = (error_logger.has_errors and error_logger.valid_rules_count == 0)` and skips calling schedule_final_cleanup() entirely, logging 'Cleanup skipped due to critical YARA processing errors' instead; and valid_rules_count == 0 aborts the run during compilation anyway. 'Critical errors detected - skipping cleanup to preserve diagnostic data' is reachable only through the >50% error-log-ratio branch.
- storage / 'Uncapped per-string-ID census in the alert text': the parenthetical "a match with no string ID renders as `$?`" is unreachable on a live scan. _write_alerts consumes strings produced by _iter_hit_fields -> _normalize_match_strings, which always coerces the identifier with str(...) and substitutes the literal 'unknown' when absent - sid is never None. The census itself, 'Total string hits: N', and the sum-equals-total assertion are all fine.
- rules / 'Comment- and string-aware pack parser': `Found N rule start positions` (line 4663) is a bare logging.info on the root logger, which setup_logging pins at WARNING with no handlers - it is written nowhere. Only the second half (total_rules_found in the 'YARA Rules loaded' system event) is usable, and that is the pre-split census, not the compile-path count the entry wants to compare against.
- rules / 'Per-rule trial compile then namespaced whole-pack compile': `Successfully built ruleset with N rules (M failed) (K skipped - missing modules)` is emitted by logging.info ONLY (lines 4611-4615) and never mirrored to error_logger, so it appears in no file and on no stream. The running.json 'compiling' to first-worker-start half does work.
- rules / 'Unnamed-rule fallback naming': the rule_N placeholder is unreachable. _clean_rule_content's guard regex `^\s*(?:(?:private\|global)\s+)*rule\s+\w+` (line 4319) drops any block where 'rule' is not followed by a \w+ token, so nothing arriving at _compile_yara_rules can fail its `re.search(r'rule\s+(\w+)')` (line 4479). No 'Rule Name: rule_7' failure block and no failed_rule_rule_7.yar can ever be produced.
- rules / 'Rule-count propagation into scan telemetry' (scan_status half): valid_rules_count / failed_rules_count are never emitted on scan_status. upload_scan_status only adds them when scanner_stats is truthy (lines 3528-3537), and all nine set_status() call sites (5621, 5725, 5747, 5773, 5870, 6254, 6257, 6278, 6457) call upload_scan_status() with no argument. Every scan_status row carries only the six base fields.
- delivery / 'Scan-rate reporting in the terminal artefacts', item (5): scan_rate_files_per_second in scan_status events - same cause as above, never emitted. Also scan_status events are per-transition, not 'periodic'. Items (1)-(4) are fine.
- delivery x3 / wrong alert directory: 'Uncapped per-string-ID census in the finding (match_ids)', 'Condition-only match representation' and 'Local alert file as the uncapped offset record' all point at <scanner_dir>/alerts/<rule>.txt. The on-disk directory is `alert` (singular) - os.path.join(self.scanner_dir, "alert") at line 2697, written at 5159. Only the evidence ZIP uses an `alerts/` member prefix (line 3921). Each cross-check would look in a directory that does not exist.
- delivery / 'Circuit breaker on the telemetry channel': the recipe 'with a dead collector' cannot open the circuit. _process_standard_batch calls _circuit.on_failure() only on a non-retryable HTTP status (line 3687) or an unexpected exception (3692); requests.Timeout / requests.ConnectionError (3689) and the retryable set 408/429/500/502/503/504 (3684) never touch it. An unreachable collector yields ConnectionError, so the breaker stays closed for the whole run and no 40 s quiet windows appear.
- delivery / 'Throttled upload logging': the upload_err bucket is logged via _throttled_log's DEFAULT level='error' (call sites 3243, 3256, 3262), which routes to log_error and lands in scan_errors_<run_id>.log, not uploads_<run_id>.log. Only upload_ok, upload_retry and upload_neterr pass level='upload'. Grepping uploads_<run_id>.log for the 20 full errors and the '[upload_err] further similar messages suppressed' line finds nothing.
- storage / 'Matched-file copy toggle (COLLECT_MATCHED_FILES)': 'the root logger records Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only...' - that is logging.info (line 3913), suppressed by setup_logging. The unzip -l half of the check works.
- storage / 'Content-addressed dedupe of packaged matched files': 'the root logger prints Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped' - logging.info (line 3926), suppressed. The bare-hex arcnames and entry-count comparison still work; 'Error adding file to zip' is logging.error and does reach stderr.
- storage / 'Log/summary retention across runs' and lifecycle / 'Artefact retention across runs': 'Log retention applied: kept last N scans (M run IDs including current), removed X log files' is logging.info (line 3992), suppressed. Only the WARNING-level 'Cannot remove log file (in use)' and 'Log retention: N log files could not be removed' reach stderr. Verify retention by listing logs/ instead.
- storage / 'Initial cleanup at scan start': 'Starting initial cleanup of old data...' (4002), 'Removed: <path>' (4018) and 'Initial cleanup completed successfully' (4033) are all logging.info, suppressed. Observable substitutes: the WARNING 'Some cleanup operations failed - continuing with scan' (4031) and the system-log line 'Initial cleanup completed' emitted by main() at line 6030.
- storage / 'Windows scheduled cleanup task (CleanupScript)': 'The root logger prints Windows cleanup task scheduled for HH:MM' - logging.info (line 4147), suppressed. schtasks /query and the system-log 'Windows cleanup task scheduled successfully' are the working checks.
- storage / 'Linux systemd cleanup unit': 'Root logger prints Linux cleanup service created and started' - logging.info (line 4183), suppressed. systemctl status and the system-log 'Linux cleanup service scheduled successfully' work.
- traversal / 'Unknown-platform target fallback': the second observable, `Using default Unix target: ['/']` (line 5278), is logging.info and suppressed. The 'Unknown platform - manual target specification required' warning does land in yara_processing_<run_id>.log (error_logger.warning, line 3084), so only half the entry stands.
- lifecycle / 'scan_status lifecycle values and the terminal status': (a) the local line 'Scan status changed to: <value>' is logging.info (line 3560), suppressed - scan_status is collector-only. (b) The stated test criterion ('every run ends with exactly one terminal value') fails on main()'s outer critical-error path (6466+): it writes 'SCAN_STATUS: ERROR' to stderr and queues a scan_completion_summary with status='critical_error', but never calls set_status, so the last scan_status row can remain 'finishing'.
- lifecycle / 'Fatal worker failure path': not reproducible on a live scan. scan_file already wraps everything in `except Exception` (4972), and _worker's inner `except Exception ... continue` (4737-4744) swallows the rest, so the outer handler that logs 'Worker <id> fatal error:' and calls _mark_scan_failed (4746-4749) is effectively unreachable. There is no way to drive the run to 'Scan stopped due to fatal failures' / outcome='failed' through this path.

### Entries needing correction (24)

*Stated control, default or source does not match code.*

- performance, "Per-finding network payload cap": claims `total_matches` in the ResultsUploader books (match_delivery in scan_summary) "equals the number of findings, not the number of offsets". Inverted — `ResultsUploader.add_match` increments `self.upload_stats['total_matches'] += 1` inside the loop over `upload_entries`, i.e. once per OFFSET (line 3356). main()'s own comment at 6416-6420 states this explicitly ("total_matches counts OFFSETS ... while these three count UPLOAD ITEMS"), which is why the shortfall denominator is ok+failed+undelivered.
- rules, "Rule input size cap": the observe note says it fires "before ErrorLogger emits anything else (no run_id / logs dir content)" and surfaces as the `Critical startup error:` stderr block. Both false. `decode_yara_rules` runs from ScanConfig AFTER ErrorLogger is built and has already written the banner, `Webhook API Key`, `API Endpoint`, `Default alert severity` and `Using YARA rules from provided parameter` lines to yara_processing_<run_id>.log; ScanConfig then logs `CRITICAL: Failed to decode YARA rules: YARA rules input too large` there (2731-2733). The ValueError is caught by main()'s outer `except Exception`, which returns `Scan failed: 0 files scanned \| ... \| Critical error occurred`. `Critical startup error:` exists only in the `__main__` wrapper (6658), which is never reached because main() does not re-raise.
- rules "Diagnostic-preserving cleanup suppression" and storage "Cleanup scheduling is suppressed on critical errors or zero alerts": the >50% error-log-ratio trigger is DEAD CODE. It is gated on `if hasattr(self.config, 'log_manager')` (4046-4051) and nothing anywhere in the file ever assigns `config.log_manager` (only reads at 1333, 4046-4085). Only the `error_logger.has_errors and valid_rules_count == 0` condition can ever fire.
- rules, "Per-rule compilation-failure diagnostics": "The same structure is emitted as a webhook error event with `error_analysis`, `error_line_number`, `rule_length_lines`, `compilation_failure_number` fields." That event is never emitted — `ErrorLogger.log_rule_compilation_error` gates it on `hasattr(self.config, 'log_manager') and self.config.log_manager` (line 1333), and `config.log_manager` is never set. Only the yara_processing_<run_id>.log text block exists.
- delivery "privilege_status event" and lifecycle "Privilege detection and privilege_status telemetry": the event is built inside `if not is_root:` (6070-6100), not merely on non-Windows. A ROOT Linux/macOS scan emits ZERO privilege_status rows, and `data.running_as_root` is therefore always `false` and `recommended_action` always `'run_as_sudo'` — the documented "none"/root-true variant cannot occur.
- delivery, "Credential placeholder detection and early abort": "No files are scanned and no events are sent." Events ARE sent. LogManager (which logs+uploads `Enhanced Log Manager initialized...`), StatisticsManager and WebhookUploader are all constructed and started at 6021-6026, `Initial cleanup completed` is logged at 6030, and `log_manager.log_error(abort_msg)` at 6044 queues an `error`-type event before returning.
- delivery, "Backlog-proportional shutdown drain window": cites `ResultsUploader.upload_results()` as one of the drain sites. That method (3423-3479) has no callers anywhere in the file — grep for `upload_results` returns only its own definition and the class comment saying so. There are three live drain sites (`ResultsUploader.stop`, `WebhookUploader.stop_uploader`, `LogManager.stop_logging`), not four, so its `Waiting for N pending uploads (max Ms)...` line can never appear.
- delivery, "statistics_summary checkpoints with per-type rate limiting": only the literal `'statistics'` key ever reaches `_should_upload` (line 3714, the sole caller). The `performance: 30`, `system_resource: 45`, `worker_stats: 120`, `time_estimates: 60` entries of `upload_intervals` are never consulted by any code path — presenting them as active defaults overstates the mechanism.
- lifecycle, "Module-skipped rules counted separately from failures": lists `Compilation complete: V valid, F failed, S skipped` as a yara_processing_<run_id>.log line. It is a bare `logging.info` (line 4578) on the quieted root logger and reaches no file. Only `Skipped N rules due to unavailable modules` (4588, via error_logger) lands in that file.
- storage, "Six per-category run logs in logs/": "`ls /opt/yara_scanner/logs/*_<run_id>.log` returns exactly these six files". It returns seven — `yara_processing_<run_id>.log` matches the same glob (and an eighth, `script_exceptions_<run_id>.log`, when an exception was logged). Storage's own later entry and lifecycle both say 7, so the six-file glob assertion contradicts them.
- storage, "macOS has no working scheduled-cleanup path": cites scan_errors_<run_id>.log carrying `Failed to schedule cleanup: <err>`. That line is inside the dead `hasattr(self.config, 'log_manager')` guard (4084-4086) and never fires; only main()'s `Error scheduling cleanup: <err>` (6367) is observable.
- performance / 'Per-finding network payload cap': the claim "`total_matches` in the ResultsUploader books (`match_delivery` in scan_summary_<run_id>.json) equals the number of findings, not the number of offsets" is backwards. ResultsUploader.add_match() increments self.upload_stats['total_matches'] once per entry of upload_entries, i.e. once per matched OFFSET (line ~3355), while successful/failed/undelivered count upload items (= findings). main()'s own shortfall comment says so explicitly: 'total_matches counts OFFSETS (incremented per matched string instance)'. A single 21,047-hit finding books total_matches=21047, ok=1.
- performance / 'Optional system resource monitor (SystemResourceMonitor)': the event type is named `system_resources`. The actual log_type passed to create_standard_log in SystemResourceMonitor._upload_resource_data (line ~2433) is `system_resource_snapshot` (the delivery section's twin entry has it right). An XQL filter on type='system_resources' returns nothing even with YARA_ENABLE_RESOURCE_MONITOR=true.
- delivery / 'privilege_status event': default states "recommended_action = 'run_as_sudo' when not root", implying a root variant. The whole `if webhook_uploader: create_standard_log(log_type='privilege_status' ...)` block is nested INSIDE `if not is_root:` in main() (lines ~6070-6100), so a root Linux/macOS scan emits NO privilege_status row at all and the 'none' branch of recommended_action is dead. The observe note ('XQL type=privilege_status for a Linux/macOS scan; zero rows on Windows') fails on any sudo/root run.
- delivery / three entries point at `<scanner_dir>/alerts/<rule>.txt` - 'Uncapped per-string-ID census in the finding (match_ids)', 'Condition-only match representation', and 'Local alert file as the uncapped offset record'. The on-host directory is `alert/` (ScanConfig.alert_dir = os.path.join(scanner_dir, 'alert'), line ~2697; _write_alerts writes os.path.join(self.config.alert_dir, f'{rule}.txt')). `alerts/` exists only as the arcname prefix inside the evidence ZIP (EvidenceCollector._create_evidence_zip). The storage section has it right, so the two halves of the doc contradict each other.
- storage / 'Cleanup scheduling is suppressed on critical errors or zero alerts': the stated scenario "A scan where every rule failed to compile logs 'Critical errors detected - skipping cleanup to preserve diagnostic data' (with data {'preserve_logs': True}) and 'Cleanup skipped due to critical YARA processing errors'" cannot happen. With zero valid rules, _compile_yara_rules() raises ValueError inside YaraScanner.__init__, main() jumps to its critical-error handler, and cleanup_manager.schedule_final_cleanup() is never reached - no scanner, no cleanup log line, no scan_summary. Both quoted lines require a run that completed scan_system().
- delivery / 'Per-finding network payload cap': the claim "total_matches in the ResultsUploader books (match_delivery) equals the number of findings, not the number of offsets" is exactly backwards. `self.upload_stats['total_matches'] += 1` sits INSIDE the per-offset loop of add_match (line 3356), so match_delivery.total_matches and `matches=N` in the 'Match delivery final:' line count string hits/offsets. Only successful_uploads/failed_uploads/undelivered count events (findings).
- rules / 'Rule input size cap': two factual errors. (a) The 50M check is inside decode_yara_rules, reached AFTER ErrorLogger is constructed and after 'Using YARA rules from provided parameter' is already written, and ScanConfig's except block logs 'CRITICAL: Failed to decode YARA rules: YARA rules input too large' to yara_processing_<run_id>.log (lines 2722-2733) - so 'no run_id / logs dir content' is false. (b) It does not surface as 'Critical startup error:'; that string exists only in the __main__ guard (line 6660) for exceptions escaping main(). A ValueError from ScanConfig is caught by main()'s own except and yields the 'Scan failed: ... \| Critical error occurred' result line. Exit code 1 is correct.
- performance / 'Optional system resource monitor': the emitted event type is `system_resource_snapshot` (line 2434), not `system_resources`. The delivery section names it correctly; the performance section's observe note filters on a type that never exists.
- delivery / 'statistics_summary checkpoints with per-type rate limiting': the two call sites are phase='initialization' in main() (line 6238) and phase='scan_configuration' in scan_system() (line 5742), in that order and milliseconds apart. Both share the 'statistics' rate-limit key (60 s), so scan_configuration is suppressed on essentially EVERY run, not 'on a very fast scan' - and it is the second checkpoint, not the first.
- delivery / 'privilege_status event': the config line omits the real gate. The event is emitted only inside `if not is_root:` (line 6070), so a root Linux/macOS scan produces ZERO rows. Consequently running_as_root is always false, recommended_action is always 'run_as_sudo', and the level=='INFO' / 'none' branches (lines 6093, 6097) are dead code.
- traversal / 'Case-folding policy for path matching': 'Linux case-sensitive' is true only of lin_skip_directory (line 5063, matched on case-preserved normalized_path). skip_filenames, skip_extensions, skip_path_fragments, force_scan_fragments and force_scan_never_under are all matched against portable_path, which is .lower()ed on every platform (line 5010) - so those layers are case-INSENSITIVE on Linux too. The /opt/Traps vs /opt/traps test still works; the blanket default statement does not.
- storage / 'Six per-category run logs in logs/': the stated recipe `ls logs/*_<run_id>.log` does not return exactly six files - yara_processing_<run_id>.log matches the same glob (seven), and script_exceptions_<run_id>.log makes eight when an exception was logged. The lifecycle section states the count correctly as seven.
- lifecycle / 'alert_severity input validation': on the CLI path _parse_alert_severity(sys.argv[3]) is called outside main() (line ~6626), so the exception escapes to the __main__ guard: stderr gets 'Critical startup error: Invalid alert_severity ...' plus the traceback and exit 1, and NO 'SCAN_RESULT:' line is printed at all. 'result line reports the critical error' holds only on the Action Center entry-point path, where ScanConfig raises inside main().

### Capabilities not yet catalogued (35)

*Real capabilities no enumeration pass captured.*

- CLI `cancel` keyword dispatch — `if (yarafile_arg or "").strip().lower() == "cancel": result = cancel()` in the `__main__` block (lines 6625-6629). `python3 xsiam_yara_scanner.py cancel` delivers a cooperative cancel instead of starting a scan; the lifecycle dimension documents the zero-input `cancel()` entry point and the CLI dispatch separately but never the argv[1] keyword that joins them (and the exit-code guard's `_rt.startswith("cancel failed")` arm only exists because of it).
- Base64 input normalization in `_b64_to_text` (lines 359-373): strips an optional `b64:` prefix (case-insensitive), removes all \n/\r/spaces, translates URL-safe alphabet (`-`->`+`, `_`->`/`), and re-pads with `=` to a multiple of 4. The rules dimension only says "base64-only input"; none of the six mention that URL-safe, unpadded, or `b64:`-prefixed rule blobs are accepted.
- Condition-only match summary is a source-mining heuristic, not just a meta dump — `_summarize_condition_only_match` (512-557) pulls meta keys `purpose`/`severity`/`scope`/`author` and tags, then greps the rule's ORIGINAL source for `uint16(0) == 0x5A4D` (emits "checks for an MZ/PE header"), extracts every distinct `pe.imports("lib","func")` function name (emits "references imports: ..."), and any `\bpe\.` usage ("uses the PE module for structural checks"). Rules/delivery both call it just "the generated summary".
- Host-identity derivation carried on EVERY uploaded event — `get_os_info()` (308-328) maps the Darwin kernel major to a marketing name table (24 -> macOS 15 Sequoia, 23 -> Sonoma, 22 -> Ventura, 21 -> Monterey, else `macOS (Darwin <rel>)`) with an `[arch]` suffix; `get_system_info()` (331-345) enumerates IPs via `socket.getaddrinfo(hostname)`, drops `127.*`, de-dupes, and on failure returns the single string `"Unable to determine IP address: <err>"` — which then becomes the `ipAddress` field on every event, the `ip_address` in scan_summary JSON, and the `IP Addresses:` line in evidence/file_mapping.txt.
- macOS case-sensitivity probe writes a real file, per scanned file — `_is_case_sensitive_fs()` (607-622) creates and deletes `/tmp/CaSe_TeSt_YaRa_<pid>`. It is called from `_get_real_path()` (640-662), which `scan_file` invokes for every file (line 4872), so a macOS scan performs one /tmp create+exists+unlink per scanned file. Traversal cites `_is_case_sensitive_fs` only as the source of the case-folding policy.
- yara-python API-shape compatibility shim — `_normalize_match_strings` (844-867) accepts the 3.x `(offset, identifier, data)` tuple form, the 4.x `StringMatch.identifier` + `.instances[].offset/.matched_data` form, and a flat `.offset/.identifier/.matched_data\|.data` attribute form. This is what lets one uploaded script produce identical findings across the differing libyara/yara-python builds embedded in different XDR agents.
- Cached-hit ingestion path — `_iter_hit_fields` (979-999) accepts a dict-shaped hit whose strings are hex strings and rehydrates them with `bytes.fromhex` (falling back to utf-8 encode). Live code in the match-rendering chain (used by `_write_alerts` and `scan_file`) belonging to the dormant "scan caching" roadmap feature.
- A SECOND, differently-formatted scan_id inside the scan-configuration event — `scan_config_data['scan_id'] = f"{hostname}_{datetime.now():%Y%m%d_%H%M%S}"` (line 5731), which is neither `config.scan_id` nor the envelope's `scan_id` on the same row. Delivery documents the `Scan configuration established` payload field-by-field but omits this; any consumer joining on `data.scan_id` for that one type silently fails.
- Two skip-reason keys nobody lists: `"Permission denied"` from `scan_file`'s `except PermissionError` arm (line 4966) — distinct from the pre-flight `"No read permission"` (4869) and produced when access is lost between the check and `rules.match` — and `"Junction/symlink duplicate"` from the dedupe arm (4877).
- FD monitoring never samples on a matching file — the FD block (4938-4963) sits AFTER `if matches: ... return True, "Scanned and matched"`, so matched files never advance `files_since_fd_check`. The counter is also incremented from both workers with no lock, so the nominal 1000-file interval is approximate.
- Uncapped per-rule detection census shipped on the wire — `comprehensive_final_report.data.detection_results.detection_breakdown = dict(scanner.detection_counts)` (line 5924), one key per triggered rule with no cap, alongside `top_10_rules`. Its local twin is `_log_final_results`' `top_10_detections`, which IS capped at 10. Separately, `failure_data.failure_reasons` is capped at 20 (line 6272).
- The efficiency-score arithmetic itself: `score = 100 - (files_skipped/files_processed)*20 - (failed_rules/total_rules)*30`, floored at 0 (lines 5959-5968). Every dimension names `efficiency_score`; none gives the formula, so nobody can predict or assert its value.
- The critical-error path dumps the full traceback to STDOUT as well as stderr — `CRITICAL ERROR: <msg>`, `Error details: <traceback.format_exc()>`, `Process failed with critical error` (6475-6478) — and then `time.sleep(2)` before returning. In an Action Center run the result stream therefore carries a full Python traceback ahead of the `SCAN_RESULT:` line.
- Windows default-target discovery is a three-source union, not one mechanism — `psutil.disk_partitions(all=False)` mountpoints, then the `GetLogicalDrives()` bitmask A-Z sweep, then a bare A-Z `os.path.isdir` sweep if both produced nothing, de-duplicated by `os.path.normcase` (2980-3027). Consequence traversal never states: mounted network/removable volumes returned by `disk_partitions` enter the default full-machine scope.
- `_log_critical` uses a DIFFERENT wire format from every other send — a single JSON object with `Content-Type: application/json` via `requests.post(json=...)` (1958-1965), not NDJSON with `text/plain`. Delivery documents the critical-path synchronous send but not that it is the one place the collector receives a non-NDJSON body.
- Telemetry-log drops on the LogManager channel are silent and unaccounted — `_log_with_webhook`'s `self.webhook_queue.put(standard_log, timeout=1.0)` is wrapped in a bare `except Exception: pass` (1929-1932) with no counter and no log line, unlike `ResultsUploader.add_match` ("Upload queue full - skipping...") and `WebhookUploader._queue_standard_upload`. Delivery's "Queue-full handling" entry covers the other two channels only.
- The placeholder-credential abort still performs the destructive half of a run — `LogManager`, `StatisticsManager`, `WebhookUploader` are constructed and their threads started, and `cleanup_manager.initial_cleanup()` has already wiped alert/ and evidence/ and pruned old runs' logs (6021-6029) BEFORE the check at 6034-6047. Because `scanner` never binds, the finally-block guard `'scanner' in locals()` also means NO `scan_summary_<run_id>.json` is written on this path.
- Circuit-open re-queue semantics — `_process_standard_batch` puts every item of a blocked batch back on the TAIL of the queue and sleeps 2.0s (3661-3669), so telemetry is reordered relative to emission and the same events can bounce repeatedly through open windows before ever being counted.
- macOS disk-I/O telemetry is structurally zero by design — both `StatisticsManager._collect_performance_snapshot` (1497-1504) and `SystemResourceMonitor` (2239-2246, 2303-2312) branch on `platform.system() != "Darwin"` before touching `io_counters()`, so `disk_io_read_mb`/`io_read_mb`/`io_write_mb` are always 0 on macOS (only the progress path at 5305-5312 uses a try/except instead). Performance's "disk_io_mb rises only in proportion to matched-file bytes" observable cannot hold there.
- `system_resource_snapshot.monitoring_duration_minutes` is derived from `psutil.boot_time()` — i.e. HOST UPTIME, not scan or monitor duration (2416-2419) — while the sibling `resource_monitoring_summary.monitoring_duration_seconds` is `len(resource_history) * 10`. Two same-named-looking duration fields measuring different things.
- `StatisticsManager.stop_monitoring()` writes a `COMPREHENSIVE STATISTICS SUMMARY` block (peak/avg CPU+memory, scan_estimates, and a per-worker `files_processed`/`avg_processing_time_ms`/`error_rate_percent` table, pretty-printed JSON) to statistics_<run_id>.log on EVERY run, including when the perf monitor is disabled and `performance_history` is empty (1701-1728) — and `__del__` calls it too, so it can fire a second time at interpreter teardown.
- Host identity on every event: get_os_info() / get_system_info() (lines 308-345) derive hostname (socket.gethostname), the ipAddress list (socket.getaddrinfo, 127.* filtered, falling back to the literal string 'Unable to determine IP address: <err>'), and a human-readable os_info via a hardcoded Darwin-major -> marketing-name table ({'24':'macOS 15 (Sequoia)' ... '21':'macOS 12 (Monterey)'}, unknown majors -> 'macOS (Darwin <release>)'). Every uploaded row and the evidence file_mapping header carry these; no dimension lists the source or the staleness risk in that table.
- yara-version compatibility shim for match strings: _normalize_match_strings() (844-867) accepts the legacy 3-tuple form, the yara >= 4.3 StringMatch object (identifier + instances[].offset/.matched_data), and a bare-object fallback, normalising all three to (offset, string_id, data). Every offset, string ID and rendered byte value in alert/<rule>.txt and in the yara_match payload flows through it; missing offsets surface as -1 and missing IDs as the literal 'unknown'.
- macOS writes a probe file to /tmp on every scanned file: _is_case_sensitive_fs() (607-622) creates and deletes /tmp/CaSe_TeSt_YaRa_<pid> on Darwin, and _get_real_path() (640-662) calls it for EVERY file scan_file() processes (line 4873). That is a per-file create+unlink outside scanner_dir, on the host being scanned - no storage/traversal entry mentions the scanner writing anywhere but scanner_dir.
- File creation-time derivation and its platform asymmetry: _get_file_creation_time_iso() (881-896) returns st_ctime on Windows, st_birthtime where the platform exposes it, and None otherwise - so file_creation_time is null on most Linux filesystems, both in the 'File Creation Time:' line of alert/<rule>.txt and in the yara_match / alert event payloads. The artefacts are listed but the derivation and the null-on-Linux case are not.
- CLI cancel dispatch: the __main__ block routes argv[1] == 'cancel' (case-insensitive) to cancel() instead of main(), and the exit-code guard additionally treats a result starting with 'cancel failed' as failure. Both cancel entries in the inventory describe only the zero-input Action Center entry point; the lifecycle 'CLI dispatch and exit-code contract' entry documents only the 3 scan arguments.
- Second, non-canonical scan_id inside the 'Scan configuration established' statistics event: scan_config_data (line ~5730) sets 'scan_id': f"{hostname}_{datetime.now():%Y%m%d_%H%M%S}" - no rule-hash suffix and no microseconds - so data.scan_id on that one event disagrees with the envelope scan_id every other row carries. The delivery entry enumerates the other six keys but not this trap.
- 'Permission denied' as a distinct skip_breakdown key: scan_file()'s `except PermissionError` (line ~4966) returns that literal reason, separate from the pre-check's 'No read permission' and from the bounded 'Scan error (<Type>)' labels. No entry lists it, so a skip-reason inventory built from the doc is incomplete.
- "Permission denied" as a distinct skip_reasons key: scan_file's `except PermissionError: return False, "Permission denied"` (line 4968) is a fourth permission label, separate from the pre-check's "No read permission" (4869) and from _scan_error_reason's "Scan error (PermissionError)". No traversal/lifecycle entry lists it. It also distorts a listed capability: error_summary.scan_errors sums only skip_reasons keys containing 'error' (line 6313), so files failing this way are counted nowhere.
- Per-target error isolation in scan_system: the inner `except Exception as e: log_error(f"Error scanning target {target}: {e}"); continue` (lines 5862-5864) abandons one failing target and carries on with the rest instead of failing the run. Observable as that line in scan_errors_<run_id>.log plus a missing 'Target scan completed:' statistics event for that target while later targets still report theirs. No dimension covers mid-walk per-target failure.
- _normalize_match_strings (line 844): cross-version normalisation of yara-python match strings - 3-tuples (yara 3.x), StringMatch objects with .identifier/.instances/.matched_data (yara-python 4.3+), and a bare .offset/.identifier/.data fallback, all flattened to (offset, string_id, data). Every claim about match_count, match_ids, 'Total string hits', string_match_count and per-offset alert rendering depends on it, and the module-availability entry already establishes libyara differs per endpoint. Listed by no entry.
- _iter_hit_fields cached-dict branch (lines 981-992): the match-field extractor also accepts a dict-shaped hit whose strings are hex-encoded (bytes.fromhex with a UTF-8 fallback), i.e. a second, non-live-Match ingestion path for match data. No entry mentions it.
- The uploads-log receipt `Queued finding for upload: rule='X', file=Y, hits=N (truncated)` (lines 3409-3412) - the per-finding queue confirmation and the only place the `truncated` flag is visible locally (the alert text renders the omission note instead). No delivery entry lists it; entries cite only the 'Added N local result entries...' line.
- performance_summary in comprehensive_final_report (lines 5947-5949, from StatisticsManager.get_current_stats_for_upload()) and performance_metrics in scan_completion_summary (line 6305). The delivery entries enumerate upload_summary, file_processing, rule_compilation, efficiency_score and error_summary but never these two blocks.
- _apply_light_process_priority's outer failure path (lines 928-930) emits a different system message with NO data payload: 'Could not apply light profile process priority tuning: <err>'. The performance/lifecycle entries list only the cpu_priority_error / io_priority_error data keys, which come from the inner handlers.

---

*Generated from a source enumeration of `xsiam_yara_scanner.py`, audited for completeness,
accuracy and observability. Keep it current in the same commit that changes behaviour —
a stale capability reference is worse than none, because it is trusted.*
