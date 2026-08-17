# XSIAM Scanner — Capability Reference

`xsiam_yara_scanner.py` **v4.4.0** · Cortex XSIAM edition (HTTP Log Collector delivery).
The XDR edition has its own: [`docs/xdr/CAPABILITIES.md`](../xdr/CAPABILITIES.md).

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
| Capabilities catalogued | **297** |
| &nbsp;&nbsp;Rule Handling | 44 |
| &nbsp;&nbsp;Scan Targeting, Traversal & Skipping | 47 |
| &nbsp;&nbsp;Performance & Resource Management | 48 |
| &nbsp;&nbsp;Local Storage & Host Footprint | 35 |
| &nbsp;&nbsp;Delivery, Aggregation & Telemetry | 58 |
| &nbsp;&nbsp;Scan Lifecycle, Control & Error Handling | 65 |
| ⚠ Control gaps (verified) | 27 |
| ⚠ Observability gaps | 17 |

**17 open observability gaps**, after triage — down from the 40 this inventory
originally recorded. The closed ones were never really broken: their evidence was an
info-level log that reached nothing until root logging gained a disk sink. See
*Observability status* below for the split between what still needs instrumentation and
what is believed dead. Inline ⚠ markers are a subset — the section below is authoritative.

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
- **Observe:** Rewrite Observe to: "Pass a base64 blob longer than 50,000,000 characters. stderr shows `YARA Scanner Critical Error: Critical scanner error: YARA rules input too large` followed by `SCAN_STATUS: ERROR` (main's handler, lines 6651-6656), and the SCAN_RESULT line reads `Scan failed: 0 files scanned \| ... \| Critical error occurred` with exit code 1. logs/yara_processing_<run_id>.log already exists with its 4-line banner and ends with `CRITICAL: Failed to decode YARA rules: YARA rules input too large` (written at line 2797). Do NOT expect `Critical startup error:` - that prefix (line 6851) only fires for exceptions escaping main(), and do not expect an empty logs dir."
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
- **Observe:** Rewrite Observe to: "Read logs/diagnostics_<run_id>.log for the line `Found N rule start positions` (emitted at line 4784) and compare N against `total_rules_found` in the `YARA Rules loaded: N rules, M imports` system event (line 6391, system_<run_id>.log). They must be equal for a pack whose rule keywords appear inside comments or strings. The same file also carries `Found N unique import statements` (4772) and `Rule extraction complete: N successful, M failed` (4808)."
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
- **Observe:** Rewrite Observe to: "logs/diagnostics_<run_id>.log contains one line `Successfully built ruleset with N rules` - with ` (M failed)` and ` (K skipped - missing modules)` appended when non-zero - emitted at line 4738. N must equal the number of namespaced sources actually handed to yara.compile at line 4730; cross-check M and K against failed_rules_count / skipped_rules_count on the SCAN_RESULT line and in scan_summary_<run_id>.json."
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
- **Observe:** Only the text block in logs/yara_processing_<run_id>.log exists (`=== RULE COMPILATION FAILURE #n ===`, rule name, error, numbered rule source with `<-- ERROR HERE`). The webhook `YARA rule compilation failed: <rule>` error event carrying error_analysis / error_line_number / rule_length_lines / compilation_failure_number is never emitted — it is gated on `hasattr(self.config, 'log_manager') and self.config.log_manager`, and ScanConfig never gets that attribute.
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

Only the rule-health condition can ever fire: `error_logger.has_errors and error_logger.valid_rules_count == 0`. The >50% error-log-ratio trigger is dead code — it is gated on `hasattr(self.config, 'log_manager')`, and nothing in the file ever assigns `log_manager` onto the ScanConfig object (every occurrence of `config.log_manager` is a read).

- **Control:** not configurable — default `suppression triggers on `error_logger.has_errors and valid_rules_count == 0` (also on a >50% error-log ratio)`
- **Observe:** `logs/system_<run_id>.log`: `Critical errors detected - skipping cleanup to preserve diagnostic data`, and no `cleanup_script.bat` / `cleanup_script.sh` is written under scanner_dir.
- **Source:** ``CleanupManager.schedule_final_cleanup` (4039-4058)`

### YARA runtime version banner  <sub>all (values are the per-agent embedded Python/libyara build)</sub>

The processing log opens with the interpreter and engine identity: Python version, full platform string, and `yara.__version__` (or `Unknown` when the attribute is absent) — the ground truth for why a module probe or a rule syntax behaves differently on one endpoint than another.

- **Control:** not configurable — default `always written as the first four lines`
- **Observe:** Head of `logs/yara_processing_<run_id>.log`: `=== YARA Processing Log ===`, `Python Version: ...`, `Platform: ...`, `YARA Version: ...`. Also duplicated in the `scanner_initialization` event data as `yara_version` / `python_version`, and in the final report's `system_info`.
- **Source:** ``ErrorLogger._setup_error_logger` (1222-1226), `main` init_data (6169-6170)`

### Lenient base64 rule-payload decoding (b64: prefix, URL-safe, unpadded)

The rule blob passed as the scanner's first argument does not have to be canonical base64: a leading `b64:`/`B64:` marker (case-insensitive), embedded newlines/carriage-returns/spaces (which console and Action Center wrapping introduce), the URL-safe alphabet (`-`,`_`), and missing `=` padding are all normalized away before decoding, so the same ruleset pasted in any of those forms decodes to byte-identical text and yields an identical rule_hash. It does NOT yield an identical scan_id: scan_id is `f"{hostname}_{run_id}_yara_{rule_hash[:12]}"` (line 2744) and run_id is a per-run microsecond timestamp (line 2673), so only the trailing 12-char hash component is stable across runs. The surprising consequence is the opposite case: raw, un-encoded YARA text is not accepted, and which of two errors the customer sees is essentially arbitrary. base64.b64decode runs with validate=False, so it silently discards the non-alphabet characters, but the padding is computed on the pre-filter length (line 366), so the outcome depends on how many base64-alphabet characters the pasted rule happens to contain: verified empirically, a normal multi-line rule decodes to garbage bytes and then fails the rule-declaration check ('Decoded content does not contain any YARA rule declarations'), while a one-line `rule Test { condition: true }` instead raises binascii.Error ('number of data characters (21) cannot be 1 more than a multiple of 4') and surfaces as 'Base64 decode failed'. Neither message says 'this looks like plain text, base64-encode it'.

- **Control:** Not configurable — confirmed by grepping every base64 reference in the file (lines 26, 359-373, 559-584): no env var or constant governs the normalization. The only related guard is the hardcoded 50_000_000-character ceiling on the ENCODED input in decode_yara_rules (line 573), checked before the empty-input check and before decoding. — default `-`
- **Observe:** logs/yara_processing_<run_id>.log under scanner_dir (logs_dir = scanner_dir/logs, line 2686; ErrorLogger's own FileHandler at INFO with propagate=False, file path 1183-1185, handler 1206-1221 — not the root logger): a blob that raises logs `DECODE_ERROR: Base64 decode failed: ...` (586-589) and successfully-decoded-but-not-YARA content logs `VALIDATION_ERROR: Decoded content does not contain any YARA 'rule' declarations` (598-601). Note that on either failure ScannerConfig.__init__ re-raises (2732-2734) before a scanner object exists, and write_scan_summary is guarded on `scanner is not None` (line 6576), so NO scan_summary JSON is written for a failed decode — this log is the only artifact. Positive proof of normalization: submit the same ruleset padded, unpadded, URL-safe and `b64:`-prefixed and compare `rule_hash` in logs/scan_summary_<run_id>.json (path 2146, rule_hash 2152) — all four must be identical; `scan_id` (2151) will differ per run except for its `_yara_<12 hex>` suffix.
- **Source:** `_b64_to_text (359-373: prefix strip 362-363, whitespace strip 364 — only \n, \r and space, tabs are not stripped, URL-safe translate 365, re-pad 366-368, decode 370-371, raise 372-373); called only from decode_yara_rules (559-604) at line 584, whose size guard is line 573 and whose rule-declaration validation is 592-602; entry points ScannerConfig.__init__ lines 2724-2731, rule_hash 2743, scan_id 2744, run_id 2673.`

### Condition-only match explanation mined from the rule's own source text

When a rule fires but yara returns no string instances, the alert is not left blank — the scanner re-reads the ORIGINAL text of that specific rule (kept in a per-rule source map built once at scanner construction from the decoded ruleset, keyed by lowercased rule name) and appends a `Condition evidence:` clause on top of the meta dump: 'checks for an MZ/PE header' for a `uint16(0) == 0x5A4D` test, 'references imports: <names>' listing every distinct function name from the two-argument `pe.imports("lib","func")` form, and 'uses the PE module for structural checks' for any `pe.` reference. The consequences are narrower than they look. Because the third pattern is a bare `\bpe\.` catch-all, any rule that touches the PE module at all still gets an evidence clause — the DLL-only `pe.imports("kernel32.dll")` and the hash-based `pe.imports()` overloads lose only the 'references imports' line, not the whole clause. A truly meta-only summary happens only when the rule references no `pe.` at all (elf./math./hash./dotnet rules) or when its name is missing from the source map. The MZ pattern is also order- and form-sensitive: it is anchored on `uint16 ( 0 ) == 0x5A4D`, so a reversed `0x5A4D == uint16(0)` or a `uint16be(0) == 0x4D5A` test yields no MZ note even though the rule does the same thing. The second real surprise holds: that same prose string is what ships to XSIAM as the `string` field of the yara_match event (match_scope 'rule', empty offset), so the 'matched string' column contains a sentence rather than bytes.

- **Control:** Not configurable — the three patterns are hardcoded regexes at lines 536, 541 and 549; the meta keys consumed (purpose/severity/scope/author) are hardcoded at 518-521 and tags are appended at 531-532. No env var or constant gates any of it. — default `-`
- **Observe:** scanner_dir/alert/<rule>.txt: the block written under `Condition Match Details:` (lines 5218-5222) contains the whole summary including the `Condition evidence:` clause; it is written only in the `elif condition_only_detail` arm, i.e. only when the finding produced zero string instances. On the wire, the corresponding yara_match event carries `match_scope: "rule"`, `offset: ""`, `match_count: 1` and the summary text in `string` (fallback entry built 3337-3342, _first_string set 3361-3363, emitted 3393-3396), subject to UPLOAD_RESULTS (line 109, True) and a live uploader thread (3370). A rule with `uint16(0) == 0x5A4D and pe.imports("kernel32.dll","CreateRemoteThread")` and no strings section is the direct test case; for the meta-only case use a rule whose condition references no `pe.` (e.g. `filesize < 100`).
- **Source:** `_summarize_condition_only_match (512-556): meta 518-521 and tags 531-532, MZ regex 536 (IGNORECASE), pe.imports extraction with dedupe 539-547 (findall 541, IGNORECASE), bare `pe.` check 549-550 (note: NOT IGNORECASE, unlike the other two), 'Condition evidence:' join 552-553, trailing 'Rule:' 555. Source text supplied by _build_yara_rule_source_map (500-509, keys lowercased at 508) stored as self.rule_source_map at 4220; sole call site _write_alerts — guard `if not strings` 5142-5143, call 5144-5149 with a `.get(..., "")` default so an unmapped rule name silently skips the whole evidence block.`

### yara-python version shim for match strings (3.x tuples vs 4.x StringMatch instances)

Every offset, string ID and rendered byte the scanner reports — in alert files and in uploaded yara_match events — is produced by one normalizer that flattens three different yara-python return shapes into `(offset, string_id, data)`: the legacy 3-tuple (yara 3.x, what the Linux agents' yara 3.11.0 returns), the modern StringMatch object whose `.instances[]` each carry `.offset`/`.matched_data` (yara 4.x on the Windows/macOS agents), and a bare object exposing `.offset`/`.identifier`/`.matched_data` or `.data`. Grepping the file confirms `.instances` and `.matched_data` appear nowhere else (only lines 853-863), so this really is the single choke point that lets one uploaded script produce identical findings across agents with different embedded libyara builds. Two surprises hold, with one qualification. It does not raise on an unrecognised shape — a 2-tuple, or an object with none of the expected attributes, falls through to the last branch and becomes offset -1 / identifier 'unknown' / data b'' rather than an exception, and those sentinels propagate into alert files and into the fields sent to the tenant. (It CAN still raise on a recognised-but-malformed shape: `int()` at 850/856/861 raises TypeError if an offset is present but non-numeric, e.g. None.) And the 4.x branch expands each StringMatch into one tuple per instance, which is why match_count / 'Total string hits' counts OFFSETS, not distinct rule strings.

- **Control:** Not configurable — no flag selects a shape (detection is by isinstance/hasattr at 848/853). Only the downstream volume of the tuples it produces is capped: MAX_ALERT_OFFSETS_PER_FINDING (line 291, env YARA_MAX_ALERT_OFFSETS, default 50, clamped non-negative at 292, and 0 means UNCAPPED per the `cap <= 0` test at 5202) for alert files, and MAX_MATCH_SAMPLES_PER_FINDING (line 118, env YARA_MAX_MATCH_SAMPLES, default 50, minimum=1 so 0 falls back to the default) for uploads. — default `-`
- **Observe:** scanner_dir/alert/<rule>.txt: the deliberately uncapped `Total string hits: N` and `Hits per string ID: $a=3, ...` census (5196-5198; a None identifier is rendered `$?` per 5194) plus each `String ID:` / `Offset:` / `Data:` block (loop 5206, fields 5208-5210). A literal `String ID: unknown` is direct evidence the bare-object fallback branch (861-864) was taken — it cannot come from the StringMatch branch, whose hasattr guard means `identifier` exists. `Offset: -1` is NOT exclusive to that branch: the 4.x instances branch defaults a missing per-instance offset to -1 as well (line 856). On the wire, the same normalized tuples — re-ordered to (sid, off, data) at line 5166 before hand-off — appear in the yara_match event as `offsets`, `strings`, `match_ids` (uncapped per-identifier counts), `string_match_count` and `truncated` (3397-3401), and the count is echoed in the merged scan alert as `total_string_matches` (5236, consumed 4941/4951).
- **Source:** `_normalize_match_strings (844-866): 3-tuple branch 848-851, StringMatch+instances branch 853-859 (offset default -1 at 856), bare-attribute fallback 861-864 with the -1 / 'unknown' sentinels. Sole caller _iter_hit_fields line 994; consumers _write_alerts 5141-5222 (tuple re-order for upload at 5166) and 5236, ResultsUploader.add_match 3327-3421, scan_file 4938.`

### Dead cached-hit dict ingestion path in match-field extraction

**⚠ OBSERVABILITY GAP**  
The match-field extractor accepts two shapes, not one: a live yara Match object, or a plain dict whose `strings` are `(offset, id, hex-text)` triples that it rehydrates with bytes.fromhex, falling back to a utf-8 encode of the raw value. Nothing in the scanner ever builds such a dict — matches come only from rules.match() — and the 'Scan caching' feature that would have produced them is still listed as Roadmap in the module docstring and left as an empty placeholder section in the body. So this is a second, unreachable ingestion path sitting in live match-rendering code that both _write_alerts and scan_file call on every finding. It matters to maintainers rather than to a running scan: the branch is untested, and its fallback assumes the hex field is a str — verified in Python, handing it bytes makes bytes.fromhex raise TypeError, which the bare `except Exception` catches, and then `hx.encode` raises an UNCAUGHT AttributeError instead of falling back — so anyone reviving caching must serialize match data as hex text, not bytes.

- **Control:** Not configurable — no flag enables or reaches the dict branch; selection is a bare isinstance(hit, dict) test at line 981. — default `-`
- **Observe:** UNOBSERVABLE: no live scan can reach it, so it cannot be a runtime test criterion. Every finding on a real scan takes the else-branch (993-995), because `matches` is always the return of self.rules.match(...) at 4911-4915. Confirmable only statically, or by a unit-level call such as _iter_hit_fields({'rule': 'r', 'strings': [(0, '$a', '4d5a')]}) asserting the returned data is b'MZ' (confirmed by direct execution). Making it observable on a scan would require a cache writer that persists hits as dicts and feeds them back into _write_alerts — no such writer exists in the file.
- **Source:** `_iter_hit_fields (979-995): docstring naming the cached-dict shape at 980, dict branch 981-992 (bytes.fromhex 988, utf-8 fallback 990), live-Match branch 993-995. Callers: _write_alerts 5141 and 5236, scan_file 4938. Roadmap note 'Scan caching for enhanced performance (Roadmap)' at line 9, plus the empty 'ROADMAP FEATURES (Caching)' section at 1167-1171 whose only content is the comment 'Roadmap Feature: Caching implementation (currently disabled/dormant)'.`

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
- **Observe:** Rewrite Observe to: "Both halves are now checkable: `Unknown platform - manual target specification required` in yara_processing_<run_id>.log (3162), and the exact line `Using default Unix target: ['/']` in <scanner_dir>/logs/diagnostics_<run_id>.log (logging.info at 5423). The sibling `Using default Windows targets: [...]` (5420) and `Using configured scan targets: [...]` (5415) land in the same file, so the branch actually taken is distinguishable."
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

- **Control:** not configurable — default `Windows and macOS match case-insensitively throughout. On Linux only lin_skip_directory is case-sensitive (matched on the case-preserved normalized_path); skip_filenames, skip_extensions, skip_path_fragments, force_scan_fragments and force_scan_never_under all match the lower-cased portable_path and are therefore case-insensitive on Linux too.`
- **Observe:** on Windows, `C:\PROGRAMDATA\CYVERA` and `C:\programdata\cyvera` are both skipped; on Linux, `/opt/Traps/` is NOT skipped while `/opt/traps/` is — assert via presence/absence in the alert log or the per-target files_found delta
- **Source:** `_is_special_file lines 4997-5010; ScanConfig lines 2885-2888, 2935-2938; _is_case_sensitive_fs lines 600-622; _get_real_path lines 640-662`

### macOS case-sensitivity probe file written to /tmp for every file that reaches the scan body  <sub>darwin</sub>

**⚠ OBSERVABILITY GAP**  
On macOS, every file that gets past scan_file's exists / os.access(R_OK) / _is_special_file pre-checks causes one create+write+exists+unlink of `/tmp/CaSe_TeSt_YaRa_<pid>` on the host being scanned. It is the only PER-FILE write outside scanner_dir (the scanner does make one other out-of-tree write attempt: `_schedule_linux_cleanup` writes `/etc/systemd/system/yara-cleanup.service` at 4185-4186, and the dispatch at 4091-4096 runs that arm on every non-Windows platform including Darwin, where it simply fails and is swallowed). The probe's answer is used only to decide whether to lowercase the resolved path, and the resolved path is then discarded: the dedupe set it feeds is gated on `track_real_paths`, hard-set to False (2782), so on a million-file scan the scanner does ~a million /tmp round-trips for a value nothing consumes. All workers share one probe path (keyed by pid, not thread) and scan_file runs on N worker threads (worker loop 4725-4741), so the race is real; the bare `except:` (619-620) turns any race or failure into "case-insensitive", silently lowercasing paths. Note it is NOT literally every enumerated file: files pruned during the walk (skipped directory 5835-5836, junction skip 5849-5850, special file 5859-5860) never reach scan_file at all.

- **Control:** Not configurable — probe path is a literal at line 612 with no env knob (grep for CaSe_TeSt_YaRa returns only 612). `self.track_real_paths = False` (2782, the only occurrence — no env override anywhere) gates only the dedupe consumer (4892-4894, 4905-4907), NOT the `_get_real_path()` call at 4891, so changing it changes nothing about the /tmp writes. — default `Always on for Darwin scans (Windows short-circuits at 609-610, Linux at 621-622, neither touches disk).`
- **Observe:** UNOBSERVABLE from the scanner: no log line, no summary field. The two fields that would hint at it — `unique_real_paths` (5367, inside the additional_metrics dict shipped by log_scan_progress at 5372-5375) and `unique_paths_scanned` (5393, in _log_final_results) — are both `len(self.scanned_real_paths)` and are always 0, because the only `.add()` is at 4907 behind track_real_paths. To confirm it, watch the filesystem outside the scanner: `sudo fs_usage -w -f filesys \| grep CaSe_TeSt_YaRa` on the macOS endpoint during a scan, or query the tenant for file-create events on `/tmp/CaSe_TeSt_YaRa_*` from the agent's own file telemetry. To close it: Two minimal edits, both small. (1) Memoise and log the probe once: wrap _is_case_sensitive_fs (671) in functools.lru_cache(maxsize=1) and add, just before the Darwin `return not exists_lower` at 682, `logging.info(f"FS case-sensitivity probe: {test_file} -> case_sensitive={not exists_lower}")` (plus a logging.warning in the bare except at 683-684 naming the failure) - both then land in diagnostics_<run_id>.log via the handler at 6057-6061, and the /tmp write drops from once-per-file to once-per-run. (2) Add `"fs_case_sensitive": _is_case_sensitive_fs()` to the write_scan_summary dict in main()'s finally block (near the existing entries at 6765-6790) so the value is recorded per run. Separately note that unique_real_paths (5495) and unique_paths_scanned (5521) are hardcoded-0 telemetry while track_real_paths is False at 2854 - they should be dropped or the flag made configurable, but that is its own item.
- **Source:** ``_is_case_sensitive_fs()` 607-622 (Windows arm 609-610, Darwin arm 611-620, probe path 612, write 614-615, exists 616, unlink 617, bare except 619-620, Linux arm 621-622); `_get_real_path()` 640-662, calling `_is_case_sensitive_fs()` at 647 (try path) and 657 (except path); sole call site `real_path = _get_real_path(file_path)` in `scan_file` at 4891, reached only after the pre-checks at 4858-4890; `self.track_real_paths = False` 2782; consumers 4892-4894 and 4905-4907; `self.scanned_real_paths = set()` 4279; worker threading 4725-4741; competing out-of-tree write `_schedule_linux_cleanup` 4169-4187 with dispatch 4091-4096.`

### Undocumented skip_breakdown keys: "Permission denied" and "Junction/symlink duplicate"

Two skip labels reach `skip_breakdown` that a skip-reason inventory built from the docs will miss. `"Permission denied"` (4989) fires when a file passes the `os.access` pre-check but raises PermissionError later (at `os.stat` or `rules.match`) — distinct from the pre-flight `"No read permission"` (4886). Unlike the pre-flight arm, which logs each denial to the system log (4877), this arm logs nothing at all; and because `error_summary.scan_errors` sums only skip_reasons keys containing 'error' (6330-6331), these files are counted in no error total anywhere — they exist only as a raw skip_breakdown key. Note the label `"Scan error (PermissionError)"` from `_scan_error_reason` (935-950) is NOT a third variant: `except PermissionError` (4987) precedes `except Exception` (4990), and 4997 is the only call site of `_scan_error_reason` in the file, so that string can never be produced. `"Junction/symlink duplicate"` (4895) is unreachable: it sits behind `self.config.track_real_paths`, hard-set False (2782), so a report or test expecting it will always read zero — do not confuse it with the separate and reachable walk-time key `"Junction/symlink skip"` (5849-5850). Side note on the pre-flight arm: `self.permission_denials` (4879-4881) grows one dict per denied file and is never read anywhere in the file (grep returns only 4879-4881).

- **Control:** Not configurable for "Permission denied" — literal return at 4989, no knob. "Junction/symlink duplicate" is governed by `self.track_real_paths = False` (2782), the attribute's only occurrence in the file: a hard-coded config attribute with no env override. — default `"Permission denied" always active; "Junction/symlink duplicate" effectively disabled (track_real_paths False).`
- **Observe:** Read the `skip_breakdown` dict, not the summary JSON. On disk: `logs/statistics_<run_id>.log` (path built at 1781), the "Skip reasons: ..." record whose data carries `{'total_skipped', 'skip_breakdown'}` (5425-5430), and the "COMPREHENSIVE SCAN REPORT" statistics record (call 6001-6004, message string 6002, payload `final_report_data`). On the wire: the `comprehensive_final_report` webhook event (log_type set at 5989), field `data.file_processing.skip_breakdown` (5934), where `data.error_summary.scan_errors` (6330-6331) can be checked to confirm permission-denied files are excluded from it. NOT in `scan_summary_<run_id>.json` — that payload carries only `files_skipped` (6605), no breakdown (write_scan_summary payload 6597-6618). The pre-flight "No read permission" path is separately visible as per-file "Permission denied: <path>" lines in `logs/system_<run_id>.log` (log_system call 4877, file path built at 1785); the `except PermissionError` arm produces no such line, which is how the two are told apart.
- **Source:** ``scan_file`: pre-flight `return False, "No read permission"` at 4886 with per-file logging 4876-4881; dedupe `return False, "Junction/symlink duplicate"` at 4895 behind 4892-4894; `except PermissionError:` 4987, `error_occurred = True` 4988, `return False, "Permission denied"` 4989; `except Exception as e:` 4990 with `return False, _scan_error_reason(e)` at 4997 (its only call site); `_scan_error_reason` 935-950 (return at 950); accumulation into `self.skip_reasons` at 4738-4741; walk-time `"Junction/symlink skip"` 5849-5850; emission at 5425-5430, 5934 (event type 5989), 6001-6004; `scan_errors` sum at 6330-6331; `self.track_real_paths = False` 2782.`

### Windows default scan scope is every mounted volume, including network and removable drives  <sub>windows</sub>

**⚠ OBSERVABILITY GAP**  
With no `scan_folder` (or the literal "default"), Windows whole-machine scope is not just `C:\`. It is a union of three sources de-duped by `os.path.normcase`: every `psutil.disk_partitions(all=False)` mountpoint that is a directory, then every drive letter set in the `GetLogicalDrives()` bitmask that is a directory, then — only if both produced nothing — a bare A-Z `os.path.isdir` sweep, with `["C:\\"]` as the last-resort fallback. The `GetLogicalDrives()` arm (2994-3006) is the decisive one: the bitmask carries every assigned letter regardless of drive type, so mapped network shares, USB/removable volumes and attached VHDs enter the default scope, and a "default" scan on one workstation can end up walking a file server over SMB. The `os.path.isdir(root)` guard at 3001 is the only filter, so an empty removable slot or a disconnected mapping drops out but a live one does not.

- **Control:** `scan_folder` — main()'s second Action Center input (signature at 6025), stored at 2707 and tested at 2945 (`if self.scan_folder and self.scan_folder.lower() != "default"`). Any other value replaces this discovery entirely with the validated comma-separated list (2945-2969). The union itself has no knob. Note `if hasattr(self, "_discover_all_targets")` at 2971: grep for `_discover_all_targets` returns only 2971-2972 — the method is never defined — so `_default_discover_targets` (2977) always runs. — default `Default (scan_folder unset or "default"): the three-source union; `["C:\\"]` only if the union is empty (3025-3026).`
- **Observe:** The resolved list is recorded in three places: `scan_summary_<run_id>.json` field `scan_targets` (written at 6601, inside the write_scan_summary payload 6597-6618); `logs/yara_processing_<run_id>.log` (path built at 1183-1184), the line "Light profile full-scope targets on Windows: [...]" (3027) — this is ErrorLogger's own INFO FileHandler (setup 1196-1221, level INFO at 1200/1212, `propagate = False` at 1221), so it survives `setup_logging`'s root pin to WARNING (5899-5913); and on the wire as `scan_targets` inside the "YARA Scanner initialization completed" system event (init_data dict 6181-6203, the field at 6189, emitted 6205) plus the "SCAN SCOPE: Full system scan" system event data (6207-6212, data dict at 6212). Confirm the network/removable case by comparing that list against `net use` / `wmic logicaldisk get name,drivetype` on the endpoint. Do NOT rely on `_get_scan_targets`' "Using configured scan targets" line (5287) — that one is `logging.info` on the root logger and is unobservable.
- **Source:** ``_default_discover_targets` 2977; Windows branch 2980; psutil `disk_partitions(all=False)` loop 2983-2992; `GetLogicalDrives()` bitmask sweep 2994-3006 (isdir guard 3001); bare A-Z fallback sweep 3008-3015 behind `if not discovered:` 3008; `os.path.normcase` dedupe 3017-3023; `["C:\\"]` fallback 3025-3026; info log 3027. Dispatch at 2970-2975 (`hasattr(self, "_discover_all_targets")` 2971, `_default_discover_targets()` 2974). Non-default path 2945-2969. `self.scan_folder = scan_folder` 2707; `def main(yarafile=None, scan_folder=None, alert_severity="low")` 6025. Emission: 6189, 6205, 6207-6212, 6601.`

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

**⚠ OBSERVABILITY GAP**  
`_sample_governor()` is called on every file (and on every queue-full backoff) but only re-reads CPU once the configured interval has elapsed, so psutil is not sampled per file.

- **Control:** `self.throttle_check_interval_secs = _env_number("YARA_CPU_SAMPLE_SECS", 0.5, minimum=0)` in ScanConfig — default `0.5 seconds`
- **Observe:** UNOBSERVABLE: Frequency of `CPU governor \|` performance lines is bounded by this interval combined with the emit policy below; with a debug build, `last_governor_sample` advances at most every 0.5 s. minimum=0 is deliberate — a negative value would make the check always true and sample psutil on every file. To close it: Instrument _sample_governor (line 4887). Add `self._governor_sample_count = 0` beside line 4408, then immediately after line 4898 insert `self._governor_sample_count += 1` and capture the gap, e.g. `_gap = now - _prev` where `_prev = self.last_governor_sample` is read before line 4898. Add both to the payload already emitted at 4917-4920 by extending `s_` with `{'samples_taken': self._governor_sample_count, 'secs_since_last_sample': round(_gap, 3), 'sample_interval_secs': self.config.throttle_check_interval_secs}`. performance_<run_id>.log then shows sampling cadence directly and the criterion becomes "secs_since_last_sample is never below throttle_check_interval_secs (default 0.5)" - no debug build required.
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
- **Observe:** XQL filter on the event type `system_resource_snapshot` (plus `resource_monitoring_summary` at the end of the run) — `system_resources` is not an emitted type and matches nothing.
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
- **Observe:** total_matches counts OFFSETS, not findings: it is incremented once per entry of upload_entries inside add_match(), so one 21,047-hit finding books total_matches=21047 while successful_uploads/failed_uploads/undelivered book 1 (they count upload items = one per (rule, file) finding). That is why the result-line shortfall denominator is ok+failed+undelivered and never total_matches.
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

### File-descriptor leak sampling (skipped on every matched file, and on every skipped file)  <sub>linux, darwin</sub>

**⚠ OBSERVABILITY GAP** · **⚠ CONTROL GAP**  
When FD monitoring is on, the scanner is supposed to re-read its own open-FD count every 1000 files and warn on growth. The check sits near the very end of `scan_file` (def at 4850), after the `if matches: ... return True, "Scanned and matched"` early return at 4956 — so a file that matches a rule never advances the counter. It is also skipped by every earlier bail-out in the same function: "File does not exist" (4860), "No read permission" (4886), "Special system file" (4889), "Junction/symlink duplicate" (4895), "Not a regular file" (4899), "File too large" (4903), and both exception handlers (4987-4990+). Only the terminal "Scanned but not matched" path (4985) increments it. On a noisy ruleset or a storm scan the FD probe therefore fires far less often than every 1000 files, and on a run where nearly everything matches or is skipped it may never fire at all. The counter is also a plain int shared by both worker threads with no lock (`self.lock_files`, created at 4251, is taken only once — at 4931, around the evidence-collector call), so `+=` at 4959 is a read-modify-write that can lose updates and make the interval approximate even without matches. The whole path is off by default and non-Windows only; the inner `platform.system() != "Windows"` re-check at 4963 is redundant with the gate in main() at 6119, which is the only thing that can set `config.monitor_fd_usage = True`.

- **Control:** `ENABLE_FD_MONITOR` at line 202 (env `YARA_ENABLE_FD_MONITOR`) enables the feature; `ScanConfig` copies it to `self.enable_fd_monitoring` at 2781. main() additionally requires non-Windows and `psutil.Process.num_fds` before setting `config.monitor_fd_usage = True` (6119, 6162). The 1000-file interval itself is hardcoded — `self.fd_check_interval = 1000` at line 4218, not configurable (no env var or flag reads it). — default `Disabled (`ENABLE_FD_MONITOR = False`, line 202); interval 1000 files when enabled`
- **Observe:** UNOBSERVABLE: a sample that finds nothing emits nothing, so you cannot tell whether a sample ran, was skipped by a match/skip path, or was lost to the unlocked increment. The only artefacts are threshold breaches in `<scanner_dir>/logs/system_<run_id>.log` (`logs_dir` built at 2686, SYSTEM file name at 1785): `Initial file descriptors in use: N` once at startup (6160), then `FD usage increased by <n> (current: <n>)` only when growth exceeds 100 (4970-4973) and `WARNING: High FD usage: <n>` only above 900 (4975-4978). The same lines also reach the collector via `_log_with_webhook` (1901-1931) — note the wire field is `type` (value `"system"`), not `log_type`, per `StandardLogEntry.to_dict` at 1042; delivery additionally requires `UPLOAD_RESULTS`/`UPLOAD_NON_MATCH_DATA`/`API_ENDPOINT` and a live webhook thread (1916-1917), all true by default (109-110). Confirming the sampling gap needs added instrumentation — e.g. logging `files_since_fd_check` on every sample, or asserting sample count against a run where every file matches. To close it: Rewrite Observe to state the default-off gate first (flip ENABLE_FD_MONITOR at 248 to True in the uploaded script - env vars are not settable via Action Center), then add the missing sample record: in scan_file's FD block, emit one line per sample regardless of thresholds, e.g. immediately after the reset at 5065 add `self.log_manager.log_system(f"FD sample: files_since_check={self.fd_check_interval}, current={current_fds}, delta={fd_increase}")` (move it inside the num_fds try at 5071 so current_fds is bound), and make the increment atomic by taking self.lock_counts around 5063. Also add a `fd_samples_taken` counter incremented at 5065 and surface it in write_scan_summary (dict at 6765-6790) so the sample count can be compared against files_scanned/1000 - that is what proves the matched-file and early-return skips, since a run where every file matches would otherwise show zero samples with no explanation.
- **Source:** ``YaraScanner.__init__` 4216-4219 (`fd_monitoring_enabled` from `config.monitor_fd_usage`, `initial_fd_count`, `fd_check_interval = 1000`, `files_since_fd_check = 0`); `scan_file` def at 4850 with early returns at 4860/4886/4889/4895/4899/4903 and the matched-file return at 4956; the FD block at 4958-4983; the non-match return at 4985; `self.lock_files` created at 4251 and used only at 4931; setup and gating in main() (def 6025) at 6119-6173 (`config.monitor_fd_usage` True at 6162, False at 6164/6168/6173), which runs before the scanner is constructed at 6238; `ENABLE_FD_MONITOR` at 202, mirrored to `config.enable_fd_monitoring` at 2781; worker count capped at 2 by `self.max_workers` at 2762, threads started at 5767-5770`

### macOS disk-I/O telemetry is structurally zero  <sub>darwin</sub>

Every disk-I/O number the scanner reports is hard 0 on macOS, in all three collection paths, because psutil has no `Process.io_counters()` on Darwin. Two paths branch on `platform.system() != "Darwin"` and substitute 0 before ever calling it (1576-1586, 2308-2318); the third calls it inside a try and swallows `AttributeError`/`NotImplementedError`/`AccessDenied`, leaving the pre-set `disk_io_mb = 0` (5324-5329). The consequence is that a macOS run looks like it performed no disk reads at all, and any test or dashboard rule of the form "disk_io rises with bytes scanned" silently passes/fails for the wrong reason there. The derived `efficiency.io_intensity` (2360) is 0 for the same reason. Unlike the two monitor paths, the third one is NOT off by default: `_log_progress` is driven by the progress-heartbeat thread, started unconditionally at 5778-5782 and ticking every `config.log_interval` (default 30 s, line 2778), so `disk_io_mb: 0.0` is emitted on a stock macOS run.

- **Control:** Emission of the two monitor paths is gated by `ENABLE_PERF_MONITOR` at line 201 (env `YARA_ENABLE_PERF_MONITOR`, checked in `StatisticsManager.start_monitoring` at 1537) and `ENABLE_RESOURCE_MONITOR` at line 200 (env `YARA_ENABLE_RESOURCE_MONITOR`, checked in `SystemResourceMonitor.start_monitoring` at 2262). The third path is ungated; its cadence is `YARA_PROGRESS_LOG_SECS` (default 30, line 2778). The Darwin zeroing itself is Not configurable — hardcoded `platform.system()` comparisons at 1501, 1576, 2241 and 2308, plus the untyped-exception fallback at 5328. — default `Both monitors disabled by default (200-201); the progress-heartbeat path is always on. On macOS the I/O fields are 0 wherever they appear.`
- **Observe:** Stock config, macOS, no flags: `<scanner_dir>/logs/performance_<run_id>.log` gets `System Resources \| CPU: … \| Memory: … \| Disk I/O: 0.0MB \| Network: …` every ~30 s from `log_system_resources` (2067-2083), and the same lands on the wire as a `type: "performance"` event with `data.disk_io_mb == 0.0` (via `_log_with_webhook`, 1901-1931). Also stock: `type: "scan_completion_summary"` (created 6349-6357, priority-queued 6359) carries `data.performance_metrics.current_performance` — which is `PerformanceSnapshot.to_dict()` including `disk_io_read_mb`/`disk_io_write_mb` (1095-1096) — but only non-null when perf monitoring populated `performance_history`; the same dict rides `type: "comprehensive_final_report"` at 5966/5988-5998. With `ENABLE_PERF_MONITOR=True`: `Performance Snapshot \| … Disk I/O: R:0.0MB W:0.0MB` in the same log (1636-1645), written on every 6th snapshot at a 5 s cadence (1557-1560) i.e. ~30 s — but note `performance_history` is a `deque(maxlen=1000)` (1462) and the test is `len(...) % 6 == 0`, so once it saturates (1000 % 6 == 4) that line stops forever after ~83 min. With `ENABLE_RESOURCE_MONITOR=True`: `type: "system_resource_snapshot"` events (created 2433-2442, queued 2444) carry `data.process.io_read_mb == 0`, `data.process.io_write_mb == 0`, `data.efficiency.io_intensity == 0`. Run the identical scan on a Linux endpoint to see the same fields non-zero — that A/B is the test.
- **Source:** ``StatisticsManager.__init__` 1501-1507 (Darwin -> `initial_io_counters = None`); `_collect_performance_snapshot` def 1568, Darwin guard 1576-1586, feeding `disk_io_read_mb`/`disk_io_write_mb` at 1597-1598, printed by `_log_performance_details` 1636-1645 (called 1557-1558, loop sleep 5 s at 1560); `SystemResourceMonitor.__init__` 2241-2247 (Darwin -> `initial_io = None`); `_collect_resource_snapshot` def 2295, Darwin guard 2308-2318, feeding `io_read_mb`/`io_write_mb` at 2335-2336 and `io_intensity` at 2360; the third path, `YaraScanner._log_progress` (def 5298), uses try/except at 5324-5329 and calls `log_system_resources` at 5334; heartbeat thread 5778-5782 driving `_progress_heartbeat` 5607-5622 at `config.log_interval` (2778). `PerformanceSnapshot.to_dict` 1088-1103 (I/O fields 1095-1096) is reached on the wire through `get_current_stats_for_upload` (1730-1746), which HAS two callers: 5965 (-> `comprehensive_final_report`, 5988-5998) and 6313 (-> `scan_completion_summary`, 6349-6359).`

### monitoring_duration_minutes reports host uptime, not scan duration

`system_resource_snapshot` events carry a `monitoring_duration_minutes` field computed from `psutil.boot_time()` (captured at 2240, used at 2423), so it is how long the MACHINE has been up, not how long the scan or the monitor has been running. On a long-lived server it reads thousands of minutes on the very first snapshot. The trap is the sibling field: `resource_monitoring_summary.monitoring_duration_seconds` (2501) measures the monitor's own run (`len(resource_history) * monitoring_interval`). Two similarly named duration fields from the same class disagree by orders of magnitude, and any rate computed by dividing work by `monitoring_duration_minutes` is wrong. Caveat on the 'correct' sibling: `resource_history` is a `deque(maxlen=360)` (2232) at a 10 s interval, so `monitoring_duration_seconds` saturates at 3600 — it is accurate only for scans under 60 minutes and silently under-reports longer ones.

- **Control:** `ENABLE_RESOURCE_MONITOR` at line 200 (env `YARA_ENABLE_RESOURCE_MONITOR`) gates whether either field is emitted at all — `ScanConfig.enable_resource_monitoring` at 2780, checked at 5726 before the monitor is constructed and again in `start_monitoring` at 2262. `self.monitoring_interval = 10` at line 2224 is the multiplier behind the correct sibling field; `self.upload_interval = 45` at 2225 controls how often snapshots are actually uploaded. The boot_time derivation itself is Not configurable (single hardcoded expression at 2423). — default `Disabled (`ENABLE_RESOURCE_MONITOR = False`, line 200); when enabled, snapshots are collected every 10 s (2224, sleep at 2289) but uploaded only every 45 s (2225, gate at 2285-2287), and history is capped at 360 entries (deque maxlen, line 2232)`
- **Observe:** With resource monitoring enabled, compare two events from the same `scan_id`: `type: "system_resource_snapshot"` -> `data.monitoring_duration_minutes` (event created 2433-2442, queued 2444) versus `type: "resource_monitoring_summary"` -> `data.monitoring_duration_seconds` (created 2532-2541, priority-queued 2542 from `stop_monitoring`, itself called at 5700). The same summary dict is also embedded as `data.resource_summary` in the `comprehensive_final_report` event (5969-5970 -> 5988-5998), giving a second read path. On any host up longer than the scan, `monitoring_duration_minutes * 60` will exceed `monitoring_duration_seconds` by roughly the host's uptime. Cross-check against `uptime` on the endpoint over SSH — the minutes value should match uptime, not scan wall time. Note the wire field is `type`, not `log_type` (`StandardLogEntry.to_dict`, 1042).
- **Source:** ``SystemResourceMonitor.__init__` line 2240 `self.system_boot_time = psutil.boot_time()` (only other use of the attribute is 2423); `_upload_resource_data` (def 2413) line 2423 `'monitoring_duration_minutes': (time.time() - self.system_boot_time) / 60` inside `enhanced_data`, uploaded as `log_type='system_resource_snapshot'` (create at 2433-2442, queue at 2444); `get_resource_summary` (def 2491) line 2501 `'monitoring_duration_seconds': len(self.resource_history) * self.monitoring_interval`, uploaded as `log_type='resource_monitoring_summary'` (create 2532-2541, priority queue 2542); `monitoring_interval = 10` at 2224, `upload_interval = 45` at 2225, `resource_history = deque(maxlen=360)` at 2232; monitor constructed only under `config.enable_resource_monitoring` at 5726-5727 and stopped at 5699-5700`

### Light-profile priority tuning: outer failure emits a message with no data payload

At startup the scanner renices itself (Windows: `BELOW_NORMAL_PRIORITY_CLASS`; POSIX: `nice = max(current, 10)`; Linux additionally `ionice` best-effort 7) so user activity wins on a busy machine. There are two distinct failure shapes, and only one is queryable. Per-mechanism failures are caught inside and reported as `cpu_priority_error` / `io_priority_error` keys in the success message's `details` dict. But if anything before or around them throws — most plausibly `psutil.Process()` at 902 — the outer handler at 928 emits a completely different message, `Could not apply light profile process priority tuning: <err>`, with NO data argument at all. Because `StandardLogEntry` only sets `self.data` when `data` is truthy (1036-1037) and `to_dict` only emits the key when the attribute exists (1057-1058), the wire event has no `data` field whatsoever — not even an empty object. So on that path there is no structured field to filter on: the reason exists only inside the free-text message, and none of the `*_priority_error` keys are present. The function returns None either way (932), so the caller at 6040 cannot tell tuning failed.

- **Control:** Not configurable — `_apply_light_process_priority(log_manager)` is called unconditionally in `main()` (def 6025) at line 6040, immediately after the LogManager is built at 6039. It is the function's only call site in the file. There is no flag, env var, or profile switch guarding it. — default `-`
- **Observe:** `<scanner_dir>/logs/system_<run_id>.log` — the tuning line is effectively the second line of the file (the first is `Enhanced Log Manager initialized with standardized logging`, emitted from `LogManager.__init__` at 1806). Success: `Applied light profile process priority tuning` (emitted at 927), whose accompanying `details` dict carries `cpu_priority` / `io_priority` and, on partial failure, `cpu_priority_error` / `io_priority_error`. Outer failure: `Could not apply light profile process priority tuning: <err>` (emitted at 930) and no data key at all. Both also reach the collector as `type: "system"` events via `log_system` (2022-2024) -> `_log_with_webhook` (1901-1931) — the wire field is `type`, not `log_type` (to_dict at 1042) — so on the wire you must match on the message text; filtering on `cpu_priority_error` will never surface the outer failure. Independently verifiable on the endpoint with `ps -o nice -p <pid>` (POSIX) or the process priority class in Task Manager (Windows).
- **Source:** ``_apply_light_process_priority` defined at 898, `details = {}` at 900, `psutil.Process()` at 902; inner Windows handler 904-909 (`cpu_priority_error` at 909); inner POSIX nice handler 910-917 (`cpu_priority_error` at 917); inner Linux ionice handler 919-924 (`io_priority_error` at 924); success emission `if log_manager:` 926 with the `log_system(..., details)` call at 927; outer `except Exception as e:` at 928 emitting the payload-less message at 929-930; `return None` at 932. Sole call site: `main()` (def 6025) line 6040, LogManager built at 6039. `LogType.SYSTEM` file path built at 1785, logger built by `_setup_logger` 1808-1838 with a real `logging.FileHandler` at 1819-1823 and `propagate = False` at 1832 (so this is not affected by `setup_logging` pinning the root logger to WARNING at 5908-5911). `data` omission mechanics: 1036-1037 and 1057-1058.`

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
- **Observe:** That glob returns seven files, not six: the six LogManager category logs (alerts_, statistics_, scan_errors_, performance_, uploads_, system_) plus yara_processing_<run_id>.log, which matches the same pattern; and eight when an exception was logged, since script_exceptions_<run_id>.log is created lazily and matches too.
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
- **Observe:** Rewrite Observe to: "With COLLECT_MATCHED_FILES=false, grep <scanner_dir>/logs/system_<run_id>.log for the exact line `Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only (paths + SHA256 + alert texts, no matched file copies)` (emitted at 4007-4010, structured field collect_matched_files=false). The `unzip -l` half of the check - archive contains alerts/ and file_mapping.txt but no matched_files/ members - still applies." Note the sink is system_<run_id>.log, not diagnostics_<run_id>.log.
- **Source:** `COLLECT_MATCHED_FILES; EvidenceCollector._create_evidence_zip (copy_files branch)`

### Content-addressed dedupe of packaged matched files

When file copying is on, each matched file is stored under its SHA256 as the archive name (matched_files/<sha256>), so N paths holding identical bytes collapse to one blob. A hash is only marked packaged after a successful write, so a path that vanished mid-scan does not block a same-content sibling. This is correctness, not just size: zipfile only warns on a duplicate arcname and writes the member anyway, so readers could otherwise only ever see the first copy.

- **Control:** not configurable (active whenever COLLECT_MATCHED_FILES is on) — default `always on when copying`
- **Observe:** Rewrite Observe to: "On a run with duplicate matched content, grep <scanner_dir>/logs/system_<run_id>.log for `Evidence ZIP: N unique file(s) packaged, M duplicate copy(ies) skipped` (4020-4024; structured fields unique_files_packaged / duplicate_copies_skipped). Absence of the line means zero duplicates were seen, not that dedupe is off - it is gated on duplicates_skipped at 4019 - so keep the bare-hex `matched_files/<sha256>` arcnames plus entry-count-vs-file_mapping.txt comparison as the zero-duplicate check. `Error adding file to zip ...` (4005) is logging.error and now lands in both stderr and diagnostics_<run_id>.log."
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

**⚠ OBSERVABILITY GAP**  
On Windows the cleanup script is registered as a one-shot scheduled task running as SYSTEM, one minute in the future, force-overwriting any existing task of the same name.

- **Control:** not configurable (schtasks /create /tn CleanupScript /tr <cleanup_script> /sc once /st <now+1min> /ru SYSTEM /f) — default `task name "CleanupScript", /sc once, /ru SYSTEM, /f`
- **Observe:** Rewrite Observe to: "On Windows, grep <scanner_dir>/logs/diagnostics_<run_id>.log for `Windows cleanup task scheduled for HH:MM` (logging.info at 4264, emitted after the schtasks /create at 4256-4263). `schtasks /query /tn CleanupScript` and the system_<run_id>.log line `Windows cleanup task scheduled successfully` (4197) remain the corroborating checks."
- **Source:** `CleanupManager._schedule_windows_cleanup`

### Linux systemd cleanup unit (yara-cleanup.service)  <sub>linux (this branch is also taken on macOS — see the macOS entry)</sub>

On non-Windows the scanner writes a systemd unit to /etc/systemd/system/yara-cleanup.service (Type=oneshot, User=root, ExecStart=/bin/bash <cleanup_script>, WantedBy=multi-user.target), verifies the file exists and is root-owned, then daemon-reload / enable / start. Because it is enabled with an [Install] section, this leaves a persistent, boot-activated unit on the host, not just a one-shot.

- **Control:** not configurable (service_path hardcoded to /etc/systemd/system/yara-cleanup.service) — default `unit name yara-cleanup.service; enabled and started immediately`
- **Observe:** `systemctl status yara-cleanup.service` and `systemctl is-enabled yara-cleanup.service` on the endpoint after a matching scan; `cat /etc/systemd/system/yara-cleanup.service` shows the generated unit with ExecStart=/bin/bash /opt/yara_scanner/cleanup_script.sh. Root logger prints `Linux cleanup service created and started`; system_<run_id>.log records `Linux cleanup service scheduled successfully`.
- **Source:** `CleanupManager._schedule_linux_cleanup`

### macOS has no working scheduled-cleanup path  <sub>macos</sub>

schedule_final_cleanup branches only on `platform.system() == "Windows"` versus everything else, so on Darwin it calls _schedule_linux_cleanup — which writes a systemd unit to /etc/systemd/system and shells out to systemctl. On macOS this fails; the exception is logged and re-raised, then caught by main()'s wrapper so the scan still returns its result line. Consequence: on macOS the .txt -> .alert rotation never happens, and cleanup_script.sh is still written and chmod'ed 0755.

- **Control:** not configurable — default `n/a — behaviour of the else-branch`
- **Observe:** scan_errors_<run_id>.log carries `Error scheduling cleanup: <err>` (from main()). The `Failed to schedule cleanup: <err>` line never fires — it sits inside the dead `hasattr(self.config, 'log_manager')` guard in schedule_final_cleanup, and ScanConfig is never given a log_manager attribute; the same except also emits `Error scheduling final cleanup: <err>` via the root logger, which surfaces on stderr only.
- **Source:** `CleanupManager.schedule_final_cleanup (`if platform.system() == "Windows": ... else: self._schedule_linux_cleanup()`)`

### Cleanup scheduling is suppressed on critical errors or zero alerts

Two live suppressors only: (1) `error_logger.has_errors and error_logger.valid_rules_count == 0`, checked both in main() before the call and again inside schedule_final_cleanup; (2) `_check_for_alerts()` finding no .txt file in alert_dir. The third documented trigger, error-log ratio > 0.5, is unreachable: it sits behind `hasattr(self.config, 'log_manager')`, and ScanConfig is never given a log_manager attribute anywhere in the file.

- **Control:** not configurable (error_ratio threshold 0.5 hardcoded) — default `error_ratio > 0.5 or (has_errors and valid_rules_count == 0) => skip; empty alert dir => skip`
- **Observe:** Run a ruleset that compiles but matches nothing: alert/ stays empty, so logs/system_<run_id>.log gets 'No alerts found, skipping cleanup scheduling' and no task/unit is created. The critical-error branch is reachable only through the >50% error-ratio test, not through failed rules — a pack where every rule fails aborts before any cleanup code runs, so neither quoted line appears.
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

### End-of-run "COMPREHENSIVE STATISTICS SUMMARY" block in statistics_<run_id>.log

**⚠ CONTROL GAP**  
Every run writes a fixed summary block near the end of logs/statistics_<run_id>.log: peak/avg CPU and memory, the scan_estimates dict, and a per-worker files_processed / avg_processing_time_ms / error_rate_percent table, all pretty-printed JSON. The surprising part is that the CPU/memory half is normally meaningless - the perf monitor is OFF by default, so no snapshots are ever collected and the block still prints peak_cpu_percent/avg_cpu_percent/peak_memory_mb/avg_memory_mb as 0.0 with samples_collected 0, which reads like "the scan consumed nothing" rather than "nothing was measured". The same defect hits one Time Estimates field: scan_estimates['average_rate'] is computed from performance_history (1693-1699) and so also stays 0.0, while current_rate/eta_seconds/total_files_estimate are real. The per-worker table IS real regardless - update_worker_stats runs in scan_file's finally, so it fires for every file that reaches scan_file, including permission-denied and error paths. The block is written straight to the statistics file logger, bypassing LogManager.log_statistics()/_log_with_webhook (1937-1939), so this formatted block and the per-worker breakdown exist only on the endpoint disk, and only for the last 2 runs (log retention prunes older run_ids). Note it is NOT true that the numbers never reach the tenant: get_current_stats_for_upload() ships performance_metrics, scan_estimates, worker_count and total_worker_files inside the comprehensive_final_report and scan_completion_summary events - what the tenant never sees is the per-worker table (only the two aggregate worker counts) and the formatted text.

- **Control:** ENABLE_PERF_MONITOR = _env_bool("YARA_ENABLE_PERF_MONITOR", False) (line 201, surfaced as config.enable_performance_monitoring at line 2779) governs only whether the CPU/memory numbers (and average_rate) are real, not whether the block is written. The block itself is Not configurable - verified by grep: log_comprehensive_stats has exactly one definition (1701) and one call site (1757), inside stop_monitoring, with no flag around it. Retention of the file is _prune_old_scan_logs(keep_scans=2) (def 3965, called 4045 from initial_cleanup); because initial_cleanup runs at 6046 after LogManager already created this run's file at 6039, the kept set is the current run plus one prior run. The file's directory is relocatable via YARA_SCANNER_DIR (2675-2684) but that does not affect whether the block is emitted. — default `Block always written, once per StatisticsManager instance (the _stopped guard at 1750-1752 prevents a second copy); CPU/memory fields 0.0, samples_collected 0, and average_rate 0.0 because ENABLE_PERF_MONITOR defaults to False`
- **Observe:** On the endpoint, read the per-run stats log: <scanner_dir>/logs/statistics_<run_id>.log, where scanner_dir is /opt/yara_scanner on Linux, /usr/local/yara_scanner on macOS, C:\yara_scanner on Windows (2678-2684), unless YARA_SCANNER_DIR overrides it; logs_dir at 2686. Look for the literal line `COMPREHENSIVE STATISTICS SUMMARY` between two `====` rules, followed by `Performance Metrics: {...}`, `Time Estimates: {...}`, `Worker Summary: {...}`. Corroborate that the perf monitor was off by the earlier line `Performance monitoring disabled in light profile` in the same file (emitted at 1538). The logger is a named logger set to INFO with its own FileHandler and propagate=False (1811-1832), so setup_logging's root-WARNING pin (5911) does not suppress it - this IS observable. The file is opened mode="w" and named per run_id, so it is per-run, not cumulative. The block is not in scan_summary_<run_id>.json (that record, 2146-2158 + 6597-6617, carries no worker or CPU/memory fields) and the block text is not sent over the webhook - reachable only via SSH/file collection, not the Action Center result. The underlying aggregates ARE visible tenant-side, under data.performance_summary of the comprehensive_final_report event and data.performance_metrics of the scan_completion_summary event, but with worker_count/total_worker_files only, no per-worker rows.
- **Source:** `StatisticsManager.log_comprehensive_stats (1701-1728; header string at 1723, perf_summary at 1704-1710 including samples_collected from len(self.performance_history), worker_summary at 1712-1720, three json.dumps(..., indent=2) emits at 1725-1727). Called unconditionally by stop_monitoring (def 1748) at 1757, guarded to run once by the self._stopped check at 1750-1752. stop_monitoring has two real call sites, both reached in normal operation: YaraScanner cleanup at 5701 (after resource_monitor.stop_monitoring() at 5699-5700, inside a try that logs any failure at 5702-5703), and main()'s finally at 6564-6565, which runs on every exit path including fatal failure and before log_manager.stop_logging() at 6625 closes the handler. __del__ (1761-1766) calls stop_monitoring again but is a no-op backstop in practice given the finally block. Worker counters come from update_worker_stats (def 1657, body 1659-1672), invoked in scan_file's finally at 4998-5000 (scan_file def at 4850). Zeroed metrics path: start_monitoring returns early at 1537-1539 when enable_performance_monitoring is False, leaving performance_history empty and performance_metrics at its 0.0 init (1478-1484); scan_estimates['average_rate'] likewise never set because 1693 requires len(performance_history) > 1. Log destination: LogType.STATISTICS -> statistics_<run_id>.log (1781), file handler with mode="w" and propagate=False (1819-1832), logger level INFO at 1812; stats_logger bound at 1492 (falls back to the root logger at 1495 only when log_manager is None, which does not happen on the main path - 6042 passes it). Webhook-bearing alternative that this block bypasses: LogManager.log_statistics -> _log_with_webhook (1937-1939). Tenant-side exposure of the same numbers: get_current_stats_for_upload (1730-1746) -> final_report_data['performance_summary'] (5964-5966) uploaded at 5987-5998, and comprehensive_final_stats['performance_metrics'] (6313, 6325) uploaded at 6349-6359.`

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

**⚠ OBSERVABILITY GAP**  
WebhookUploader (telemetry/logs uploader) is guarded by a CircuitBreaker: after N consecutive failures it opens, and while open every batch is put back on the queue untouched followed by a 2 s sleep — no POST is attempted and no counters move. After the reset timeout it goes half_open and lets exactly one batch probe; failure re-opens it, success closes it. Counting happens AFTER the allow() check specifically so re-queued events are not counted repeatedly (an earlier bug showed total=31/failed=6 when nothing had landed). Note: the match channel (ResultsUploader) has NO circuit breaker — it retries per batch only.

- **Control:** CIRCUIT_FAILURE_THRESHOLD, CIRCUIT_RESET_TIMEOUT_SECS — not env-overridable. — default `CIRCUIT_FAILURE_THRESHOLD = 5, CIRCUIT_RESET_TIMEOUT_SECS = 40`
- **Observe:** UNOBSERVABLE: With a dead collector, telemetry POSTs stop entirely for ~40 s windows while the queue grows; the per-type `total` in WebhookUploader.get_upload_statistics() (and scan_summary's telemetry_delivery) stays flat during an open window rather than inflating, and undelivered rises at shutdown. To close it: Minimal instrumentation: in CircuitBreaker.on_failure (1202-1210), emit on the two transitions into 'open' (after 1207 and after 1210) `logging.warning(f"Telemetry circuit opened after {self.consecutive_failures} consecutive failures; pausing uploads for {self.reset_timeout}s")`, and in allow() (1188-1189) log the half-open probe — both now land in diagnostics_<run_id>.log; optionally add a `circuit_opens` counter to WebhookUploader.upload_stats so it surfaces in the upload statistics summary. Then rewrite Observe to induce it with a rejected-but-reachable collector (wrong API key → non-2xx outside 408/429/5xx, hitting line 3765) rather than a dead one, and state explicitly that an unreachable collector does NOT open the circuit. Separately flag as a design question — not an observability fix — whether the ConnectionError/Timeout branch at 3767 should call on_failure() once MAX_RETRIES_PER_ITEM (=2, line 157) is exhausted.
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
- **Observe:** <scanner_dir>/alert/<rule>.txt
- **Source:** `ResultsUploader.add_match() (`_match_id_counts`, `'match_ids': json.dumps(_match_id_counts)`); YaraScanner._write_alerts() id_counts block`

### yara_match event payload shape (incl. dashboard-flattened aliases)

The findings event is type="yara_match", message "YARA match: rule 'R' in F (N string hit(s))" (or "YARA rule-only match: …"), with data carrying: filename, rule, the flattened dashboard aliases file_name and rule_id, threat_level, string (first rendered hit), offset (first offset), match_scope, match_count, offsets, strings, match_ids, truncated, string_match_count (raw YARA string-instance count), dateOfScan (uploader construction time, UTC ISO), file_sha256, file_creation_time.

- **Control:** threat_level comes from the alert_severity entry-point argument via config.alert_severity (validated low\|medium\|high by _parse_alert_severity). — default `alert_severity = "low"`
- **Observe:** XQL on type="yara_match": every listed field must be non-null for a string match; file_name/rule_id must mirror filename/rule (the "Yara Matches" dashboard queries only the flattened names). dateOfScan is identical across every finding of one run.
- **Source:** `ResultsUploader.add_match() data dict; _parse_alert_severity(); _render_match_data()`

### Condition-only match representation

A rule that fires on its condition with no string instances still produces a finding: the empty match list is replaced by a single synthetic entry carrying a human-readable condition summary, match_scope is "rule" instead of "string", offset is "" and the message says "YARA rule-only match".

- **Control:** Not configurable. — default `Fallback text "Condition-only YARA match; no string instances were produced." when no summary could be derived`
- **Observe:** <scanner_dir>/alert/<rule>.txt
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

Two checkpoints in fixed order — phase='initialization' first (main(), line 6255) and phase='scan_configuration' second (scan_system(), line 5759), milliseconds apart. Both share the single 'statistics' rate-limit key (60 s), so in practice only the initialization checkpoint ships and scan_configuration is suppressed on essentially every run, not just fast ones.

- **Control:** WebhookUploader.upload_intervals dict; not env-overridable. — default `Only `statistics: 60` is ever applied. upload_intervals also holds performance 30, system_resource 45, worker_stats 120 and time_estimates 60, but no code path ever passes those keys — `_should_upload` has exactly one caller, `upload_statistics_summary`, which passes the literal 'statistics' (and `_mark_uploaded` likewise). The other four entries are inert.`
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

Emitted only on a NON-ROOT non-Windows scan — the event block is nested inside `if not is_root:`. A root Linux/macOS run emits zero privilege_status rows, so in practice data.running_as_root is always false, recommended_action is always 'run_as_sudo', level is always WARNING, and data.platform is hardcoded 'linux' even on macOS.

- **Control:** Emitted only on non-Windows AND only when the process is not root: the create_standard_log call is nested inside `if platform.system() != "Windows":` (line 6066) → `if not is_root:` (line 6087) → `if webhook_uploader:` (line 6102). A sudo/root Linux or macOS scan emits zero privilege_status rows. — default `recommended_action is always 'run_as_sudo' and running_as_root is always false; level is always WARNING. The `else 'none'` / `else "INFO"` branches are dead code because the event is only constructed on the non-root path.`
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
- **Source:** `Three live drain sites: LogManager.stop_logging(), ResultsUploader.stop() and WebhookUploader.stop_uploader(), each calling _compute_drain_budget(initial_queue_size). ResultsUploader.upload_results() also contains a copy of the drain loop but has no callers anywhere in the file, so its `Waiting for N pending uploads (max Ms)...` line can never appear.`

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
- **Observe:** No files are scanned, but events ARE produced and queued: ScanConfig, LogManager (which logs and, whenever API_ENDPOINT is non-empty, starts its webhook thread and uploads `Enhanced Log Manager initialized with standardized logging`), StatisticsManager, WebhookUploader and CleanupManager are all constructed and started first; `Initial cleanup completed` is logged as a system event, and the abort itself is logged via `log_manager.log_error(abort_msg)`, which writes scan_errors_<run_id>.log and queues an error-type event. main() then returns the `SCAN ABORTED - ...` string and the finally block still runs stop_logging(), draining that queue.
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
- **Observe:** <scanner_dir>/alert/<rule>.txt
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

**⚠ OBSERVABILITY GAP**  
Two module-level switches gate delivery: UPLOAD_RESULTS gates everything (with it False the placeholder-credential abort is also skipped, giving a genuinely local-only scan), and UPLOAD_NON_MATCH_DATA gates telemetry/log/status events only, leaving findings uploading. A missing/empty API_ENDPOINT independently prevents any uploader thread from starting.

- **Control:** UPLOAD_RESULTS, UPLOAD_NON_MATCH_DATA — plain module constants, no env override. — default `Both True`
- **Observe:** UNOBSERVABLE: scanner_initialization data.upload_enabled and data.telemetry_upload_enabled echo the two flags. With UPLOAD_RESULTS False, uploads_<run_id>.log ends with "Upload disabled - N matches saved locally"; with API_ENDPOINT empty it logs "API_ENDPOINT not configured - real-time match upload disabled". To close it: Minimal instrumentation for the live half: give ResultsUploader.__init__ a `log_manager=None` parameter (3174) and set `self.log_manager = log_manager` before the `if UPLOAD_RESULTS: self._start_upload_thread()` at 3208-3209, then pass it at the construction site (line 4353 -> `ResultsUploader(config, log_manager=self.log_manager)`) and drop the now-redundant assignment at 4360; lines 3232/3236/3242 then land in uploads_<run_id>.log. Cheaper alternative that needs no wiring: change those three calls to `logging.info(...)`, which now reaches diagnostics_<run_id>.log. Separately, the dead method ResultsUploader.upload_results (3501-3559) — including the 'Upload disabled' line at 3557 — is safe to delete; do not cite it as evidence. The scanner_initialization upload_enabled/telemetry_upload_enabled half of the entry stays as-is.
- **Source:** `UPLOAD_RESULTS, UPLOAD_NON_MATCH_DATA, ResultsUploader._start_upload_thread(), LogManager.__init__ / _log_with_webhook(), WebhookUploader.__init__, ScanStatusUploader.upload_scan_status()`

### Queue-full handling on the findings channel

Queueing a finding uses a 1.0 s put timeout; if the queue cannot accept it the finding's network representation is dropped with an explicit log line rather than blocking the scan thread. The queues themselves are unbounded Queue() instances, so this fires only under pathological conditions — but the drop is logged, never silent.

- **Control:** Not configurable (put timeout=1.0). — default `Unbounded Queue(); 1.0 s put timeout on the match channel, 1.0 s (0.1 s when priority=True) on the telemetry channel`
- **Observe:** There is no bounded findings queue — ResultsUploader.upload_queue (3194) and WebhookUploader.upload_queue (3653) are both unbounded, so the message 'Upload queue full - skipping real-time upload for finding' (3493) cannot be produced by queue pressure and its expected count on any healthy scan is zero; it fires only if event serialization throws. Observe queue backlog instead through the drain-time lines in ResultsUploader.stop(): 'Waiting for N pending match uploads (max Ms)...' (3357) and the leftover/undelivered accounting at 3378-3388." Also reword the message at 3493 to name its real cause (e.g. 'Failed to queue finding for upload (serialization error) - skipping real-time upload').
- **Source:** `ResultsUploader.add_match() (`self.upload_queue.put(standard_log, timeout=1.0)` / except branch), WebhookUploader._queue_standard_upload()`

### Host identity (hostname / os_info / ipAddress) stamped on every uploaded event

Every event, the scan summary JSON and the evidence file_mapping header carry a host identity derived once at ScanConfig construction (line 2672): `socket.gethostname()`, a human OS string, and IPs from `socket.getaddrinfo(hostname)` with entries starting `127.` dropped and duplicates removed. Three things to know. (1) The macOS name comes from a hardcoded Darwin-major table with only four entries — 24/23/22/21 -> Sequoia/Sonoma/Ventura/Monterey; any other kernel falls through to the literal `macOS (Darwin <release>)`, so a future macOS silently reports an unnamed string. (2) Only the IPv4 loopback prefix is filtered — `::1` is NOT dropped, so a host whose name resolves to IPv6 loopback first can ship `ipAddress: "::1"` on every row. (3) On resolver failure the IP list is not empty — it becomes a one-element list holding the sentence `Unable to determine IP address: <err>`, and because consumers take `ip_addresses[0]`, that whole English sentence becomes the `ipAddress` value on every row for the run. Note the raw list is not confined to the evidence file: it also rides the wire in `scanner_initialization` (`data.ip_addresses`, line 6184) and in `comprehensive_final_report` (`data.scan_metadata.ip_addresses`, line 5923).

- **Control:** Not configurable — `get_os_info()` line 308, mac_names table lines 316-321, `get_system_info()` line 331, `127.` filter line 340, failure sentinel line 344. Consumers read `config.ip_addresses[0]` (lines 1452, 1776, 2221, 3110, 3499, 3572, 5992, 6107, 6138, 6230, 6353, 6527). — default `-`
- **Observe:** `scan_summary_<run_id>.json` in `<scanner_dir>/logs` carries `hostname`, `os_info`, `ip_address` (record built at lines 2147-2157, fields 2153-2155; written from the finally block at line 6597 so it survives failure and cancellation); `evidence/file_mapping.txt` opens with `Host Information: / Hostname: / OS: / IP Addresses:` (lines 3879-3882); on the wire every StandardLogEntry has top-level `hostname`, `os_info`, `ipAddress` (assigned 1023-1025, serialized 1043-1045). To see the failure path, break name resolution for the local hostname and confirm `ipAddress` literally equals `Unable to determine IP address: ...`.
- **Source:** ``get_os_info()` 308-328; `get_system_info()` 331-344; `StandardLogEntry.__init__` 1019-1037 and `to_dict` 1039-1050; `ScanConfig.__init__` 2672; `LogManager.write_scan_summary` 2132-2173; `EvidenceCollector._process_matched_files` 3876-3886; raw-list uploads 5923, 6184`

### Second, non-canonical scan_id inside the "Scan configuration established" payload

The `scan_config_data` dict carries its own `scan_id` built as `<hostname>_<YYYYmmdd_HHMMSS>` — no microseconds and no rule-hash suffix — while the envelope `scan_id` on every row of the run is `<hostname>_<YYYYmmdd_HHMMSS_ffffff>_yara_<rulehash12>` (`run_id` is the bare timestamp, line 2673; the hostname and `_yara_<hash12>` are added at 2744). Any consumer joining on this inner `scan_id` gets a value that matches nothing else in the run, and two scans started in the same second on one host collide on it. The dict is shipped TWICE, not once: `log_statistics("Scan configuration established", scan_config_data)` at 5758 both writes it to the statistics log and (via `_log_with_webhook`) uploads it as a `statistics` event where the bad id sits at `data.scan_id`; the `upload_statistics_summary` call at 5759-5762 wraps the same dict and uploads it as a `statistics_summary` event where it sits at `data.data.scan_id` under `data.phase == 'scan_configuration'`.

- **Control:** Not configurable — hardcoded at line 5748 (`scan_config_data['scan_id']`). The canonical form is `ScanConfig.scan_id`, line 2744, built from `self.hostname`, `run_id` (line 2673) and the rule SHA-256 prefix (`yara_hash[:12]`, hash computed 2736). The `statistics_summary` copy additionally passes through `_should_upload('statistics')` (line 3714, interval 60s at 3593) — at scan start `last_upload_by_type` defaults to 0.0 so the first call always passes. — default `-`
- **Observe:** On the wire: two events. (a) `type == 'statistics'` with `message == 'Scan configuration established'` — compare `data.scan_id` against the row's envelope `scan_id`. (b) `type == 'statistics_summary'` with `data.phase == 'scan_configuration'` — compare `data.data.scan_id` against the envelope. Locally the same dict is written into `statistics_<run_id>.log` by the 5758 call, so one run shows both id forms in one file.
- **Source:** ``scan_system()` lines 5747-5762 (dict built 5747-5756, logged+uploaded 5758-5762); canonical `self.scan_id` line 2744; `run_id` line 2673; `_should_upload` 3731-3740`

### Uncapped per-rule detection breakdown in comprehensive_final_report

The terminal `comprehensive_final_report` event ships `detection_results.detection_breakdown` as the full `dict(scanner.detection_counts)` — one key per rule that fired, no cap — right next to `top_10_rules`, which is the same data truncated to 10. A ruleset where hundreds of rules trigger makes this one event's payload grow without bound. Its local twin in `_log_final_results` is capped (`top_10_detections`, slice at 5414), and the fatal-failure event caps `failure_reasons` at 20 (6280) — but capping is not universal in this file: the same `_log_final_results` uploads the FULL `failure_reasons` list on a failed run (5407) and the full `skip_breakdown` (5429), and `write_scan_summary` writes the full list again (6599). `skip_breakdown` inside this report (5934) is likewise uncapped but bounded by the fixed set of skip reasons. Note the event is not emitted at all on a fatal-failure run — that path returns at 6304 before `upload_final_comprehensive_report` is reached (6361).

- **Control:** Not configurable — `detection_breakdown` line 5941, uncapped; `top_10_rules` slice `[:10]` lines 5942-5943; local twin `top_10_detections` slice `[:10]` line 5414 (emitted 5421); `failure_reasons` slice `[:20]` line 6280; uncapped siblings at 5407, 5429, 6599. — default `-`
- **Observe:** On the wire: event `log_type == 'comprehensive_final_report'` (created 5988-5997) — compare `data.detection_results.detection_breakdown` key count against `data.detection_results.unique_rules_triggered`; they are equal by construction (5940 vs 5941). Locally the identical dict is written to `statistics_<run_id>.log` by `log_statistics("COMPREHENSIVE SCAN REPORT \| ...")` (lines 6001-6004), while `alerts_<run_id>.log` (path 1780) shows only the 10-key `top_10_detections` — and only when `total_detections > 0` (guard 5412).
- **Source:** ``upload_final_comprehensive_report()` lines 5938-5945, 5987-5998; `_log_final_results()` (def 5382) lines 5404-5423, 5425-5430; failure_data lines 6278-6284; summary JSON 6599`

### efficiency_score formula (what the 0-100 number in the final report actually means)

**⚠ OBSERVABILITY GAP**  
`efficiency_score` is named in the terminal event's payload and message and in the statistics completion line, but it is a fixed two-term penalty with no relation to detections, speed or errors: start at 100, subtract `(files_skipped / files_processed) * 20`, subtract `(failed_rules / total_rules) * 30`, then floor at 0. The theoretical minimum is therefore 50 and the `max(0, ...)` floor at 5985 can never bind. A scan that skipped every file and compiled every rule scores 80; a perfectly clean scan of zero files scores 100 (both penalty branches are guarded on a non-zero denominator, 5977 and 5981). It is not a health score and should not be alerted on as one. Minor wart: the payload field is the floored value (5985) while the message and log lines format the pre-floor variable (5994, 6002) — identical in practice since the value cannot go below 50.

- **Control:** Not configurable — computed inline at lines 5976-5985 (`efficiency_score = 100` at 5976; skip penalty 5977-5979; rule-failure penalty 5981-5983; `max(0, ...)` stored at 5985). Its inputs come from `total_files_skipped`/`total_files_processed` (5932-5933) and `failed_rules_skipped`/`total_rules_processed` (5949-5950), which read `scanner.files_skipped`/`files_scanned` and `config.error_logger`'s rule counters. — default `100 (when no files are skipped and no rules fail)`
- **Observe:** On the wire: `comprehensive_final_report` event, top-level `data.efficiency_score`, with the value also formatted into the event `message` as `Comprehensive scan report - Efficiency Score: N/100` (line 5994). Locally: the `COMPREHENSIVE SCAN REPORT \| Efficiency Score: N/100` line in `statistics_<run_id>.log` (6001-6004). The third mention, `logging.info(...)` at line 6006, is UNOBSERVABLE — `setup_logging` pins the root logger to WARNING (5911), so that line reaches nothing. Assertable: recompute from `data.file_processing` and `data.rule_compilation` in the same payload.
- **Source:** ``upload_final_comprehensive_report()` lines 5976-5998, inputs 5930-5953; root-logger pin 5907-5911`

### Critical-path events post single-object JSON, not NDJSON — the only non-NDJSON body the collector sees

`LogManager._log_critical` bypasses the batching queue and does a synchronous `requests.post(json=standard_log.to_dict(), headers={'Content-Type': 'application/json'})` — one JSON object, one request. This is literally the only other `requests.post` in the file: the sole other call site is inside `_post_ndjson` (line 736), which sends `Content-Type: text/plain` with an NDJSON body. So if a collector-side HTTP Log Collector, proxy or WAF is configured or filtered on the NDJSON/text-plain body shape, these events are the ones that break, and they break differently from everything else. Scope correction: only two call sites exist — `log_performance_critical` for worker-thread startup (5773, once per scan) and `log_statistics_critical` for "Target scan completed: <target>" (5869, once per scan TARGET, so N per run) — not "scan started / target completed" as the docstring at 1946-1949 suggests. The fallback is not free of duplicates: on an exception (e.g. a read timeout after the server already wrote the row) it logs the ambiguity and re-queues, so the event can land twice. If there is no live queue to fall back to, the drop IS counted and logged (1988-2000).

- **Control:** Gated by `UPLOAD_RESULTS` (line 109, default True), `UPLOAD_NON_MATCH_DATA` (line 110, default True) and `API_ENDPOINT` (line 193) at line 1955; request timeout `DEFAULT_TIMEOUT_SECS` (line 111, default 20). None of the three gates is an env var — they are module constants an editor overwrites in place. The body format is hardcoded at lines 1964-1969. — default `Enabled whenever uploads are on; timeout 20s`
- **Observe:** On the wire: a lone JSON object with `Content-Type: application/json` arriving out of band from the `text/plain` NDJSON batches. Locally, in `uploads_<run_id>.log` (path 1784): on a non-2xx, `Critical log immediate send failed (HTTP <code>): ... - falling back to async queue` (1973-1976); on an exception, `Critical log immediate send raised <ExcType>: ... - falling back to async queue (may deliver a duplicate if the request actually landed)` (1983-1986); if the fallback itself fails or no thread exists, `Critical log dropped for <type>: ...` plus a `failed_uploads` increment (1992-2000). A clean success writes no line — only `upload_stats['successful_uploads']` increments (1971), surfacing later in the upload statistics block.
- **Source:** ``LogManager._log_critical` lines 1941-2000 (gate 1955, entry built 1958-1962, post 1964-1969, success 1970-1972, HTTP-fail log 1973-1976, exception log 1977-1986, fallback 1988-2000); `log_statistics_critical` 2002-2004, `log_performance_critical` 2006-2008; call sites 5773, 5869; contrast `_post_ndjson` 734-741 (text/plain) used at 1888 and 3679`

### LogManager's telemetry books over-count: total_logs increments before the upload gate

**⚠ OBSERVABILITY GAP**  
In `_log_with_webhook` the counter `upload_stats['total_logs']` (and the per-type counter) is incremented at 1913, BEFORE the gate at 1916-1917 that decides whether the event is uploaded at all. That gate excludes, permanently, every `LogType.UPLOAD` line (the whole uploads log is local-only by design) and everything logged while uploads are off or before/after the webhook thread is alive. All of it still counts in `total_logs`, so the delivery books over-report: `total_logs` is a count of local log lines, not of events handed to the wire, and must not be compared against rows received. Correction to the drafted claim about a silent drop path: the construction+`put` block is closed by a bare `except Exception: pass` (1930-1931), but neither of its two statements can realistically raise — `create_standard_log` (1064-1066) only assigns attributes and does no serialization (JSON encoding happens later in `_ndjson_body`, 724-731, inside `_upload_standard_batch`'s try where failure IS counted and logged at 1897-1899), and `webhook_queue = Queue()` is unbounded (1792) so `put(..., timeout=1.0)` cannot raise Full. That except is defensive, effectively unreachable code — not an active drop path. The same shape appears on the standard-upload channel (`WebhookUploader._queue_standard_upload`, bare except at 3709-3710, also an unbounded Queue at 3575); only `ResultsUploader.add_match` logs anything on that branch (3415).

- **Control:** Not configurable — counter at 1913, gate at 1916-1917 (`UPLOAD_RESULTS`, `UPLOAD_NON_MATCH_DATA`, `API_ENDPOINT`, a live webhook thread, and `log_type != LogType.UPLOAD`), bare `except Exception: pass` at 1930-1931. The webhook thread is started only if the same three constants are truthy (1803-1804). — default `-`
- **Observe:** Observable: run with `API_ENDPOINT` left at its placeholder (or with the webhook thread not started) and compare the final upload-statistics block's `total_logs` against `successful_uploads + failed_uploads` — the gap is the count of events that were never eligible for upload. The `by_type` map (1799, incremented 1914) makes the `upload` category's contribution explicit: those rows can never be sent. UNOBSERVABLE by artefact: a drop at 1930-1931 would leave no log line, no stat and a normal-looking local category log — but no realistic trigger for it exists, so the practical risk is the accounting, not lost events. To harden, the except would need a `dropped` counter plus a line in `uploads_<run_id>.log`, matching the `Upload queue full - skipping real-time upload for finding` line that only the findings path emits (3415).
- **Source:** ``LogManager._log_with_webhook` lines 1901-1931 (counters 1913-1914, gate 1916-1917, entry 1919-1928, put 1929, silent except 1930-1931); `webhook_queue = Queue()` 1792; stats init 1795-1800; thread gate 1803-1804; `create_standard_log` 1064-1066; `_ndjson_body` 724-731 and counted failure 1897-1899; contrast `ResultsUploader.add_match` 3413-3415 and `WebhookUploader._queue_standard_upload` 3700-3710`

### Circuit-open batches go to the TAIL of the upload queue (telemetry reordering and re-bounce)

When the circuit breaker is open, `WebhookUploader._process_standard_batch` does not drop or park the batch — it re-`put`s every item at the BACK of the same `upload_queue` and sleeps 2.0s. Two consequences a consumer must expect: (1) events arrive at the collector out of emission order, so ordering telemetry by arrival is wrong during and after any outage window — sort by the event `timestamp`/`timestamp_iso` field instead; (2) the same batch can cycle through repeated open windows, and each re-queue is intentionally NOT counted — the per-type `total` increment happens after the circuit check (3670-3671), with the in-code comment recording why (an earlier version counted every bounce, so an operator read total=31/failed=6 as "25 landed" when none had). The re-`put` is wrapped in a bare `except: pass` (3665-3666), but `upload_queue = Queue()` is unbounded (3575) so `put(..., timeout=1.0)` cannot raise Full — silent loss there is theoretical, not a live path. Circuit semantics: `on_failure` opens after N consecutive failures, `allow()` flips to half_open once `reset_timeout` has elapsed, and a failure while half_open re-opens immediately.

- **Control:** `CIRCUIT_FAILURE_THRESHOLD` line 128 (default 5 consecutive failures to open); `CIRCUIT_RESET_TIMEOUT_SECS` line 129 (default 40s before probing again) — both consumed as `CircuitBreaker.__init__` defaults (class at 1110). The 2.0s settle sleep is hardcoded at line 3667; `MAX_RETRIES_PER_ITEM` line 112 (default 2) caps the send attempts once the circuit allows (loop 3676), with retryable HTTP codes 408/429/500/502/503/504 backing off at 3684-3686. — default `open after 5 consecutive failures; 40s open window; 2.0s per re-queue cycle; 2 send attempts per batch`
- **Observe:** On the wire: during an induced collector outage, event arrival order for a single `scan_id` diverges from the `timestamp` field ordering. Locally there is almost nothing: the open-circuit path writes NO line, and the only failure line this method produces is `Webhook unexpected error for batch: ...` (3693), which goes through `log_manager.log_error` into `scan_errors_<run_id>.log` — NOT the uploads log. On a plain non-2xx or on retry exhaustion this method logs nothing at all. The only `uploads_<run_id>.log` lines WebhookUploader emits are `WebhookUploader initialized and started` (3601) and the worker start/stop lines (3615, 3643). The counted effect is visible in the final `upload_summary` block (`get_upload_statistics`, 3746): per-type `total` counts stay flat while a batch bounces, then jump once when it is finally attempted.
- **Source:** ``WebhookUploader._process_standard_batch` lines 3645-3698 (circuit check + tail re-queue + sleep 3661-3668; counting after the check 3670-3671; retry loop 3676-3694; final accounting 3696-3698); `upload_queue = Queue()` 3575; `CircuitBreaker` 1110-1146; constants 112, 128-129`

### file_creation_time is null on most Linux filesystems (platform-asymmetric derivation)

`_get_file_creation_time_iso()` is best-effort and platform-dependent: on Windows it returns `st_ctime`, elsewhere it returns `st_birthtime` only if the stat result exposes it (macOS does; most Linux filesystems via CPython do not). There is no `else` branch after the birthtime check, so the function falls off the end and returns None implicitly — on a typical Linux endpoint the field is null on every finding. The null propagates identically to the local and remote artefacts: the alert text writes the `File Creation Time:` line only `if file_creation_time` (5183-5184), so the line is simply absent on Linux; the `yara_match` upload payload carries `file_creation_time: null` (3404); and the per-file `alert` event carries it both at `data.file_creation_time` (4947) and inside each entry of `data.detections` (built at 5161). On Windows the value is also not a true birth time — `st_ctime` is the metadata-change time, so it moves when the file is renamed or its permissions change.

- **Control:** Not configurable — `_get_file_creation_time_iso()` lines 881-895 (try 886, stat 887, Windows branch 889-890, `st_birthtime` branch 892-893, implicit None fallthrough after 893, `except: return None` 894-895). Grep confirms no env var or flag touches it. — default `None on Linux (typical); ISO-8601 UTC string on Windows and macOS`
- **Observe:** In `alert/<rule>.txt`: presence or absence of the `File Creation Time: <iso>` line (written 5184, guarded 5183). On the wire: `file_creation_time` in the `yara_match` finding payload (3404) and in the `alert` event payload (4947, plus each `detections[]` entry from 5161). Cross-platform assertion: the same file scanned on `thor` (Windows) yields a value; on `xsoar` (Ubuntu 20.04/ext4) the field is null and the alert-text line is missing. Note the value is computed only when a file actually matches — `_get_file_creation_time_iso` is called inside the `if matches:` branch of `scan_file` (4922-4923), not for every scanned file.
- **Source:** ``_get_file_creation_time_iso()` lines 881-895; call site `scan_file` (def 4850) line 4923, inside the `if matches:` branch at 4922; `_write_alerts` (def 5136) lines 5161, 5172, 5183-5184; `ResultsUploader.add_match` signature 3327 and payload 3404; alert event 4947`

### Per-finding "Queued finding for upload" receipt in the uploads log (only local view of the truncated flag)

A finding that is successfully queued for upload writes one confirmation line to the uploads log: `Queued finding for upload: rule='<rule>', file=<file>, hits=<n>` with ` (truncated)` appended when the offset sample was capped. This is the per-finding delivery receipt — it proves the event was handed to the queue, distinct from the `Added N local result entries for rule '<rule>' in file: <file> (1 upload item, X of N sampled)` line that follows (3417-3421) and reports local bookkeeping. Important scope correction: the receipt is NOT unconditional. The whole queue-and-receipt block is gated at 3370 on `UPLOAD_RESULTS and self.upload_thread and self.upload_thread.is_alive()` and again on `self.log_manager` (3408), so with uploads off or the thread dead only the "Added N local result entries" line appears. The `Upload queue full - skipping real-time upload for finding` fallback (3413-3415) is a misnomer: `upload_queue = Queue()` is unbounded (3116), so `put(..., timeout=1.0)` cannot raise Full — that line can only fire on some other, effectively unreachable exception. The receipt is also the only place the `truncated` boolean surfaces as a flag locally: the alert text never prints the word, it renders an omission sentence instead (`N further offset(s) omitted (YARA_MAX_ALERT_OFFSETS=...)`), governed by a different constant.

- **Control:** `truncated` is set by `MAX_MATCH_SAMPLES_PER_FINDING` — line 118, `_env_number("YARA_MAX_MATCH_SAMPLES", 50, cast=int, minimum=1)` — via the sample cap at 3364 and `truncated = match_count > len(_offsets_sample)` at 3368. The receipt line is at 3409-3412, inside the success branch at 3370-3412. The alert-text omission note is governed by `MAX_ALERT_OFFSETS_PER_FINDING` — lines 291-292, `_env_number("YARA_MAX_ALERT_OFFSETS", 50, cast=int)` floored at 0, where 0 means "no cap" (the opposite of the other knob's 0) — applied at 5201-5202 and rendered at 5212-5217. Both default to 50, so on a default profile the two thresholds coincide; they diverge only when one env var is overridden. — default `50 sampled offsets per finding; `truncated` false below that`
- **Observe:** `logs/uploads_<run_id>.log` (path built at 1784; note LogType.UPLOAD is excluded from webhook upload by the gate at 1916-1917, so this log is local-only): one `Queued finding for upload: rule='X', file=Y, hits=N` line per successfully queued finding, with ` (truncated)` when hits > 50. Cross-check against the wire: the `yara_match` event's `data.truncated` for the same rule/file must agree, and `data.offsets` — which is a JSON-ENCODED STRING (`json.dumps(_offsets_sample)`, line 3397), not an array — must decode to exactly 50 entries when it is true.
- **Source:** ``ResultsUploader.add_match` lines 3327-3421 (sampling cap 3364, appends 3365-3366, `truncated` 3368, upload gate 3370, payload flag 3400, offsets JSON string 3397, receipt 3408-3412, fallback 3413-3415, local-entries line 3417-3421); `upload_queue = Queue()` 3116; constants 118 and 291-292; log file path 1784; alert-text cap 5201-5202 and omission note 5212-5217`

### performance_summary / performance_metrics blocks in the two terminal events

Both terminal events carry a performance block sourced from the same `StatisticsManager.get_current_stats_for_upload()` call, under two different key names: `comprehensive_final_report` gets `data.performance_summary` (5966), `scan_completion_summary` gets `data.performance_metrics` (6325). The block contains a nested `performance_metrics` dict plus `scan_estimates`, `current_performance`, `worker_count`, `total_worker_files` — and it duplicates the host identity (`hostname`, `os_info`, `ipAddress`, 1736-1738) and a stray `log_type: 'statistics'` (1740) already present on the envelope. Two traps: (1) the CPU/memory numbers are written only by `_update_performance_metrics` (1620-1634), which is called only from the performance-monitoring thread, and that thread is OFF by default (`YARA_ENABLE_PERF_MONITOR` defaults False, enforced at 1537) — so `peak_cpu_percent`, `avg_cpu_percent`, `peak_memory_mb`, `avg_memory_mb` are all 0.0 and `current_performance` is null on a default run (the history deque is only appended to by that same thread); (2) `io_efficiency` is initialised to 0.0 at 1483 and appears nowhere else in the file — it is always 0.0, monitoring on or off. Correction: `performance_summary` is NOT meaningfully conditional — its `hasattr(scanner, 'stats_manager')` guard at 5964 can never fail, because `YaraScanner.__init__` always assigns `self.stats_manager` (4223). Both events are skipped entirely on a fatal-failure run (early return at 6304).

- **Control:** `ENABLE_PERF_MONITOR` line 201 — `_env_bool("YARA_ENABLE_PERF_MONITOR", False)`, surfaced as `config.enable_performance_monitoring` (2779) and enforced in `StatisticsManager.start_monitoring()` (1537, which logs "Performance monitoring disabled in light profile" and returns). The two key names are hardcoded: `performance_summary` 5966, `performance_metrics` 6325. — default `YARA_ENABLE_PERF_MONITOR=false — CPU/memory fields all 0.0, current_performance null; io_efficiency always 0.0`
- **Observe:** On the wire: `data.performance_summary` on the `comprehensive_final_report` event (created 5988-5997) and `data.performance_metrics` on the `scan_completion_summary` event (log_type set at 6350). Locally the identical dicts land in `statistics_<run_id>.log` — under `COMPREHENSIVE SCAN REPORT \| ...` (6001-6004) and `SCAN COMPLETED SUCCESSFULLY in ...` / `SCAN CANCELLED BY OPERATOR after ...` (6363-6367). Assertable: with the default profile, `performance_summary.performance_metrics.peak_cpu_percent == 0.0` and `performance_summary.current_performance is null`; set YARA_ENABLE_PERF_MONITOR=true and they become non-zero, but `io_efficiency` stays 0.0 either way. A confirming local signal that monitoring is off: the `Performance monitoring disabled in light profile` line in `statistics_<run_id>.log` (1538).
- **Source:** ``StatisticsManager.get_current_stats_for_upload()` lines 1730-1746; `performance_metrics` init 1478-1484 (io_efficiency 1483, sole occurrence in the file); writers `_update_performance_metrics` 1620-1634 via `_monitoring_worker` 1545-1566; `upload_final_comprehensive_report` 5964-5966; `comprehensive_final_stats` 6313, 6317-6333 (performance_metrics 6325) and event 6349-6359; gates 201, 1537, 2779; `self.stats_manager` always set at 4223`

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
- **Observe:** Rewrite Observe to: "logs/diagnostics_<run_id>.log carries one `Scan status changed to: <value>` line per transition (emitted at line 3638). Grep it for the ordered sequence initializing -> starting_workers -> scanning -> finishing -> completed (or the terminal cancelled/failed/error/interrupted) and check the last such line matches the SCAN_RESULT outcome. This local trail is unconditional; the uploaded scan_status events remain a second, optional channel gated on UPLOAD_RESULTS + UPLOAD_NON_MATCH_DATA + a non-empty API_ENDPOINT + webhook_uploader wired on by main()."
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
- **Observe:** Rewrite Observe to: "Instrumented, but not a live-scan criterion. When it fires, grep <scanner_dir>/logs/scan_errors_<run_id>.log for `Worker <thread-name> fatal error: <exc>` (log_manager.log_error at 4868-4869), followed by `Scan stopped due to fatal failures` (6451), scan_status 'failed' (6462) and outcome='failed' in scan_summary_<run_id>.json (6764). It cannot be provoked by file content - scan_file's blanket handler (5093-5099) and _worker's inner handler (4862-4866) absorb everything from the loop body; only a failure inside the inner handler itself (stderr write 4864 / log_error 4865) escapes to 4867. Verify it by fault injection in a unit harness, not on a scan." No code change required; do not delete the handler - it is the only net under the inner one.
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
- **Observe:** Action Center path only: main() gets the bad value, ScanConfig raises inside main()'s try, and the result line reads 'Scan failed: 0 files scanned \| ... \| Critical error occurred' (exit 1). On the CLI path nothing is printed on stdout at all — the parse happens outside main(), so stderr gets 'Critical startup error: Invalid alert_severity ...' plus the full traceback and the process exits 1 with no SCAN_RESULT: line.
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

**⚠ OBSERVABILITY GAP**  
Rules the agent's libyara cannot run (missing module) are counted in error_logger.skipped_rules_count rather than failed_rules_count, and published on the error logger so main() can surface them; without it a pack whose rules mostly never ran reads as a clean '0 rules failed compilation'.

- **Control:** not configurable — default `skipped_rules_count = 0`
- **Observe:** That line never reaches any file — it is a bare `logging.info` on the root logger, which setup_logging strips of handlers and pins at WARNING, so it is dropped entirely (no file, no console). What yara_processing_<run_id>.log actually carries is the COMPILATION SUMMARY block (total / valid / failed / success rate — no skipped count) plus, when skipped_count > 0, the error_logger line `Skipped N rules due to unavailable modules`.
- **Source:** `ErrorLogger.skipped_rules_count; `error_logger.skipped_rules_count = skipped_count` in _compile_yara_rules(); main()'s _skipped_txt`

### Privilege detection and privilege_status telemetry  <sub>linux, macos (skipped on Windows); note the event's data.platform is hardcoded 'linux' even on macOS</sub>

Privilege is detected on every non-Windows run (log_system lines for root and non-root alike), but the privilege_status telemetry event is emitted only when NOT root — it is built inside `if not is_root:`. Root runs produce the local log lines and no privilege_status event at all, so the shipped event always carries running_as_root=false, recommended_action='run_as_sudo', level WARNING and platform 'linux'.

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

### `cancel` as the first CLI argument (cancel keyword dispatch)

Passing `cancel` as the first positional argument delivers a cooperative cancel to a scan already running on this endpoint instead of starting a new one — the CLI twin of the zero-input `cancel()` Action Center entry point. The comparison is case-insensitive and whitespace-stripped, so `Cancel`, `CANCEL`, and ` cancel ` all hit it; a rules file argument that is literally the bare word `cancel` can therefore never be scanned (a path such as `cancel.yar` or `./cancel` is unaffected). The branch is taken before any config/logging/rule machinery is built, so this path writes nothing under logs/ — only `<scanner_dir>/control/cancel.flag`. The exit-code guard carries a third failure prefix, `cancel failed`, that exists solely to serve this branch (the only two returns of that string in the whole file are inside `_handle_cancel_request`, at 778 and 801), so a cancel that cannot create the control dir or write the flag exits 1 rather than 0.

- **Control:** The keyword itself is not configurable — the literal `"cancel"` compared at line 6648, and the `cancel failed` exit-code arm is the literal at line 6672. The DIRECTORY it targets IS configurable: `_default_scanner_dir()` honours the `YARA_SCANNER_DIR` env var before falling back to the platform default (751-753). The `scanner running: yes/no` verdict this path reports is governed by RUNNING_MARKER_STALE_SECS = 180.0 (line 168), compared against `updated_at` in control/running.json (789-790). — default `- (absent or any other argv[1] falls through to `main(yarafile, scan_folder, alert_severity)` at 6651-6655)`
- **Observe:** Run `python3 xsiam_yara_scanner.py cancel`. Two artefacts: (a) stdout carries `SCAN_RESULT: Cancel signal delivered (<scanner_dir>/control/cancel.flag) \| scanner running: yes\|no \| scan_id=<id>` (string built 803-806, printed at 6663), or on failure `SCAN_RESULT: Cancel failed: ...` with exit code 1; (b) the file `<scanner_dir>/control/cancel.flag` appears on disk containing `{"requested_at_ms": ..., "source": "action_center"}` (written at 794-799). scanner_dir is `$YARA_SCANNER_DIR` if set, else `C:\yara_scanner` / `/usr/local/yara_scanner` / `/opt/yara_scanner` per `_default_scanner_dir()` (749-758). Negative check: no `*_<run_id>.log` and no `scan_summary_<run_id>.json` are created by this path — logs/ is untouched (ScanConfig/LogManager are never constructed). On the scan side, the cancelled run's `scan_summary_<run_id>.json` shows `"outcome": "cancelled"` (derived 6578-6579, written 6597-6617).
- **Source:** ``__main__` argv parsing at 6637-6644; the dispatch comment at 6646-6647 with `if (yarafile_arg or "").strip().lower() == "cancel":` at 6648 and `result = cancel()` at 6649, `else:` at 6650 with `main(...)` at 6651-6655; `print("SCAN_RESULT: " + result_text)` at 6663; the exit-code guard at 6668-6674 with `_rt.startswith("cancel failed")` at 6672; `cancel()` at 6014-6022 delegating to `_handle_cancel_request()` at 761-806 (makedirs 776, failure return 778, running-marker check 785-792, flag write 794-799, failure return 801, success string 803-806); `_default_scanner_dir()` at 749-758 (env override 751-753); RUNNING_MARKER_STALE_SECS at 168.`

### Critical-error handler prints the Python traceback to STDOUT before the result line

When main() dies with an unhandled exception, the handler does not just log it — it writes `CRITICAL ERROR: Critical scanner error: <msg>`, `Error details: <full traceback.format_exc()>` and `Process failed with critical error` to **stdout** (in addition to a similar block on stderr, which also carries `SCAN_STATUS: ERROR`) and then sleeps 2 seconds before returning its `Scan failed: ...` summary. Because the `SCAN_RESULT:` line is printed only after main() returns (at 6663), an Action Center result stream (or a piped CI run) carries a full multi-line Python traceback ahead of the single result line, which breaks any consumer that assumes the output's first/only line is parseable, and leaks absolute endpoint paths and internal frames into the console result field. The unconditional 2s sleep is added to every crashed run.

- **Control:** Not configurable — `sys.stdout.write` calls hard-coded at 6492-6494 and the literal `time.sleep(2)` at 6497. No verbosity or quiet flag gates them (no env read or config attribute appears anywhere in the handler at 6483-6560). — default `- (always on; the sleep is a fixed 2 seconds)`
- **Observe:** Force an exception in main() and read the process stdout: three literal lines appear before the result — `CRITICAL ERROR: Critical scanner error: <msg>`, `Error details: Traceback (most recent call last): ...`, `Process failed with critical error` — followed by `SCAN_RESULT: Scan failed: <n> files scanned \| <n> rules failed compilation \| <n> matches found \| Critical error occurred` (built at 6556-6558, returned 6560, printed at 6663), exit code 1 via the `scan failed` prefix arm at 6670. Corroborating artefacts: `scan_errors_<run_id>.log` gains a `CRITICAL_ERROR: ...` line (log_manager.log_error at 6499-6503 -> `_log_with_webhook` 1901-1911 -> LogType.ERROR file mapped at 1782), and if `scanner` had bound (only at 6238), `scan_summary_<run_id>.json` shows `"outcome": "failed"` with `"failure_reasons": ["Critical scanner error: <ExcType>"]` (marked at 6549-6554, outcome derived 6580-6581, written 6597-6599). A `scan_completion_summary` webhook event with `status: critical_error` is also queued at priority (6521-6537) — queued only, and `_queue_standard_upload` (3700-3710) drops it outright if UPLOAD_NON_MATCH_DATA is False, so actual delivery depends on the uploader draining at shutdown.
- **Source:** ``except Exception as e:` at 6483 with `error_msg` at 6484; stderr block 6486-6490 (including `SCAN_STATUS: ERROR` at 6489); the stdout writes at 6492-6494 plus `sys.stdout.flush()` at 6495; `time.sleep(2)` at 6497; log_manager error at 6499-6503; webhook event 6521-6537 (`_queue_standard_upload(..., priority=True)` at 6537, impl 3700-3710); failure-reason marking at 6549-6554; `error_summary` at 6556-6558 returned at 6560; finally-block summary write 6576-6617; `print("SCAN_RESULT: " + result_text)` at 6663; exit arm `_rt.startswith("scan failed")` at 6670.`

### Placeholder-credential abort still wipes alert/, evidence/ and old run logs first — and writes no scan summary

**⚠ CONTROL GAP**  
The "SCAN ABORTED - XSIAM HTTP Collector credentials are not set" guard fires late, not early. By the time it runs, LogManager, StatisticsManager and WebhookUploader have all been constructed, LogManager's webhook thread and WebhookUploader's upload thread have both started inside `__init__` (each gated on `UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT`, all true with shipped defaults), and `cleanup_manager.initial_cleanup()` has already `shutil.rmtree`'d the alert/ and evidence/ directories (recreating them empty) and pruned the logs of every run older than the two newest run_ids. So the message "Nothing was scanned" is true, but the run is not side-effect-free: the previous run's alerts, evidence ZIPs and older logs are gone. Separately, because `scanner` is only ever assigned at 6238 — far past the abort — the finally block's `'scanner' in locals()` guard is False and **no `scan_summary_<run_id>.json` is written at all**: the one machine-readable per-run artefact is missing exactly on the misconfiguration path an operator would most want to inspect programmatically. (StatisticsManager's monitoring thread is the exception: it does NOT start by default — `start_monitoring` returns immediately unless `config.enable_performance_monitoring` is set, and that comes from ENABLE_PERF_MONITOR, default False.)

- **Control:** UPLOAD_RESULTS (line 109) gates whether the abort fires at all — with it False, placeholder creds are accepted and the run proceeds local-only. What counts as a placeholder is _PLACEHOLDER_API_KEY = "http_collector_key" (186) and _PLACEHOLDER_API_ENDPOINT = "http_collector_api" (187), matched against API_KEY / API_ENDPOINT (192-193). Those globals are NOT env-overridable: ScanConfig.__init__ unconditionally reassigns `API_KEY = DEFAULT_API_KEY` / `API_ENDPOINT = DEFAULT_API_ENDPOINT` at 2709-2711, so only editing DEFAULT_API_KEY / DEFAULT_API_ENDPOINT (189-190) clears the abort. Retention on the destructive pre-step is `_prune_old_scan_logs(keep_scans=2)` (4045, impl 3965-4014). The ordering itself is not configurable. — default `UPLOAD_RESULTS = True and the shipped DEFAULT_* values are the placeholders, so an unedited script always takes this path`
- **Observe:** Run the unedited script. `SCAN_RESULT: SCAN ABORTED - XSIAM HTTP Collector credentials are not set. ...` on stdout, exit code 1 (the `scan aborted` prefix arm at 6671). On disk under scanner_dir: `logs/scan_errors_<run_id>.log` contains that same abort text (logged at 6063), a full set of `alerts_/statistics_/scan_errors_/performance_/uploads_/system_<run_id>.log` files exists (paths mapped in LogManager.__init__ at 1779-1786, files truncated/created by `_setup_logger`'s FileHandler with mode="w" at 1819-1823), `alert/` and `evidence/` exist and are **empty** (rmtree at 4034, recreated at 4041-4043), and — the decisive check — `logs/scan_summary_<run_id>.json` is **absent**. Compare `ls logs/` before and after to see runs older than the two newest run_ids pruned away.
- **Source:** `main() at 6025; constructors at 6039-6044 (`LogManager` 6039, `StatisticsManager` 6042, `WebhookUploader` 6043, `CleanupManager` 6044); `cleanup_manager.initial_cleanup()` at 6046; the credential check and abort at 6053-6064 (`_ep_bad`/`_key_bad` 6055-6056, `if UPLOAD_RESULTS and (...)` 6057, `log_manager.log_error(abort_msg)` 6063, `return abort_msg` 6064). Thread starts: LogManager `_start_webhook_thread()` called at 1803-1804 under `if UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT:` (impl 1840-1844); WebhookUploader `_start_upload_thread()` called at 3599-3601 under the same guard (impl 3603-3606); StatisticsManager `self.start_monitoring()` at 1528-1529 (impl 1535-1543, early-return gate at 1537-1539; ENABLE_PERF_MONITOR default False at 201, assigned to config at 2779). `CleanupManager.initial_cleanup` at 4016-4054 — `paths_to_clean` = alert_dir/evidence_dir/output_log at 4021-4025, `shutil.rmtree` at 4034, dirs recreated 4041-4043, prune at 4045; `_prune_old_scan_logs` at 3965-4014 (keep set 3988-3991). `run_id` is a per-run timestamp at 2673; `output_log` = logs/scanner_<run_id>.log at 2751. `scanner = YaraScanner(...)` at 6238 (the only assignment). Finally-block guard `if log_manager and config is not None and 'scanner' in locals() and scanner is not None:` at 6576 (comment 6571-6575), `write_scan_summary` at 2132 (path built at 2146).`

### One failing scan target is abandoned mid-walk; the rest of the scan continues and still reports success

Inside scan_system's per-target loop, an exception raised while processing a target is caught per target, logged as one line, and the loop `continue`s to the next target. The run does not fail: `_mark_scan_failed` is never called on this path (that only happens for an exception escaping the whole loop), so the final result line still reads `Scan completed: ...` and the summary JSON still says `outcome: completed`. The abandoned target is also not added to `excluded_targets` by this handler, so it does not appear in the result line's "targets EXCLUDED by the skip list" warning either. Note what this handler does NOT cover: filesystem errors during the walk itself — PermissionError, FileNotFoundError, NotADirectoryError and any other OSError — are swallowed one directory at a time inside `_walk_cancellable` (5594-5597, bare `continue`), so an unreadable or vanished subtree never reaches this handler, produces no error line at all, and still logs `Target scan completed` with a silently short file count. The per-target handler therefore fires only for exceptions raised by the loop body — the log_manager calls, `_is_special_file`, `_should_skip_junction`, `_enqueue_scan_path`, or an unexpected non-OSError out of the generator. Either way coverage silently shrinks while the scan reports clean.

- **Control:** Not configurable — bare `except Exception` / `continue` at 5879-5881, no retry count, no fail-fast flag, no threshold; the swallow-and-continue inside the walk at 5594-5597 is likewise unguarded by any knob. — default `- (always on; every target is isolated this way)`
- **Observe:** Three-way check on one run. (1) `logs/scan_errors_<run_id>.log` contains `Error scanning target <path>: <exception>` (log_error 2010-2012 -> `_log_with_webhook` 1901-1911 -> LogType.ERROR file, mapped at 1782). (2) `logs/statistics_<run_id>.log` contains `Target scan completed: <target>` for every other target but **not** for that one — this is the load-bearing negative, and it holds only for this handler's exceptions, not for walk-level OS errors, which still reach the success path; the same event also goes on the wire as a `statistics` webhook log with data `{target, files_found, scan_time_seconds, files_per_second}` via log_statistics_critical -> `_log_critical`, which attempts a synchronous POST first and falls back to the async queue (the local file line at 1951 is written unconditionally, before any upload gate). (3) Despite the gap, `logs/scan_summary_<run_id>.json` shows `"outcome": "completed"` with an empty `failure_reasons`, and stdout's `SCAN_RESULT:` line begins `Scan completed:`. Note the per-target file count for the failed target is lost entirely — `files_per_target[target]` is only assigned after a successful walk (5867); both it and `total_files_found` are passed to `_perform_enhanced_cleanup` (5891) and neither is referenced anywhere in that method's body, so both parameters are write-only.
- **Source:** `Per-target loop `for target_idx, target in enumerate(targets):` at 5793, inner `try:` at 5801; success-path `files_per_target[target] = target_files_found` at 5867 and `log_statistics_critical(f"Target scan completed: {target}", ...)` at 5869-5877; the isolation arm `except Exception as e: self.log_manager.log_error(f"Error scanning target {target}: {e}"); continue` at 5879-5881. Contrast the outer handler at 5883-5887, which *does* call `self._mark_scan_failed(error_msg)` and `set_status("error")`. Walk-level error swallowing in `_walk_cancellable` at 5594-5597 (def 5554). `_perform_enhanced_cleanup(start_time, total_files_found, files_per_target)` call at 5891 (definition 5635; neither `total_files_found` nor `files_per_target` appears in the body). Error-log file mapping `LogType.ERROR -> scan_errors_<run_id>.log` at 1782; `log_error` at 2010-2012; `_log_with_webhook` at 1901-1935; `_log_critical` at 1941-2000 (local file write at 1951, sync POST 1963-1976, queue fallback 1988-1995); `log_statistics_critical` at 2002-2004; `_verb = "Scan completed"` at 6451 and the summary line at 6478-6481; summary `outcome` derivation at 6578-6583, written 6597-6617.`

---

# Control gaps — capabilities the customer cannot tune

Verified by hand against source. Most of the gaps this file originally recorded have
since been closed; they are listed as **Closed** rather than deleted, because knowing a
knob was recently added is as useful as knowing one is missing.

### Closed

| Was | Now |
|---|---|
| `YARA_THREADS` read, validated, then overwritten by `min(2, ...)` | Honoured. The cap was correct while impact control was the system-CPU pause loop; the CPU governor replaced it, so throughput is no longer welded to impact. |
| Every skip list hardcoded, no override of any kind | `YARA_EXTRA_SKIP_PATHS` — comma-separated, **additive only**, normalised to bounded `/x/` component matching. |
| Alert directory total unbounded | `YARA_ALERT_DIR_MAX_MB` (default 256, 0 = off). Degrades detail past the ceiling and keeps counts complete. |
| Retention a `keep_scans=2` method default | `YARA_LOG_KEEP` (default 10), matching the XDR edition. |
| Twin cap knobs where `0` meant opposite things | Both mean *no cap*; negatives fall back to the default instead of clamping onto "unbounded". |

### Still open

**The built-in skip entries cannot be removed.** `YARA_EXTRA_SKIP_PATHS` only adds. That
is deliberate — a replace-style knob would let one typo silently drop the Cortex agent
paths — but a site that genuinely needs to scan inside a default-skipped directory still
has no supported way to do it.

**The evidence ZIP total is still unbounded.** The alert directory now has a ceiling; the
evidence ZIP does not. It is content-addressed and defaults to metadata-only
(`COLLECT_MATCHED_FILES=False`), so the exposure is narrower, but a run with collection
enabled against a noisy ruleset has no byte budget.

**No per-run override channel.** The Action Center form carries only this script's three
declared inputs, so every knob above requires either an endpoint env var or editing a
constant before upload. The XDR edition has a ten-key `options` string that needs neither;
porting it is the largest remaining control-surface difference between the editions.

**Governor internals are fixed (deliberate).** `GAIN`, `RATIO_MAX`, `PACE_CAP_SECS` are
control-loop tuning, not policy, and the policy knobs above them are exposed.

---

# Observability status

Every entry once marked ⚠ OBSERVABILITY GAP was re-triaged against the current source.
"Unobservable" turned out to conflate three different problems with three different
fixes, which is why they are separated here rather than counted as one number.

| Outcome | Count | Meaning |
|---|---|---|
| Closed | 25 | Evidence exists. The capability was always observable once root logging had a disk sink; only the wording was stale. |
| Needs instrumentation | 9 | Runs, records nothing anywhere. Real work, listed below with what would close each. |
| Unverified-dead | 8 | Believed unreachable — **not deleted, and not safe to delete on this evidence.** See the warning below. |

## Needs instrumentation

These execute and leave no trace at any log level. Each line names the minimal
change that would make the capability assertable on a live scan.

- **Initial cleanup at scan start** — Minimal fix, no ordering change: in CleanupManager.initial_cleanup, replace the three bare calls with the manager's own channel - line 4120 -> `self._log("Starting initial cleanup of old data...")`, line 4136 -> `self._log(f"Removed: {path}")`, line 4151 -> `self._log("Initial cleanup completed successfully", {"paths_cleaned": len(paths_to_clean)})`. All three then land in logs/system_<run_id>.log, which already exists at that point (LogManager is built before CleanupManager in main). Do NOT rely on diagnostics_<run_id>.log here - setup_logging has not run yet.
- **Log/summary retention across runs** — Route it through the LogManager that CleanupManager already holds: change line 4110 to `self._log(f"Log retention applied: kept last {keep_count} scans ({len(keep_run_ids)} run IDs including current), removed {removed} files", {"keep_scans": keep_count, "run_ids_kept": len(keep_run_ids), "files_removed": removed, "files_failed": failed})` and line 4114 to `self._log(f"Log retention: {failed} files could not be removed", level="error")`. Both land in system_<run_id>.log / scan_errors_<run_id>.log, which exist before initial_cleanup runs. Moving setup_logging(config) above line 6212 in main() would also work and would fix item 44 at the same time, but it changes startup ordering; the _log route is the lower-risk minimum.
- **Governor sampling cadence (rate limit)** — Instrument _sample_governor (line 4887). Add `self._governor_sample_count = 0` beside line 4408, then immediately after line 4898 insert `self._governor_sample_count += 1` and capture the gap, e.g. `_gap = now - _prev` where `_prev = self.last_governor_sample` is read before line 4898. Add both to the payload already emitted at 4917-4920 by extending `s_` with `{'samples_taken': self._governor_sample_count, 'secs_since_last_sample': round(_gap, 3), 'sample_interval_secs': self.config.throttle_check_interval_secs}`. performance_<run_id>.log then shows sampling cadence directly and the criterion becomes "secs_since_last_sample is never below throttle_check_interval_secs (default 0.5)" - no debug build required.
- **Upload channels can be disabled independently** — Minimal instrumentation for the live half: give ResultsUploader.__init__ a `log_manager=None` parameter (3174) and set `self.log_manager = log_manager` before the `if UPLOAD_RESULTS: self._start_upload_thread()` at 3208-3209, then pass it at the construction site (line 4353 -> `ResultsUploader(config, log_manager=self.log_manager)`) and drop the now-redundant assignment at 4360; lines 3232/3236/3242 then land in uploads_<run_id>.log. Cheaper alternative that needs no wiring: change those three calls to `logging.info(...)`, which now reaches diagnostics_<run_id>.log. Separately, the dead method ResultsUploader.upload_results (3501-3559) — including the 'Upload disabled' line at 3557 — is safe to delete; do not cite it as evidence. The scanner_initialization upload_enabled/telemetry_upload_enabled half of the entry stays as-is.
- **Circuit breaker on the telemetry channel** — Minimal instrumentation: in CircuitBreaker.on_failure (1202-1210), emit on the two transitions into 'open' (after 1207 and after 1210) `logging.warning(f"Telemetry circuit opened after {self.consecutive_failures} consecutive failures; pausing uploads for {self.reset_timeout}s")`, and in allow() (1188-1189) log the half-open probe — both now land in diagnostics_<run_id>.log; optionally add a `circuit_opens` counter to WebhookUploader.upload_stats so it surfaces in the upload statistics summary. Then rewrite Observe to induce it with a rejected-but-reachable collector (wrong API key → non-2xx outside 408/429/5xx, hitting line 3765) rather than a dead one, and state explicitly that an unreachable collector does NOT open the circuit. Separately flag as a design question — not an observability fix — whether the ConnectionError/Timeout branch at 3767 should call on_failure() once MAX_RETRIES_PER_ITEM (=2, line 157) is exhausted.
- **Log/summary retention across runs** — Minimal fix, either one: (a) in CleanupManager._prune_old_scan_logs, replace the logging.info at 4110-4113 with `self._log(...)` so the same text lands in logs/system_<run_id>.log via the channel already wired at 6211/4039-4050; or (b) move `setup_logging(config)` from 6342 to immediately after `config.log_manager = log_manager` (6206), before `cleanup_manager.initial_cleanup()` at 6213 - safe because _prune_old_scan_logs preserves the current run_id (4063 regex + keep_run_ids), so the just-created diagnostics_<run_id>.log is not pruned. Until then Observe must say: verify retention by listing logs/ and counting distinct run_ids, not by grepping for the message.
- **Initial cleanup at scan start** — Minimal instrumentation: convert the three logging.info calls in CleanupManager.initial_cleanup (4120, 4136, 4151) to `self._log(...)` - the method already exists at 4039-4054 and routes to log_manager.log_system, and cleanup_manager is constructed with the real log_manager at 6211 - so they land in logs/system_<run_id>.log. Equivalent alternative: hoist `setup_logging(config)` from 6342 to just after 6206 so the diagnostics handler exists before 6213. Until one of those lands, Observe should say only `Some cleanup operations failed - continuing with scan` (stderr) and `Initial cleanup completed` (system_<run_id>.log, emitted by main() at 6214) are checkable.
- **macOS case-sensitivity probe file written to /tmp for every file that reaches the scan body** — Two minimal edits, both small. (1) Memoise and log the probe once: wrap _is_case_sensitive_fs (671) in functools.lru_cache(maxsize=1) and add, just before the Darwin `return not exists_lower` at 682, `logging.info(f"FS case-sensitivity probe: {test_file} -> case_sensitive={not exists_lower}")` (plus a logging.warning in the bare except at 683-684 naming the failure) - both then land in diagnostics_<run_id>.log via the handler at 6057-6061, and the /tmp write drops from once-per-file to once-per-run. (2) Add `"fs_case_sensitive": _is_case_sensitive_fs()` to the write_scan_summary dict in main()'s finally block (near the existing entries at 6765-6790) so the value is recorded per run. Separately note that unique_real_paths (5495) and unique_paths_scanned (5521) are hardcoded-0 telemetry while track_real_paths is False at 2854 - they should be dropped or the flag made configurable, but that is its own item.
- **File-descriptor leak sampling (skipped on every matched file, and on every skipped file)** — Rewrite Observe to state the default-off gate first (flip ENABLE_FD_MONITOR at 248 to True in the uploaded script - env vars are not settable via Action Center), then add the missing sample record: in scan_file's FD block, emit one line per sample regardless of thresholds, e.g. immediately after the reset at 5065 add `self.log_manager.log_system(f"FD sample: files_since_check={self.fd_check_interval}, current={current_fds}, delta={fd_increase}")` (move it inside the num_fds try at 5071 so current_fds is bound), and make the increment atomic by taking self.lock_counts around 5063. Also add a `fd_samples_taken` counter incremented at 5065 and surface it in write_scan_summary (dict at 6765-6790) so the sample count can be compared against files_scanned/1000 - that is what proves the matched-file and early-return skips, since a run where every file matches would otherwise show zero samples with no explanation.

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

- Unnamed-rule fallback naming
- Rule-count propagation into scan telemetry (valid/failed on scan_status)
- Scan-rate reporting item (5): scan_rate_files_per_second on scan_status
- Diagnostic-preserving cleanup suppression
- $? placeholder for a match with no string ID
- Rule-count propagation into scan telemetry (scan_status half)
- Scan-rate reporting item (5) — scan_rate on scan_status
- Dead cached-hit dict ingestion path in match-field extraction

---

# Known issues in this inventory

Raised by three independent audits of the enumeration.

**Closed:** 35 uncatalogued capabilities and 24 miscatalogued entries. Each was deduplicated across the three audits,
re-derived from source, and either folded in as a real entry or — where the audit claim
was itself wrong — refuted with the deciding line. Audit prose was not trusted as input.

### The root logger is silent — most `logging.info` evidence does not exist

**Root cause fixed; the per-entry markers below are now stale.** `setup_logging()` used
to remove every root handler and pin `WARNING`, so all 40 `logging.info(...)` calls in
this file reached nothing on any host — which is what made the capabilities below
untestable. Root now carries an INFO `FileHandler` writing to
`logs/diagnostics_<run_id>.log`, while stdout stays clean (Action Center truncates stdout
at 10,240 chars, which is why the original suppression existed).

The entries below therefore still carry ⚠ OBSERVABILITY GAP markers that no longer
apply. Re-deriving each *Observe* field against the new sink is outstanding work; until
that pass runs, treat a marked entry as "evidence exists in diagnostics_<run_id>.log,
wording not yet updated" rather than "unobservable".

Two such cases were fixed while writing this file (the evidence-ZIP dedupe and the
metadata-only packaging line, both now routed through `LogManager`). The remaining
17 are listed below — they are the single largest blocker to testing this scanner,
because each is a behaviour that works and cannot be proven to have worked.

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

---

*Generated from a source enumeration of `xsiam_yara_scanner.py`, audited for completeness,
accuracy and observability. Keep it current in the same commit that changes behaviour —
a stale capability reference is worse than none, because it is trusted.*
