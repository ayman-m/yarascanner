/* High-Severity Triage Queue
   Actionable triage table of the newest High-severity matches with host, file, rule and
   match detail for immediate hunting.
   category: detection-depth

   2026-08 grain change: rows stopped carrying offset/matched_length - each row became one
   (rule, file) finding with match_count (true total hits) and offsets/strings (JSON arrays,
   sampled up to CONFIG_LOOKUP_ROWS_PER_FINDING_MAX per finding) plus truncated.

   2026-08-20 v4 grain change: rows are now one per FILE, and FOUR of the columns this table
   used to select are gone. `scan_date` was dropped as derivable, so the timestamp is
   rebuilt from event_timestamp_ms. `rule`, `match_count` and `offsets` moved inside
   `rules`, a TEXT column holding a JSON array of per-rule objects, so the table expands
   that array and shows ONE ROW PER (file, rule) - which is what a triage queue wants
   anyway: an analyst works a specific rule against a specific file, not a file in the
   abstract. Two extraction details that matter if you edit this: json_extract_scalar
   returns null on a nested array, so `offsets` must come out via json_extract (which yields
   its JSON text); and `truncated` is read from the ROW, not the element, because the row's
   flag is already "true if ANY of this file's rules was capped".

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the source
   shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a constant -
   so it degenerates to (scan_id, hostname, filename), exactly a v4 row's identity; on a v3
   row it is the full per-finding key. Note it now runs BEFORE the sort/limit as well as
   before arrayexpand: deduping after expansion would collapse the per-rule fan-out and hide
   every rule but one from the analyst.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field rules"). The if() below synthesises a one-element array from a v3 row's
     own rule/match_count AND its real offsets column - so v3 findings keep their offset
     sample in this table rather than showing blank. Therefore:
       - CANNOT run before the first v4 matches dataset exists (nothing defines `rules`).
       - CANNOT run once the last v3 shard is pruned (nothing defines
         `rule`/`match_count`/`offsets`); at that point delete the if() bridge and use
         `rules` directly.
       - v2 shards drop out: their match_count is null, so the synthesised JSON is malformed
         and arrayexpand discards the row. */
dataset = yara_scanner_matches*
| filter severity = "High"
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), ",\"offsets\":", offsets, "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter rule = json_extract_scalar(rule_obj, "$.rule")
| alter rule_hits = to_integer(json_extract_scalar(rule_obj, "$.match_count"))
| alter rule_offsets = json_extract(rule_obj, "$.offsets")
| alter scan_time = to_timestamp(to_integer(event_timestamp_ms), "MILLIS")
| sort desc event_timestamp_ms
| limit 25
| fields scan_time, hostname, os_type, rule, filename, file_size, rule_hits, truncated, rule_offsets, file_sha256
| view graph type = table header = "High-Severity Triage Queue"
