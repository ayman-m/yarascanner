/* Unique Malicious Files per Rule
   Count distinct SHA-256 files behind each rule to separate broad-impact rules from single-file noise.
   category: detection-depth

   2026-08 grain change: rows became one per (rule, file) finding, not one per
   matched-string offset - hits summed match_count; unique_files (count_distinct) is
   unaffected by row grain.

   2026-08-20 v4 grain change: rows are now one per FILE and the columns `rule` and
   `match_count` no longer exist - every rule that hit the file lives inside `rules`, a TEXT
   column holding a JSON array of per-rule objects. Both measures here therefore have to be
   taken AFTER expanding that array: the grouping key because there is no `rule` column
   left, and hits because the row's match_total is the file's total across ALL its rules
   (summing it per rule would multiply every file's hits by its rule_count).
   count_distinct(file_sha256) stays correct under expansion - a file matched by two rules
   contributes the same sha256 twice to one rule only if that rule matched it twice, which
   it cannot.

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the per-host
   source shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a
   constant - so the key degenerates to (scan_id, hostname, filename), which is exactly a v4
   row's identity; on a v3 row it is the full per-finding key. It must run BEFORE
   arrayexpand: after expansion many rows share (scan_id, hostname, filename), so deduping
   then would collapse the fan-out and throw away every rule but one.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field rules"). So the if() below synthesises a one-element array from a v3
     row's own rule/match_count and expands whichever shape the row actually has. Therefore:
       - This query CANNOT run before the first v4 matches dataset exists - nothing defines
         `rules` and the whole widget errors. Deploy after the first v4 scan lands.
       - This query CANNOT run once the last v3 shard is pruned - nothing defines
         `rule`/`match_count`. At that point delete the if() bridge and use `rules` directly.
       - v2 shards drop out: their match_count is null, so the synthesised JSON is malformed
         and arrayexpand discards the row. Unchanged from v3 behaviour. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter rule = json_extract_scalar(rule_obj, "$.rule")
| alter rule_hits = to_integer(json_extract_scalar(rule_obj, "$.match_count"))
| comp count_distinct(file_sha256) as unique_files, sum(rule_hits) as hits by rule
| sort desc unique_files
| limit 15
| view graph type = column header = "Unique Malicious Files per Rule" xaxis = rule yaxis = unique_files
