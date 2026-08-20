/* Largest Matched Files
   Surface the biggest files that triggered a YARA hit, where bulky payloads or packed binaries often hide.
   category: detection-depth

   2026-08 grain change: rows became one per (rule, file) finding, not one per
   matched-string offset - hits summed match_count; max(file_size) is unaffected by row
   grain.

   2026-08-20 v4 grain change: rows are now one per FILE and the columns `rule` and
   `match_count` no longer exist - every rule that hit the file lives inside `rules`, a TEXT
   column holding a JSON array of per-rule objects. This table groups by (filename, rule,
   hostname), so it still needs the array expanded to recover `rule`, and each rule's hits
   read from its own element rather than from the row (the row's match_total is the file's
   total across ALL its rules, so using it here would repeat the file's whole total against
   every rule it matched). max(file_size) stays correct under expansion - every expanded row
   from a given file carries the same file_size, and max() is idempotent over duplicates.

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the per-host
   source shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a
   constant - so it degenerates to (scan_id, hostname, filename), exactly a v4 row's
   identity; on a v3 row it is the full per-finding key. It must run BEFORE arrayexpand:
   after expansion many rows share (scan_id, hostname, filename), so deduping then would
   collapse the fan-out and throw away every rule but one.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field rules"). So the if() below synthesises a one-element array from a v3
     row's own rule/match_count and expands whichever shape the row actually has. Therefore:
       - CANNOT run before the first v4 matches dataset exists (nothing defines `rules`).
       - CANNOT run once the last v3 shard is pruned (nothing defines `rule`/`match_count`);
         at that point delete the if() bridge and use `rules` directly.
       - v2 shards drop out: their match_count is null, so the synthesised JSON is malformed
         and arrayexpand discards the row. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter rule = json_extract_scalar(rule_obj, "$.rule")
| alter rule_hits = to_integer(json_extract_scalar(rule_obj, "$.match_count"))
| comp max(file_size) as bytes, sum(rule_hits) as hits by filename, rule, hostname
| sort desc bytes
| limit 20
| view graph type = table header = "Largest Matched Files"
