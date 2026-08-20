/* Distinct Rules Fired
   Single-value KPI of how many unique YARA rules produced at least one match.
   category: alerts-and-kpis

   2026-08 grain change: count_distinct is unaffected by row grain, so this widget only
   gained the dedup guard.

   2026-08-20 v4 grain change: rows are now one per FILE and the `rule` COLUMN no longer
   exists - every rule that hit the file lives inside `rules`, a TEXT column holding a JSON
   array of per-rule objects. count_distinct is still grain-independent, but there is no
   longer a `rule` column to count, so the array has to be expanded purely to recover the
   rule names. This is the one widget where the v4 grain costs work without changing the
   answer.

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the per-host
   source shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a
   constant - so it degenerates to (scan_id, hostname, filename), exactly a v4 row's
   identity; on a v3 row it is the full per-finding key. It must run BEFORE arrayexpand:
   after expansion many rows share (scan_id, hostname, filename), so deduping then would
   collapse the fan-out and throw away every rule but one - which for this widget would
   directly understate the KPI.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field rules"). So the if() below synthesises a one-element array from a v3
     row's own rule/match_count and expands whichever shape the row actually has. Therefore:
       - CANNOT run before the first v4 matches dataset exists (nothing defines `rules`).
       - CANNOT run once the last v3 shard is pruned (nothing defines `rule`/`match_count`);
         at that point delete the if() bridge and use `rules` directly.
       - v2 shards drop out: their match_count is null, so the synthesised JSON is malformed
         and arrayexpand discards the row. Rules that ONLY ever fired in the v2 era are
         therefore not counted here. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter rule = json_extract_scalar(rule_obj, "$.rule")
| comp count_distinct(rule) as distinct_rules
| view graph type = single header = "Rules Fired"
