/**************************************************************************
  Top Rules by Hits

  Noisiest YARA rules by total match count (yara_scanner_matches).

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  2026-08 grain change: rows became one per (rule, file) finding, not one per
  matched-string offset - hits summed match_count instead of counting rows.

  2026-08-20 v4 grain change: rows are now one per FILE. The columns `rule` and
  `match_count` no longer exist. Every rule that hit the file lives inside `rules`, a TEXT
  column holding a JSON array of per-rule objects
  {rule,match_count,offsets,strings,string_ids,truncated,severity}. To group by rule the
  array must be expanded first and each rule's total read from inside its own element -
  NOT from the row. The row's match_total is the file's total across ALL its rules, so
  summing match_total per rule would multiply every file's hits by its rule_count.

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
        and arrayexpand discards the row. Unchanged from v3 behaviour.
**************************************************************************/
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter rule = json_extract_scalar(rule_obj, "$.rule")
| alter rule_hits = to_integer(json_extract_scalar(rule_obj, "$.match_count"))
| comp sum(rule_hits) as hits by rule
| sort desc hits
| limit 15

| view graph type = pie subtype = full header = "Top YARA Rules by Hits" xaxis = rule yaxis = hits
