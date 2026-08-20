/**************************************************************************
  Endpoints Impacted per Rule

  How many distinct endpoints each rule fired on.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  2026-08 grain change: rows became one per (rule, file) finding; count_distinct is
  unaffected by row grain, so only the dedup guard was added.

  2026-08-20 v4 grain change: rows are now one per FILE and the `rule` COLUMN no longer
  exists - every rule that hit the file lives inside `rules`, a TEXT column holding a JSON
  array of per-rule objects. count_distinct(hostname) is still unaffected by row grain, but
  the grouping key itself has to be recovered by expanding that array; there is no `rule`
  column left to group by. Expanding does not distort this metric: a file matched by two
  rules yields two rows for the same hostname, and count_distinct collapses them.

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
| comp count_distinct(hostname) as endpoints by rule
| sort desc endpoints
| limit 15

| view graph type = bar header = "Endpoints Impacted per Rule" xaxis = rule yaxis = endpoints
