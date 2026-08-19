/**************************************************************************
  Endpoints Impacted per Rule

  How many distinct endpoints each rule fired on.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  Unaffected by the 2026-08 match-upload grain change (count_distinct is unaffected by row
  grain), but still dedups by (scan_id, hostname, rule, filename) as defense-in-depth
  against the narrow window where consolidation has copied a finding into its per-scan
  target but not yet removed it from the per-host source shard.
**************************************************************************/
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp count_distinct(hostname) as endpoints by rule
| sort desc endpoints
| limit 15

| view graph type = bar header = "Endpoints Impacted per Rule" xaxis = rule yaxis = endpoints
