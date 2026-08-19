/**************************************************************************
  Matches Over Time

  Match volume in hourly buckets. Lookup rows have no _time, so we bucket on
event_timestamp_ms (epoch ms) -> hourly timestamp.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  2026-08 grain change: rows are one per (rule, file) finding, not one per matched-string
  offset - hits sums match_count (the true per-finding total) instead of counting rows.
  Also dedups by (scan_id, hostname, rule, filename) against the narrow window where
  consolidation has copied a finding into its per-scan target but not yet removed it from
  the per-host source shard.
**************************************************************************/
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| alter bucket_ms = multiply(to_integer(divide(event_timestamp_ms, 3600000)), 3600000)
| alter ts = to_timestamp(bucket_ms, "MILLIS")
| comp sum(to_integer(match_count)) as hits by ts
| sort asc ts

| view graph type = line header = "Matches Over Time (hourly)" xaxis = ts yaxis = hits
