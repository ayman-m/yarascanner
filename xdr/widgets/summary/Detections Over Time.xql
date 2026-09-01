/**************************************************************************
  Detections Over Time

  Detections per day, bucketed from event_timestamp_ms. Bucketing matters:
  grouping on the raw millisecond gives one point per scan-write instant and
  a chart nobody can read.

  Dataset(s): yara_scanner_summary_v4_rules_* - the SUMMARY consolidation
  target, one row per (host, rule). Four columns only: scan_id, hostname,
  rule, event_timestamp_ms. There is no file, no offset and no match count
  here; that detail lives in the FULL target and in the per-host matches
  datasets. Ask this dataset "which rules fired where", never "how much".

  Lookup rows carry no _time - time-filter on event_timestamp_ms.

  dedup scan_id, hostname, rule guards the window where a consolidation pass
  has written a row into its per-ruleset target but not yet reconciled the
  superseded one out. Without it a host re-scanned with the same ruleset
  counts twice.
**************************************************************************/
dataset = yara_scanner_summary_v4_rules_*
| dedup scan_id, hostname, rule
| alter day = format_timestamp("%Y-%m-%d", to_timestamp(to_integer(event_timestamp_ms), "MILLIS"))
| comp count() as detections by day
| sort asc day

| view graph type = line subtype = smooth header = "Detections Over Time" xaxis = day yaxis = detections
