/**************************************************************************
  Hosts With Detections

  How many hosts have at least one rule hit. Compare against the fleet
  size: this counts hosts that MATCHED, not hosts that were scanned - a
  host scanned clean never appears in this dataset at all.

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
| comp count_distinct(hostname) as hosts_with_detections

| view graph type = single subtype = none header = "Hosts With Detections"
