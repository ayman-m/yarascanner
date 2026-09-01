/**************************************************************************
  Detections by Ruleset

  Which ruleset produced each detection. The ruleset hash is the last
  component of every scan_id and is the only part every host in one launch
  shares, which is why consolidation keys its targets on it.

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
| alter ruleset = arrayindex(split(scan_id, "_yara_"), 1)
| comp count() as detections by ruleset
| sort desc detections

| view graph type = pie subtype = full header = "Detections by Ruleset" xaxis = ruleset yaxis = detections
