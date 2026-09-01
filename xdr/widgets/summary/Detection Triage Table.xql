/**************************************************************************
  Detection Triage Table

  Every (host, rule) pair with the ruleset that produced it and when it
  landed. This is the working list - the other widgets summarise it.

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
| alter detected = format_timestamp("%Y-%m-%d %H:%M", to_timestamp(to_integer(event_timestamp_ms), "MILLIS"))
| fields hostname, rule, ruleset, detected
| sort desc detected
| limit 50

| view graph type = table header = "Detection Triage"
