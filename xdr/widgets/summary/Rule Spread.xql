/**************************************************************************
  Rule Spread

  Whether each rule is isolated or fleet-wide. A rule on one host is a
  candidate for triage; the same rule on every host is more often a rule
  that needs tightening than an incident that needs response.

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
| comp count_distinct(hostname) as hosts by rule
| alter spread = if(hosts > 2, "3+ hosts", if(hosts = 2, "2 hosts", "1 host"))
| comp count() as rules by spread
| sort desc rules

| view graph type = pie subtype = full header = "Rule Spread" xaxis = spread yaxis = rules
