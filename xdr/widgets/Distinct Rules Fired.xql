/* Distinct Rules Fired
   Single-value KPI of how many unique YARA rules produced at least one match.
   category: alerts-and-kpis

   Unaffected by the 2026-08 match-upload grain change (count_distinct is unaffected by row
   grain), but still dedups by (scan_id, hostname, rule, filename) as defense-in-depth
   against the narrow window where consolidation has copied a finding into its per-scan
   target but not yet removed it from the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp count_distinct(rule) as distinct_rules
| view graph type = single header = "Rules Fired"
