/* Total YARA Matches
   Single-value KPI of every matched YARA string across the fleet.
   category: alerts-and-kpis

   2026-08 grain change: yara_scanner_matches rows are one per (rule, file) finding, not
   one per matched-string offset. match_count carries the true per-finding total, so this
   sums match_count instead of counting rows - counting rows would report finding count,
   not match count (orders of magnitude lower on any rule with many string-offset hits).
   Also dedups by (scan_id, hostname, rule, filename): xdr_consolidate.py copies a finding
   into its per-scan target before removing it from the per-host source shard, so a query
   across both during that window would otherwise double-count it. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp sum(to_integer(match_count)) as total_matches
| view graph type = single header = "Total Matches"
