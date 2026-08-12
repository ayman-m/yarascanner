/* Unique Malicious Files per Rule
   Count distinct SHA-256 files behind each rule to separate broad-impact rules from single-file noise.
   category: detection-depth

   2026-08 grain change: rows are one per (rule, file) finding, not one per matched-string
   offset - hits sums match_count (the true per-finding total) instead of counting rows;
   unique_files (count_distinct) is unaffected by row grain. Dedups by (scan_id, hostname,
   rule, filename) against the narrow window where consolidation has copied a finding into
   its per-scan target but not yet removed it from the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp count_distinct(file_sha256) as unique_files, sum(to_integer(match_count)) as hits by rule
| sort desc unique_files
| limit 15
| view graph type = column header = "Unique Malicious Files per Rule" xaxis = rule yaxis = unique_files
