/* Largest Matched Files
   Surface the biggest files that triggered a YARA hit, where bulky payloads or packed binaries often hide.
   category: detection-depth

   2026-08 grain change: rows are one per (rule, file) finding, not one per matched-string
   offset - hits sums match_count (the true per-finding total) instead of counting rows;
   max(file_size) is unaffected by row grain. Dedups by (scan_id, hostname, rule, filename)
   against the narrow window where consolidation has copied a finding into its per-scan
   target but not yet removed it from the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp max(file_size) as bytes, sum(to_integer(match_count)) as hits by filename, rule, hostname
| sort desc bytes
| limit 20
| view graph type = table header = "Largest Matched Files"
