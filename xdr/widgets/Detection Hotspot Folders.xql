/* Detection Hotspot Folders
   Rank the scan folders where matches cluster, exposing directories that concentrate suspicious files.
   category: detection-depth

   2026-08 grain change: rows are one per (rule, file) finding, not one per matched-string
   offset - hits sums match_count (the true per-finding total) instead of counting rows;
   unique_files (count_distinct) is unaffected by row grain. Dedups by (scan_id, hostname,
   rule, filename) against the narrow window where consolidation has copied a finding into
   its per-scan target but not yet removed it from the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp sum(to_integer(match_count)) as hits, count_distinct(file_sha256) as unique_files by scan_folder
| sort desc hits
| limit 15
| view graph type = bar header = "Detection Hotspot Folders" xaxis = scan_folder yaxis = hits
