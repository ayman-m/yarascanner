/* Detections by OS Platform
   Segment YARA matches across Windows/Linux/macOS to reveal which platform carries the most detection load.
   category: detection-depth

   2026-08 grain change: rows are one per (rule, file) finding, not one per matched-string
   offset - hits sums match_count (the true per-finding total) instead of counting rows;
   endpoints (count_distinct) is unaffected by row grain. Dedups by (scan_id, hostname,
   rule, filename) against the narrow window where consolidation has copied a finding into
   its per-scan target but not yet removed it from the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| comp sum(to_integer(match_count)) as hits, count_distinct(hostname) as endpoints by os_type
| sort desc hits
| view graph type = pie subtype = full header = "Detections by OS Platform" xaxis = os_type yaxis = hits
