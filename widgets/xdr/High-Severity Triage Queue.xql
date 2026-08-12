/* High-Severity Triage Queue
   Actionable triage table of the newest High-severity matches with host, file, rule and
   match detail for immediate hunting.
   category: detection-depth

   2026-08 grain change: yara_scanner_matches rows no longer carry offset/matched_length -
   each row is now one (rule, file) finding with match_count (true total hits) and
   offsets/strings (JSON arrays, sampled up to CONFIG_LOOKUP_ROWS_PER_FINDING_MAX per
   finding) plus truncated (bool, true if the finding had more hits than the sample
   holds). Shows the raw sample fields as-is for the analyst to inspect; explode them
   further with json_extract_array() if a per-offset breakdown is needed. Also dedups by
   (scan_id, hostname, rule, filename) against the narrow window where consolidation has
   copied a finding into its per-scan target but not yet removed it from the source shard. */
dataset = yara_scanner_matches*
| filter severity = "High"
| sort desc event_timestamp_ms
| dedup scan_id, hostname, rule, filename
| limit 25
| fields scan_date, hostname, os_type, rule, filename, file_size, match_count, truncated, offsets, file_sha256
| view graph type = table header = "High-Severity Triage Queue"
