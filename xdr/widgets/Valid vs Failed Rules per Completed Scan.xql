/* Valid vs Failed Rules per Completed Scan
   Per-scan breakdown of how many rules compiled versus failed, ranked by worst failures to triage rule-pack quality.
   category: rule-health */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | alter total_rules = add(valid_rules, failed_rules) | fields hostname, scan_id, valid_rules, failed_rules, total_rules | sort desc failed_rules | limit 20 | view graph type = table header = "Valid vs Failed Rules per Completed Scan"
