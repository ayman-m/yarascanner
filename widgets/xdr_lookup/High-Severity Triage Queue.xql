/* High-Severity Triage Queue
   Actionable triage table of the newest High-severity matches with host, file, rule and offset for immediate hunting.
   category: detection-depth */
dataset = yara_scanner_matches* | filter severity = "High" | sort desc event_timestamp_ms | limit 25 | fields scan_date, hostname, os_type, rule, filename, file_size, offset, matched_length, file_sha256 | view graph type = table header = "High-Severity Triage Queue"
