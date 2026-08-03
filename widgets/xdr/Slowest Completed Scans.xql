/* Slowest Completed Scans
   List the longest-running completed scans with rate, files, and pause context for tuning investigation.
   category: perf-throughput */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | fields hostname, os_type, files_scanned, elapsed_secs, scan_rate_fps, total_paused_secs, throttle_mode | sort desc elapsed_secs | limit 20 | view graph type = table header = "Slowest Completed Scans"
