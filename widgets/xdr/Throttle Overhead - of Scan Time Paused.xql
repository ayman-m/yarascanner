/* Throttle Overhead - % of Scan Time Paused
   Surface hosts losing the most relative time to the throttle pause loop (paused/elapsed ratio).
   category: perf-throughput */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | filter elapsed_secs > 0 | alter pause_ratio_pct = multiply(divide(total_paused_secs, elapsed_secs), 100) | comp avg(pause_ratio_pct) as avg_pause_pct by hostname | sort desc avg_pause_pct | limit 15 | view graph type = column header = "Throttle Overhead - % of Scan Time Paused" xaxis = hostname yaxis = avg_pause_pct
