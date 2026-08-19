/* Scan Rate Leaderboard (files/sec)
   Rank hosts by average YARA scan throughput to spot fast vs. underperforming endpoints.
   category: perf-throughput */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | comp avg(scan_rate_fps) as avg_fps by hostname | sort desc avg_fps | limit 15 | view graph type = bar header = "Scan Rate Leaderboard (files/sec)" xaxis = hostname yaxis = avg_fps
