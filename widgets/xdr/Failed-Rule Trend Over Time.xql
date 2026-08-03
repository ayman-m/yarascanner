/* Failed-Rule Trend Over Time
   Daily trend of total failed rule compilations across the fleet to catch regressions when a new rule pack ships.
   category: rule-health */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | alter bucket_ms = multiply(to_integer(divide(event_timestamp_ms, 86400000)), 86400000) | alter ts = to_timestamp(bucket_ms, "MILLIS") | comp sum(failed_rules) as failed_rules by ts | sort asc ts | view graph type = line header = "Failed-Rule Trend Over Time" xaxis = ts yaxis = failed_rules
