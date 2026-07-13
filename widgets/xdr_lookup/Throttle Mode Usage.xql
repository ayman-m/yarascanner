/* Throttle Mode Usage
   Show how scans are distributed across throttle modes to validate throttling policy rollout.
   category: perf-throughput */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | comp count() as scans by throttle_mode | sort desc scans | view graph type = pie subtype = full header = "Throttle Mode Usage" xaxis = throttle_mode yaxis = scans
