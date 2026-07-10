/* Scan Completions Over Time
   Daily trend of scans reaching completed state, showing coverage cadence across the fleet.
   category: fleet-coverage */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | alter bucket_ms = multiply(to_integer(divide(event_timestamp_ms, 86400000)), 86400000) | alter ts = to_timestamp(bucket_ms, "MILLIS") | comp count() as completed_scans by ts | sort asc ts | view graph type = line header = "Scan Completions Over Time" xaxis = ts yaxis = completed_scans
