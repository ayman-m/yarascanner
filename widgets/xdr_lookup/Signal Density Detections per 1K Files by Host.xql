/* Signal Density (Detections per 1K Files) by Host
   Ratio of detections to files scanned per host, exposing which endpoints yield the richest signal per unit of scan effort.
   category: rule-health */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | filter files_scanned > 0 | comp sum(detections) as detections, sum(files_scanned) as files by hostname | alter signal_density = multiply(divide(detections, files), 1000) | sort desc signal_density | limit 15 | view graph type = bar header = "Signal Density (Detections per 1K Files) by Host" xaxis = hostname yaxis = signal_density
