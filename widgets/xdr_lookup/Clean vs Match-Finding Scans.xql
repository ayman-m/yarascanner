/* Clean vs Match-Finding Scans
   Fleet-wide split of completed scans that found zero matches versus those with detections, showing the clean-fleet baseline.
   category: rule-health */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | alter outcome = if(detections > 0, "Found Matches", "Clean (Zero Matches)") | comp count() as scans by outcome | view graph type = pie subtype = full header = "Clean vs Match-Finding Scans" xaxis = outcome yaxis = scans
