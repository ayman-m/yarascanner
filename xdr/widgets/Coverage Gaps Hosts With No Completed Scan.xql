/* Coverage Gaps: Hosts With No Completed Scan
   Lists endpoints that have scan activity but never reached a completed state, flagging blind spots.
   category: fleet-coverage */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | alter completed_flag = if(status = "completed", 1, 0) | comp count() as total_scans, sum(completed_flag) as completed_scans by hostname, os_type | filter completed_scans = 0 | sort desc total_scans | view graph type = table header = "Coverage Gaps: Hosts With No Completed Scan"
