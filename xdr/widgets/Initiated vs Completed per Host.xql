/* Initiated vs Completed per Host
   Reconciles scans started against scans completed per host, surfacing the unfinished delta.
   category: fleet-coverage */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | alter completed_flag = if(status = "completed", 1, 0) | comp count() as scans_started, sum(completed_flag) as scans_completed by hostname | alter not_completed = subtract(scans_started, scans_completed) | sort desc not_completed | view graph type = table header = "Initiated vs Completed per Host"
