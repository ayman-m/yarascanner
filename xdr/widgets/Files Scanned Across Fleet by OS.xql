/* Files Scanned Across Fleet by OS
   Total files-scanned volume aggregated per os_type to gauge fleet scan workload distribution.
   category: fleet-coverage */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | comp sum(files_scanned) as files_scanned by os_type | sort desc files_scanned | view graph type = column header = "Files Scanned Across Fleet by OS" xaxis = os_type yaxis = files_scanned
