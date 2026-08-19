/* Files Scanned by OS Type
   Compare total scan throughput (files processed) across Windows, Linux, and macOS fleets.
   category: perf-throughput */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter status = "completed" | comp sum(files_scanned) as total_files by os_type | sort desc total_files | view graph type = pie subtype = donut header = "Files Scanned by OS Type" xaxis = os_type yaxis = total_files
