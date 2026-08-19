/******************************************************************************************
W-Perf — Scan Time in Minutes (Bubble)
Goal:
  Summarize scan-time per host (sum of partition scan times), then derive AVG/MAX/MIN in minutes
  and visualize as a packed bubble chart.

Signal:
  COMPLETE → message contains "Target scan completed:" AND data != null

Parsing (from `data` JSON):
  target_partition ← $.target
  files_found      ← $.files_found
  scan_time_seconds← $.scan_time_seconds
  files_per_second ← $.files_per_second

Method (no logic changes):
  1) Keep the latest completion per (hostname, target_partition).
  2) Sum scan_time_seconds per hostname → scan_time_by_host.
  3) Compute AVG/MAX/MIN of that sum across hosts.
  4) Convert seconds → minutes and cast to integers for display.
  5) Plot AVG/MIN/MAX as separate series in a packed bubble widget.
******************************************************************************************/
dataset = yara_scans_raw
| filter message contains "Target scan completed:" and data != null
| alter
    target_partition   = json_extract_scalar(data, "$.target"),
    files_found        = to_integer(json_extract_scalar(data, "$.files_found")),
    scan_time_seconds  = to_float(json_extract_scalar(data, "$.scan_time_seconds")),
    files_per_second   = to_float(json_extract_scalar(data, "$.files_per_second"))
| sort desc _time
| dedup hostname, target_partition
| fields
    _time,
    hostname,
    ipAddress,
    target_partition,
    files_found,
    files_per_second,
    scan_time_seconds,
    data ,
    message
| comp sum(scan_time_seconds ) as scan_time_by_host by hostname
| comp avg(scan_time_by_host ) as avg_scan_time , max(scan_time_by_host ) as max_scan_time, min(scan_time_by_host )  as min_scan_time
| alter avg_scan_time_mins = to_integer(divide(avg_scan_time, 60)), max_scan_time_mins = to_integer(divide(max_scan_time, 60)), min_scan_time_mins = to_integer(divide(min_scan_time, 60))

| view graph
    type = bubble subtype = packed
    header = "Scan Time in Minutes"
    show_callouts = `true`
    xaxis = avg_scan_time_mins
    yaxis = avg_scan_time_mins,max_scan_time_mins,min_scan_time_mins
    seriescolor("max_scan_time_mins","#ff0000")
    seriescolor("min_scan_time_mins","#1da800")
    seriescolor("avg_scan_time_mins","#009de5")
    seriestitle("avg_scan_time_mins","AVG Scan Time")
    seriestitle("max_scan_time_mins","MAX Scan Time")
    seriestitle("min_scan_time_mins","MIN Scan Time")
