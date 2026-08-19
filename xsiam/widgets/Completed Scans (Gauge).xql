/******************************************************************************************
W-Perf — Completed Scans (Gauge)
Goal: Count unique hosts that reported a completed target scan in the selected timeframe.
Signal definition:
  COMPLETE → message contains "Target scan completed:" and data != null
Parsing (from `data` JSON):
  target_partition (target), files_found, scan_time_seconds, files_per_second
Method:
  - Sort by newest, dedup per hostname to keep the latest completion per host.
  - Count remaining rows → scan_completed.
Notes:
  - No logic changes—formatting & documentation only.
******************************************************************************************/
dataset = yara_scans_raw
| filter message contains "Target scan completed:" and data != null
| alter
    target_partition   = json_extract_scalar(data, "$.target"),
    files_found        = to_integer(json_extract_scalar(data, "$.files_found")),
    scan_time_seconds  = to_float(json_extract_scalar(data, "$.scan_time_seconds")),
    files_per_second   = to_float(json_extract_scalar(data, "$.files_per_second"))
| sort desc _time
| dedup hostname
| fields
    _time,
    hostname,
    ipAddress,
    target_partition,
    files_found,
    files_per_second,
    scan_time_seconds,
    message
| comp count() as scan_completed

| view graph
    type = gauge subtype = radial
    header = "Completed Scans"
    yaxis = scan_completed
    maxscalerange = 880
    scale_threshold("#ff0303","#ffbf00","100","#0248d0","300","#34c001","500")
    dataunit = "Hosts"
