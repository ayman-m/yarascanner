/******************************************************************************************
W-Perf — Top Hosts by Scanned Files Volume (Bubble)
Goal:
  Show the top 10 hosts by total files found in completed scans within the timeframe.

Signal:
  COMPLETE → message contains "Target scan completed:" AND data != null

Parsing (from `data` JSON):
  target_partition ← $.target
  files_found      ← $.files_found
  scan_time_seconds← $.scan_time_seconds
  files_per_second ← $.files_per_second

Method (no logic changes):
  - Keep the latest completion per (hostname, target_partition).
  - Sum files_found per hostname.
  - Sort desc, take top 10.
  - Visualize as packed bubbles sized by files_scanned_by_host.
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
    data,
    message
| comp sum(files_found) as files_scanned_by_host by hostname
| sort desc files_scanned_by_host
| limit 10

| view graph
    type = bubble subtype = packed
    header = "By Scanned Files Volume"
    xaxis  = hostname
    yaxis  = files_scanned_by_host
    series = hostname
    bubblerad = files_scanned_by_host
