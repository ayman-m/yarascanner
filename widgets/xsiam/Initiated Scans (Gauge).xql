/******************************************************************************************
W-Perf — Initiated Scans (Gauge)
Goal: Count unique hosts that reported a scan start signal in the selected timeframe.
Signal definition:
  START → type = "performance" AND message contains "Worker thread startup completed"
Output:
  scanned_hosts → count_distinct(hostname)
Notes:
- case_sensitive = false to match the message reliably.
- No logic changes—formatting & documentation only.
******************************************************************************************/
config case_sensitive = false
| dataset = yara_scans_raw
| filter type = "performance" and message contains "Worker thread startup completed"
| comp count_distinct(hostname) as scanned_hosts

| view graph
    type = gauge subtype = radial
    header = "Initiated Scans"
    yaxis = scanned_hosts
    maxscalerange = 880
    scale_threshold("#f50303","#ffbf00","300","#0248d0","500","#34c001","700")
    dataunit = "Hosts"
