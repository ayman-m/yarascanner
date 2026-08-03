/******************************************************************************************
W-Perf — Scan Rate (Gauge)
Goal: Show the average scan throughput (files per second) in the selected timeframe.

Signal source:
  type = "statistics" AND message contains "Scan Progress"   

Parsing:
  fps     ← scan_rate_files_per_sec (float)
  scanned ← files_scanned (int)   // not used in this KPI
  skipped ← files_skipped (int)   // not used in this KPI

Aggregation:
  rate_fps = avg(fps)

Notes:
- No logic changes—formatting & documentation only.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics" and message contains "Scan Progress"  /* confirm field: message */
| alter
    fps     = to_float(scan_rate_files_per_sec),
    scanned = to_integer(files_scanned),
    skipped = to_integer(files_skipped)
| comp
    avg(fps) as rate_fps

| view graph
    type = gauge subtype = radial
    header = "Scan Rate"
    yaxis = rate_fps
    maxscalerange = 150
    scale_threshold("#929191","#ff0000","0","#0020ff","50","#0aae00","100")
    dataunit = "Files Per Second"
