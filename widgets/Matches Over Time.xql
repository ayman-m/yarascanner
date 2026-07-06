/******************************************************************************************
D-Det01 — Matches Over Time by Severity
Goal:
  Trend YARA matches over time, split by severity level.

Method (logic unchanged):
  - Filter YARA match events with a valid `level`.
  - Bucket time into 10-minute bins.
  - Count matches per (level, time bin).
  - Plot as multi-series line where each series = severity `level`.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and level != null
| bin _time span = 10m
| comp count() as hits by level, _time
| sort asc _time, asc level

| view graph
    type   = line
    header = "YARA Matches Over Time (by Level)"
    xaxis  = _time
    yaxis  = hits
    series = level
    legend = `false`
    xaxistitle = "10-minute buckets"
    yaxistitle = "Matches"
