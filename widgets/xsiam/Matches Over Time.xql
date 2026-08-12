/******************************************************************************************
D-Det01 — Matches Over Time by Severity
Goal:
  Trend YARA matches over time, split by severity level.

Method:
  - Filter YARA match events with a valid `level`.
  - Bucket time into 10-minute bins.
  - Sum match_count per (level, time bin) - NOT count(). Each yara_match row is now one
    (rule, file) finding, not one matched-string instance (2026-08 grain change); match_count
    carries the true, uncapped hit total for that finding, so count() would undercount by
    orders of magnitude whenever a finding has many string-offset hits.
  - Plot as multi-series line where each series = severity `level`.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and level != null
| bin _time span = 10m
| comp sum(to_integer(match_count)) as hits by level, _time
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
