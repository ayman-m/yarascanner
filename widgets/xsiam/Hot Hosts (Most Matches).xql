/******************************************************************************************
D-Det04 — Hot Hosts (Most Matches)
Goal:
  Identify which hosts produce the most YARA matches in the timeframe; show latest IP for context.

Method:
  - Filter YARA match events with a populated hostname.
  - Aggregate per host: total hits (summed from match_count, not row count) + latest IP.
  - Sort by hits desc, take top 12.
  - Visualize as a pie (share of matches by host).

Notes:
  - `latest(ipAddress)` supplies a recent IP per host for table/tooltips; pie uses hits only.
  - hits = sum(match_count), NOT count(). Each yara_match row is now one (rule, file) finding,
    not one matched-string instance (2026-08 grain change) - match_count carries the true,
    uncapped hit total for that finding. count() here would undercount by orders of magnitude
    on any finding with many string-offset hits.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and hostname != null
| comp
    sum(to_integer(match_count)) as hits,
    latest(ipAddress) as ipAddress
  by hostname
| sort desc hits
| limit 12

| view graph
    type = pie
    header = "Top Hosts by YARA Matches"
    xaxis  = hostname
    yaxis  = hits
