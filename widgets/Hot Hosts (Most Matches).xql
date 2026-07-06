/******************************************************************************************
D-Det04 — Hot Hosts (Most Matches)
Goal:
  Identify which hosts produce the most YARA matches in the timeframe; show latest IP for context.

Method (logic unchanged):
  - Filter YARA match events with a populated hostname.
  - Aggregate per host: total hits + latest observed IP.
  - Sort by hits desc, take top 12.
  - Visualize as a pie (share of matches by host).

Notes:
  - `latest(ipAddress)` supplies a recent IP per host for table/tooltips; pie uses hits only.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and hostname != null
| comp
    count() as hits,
    latest(ipAddress) as ipAddress
  by hostname
| sort desc hits
| limit 12

| view graph
    type = pie
    header = "Top Hosts by YARA Matches"
    xaxis  = hostname
    yaxis  = hits
