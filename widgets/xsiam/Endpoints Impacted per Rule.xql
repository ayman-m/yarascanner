/******************************************************************************************
D-Det03 — Endpoints Impacted per Rule (Blast Radius)
Goal:
  Show how many distinct endpoints (hosts) each YARA rule impacted within the timeframe.

Method (logic unchanged):
  - Filter YARA match events that have both rule_id and hostname.
  - Aggregate: count_distinct(hostname) per rule_id → hosts.
  - Sort by hosts desc and take Top 10.
  - Visualize as a funnel (each step = a rule sized by impacted hosts).

Notes:
  - hostname field assumed present in yara_match events. confirm field: hostname 
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and rule_id != null and hostname != null     /* confirm field: hostname */
| comp count_distinct(hostname) as hosts by rule_id
| sort desc hosts
| limit 10


| view graph type = funnel header = "Endpoints Impacted per Rule" show_callouts = `true` show_callouts_names = `true` show_percentage = `false` xaxis = rule_id yaxis = hosts 