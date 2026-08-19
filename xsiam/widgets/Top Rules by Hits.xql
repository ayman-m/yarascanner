/******************************************************************************************
D-Det02 — Top Rules by Hits (Last 24h)
Goal:
  Find the noisiest YARA rules by total match count to prioritize tuning/triage.

Method:
  - Filter YARA match events that have a rule_id.
  - Aggregate: sum(match_count) as hits per rule_id.
  - Sort by hits desc and keep Top 15.
  - Visualize as a full pie (each slice = rule share of total hits).

Notes:
  - hits = sum(match_count), NOT count(). Each yara_match row is now one (rule, file) finding,
    not one matched-string instance (2026-08 grain change) - match_count carries the true,
    uncapped hit total for that finding. count() here would undercount by orders of magnitude
    on any rule with many string-offset hits.
  - Consider pairing with a table showing example files/strings for top rules.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and rule_id != null
| comp sum(to_integer(match_count)) as hits by rule_id
| sort desc hits
| limit 15


| view graph type = pie subtype = full header = "Top YARA Rules by Hits" show_callouts_names = `true` show_percentage = `false` xaxis = rule_id yaxis = hits valuecolor("ID_86787","#008eff") 