/******************************************************************************************
Yara - Rule-only vs String Matches
Dashboard: YARA Matches
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and match_scope != null
| comp count() as findings, count_distinct(hostname) as hosts by match_scope, rule_id
| sort desc findings
| limit 20

| view graph type = column subtype = stacked layout = horizontal header = "Rule-only vs String Matches (by rule)" xaxis = rule_id yaxis = findings series = match_scope
