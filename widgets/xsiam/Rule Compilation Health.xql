/******************************************************************************************
Yara - Rule Compilation Health
Dashboard: YARA Matches
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics_summary" and valid_rules_compiled != null and hostname != null
| alter valid_rules = to_integer(valid_rules_compiled), failed_rules = to_integer(failed_rules_skipped)
| sort desc _time
| dedup hostname
| fields hostname, valid_rules, failed_rules
| sort desc failed_rules
| limit 15

| view graph type = column subtype = stacked layout = horizontal header = "Rule Compilation Health per Endpoint" xaxis = hostname yaxis = valid_rules,failed_rules seriescolor("valid_rules","#0aae00") seriescolor("failed_rules","#dd0236")
