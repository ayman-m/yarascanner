/******************************************************************************************
Yara - Truncated Findings (Noisiest Rules)
Dashboard: YARA Matches
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and truncated = "true"
| alter hits = to_integer(match_count)
| comp count() as truncated_findings, sum(hits) as total_hits, max(hits) as worst_single_finding,
       count_distinct(file_name) as files by rule_id
| sort desc total_hits
| limit 15

| view graph type = column subtype = stacked layout = horizontal header = "Truncated Findings - Noisiest Rules" xaxis = rule_id yaxis = total_hits yaxistitle = "Total string hits"
