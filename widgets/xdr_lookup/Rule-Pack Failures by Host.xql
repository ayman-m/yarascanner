/* Rule-Pack Failures by Host
   Surface endpoints whose latest scans failed to compile the most YARA rules, flagging broken rule-pack deployments.
   category: rule-health */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | filter failed_rules > 0 | comp sum(failed_rules) as failed_rules by hostname | sort desc failed_rules | limit 15 | view graph type = bar header = "Rule-Pack Failures by Host" xaxis = hostname yaxis = failed_rules
