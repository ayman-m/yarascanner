/* Top YARA-Alerting Rules
   Ranks rules by reliable alert volume from the alerts channel to confirm dataset-side top rules.
   category: alerts-and-kpis */
dataset = alerts | filter alert_name contains "YARA Match" | comp count() as alert_count by alert_name | sort desc alert_count | limit 15 | view graph type = bar header = "Top YARA-Alerting Rules" xaxis = alert_name yaxis = alert_count
