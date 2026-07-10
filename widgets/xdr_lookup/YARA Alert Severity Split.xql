/* YARA Alert Severity Split
   Distribution of YARA alerts by severity from the reliable alerts channel.
   category: alerts-and-kpis */
dataset = alerts | filter alert_name contains "YARA Match" | comp count() as alerts by severity | sort desc alerts | view graph type = pie subtype = full header = "YARA Alert Severity Split" xaxis = severity yaxis = alerts
