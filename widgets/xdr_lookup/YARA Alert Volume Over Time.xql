/* YARA Alert Volume Over Time
   Hourly trend of YARA alert firings to spot detection spikes on the reliable channel.
   category: alerts-and-kpis */
dataset = alerts | filter alert_name contains "YARA Match" | bin _time span = 1d | comp count() as alerts by _time | sort asc _time | view graph type = line header = "YARA Alert Volume Over Time" xaxis = _time yaxis = alerts
