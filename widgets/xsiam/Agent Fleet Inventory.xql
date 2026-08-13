/******************************************************************************************
Yara - Agent Fleet Inventory
Dashboard: YARA Scan Performance
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics_summary" and platform != null and hostname != null
| sort desc _time
| dedup hostname
| comp count_distinct(hostname) as hosts by platform, yara_version, python_version
| sort desc hosts

| view graph type = column subtype = stacked layout = horizontal header = "Agent Fleet Inventory (platform / libyara)" xaxis = platform yaxis = hosts series = yara_version
