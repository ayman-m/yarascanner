/******************************************************************************************
Yara - Disk Headroom on Scanned Endpoints
Dashboard: YARA Scan Performance
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "system_resource_snapshot" and sys_disk_used_percent != null and hostname != null
| alter used_pct = to_float(sys_disk_used_percent), free_gb = to_float(sys_disk_free_gb)
| sort desc _time
| dedup hostname
| fields hostname, used_pct, free_gb
| sort desc used_pct
| limit 15

| view graph type = column subtype = stacked layout = horizontal header = "Disk Headroom on Scanned Endpoints" xaxis = hostname yaxis = used_pct yaxistitle = "Disk used (%)"
