/******************************************************************************************
Yara - Host Load vs Scanner CPU Share
Dashboard: YARA Scan Performance
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "system_resource_snapshot" and sys_cpu_percent != null and proc_cpu_percent != null and hostname != null
| alter sys_cpu = to_float(sys_cpu_percent), proc_cpu = to_float(proc_cpu_percent)
| comp avg(sys_cpu) as avg_system_cpu, avg(proc_cpu) as avg_scanner_cpu, max(proc_cpu) as peak_scanner_cpu by hostname
| sort desc avg_scanner_cpu
| limit 15

| view graph type = column subtype = grouped layout = horizontal header = "Host Load vs Scanner CPU Share" xaxis = hostname yaxis = avg_system_cpu,avg_scanner_cpu seriescolor("avg_system_cpu","#8f9bb3") seriescolor("avg_scanner_cpu","#0031c1")
