/******************************************************************************************
Yara - Scanner Memory Growth Over Time
Dashboard: YARA Scan Performance
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "system_resource_snapshot" and proc_memory_mb != null and hostname != null
| alter mem_mb = to_float(proc_memory_mb)
| bin _time span = 5m
| comp avg(mem_mb) as avg_mem_mb, max(mem_mb) as peak_mem_mb by hostname, _time
| sort asc _time

| view graph type = line header = "Scanner Memory Growth (per host)" xaxis = _time yaxis = peak_mem_mb series = hostname yaxistitle = "Process RSS (MB)" xaxistitle = "5-minute buckets"
