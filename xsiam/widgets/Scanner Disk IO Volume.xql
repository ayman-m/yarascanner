/******************************************************************************************
Yara - Scanner Disk I/O Volume
Dashboard: YARA Scan Performance
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "system_resource_snapshot" and proc_io_read_mb != null and hostname != null
| alter read_mb = to_float(proc_io_read_mb), write_mb = to_float(proc_io_write_mb)
| comp max(read_mb) as total_read_mb, max(write_mb) as total_write_mb by hostname
| sort desc total_read_mb
| limit 15

| view graph type = column subtype = stacked layout = horizontal header = "Scanner Disk I/O Volume" xaxis = hostname yaxis = total_read_mb,total_write_mb seriescolor("total_read_mb","#0aae00") seriescolor("total_write_mb","#dd0236")
