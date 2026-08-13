/******************************************************************************************
Yara - Scan ETA / Remaining Work
Dashboard: YARA Scan Performance

NOTE: sourced from the 'Time Estimates' statistics event, which the progress heartbeat emits
during an ACTIVE scan. Rows are the latest per host; a finished scan's last ETA trends to 0.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics" and message contains "Time Estimates" and hostname != null
| alter eta_min = divide(to_float(eta_seconds), 60.0),
        remaining = to_integer(files_remaining),
        rate_fps = to_float(current_rate_files_per_sec)
| sort desc _time
| dedup hostname
| fields hostname, eta_min, remaining, rate_fps
| sort desc eta_min
| limit 15

| view graph type = column subtype = grouped layout = horizontal header = "Scan ETA / Remaining Work (latest per host)" xaxis = hostname yaxis = eta_min yaxistitle = "ETA (minutes)"
