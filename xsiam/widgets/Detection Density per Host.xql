/******************************************************************************************
Yara - Detection Density per Host
Dashboard: YARA Matches

NOTE: normalizes detections against files actually scanned, so a small endpoint with a few
hits ranks above a large one with many. Sourced from the latest 'Scan Progress' event per host.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics" and message contains "Scan Progress" and files_scanned != null and hostname != null
| alter scanned = to_float(files_scanned), dets = to_float(total_detections)
| sort desc _time
| dedup hostname
| alter density_per_1k = if(scanned > 0, multiply(divide(dets, scanned), 1000.0), 0)
| fields hostname, scanned, dets, density_per_1k
| sort desc density_per_1k
| limit 15

| view graph type = column subtype = stacked layout = horizontal header = "Detection Density (matches per 1,000 files scanned)" xaxis = hostname yaxis = density_per_1k yaxistitle = "Detections / 1k files"
