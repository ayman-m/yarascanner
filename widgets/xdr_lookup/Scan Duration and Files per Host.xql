/**************************************************************************
  Scan Duration and Files per Host

  Completed-scan throughput per host (latest completed row per scan).

  Dataset(s): yara_scanner_scans. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_scans*
| filter status = "completed"
| sort desc event_timestamp_ms
| dedup scan_id
| comp avg(elapsed_secs) as avg_secs, sum(files_scanned) as files_scanned by hostname
| sort desc files_scanned

| view graph type = table header = "Scan Duration & Files per Host"
