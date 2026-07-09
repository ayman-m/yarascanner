/**************************************************************************
  Total Paused Time per Host

  Cumulative CPU-throttle pause time per host (throttle visibility).

  Dataset(s): yara_scanner_scans. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_scans
| filter status = "completed"
| sort desc event_timestamp_ms
| dedup scan_id
| comp sum(total_paused_secs) as paused_secs by hostname
| sort desc paused_secs

| view graph type = bar header = "Total Paused Time per Host" xaxis = hostname yaxis = paused_secs
