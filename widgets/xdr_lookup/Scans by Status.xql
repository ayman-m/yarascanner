/**************************************************************************
  Scans by Status

  Latest lifecycle state per scan (initiated/running/completed/cancelled/failed).

  Dataset(s): yara_scanner_scans. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_scans*
| sort desc event_timestamp_ms
| dedup scan_id
| comp count() as scans by status

| view graph type = pie subtype = full header = "Scans by Status" xaxis = status yaxis = scans
