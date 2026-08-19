/**************************************************************************
  Cancelled Scans Audit

  Operator-cancelled scans with partial counts.

  Dataset(s): yara_scanner_scans. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_scans*
| filter status = "cancelled"
| sort desc event_timestamp_ms
| fields hostname, scan_id, files_scanned, detections, total_paused_secs, message
| limit 50

| view graph type = table header = "Cancelled Scans Audit"
