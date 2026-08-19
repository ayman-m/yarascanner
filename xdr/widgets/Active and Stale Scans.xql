/**************************************************************************
  Active and Stale Scans

  Scans whose latest state is running/initiated. A stale row (old event_timestamp_ms)
with no terminal update usually means the scan was hard-killed.

  Dataset(s): yara_scanner_scans. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_scans*
| sort desc event_timestamp_ms
| dedup scan_id
| filter status in ("running","initiated")
| fields hostname, scan_id, status, files_scanned, detections, throttle_mode, event_timestamp_ms

| view graph type = table header = "Active / Stale Scans"
