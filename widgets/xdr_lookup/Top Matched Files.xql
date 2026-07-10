/**************************************************************************
  Top Matched Files

  Files triggering the most string matches (by path + sha256).

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches
| comp count() as hits by filename, file_sha256
| sort desc hits
| limit 20

| view graph type = table header = "Top Matched Files"
