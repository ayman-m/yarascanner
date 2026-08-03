/**************************************************************************
  Severity Split

  Distribution of match severity.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches*
| comp count() as hits by severity

| view graph type = pie subtype = donut header = "Matches by Severity" xaxis = severity yaxis = hits
