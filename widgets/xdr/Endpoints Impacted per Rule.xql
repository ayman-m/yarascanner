/**************************************************************************
  Endpoints Impacted per Rule

  How many distinct endpoints each rule fired on.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches*
| comp count_distinct(hostname) as endpoints by rule
| sort desc endpoints
| limit 15

| view graph type = bar header = "Endpoints Impacted per Rule" xaxis = rule yaxis = endpoints
