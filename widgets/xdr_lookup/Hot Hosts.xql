/**************************************************************************
  Hot Hosts

  Endpoints with the most matches.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches
| comp count() as hits by hostname
| sort desc hits
| limit 15

| view graph type = pie subtype = donut header = "Hot Hosts (Most Matches)" xaxis = hostname yaxis = hits
