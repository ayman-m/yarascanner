/**************************************************************************
  Top Rules by Hits

  Noisiest YARA rules by total match count (yara_scanner_matches).

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches
| comp count() as hits by rule
| sort desc hits
| limit 15

| view graph type = pie subtype = full header = "Top YARA Rules by Hits" xaxis = rule yaxis = hits
