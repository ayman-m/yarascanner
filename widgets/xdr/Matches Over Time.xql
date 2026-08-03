/**************************************************************************
  Matches Over Time

  Match volume in hourly buckets. Lookup rows have no _time, so we bucket on
event_timestamp_ms (epoch ms) -> hourly timestamp.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.
**************************************************************************/
dataset = yara_scanner_matches*
| alter bucket_ms = multiply(to_integer(divide(event_timestamp_ms, 3600000)), 3600000)
| alter ts = to_timestamp(bucket_ms, "MILLIS")
| comp count() as hits by ts
| sort asc ts

| view graph type = line header = "Matches Over Time (hourly)" xaxis = ts yaxis = hits
