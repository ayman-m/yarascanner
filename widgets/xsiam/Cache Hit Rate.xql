/******************************************************************************************
W-Perf — Cache Hit-Rate (Weighted Across All Endpoints)
Goal:
  Compute a single cache hit-rate KPI weighted by request volume across all reporting hosts.

Signal source:
  type = "statistics" AND message contains "Cache Performance"
Parsed fields:
  hit_rate_percent (0–100), total_requests
Method:
  - Cast values to numeric.
  - Weighted mean: sum(hit% × requests) ÷ sum(requests).
  - Guard against divide-by-zero (no requests).

Notes:
  - No logic changes—formatting & documentation only.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics" and message contains "Cache Performance"
        and hit_rate_percent != null and total_requests != null
| alter
    hit = to_float(hit_rate_percent),     /* percent 0–100 */
    req = to_integer(total_requests)
| comp
    sum(multiply(hit, req)) as w_sum,     /* weighted by request volume */
    sum(req)                 as req_sum
| alter
    hit_rate_weighted = if(req_sum = 0, 0, divide(w_sum, req_sum))  /* % */

| view graph
    type = gauge subtype = filler
    header = "Cache Hit-Rate (All Endpoints)"
    yaxis = hit_rate_weighted
    maxscalerange = 100
    scale_threshold("#929191","#ff4d4f","0","#faad14","40","#52c41a","60")
    dataunit = "%"
