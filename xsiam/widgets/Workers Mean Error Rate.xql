/******************************************************************************************
W-Perf — Workers Mean Error Rate (Per Worker)
Goal:
  For each worker, summarize performance over the last 24h and chart the mean error rate.

Signals & parsing:
  From type = "performance"
    - files_processed          → fp_millions (scaled to millions for context)
    - avg_processing_time_ms   → ms  (per-file avg latency, ms)
    - error_rate_percent       → err (error %, 0–100)

Aggregation (per worker_id):
  files_in_millions = sum(fp_millions)     // total files handled in the window (M)
  avg_ms            = avg(ms)              // mean processing latency (ms)
  err_pct           = avg(err)             // mean error rate (%)

Visualization:
  Horizontal grouped column chart: X = worker_id, Y = err_pct, series = files_in_millions.
  (Legend hidden; series retained for tooltips/context.)
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "performance" and worker_id != null
| alter
    fp_millions  = divide(to_integer(files_processed),1000000),
    ms  = to_float(avg_processing_time_ms),
    err = to_float(error_rate_percent)
| comp
    sum(fp_millions)  as files_in_millions,       // total files handled by this worker in the window
    avg(ms)  as avg_ms,                            // mean per-file processing latency (ms)
    avg(err) as err_pct                            // mean error rate (%)
  by worker_id

| view graph
    type = column subtype = grouped layout = horizontal
    header = "Workers Mean Error Rate"
    xaxis = worker_id
    yaxis = err_pct
    series = files_in_millions
    legend = `false`
