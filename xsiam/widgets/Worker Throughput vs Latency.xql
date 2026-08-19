/******************************************************************************************
W-Perf — Worker Throughput vs Latency (Top 10 by Volume)
Goal:
  Compare each worker’s total throughput vs average processing latency over the last 24h.
  X-axis: avg processing time (ms). Y-axis: total files (in millions). Series: worker_id.

Source:
  type = "performance"
Parsed fields:
  files_processed          → fp_millions (scaled: /1,000,000)
  avg_processing_time_ms   → ms (per-file avg latency in ms)
  error_rate_percent       → err (kept for completeness; not plotted here)

Aggregations (per worker_id):
  files_in_millions = sum(fp_millions)   // total files handled in window (M)
  avg_ms            = avg(ms)            // mean per-file processing latency (ms)
  err_pct           = avg(err)           // mean error rate (%) — not used in this chart

Selection:
  Sort by highest throughput (files_in_millions) and keep Top 10 to avoid clutter.

Visualization:
  Scatter: X = avg_ms, Y = files_in_millions, series = worker_id.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "performance" and worker_id != null
| alter
    fp_millions  = divide(to_integer(files_processed), 1000000),
    ms           = to_float(avg_processing_time_ms),
    err          = to_float(error_rate_percent)
| comp
    sum(fp_millions)  as files_in_millions,   // total files handled by this worker in the window
    avg(ms)           as avg_ms,              // mean per-file processing latency (ms)
    avg(err)          as err_pct              // mean error rate (%)
  by worker_id
| sort desc files_in_millions
| limit 10

| view graph
    type   = scatter
    header = "Worker Throughput vs Latency"
    xaxis  = avg_ms
    yaxis  = files_in_millions
    series = worker_id
    xaxistitle = "Avg Processing Time (ms)"
    yaxistitle = "Files Processed in Millions (window)"
