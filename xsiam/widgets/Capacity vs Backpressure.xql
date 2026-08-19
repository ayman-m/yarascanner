/******************************************************************************************
W-Perf — Capacity vs Backpressure (Indexed to 100)
Goal:
  Plot Workers vs Queue together while keeping both lines readable by normalizing each
  series to its own MAX within the time window (0–100 scale).

Signal source:
  type = "statistics" AND message contains "Scan Progress"
Required fields:
  active_workers, queue_size  (numeric after casting)

Method (logic unchanged):
  1) Build two hourly time series (avg Workers, avg Queue) and stack them with union.
  2) Rebuild the same two series to compute per-series MAX, then join by `metric`.
  3) Index each point: value_index = 100 × value ÷ max_value (guard divide-by-zero).
  4) Draw a single multi-series area chart (series = metric).

Notes:
- `bin _time span = 1h` ensures aligned time buckets across both series.
- `join (...) as mx metric = mx.metric` pairs each row with its series MAX.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics"
        and message contains "Scan Progress"      /* confirm field: message */
        and active_workers != null
        and queue_size    != null

/* 1) Build Workers series */
| alter aw = to_integer(active_workers)
| bin _time span = 1h
| comp avg(aw) as value by _time
| alter metric = "Workers"

/* 2) Build Queue series and stack with Workers */
| union (
    dataset = yara_scans_raw
    | filter type = "statistics"
            and message contains "Scan Progress"
            and active_workers != null
            and queue_size    != null
    | alter q = to_integer(queue_size)
    | bin _time span = 1h
    | comp avg(q) as value by _time
    | alter metric = "Queue"
  )

/* 3) Compute per-series MAX and join properly by metric */
| join
  (
    dataset = yara_scans_raw
    | filter type = "statistics"
            and message contains "Scan Progress"
            and active_workers != null
            and queue_size    != null
    | alter aw = to_integer(active_workers)
    | bin _time span = 1h
    | comp avg(aw) as value by _time
    | alter metric = "Workers"
    | union (
        dataset = yara_scans_raw
        | filter type = "statistics"
                and message contains "Scan Progress"
                and active_workers != null
                and queue_size    != null
        | alter q = to_integer(queue_size)
        | bin _time span = 1h
        | comp avg(q) as value by _time
        | alter metric = "Queue"
      )
    | comp max(value) as max_value by metric
  )
  as mx metric = mx.metric

/* 4) Materialize joined field and index to 0–100 */
| fields *, max_value as max_value
| alter value_index = if(max_value = 0, 0, multiply(100.0, divide(to_float(value), to_float(max_value))))
| sort asc _time, asc metric

/* 5) Visualize — multi-series area chart */
| view graph
    type = area subtype = standard
    header = "Capacity vs Backpressure (Indexed to 100)"
    show_percentage = `false`
    xaxis = _time
    yaxis = value_index
    series = metric
    yaxminrange = 0
    default_limit = `false`
    seriescolor("Workers","#00cfff")
    seriescolor("Queue","#df01ec")
    legend = `false`
    xaxistitle = "Hourly"
    yaxistitle = "Indexed (max = 100)"
