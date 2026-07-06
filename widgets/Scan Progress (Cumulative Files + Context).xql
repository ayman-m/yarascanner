/******************************************************************************************
W-Perf — Scan Progress (Cumulative Files + Context)
Goal:
  Display cumulative files scanned over time (hourly bins). Upstream also computes:
    - rate_fps     = avg files/sec (throughput per bin)
    - cum_skipped  = latest skipped count per bin
  but the visualization plots only cum_scanned as an area chart.

Signal source:
  type = "statistics" AND message contains "Scan Progress"  , confirm field: message 

Parsing:
  fps     ← to_float(scan_rate_files_per_sec)
  scanned ← to_integer(files_scanned)
  skipped ← to_integer(files_skipped)

Aggregation (hourly):
  rate_fps    = avg(fps)                 // throughput per bin (not plotted here)
  cum_scanned = latest(scanned)          // cumulative snapshot per bin
  cum_skipped = latest(skipped)          // cumulative snapshot per bin

Notes:
- Time bucketing done with `bin _time span = 1h`.
- No logic changes—formatting, documentation only.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "statistics" and message contains "Scan Progress"  /* confirm field: message */
| alter
    fps     = to_float(scan_rate_files_per_sec),
    scanned = to_integer(files_scanned),
    skipped = to_integer(files_skipped)
| bin _time span = 1h  // correct time bucketing
| comp
    avg(fps)         as rate_fps,      // throughput
    latest(scanned)  as cum_scanned,   // cumulative snapshot per bin
    latest(skipped)  as cum_skipped
  by _time
| sort asc _time

| view graph
    type = area subtype = standard
    header = "Scan Progress"
    show_percentage = `false`
    xaxis = _time
    yaxis = cum_scanned
    legend = `false`
    xaxistitle = "Hourly"
    yaxistitle = "No of Files"
