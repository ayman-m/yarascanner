/******************************************************************************************
W-Perf — Average System Memory Utilization While Scanning (All Endpoints)
Goal:
  Compute the overall average **system memory %** across all hosts, restricted to each host’s
  active scan window (latest START → earliest COMPLETION after that start), then render a KPI.

Signals:
  START    → type = "performance" AND message contains "Worker thread startup completed"
  COMPLETE → message contains "Target scan completed:"

Metrics source (snapshots):
  From type = "system_resource_snapshot"
    - sys_memory_used_percent → system memory utilization (%)
    - proc_memory_mb          → scanner process memory (MB)  // optional; included for context

Method (documentation/formatting only — no logic changes):
  1) Per host, find latest START in timeframe.
  2) Earliest COMPLETION after that start → [start_time, end_time].
  3) Join memory snapshots that fall inside the window.
  4) Average per host, then average across ALL endpoints.
  5) Output KPIs and display the **system memory %** as a marker gauge.
******************************************************************************************/
config case_sensitive = false
| dataset = yara_scans_raw

/* 1) Latest START per host */
| filter type = "performance"
        and message contains "Worker thread startup completed"
        and hostname != null
| comp latest(_time) as start_time by hostname
| alter host = hostname

/* 2) Earliest COMPLETION after that start (per host) */
| join type = left
  (
    config case_sensitive = false
    | dataset = yara_scans_raw
    | filter message contains "Target scan completed:" and hostname != null
    | fields hostname, _time as completed_time
  ) as comp_hosts host = comp_hosts.hostname
| filter completed_time = null or completed_time >= start_time
| comp
    min(start_time)     as start_time,
    min(completed_time) as end_time
  by host
| filter end_time != null   /* only completed windows */

/* 3) Join memory snapshots INSIDE each scan window */
| join type = inner
  (
    dataset = yara_scans_raw
    | filter type = "system_resource_snapshot"
            and sys_memory_used_percent != null
            and hostname != null
    | alter host     = hostname,
            snap_time= _time,
            sys_mem  = to_float(sys_memory_used_percent),
            proc_mem = to_float(proc_memory_mb)   /* optional; may be null */
    | fields host, snap_time, sys_mem, proc_mem
  )
  as snap host = snap.host
        and snap.snap_time >= start_time
        and snap.snap_time <= end_time

/* 4) Average per host’s window, then average across ALL endpoints */
| comp
    avg(sys_mem)  as host_avg_sys_mem_pct,
    avg(proc_mem) as host_avg_proc_mem_mb
  by host
| comp
    avg(host_avg_sys_mem_pct)  as avg_sys_mem_percent_all,
    avg(host_avg_proc_mem_mb)  as avg_proc_mem_mb_all

/* 5) KPI-style output + gauge */
| alter
    avg_sys_mem_percent_all = to_integer(avg_sys_mem_percent_all),
    avg_proc_mem_mb_all     = to_integer(avg_proc_mem_mb_all)
| fields avg_sys_mem_percent_all, avg_proc_mem_mb_all

| view graph
    type = gauge subtype = marker
    header = "Average System Memory Utilization"
    yaxis = avg_sys_mem_percent_all
    maxscalerange = 100
    scale_threshold("#0aa901","#ffd500","70","#fb0202","90")
    dataunit = "%"
    seriestitle("avg_sys_mem_percent_all","Average Memory Utilization")
