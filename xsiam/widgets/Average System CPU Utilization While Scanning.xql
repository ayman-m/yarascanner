/******************************************************************************************
W-Perf — Average CPU Utilization While Scanning (All Endpoints)
Goal:
  Compute the overall average CPU utilization across all hosts, restricted to each host’s
  active scan window (latest START → earliest COMPLETION after that start), then render a KPI.

Signals:
  START    → type = "performance" AND message contains "Worker thread startup completed"
  COMPLETE → message contains "Target scan completed:"

Metric source (snapshots):
  From type = "system_resource_snapshot"
    - sys_cpu_percent  → system-wide CPU %
    - proc_cpu_percent → scanner process CPU % (may exceed 100% on multi-core)

Method (no logic changes):
  1) For each host, find the latest START in the window.
  2) Find the earliest COMPLETION occurring after that START.
  3) Join CPU snapshots that fall INSIDE [start_time, end_time].
  4) Average per host, then average across ALL endpoints.
  5) Display the system CPU KPI as a marker gauge.
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
| filter end_time != null                            /* keep only completed windows */

/* 3) Join CPU snapshots INSIDE each scan window */
| join type = inner
  (
    dataset = yara_scans_raw
    | filter type = "system_resource_snapshot"
            and sys_cpu_percent != null
            and hostname != null
    | alter host = hostname,
            snap_time = _time,
            sys_cpu   = to_float(sys_cpu_percent),
            proc_cpu  = to_float(proc_cpu_percent) 
    | fields host, snap_time, sys_cpu, proc_cpu
  )
  as snap host = snap.host
        and snap.snap_time >= start_time
        and snap.snap_time <= end_time

/* 4) Average per host’s window, then average across ALL endpoints */
| comp
    avg(sys_cpu)  as host_avg_sys_cpu,
    avg(proc_cpu) as host_avg_proc_cpu
  by host
| comp
    avg(host_avg_sys_cpu)  as avg_sys_cpu_percent_all,
    avg(host_avg_proc_cpu) as avg_proc_cpu_percent_all

/* 5) Output (overall KPI-style table) */
| alter avg_sys_cpu_percent_all = to_integer(avg_sys_cpu_percent_all), avg_proc_cpu_percent_all = to_integer(avg_proc_cpu_percent_all)
| fields avg_sys_cpu_percent_all, avg_proc_cpu_percent_all

| view graph
    type = gauge subtype = marker
    header = "Average System CPU Utilization While Scanning"
    yaxis = avg_sys_cpu_percent_all
    maxscalerange = 100
    scale_threshold("#0aa901","#ffd500","70","#fb0202","90")
    dataunit = "%"
    seriestitle("avg_sys_cpu_percent_all","System CPU Utilization")
