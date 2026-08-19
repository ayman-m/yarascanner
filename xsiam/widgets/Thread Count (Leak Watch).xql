/******************************************************************************************
Yara - Thread Count (Leak Watch)
Dashboard: YARA Scan Performance

NOTE: leads with thread count because proc_file_descriptors is POSIX-only (psutil num_fds());
Windows endpoints report 0 for FDs. Thread count is populated on every platform.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "system_resource_snapshot" and proc_thread_count != null and hostname != null
| alter threads = to_integer(proc_thread_count), fds = to_integer(proc_file_descriptors)
| bin _time span = 5m
| comp max(threads) as peak_threads, max(fds) as peak_fds by hostname, _time
| sort asc _time

| view graph type = line header = "Scanner Thread Count (leak watch)" xaxis = _time yaxis = peak_threads series = hostname yaxistitle = "Peak threads"
