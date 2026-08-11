// Yara Scanner (XSIAM edition) - parsing rule for yara_scans_raw
//
// This is the tenant's real, working rule, checked into the repo for the first time on
// 2026-08-11 (nothing existed here before - the Deployment Guide only had the bare
// [INGEST:...] header). It was found on-tenant wrapped in a single /* ... */ comment
// spanning the entire body, including the [INGEST:...] header itself - which silently
// disabled the whole rule. That comment wrap has been removed below; the rule content
// is otherwise unchanged from what was live on the tenant.
//
// Correctly targets the scanner's nested payload shape (data.metrics.active_workers,
// data.process.cpu_percent, data.system.cpu_percent, data.rule, data.filename, etc.) -
// do not "flatten" these paths to match newer top-level aliases without re-checking
// against the actual scanner code first.

[INGEST:vendor="yara", product="scans", target_dataset="yara_scans_raw", no_hit = keep]
filter type= "yara_match" 
| alter 
  file_name = json_extract_scalar(data, "$.filename"),
  match = json_extract_scalar(data, "$.match"), 
  offset = json_extract_scalar(data, "$.offset"),
  rule_id = json_extract_scalar(data, "$.rule"),
  string = json_extract_scalar(data, "$.string");
filter type= "performance" 
| alter 
  worker_id = json_extract_scalar(data, "$.worker_id"),
  files_processed = json_extract_scalar(data, "$.files_processed"), 
  avg_processing_time_ms = json_extract_scalar(data, "$.avg_processing_time_ms"),
  error_rate_percent = json_extract_scalar(data, "$.error_rate_percent");
filter type= "statistics" and message contains "Scan Progress"
| alter 
  files_scanned           = json_extract_scalar(data, "$.files_scanned"),
  files_skipped           = json_extract_scalar(data, "$.files_skipped"),
  total_detections        = json_extract_scalar(data, "$.total_detections"),
  queue_size              = json_extract_scalar(data, "$.queue_size"),
  scan_rate_files_per_sec = json_extract_scalar(data, "$.scan_rate_files_per_sec"),
  cpu_percent             = json_extract_scalar(data, "$.metrics.cpu_percent"),
  memory_mb               = json_extract_scalar(data, "$.metrics.memory_mb"),
  disk_io_mb              = json_extract_scalar(data, "$.metrics.disk_io_mb"),
  network_mb              = json_extract_scalar(data, "$.metrics.network_mb"),
  active_workers          = json_extract_scalar(data, "$.metrics.active_workers"),
  elapsed_seconds         = json_extract_scalar(data, "$.metrics.elapsed_seconds"),
  eta_seconds             = json_extract_scalar(data, "$.metrics.eta_seconds"),
  cache_hit_rate          = json_extract_scalar(data, "$.metrics.cache_hit_rate"),
  junction_skips          = json_extract_scalar(data, "$.metrics.junction_skips"),
  unique_real_paths       = json_extract_scalar(data, "$.metrics.unique_real_paths");
filter type= "statistics" and message contains "Cache Performance"
| alter 
  hit_rate_percent           = json_extract_scalar(data, "$.hit_rate_percent"),
  total_requests           = json_extract_scalar(data, "$.total_requests"),
  memory_usage_mb           = json_extract_scalar(data, "$.memory_usage_mb");
filter type= "statistics" and message contains "Time Estimates"
| alter 
  eta_seconds           = json_extract_scalar(data, "$.eta_seconds"),
  estimated_completion           = json_extract_scalar(data, "$.estimated_completion"),
  current_rate_files_per_sec           = json_extract_scalar(data, "$.current_rate_files_per_sec"),
  files_remaining           = json_extract_scalar(data, "$.files_remaining");
filter type= "statistics_summary"
| alter
  phase                       = json_extract_scalar(data, "$.phase"),
  hostname                    = json_extract_scalar(data, "$.system_info.hostname"),
  ip_addresses                 = json_extract_scalar(data, "$.system_info.ip_addresses"),
  platform                    = json_extract_scalar(data, "$.system_info.platform"),
  python_version               = json_extract_scalar(data, "$.system_info.python_version"),
  yara_version                 = json_extract_scalar(data, "$.system_info.yara_version"),
  rule_source                  = json_extract_scalar(data, "$.system_info.rule_source"),
  scan_targets                 = json_extract_scalar(data, "$.system_info.scan_targets[0]"),
  max_workers                  = json_extract_scalar(data, "$.system_info.max_workers"),
  max_file_mb                  = json_extract_scalar(data, "$.system_info.max_file_mb"),
  upload_enabled               = json_extract_scalar(data, "$.system_info.upload_enabled"),
  webhook_key_source           = json_extract_scalar(data, "$.system_info.webhook_key_source"),
  webhook_endpoint_source      = json_extract_scalar(data, "$.system_info.webhook_endpoint_source"),
  api_endpoint                 = json_extract_scalar(data, "$.system_info.api_endpoint"),
  logging_format               = json_extract_scalar(data, "$.system_info.logging_format"),
  valid_rules_compiled         = json_extract_scalar(data, "$.compilation_results.valid_rules_compiled"),
  failed_rules_skipped         = json_extract_scalar(data, "$.compilation_results.failed_rules_skipped"),
  compilation_success_rate     = json_extract_scalar(data, "$.compilation_results.compilation_success_rate");
filter type = "system_resource_snapshot"
| alter
  proc_cpu_percent              = json_extract_scalar(data, "$.process.cpu_percent"),
  proc_memory_mb                = json_extract_scalar(data, "$.process.memory_mb"),
  proc_memory_percent           = json_extract_scalar(data, "$.process.memory_percent"),
  proc_io_read_mb               = json_extract_scalar(data, "$.process.io_read_mb"),
  proc_io_write_mb              = json_extract_scalar(data, "$.process.io_write_mb"),
  proc_thread_count             = json_extract_scalar(data, "$.process.thread_count"),
  proc_file_descriptors         = json_extract_scalar(data, "$.process.file_descriptors"),
  sys_cpu_percent               = json_extract_scalar(data, "$.system.cpu_percent"),
  sys_memory_total_mb           = json_extract_scalar(data, "$.system.memory_total_mb"),
  sys_memory_available_mb       = json_extract_scalar(data, "$.system.memory_available_mb"),
  sys_memory_used_percent       = json_extract_scalar(data, "$.system.memory_used_percent"),
  sys_disk_total_gb             = json_extract_scalar(data, "$.system.disk_total_gb"),
  sys_disk_free_gb              = json_extract_scalar(data, "$.system.disk_free_gb"),
  sys_disk_used_percent         = json_extract_scalar(data, "$.system.disk_used_percent"),
  sys_load_avg_1m               = json_extract_scalar(data, "$.system.load_avg_1m"),
  sys_load_avg_5m               = json_extract_scalar(data, "$.system.load_avg_5m"),
  sys_load_avg_15m              = json_extract_scalar(data, "$.system.load_avg_15m"),
  net_sent_mb                   = json_extract_scalar(data, "$.network.sent_mb"),
  net_recv_mb                   = json_extract_scalar(data, "$.network.recv_mb"),
  net_total_mb                  = json_extract_scalar(data, "$.network.total_mb"),
  eff_memory_efficiency         = json_extract_scalar(data, "$.efficiency.memory_efficiency"),
  eff_cpu_efficiency            = json_extract_scalar(data, "$.efficiency.cpu_efficiency"),
  eff_io_intensity              = json_extract_scalar(data, "$.efficiency.io_intensity"),
  eff_network_intensity         = json_extract_scalar(data, "$.efficiency.network_intensity"),
  trend_cpu_trend               = json_extract_scalar(data, "$.trends.cpu_trend"),
  trend_memory_trend            = json_extract_scalar(data, "$.trends.memory_trend"),
  trend_cpu_avg_10min           = json_extract_scalar(data, "$.trends.cpu_avg_10min"),
  trend_memory_avg_10min        = json_extract_scalar(data, "$.trends.memory_avg_10min"),
  trend_data_points             = json_extract_scalar(data, "$.trends.data_points"),
  alert_count_last_hour         = json_extract_scalar(data, "$.alert_count_last_hour"),
  monitoring_duration_minutes   = json_extract_scalar(data, "$.monitoring_duration_minutes");
