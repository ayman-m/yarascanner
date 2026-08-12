/**************************************************************************
  Consolidation Run Health

  One row per completed YaraConsolidateApply pass (the XSOAR playbook's
  mutating step, meant to run twice daily as a scheduled Job) - status is
  success / partial_failure / crashed, plus how many scans were
  consolidated or failed that pass.

  This is the only tenant-visible signal for whether the consolidation
  pipeline itself is healthy. Task 8 ("Flag failures for attention") in
  playbook-YARA_Dataset_Consolidation.yml only writes to that one run's own
  ephemeral XSOAR investigation context - nothing else reads it, and a
  total execution crash (task 1/4/6 erroring before task 8 is ever
  reached) bypasses it entirely. This dataset and widget cover both cases.

  Dataset(s): yara_scanner_consolidation_runs. Lookup rows carry no _time;
  read run_time (derived from run_ts_ms) instead. No row in the last ~24h
  (roughly 2x the twice-daily schedule interval) means the Job did not
  complete a pass recently - check the Job's own run history, since a
  crash before task 8 leaves no "needs attention" flag either.
**************************************************************************/
dataset = yara_scanner_consolidation_runs*
| sort desc run_ts_ms
| alter run_time = to_timestamp(run_ts_ms, "MILLIS")
| fields run_time, status, consolidated_count, failed_count, failed_scan_ids, error_message
| limit 20

| view graph type = table header = "Consolidation Run Health"
