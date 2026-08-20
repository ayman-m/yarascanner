/**************************************************************************
  Severity Split

  Distribution of match severity.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  2026-08 grain change: rows became one per (rule, file) finding, not one per
  matched-string offset - hits summed match_count instead of counting rows.

  2026-08-20 v4 grain change: rows are now one per FILE. `severity` survives as a row
  column, but its MEANING changed and a reader must know this: on a v3 row it was that one
  finding's severity, whereas on a v4 row it is the HIGHEST severity across every rule that
  matched the file. So a file hit by both a Low rule and a High rule now contributes its
  whole match_total to High, where v3 split those hits between the two buckets. Today that
  is invisible - every rule inherits the scan's configured alert severity, so severity is
  scan-constant and the max is the same value - but it becomes a real skew toward the top
  bucket the moment per-rule severities differ. If you need the true per-rule split at that
  point, expand `rules` and read "$.severity" per element instead of using this row column.

  Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
  has copied a finding into its per-scan target but not yet removed it from the per-host
  source shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a
  constant - so it degenerates to (scan_id, hostname, filename), exactly a v4 row's
  identity; on a v3 row it is the full per-finding key.

  MIXED v3/v4 during rollout - read this before deploying:
    `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
    as null, but a column missing from EVERY shard in the union is a hard error
    ("unknown field match_total"). The if() below takes match_total on a v4 row and falls
    back to match_count on a v3 row. Therefore:
      - CANNOT run before the first v4 matches dataset exists (nothing defines match_total).
      - CANNOT run once the last v3 shard is pruned (nothing defines match_count); at that
        point drop the if() and sum match_total directly.
      - v2 shards contribute nothing: their match_count is null and sum() skips nulls.
**************************************************************************/
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter hits_n = if(match_total = null, to_integer(match_count), match_total)
| comp sum(hits_n) as hits by severity

| view graph type = pie subtype = donut header = "Matches by Severity" xaxis = severity yaxis = hits
