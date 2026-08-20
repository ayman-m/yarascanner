/**************************************************************************
  Hot Hosts

  Endpoints with the most matches.

  Dataset(s): yara_scanner_matches. Lookup rows carry no _time; time-filter on
  event_timestamp_ms. tenant_id is present on every row for multi-tenant views.

  2026-08 grain change: rows became one per (rule, file) finding, not one per
  matched-string offset - hits summed match_count instead of counting rows.

  2026-08-20 v4 grain change: rows are now one per FILE and `match_count` no longer exists
  as a column; the file-level equivalent is match_total, the true total hits across every
  rule that matched the file. Grouping is by hostname, which is still a plain row column, so
  this needs no arrayexpand - summing the file-level match_total per host is both correct
  and cheaper than expanding `rules`.

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
| comp sum(hits_n) as hits by hostname
| sort desc hits
| limit 15

| view graph type = pie subtype = donut header = "Hot Hosts (Most Matches)" xaxis = hostname yaxis = hits
