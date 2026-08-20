/* Total YARA Matches
   Single-value KPI of every matched YARA string across the fleet.
   category: alerts-and-kpis

   2026-08 grain change: rows became one per (rule, file) finding, not one per
   matched-string offset. match_count carried the true per-finding total, so this summed
   match_count instead of counting rows - counting rows would report finding count, not
   match count.

   2026-08-20 v4 grain change: rows are now one per FILE and `match_count` no longer exists
   as a column. The file-level equivalent is match_total, the true total string hits across
   every rule that matched the file. This widget needs no arrayexpand - it wants the fleet
   total, and summing the file-level match_total gives exactly that, more cheaply than
   expanding `rules` and summing each element.

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the per-host
   source shard, so a query across both would otherwise double-count it. That key is correct
   for BOTH generations: on a v4 row `rule` is null - a constant - so it degenerates to
   (scan_id, hostname, filename), exactly a v4 row's identity; on a v3 row it is the full
   per-finding key, which is what keeps every finding of a multi-rule file summing
   separately.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field match_total"). The if() below takes the file-level match_total on a v4
     row and falls back to the per-finding match_count on a v3 row; both sum to the same
     fleet total. Therefore:
       - CANNOT run before the first v4 matches dataset exists (nothing defines
         match_total). Deploy after the first v4 scan lands.
       - CANNOT run once the last v3 shard is pruned (nothing defines match_count); at that
         point drop the if() and sum match_total directly.
       - v2 shards contribute nothing: their match_count is null and sum() skips nulls.
         Unchanged from v3 behaviour. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter hits_n = if(match_total = null, to_integer(match_count), match_total)
| comp sum(hits_n) as total_matches
| view graph type = single header = "Total Matches"
