/* Detection Hotspot Folders
   Rank the scan folders where matches cluster, exposing directories that concentrate suspicious files.
   category: detection-depth

   2026-08 grain change: rows became one per (rule, file) finding, not one per
   matched-string offset - hits summed match_count; unique_files (count_distinct) is
   unaffected by row grain.

   2026-08-20 v4 grain change: this widget lost its ONLY grouping key. v4 drops
   `scan_folder` from the matches row as scan-constant and therefore derivable, which is
   true - but it is derivable from the SCANS dataset, not from the matches row, so this is
   the one widget the v4 shape cannot serve on its own. The folder is recovered by joining
   yara_scanner_scans* on scan_id; that dataset still carries scan_folder and was
   deliberately left at its existing schema (it is ~2 rows / ~1.2 KB per scan, so it was
   never worth shrinking).

   Two things about that join a reader must know before editing it:
     - The subquery MUST `dedup scan_id`. The scans dataset holds a lifecycle row per state
       (initiated, completed, ...), so joining it raw multiplies every match row by the
       number of lifecycle rows its scan has - measured on this tenant, that inflated total
       hits from 12.1M to 39.7M, a silent ~3x overcount.
     - The joined column is renamed to `folder` inside the subquery. During the v3/v4
       overlap the left side still has its own `scan_folder` column, and this join merges
       columns UNQUALIFIED - an alias-qualified reference like s.scan_folder is rejected as
       an unknown field - so without the rename the two would collide.
   `type = inner` is deliberate: a match whose scan lifecycle rows have already been pruned
   cannot be attributed to a folder, and dropping it is more honest than bucketing it under
   null. On this tenant that costs ~0.4% of hits.

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
         point drop the if() and sum match_total directly. The join stays either way.
       - v2 shards contribute to unique_files but not to hits: their match_count is null and
         sum() skips nulls. Unchanged from v3 behaviour. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter hits_n = if(match_total = null, to_integer(match_count), match_total)
| join type = inner (dataset = yara_scanner_scans* | dedup scan_id | alter folder = scan_folder | fields scan_id, folder) as s s.scan_id = scan_id
| comp sum(hits_n) as hits, count_distinct(file_sha256) as unique_files by folder
| sort desc hits
| limit 15
| view graph type = bar header = "Detection Hotspot Folders" xaxis = folder yaxis = hits
