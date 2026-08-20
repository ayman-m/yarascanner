/* Matched-Length Size Buckets
   Bucket findings by how many times their pattern matched, to distinguish a single
   incidental hit from a file saturated with a signature.
   category: detection-depth

   2026-08 grain change: yara_scanner_matches rows stopped carrying a per-offset
   matched_length column - each row became one (rule, file) finding, and the original
   byte-length-of-match data was dropped from the schema in that redesign. There is no way
   to recover the original per-offset length distribution from what is stored, so this
   widget was repurposed to bucket by match_count (the true, uncapped per-finding hit count)
   instead of by matched-string byte length - the closest still-available signal for the
   same underlying question ("is this a trivial one-off match or a saturated file?").

   2026-08-20 v4 grain change: rows are now one per FILE and `match_count` no longer exists
   as a column. The question this widget asks is still a PER-FINDING one - a single rule's
   saturation of a single file - so it must expand `rules` and bucket on each element's own
   match_count. Do NOT bucket on the row's match_total: that is the file's total across all
   its rules, so a file matched once each by three rules would land in the "3 hits" bucket
   as though one rule had hit it three times, quietly inflating the saturated end of the
   histogram in proportion to how many rules the pack contains. `findings` therefore counts
   expanded elements, which is the same unit this widget counted under v3.

   Dedup key (scan_id, hostname, filename, rule) still guards the window where consolidation
   has copied a finding into its per-scan target but not yet removed it from the per-host
   source shard. That key is correct for BOTH generations: on a v4 row `rule` is null - a
   constant - so it degenerates to (scan_id, hostname, filename), exactly a v4 row's
   identity; on a v3 row it is the full per-finding key. It must run BEFORE arrayexpand:
   after expansion many rows share (scan_id, hostname, filename), so deduping then would
   collapse the fan-out and drop findings straight out of the histogram.

   MIXED v3/v4 during rollout - read this before deploying:
     `yara_scanner_matches*` spans both generations. A column missing from SOME shard reads
     as null, but a column missing from EVERY shard in the union is a hard error
     ("unknown field rules"). So the if() below synthesises a one-element array from a v3
     row's own rule/match_count and expands whichever shape the row actually has. Therefore:
       - CANNOT run before the first v4 matches dataset exists (nothing defines `rules`).
       - CANNOT run once the last v3 shard is pruned (nothing defines `rule`/`match_count`);
         at that point delete the if() bridge and use `rules` directly.
       - v2 shards drop out: their match_count is null, so the synthesised JSON is malformed
         and arrayexpand discards the row. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, filename, rule
| alter rules_json = if(rules = null, concat("[{\"rule\":\"", rule, "\",\"match_count\":", to_string(match_count), "}]"), rules)
| alter rule_obj = json_extract_array(rules_json, "$")
| arrayexpand rule_obj
| alter mc = to_integer(json_extract_scalar(rule_obj, "$.match_count"))
| alter hit_bucket = if(mc < 2, "01: 1 hit", mc < 5, "02: 2-4 hits", mc < 20, "03: 5-19 hits", mc < 100, "04: 20-99 hits", "05: >=100 hits")
| comp count() as findings by hit_bucket
| sort asc hit_bucket
| view graph type = column header = "Match Count Buckets" xaxis = hit_bucket yaxis = findings
