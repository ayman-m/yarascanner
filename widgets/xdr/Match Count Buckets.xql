/* Matched-Length Size Buckets
   Bucket findings by how many times their pattern matched, to distinguish a single
   incidental hit from a file saturated with a signature.
   category: detection-depth

   2026-08 grain change: yara_scanner_matches rows no longer carry a per-offset
   matched_length column at all - each row is now one (rule, file) finding, and the
   original byte-length-of-match data was dropped from the schema in that redesign (only a
   capped sample of the matched substrings themselves survives, in `strings`). There is no
   way to recover the original per-offset length distribution from what's stored, so this
   widget is repurposed to bucket by match_count (the true, uncapped per-finding hit
   count) instead of by matched-string byte length - the closest still-available signal
   for the same underlying question ("is this a trivial one-off match or a saturated
   file?"). Dedups by (scan_id, hostname, rule, filename) against the narrow window where
   consolidation has copied a finding into its per-scan target but not yet removed it from
   the per-host source shard. */
dataset = yara_scanner_matches*
| dedup scan_id, hostname, rule, filename
| alter mc = to_integer(match_count)
| alter hit_bucket = if(mc < 2, "01: 1 hit", mc < 5, "02: 2-4 hits", mc < 20, "03: 5-19 hits", mc < 100, "04: 20-99 hits", "05: >=100 hits")
| comp count() as findings by hit_bucket
| sort asc hit_bucket
| view graph type = column header = "Match Count Buckets" xaxis = hit_bucket yaxis = findings
