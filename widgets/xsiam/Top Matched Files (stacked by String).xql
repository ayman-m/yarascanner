/******************************************************************************************
D-Det08 — Top Matched Files (stacked by String) — fixed for visible stacks
Goal:
  Show the noisiest files (Top 5 by total hits) and, within each file, break down hits by
  matched `string`. Uses bubble "group packed" view to cluster per file.

Notes:
- 2026-08 grain change: yara_match rows are one per (rule, file) finding, not one per
  matched-string instance. A finding's string list is a JSON array in `strings`, capped at
  50 samples (see `truncated` on the source row; match_count carries the true, uncapped total).
- Grain A (per-string breakdown) explodes that sample array back into one row per string, so
  its `hits` undercounts in absolute terms for any finding past the 50-sample cap - it's a
  same-caveat approximation as "Top Matched Strings".
- Grain B (which 5 files are noisiest) uses sum(match_count) instead, so file SELECTION stays
  exact even though the per-string breakdown within those files is a sample.
- Final shape: keep `f` (file), `s` (string), `hits`, and `total_hits` for the chart.
- View is a bubble (group packed) with:
    xaxis      = s
    yaxis      = total_hits
    series     = f
    bubblerad  = s
  Depending on your UI, a non-numeric `bubblerad` may render uniformly or cause a warning.

Steps:
  A) Explode the string sample and count hits per (file_name, string)
  B) Compute Top 5 files by TRUE total hits (sum of match_count)
  C) Keep only those files and project chart fields
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and file_name != null and strings != null

/* A) Explode the sampled strings array, then count per (file, string) */
| alter strings_arr = json_extract_array(strings, "$")
| arrayexpand strings_arr
| alter string = json_extract_scalar(strings_arr, "$")
| filter string != null
| comp count() as hits by file_name, string

/* B) Top-N files by TRUE total hits (inner-join to keep only these files) */
| join type = inner
  (
    dataset = yara_scans_raw
    | filter type = "yara_match" and file_name != null
    | comp sum(to_integer(match_count)) as total_hits by file_name
    | sort desc total_hits
    | limit 5
  ) as top_files file_name = top_files.file_name

/* C) Final shaping for the chart */
| alter f = file_name, s = string
| fields f, s, hits, total_hits   /* ensure chart has x, y, and series columns */
| sort desc total_hits

| view graph
    type = bubble subtype = grouppacked
    header = "Top Matched Files (stacked by String)"
    show_callouts_names = `true`
    xaxis = s
    yaxis = total_hits
    series = f
    bubblerad = s
    default_limit = `false`
