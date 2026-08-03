/******************************************************************************************
D-Det08 — Top Matched Files (stacked by String) — fixed for visible stacks
Goal:
  Show the noisiest files (Top 5 by total hits) and, within each file, break down hits by
  matched `string`. Uses bubble "group packed" view to cluster per file.

Notes (per your original logic; no changes applied):
- Grain A: (file_name, string) → hits.
- Grain B: Top files by total_hits → inner-joined to restrict to Top 5 files.
- Final shape: keep `f` (file), `s` (string), `hits`, and `total_hits` for the chart.
- View is a bubble (group packed) with:
    xaxis      = s
    yaxis      = total_hits
    series     = f
    bubblerad  = s            
  Depending on your UI, a non-numeric `bubblerad` may render uniformly or cause a warning.

Steps:
  A) Count hits per (file_name, string)
  B) Compute Top 5 files by total_hits
  C) Keep only those files and project chart fields
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and file_name != null and string != null

/* A) Counts per (file, string) */
| comp count() as hits by file_name, string

/* B) Top-N files by total hits (inner-join to keep only these files) */
| join type = inner
  (
    dataset = yara_scans_raw
    | filter type = "yara_match" and file_name != null and string != null
    | comp count() as total_hits by file_name
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
