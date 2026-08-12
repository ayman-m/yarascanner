/******************************************************************************************
D-Det07 — Top Matched Strings
Goal:
  Rank the most frequently matched YARA strings and provide context on spread:
    - hits  = match count for the string (see caveat below)
    - rules = how many distinct rules reference that string
    - hosts = how many distinct endpoints saw that string

2026-08 grain change: yara_match rows are now one per (rule, file) finding, not one per
matched-string instance. A finding's full string list no longer exists as one string per
row - it's a JSON array in the `strings` field, capped at 50 samples per finding (the same
cap applied at upload time; see `truncated` on the source row). This widget explodes that
sample array back into one row per string, so `hits` here is "how often this string appeared
across the first 50 samples of each finding" - a good relative ranking, but an undercount in
absolute terms for any finding with more than 50 true hits (match_count on that finding will
be higher). There is no way to get an exact count broken out by literal string text post-grain
-change without re-widening the upload; match_ids on the source row gives an EXACT count, but
keyed by the rule's internal string identifier (e.g. "$ps"), not the literal matched text.
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and strings != null
| alter strings_arr = json_extract_array(strings, "$")
| arrayexpand strings_arr
| alter s = json_extract_scalar(strings_arr, "$")  /* one exploded string sample per row; case kept as-is */
| filter s != null
| comp
    count()                          as hits,
    count_distinct(rule_id)          as rules,        /* how many rules use this string */
    count_distinct(hostname)         as hosts         /* how many endpoints saw it */
  by s
| sort desc hits
| limit 20

| view graph
    type = column subtype = stacked layout = horizontal
    header = "Top Matched Strings"
    show_callouts_names = `true`
    xaxis = s
    yaxis = hosts,hits
    seriescolor("hosts","#dd0236")
    seriescolor("hits","#0031c1")
    headcolor = "#0f0f10"
