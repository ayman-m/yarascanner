/******************************************************************************************
D-Det07 — Top Matched Strings
Goal:
  Rank the most frequently matched YARA strings and provide context on spread:
    - hits  = total match count for the string
    - rules = how many distinct rules reference that string
    - hosts = how many distinct endpoints saw that string

Notes:
  - Logic unchanged; formatting & documentation only.
  - Keeps raw engine string identifier as-is (case preserved).
******************************************************************************************/
dataset = yara_scans_raw
| filter type = "yara_match" and string != null
| alter s = string  /* raw match identifier from engine; case kept as-is */
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
