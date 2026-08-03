/* Distinct Rules Fired
   Single-value KPI of how many unique YARA rules produced at least one match.
   category: alerts-and-kpis */
dataset = yara_scanner_matches* | comp count_distinct(rule) as distinct_rules | view graph type = single header = "Rules Fired"
