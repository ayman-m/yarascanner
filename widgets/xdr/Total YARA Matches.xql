/* Total YARA Matches
   Single-value KPI of every matched YARA string across the fleet.
   category: alerts-and-kpis */
dataset = yara_scanner_matches* | comp count() as total_matches | view graph type = single header = "Total Matches"
