/* Total Scans Run
   Single-value KPI counting distinct scan lifecycles executed fleet-wide.
   category: alerts-and-kpis */
dataset = yara_scanner_scans* | comp count_distinct(scan_id) as total_scans | view graph type = single header = "Total Scans"
