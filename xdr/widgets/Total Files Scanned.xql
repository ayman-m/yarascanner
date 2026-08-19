/* Total Files Scanned
   Single-value KPI summing files inspected across all completed and in-flight scans.
   category: alerts-and-kpis */
dataset = yara_scanner_scans* | comp sum(files_scanned) as total_files | view graph type = single header = "Files Scanned"
