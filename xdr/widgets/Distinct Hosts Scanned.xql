/* Distinct Hosts Scanned
   Fleet-wide KPI of how many unique endpoints the scanner has ever touched.
   category: fleet-coverage */
dataset = yara_scanner_scans* | comp count_distinct(hostname) as hosts_scanned | view graph type = single header = "Distinct Hosts Scanned"
