/* Unique Malicious Files per Rule
   Count distinct SHA-256 files behind each rule to separate broad-impact rules from single-file noise.
   category: detection-depth */
dataset = yara_scanner_matches* | comp count_distinct(file_sha256) as unique_files, count() as hits by rule | sort desc unique_files | limit 15 | view graph type = column header = "Unique Malicious Files per Rule" xaxis = rule yaxis = unique_files
