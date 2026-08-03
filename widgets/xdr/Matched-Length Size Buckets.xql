/* Matched-Length Size Buckets
   Bucket matches by the byte length of the matched string to distinguish tiny signature hits from large-region matches.
   category: detection-depth */
dataset = yara_scanner_matches* | alter len_bucket = if(matched_length < 16, "01: <16B", matched_length < 64, "02: 16-64B", matched_length < 256, "03: 64-256B", matched_length < 1024, "04: 256B-1KB", "05: >=1KB") | comp count() as hits by len_bucket | sort asc len_bucket | view graph type = column header = "Matched-Length Size Buckets" xaxis = len_bucket yaxis = hits
