/* Largest Matched Files
   Surface the biggest files that triggered a YARA hit, where bulky payloads or packed binaries often hide.
   category: detection-depth */
dataset = yara_scanner_matches* | comp max(file_size) as bytes, count() as hits by filename, rule, hostname | sort desc bytes | limit 20 | view graph type = table header = "Largest Matched Files"
