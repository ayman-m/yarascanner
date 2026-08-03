/* Detection Hotspot Folders
   Rank the scan folders where matches cluster, exposing directories that concentrate suspicious files.
   category: detection-depth */
dataset = yara_scanner_matches* | comp count() as hits, count_distinct(file_sha256) as unique_files by scan_folder | sort desc hits | limit 15 | view graph type = bar header = "Detection Hotspot Folders" xaxis = scan_folder yaxis = hits
