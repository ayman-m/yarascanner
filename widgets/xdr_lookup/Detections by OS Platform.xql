/* Detections by OS Platform
   Segment YARA matches across Windows/Linux/macOS to reveal which platform carries the most detection load.
   category: detection-depth */
dataset = yara_scanner_matches* | comp count() as hits, count_distinct(hostname) as endpoints by os_type | sort desc hits | view graph type = pie subtype = full header = "Detections by OS Platform" xaxis = os_type yaxis = hits
