/* Scans by OS Type
   Distinct scans segmented by operating system to show platform coverage balance.
   category: fleet-coverage */
dataset = yara_scanner_scans* | sort desc event_timestamp_ms | dedup scan_id | comp count() as scans by os_type | sort desc scans | view graph type = pie subtype = full header = "Scans by OS Type" xaxis = os_type yaxis = scans
