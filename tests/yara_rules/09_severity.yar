rule Sev_Low    { meta: threat_level = "low"    strings: $s = "certutil -urlcache -split -f" condition: $s }
rule Sev_Medium { meta: threat_level = "medium" strings: $s = "-EncodedCommand" nocase condition: $s }
rule Sev_High   { meta: threat_level = "high"   strings: $s = "sekurlsa::logonpasswords" nocase condition: $s }
