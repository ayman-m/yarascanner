rule Pack_M_0_APT_Mimikatz { meta: threat_level = "high" strings: $s = "sekurlsa::logonpasswords" ascii nocase condition: $s }
rule Pack_M_1_Ransom_Note { meta: threat_level = "high" strings: $s = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase condition: $s }
rule Pack_M_2_LOLBin_Certutil { meta: threat_level = "medium" strings: $s = "certutil -urlcache -split -f" ascii nocase condition: $s }
rule Pack_M_3_Webshell_PHP { meta: threat_level = "high" strings: $s = "eval($_POST" ascii nocase condition: $s }
rule Pack_M_4_PS_Encoded { meta: threat_level = "medium" strings: $s = "-EncodedCommand" ascii nocase condition: $s }
rule Pack_M_5_EICAR { meta: threat_level = "low" strings: $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii nocase condition: $s }
rule Pack_M_6_CobaltStrike { meta: threat_level = "high" strings: $s = "ReflectiveLoader" ascii nocase condition: $s }
rule Pack_M_7_Kerberos_List { meta: threat_level = "high" strings: $s = "kerberos::list" ascii nocase condition: $s }
rule Pack_N_0 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0000_zzz" condition: $a }
rule Pack_N_1 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0001_zzz" condition: $a }
rule Pack_N_2 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0002_zzz" condition: $a }
rule Pack_N_3 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0003_zzz" condition: $a }
rule Pack_N_4 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0004_zzz" condition: $a }
rule Pack_N_5 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0005_zzz" condition: $a }
rule Pack_N_6 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0006_zzz" condition: $a }
rule Pack_N_7 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0007_zzz" condition: $a }
rule Pack_N_8 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0008_zzz" condition: $a }
rule Pack_N_9 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0009_zzz" condition: $a }
rule Pack_N_10 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0010_zzz" condition: $a }
rule Pack_N_11 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0011_zzz" condition: $a }
rule Pack_N_12 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0012_zzz" condition: $a }
rule Pack_N_13 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0013_zzz" condition: $a }
rule Pack_N_14 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0014_zzz" condition: $a }
rule Pack_N_15 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0015_zzz" condition: $a }
rule Pack_N_16 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0016_zzz" condition: $a }
rule Pack_N_17 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0017_zzz" condition: $a }
rule Pack_N_18 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0018_zzz" condition: $a }
rule Pack_N_19 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0019_zzz" condition: $a }
rule Pack_N_20 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0020_zzz" condition: $a }
rule Pack_N_21 { meta: threat_level = "low" strings: $a = "benign_marker_no_match_0021_zzz" condition: $a }
