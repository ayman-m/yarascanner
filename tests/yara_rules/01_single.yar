rule Single_Mimikatz {
    meta:
        description = "one rule, matches the mimikatz decoy"
        threat_level = "high"
    strings:
        $s = "sekurlsa::logonpasswords" ascii nocase
    condition:
        $s
}
