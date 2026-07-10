rule DupName { strings: $a = "sekurlsa::logonpasswords" nocase condition: $a }
rule DupName { strings: $a = "kerberos::list" nocase condition: $a }
rule DupName { strings: $a = "gentilkiwi" nocase condition: $a }
