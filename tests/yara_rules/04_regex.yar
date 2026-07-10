rule Regex_Base64Cmd {
    strings:
        $re = /-Enc(odedCommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $p  = "powershell" nocase
    condition:
        $p and $re
}
rule Regex_IPv4 { strings: $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/ condition: #ip > 0 }
