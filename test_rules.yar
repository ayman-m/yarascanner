/*
    Test YARA rules for the YARA scanner.

    MatchCalc and MatchNotepad are designed to fire on the stock Windows
    calc.exe and notepad.exe binaries so the scanner pipeline can be
    validated end-to-end without staging real malware.

    The remaining eight rules are realistic-looking detection signatures
    (Mimikatz, Cobalt Strike, common ransomware indicators, etc.) that
    should not match on a clean system.
*/

rule MatchCalc
{
    meta:
        description = "Matches the Windows Calculator binary (test rule)"
        author      = "yarascanner-test"
        threat_level = "low"
        category    = "test"
    strings:
        $mz    = { 4D 5A }
        $calc1 = "CalcUtility" ascii wide nocase
        $calc2 = "Windows Calculator" ascii wide nocase
        $calc3 = "calc.exe" ascii wide nocase
    condition:
        $mz at 0 and any of ($calc*)
}

rule MatchNotepad
{
    meta:
        description = "Matches the Windows Notepad binary (test rule)"
        author      = "yarascanner-test"
        threat_level = "low"
        category    = "test"
    strings:
        $mz    = { 4D 5A }
        $np1   = "Notepad" ascii wide
        $np2   = "NPENCODINGDIALOG" ascii wide
        $np3   = "notepad.exe" ascii wide nocase
    condition:
        $mz at 0 and any of ($np*)
}

rule Mimikatz_Indicator
{
    meta:
        description  = "Detects strings commonly emitted by Mimikatz"
        author       = "yarascanner-test"
        threat_level = "high"
        category     = "credential_theft"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "gentilkiwi"               ascii nocase
        $s3 = "mimikatz"                 ascii nocase
        $s4 = "kerberos::list"           ascii nocase
    condition:
        any of them
}

rule CobaltStrike_Beacon_Generic
{
    meta:
        description  = "Generic Cobalt Strike beacon indicators"
        author       = "yarascanner-test"
        threat_level = "high"
        category     = "c2_framework"
    strings:
        $s1 = "beacon.dll"        ascii wide
        $s2 = "ReflectiveLoader"  ascii wide
        $s3 = "%%IMPORT%%"        ascii
        $s4 = "beacon_initialize" ascii
    condition:
        2 of them
}

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description  = "PowerShell launched with -EncodedCommand and hidden window"
        author       = "yarascanner-test"
        threat_level = "medium"
        category     = "scripting_abuse"
    strings:
        $ps   = "powershell"                  ascii wide nocase
        $enc  = "-EncodedCommand"             ascii wide nocase
        $hide = "-WindowStyle Hidden"         ascii wide nocase
        $np   = "-NoProfile"                  ascii wide nocase
    condition:
        $ps and ($enc or ($hide and $np))
}

rule Ransomware_Note_And_Extensions
{
    meta:
        description  = "Ransomware note plus encrypted-file extensions"
        author       = "yarascanner-test"
        threat_level = "high"
        category     = "ransomware"
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "All your files are encrypted"   ascii wide nocase
        $note3 = "send bitcoin to"                 ascii wide nocase
        $ext1  = ".locked"                          ascii wide
        $ext2  = ".crypt"                           ascii wide
        $ext3  = ".encrypted"                       ascii wide
    condition:
        any of ($note*) or 2 of ($ext*)
}

rule UPX_Packed_Binary
{
    meta:
        description  = "Binary packed with UPX"
        author       = "yarascanner-test"
        threat_level = "low"
        category     = "packer"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        2 of them
}

rule WebShell_PHP_Generic
{
    meta:
        description  = "Generic PHP webshell patterns"
        author       = "yarascanner-test"
        threat_level = "high"
        category     = "webshell"
    strings:
        $php  = "<?php"                       ascii
        $ep   = "eval($_POST"                 ascii
        $eg   = "eval($_GET"                  ascii
        $b64  = "base64_decode($_REQUEST"     ascii
        $sys  = "system($_REQUEST"            ascii
    condition:
        $php and 1 of ($ep, $eg, $b64, $sys)
}

rule LOLBin_Download_Abuse
{
    meta:
        description  = "Living-off-the-land binary used for remote download"
        author       = "yarascanner-test"
        threat_level = "medium"
        category     = "lolbin"
    strings:
        $cu = "certutil -urlcache -split -f" ascii nocase
        $rs = "regsvr32 /s /n /u /i:http"     ascii nocase
        $mh = "mshta http"                    ascii nocase
        $bp = "bitsadmin /transfer"           ascii nocase
    condition:
        any of them
}

rule PowerSploit_Empire_Indicator
{
    meta:
        description  = "PowerSploit / Empire / offensive PowerShell tooling"
        author       = "yarascanner-test"
        threat_level = "high"
        category     = "post_exploitation"
    strings:
        $s1 = "Invoke-Mimikatz"     ascii wide nocase
        $s2 = "PowerSploit"          ascii wide nocase
        $s3 = "Invoke-Empire"        ascii wide nocase
        $s4 = "Invoke-Obfuscation"   ascii wide nocase
        $s5 = "Invoke-DllInjection"  ascii wide nocase
    condition:
        any of them
}
