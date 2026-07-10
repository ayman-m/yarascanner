rule Str_Ascii_Wide_Nocase {
    meta: threat_level = "medium"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $b = "send bitcoin to" ascii nocase
    condition:
        any of them
}
