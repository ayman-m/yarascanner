#!/usr/bin/env python3
"""Generate a battery of YARA rule files for comprehensive scanner testing.

Emits files into tests/yara_rules/ ranging from a single rule to 500 rules, and
covering every rule shape the scanner must handle: plain/wide/hex/regex strings,
pe/elf/math/hash modules, meta severity mapping, module auto-injection, deliberately
failing rules, unavailable-module (cuckoo) skip, condition-only rules, and external
variables. The matching rules target the seeded corpus (see seed_corpus.py) so scans
produce deterministic hits.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")
os.makedirs(OUT, exist_ok=True)

# Decoy strings that the seeded corpus contains — matching rules key off these.
DECOY = {
    "mimikatz": "sekurlsa::logonpasswords",
    "ransom": "YOUR FILES HAVE BEEN ENCRYPTED",
    "lolbin": "certutil -urlcache -split -f",
    "webshell": "eval($_POST",
    "powershell": "-EncodedCommand",
    "eicar": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
}


def w(name, body):
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body.strip() + "\n")
    nrules = body.count("rule ")
    print(f"  {name:32} ~{nrules} rule(s)")


# 1) single rule
w("01_single.yar", '''
rule Single_Mimikatz {
    meta:
        description = "one rule, matches the mimikatz decoy"
        threat_level = "high"
    strings:
        $s = "sekurlsa::logonpasswords" ascii nocase
    condition:
        $s
}
''')

# 2) string types: ascii/wide/nocase
w("02_string_types.yar", '''
rule Str_Ascii_Wide_Nocase {
    meta: threat_level = "medium"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $b = "send bitcoin to" ascii nocase
    condition:
        any of them
}
''')

# 3) hex / byte patterns (MZ, ELF magic, wildcards)
w("03_hex.yar", '''
rule Hex_MZ_Header { strings: $mz = { 4D 5A } condition: $mz at 0 }
rule Hex_ELF_Header { strings: $elf = { 7F 45 4C 46 } condition: $elf at 0 }
rule Hex_Wildcard { strings: $h = { 4D 5A ?? ?? 90 00 } condition: $h }
''')

# 4) regex
w("04_regex.yar", '''
rule Regex_Base64Cmd {
    strings:
        $re = /-Enc(odedCommand)?\\s+[A-Za-z0-9+\\/=]{20,}/ nocase
        $p  = "powershell" nocase
    condition:
        $p and $re
}
rule Regex_IPv4 { strings: $ip = /([0-9]{1,3}\\.){3}[0-9]{1,3}/ condition: #ip > 0 }
''')

# 5) wide (UTF-16) strings
w("05_wide.yar", '''
rule Wide_Notepad { strings: $n = "Notepad" wide condition: $n }
rule Wide_Secret  { strings: $s = "TOP-SECRET-WIDE-MARKER" wide condition: $s }
''')

# 6) pe module (Windows binaries)
w("06_module_pe.yar", '''
import "pe"
rule PE_Is_Executable { condition: pe.is_pe }
rule PE_Has_Imports { condition: pe.is_pe and pe.number_of_imports > 0 }
''')

# 7) elf module (Linux binaries)
w("07_module_elf.yar", '''
import "elf"
rule ELF_Is_Executable { condition: elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN }
rule ELF_Has_Sections { condition: elf.number_of_sections > 0 }
''')

# 8) math + hash modules (entropy / md5) — tests auto-injection too (no import line for math)
w("08_module_math_hash.yar", '''
import "hash"
rule High_Entropy_Region {
    condition:
        filesize > 64 and math.entropy(0, filesize) >= 7.2
}
rule Known_Hash_Placeholder {
    condition:
        filesize < 1048576 and hash.md5(0, filesize) == "00000000000000000000000000000000"
}
''')

# 9) meta severity mapping (low/medium/high -> XDR severity)
w("09_severity.yar", '''
rule Sev_Low    { meta: threat_level = "low"    strings: $s = "certutil -urlcache -split -f" condition: $s }
rule Sev_Medium { meta: threat_level = "medium" strings: $s = "-EncodedCommand" nocase condition: $s }
rule Sev_High   { meta: threat_level = "high"   strings: $s = "sekurlsa::logonpasswords" nocase condition: $s }
''')

# 10) condition-only rules (no strings)
w("10_condition_only.yar", '''
rule CondOnly_SmallFile { condition: filesize < 1024 }
rule CondOnly_Always    { condition: true }
''')

# 11) external variables (filename / filepath) — scanner exposes these
w("11_externals.yar", '''
rule Ext_TxtFile { condition: filename matches /\\.txt$/i }
rule Ext_InTemp  { condition: filepath contains "yara_corpus" }
''')

# 12) deliberately failing rules mixed with valid — tests failed_rules handling
w("12_mixed_failing.yar", '''
rule Valid_One { strings: $a = "eval($_POST" condition: $a }
rule Broken_MissingCondition { strings: $a = "x" }
rule Broken_BadField { import "pe" condition: pe.this_field_does_not_exist == 1 }
rule Valid_Two { strings: $b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $b }
''')

# 13) unavailable module (cuckoo) — should be skipped, not fail the whole set
w("13_cuckoo_skip.yar", '''
import "cuckoo"
rule Uses_Cuckoo { condition: cuckoo.network.http_request(/evil\\.example/) }
rule Plain_Alongside { strings: $s = "certutil -urlcache" condition: $s }
''')

# 14) a broad "realistic pack" (~30 rules, several match the corpus)
def realistic_pack(n_match=8, n_noise=22):
    parts = []
    matchers = [
        ('APT_Mimikatz', 'sekurlsa::logonpasswords', 'high'),
        ('Ransom_Note', 'YOUR FILES HAVE BEEN ENCRYPTED', 'high'),
        ('LOLBin_Certutil', 'certutil -urlcache -split -f', 'medium'),
        ('Webshell_PHP', 'eval($_POST', 'high'),
        ('PS_Encoded', '-EncodedCommand', 'medium'),
        ('EICAR', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', 'low'),
        ('CobaltStrike', 'ReflectiveLoader', 'high'),
        ('Kerberos_List', 'kerberos::list', 'high'),
    ]
    for i, (nm, s, sev) in enumerate(matchers[:n_match]):
        parts.append(f'rule Pack_M_{i}_{nm} {{ meta: threat_level = "{sev}" '
                     f'strings: $s = "{s}" ascii nocase condition: $s }}')
    for i in range(n_noise):
        parts.append(f'rule Pack_N_{i} {{ meta: threat_level = "low" '
                     f'strings: $a = "benign_marker_no_match_{i:04d}_zzz" condition: $a }}')
    return "\n".join(parts)

w("14_realistic_pack.yar", realistic_pack())

# 15) THE BIG ONE: 500 rules (compilation + perf-at-scale). ~20 match the corpus.
def big_pack(total=500, n_match=20):
    matchers = list(DECOY.values()) + ["ReflectiveLoader", "kerberos::list", "gentilkiwi",
                                        "mimikatz", "Invoke-Mimikatz", "beacon.dll",
                                        ".locked", "lsadump::sam", "privilege::debug",
                                        "FromBase64String", "regsvr32 /s /n /u /i:http",
                                        "mshta http", "bitsadmin /transfer", "cmd.exe /c start"]
    parts = []
    for i in range(n_match):
        s = matchers[i % len(matchers)]
        parts.append(f'rule Big_M_{i:04d} {{ meta: threat_level = "high" '
                     f'strings: $s = "{s}" ascii nocase condition: $s }}')
    for i in range(total - n_match):
        # multi-string noise rules that won't match the corpus
        parts.append(
            f'rule Big_N_{i:04d} {{ meta: threat_level = "low" '
            f'strings: $a = "noise_{i:05d}_alpha" $b = "noise_{i:05d}_beta" '
            f'condition: all of them }}')
    return "\n".join(parts)

w("15_big_500.yar", big_pack())

# 16 / 17) mid-scale packs (100 / 250 rules) for the compile-time performance curve
w("16_pack_100.yar", big_pack(total=100, n_match=10))
w("17_pack_250.yar", big_pack(total=250, n_match=15))

# 18) duplicate rule names — the scanner namespaces each rule, so dupes must not collide
w("18_dup_names.yar", '''
rule DupName { strings: $a = "sekurlsa::logonpasswords" nocase condition: $a }
rule DupName { strings: $a = "kerberos::list" nocase condition: $a }
rule DupName { strings: $a = "gentilkiwi" nocase condition: $a }
''')

# 19) one rule with many strings (string-count performance in a single rule)
def many_strings(n=200):
    strs = "\n".join(f'        $s{i} = "manystr_{i:04d}_marker"' for i in range(n))
    strs += '\n        $hit = "sekurlsa::logonpasswords" nocase'
    return f"rule Many_Strings {{\n    strings:\n{strs}\n    condition:\n        $hit or 3 of them\n}}"

w("19_many_strings.yar", many_strings())

# 20) rules that match NOTHING in the corpus (clean-scan / zero-detection path)
w("20_no_match.yar", '''
rule NoMatch_A { strings: $a = "this_string_is_not_in_the_corpus_aaaa" condition: $a }
rule NoMatch_B { strings: $b = "this_string_is_not_in_the_corpus_bbbb" condition: $b }
''')

print("done ->", OUT)
