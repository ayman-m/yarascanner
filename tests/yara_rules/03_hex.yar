rule Hex_MZ_Header { strings: $mz = { 4D 5A } condition: $mz at 0 }
rule Hex_ELF_Header { strings: $elf = { 7F 45 4C 46 } condition: $elf at 0 }
rule Hex_Wildcard { strings: $h = { 4D 5A ?? ?? 90 00 } condition: $h }
