rule Wide_Notepad { strings: $n = "Notepad" wide condition: $n }
rule Wide_Secret  { strings: $s = "TOP-SECRET-WIDE-MARKER" wide condition: $s }
