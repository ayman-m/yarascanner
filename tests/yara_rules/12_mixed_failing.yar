rule Valid_One { strings: $a = "eval($_POST" condition: $a }
rule Broken_MissingCondition { strings: $a = "x" }
rule Broken_BadField { import "pe" condition: pe.this_field_does_not_exist == 1 }
rule Valid_Two { strings: $b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $b }
