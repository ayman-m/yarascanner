import "pe"
rule PE_Is_Executable { condition: pe.is_pe }
rule PE_Has_Imports { condition: pe.is_pe and pe.number_of_imports > 0 }
