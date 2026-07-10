import "elf"
rule ELF_Is_Executable { condition: elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN }
rule ELF_Has_Sections { condition: elf.number_of_sections > 0 }
