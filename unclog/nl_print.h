#pragma once

#include "nl_elf.h"

void nl_print(elf_osabi eo);
void nl_print(elf_type et);
void nl_print(elf_sec_type est);
void nl_print(elf_sec_flags esf);
void nl_print(elf_sym_bind esb);
void nl_print(elf_sym_type est);
void nl_print(elf_hdr32 const& h);
void nl_print(elf_prog_hdr32 const& p);
void nl_print(elf_section_hdr32 const& s, char const *sec_names);
void nl_print(elf_symbol32 const& s, char const *strtab);
