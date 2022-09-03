#pragma once

struct elf;
struct elf_symbol32;

bool thumb2_find_log_strs_in_func(elf const& e,
                                  elf_symbol32 const& func);
