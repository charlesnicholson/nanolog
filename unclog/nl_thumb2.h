#pragma once

#include "nl_types.h"
#include <vector>

struct elf;
struct elf_symbol32;

struct log_call {
  u32 call_inst_addr, log_func_addr;

  enum strategy_type {
    PC_RELATIVE_LOAD,
  };

  strategy_type t;
  union {
    struct pc_rel_load {
      u32 load_inst_addr, fmt_str_addr_addr;
    } pc_rel_load;
  } s;
};

bool thumb2_find_log_calls_in_func(elf const& e,
                                   elf_symbol32 const& func,
                                   std::vector<elf_symbol32 const*> const& log_funcs,
                                   std::vector<log_call>& out_log_calls);
