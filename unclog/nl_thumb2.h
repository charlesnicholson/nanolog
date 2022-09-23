#pragma once

#include "nl_thumb2_inst.h"
#include <vector>

struct elf;
struct elf_symbol32;

struct log_call {
  enum strategy_type : u8 { PC_RELATIVE_LOAD } t;
  u8 node_idx;
};

struct reg_mut_node {
  inst i;
  i8 par_idxs[3];
};

struct log_call_analysis {
  std::vector<reg_mut_node> reg_muts;
  std::vector<log_call> log_calls;
};

bool thumb2_analyze_func(elf const& e,
                         elf_symbol32 const& func,
                         std::vector<elf_symbol32 const*> const& log_funcs,
                         log_call_analysis& out_lca);

