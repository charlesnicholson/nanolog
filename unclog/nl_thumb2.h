#pragma once

#include "nl_stats.h"
#include "nl_thumb2_inst.h"
#include <unordered_map>
#include <vector>

struct elf;
struct elf_symbol32;

#define FMT_STR_STRAT_LIST() \
  X(DIRECT_LOAD) \
  X(MOV_FROM_DIRECT_LOAD) \
  X(ADD_IMM_FROM_BASE_REG)

#define X(NAME) NAME,
enum class fmt_str_strat: u8 { FMT_STR_STRAT_LIST() };
#undef X

char const *fmt_str_strat_name(fmt_str_strat s);

struct log_call {
  u32 fmt_str_addr;
  u32 log_func_call_addr;
  u16 node_idx;
  fmt_str_strat s;
};

struct reg_mut_node {
  inst i;
  u16 par_idxs[3] = { 0xFFFFu, 0xFFFFu, 0xFFFFu };
};

struct func_log_call_analysis {
  explicit func_log_call_analysis(elf_symbol32 const& func_) : func(func_) {}
  elf_symbol32 const& func;
  std::vector<reg_mut_node> reg_muts;
  std::unordered_map<u32, log_call> log_calls; // fmt str addr -> log_call
};

bool thumb2_analyze_func(elf const& e,
                         elf_symbol32 const& func,
                         std::vector<elf_symbol32 const*> const& log_funcs,
                         func_log_call_analysis& out_lca,
                         analysis_stats& out_stats);

