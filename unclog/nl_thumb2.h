#pragma once

#include "nl_stats.h"
#include "nl_thumb2_inst.h"
#include <vector>

struct elf;
struct elf_section_hdr32;
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
  u8 severity;
};

struct reg_mut_node {
  inst i;
  u16 par_idxs[3] = { 0xFFFFu, 0xFFFFu, 0xFFFFu };
};

struct func_log_call_analysis {
  explicit func_log_call_analysis(elf_symbol32 const& func_) : func(func_) {
    log_calls.reserve(64);
    reg_muts.reserve(1024);
    subs.reserve(128);
  }

  elf_symbol32 const& func;
  u32_vec subs;
  std::vector<reg_mut_node> reg_muts;
  std::vector<log_call> log_calls;
};

enum thumb2_analyze_func_ret {
  SUCCESS,
  ERR_RAN_OFF_END_OF_FUNC,
  ERR_INSTRUCTION_DECODE,
  ERR_SIMULATE_LOGIC_INCOMPLETE,
  ERR_UNKNOWN_LOG_CALL_STRATEGY,
};

thumb2_analyze_func_ret thumb2_analyze_func(
  elf const& e,
  elf_symbol32 const& func,
  elf_section_hdr32 const& nl_sec_hdr,
  std::vector<elf_symbol32 const*> const& log_funcs,
  u32_set const& noreturn_func_addrs,
  func_log_call_analysis& out_lca,
  analysis_stats& out_stats);

bool thumb2_patch_fmt_strs(elf const& e,
                           elf_section_hdr32 const& nl_sec_hdr,
                           byte* patched_elf,
                           std::vector<func_log_call_analysis> const& log_call_funcs,
                           u32_vec const& fmt_bin_addrs);
