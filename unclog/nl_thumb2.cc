#include "nl_thumb2.h"
#include "nl_thumb2_inst.h"
#include "nl_elf.h"

#include <cassert>
#include <stack>
#include <vector>

struct reg_state {
  u16 known;
  u32 regs[16];
  u16 reg_node_idxs[16];
};

struct func_state {
  func_state(elf_symbol32 const& f_,
             elf const& e_,
             elf_section_hdr32 const& s,
             log_call_analysis& lca_)
    : f(f_)
    , e(e_)
    , lca(lca_)
    , visited(s.sh_size / 2)
    , func_start{f_.st_value & ~1u}
    , func_end{func_start + f.st_size}
    , func_ofs{s.sh_offset + func_start - s.sh_addr} {}

  elf_symbol32 const& f;
  elf const& e;
  log_call_analysis& lca;
  std::vector<bool> visited; // i know i know
  std::stack<reg_state, std::vector<reg_state>> paths;
  unsigned const func_start, func_end, func_ofs;
};

char const *fmt_str_strat_name(fmt_str_strat s) {
#define X(NAME) case fmt_str_strat::NAME: return #NAME;
  switch (s) { FMT_STR_STRAT_LIST() default: return "unknown"; }
#undef X
}

namespace {

bool address_in_func(u32 addr, func_state const& s) {
  return (addr >= s.func_start) && (addr <= s.func_end);
}

void mark_visited(u32 addr, func_state& s) { s.visited[(addr - s.func_start) / 2] = true; }

bool test_visited(u32 addr, func_state const& s) {
  return s.visited[(addr - s.func_start) / 2];
}

inline bool test_reg_known(u16 regs, u8 index) { return (regs >> index) & 1u; }
inline void mark_reg_known(u16& regs, u8 index) { regs |= (1u << index); }

inline void copy_reg_known(u16& regs, u8 dst_index, u8 src_index) {
  regs = u16(regs & ~(1u << dst_index)) | u16(((regs >> src_index) & 1u) << dst_index);
}

bool inst_terminates_path(inst const& i, func_state& s) {
  switch (i.type) {
    case inst_type::BRANCH:
      if (cond_code_is_always(i.i.branch.cc)) {
        if (!address_in_func(i.i.branch.addr, s)) { return true; }
        return test_visited(i.i.branch.addr, s);
      }
      break;

    case inst_type::BRANCH_XCHG: // BX LR
      if (i.i.branch_xchg.m == reg::LR) { return true; }
      break;

    case inst_type::POP: // POP { ..., PC }
      if (i.i.pop.reg_list & (1u << reg::PC)) { return true; }
      break;

    case inst_type::LOAD_IMM: // LDR PC, [..], #..
      if (i.i.load_imm.t == reg::PC) { return true; }
      break;

    case inst_type::LOAD_MULT_INC_AFTER: // LDMIA SP!, { ... PC }
      if (i.i.load_mult_inc_after.regs & (1u << reg::PC)) { return true; }
      break;

    case inst_type::LOAD_LIT: // LDR PC, [PC, #x]
      // TODO: implement
      break;

    default: break;
  }

  return false;
}

bool inst_is_log_call(inst const& i, std::vector<elf_symbol32 const*> const& log_funcs) {
  u32 label;
  if (!inst_is_unconditional_branch(i, label)) { return false; }
  return std::find_if(std::begin(log_funcs), std::end(log_funcs),
    [=](elf_symbol32 const *cand) { return (cand->st_value & ~1u) == label; })
    != std::end(log_funcs);
}

void simulate(inst const& i, func_state& fs, reg_state& regs) {
  std::vector<reg_mut_node>& reg_muts = fs.lca.reg_muts;

  switch (i.type) {
    case inst_type::LOAD_LIT:
      memcpy(&regs.regs[i.i.load_lit.t],
             &fs.e.bytes[fs.func_ofs + (i.i.load_lit.addr - fs.func_start)],
             4);
      mark_reg_known(regs.known, i.i.load_lit.t);
      reg_muts.push_back(reg_mut_node{.i = i});
      regs.reg_node_idxs[i.i.load_lit.t] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV:
      regs.regs[i.i.mov.d] = regs.regs[i.i.mov.m];
      copy_reg_known(regs.known, i.i.mov.d, i.i.mov.m);
      reg_muts.push_back(reg_mut_node{.i = i, .par_idxs[0] = regs.reg_node_idxs[i.i.mov.m]});
      regs.reg_node_idxs[i.i.mov.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::ADD_IMM:
      regs.regs[i.i.add_imm.d] = regs.regs[i.i.add_imm.n] + i.i.add_imm.imm;
      copy_reg_known(regs.known, i.i.add_imm.d, i.i.add_imm.n);
      reg_muts.push_back(
        reg_mut_node{.i = i, .par_idxs[0] = regs.reg_node_idxs[i.i.add_imm.n]});
      regs.reg_node_idxs[i.i.add_imm.d] = u16(reg_muts.size() - 1u);

    default: break;
  }
}
}

bool thumb2_analyze_func(elf const& e,
                         elf_symbol32 const& func,
                         std::vector<elf_symbol32 const*> const& log_funcs,
                         log_call_analysis& out_lca) {
  func_state s{func, e, e.sec_hdrs[func.st_shndx], out_lca};
  out_lca.reg_muts.reserve(256);

  printf("\nScanning %s: addr %x, len %x, range %x-%x, offset %x:\n", &e.strtab[func.st_name],
    func.st_value, func.st_size, s.func_start, s.func_end, s.func_ofs);

  s.paths.push(reg_state{.regs[reg::PC] = s.func_start, .known = 0u});

  while (!s.paths.empty()) {
    reg_state path{s.paths.top()};
    s.paths.pop();
    printf("  Starting path\n");

    for (;;) {
      if (func.st_size && (path.regs[reg::PC] >= s.func_end)) {
        printf("  Stopping path: Ran off the end!\n");
        break;
      }

      inst pc_i;
      bool const decode_ok = inst_decode(&e.bytes[s.func_ofs], s.func_start,
        path.regs[reg::PC] - s.func_start, pc_i);

      printf("    %x: %04x ", path.regs[reg::PC], pc_i.w0);
      if (pc_i.len == 2) { printf("       "); } else { printf("%04x   ", pc_i.w1); }
      inst_print(pc_i);
      printf("\n");

      if (!decode_ok) {
        printf("  Stopping path: Unknown instruction!\n");
        break;
      }

      mark_visited(path.regs[reg::PC], s);

      if (inst_terminates_path(pc_i, s)) {
        printf("  Stopping path: terminal pattern\n");
        break;
      }

      u32 label;
      if (inst_is_conditional_branch(pc_i, label) &&
          address_in_func(label, s) &&
          !test_visited(label, s)) {
        printf("  Internal branch, pushing state\n");
        s.paths.push(reg_state{.regs[reg::PC] = label});
      } else if (inst_is_log_call(pc_i, log_funcs)) {
        if (!test_reg_known(path.known, reg::R0)) {
          printf("  Found log function, R0 is unknown\n");
          break;
        }

        printf("  Found log function, format string 0x%08x\n", path.regs[reg::R0]);
        inst const& r0_i = s.lca.reg_muts[path.reg_node_idxs[reg::R0]].i;
        switch (r0_i.type) {
          case inst_type::LOAD_LIT:
            out_lca.log_calls.push_back(log_call{
              .fmt_str_addr = path.regs[reg::R0],
              .log_func_call_addr = pc_i.addr,
              .node_idx = path.reg_node_idxs[reg::R0],
              .s = fmt_str_strat::DIRECT_LOAD });
            break;

          case inst_type::MOV:
            out_lca.log_calls.push_back(log_call{
              .fmt_str_addr = path.regs[reg::R0],
              .log_func_call_addr = pc_i.addr,
              .node_idx = path.reg_node_idxs[reg::R0],
              .s = fmt_str_strat::MOV_FROM_DIRECT_LOAD });
            break;

          default:
            printf("Unrecognized pattern!\n"); break;
        }
      } else {
        simulate(pc_i, s, path);
      }

      path.regs[reg::PC] += pc_i.len;
    }
  }
  return true;
}
