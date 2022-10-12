#include "nl_thumb2.h"
#include "nl_thumb2_inst.h"
#include "nl_elf.h"

#include <cassert>
#include <stack>
#include <unordered_set>
#include <vector>

namespace {

struct reg_state {
  u32 regs[16];
  u32 cmp_imm_lits[16];
  u16 mut_node_idxs[16];
  u16 known = u16(1u << reg::PC);
  u16 cmp_imm_present = 0;
};

struct path_state {
  reg_state rs;
  std::unordered_set<u32> taken_branches;
};

using path_state_vec = std::vector<path_state>;
using path_state_stack = std::stack<path_state, path_state_vec>;

struct func_state {
  func_state(elf_symbol32 const& f_,
             elf const& e_,
             elf_section_hdr32 const& s,
             log_call_analysis& lca_)
    : f(f_)
    , e(e_)
    , lca(lca_)
    , func_start{f_.st_value & ~1u}
    , func_end{func_start + f.st_size}
    , func_ofs{s.sh_offset + func_start - s.sh_addr} {
    taken_branches_reg_states.reserve(64);
  }

  elf_symbol32 const& f;
  elf const& e;
  log_call_analysis& lca;
  path_state_stack paths;
  std::unordered_map<u32, std::vector<reg_state>> taken_branches_reg_states;
  unsigned const func_start, func_end, func_ofs;
};

path_state path_state_branch(path_state const& p, u32 label) {
  path_state b{p};
  b.rs.regs[reg::PC] = label;
  return b;
}

bool reg_states_equal(reg_state const& r1, reg_state const& r2) {
  if (r1.known != r2.known) { return false; }
  for (auto i{0u}; i < 16; ++i) {
    if ((r1.known & (1 << i)) && (r1.regs[i] != r2.regs[i])) { return false; }
  }
  return true;
}

void print(reg_state const& r) {
  for (auto i{0u}; i < 16; ++i) {
    if (r.known & (1u << i)) { NL_LOG_DBG("  R%d: %x ", int(i), r.regs[i]); }
  }
  NL_LOG_DBG("\n");
}

void print(std::unordered_set<u32> const& b) {
  NL_LOG_DBG("taken_branches: ");
  for (auto const i: b) { NL_LOG_DBG("%x ", i); }
  NL_LOG_DBG("\n");
}

bool address_in_func(u32 addr, func_state const& s) {
  return !s.f.st_size || ((addr >= s.func_start) && (addr <= s.func_end));
}

bool test_reg_known(u16 regs, u8 idx) { return (regs >> idx) & 1u; }
void mark_reg_known(u16& regs, u8 dst) { regs |= (1u << dst); }
void copy_reg_known(u16& regs, u8 dst, u8 src) {
  regs = u16(regs & ~(1u << dst)) | u16(((regs >> src) & 1u) << dst);
}

void union_reg_known(u16& regs, u8 dst, u8 src1, u8 src2) {
  u16 const u{u16(u16(regs >> src1) & u16(regs >> src2) & 1u)};
  regs = u16(regs & ~(1u << dst)) | u16(u << dst);
}

bool cmp_imm_lit_get(reg_state const& rs, u8 index, u32& out_lit) {
  out_lit = rs.cmp_imm_lits[index];
  return bool(rs.cmp_imm_present & (1 << index));
}

void cmp_imm_lit_set(reg_state& rs, u8 index, u32 lit) {
  rs.cmp_imm_lits[index] = lit;
  rs.cmp_imm_present |= (1 << index);
}

bool branch(u32 addr, path_state& p, func_state& s) {
  if (p.taken_branches.contains(addr)) { return false; }
  auto const it = s.taken_branches_reg_states.find(addr);
  if (it != s.taken_branches_reg_states.end()) {
    auto const& reg_states{it->second};
    auto const b{reg_states.begin()}, e{reg_states.end()};
    if (std::find_if(b,
                     e,
                     [&](auto const& rs) { return reg_states_equal(p.rs, rs); }) != e) {
      return false;
    }
  }

  p.taken_branches.insert(addr);
  auto [vi, inserted] = s.taken_branches_reg_states.insert({addr, {}});
  vi->second.push_back(p.rs);
  return true;
}

bool inst_terminates_path(inst const& i, func_state& s) {
  switch (i.type) {
    case inst_type::BRANCH:
      if (cond_code_is_always(i.i.branch.cc)) {
        if (!address_in_func(i.i.branch.addr, s)) { return true; }
      }
      break;

    case inst_type::BRANCH_XCHG: // BX ... (All BX are tail calls?)
      return true;

    case inst_type::POP: // POP { ..., PC }
      if (i.i.pop.reg_list & (1u << reg::PC)) { return true; }
      break;

    case inst_type::LOAD_IMM: // LDR PC, [..], #..
      if (i.i.load_imm.t == reg::PC) { return true; }
      break;

    case inst_type::LOAD_MULT_INC_AFTER: // LDMIA SP!, { ... PC }
      if (i.i.load_mult_inc_after.regs & (1u << reg::PC)) { return true; }
      break;

    case inst_type::LOAD_REG: // LDR PC, [...]
      if (i.i.load_reg.t == reg::PC) { return true; }

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

u32 table_branch(u32 addr, u32 sz, u32 base, u32 ofs, path_state& path, func_state& fs) {
  if (base != reg::PC) { return 4; }

  bool const will_take{branch(addr, path, fs)};

  u32 cmp_imm_lit;
  if (!cmp_imm_lit_get(path.rs, u8(ofs), cmp_imm_lit)) { return 0; }
  ++cmp_imm_lit;

  if (will_take) {
    unsigned const src_off{fs.func_ofs + (addr - fs.func_start) + 4};
    auto const *src{reinterpret_cast<unsigned char const *>(&fs.e.bytes[src_off])};

    for (auto i = 0u; i < cmp_imm_lit; ++i) {
      u32 val{*src++};
      if (sz == 2) { val = u32(val | u32(*src++ << 8u)); }
      u32 const label{path.rs.regs[reg::PC] + 4 + (val << 1u)};
      fs.paths.push(path_state_branch(path, label));
    }
  }

  u32 const table_size_pad{((cmp_imm_lit * sz) + 1u) & ~1u};
  return 4 + table_size_pad;
}

bool simulate(inst const& i, func_state& fs, path_state& path) {
  std::vector<reg_mut_node>& reg_muts{fs.lca.reg_muts};
  u32 len{i.len};

  switch (i.type) {
    case inst_type::LOAD_LIT:
      memcpy(&path.rs.regs[i.i.load_lit.t],
             &fs.e.bytes[fs.func_ofs + (i.i.load_lit.addr - fs.func_start)],
             4);
      mark_reg_known(path.rs.known, i.i.load_lit.t);
      reg_muts.push_back(reg_mut_node{.i = i});
      path.rs.mut_node_idxs[i.i.load_lit.t] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV_REG: {
      auto const& mov = i.i.mov_reg;
      path.rs.regs[mov.d] = path.rs.regs[mov.m];
      copy_reg_known(path.rs.known, mov.d, mov.m);
      reg_muts.push_back(reg_mut_node{.i = i, .par_idxs[0] = path.rs.mut_node_idxs[mov.m]});
      path.rs.mut_node_idxs[mov.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::MOV_IMM:
      path.rs.regs[i.i.mov_imm.d] = i.i.mov_imm.imm;
      mark_reg_known(path.rs.known, i.i.mov_imm.d);
      reg_muts.push_back(reg_mut_node{.i = i});
      path.rs.mut_node_idxs[i.i.mov_imm.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV_NEG_IMM: {
      auto const& mvn = i.i.mov_neg_imm;
      path.rs.regs[mvn.d] = ~u32(mvn.imm);
      mark_reg_known(path.rs.known, mvn.d);
      reg_muts.push_back(reg_mut_node{.i = i});
      path.rs.mut_node_idxs[mvn.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::ADD_IMM: {
      auto const& add = i.i.add_imm;
      path.rs.regs[add.d] = path.rs.regs[add.n] + add.imm;
      copy_reg_known(path.rs.known, add.d, add.n);
      reg_muts.push_back(
        reg_mut_node{.i = i, .par_idxs[0] = path.rs.mut_node_idxs[add.n]});
      path.rs.mut_node_idxs[add.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::ADD_REG: {
      auto const& add = i.i.add_reg;
      path.rs.regs[add.d] = path.rs.regs[add.n] + path.rs.regs[add.m];
      union_reg_known(path.rs.known, add.d, add.m, add.n);
      reg_muts.push_back(
        reg_mut_node{.i = i, .par_idxs[0] = path.rs.mut_node_idxs[add.n],
          .par_idxs[1] = path.rs.mut_node_idxs[add.m]});
      path.rs.mut_node_idxs[add.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::CMP_IMM:
      cmp_imm_lit_set(path.rs, i.i.cmp_imm.n, i.i.cmp_imm.imm);
      break;

    case inst_type::SUB_IMM: {
      auto const& sub = i.i.sub_imm;
      path.rs.regs[sub.d] = path.rs.regs[sub.n] - sub.imm;
      copy_reg_known(path.rs.known, sub.d, sub.n);
      reg_muts.push_back(
        reg_mut_node{.i = i, .par_idxs[0] = path.rs.mut_node_idxs[sub.n]});
      path.rs.mut_node_idxs[sub.d] = u16(reg_muts.size() - 1u);
    } break;


    case inst_type::TABLE_BRANCH_HALF: {
      auto const& tbh = i.i.table_branch_half;
      len = table_branch(i.addr, 2, tbh.n, tbh.m, path, fs);
      if (!len) { printf("TBH failure\n"); }
    } break;

    case inst_type::TABLE_BRANCH_BYTE: {
      auto const& tbb = i.i.table_branch_byte;
      len = table_branch(i.addr, 1, tbb.n, tbb.m, path, fs);
      if (!len) { printf("TBB failure\n"); }
    } break;

    default: break;
  }

  path.rs.regs[reg::PC] += len;
  return bool(len);
}

}

bool thumb2_analyze_func(elf const& e,
                         elf_symbol32 const& func,
                         std::vector<elf_symbol32 const*> const& log_funcs,
                         log_call_analysis& out_lca) {
  func_state s{func, e, e.sec_hdrs[func.st_shndx], out_lca};
  out_lca.reg_muts.reserve(256);

  NL_LOG_DBG("\nScanning %s: addr %x, len %x, range %x-%x, offset %x:\n", &e.strtab[func.st_name],
    func.st_value, func.st_size, s.func_start, s.func_end, s.func_ofs);

  s.paths.push(path_state{.rs{.regs[reg::PC] = s.func_start}});

  while (!s.paths.empty()) {
    path_state path{s.paths.top()};
    s.paths.pop();

    NL_LOG_DBG("  Starting path\n");
    //print(path);

    for (;;) {
      if (func.st_size && (path.rs.regs[reg::PC] >= s.func_end)) {
        NL_LOG_DBG("  Stopping path: Ran off the end!\n");
        break;
      }

      inst pc_i;
      bool const decode_ok = inst_decode(&e.bytes[s.func_ofs], s.func_start,
        path.rs.regs[reg::PC] - s.func_start, pc_i);

      NL_LOG_DBG("    %x: %04x ", path.rs.regs[reg::PC], pc_i.w0);
      if (pc_i.len == 2) { NL_LOG_DBG("       "); } else { NL_LOG_DBG("%04x   ", pc_i.w1); }
      inst_print(pc_i);
      NL_LOG_DBG("\n");

      if (!decode_ok) {
        NL_LOG_DBG("  Stopping path: Unknown instruction!\n");
        break;
      }

      if (inst_is_log_call(pc_i, log_funcs)) {
        if (!test_reg_known(path.rs.known, reg::R0)) {
          NL_LOG_DBG("  Found log function, R0 is unknown\n");
          break;
        }

        auto [it, inserted] = out_lca.log_calls.insert({path.rs.regs[reg::R0],
          log_call{ .fmt_str_addr = path.rs.regs[reg::R0], .log_func_call_addr = pc_i.addr,
            .node_idx = path.rs.mut_node_idxs[reg::R0] }});

        if (!inserted) {
          NL_LOG_DBG("  Found log function, already discovered\n");
          break;
        }

        NL_LOG_DBG("  Found log function, format string 0x%08x\n", path.rs.regs[reg::R0]);
        inst const& r0_i = s.lca.reg_muts[path.rs.mut_node_idxs[reg::R0]].i;
        switch (r0_i.type) {
          case inst_type::LOAD_LIT:
            it->second.s = fmt_str_strat::DIRECT_LOAD;
            break;

          case inst_type::MOV_REG:
            it->second.s = fmt_str_strat::MOV_FROM_DIRECT_LOAD;
            break;

          case inst_type::ADD_IMM:
            it->second.s = fmt_str_strat::ADD_IMM_FROM_BASE_REG;
            break;

          default:
            NL_LOG_DBG("Unrecognized pattern!\n***\n");
            inst_print(r0_i);
            NL_LOG_DBG("\n***\n");
            break;
        }
      }

      if (inst_terminates_path(pc_i, s)) {
        NL_LOG_DBG("  Stopping path: terminal pattern\n");
        break;
      }

      u32 label;
      if (inst_is_conditional_branch(pc_i, label) && address_in_func(label, s)) {
        if (branch(pc_i.addr, path, s)) {
          NL_LOG_DBG("  Internal branch, pushing state\n");
          s.paths.push(path_state_branch(path, label));
        }
      }

      if (inst_is_goto(pc_i, label) && address_in_func(label, s)) {
        if (branch(pc_i.addr, path, s)) {
          path.rs.regs[reg::PC] = label;
          continue;
        }
        NL_LOG_DBG("  Stopping path: revisiting unconditional branch\n");
        break;
      }

      if (!simulate(pc_i, s, path)) { return false; }

      if (inst_is_table_branch(pc_i)) { break; }
    }
  }

  return true;
}

char const *fmt_str_strat_name(fmt_str_strat s) {
#define X(NAME) case fmt_str_strat::NAME: return #NAME;
  switch (s) { FMT_STR_STRAT_LIST() default: return "unknown"; }
#undef X
}

