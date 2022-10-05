#include "nl_thumb2.h"
#include "nl_thumb2_inst.h"
#include "nl_elf.h"

#include <cassert>
#include <stack>
#include <vector>

struct reg_state {
  u32 regs[16];
  u32 cmp_imm_lits[16];
  u16 mut_node_idxs[16];
  u16 known = 0;
  u16 cmp_imm_present = 0;
};

reg_state reg_state_branch(reg_state const& r, u32 label) {
  reg_state b{r};
  b.regs[reg::PC] = label;
  return b;
}

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
  return !s.f.st_size || ((addr >= s.func_start) && (addr <= s.func_end));
}

void mark_visited(u32 addr, func_state& s) { s.visited[(addr - s.func_start) / 2] = true; }

bool test_visited(u32 addr, func_state const& s) {
  return s.visited[(addr - s.func_start) / 2];
}

bool test_reg_known(u16 regs, u8 index) { return (regs >> index) & 1u; }
void mark_reg_known(u16& regs, u8 index) { regs |= (1u << index); }
void copy_reg_known(u16& regs, u8 dst_index, u8 src_index) {
  regs = u16(regs & ~(1u << dst_index)) | u16(((regs >> src_index) & 1u) << dst_index);
}

bool cmp_imm_lit_get(reg_state const& rs, u8 index, u32& out_lit) {
  out_lit = rs.cmp_imm_lits[index];
  return bool(rs.cmp_imm_present & (1 << index));
}

void cmp_imm_lit_set(reg_state& rs, u8 index, u32 lit) {
  rs.cmp_imm_lits[index] = lit;
  rs.cmp_imm_present |= (1 << index);
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

u32 table_branch(u32 addr, u32 sz, u32 base, u32 ofs, reg_state& regs, func_state& fs) {
  if (base != reg::PC) { return 4; }

  u32 cmp_imm_lit;
  if (!cmp_imm_lit_get(regs, u8(ofs), cmp_imm_lit)) { return 0; }
  ++cmp_imm_lit;

  unsigned const src_off{fs.func_ofs + (addr - fs.func_start) + 4};
  auto const *src{reinterpret_cast<unsigned char const *>(&fs.e.bytes[src_off])};

  for (auto i = 0u; i < cmp_imm_lit; ++i) {
    u32 val{*src++};
    if (sz == 2) { val = u32(val | u32(*src++ << 8u)); }
    fs.paths.push(reg_state_branch(regs, regs.regs[reg::PC] + 4 + (val << 1u)));
  }

  u32 const table_size_pad{((cmp_imm_lit * sz) + 1u) & 1u};
  return 4 + table_size_pad;
}

bool simulate(inst const& i, func_state& fs, reg_state& regs) {
  u32 branch_label;
  if (inst_is_goto(i, branch_label) && address_in_func(branch_label, fs)) {
    regs.regs[reg::PC] = branch_label;
    return true;
  }

  std::vector<reg_mut_node>& reg_muts{fs.lca.reg_muts};
  u32 len{i.len};

  switch (i.type) {
    case inst_type::LOAD_LIT:
      memcpy(&regs.regs[i.i.load_lit.t],
             &fs.e.bytes[fs.func_ofs + (i.i.load_lit.addr - fs.func_start)],
             4);
      mark_reg_known(regs.known, i.i.load_lit.t);
      reg_muts.push_back(reg_mut_node{.i = i});
      regs.mut_node_idxs[i.i.load_lit.t] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV:
      regs.regs[i.i.mov.d] = regs.regs[i.i.mov.m];
      copy_reg_known(regs.known, i.i.mov.d, i.i.mov.m);
      reg_muts.push_back(reg_mut_node{.i = i, .par_idxs[0] = regs.mut_node_idxs[i.i.mov.m]});
      regs.mut_node_idxs[i.i.mov.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV_IMM:
      regs.regs[i.i.mov_imm.d] = i.i.mov_imm.imm;
      mark_reg_known(regs.known, i.i.mov_imm.d);
      reg_muts.push_back(reg_mut_node{.i = i});
      regs.mut_node_idxs[i.i.mov_imm.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::ADD_IMM:
      regs.regs[i.i.add_imm.d] = regs.regs[i.i.add_imm.n] + i.i.add_imm.imm;
      copy_reg_known(regs.known, i.i.add_imm.d, i.i.add_imm.n);
      reg_muts.push_back(
        reg_mut_node{.i = i, .par_idxs[0] = regs.mut_node_idxs[i.i.add_imm.n]});
      regs.mut_node_idxs[i.i.add_imm.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::CMP_IMM:
      cmp_imm_lit_set(regs, i.i.cmp_imm.n, i.i.cmp_imm.imm);
      break;

    case inst_type::TABLE_BRANCH_HALF:
      len = table_branch(i.addr, 2, i.i.table_branch_half.n, i.i.table_branch_half.m, regs, fs);
      break;

    case inst_type::TABLE_BRANCH_BYTE:
      len = table_branch(i.addr, 1, i.i.table_branch_byte.n, i.i.table_branch_byte.m, regs, fs);
      break;

    default: break;
  }

  regs.regs[reg::PC] += len;
  return bool(len);
}

void print(reg_state const& r) {
  for (auto i{0u}; i < 16; ++i) {
    printf("  R%d: 0x%08x known: %d\n", int(i), r.regs[i], (r.known >> i) & 1);
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

  s.paths.push(reg_state{.regs[reg::PC] = s.func_start});

  while (!s.paths.empty()) {
    reg_state path{s.paths.top()};
    s.paths.pop();

    if (test_visited(path.regs[reg::PC], s)) { continue; }

    printf("  Starting path\n");
    //print(path);

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
        s.paths.push(reg_state_branch(path, label));
      }

      if (inst_is_log_call(pc_i, log_funcs)) {
        if (!test_reg_known(path.known, reg::R0)) {
          printf("  Found log function, R0 is unknown\n");
          break;
        }

        printf("  Found log function, format string 0x%08x\n", path.regs[reg::R0]);
        inst const& r0_i = s.lca.reg_muts[path.mut_node_idxs[reg::R0]].i;
        switch (r0_i.type) {
          case inst_type::LOAD_LIT:
            out_lca.log_calls.push_back(log_call{
              .fmt_str_addr = path.regs[reg::R0],
              .log_func_call_addr = pc_i.addr,
              .node_idx = path.mut_node_idxs[reg::R0],
              .s = fmt_str_strat::DIRECT_LOAD });
            break;

          case inst_type::MOV:
            out_lca.log_calls.push_back(log_call{
              .fmt_str_addr = path.regs[reg::R0],
              .log_func_call_addr = pc_i.addr,
              .node_idx = path.mut_node_idxs[reg::R0],
              .s = fmt_str_strat::MOV_FROM_DIRECT_LOAD });
            break;

          case inst_type::ADD_IMM:
            out_lca.log_calls.push_back(log_call{
              .fmt_str_addr = path.regs[reg::R0],
              .log_func_call_addr = pc_i.addr,
              .node_idx = path.mut_node_idxs[reg::R0],
              .s = fmt_str_strat::ADD_IMM_FROM_BASE_REG });
            break;

          default:
            printf("Unrecognized pattern!\n***\n");
            inst_print(r0_i);
            printf("\n***\n");
            break;
        }
      }

      if (!simulate(pc_i, s, path)) { return false; }

      if (inst_is_table_branch(pc_i)) { break; }
    }
  }

  return true;
}
