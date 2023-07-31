#include "thumb2.h"
#include "thumb2_inst.h"
#include "elf.h"

#include <stack>
#include <unordered_map>

namespace {

struct reg_state {
  u32 regs[16];
  u32 cmp_imm_lits[16];
  u32 mut_node_idxs[16];
  u16 known = u16(1u << reg::PC);
  u16 cmp_imm_present = 0;
};

//void print(reg_state const& rs) {
//  NL_LOG_DBG("k=0x%04hx ", rs.known);
//  for (auto i = 0u; i < 16; ++i) {
//    if ((rs.known >> i) & 1) {
//      NL_LOG_DBG("R%u=%x ", unsigned(i), rs.regs[i]);
//    }
//  }
//  NL_LOG_DBG("\n");
//}

struct path_state {
  reg_state rs;
  u8 it_flags, it_rem;
};

using path_state_vec = std::vector<path_state>;
using path_state_stack = std::stack<path_state, path_state_vec>;

struct func_state {
  func_state(elf_symbol32 const& f_,
             elf const& e_,
             elf_section_hdr32 const& s,
             func_log_call_analysis& lca_)
    : f(f_)
    , func_start{f_.st_value & ~1u}
    , func_end{func_start + f.st_size}
    , func_ofs{s.sh_offset + func_start - s.sh_addr}
    , e(e_)
    , lca(lca_) {
    discovered_log_strs.reserve(32);
  }

  elf_symbol32 const& f;
  unsigned const func_start, func_end, func_ofs;
  elf const& e;
  func_log_call_analysis& lca;
  path_state_stack paths;
  std::vector<bool> taken_branches;
  u32_set discovered_log_strs;
};

path_state path_state_branch(path_state const& p, u32 label) {
  path_state b{p};
  b.rs.regs[reg::PC] = label;
  return b;
}

path_state path_state_it(path_state const& p) {
  path_state b{p};
  b.it_flags = ~b.it_flags;
  return b;
}

bool address_in_func(u32 addr, func_state const& s) {
  return (addr >= s.func_start) && (!s.f.st_size || (addr < s.func_end));
}

bool reg_test_known(u16 regs, int idx) { return regs & (1u << idx); }
void reg_mark_known(u16& regs, int idx) { regs |= (1u << idx); }
void reg_clear_known(u16& regs, int idx) { regs &= u16(~(1u << idx)); }

void reg_copy_known(u16& regs, u8 dst_idx, u8 src_idx) {
  regs = u16(regs & ~(1u << dst_idx)) | u16(((regs >> src_idx) & 1u) << dst_idx);
}

bool reg_intersect_known(u16& regs, u8 dst_idx, u8 src1_idx, u8 src2_idx) {
  u16 const u{u16(u16(regs >> src1_idx) & u16(regs >> src2_idx) & 1u)};
  regs = u16(regs & ~(1u << dst_idx)) | u16(u << dst_idx);
  return bool(u);
}

bool cmp_imm_lit_get(reg_state const& rs, u8 index, u32& out_lit) {
  out_lit = rs.cmp_imm_lits[index];
  return bool(rs.cmp_imm_present & (1u << index));
}

void cmp_imm_lit_set(reg_state& rs, u8 index, u32 lit) {
  rs.cmp_imm_lits[index] = lit;
  rs.cmp_imm_present |= (1u << index);
}

bool branch(u32 addr, func_state& s) {
  auto const idx{unsigned((addr - s.func_start) / 2)};
  if (idx > s.taken_branches.size()) {
    s.taken_branches.resize((idx + 1) * 2);
  }

  if (s.taken_branches[idx]) { return false; }
  s.taken_branches[idx] = true;
  return true;
}

int inst_is_log_call(inst const& i,
                     std::vector<elf_symbol32 const*> const& log_funcs,
                     char const *strtab) {
  u32 label;
  if (!inst_is_unconditional_branch(i, label)) { return -1; }

  auto const found{std::find_if(std::begin(log_funcs), std::end(log_funcs),
    [=](elf_symbol32 const *cand) { return (cand->st_value & ~1u) == label; })};
  if (found == std::end(log_funcs)) { return -1; }

  char const *name{&strtab[(*found)->st_name]};
  if (strstr(name, "_debug")) { return NL_SEV_DEBUG; }
  if (strstr(name, "_info")) { return NL_SEV_INFO; }
  if (strstr(name, "_warning")) { return NL_SEV_WARNING; }
  if (strstr(name, "_error")) { return NL_SEV_ERROR; }
  if (strstr(name, "_critical")) { return NL_SEV_CRITICAL; }
  if (strstr(name, "_assert")) { return NL_SEV_ASSERT; }
  if (strstr(name, "_sev")) { return UNCLOG_SEV_DYNAMIC; }
  if (strstr(name, "_buf")) { return UNCLOG_SEV_DYNAMIC; }
  return -1;
}

bool table_branch(u32 addr, u32 sz, u32 base, u32 ofs, path_state& path, func_state& fs) {
  if (base != reg::PC) { return false; }

  u32 cmp_imm_lit;
  if (!cmp_imm_lit_get(path.rs, u8(ofs), cmp_imm_lit)) { return false; }
  ++cmp_imm_lit;

  if (!branch(addr, fs)) { return true; }

  unsigned const src_off{fs.func_ofs + (addr - fs.func_start) + 4};
  auto const *src{reinterpret_cast<unsigned char const *>(&fs.e.bytes[src_off])};

  for (auto i{0u}; i < cmp_imm_lit; ++i) {
    u32 val{*src++};
    if (sz == 2) { val = u32(val | u32(*src++ << 8u)); }
    u32 const label{path.rs.regs[reg::PC] + 4 + (val << 1u)};
    fs.paths.push(path_state_branch(path, label));
  }

  return true;
}

void process_it(inst_if_then const& it, path_state& path) {
  // Reorder "Table 4.1, pg 4-93" from 1230 to 3210, shifted to LSB.
  u32 ord{u32(it.mask >> u8((4 - it.cnt) + 1))};
  ord = (ord & 0b11110000) >> 4 | (ord & 0b00001111) << 4;
  ord = (ord & 0b11001100) >> 2 | (ord & 0b00110011) << 2;
  ord = (ord & 0b10101010) >> 1 | (ord & 0b01010101) << 1;
  path.it_flags = u8((ord >> (8 - it.cnt)) | 1u);
  path.it_rem = it.cnt;
}

enum class simulate_results {
  SUCCESS,
  FAILURE,
  TERMINATE_PATH,
};

simulate_results process_ldr_pc_jump_table(inst const& i, path_state& p, func_state& fs) {
  if (!branch(i.addr, fs)) { return simulate_results::TERMINATE_PATH; }

  auto const& ldr{i.i.load_reg};

  if (!reg_test_known(p.rs.known, ldr.n)) {
    NL_LOG_ERR("  Unknown PC-rel load, stopping\n");
    return simulate_results::FAILURE;
  }

  u32 cmp_lit;
  if (!cmp_imm_lit_get(p.rs, ldr.m, cmp_lit)) {
    NL_LOG_ERR("  PC-rel load, haven't seen CMP for offset reg %s\n", reg_name(ldr.m));
    return simulate_results::FAILURE;
  }

  if (ldr.shift.n != 2) {
    NL_LOG_ERR("  PC-rel load, %s shift is %d (expected 2)\n", reg_name(ldr.m),
      int(ldr.shift.n));
    return simulate_results::FAILURE;
  }
  NL_LOG_DBG("  Known PC-rel load: %s: %x, %d entries\n", reg_name(ldr.n),
    unsigned(p.rs.regs[ldr.n]), cmp_lit);

  unsigned char const *src{&fs.e.bytes[fs.func_ofs + (p.rs.regs[ldr.n] - fs.func_start)]};
  for (u32 idx{0u}; idx <= cmp_lit; ++idx) {
    u32 jump_label;
    memcpy(&jump_label, src, 4);
    src += 4;
    fs.paths.push(path_state_branch(p, jump_label & ~1u));
  }

  return simulate_results::TERMINATE_PATH;
}

simulate_results simulate(inst const& i,
                          u32_set const& noreturn_func_addrs,
                          func_state& fs,
                          path_state& path) {
  bool const it_skip{path.it_rem && !(path.it_flags & 1)};
  if (NL_UNLIKELY(path.it_rem)) {
    --path.it_rem;
    path.it_flags >>= 1u;
  }
  if (NL_UNLIKELY(it_skip)) { // If inside an if-then and skip bit, don't sim.
    path.rs.regs[reg::PC] += i.len;
    return simulate_results::SUCCESS;
  }

  std::vector<reg_mut_node>& reg_muts{fs.lca.reg_muts};

  switch (i.type) {
    case inst_type::ADD_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& add{i.i.add_imm};
      path.rs.regs[dst_reg] = path.rs.regs[add.n] + add.imm;
      reg_copy_known(path.rs.known, u8(dst_reg), add.n);
      reg_muts.emplace_back(i, path.rs.mut_node_idxs[add.n]);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::ADD_REG: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& add{i.i.add_reg};
      path.rs.regs[dst_reg] = path.rs.regs[add.n] + path.rs.regs[add.m];
      reg_intersect_known(path.rs.known, u8(dst_reg), add.m, add.n);
      reg_muts.emplace_back(i, path.rs.mut_node_idxs[add.n],
        path.rs.mut_node_idxs[add.m]);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::ADR: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& adr{i.i.adr};
      u32 const base{inst_align(path.rs.regs[reg::PC], 4) + 4};
      path.rs.regs[dst_reg] = adr.add ? (base + adr.imm) : (base - adr.imm);
      reg_mark_known(path.rs.known, dst_reg);
      reg_muts.emplace_back(i);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::BRANCH: {
      auto const& b{i.i.branch};
      bool const addr_in_func{address_in_func(b.addr, fs)}, cond{!cond_code_is_always(b.cc)};
      if (!cond) {
        if (!addr_in_func) {
          NL_LOG_DBG("  Stopping Path: Unconditional branch out of function\n");
          return simulate_results::TERMINATE_PATH;
        }

        if (!branch(i.addr, fs)) { return simulate_results::TERMINATE_PATH; }
        path.rs.regs[reg::PC] = b.addr;
        return simulate_results::SUCCESS;
      } else {
        if (addr_in_func && branch(i.addr, fs)) {
          NL_LOG_DBG("  Internal branch, pushing state\n");
          fs.paths.push(path_state_branch(path, b.addr));
        }
      }
    } break;

    case inst_type::BRANCH_LINK: {
      auto const& bl{i.i.branch_link};
      fs.lca.subs.push_back(bl.addr);
      if (noreturn_func_addrs.contains(bl.addr)) {
        NL_LOG_DBG("  Stopping path: noreturn call\n");
        return simulate_results::TERMINATE_PATH;
      }
      path.rs.known &= 0xFFF0u; // r0-r3 are scratch
    } break;

    case inst_type::BRANCH_XCHG: return simulate_results::TERMINATE_PATH; // tail call

    case inst_type::CBNZ:
      if (branch(i.addr, fs)) {
        NL_LOG_DBG("  Internal branch, pushing state\n");
        fs.paths.push(path_state_branch(path, i.i.cmp_branch_nz.addr));
      }
      break;

    case inst_type::CBZ:
      if (branch(i.addr, fs)) {
        NL_LOG_DBG("  Internal branch, pushing state\n");
        fs.paths.push(path_state_branch(path, i.i.cmp_branch_z.addr));
      }
      break;

    case inst_type::CMP_IMM:
      cmp_imm_lit_set(path.rs, i.i.cmp_imm.n, i.i.cmp_imm.imm);
      break;

    case inst_type::IF_THEN:
      if (NL_UNLIKELY(!branch(i.addr, fs))) {
        return simulate_results::TERMINATE_PATH;
      }
      process_it(i.i.if_then, path);
      NL_LOG_DBG("  IT, pushing state\n");
      fs.paths.push(path_state_it(path));
      break;

    case inst_type::LOAD_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      if (dst_reg == reg::PC) { return simulate_results::TERMINATE_PATH; }
      reg_clear_known(path.rs.known, dst_reg);
    } break;

    case inst_type::LOAD_LIT: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& ldr{i.i.load_lit};
      memcpy(&path.rs.regs[dst_reg],
        &fs.e.bytes[fs.func_ofs + (ldr.addr - fs.func_start)], 4);
      reg_mark_known(path.rs.known, dst_reg);
      reg_muts.push_back(reg_mut_node(i));
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::LOAD_REG: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& ldr{i.i.load_reg};
      if (dst_reg == reg::PC) {
        return process_ldr_pc_jump_table(i, path, fs);
      } else {
        bool const known{reg_intersect_known(path.rs.known, u8(dst_reg), ldr.n, ldr.m)};
        u32 const addr{u32(path.rs.regs[ldr.n] + (path.rs.regs[ldr.m] << ldr.shift.n))};
        if (known && address_in_func(addr, fs)) {
          unsigned const ofs{fs.func_ofs + (addr - fs.func_start)};
          memcpy(&path.rs.regs[dst_reg], &fs.e.bytes[ofs], 4);
        }
      }
    } break;

    case inst_type::LOAD_MULT_INC_AFTER: // LDMIA SP!, { ... PC }
      if (i.dr & (1u << reg::PC)) {
        return simulate_results::TERMINATE_PATH;
      }
      path.rs.known &= ~i.dr;
      break;

    case inst_type::MOV_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& mov{i.i.mov_imm};
      path.rs.regs[dst_reg] = mov.imm;
      reg_mark_known(path.rs.known, dst_reg);
      reg_muts.emplace_back(i);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::MOV_NEG_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& mvn{i.i.mov_neg_imm};
      path.rs.regs[dst_reg] = ~u32(mvn.imm);
      reg_mark_known(path.rs.known, dst_reg);
      reg_muts.emplace_back(i);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::MOV_REG: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& mov{i.i.mov_reg};
      path.rs.regs[dst_reg] = path.rs.regs[mov.m];
      reg_copy_known(path.rs.known, u8(dst_reg), mov.m);
      reg_muts.emplace_back(i, path.rs.mut_node_idxs[mov.m]);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::POP:
      if (i.dr & (1u << reg::PC)) { return simulate_results::TERMINATE_PATH; }
      path.rs.known &= ~i.dr;
      break;

    case inst_type::SUB_REV_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& sub{i.i.sub_rev_imm};
      path.rs.regs[dst_reg] = sub.imm - path.rs.regs[sub.n];
      reg_copy_known(path.rs.known, u8(dst_reg), sub.n);
      reg_muts.emplace_back(i, path.rs.mut_node_idxs[sub.n]);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::SUB_IMM: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& sub{i.i.sub_imm};
      path.rs.regs[dst_reg] = path.rs.regs[sub.n] - sub.imm;
      reg_copy_known(path.rs.known, u8(dst_reg), sub.n);
      reg_muts.push_back(reg_mut_node(i, path.rs.mut_node_idxs[sub.n]));
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::SUB_REG: {
      int const dst_reg{inst_reg_from_bitmask(i.dr)};
      auto const& sub{i.i.sub_reg};
      path.rs.regs[dst_reg] = path.rs.regs[sub.n] - path.rs.regs[sub.m]; // shift
      reg_intersect_known(path.rs.known, u8(dst_reg), sub.n, sub.m);
      reg_muts.emplace_back(i, path.rs.mut_node_idxs[sub.n], path.rs.mut_node_idxs[sub.m]);
      path.rs.mut_node_idxs[dst_reg] = u32(reg_muts.size() - 1u);
    } break;

    case inst_type::TABLE_BRANCH_HALF: {
      auto const& tbh{i.i.table_branch_half};
      if (NL_UNLIKELY(!table_branch(i.addr, 2, tbh.n, tbh.m, path, fs))) {
        NL_LOG_ERR("  TBH failure\n");
        return simulate_results::FAILURE;
      }
      return simulate_results::TERMINATE_PATH;
    }

    case inst_type::TABLE_BRANCH_BYTE: {
      auto const& tbb{i.i.table_branch_byte};
      if (NL_UNLIKELY(!table_branch(i.addr, 1, tbb.n, tbb.m, path, fs))) {
        NL_LOG_ERR("  TBB failure\n");
        return simulate_results::FAILURE;
      }
      return simulate_results::TERMINATE_PATH;
    }

    case inst_type::UNDEFINED: return simulate_results::TERMINATE_PATH;

    default:
      path.rs.known &= ~i.dr;
      break;
  }

  path.rs.regs[reg::PC] += i.len;
  return simulate_results::SUCCESS;
}

enum process_log_call_ret {
  PROCESS_LOG_CALL_RET_SUCCESS,
  PROCESS_LOG_CALL_RET_ERR_R0_UNKNOWN,
  PROCESS_LOG_CALL_RET_ERR_R0_INVALID,
  PROCESS_LOG_CALL_RET_ERR_ALREADY_DISCOVERED,
  PROCESS_LOG_CALL_RET_UNRECOGNIZED_PATTERN,
};

process_log_call_ret process_log_call(inst const& pc_i,
                                      path_state const& path,
                                      elf_section_hdr32 const& nl_sec_hdr,
                                      int sev,
                                      func_state& fs,
                                      func_log_call_analysis& lca) {
  if (!reg_test_known(path.rs.known, reg::R0)) {
    NL_LOG_DBG("  Found log function, R0 is unknown\n");
    return PROCESS_LOG_CALL_RET_ERR_R0_UNKNOWN;
  }

  u32 const fmt_str_addr{path.rs.regs[reg::R0]};
  if (nl_sec_hdr.sh_size &&
      ((fmt_str_addr < nl_sec_hdr.sh_addr) ||
       (fmt_str_addr > (nl_sec_hdr.sh_addr + nl_sec_hdr.sh_size)))) {
    NL_LOG_ERR("  Found log function, R0 is invalid: 0x%08x\n", fmt_str_addr);
    return PROCESS_LOG_CALL_RET_ERR_R0_INVALID;
  }

  auto [_, inserted]{fs.discovered_log_strs.insert(fmt_str_addr)};
  if (!inserted) {
    NL_LOG_DBG("  Found log function, already discovered\n");
    return PROCESS_LOG_CALL_RET_ERR_ALREADY_DISCOVERED;
  }

  lca.log_calls.push_back(log_call{ .fmt_str_addr = path.rs.regs[reg::R0],
    .log_func_call_addr = pc_i.addr, .node_idx = path.rs.mut_node_idxs[reg::R0],
    .s = fmt_str_strat::UNKNOWN, .severity = u8(sev)});
  auto& log_call{lca.log_calls[lca.log_calls.size() - 1]};

  NL_LOG_DBG("  Found log function, format string 0x%08x\n", path.rs.regs[reg::R0]);
  inst const& r0_i{lca.reg_muts[path.rs.mut_node_idxs[reg::R0]].i};
  switch (r0_i.type) {
    case inst_type::LOAD_LIT: log_call.s = fmt_str_strat::DIRECT_LOAD; break;
    case inst_type::MOV_REG:  log_call.s = fmt_str_strat::MOV_FROM_DIRECT_LOAD; break;
    case inst_type::ADD_IMM:  log_call.s = fmt_str_strat::ADD_IMM_FROM_BASE_REG; break;
    default:
      NL_LOG_DBG("Unrecognized pattern!\n***\n");
      NL_LOG_DBG("0x%x\n", r0_i.addr);
      inst_print(r0_i);
      NL_LOG_DBG("\n***\n");
      return PROCESS_LOG_CALL_RET_UNRECOGNIZED_PATTERN;
  }
  return PROCESS_LOG_CALL_RET_SUCCESS;
}
}

char const *fmt_str_strat_name(fmt_str_strat s) {
#define X(NAME) case fmt_str_strat::NAME: return #NAME;
  switch (s) { FMT_STR_STRAT_LIST() default: return "unknown"; }
#undef X
}

thumb2_analyze_func_ret thumb2_analyze_func(
    elf const& e,
    elf_symbol32 const& func,
    elf_section_hdr32 const& nl_sec_hdr,
    std::vector<elf_symbol32 const*> const& log_funcs,
    u32_set const& noreturn_func_addrs,
    func_log_call_analysis& out_lca,
    analysis_stats& out_stats) {
  func_state s{func, e, e.sec_hdrs[func.st_shndx], out_lca};
  s.taken_branches.resize(1024 * 1024); //(s.func_end - s.func_start) / 2);

  out_lca.reg_muts.reserve(1024);

  NL_LOG_DBG("\nScanning %s: addr %x, len %x, range %x-%x, offset %x:\n",
    &e.strtab[func.st_name], func.st_value, func.st_size, s.func_start, s.func_end,
    s.func_ofs);

  s.paths.push([&]() { // set up the function entry point on the path stack
    path_state ps;
    ps.it_rem = 0;
    ps.rs.regs[reg::PC] = s.func_start;
    return ps;
  }());

  bool const debug{nanolog_get_threshold() == NL_SEV_DEBUG};

  auto path_count{0};
  while (!s.paths.empty()) { // recurse through the function
    if (++path_count > 1024) {
      NL_LOG_ERR("  Stopping analysis, infinite loop.");
      return thumb2_analyze_func_ret::ERR_INFINITE_LOOP;
    }

    path_state path{s.paths.top()};
    s.paths.pop();

    NL_LOG_DBG("  Starting path (%d in stack)\n", int(s.paths.size()));
    ++out_stats.analyzed_paths;

    for (;;) {
      if (NL_UNLIKELY(func.st_size && (path.rs.regs[reg::PC] >= s.func_end))) {
        NL_LOG_DBG("  Stopping path: Ran off the end!\n");
        return thumb2_analyze_func_ret::ERR_RAN_OFF_END_OF_FUNC;
      }

      inst pc_i;
      bool const decode_ok{inst_decode(&e.bytes[s.func_ofs], s.func_start,
        path.rs.regs[reg::PC] - s.func_start, pc_i)};

      ++out_stats.decoded_insts;

      if (NL_UNLIKELY(debug)) {
        NL_LOG_DBG("    %x: %04x ", path.rs.regs[reg::PC], pc_i.w0);
        if (pc_i.len == 2) {
          NL_LOG_DBG("       ");
        } else {
          NL_LOG_DBG("%04x   ", pc_i.w1);
        }
        inst_print(pc_i);
        NL_LOG_DBG("\n");
      }

      if (NL_UNLIKELY(!decode_ok)) {
        NL_LOG_DBG("  Stopping path: Unknown instruction!\n");
        return thumb2_analyze_func_ret::ERR_INSTRUCTION_DECODE;
      }

      if (int const sev{inst_is_log_call(pc_i, log_funcs, e.strtab)};
          NL_UNLIKELY(sev != -1)) {
        bool already_discovered = false;
        switch (process_log_call(pc_i, path, nl_sec_hdr, sev, s, out_lca)) {
          case PROCESS_LOG_CALL_RET_SUCCESS:
            break;

          case PROCESS_LOG_CALL_RET_ERR_R0_UNKNOWN:
          case PROCESS_LOG_CALL_RET_ERR_R0_INVALID:
          case PROCESS_LOG_CALL_RET_UNRECOGNIZED_PATTERN:
            return thumb2_analyze_func_ret::ERR_UNKNOWN_LOG_CALL_STRATEGY;

          case PROCESS_LOG_CALL_RET_ERR_ALREADY_DISCOVERED:
            already_discovered = true;
            break;
        }

        if (already_discovered) {
          NL_LOG_DBG("  Stopping path: nanolog call already discovered.\n");
          break;
        }
      }

      simulate_results const sr{simulate(pc_i, noreturn_func_addrs, s, path)};
      if (NL_UNLIKELY(sr == simulate_results::FAILURE)) {
        return thumb2_analyze_func_ret::ERR_SIMULATE_LOGIC_INCOMPLETE;
      }

      if (sr == simulate_results::TERMINATE_PATH) {
        NL_LOG_DBG("  Stopping path: terminal pattern\n");
        break;
      }
    }
  }

  return thumb2_analyze_func_ret::SUCCESS;
}

bool thumb2_patch_fmt_strs(elf const& e,
                           elf_section_hdr32 const& nl_sec_hdr,
                           byte* patched_elf,
                           std::vector<func_log_call_analysis> const& log_call_funcs,
                           u32_vec const& fmt_bin_addrs) {
  for (u32 i{0}; auto const &func : log_call_funcs) {
    u32 const func_ofs{e.sec_hdrs[func.func.st_shndx].sh_offset},
      func_addr{e.sec_hdrs[func.func.st_shndx].sh_addr};

    for (auto const &log_call : func.log_calls) {
      auto const& r0_mut{func.reg_muts[log_call.node_idx]};
      u32 const bin_addr{fmt_bin_addrs[i] + nl_sec_hdr.sh_addr};

      switch (log_call.s) {
        case fmt_str_strat::DIRECT_LOAD: {
          unsigned const dst_ofs{func_ofs + (r0_mut.i.i.load_lit.addr - func_addr)};
          memcpy(&patched_elf[dst_ofs], &bin_addr, sizeof(u32));
        } break;

        case fmt_str_strat::MOV_FROM_DIRECT_LOAD: {
          reg_mut_node const& rn_mut{func.reg_muts[r0_mut.par_idxs[0]]};
          unsigned const dst_ofs{func_ofs + (rn_mut.i.i.load_lit.addr - func_addr)};
          memcpy(&patched_elf[dst_ofs], &bin_addr, sizeof(u32));
        } break;

        case fmt_str_strat::ADD_IMM_FROM_BASE_REG:
          NL_LOG_ERR("Strategy ADD_IMM_FROM_BASE_REG not supported yet.\n");
          return false;

        case fmt_str_strat::UNKNOWN:
          NL_LOG_ERR("Unknown strategy\n");
          return false;
      }

      ++i;
    }
  }

  return true;
}

