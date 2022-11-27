#include "thumb2.h"
#include "thumb2_inst.h"
#include "elf.h"

#include <stack>
#include <unordered_map>

namespace {

struct reg_state {
  u32 regs[16];
  u32 cmp_imm_lits[16];
  u16 mut_node_idxs[16];
  u16 known = u16(1u << reg::PC);
  u16 cmp_imm_present = 0;
};

void print(reg_state const& rs) {
  for (auto i = 0u; i < 16; ++i) {
    NL_LOG_DBG("R%u %u %x\n", unsigned(i), unsigned((rs.known >> i) & 1), rs.regs[i]);
  }
}

struct path_state {
  reg_state rs;
  std::vector<bool> taken_branches;
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
    taken_branches_reg_states.reserve(64);
    discovered_log_strs.reserve(32);
  }

  elf_symbol32 const& f;
  unsigned const func_start, func_end, func_ofs;
  elf const& e;
  func_log_call_analysis& lca;
  path_state_stack paths;
  std::unordered_map<u32, std::vector<reg_state>> taken_branches_reg_states;
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

bool reg_states_equal(reg_state const& r1, reg_state const& r2) {
  if (r1.known != r2.known) { return false; }
  for (auto i{0u}; i < 16; ++i) {
    if ((r1.known & (1 << i)) && (r1.regs[i] != r2.regs[i])) { return false; }
  }
  return true;
}

bool address_in_func(u32 addr, func_state const& s) {
  return !s.f.st_size || ((addr >= s.func_start) && (addr < s.func_end));
}

bool test_reg_known(u16 regs, u8 idx) { return (regs >> idx) & 1u; }
void mark_reg_known(u16& regs, u8 dst) { regs |= (1u << dst); }
void copy_reg_known(u16& regs, u8 dst, u8 src) {
  regs = u16(regs & ~(1u << dst)) | u16(((regs >> src) & 1u) << dst);
}

bool union_reg_known(u16& regs, u8 dst, u8 src1, u8 src2) {
  u16 const u{u16(u16(regs >> src1) & u16(regs >> src2) & 1u)};
  regs = u16(regs & ~(1u << dst)) | u16(u << dst);
  return bool(u);
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
  auto const idx{unsigned((addr - s.func_start) / 2)};
  if (NL_UNLIKELY(idx >= p.taken_branches.size())) {
    p.taken_branches.resize((idx + 1) * 10);
  }
  if (p.taken_branches[idx]) { return false; }

  auto const it{s.taken_branches_reg_states.find(addr)};
  if (it != s.taken_branches_reg_states.end()) {
    auto const& reg_states{it->second};
    auto const b{std::begin(reg_states)}, e{std::end(reg_states)};
    if (std::find_if(b, e, [&](auto& rs) { return reg_states_equal(p.rs, rs); }) != e) {
      return false;
    }
  }

  p.taken_branches[idx] = true;
  auto [vi, inserted]{s.taken_branches_reg_states.insert({addr, {}})};
  vi->second.push_back(p.rs);
  return true;
}

int inst_is_log_call(inst const& i,
                     std::vector<elf_symbol32 const*> const& log_funcs,
                     char const *strtab) {
  u32 label;
  if (!inst_is_unconditional_branch(i, label)) { return -1; }

  auto const found = std::find_if(std::begin(log_funcs), std::end(log_funcs),
    [=](elf_symbol32 const *cand) { return (cand->st_value & ~1u) == label; });
  if (found == std::end(log_funcs)) { return -1; }

  char const *name{&strtab[(*found)->st_name]};
  if (strstr(name, "_debug")) { return NL_SEV_DEBUG; }
  if (strstr(name, "_info")) { return NL_SEV_INFO; }
  if (strstr(name, "_warning")) { return NL_SEV_WARNING; }
  if (strstr(name, "_error")) { return NL_SEV_ERROR; }
  if (strstr(name, "_critical")) { return NL_SEV_CRITICAL; }
  if (strstr(name, "_assert")) { return NL_SEV_ASSERT; }
  return -1;
}

bool table_branch(u32 addr, u32 sz, u32 base, u32 ofs, path_state& path, func_state& fs) {
  if (base != reg::PC) { return false; }

  u32 cmp_imm_lit;
  if (!cmp_imm_lit_get(path.rs, u8(ofs), cmp_imm_lit)) { return false; }
  ++cmp_imm_lit;

  if (!branch(addr, path, fs)) { return true; }

  unsigned const src_off{fs.func_ofs + (addr - fs.func_start) + 4};
  auto const *src{reinterpret_cast<unsigned char const *>(&fs.e.bytes[src_off])};

  for (auto i{0u}; i < cmp_imm_lit; ++i) {
    u32 val{*src++};
    if (sz == 2) { val = u32(val | u32(*src++ << 8u)); }
    u32 const label{path.rs.regs[reg::PC] + 4 + (val << 1u)};
    fs.paths.emplace(path_state_branch(path, label));
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
  if (!branch(i.addr, p, fs)) { return simulate_results::TERMINATE_PATH; }

  auto const& ldr{i.i.load_reg};

  if (!test_reg_known(p.rs.known, ldr.n)) {
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
    fs.paths.emplace(path_state_branch(p, jump_label & ~1u));
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
      auto const& add{i.i.add_imm};
      path.rs.regs[add.d] = path.rs.regs[add.n] + add.imm;
      copy_reg_known(path.rs.known, add.d, add.n);
      reg_muts.emplace_back(reg_mut_node(i, path.rs.mut_node_idxs[add.n]));
      path.rs.mut_node_idxs[add.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::ADD_REG: {
      auto const& add{i.i.add_reg};
      path.rs.regs[add.d] = path.rs.regs[add.n] + path.rs.regs[add.m];
      union_reg_known(path.rs.known, add.d, add.m, add.n);
      reg_muts.emplace_back(reg_mut_node(i, path.rs.mut_node_idxs[add.n],
        path.rs.mut_node_idxs[add.m]));
      path.rs.mut_node_idxs[add.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::ADR: {
      auto const& adr{i.i.adr};
      u32 const base{inst_align(path.rs.regs[reg::PC], 4) + 4};
      path.rs.regs[adr.d] = adr.add ? (base + adr.imm) : (base - adr.imm);
      mark_reg_known(path.rs.known, adr.d);
      reg_muts.emplace_back(reg_mut_node(i));
      path.rs.mut_node_idxs[adr.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::BRANCH: {
      auto const& b{i.i.branch};
      bool const addr_in_func{address_in_func(b.addr, fs)}, cond{!cond_code_is_always(b.cc)};
      if (!cond) {
        if (!addr_in_func) {
          NL_LOG_DBG("  Stopping Path: Unconditional branch out of function\n");
          return simulate_results::TERMINATE_PATH;
        }

        if (!branch(i.addr, path, fs)) { return simulate_results::TERMINATE_PATH; }
        path.rs.regs[reg::PC] = b.addr;
        return simulate_results::SUCCESS;
      } else {
        if (addr_in_func && branch(i.addr, path, fs)) {
          NL_LOG_DBG("  Internal branch, pushing state\n");
          fs.paths.emplace(path_state_branch(path, b.addr));
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
    } break;

    case inst_type::BRANCH_XCHG: return simulate_results::TERMINATE_PATH; // tail call

    case inst_type::CBNZ:
      if (branch(i.addr, path, fs)) {
        NL_LOG_DBG("  Internal branch, pushing state\n");
        fs.paths.emplace(path_state_branch(path, i.i.cmp_branch_nz.addr));
      }
      break;

    case inst_type::CBZ:
      if (branch(i.addr, path, fs)) {
        NL_LOG_DBG("  Internal branch, pushing state\n");
        fs.paths.emplace(path_state_branch(path, i.i.cmp_branch_z.addr));
      }
      break;

    case inst_type::CMP_IMM:
      cmp_imm_lit_set(path.rs, i.i.cmp_imm.n, i.i.cmp_imm.imm);
      break;

    case inst_type::IF_THEN:
      if (NL_UNLIKELY(!branch(i.addr, path, fs))) {
        return simulate_results::TERMINATE_PATH;
      }
      process_it(i.i.if_then, path);
      NL_LOG_DBG("  IT, pushing state\n");
      fs.paths.emplace(path_state_it(path));
      break;

    case inst_type::LOAD_IMM: {
      auto const& ldr{i.i.load_imm};
      if (ldr.t == reg::PC) { return simulate_results::TERMINATE_PATH; }
    } break;

    case inst_type::LOAD_LIT: {
      auto const& ldr{i.i.load_lit};
      memcpy(&path.rs.regs[ldr.t], &fs.e.bytes[fs.func_ofs + (ldr.addr - fs.func_start)], 4);
      mark_reg_known(path.rs.known, ldr.t);
      reg_muts.emplace_back(reg_mut_node(i));
      path.rs.mut_node_idxs[ldr.t] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::LOAD_REG: {
      auto const& ldr{i.i.load_reg};
      if (ldr.t == reg::PC) {
        return process_ldr_pc_jump_table(i, path, fs);
      } else {
        bool const known{union_reg_known(path.rs.known, ldr.t, ldr.n, ldr.m)};
        u32 const addr{u32(path.rs.regs[ldr.n] + (path.rs.regs[ldr.m] << ldr.shift.n))};
        if (known && address_in_func(addr, fs)) {
          unsigned const ofs{fs.func_ofs + (addr - fs.func_start)};
          memcpy(&path.rs.regs[ldr.t], &fs.e.bytes[ofs], 4);
        }
      }
    } break;

    case inst_type::LOAD_MULT_INC_AFTER: // LDMIA SP!, { ... PC }
      if (i.i.load_mult_inc_after.regs & (1u << reg::PC)) {
        return simulate_results::TERMINATE_PATH;
      }
      break;

    case inst_type::MOV_IMM:
      path.rs.regs[i.i.mov_imm.d] = i.i.mov_imm.imm;
      mark_reg_known(path.rs.known, i.i.mov_imm.d);
      reg_muts.push_back(reg_mut_node(i));
      path.rs.mut_node_idxs[i.i.mov_imm.d] = u16(reg_muts.size() - 1u);
      break;

    case inst_type::MOV_NEG_IMM: {
      auto const& mvn{i.i.mov_neg_imm};
      path.rs.regs[mvn.d] = ~u32(mvn.imm);
      mark_reg_known(path.rs.known, mvn.d);
      reg_muts.push_back(reg_mut_node(i));
      path.rs.mut_node_idxs[mvn.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::MOV_REG: {
      auto const& mov{i.i.mov_reg};
      path.rs.regs[mov.d] = path.rs.regs[mov.m];
      copy_reg_known(path.rs.known, mov.d, mov.m);
      reg_muts.push_back(reg_mut_node(i, path.rs.mut_node_idxs[mov.m]));
      path.rs.mut_node_idxs[mov.d] = u16(reg_muts.size() - 1u);
    } break;

    case inst_type::POP:
      if (i.i.pop.reg_list & (1u << reg::PC)) { return simulate_results::TERMINATE_PATH; }
      break;

    case inst_type::SUB_IMM: {
      auto const& sub{i.i.sub_imm};
      path.rs.regs[sub.d] = path.rs.regs[sub.n] - sub.imm;
      copy_reg_known(path.rs.known, sub.d, sub.n);
      reg_muts.push_back(reg_mut_node(i, path.rs.mut_node_idxs[sub.n]));
      path.rs.mut_node_idxs[sub.d] = u16(reg_muts.size() - 1u);
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

    default: break;
  }

  path.rs.regs[reg::PC] += i.len;
  return simulate_results::SUCCESS;
}

bool process_log_call(inst const& pc_i,
                      path_state const& path,
                      elf_section_hdr32 const& nl_sec_hdr,
                      int sev,
                      func_state& fs,
                      func_log_call_analysis& lca) {
  if (!test_reg_known(path.rs.known, reg::R0)) {
    NL_LOG_DBG("  Found log function, R0 is unknown\n");
    return false;
  }

  u32 const fmt_str_addr{path.rs.regs[reg::R0]};
  if (nl_sec_hdr.sh_size &&
      ((fmt_str_addr < nl_sec_hdr.sh_addr) ||
       (fmt_str_addr > (nl_sec_hdr.sh_addr + nl_sec_hdr.sh_size)))) {
    NL_LOG_ERR("  Found log function, R0 is invalid: 0x%08x\n", fmt_str_addr);
    return false;
  }

  auto [_, inserted]{fs.discovered_log_strs.insert(fmt_str_addr)};
  if (!inserted) {
    NL_LOG_DBG("  Found log function, already discovered\n");
    return true;
  }

  lca.log_calls.emplace_back(log_call{ .fmt_str_addr = path.rs.regs[reg::R0],
    .log_func_call_addr = pc_i.addr, .node_idx = path.rs.mut_node_idxs[reg::R0],
    .severity = u8(sev)});
  auto& log_call{lca.log_calls[lca.log_calls.size() - 1]};

  NL_LOG_DBG("  Found log function, format string 0x%08x\n", path.rs.regs[reg::R0]);
  inst const& r0_i{lca.reg_muts[path.rs.mut_node_idxs[reg::R0]].i};
  switch (r0_i.type) {
    case inst_type::LOAD_LIT: log_call.s = fmt_str_strat::DIRECT_LOAD; break;
    case inst_type::MOV_REG:  log_call.s = fmt_str_strat::MOV_FROM_DIRECT_LOAD; break;
    case inst_type::ADD_IMM:  log_call.s = fmt_str_strat::ADD_IMM_FROM_BASE_REG; break;
    default:
      NL_LOG_DBG("Unrecognized pattern!\n***\n");
      inst_print(r0_i);
      NL_LOG_DBG("\n***\n");
      return false;
  }
  return true;
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
  out_lca.reg_muts.reserve(1024);

  NL_LOG_DBG("\nScanning %s: addr %x, len %x, range %x-%x, offset %x:\n",
    &e.strtab[func.st_name], func.st_value, func.st_size, s.func_start, s.func_end,
    s.func_ofs);

  s.paths.emplace([&]() { // set up the function entry point on the path stack
    path_state ps{.rs{.regs[reg::PC] = s.func_start}};
    ps.taken_branches.resize((s.func_end - s.func_start) / 2);
    return ps;
  }());

  bool const debug{nanolog_get_log_threshold() == NL_SEV_DEBUG};

  while (!s.paths.empty()) { // recurse through the function
    path_state path{s.paths.top()};
    s.paths.pop();

    NL_LOG_DBG("  Starting path\n");
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

      int const sev{inst_is_log_call(pc_i, log_funcs, e.strtab)};
      if (sev != -1) {
        if (!process_log_call(pc_i, path, nl_sec_hdr, sev, s, out_lca)) {
          return thumb2_analyze_func_ret::ERR_UNKNOWN_LOG_CALL_STRATEGY;
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
          unsigned dst_ofs{func_ofs + (r0_mut.i.i.load_lit.addr - func_addr)};
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
      }

      ++i;
    }
  }

  return true;
}

