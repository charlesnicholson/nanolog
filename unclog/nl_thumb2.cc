#include "nl_thumb2.h"
#include "nl_thumb2_inst.h"
#include "nl_elf.h"

#include <cassert>
#include <stack>
#include <vector>

struct reg_state {
  u32 addr, regs[16];
  u16 known = 0;
};

struct func_state {
  func_state(elf_symbol32 const& f_, elf_section_hdr32 const& s)
    : f(f_)
    , visited(s.sh_size / 2)
    , func_start{f_.st_value & ~1u}
    , func_end{func_start + f.st_size}
    , func_ofs{s.sh_offset + func_start - s.sh_addr} {}

  elf_symbol32 const& f;
  std::vector<bool> visited; // i know i know
  std::stack<reg_state, std::vector<reg_state>> paths;
  unsigned const func_start, func_end, func_ofs;
};

namespace {

bool address_in_func(u32 addr, func_state const& s) {
  return (addr >= s.func_start) && (addr <= s.func_end);
}

void mark_visited(u32 addr, func_state& s) { s.visited[(addr - s.func_start) / 2] = true; }

bool test_visited(u32 addr, func_state const& s) {
  return s.visited[(addr - s.func_start) / 2];
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
      if (reg(i.i.branch_xchg.m) == reg::LR) { return true; }
      break;

    case inst_type::POP: // POP { ..., PC }
      if (i.i.pop.reg_list & (1u << u16(reg::PC))) { return true; }
      break;

    default: break;
  }

  return false;
}

bool inst_is_log_call(inst const& i, std::vector<elf_symbol32 const*> const& log_funcs) {
  u32 label;
  if (!inst_is_unconditional_branch(i, label)) { return false; }
  return std::find_if(std::begin(log_funcs),
                      std::end(log_funcs),
                      [label](elf_symbol32 const* cand) {
                        return (cand->st_value & ~1u) == label;
                      }) != std::end(log_funcs);
}
}

bool thumb2_find_log_strs_in_func(elf const& e,
                                  elf_symbol32 const& func,
                                  std::vector<elf_symbol32 const*> const& log_funcs) {
  func_state s{func, e.sec_hdrs[func.st_shndx]};

  printf("Scanning %s: addr %x, len %x, range %x-%x, offset %x:\n", &e.strtab[func.st_name],
    func.st_value, func.st_size, s.func_start, s.func_end, s.func_ofs);

  s.paths.push(reg_state{.addr = s.func_start});

  while (!s.paths.empty()) {
    reg_state path{s.paths.top()};
    s.paths.pop();
    printf("  Starting path\n");

    for (;;) {
      if (func.st_size && (path.addr >= s.func_end)) {
        printf("  Exit: Ran off the end!\n");
        break;
      }

      inst decoded_inst;
      if (!inst_decode(&e.bytes[s.func_ofs], s.func_start, path.addr - s.func_start,
        decoded_inst)) {
        printf("  Exit: Unknown instruction!\n");
        break;
      }

      mark_visited(path.addr, s);

      inst_print(decoded_inst);
      if (inst_terminates_path(decoded_inst, s)) {
        printf("  Exit: terminal pattern\n");
        break;
      }

      u32 label;
      if (inst_is_conditional_branch(decoded_inst, label) &&
          address_in_func(label, s) &&
          !test_visited(label, s)) {
        printf("Pushing State!\n");
        s.paths.push(reg_state{.addr = label});
      } else if (inst_is_log_call(decoded_inst, log_funcs)) {
      }

      path.addr += decoded_inst.len;
    }
  }
  return true;
}
