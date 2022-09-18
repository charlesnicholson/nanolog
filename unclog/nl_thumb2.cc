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

bool inst_terminates_path(inst const& i, func_state& s) {
  switch (i.type) {
    case inst_type::BRANCH: {
      if (!cond_code_is_absolute(i.i.branch.cc)) { break; }
      if (s.visited[(i.i.branch.addr - s.func_start) / 2]) { return true; } // loop
      return address_in_func(i.i.branch.addr, s);
    }

    case inst_type::BRANCH_XCHG: // BX LR
      if (i.i.branch_xchg.m == reg::LR) { return true; }

    case inst_type::POP: // POP { ..., PC }
      if (i.i.pop.reg_list & (1u << u16(reg::PC))) { return true; }

    default: break;
  }

  return false;
}

}

bool thumb2_find_log_strs_in_func(elf const& e, elf_symbol32 const& func) {
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

      s.visited[(path.addr - s.func_start) / 2] = true;

      inst_print(decoded_inst);
      if (inst_terminates_path(decoded_inst, s)) {
        printf("  Exit: terminal pattern\n");
        break;
      }

      u32 branch_target;
      if (inst_is_conditional_branch(decoded_inst, branch_target)) {
        if (address_in_func(branch_target, s)) {
          s.paths.push(reg_state{.addr = branch_target});
        }
      }

      path.addr += decoded_inst.len;
    }
  }
  return true;
}
