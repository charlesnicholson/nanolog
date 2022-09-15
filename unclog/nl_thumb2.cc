#include "nl_thumb2.h"
#include "nl_thumb2_inst.h"
#include "nl_elf.h"

#include <cassert>
#include <stack>
#include <vector>

namespace {

bool inst_terminates_path(inst const& i, elf_symbol32 const& func) {
  switch (i.type) {
    case inst_type::BRANCH: {
      u32 const fs{func.st_value & ~1u}, fe{fs + func.st_size}, target{i.i.branch.addr};
      if (target == i.addr) { return true; } // jump to self (infinite)
      return ((target < fs) || (target >= fe)); // branch without link out of function
    }
    case inst_type::BRANCH_XCHG: // BX LR
      if (i.i.branch_xchg.m == reg::LR) { return true; }
    case inst_type::POP: // POP { ..., PC }
      if (i.i.pop.reg_list & (1u << u16(reg::PC))) { return true; }
    default: return false;
  }
}

}

struct reg_state {
  u32 addr, regs[16];
  u16 known = 0;
};

bool thumb2_find_log_strs_in_func(elf const& e, elf_symbol32 const& func) {
  elf_section_hdr32 const& func_sec_hdr = e.sec_hdrs[func.st_shndx];
  unsigned const func_start{(func.st_value) & ~1u};
  unsigned const func_end{func_start + func.st_size};
  unsigned const func_ofs{func_sec_hdr.sh_offset + (func_start - func_sec_hdr.sh_addr)};

  printf("Scanning %s: addr %x, len %x, range %x-%x, offset %x:\n",
    &e.strtab[func.st_name], func.st_value, func.st_size, func_start, func_end, func_ofs);

  std::stack<reg_state, std::vector<reg_state>> paths;
  paths.push(reg_state{.addr = func_start});

  while (!paths.empty()) {
    reg_state s{paths.top()};
    paths.pop();
    printf("  Starting path\n");

    for (;;) {
      if (func.st_size && (s.addr >= func_end)) {
        printf("  Exit: Ran off the end!\n");
        break;
      }

      inst decoded_inst;
      if (!decode(&e.bytes[func_ofs], func_start, s.addr - func_start, decoded_inst)) {
        printf("  Exit: Unknown instruction!\n");
        break;
      }

      print(decoded_inst);
      if (inst_terminates_path(decoded_inst, func)) {
        printf("  Exit: terminal pattern\n");
        break;
      }

      s.addr += decoded_inst.len;
    }
  }
  return true;
}
