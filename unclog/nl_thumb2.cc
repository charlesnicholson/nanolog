#include "nl_thumb2.h"
#include "nl_elf.h"

#include <cstdint>
#include <cassert>
#include <stack>

#define INST_TYPE_X_LIST() \
  X(PUSH, push) \
  X(NOP, nop) \
  X(BRANCH, branch)

#define X(ENUM, TYPE) ENUM,
enum class inst_type {
  INST_TYPE_X_LIST()
};
#undef X

// Instructions

struct inst_push { uint16_t register_list; }; // 4.6.99
void print(inst_push const& i) { printf("  PUSH 0x%04x\n", i.register_list); }

struct inst_nop {}; // 4.6.88
void print(inst_nop const&) { printf("  NOP\n"); }

struct inst_branch { uint32_t label; }; // 4.6.12
void print(inst_branch const& i) { printf("  B %x\n", i.label); }

//

#define X(ENUM, TYPE) inst_##TYPE TYPE;
struct inst {
  inst_type type;
  union {
    INST_TYPE_X_LIST()
  } i;
  int len; // 2 or 4
};
#undef X

#define X(ENUM, TYPE) case inst_type::ENUM: print(i.i.TYPE); break;
void print(inst const& i) {
  switch (i.type) {
    INST_TYPE_X_LIST()
    default: printf("  unknown\n"); break;
  }
}
#undef X

struct reg_state {
  uint32_t addr;
  uint32_t regs[16];
  uint16_t known = 0;
};

namespace {
bool is_16bit_inst(uint16_t w0) {
  /* 3.1 Instruction set encoding
     Table 3-1 Determination of instruction length
     0b11100 Thumb 16-bit unconditional branch instruction
     0b111xx Thumb 32-bit instructions, defined in Thumb-2
     0bxxxxx Thumb 16-bit instructions. */
  if ((w0 & 0xF000) == 0xE000) { return true; }
  if ((w0 & 0xE000) == 0xE000) { return false; }
  return true;
}

bool parse_16bit_inst(uint16_t const w0, uint32_t addr, inst& out_inst) {
  out_inst.len = 2;

  if ((w0 & 0xFE00) == 0xB400) { // 4.6.99 PUSH, T1 encoding (pg 4-211)
    uint16_t const regs = uint16_t(((w0 & 0x0100u) << 6u) | (w0 & 0x00FFu));
    out_inst.type = inst_type::PUSH;
    out_inst.i.push = inst_push{ .register_list = regs };
    return true;
  }

  if ((w0 & 0xF800) == 0xE000) { // 4.6.12 B, T2 encoding (pg 4-38)
    out_inst.type = inst_type::BRANCH;
    int const sext = 1 << 11;
    int const imm32 = (int((w0 & 0x7ff) << 1) ^ sext) - sext;
    out_inst.i.branch = inst_branch{ .label = uint32_t(int(addr + 4) + imm32) };
    return true;
  }

  if (w0 == 0xBF00) { // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP;
    out_inst.i.nop = inst_nop{};
    return true;
  }

  return false;
}

bool parse_32bit_inst(uint16_t const w0, uint16_t const w1, inst& out_inst) {
  out_inst.len = 4;
  (void)w0; (void)w1;
  return true;
}

bool parse_inst(char const *text, uint32_t addr, inst& out_inst) {
  uint16_t w0;
  memcpy(&w0, text + addr, 2);
  if (is_16bit_inst(w0)) { return parse_16bit_inst(w0, addr, out_inst); }
  uint16_t w1;
  memcpy(&w1, text + addr + 2, 2);
  return parse_32bit_inst(w0, w1, out_inst);
}
}

bool thumb2_find_log_strs_in_func(elf const& e,
                                  elf_symbol32 const& func) {
  elf_section_hdr32 const& func_sec_hdr = e.sec_hdrs[func.st_shndx];
  uint32_t const func_start = (func.st_value - func_sec_hdr.sh_addr) & ~1u;
  uint32_t const func_end = func_start + func.st_size;
  uint32_t const func_ofs = func_sec_hdr.sh_offset;

  printf("Scanning %s: %x (%x-%x):\n",
         &e.strtab[func.st_name],
         func.st_value,
         func_start,
         func_end);

  std::stack<reg_state> paths;
  paths.push(reg_state{.addr = func_start});

  while (!paths.empty()) {
    reg_state s = paths.top();
    paths.pop();

    inst decoded_inst;
    parse_inst(&e.bytes[func_ofs], s.addr, decoded_inst);
    print(decoded_inst);
  }

  return true;
}
