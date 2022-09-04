#include "nl_thumb2.h"
#include "nl_elf.h"

#include <cstdint>
#include <cassert>
#include <stack>

namespace {

// Condition Codes

#define CONDITION_CODE_X_LIST() \
  X(EQ, 0b0000) \
  X(NE, 0b0001) \
  X(CS, 0b0010) \
  X(CC, 0b0011) \
  X(MI, 0b0100) \
  X(PL, 0b0101) \
  X(VS, 0b0110) \
  X(VC, 0b0111) \
  X(HS, 0b1000) \
  X(LS, 0b1001) \
  X(GE, 0b1010) \
  X(LT, 0b1011) \
  X(GT, 0b1100) \
  X(LE, 0b1101) \
  X(AL1, 0b1110) \
  X(AL2, 0b1111)

#define X(NAME, VAL) NAME = VAL,
enum class cond_code : uint8_t { CONDITION_CODE_X_LIST() };
#undef X

#define X(NAME, VAL) case cond_code::NAME: return #NAME;
char const *cond_code_name(cond_code cc) {
  switch (cc) { CONDITION_CODE_X_LIST() }
  return "unknown";
}
#undef X

// Registers

char const *s_reg_names[] = {
  "R0", "R1", "R2",  "R3",  "R4",  "R5", "R6", "R7",
  "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC",
};

// Instructions

#define INST_TYPE_X_LIST() \
  X(PUSH, push) \
  X(POP, pop) \
  X(NOP, nop) \
  X(BRANCH, branch) \
  X(BRANCH_LINK, branch_link) \
  X(BRANCH_LINK_XCHG, branch_link_xchg) \
  X(BRANCH_XCHG, branch_xchg) \
  X(SVC, svc)

#define X(ENUM, TYPE) ENUM,
enum class inst_type { INST_TYPE_X_LIST() };
#undef X

struct inst_push { uint16_t reg_list; };
struct inst_pop { uint16_t reg_list; };
struct inst_nop {};
struct inst_branch { uint32_t label; cond_code cc; };
struct inst_branch_link { uint32_t label; };
struct inst_branch_link_xchg { uint32_t label; };
struct inst_branch_xchg { uint16_t reg; };
struct inst_svc { uint32_t label; };

void print(inst_push const& p) {
  printf("  PUSH 0x%04x { ", p.reg_list);
  for (int i = 0; i < 16; ++i) {
    if (p.reg_list & (1 << i)) { printf("%s ", s_reg_names[i]); }
  }
  printf("}\n");
}

void print(inst_pop const& i) { printf("  POP 0x%04x\n", (unsigned)i.reg_list); }
void print(inst_nop const&) { printf("  NOP\n"); }

void print(inst_branch const& i) {
  printf("  B (%s) %x\n", cond_code_name(i.cc), (unsigned)i.label);
}

void print(inst_branch_link const& i) { printf("  BL %x\n", (unsigned)i.label); }
void print(inst_branch_link_xchg const& i) { printf("  BLX %x\n", (unsigned)i.label); }
void print(inst_branch_xchg const& i) { printf("  BX %d\n", (unsigned)i.reg); }
void print(inst_svc const&) { printf("  SVC\n"); }

// Instruction (tagged union)

#define X(ENUM, TYPE) inst_##TYPE TYPE;
struct inst {
  unsigned len; // 2 or 4
  inst_type type;
  union { INST_TYPE_X_LIST() } i;
};
#undef X

#define X(ENUM, TYPE) case inst_type::ENUM: print(i.i.TYPE); return;
void print(inst const& i) {
  switch (i.type) { INST_TYPE_X_LIST() }
  printf("  unknown\n");
}
#undef X

//

struct reg_state {
  uint32_t addr;
  uint32_t regs[16];
  uint16_t known = 0;
};

int sext(int x, int sign_bit) { int const m = 1 << sign_bit; return (x ^ m) - m; }

bool is_16bit_inst(uint16_t w0) {
  // 3.1 Instruction set encoding, Table 3-1 (pg 3-2)
  if ((w0 & 0xF800) == 0xE000) { return true; }
  if ((w0 & 0xE000) == 0xE000) { return false; }
  return true;
}

bool parse_16bit_inst(uint16_t const w0, uint32_t const addr, inst& out_inst) {
  out_inst.len = 2;

  if ((w0 & 0xFE00) == 0xB400) { // 4.6.99 PUSH, T1 encoding (pg 4-211)
    out_inst.type = inst_type::PUSH;
    out_inst.i.push =
      inst_push{ .reg_list = uint16_t(((w0 & 0x0100u) << 6u) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFE00) == 0xBC00) { // 4.6.98 POP, T1 encoding (pg 4-209)
    out_inst.type = inst_type::POP;
    out_inst.i.pop =
      inst_pop{ .reg_list = uint16_t(((w0 & 0x100u) << 7) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFF00) == 0xDF00) { // 4.6.12 B, T1 encoding (pg 4-38)
    cond_code const cc = (cond_code)((w0 >> 8u) & 0xFu);
    uint32_t const label = uint32_t(sext((w0 & 0xFF) << 1, 8));
    if ((uint8_t)cc == 0xFu) { // cc 0b1111 == SVC, 4.6.181 SVC (pg 4-375)
      out_inst.type = inst_type::SVC;
      out_inst.i.svc = inst_svc{ .label = label };
    } else {
      out_inst.type = inst_type::BRANCH;
      out_inst.i.branch = inst_branch{ .label = label, .cc = cc };
    }
    return true;
  }

  if ((w0 & 0xF800) == 0xE000) { // 4.6.12 B, T2 encoding (pg 4-38)
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch =
      inst_branch{ .label = uint32_t(int(addr + 4) + sext((w0 & 0x7FF) << 1, 11)),
                   .cc = cond_code::AL1 };
    return true;
  }

  if ((w0 & 0xFF80) == 0x4700) { // 4.6.20 BX, T1 encoding (pg 4-54)
    out_inst.type = inst_type::BRANCH_XCHG;
    out_inst.i.branch_xchg = inst_branch_xchg{ .reg = uint16_t((w0 >> 3u) & 0xFu)};
    return true;
  }

  if (w0 == 0xBF00) { // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP;
    out_inst.i.nop = inst_nop{};
    return true;
  }

  printf("  Unknown: %04x\n", w0);
  return false;
}

bool parse_32bit_inst(uint16_t const w0,
                      uint16_t const w1,
                      uint32_t const addr,
                      inst& out_inst) {
  out_inst.len = 4;

  if (((w0 & 0xF800) == 0xF000) && ((w1 & 0xD000) == 0xD000)) { // 4.6.18 BL T1 (pg 4-50)
    uint32_t const sbit = (w0 >> 10u) & 1u;
    uint32_t const sext = ((sbit ^ 1u) - 1u) & 0xFF000000u;
    uint32_t const i1 = (1u - (((w1 >> 13u) & 1u) ^ sbit)) << 23u;
    uint32_t const i2 = (1u - (((w1 >> 11u) & 1u) ^ sbit)) << 22u;
    uint32_t const imm10 = (w0 & 0x3FFu) << 12u;
    uint32_t const imm11 = (w1 & 0x7FFu) << 1u;
    uint32_t const imm32 = sext | i1 | i2 | imm10 | imm11;
    out_inst.type = inst_type::BRANCH_LINK;
    out_inst.i.branch_link = inst_branch_link{ .label = addr + imm32 };
    return true;
  }

  printf("  Unknown: %04x %04x\n", w0, w1);
  return false;
}

bool parse_inst(char const *text, uint32_t addr, inst& out_inst) {
  uint16_t w0;
  memcpy(&w0, text + addr, 2);
  if (is_16bit_inst(w0)) { return parse_16bit_inst(w0, addr, out_inst); }
  uint16_t w1;
  memcpy(&w1, text + addr + 2, 2);
  return parse_32bit_inst(w0, w1, addr, out_inst);
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

    while (s.addr < func_end) {
      inst decoded_inst;
      if (!parse_inst(&e.bytes[func_ofs], s.addr, decoded_inst)) { break; }
      print(decoded_inst);
      s.addr += decoded_inst.len;
    }
  }

  return true;
}
