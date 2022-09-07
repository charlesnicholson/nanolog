#include "nl_thumb2.h"
#include "nl_elf.h"

#include <cstdint>
#include <cassert>
#include <stack>
#include <vector>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

namespace {

// Condition Codes

#define CONDITION_CODE_X_LIST() \
  X(EQ, 0b0000) X(NE, 0b0001) X(CS, 0b0010) X(CC, 0b0011) \
  X(MI, 0b0100) X(PL, 0b0101) X(VS, 0b0110) X(VC, 0b0111) \
  X(HS, 0b1000) X(LS, 0b1001) X(GE, 0b1010) X(LT, 0b1011) \
  X(GT, 0b1100) X(LE, 0b1101) X(AL1, 0b1110) X(AL2, 0b1111)

#define X(NAME, VAL) NAME = VAL,
enum class cond_code : u8 { CONDITION_CODE_X_LIST() };
#undef X

#define X(NAME, VAL) case cond_code::NAME: return #NAME;
char const *cond_code_name(cond_code cc) {
  switch (cc) { CONDITION_CODE_X_LIST() }
  return "unknown";
}
#undef X

// Registers

char const *s_rn[] = {
  "R0", "R1", "R2",  "R3",  "R4",  "R5", "R6", "R7",
  "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC",
};

// Instructions

#define INST_TYPE_X_LIST() \
  X(ADD_SP_IMM, add_sp_imm) \
  X(ADR, adr) \
  X(BRANCH, branch) \
  X(BRANCH_LINK, branch_link) \
  X(BRANCH_LINK_XCHG_REG, branch_link_xchg_reg) \
  X(BRANCH_XCHG, branch_xchg) \
  X(CBNZ, cmp_branch_nz) \
  X(CBZ, cmp_branch_z) \
  X(CMP_IMM, cmp_imm) \
  X(COUNT_LEADING_ZEROS, count_leading_zeros) \
  X(LOAD_BYTE_REG, load_byte_reg) \
  X(LOAD_BYTE_IMM, load_byte_imm) \
  X(LOAD_HALF_IMM, load_half_imm) \
  X(LOAD_IMM, load_imm) \
  X(LOAD_LIT, load_lit) \
  X(LSHIFT_LOG_IMM, lshift_log_imm) \
  X(LSHIFT_LOG_REG, lshift_log_reg) \
  X(MOV, mov) \
  X(MOV_IMM, mov_imm) \
  X(NOP, nop) \
  X(PUSH, push) \
  X(POP, pop) \
  X(RSHIFT_LOG, rshift_log) \
  X(STORE_BYTE_IMM, store_byte_imm) \
  X(STORE_IMM, store_imm) \
  X(SVC, svc) \
  X(TABLE_BRANCH_BYTE, table_branch_byte)

#define X(ENUM, TYPE) ENUM,
enum class inst_type : u8 { INST_TYPE_X_LIST() };
#undef X

struct inst_add_sp_imm { u8 src_reg, imm; };
struct inst_adr { u8 dst_reg, imm; };
struct inst_branch { u32 label; cond_code cc; };
struct inst_branch_link { u32 label; };
struct inst_branch_link_xchg_reg { u8 reg; };
struct inst_branch_xchg { u8 reg; };
struct inst_cmp_branch_nz { u8 reg, label; };
struct inst_cmp_branch_z { u8 reg, label; };
struct inst_cmp_imm { u8 reg, imm; };
struct inst_count_leading_zeros { u8 dst_reg, src_reg; };
struct inst_load_byte_imm { u8 dst_reg, src_reg, imm; };
struct inst_load_byte_reg { u8 dst_reg, base_reg, ofs_reg; };
struct inst_load_half_imm { u8 dst_reg, src_reg, imm; };
struct inst_load_imm { u16 imm; u8 dst_reg, src_reg; };
struct inst_load_lit { u32 label; u8 reg; };
struct inst_lshift_log_imm { u8 dst_reg, src_reg, imm; };
struct inst_lshift_log_reg { u8 dst_reg, src_reg; };
struct inst_mov { u8 dst_reg, src_reg; };
struct inst_mov_imm { u32 imm; u8 reg; };
struct inst_push { u16 reg_list; };
struct inst_pop { u16 reg_list; };
struct inst_nop {};
struct inst_rshift_log { u8 dst_reg, src_reg, imm; };
struct inst_store_byte_imm { u8 src_reg, dst_reg, imm; };
struct inst_store_imm { u8 src_reg, dst_reg; u16 imm; };
struct inst_svc { u32 label; };
struct inst_table_branch_byte { u8 base_reg, idx_reg; };

void print(inst_add_sp_imm const& a) {
  printf("  ADD %s, [SP, #%d]\n", s_rn[a.src_reg], (int)a.imm);
}

void print(inst_adr const& a) {
  printf("  ADR %s, PC, #%d\n", s_rn[a.dst_reg], (int)a.imm);
}

void print(inst_push const& p) {
  printf("  PUSH { ");
  for (int i = 0; i < 16; ++i) {
    if (p.reg_list & (1 << i)) { printf("%s ", s_rn[i]); }
  }
  printf("}\n");
}

void print(inst_pop const& p) {
  printf("  POP { ");
  for (int i = 0; i < 16; ++i) {
    if (p.reg_list & (1 << i)) { printf("%s ", s_rn[i]); }
  }
  printf("}\n");
}

void print(inst_nop const&) { printf("  NOP\n"); }

void print(inst_rshift_log const& r) {
  printf("  LSR %s, %s, #%d\n", s_rn[r.dst_reg], s_rn[r.src_reg], (int)r.imm);
}

void print(inst_branch const& i) {
  printf("  B%s %x\n",
         (i.cc != cond_code::AL1 && i.cc != cond_code::AL2) ? cond_code_name(i.cc) : "",
         i.label);
}

void print(inst_branch_link const& i) { printf("  BL %x\n", (unsigned)i.label); }

void print(inst_branch_link_xchg_reg const& b) {
  printf("  BLX %s\n", s_rn[b.reg]);
}

void print(inst_branch_xchg const& i) { printf("  BX %s\n", s_rn[i.reg]); }

void print(inst_cmp_branch_nz const& c) {
  printf("  CBNZ %s, %x\n", s_rn[c.reg], (unsigned)c.label);
}

void print(inst_cmp_branch_z const& c) {
  printf("  CBZ %s, %x\n", s_rn[c.reg], (unsigned)c.label);
}

void print(inst_cmp_imm const& c) {
  printf("  CMP_IMM %s, #%d\n", s_rn[c.reg], (int)c.imm);
}

void print(inst_count_leading_zeros const& c) {
  printf("  CLZ %s, %s\n", s_rn[c.dst_reg], s_rn[c.src_reg]);
}

void print(inst_load_byte_imm const& l) {
  printf("  LDRB_IMM %s, [%s, #%d]\n", s_rn[l.dst_reg], s_rn[l.src_reg], (int)l.imm);
};

void print(inst_load_byte_reg const& l) {
  printf("  LDRB_REG %s, [%s, %s]\n", s_rn[l.dst_reg], s_rn[l.base_reg], s_rn[l.ofs_reg]);
}

void print(inst_load_imm const& l) {
  printf("  LDR_IMM %s, [%s, #%d]\n", s_rn[l.dst_reg], s_rn[l.src_reg], (int)l.imm);
}

void print(inst_load_half_imm const& l) {
  printf("  LDRH_IMM %s, [%s, #%d]\n", s_rn[l.dst_reg], s_rn[l.src_reg], (int)l.imm);
}

void print(inst_load_lit const& l) {
  printf("  LDR %s, %x\n", s_rn[l.reg], l.label);
}

void print(inst_lshift_log_imm const& l) {
  printf("  LSL_IMM %s, %s, #%d\n", s_rn[l.dst_reg], s_rn[l.src_reg], (int)l.imm);
}

void print(inst_lshift_log_reg const& l) {
  printf("  LSL_REG %s, %s\n", s_rn[l.dst_reg], s_rn[l.src_reg]);
};

void print(inst_mov const& m) {
  printf("  MOV %s, %s\n", s_rn[m.dst_reg], s_rn[m.src_reg]);
}

void print(inst_mov_imm const& m) {
  printf("  MOV_IMM %s, #%d\n", s_rn[m.reg], (int)m.imm);
}

void print(inst_store_byte_imm const& s) {
  printf("  STRB_IMM %s, [%s, #%d]\n", s_rn[s.dst_reg], s_rn[s.src_reg], (int)s.imm);
};

void print(inst_store_imm const& s) {
  printf("  STR_IMM %s, [%s, #%d]\n", s_rn[s.src_reg], s_rn[s.dst_reg], (int)s.imm);
};

void print(inst_svc const&) { printf("  SVC\n"); }

void print(inst_table_branch_byte const& t) {
  printf(" TBB [%s, %s]\n", s_rn[t.base_reg], s_rn[t.idx_reg]);
}

// Instruction (tagged union)

#define X(ENUM, TYPE) inst_##TYPE TYPE;
struct inst {
  union { INST_TYPE_X_LIST() } i;
  inst_type type;
  u8 len; // 2 or 4
};
#undef X

#define X(ENUM, TYPE) case inst_type::ENUM: print(i.i.TYPE); return;
void print(inst const& i) {
  switch (i.type) { INST_TYPE_X_LIST() }
  printf("  unknown\n");
}
#undef X

// Instruction decoding

u32 decode_imm12(u32 imm12) {
  // 4.2.2 Operation (pg 4-9)
  if ((imm12 & 0xC00u) == 0) {
    u32 const imm8{imm12 & 0xFFu};
    switch ((imm12 >> 8u) & 3u) {
      case 0: return imm12;
      case 1: return (imm8 << 16) | imm8;
      case 2: return (imm8 << 24) | (imm8 << 8);
      case 3: return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
    }
  }
  u32 const x = 0x80u | (imm12 & 0x7Fu);
  u32 const n = (imm12 >> 7u) & 0x1Fu;
  return (x >> n) | (x << (32 - n)); // rotate into place
}

int sext(int x, int sign_bit) { int const m = 1 << sign_bit; return (x ^ m) - m; }

bool is_16bit_inst(u16 w0) {
  // 3.1 Instruction set encoding, Table 3-1 (pg 3-2)
  return ((w0 & 0xF800u) == 0xE000u) || ((w0 & 0xE000u) != 0xE000u);
}

bool parse_16bit_inst(u16 const w0, u32 const addr, inst& out_inst) {
  out_inst.len = 2;

  if ((w0 & 0xF800u) == 0xA800u) { // 4.5.5 ADD (SP + immediate), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.i.add_sp_imm =
      inst_add_sp_imm{ .src_reg = u8((w0 >> 8u) & 7u), .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xA000u) { // 4.6.7 ADR, T1 encoding (pg 4-28)
    out_inst.type = inst_type::ADR;
    out_inst.i.adr =
      inst_adr{ .dst_reg = u8((w0 >> 8u) & 7u), .imm = u8((w0 & 0xFFu) << 2u) };
    return true;
  }

  if ((w0 & 0xF000u) == 0xD000u) { // 4.6.12 B, T1 encoding (pg 4-38)
    cond_code const cc = (cond_code)((w0 >> 8u) & 0xFu);
    u32 const label = u32(sext((w0 & 0xFF) << 1, 8));
    if ((u8)cc == 0xFu) { // cc 0b1111 == SVC, 4.6.181 SVC (pg 4-375)
      out_inst.type = inst_type::SVC;
      out_inst.i.svc = inst_svc{ .label = label };
    } else {
      out_inst.type = inst_type::BRANCH;
      out_inst.i.branch = inst_branch{ .label = label, .cc = cc };
    }
    return true;
  }

  if ((w0 & 0xF800u) == 0xE000u) { // 4.6.12 B, T2 encoding (pg 4-38)
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = inst_branch{
      .label = u32(int(addr + 4) + sext((w0 & 0x7FF) << 1, 11)), .cc = cond_code::AL1 };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4780u) { // 4.6.19 BLX (register), T1 encoding (pg 4-52)
    out_inst.type = inst_type::BRANCH_LINK_XCHG_REG;
    out_inst.i.branch_link_xchg_reg =
      inst_branch_link_xchg_reg{ .reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4700u) { // 4.6.20 BX, T1 encoding (pg 4-54)
    out_inst.type = inst_type::BRANCH_XCHG;
    out_inst.i.branch_xchg = inst_branch_xchg{ .reg = u8((w0 >> 3u) & 0xFu)};
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB900u) { // 4.6.22 CBNZ, T1 encoding (pg 4-58)
    out_inst.type = inst_type::CBNZ;
    out_inst.i.cmp_branch_nz = inst_cmp_branch_nz{
      .reg = u8(w0 & 7u), .label = u8(2 + ((w0 >> 2u) & 0x1Eu) | ((w0 >> 3u) & 0x40u)) };
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB100u) { // 4.6.23 CBZ, T1 encoding (pg 4-60)
    out_inst.type = inst_type::CBZ;
    out_inst.i.cmp_branch_z = inst_cmp_branch_z{
      .reg = u8(w0 & 7u),
      .label = u8(2 + ((w0 >> 2u) & 0x1Eu) | ((w0 >> 3u) & 0x40u)) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2800u) { // 4.6.29 CMP (immediate), T1 encoding (pg 4-72)
    out_inst.type = inst_type::CMP_IMM;
    out_inst.i.cmp_imm =
      inst_cmp_imm{ .reg = u8((w0 >> 8u) & 7u), .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x6800u) { // 4.6.43 LDR (immediate), T1 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = inst_load_imm{
      .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u),
      .imm = u8(((w0 >> 6u) & 0x1Fu) << 2u) };
    return true;
  }

  // TODO: read label + imm, pass func start addr to parse
  if ((w0 & 0xF800u) == 0x4800u) { // 4.6.44 LDR (literal), T1 encoding (pg 4-102)
    out_inst.type = inst_type::LOAD_LIT;
    out_inst.i.load_lit = inst_load_lit{
      .label = ((w0 & 0xFFu) << 2u) + ((addr + 4u) & ~3u), .reg = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7800u) { // 4.6.46 LDRB (immediate), T1 encoding (pg 4-106)
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.i.load_byte_imm = inst_load_byte_imm{
      .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u),
      .imm = (u8)((w0 >> 6u) & 0x1Fu) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5C00u) { // 4.6.48 LDRB (register), T1 encoding (pg 4-110)
    out_inst.type = inst_type::LOAD_BYTE_REG;
    out_inst.i.load_byte_reg = inst_load_byte_reg {
      .dst_reg = u8(w0 & 7u),
      .base_reg = u8((w0 >> 3u) & 7u),
      .ofs_reg = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8800u) { // 4.6.55 LDRH (immediate), T1 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.i.load_half_imm = inst_load_half_imm{
      .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u),
      .imm = (u8)(((w0 >> 6u) & 0x1Fu) << 1u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0) { // 4.6.68 LSL (immediate), T1 encoding (pg 4-150)
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.i.lshift_log_imm = inst_lshift_log_imm{
      .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u),
      .imm = u8((w0 >> 6u) & 0x1Fu) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4080u) { // 4.6.69 LSL (register), T1 encoding (pg 4-152)
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.i.lshift_log_reg =
      inst_lshift_log_reg{ .dst_reg = u8(w0 & 7u), .src_reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x800u) { // 4.6.70 LSR (immediate), T1 encoding (pg 4-154)
    u8 const imm5 = u8((w0 >> 6u) & 0x1Fu);
    out_inst.type = inst_type::RSHIFT_LOG;
    out_inst.i.rshift_log = inst_rshift_log{
      .dst_reg = u8(w0 & 7u), .src_reg = u8((w0 >> 3u) & 7u), .imm = imm5 ? imm5 : u8(32) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2000u) { // 4.6.76 MOV (immediate), T1 encoding (pg 4-166)
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm =
      inst_mov_imm{ .imm = u8(w0 & 0xFFu), .reg = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4600u) { // 4.6.77 MOV (register), T1 encoding (pg 4-168)
    out_inst.type = inst_type::MOV;
    out_inst.i.mov = inst_mov{
      .src_reg = u8((w0 >> 3u) & 0xFu), .dst_reg = u8((w0 & 7u) | ((w0 & 8u) >> 4u)) };
    return true;
  }

  if (w0 == 0xBF00u) { // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP;
    out_inst.i.nop = inst_nop{};
    return true;
  }

  if ((w0 & 0xFE00u) == 0xBC00u) { // 4.6.98 POP, T1 encoding (pg 4-209)
    out_inst.type = inst_type::POP;
    out_inst.i.pop =
      inst_pop{ .reg_list = u16(((w0 & 0x100u) << 7) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0xB400u) { // 4.6.99 PUSH, T1 encoding (pg 4-211)
    out_inst.type = inst_type::PUSH;
    out_inst.i.push =
      inst_push{ .reg_list = u16(((w0 & 0x0100u) << 6u) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x9000u) { // 4.6.162 STR (immediate), T2 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = inst_store_imm{
      .dst_reg = 13, .src_reg = u8((w0 >> 8u) & 7u), .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7000u) { // 4.6.164 STRB (immediate), T1 encoding (pg 4-341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = inst_store_byte_imm{
      .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u),
      .imm = u8((w0 >> 6u) & 0x1Fu) };
    return true;
  }

  printf("  Unknown: %04x\n", w0);
  return false;
}

bool parse_32bit_inst(u16 const w0,
                      u16 const w1,
                      u32 const addr,
                      inst& out_inst) {
  out_inst.len = 4;

  // 4.6.18 BL, T1 encoding (pg 4-50)
  if (((w0 & 0xF800) == 0xF000) && ((w1 & 0xD000) == 0xD000)) {
    u32 const sbit = (w0 >> 10u) & 1u;
    u32 const sext = ((sbit ^ 1u) - 1u) & 0xFF000000u;
    u32 const i1 = (1u - (((w1 >> 13u) & 1u) ^ sbit)) << 23u;
    u32 const i2 = (1u - (((w1 >> 11u) & 1u) ^ sbit)) << 22u;
    u32 const imm10 = (w0 & 0x3FFu) << 12u;
    u32 const imm11 = (w1 & 0x7FFu) << 1u;
    u32 const imm32 = sext | i1 | i2 | imm10 | imm11;
    out_inst.type = inst_type::BRANCH_LINK;
    out_inst.i.branch_link = inst_branch_link{ .label = addr + 4 + imm32 };
    return true;
  }

  // 4.6.26 CLZ, T1 encoding (pg 4-66)
  if (((w0 & 0xFFF0) == 0xFAB0) && ((w1 & 0xF0F0) == 0xF080)) {
    out_inst.type = inst_type::COUNT_LEADING_ZEROS;
    out_inst.i.count_leading_zeros = inst_count_leading_zeros{
      .src_reg = u8(w1 & 7u), .dst_reg = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFF0) == 0xF8D0) { // 4.6.43 LDR (immediate), T3 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = inst_load_imm{
      .src_reg = u8(w0 & 0xFu), .dst_reg = u8((w1 >> 12u) & 7u), .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  // 4.6.76 MOV (immediate), T2 encoding (pg 4-166)
  if (((w0 & 0xFBEF) == 0xF04F) && (w1 & 0x8000) == 0) {
    unsigned const imm12 =
      (w1 & 0xFFu) | ((w1 >> 4u) & 0x700u) | (unsigned(w0 << 2u) & 0x1000u);
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm =
      inst_mov_imm{ .imm = decode_imm12(imm12), .reg = u8((w1 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFF0) == 0xF8C0) { // 4.6.162 STR (immediate), T3 encoding (4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = inst_store_imm{
      .src_reg = u8(w1 >> 12u),
      .dst_reg = u8(w0 & 0xFu),
      .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  // 4.6.168 TBB, T1 encoding (pg 4-389)
  if (((w0 & 0xFFF0) == 0xE8D0) && ((w1 & 0xF0) == 0)) {
    out_inst.type = inst_type::TABLE_BRANCH_BYTE;
    out_inst.i.table_branch_byte =
      inst_table_branch_byte{ .base_reg = u8(w0 & 7u), .idx_reg = u8(w1 & 7u) };
    return true;
  }

  printf("  Unknown: %04x %04x\n", w0, w1);
  return false;
}

bool parse_inst(char const *text, u32 addr, inst& out_inst) {
  u16 w0, w1;
  memcpy(&w0, text + addr, 2);
  if (is_16bit_inst(w0)) { return parse_16bit_inst(w0, addr, out_inst); }
  memcpy(&w1, text + addr + 2, 2);
  return parse_32bit_inst(w0, w1, addr, out_inst);
}
}

struct reg_state {
  u32 addr, regs[16];
  u16 known = 0;
};

bool thumb2_find_log_strs_in_func(elf const& e,
                                  elf_symbol32 const& func) {
  elf_section_hdr32 const& func_sec_hdr = e.sec_hdrs[func.st_shndx];
  u32 const func_start = (func.st_value - func_sec_hdr.sh_addr) & ~1u;
  u32 const func_end = func_start + func.st_size;
  u32 const func_ofs = func_sec_hdr.sh_offset;

  printf("Scanning %s: addr %x, len %x, range %x-%x:\n",
         &e.strtab[func.st_name],
         func.st_value,
         func.st_size,
         func_start,
         func_end);

  std::stack<reg_state, std::vector<reg_state>> paths;
  paths.push(reg_state{.addr = func_start});

  while (!paths.empty()) {
    reg_state s = paths.top();
    paths.pop();

    while (s.addr < func_end) {
      inst decoded_inst;
      if (!parse_inst(&e.bytes[func_ofs], s.addr, decoded_inst)) { break; }
      printf("  %x ", s.addr);
      print(decoded_inst);
      s.addr += decoded_inst.len;
    }
  }

  return true;
}
