#include "nl_thumb2_inst.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace {

#define X(NAME, VAL) case cond_code::NAME: return #NAME;
char const *cond_code_name(cond_code cc) {
  switch (cc) { CONDITION_CODE_X_LIST() }
  return "unknown";
}
#undef X

#define X(NAME) #NAME,
char const *s_rn[] = { REGISTER_X_LIST() };
#undef X

#define X(NAME) #NAME,
char const *s_sn[] = { SHIFT_X_LIST() };
#undef X

void print(inst_add_carry_reg const& a) {
  printf("  ADC_REG %s, %s, %s <%s #%d>\n", s_rn[a.d], s_rn[a.m], s_rn[a.n],
    s_sn[int(a.shift.t)], int(a.shift.n));
};

void print(inst_add_imm const& a) {
  printf("  ADD_IMM %s, %s, #%d\n", s_rn[a.d], s_rn[a.n], int(a.imm));
};

void print(inst_add_sp_imm const& a) {
  printf("  ADD %s, [SP, #%d]\n", s_rn[a.d], (int)a.imm);
}

void print(inst_add_reg const& a) {
  printf("  ADD_REG %s, %s, %s <%s #%d>\n", s_rn[a.d], s_rn[a.n], s_rn[a.m],
    s_sn[int(a.shift.t)], int(a.shift.n));
};

void print(inst_adr const& a) {
  printf("  ADR %s, PC, #%d\n", s_rn[a.dst_reg], (int)a.imm);
}

void print(inst_and_reg const& a) {
  printf("  AND_REG %s, %s, %s <%s #%d>\n", s_rn[a.dst_reg], s_rn[a.op1_reg],
    s_rn[a.op2_reg], s_sn[int(a.shift.t)], int(a.shift.n));
};

void print(inst_and_reg_imm const& a) {
  printf("  AND_REG_IMM %s, %s, #%d\n", s_rn[a.dst_reg], s_rn[a.src_reg], int(a.imm));
};

void print(inst_push const& p) {
  printf("  PUSH { ");
  for (int i = 0; i < 16; ++i) { if (p.reg_list & (1 << i)) { printf("%s ", s_rn[i]); } }
  printf("}\n");
}

void print(inst_pop const& p) {
  printf("  POP { ");
  for (int i = 0; i < 16; ++i) { if (p.reg_list & (1 << i)) { printf("%s ", s_rn[i]); } }
  printf("}\n");
}

void print(inst_nop const&) { printf("  NOP\n"); }

void print(inst_rshift_log const& r) {
  printf("  LSR %s, %s, #%d\n", s_rn[r.dst_reg], s_rn[r.src_reg], int(r.shift.n));
}

void print(inst_rshift_arith_imm const& r) {
  printf("  ASR %s, %s, #%d\n", s_rn[r.dst_reg], s_rn[r.src_reg], int(r.shift.n));
};

void print(inst_bit_clear_imm const& b) {
  printf("  BIC_IMM %s, %s, #%d\n", s_rn[b.d], s_rn[b.n], int(b.imm));
};

void print(inst_bit_clear_reg const& b) {
  printf("  BIC_REG %s, %s, %s, <%s #%d>\n", s_rn[b.d], s_rn[b.n], s_rn[b.m],
    s_sn[int(b.shift.t)], int(b.shift.n));
};

void print(inst_bitfield_extract_unsigned const& b) {
  printf("  UBFX %s, %s, #%d, #%d\n", s_rn[b.d], s_rn[b.n], int(b.lsbit),
    int(b.widthminus1 + 1));
};

void print(inst_branch const& i) {
  printf("  B%s #%d (%x)\n", i.cc >= cond_code::AL1 ? "" : cond_code_name(i.cc),
    int(i32(i.imm)), unsigned(i.addr));
}

void print(inst_branch_link const& i) {
  printf("  BL #%d (%x)\n", unsigned(i.imm), unsigned(i.addr));
}

void print(inst_branch_link_xchg_reg const& b) { printf("  BLX %s\n", s_rn[b.reg]); }
void print(inst_branch_xchg const& i) { printf("  BX %s\n", s_rn[int(i.m)]); }

void print(inst_cmp_branch_nz const& c) {
  printf("  CBNZ %s, #%d (%x)\n", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
}

void print(inst_cmp_branch_z const& c) {
  printf("  CBZ %s, #%d (%x)\n", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
}

void print(inst_cmp_imm const& c) {
  printf("  CMP_IMM %s, #%d\n", s_rn[c.reg], int(c.imm));
}

void print(inst_cmp_reg const& c) {
  printf("  CMP_REG %s, %s <%s #%d>\n", s_rn[c.op1_reg], s_rn[c.op2_reg],
    s_sn[int(c.shift.t)], int(c.shift.n));
}

void print(inst_if_then const& i) {
  printf("  IT %x, %x\n", unsigned(i.firstcond), unsigned(i.mask));
};

void print(inst_count_leading_zeros const& c) {
  printf("  CLZ %s, %s\n", s_rn[c.d], s_rn[c.m]);
}

void print(inst_load_byte_imm const& l) {
  printf("  LDRB_IMM %s, [%s, #%d]\n", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_byte_reg const& l) {
  printf("  LDRB_REG %s, [%s, %s]\n", s_rn[l.dst_reg], s_rn[l.base_reg], s_rn[l.ofs_reg]);
}

void print(inst_load_dbl_reg const& l) {
  printf("  LDRD_REG %s, %s, [%s], #%s%d\n", s_rn[l.dst1_reg], s_rn[l.dst2_reg],
    s_rn[l.base], l.add ? "" : "-", int(l.imm));
};

void print(inst_load_imm const& l) {
  printf("  LDR_IMM %s, [%s], #%d\n", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_half_imm const& l) {
  printf("  LDRH_IMM %s, [%s, #%d]\n", s_rn[l.dst_reg], s_rn[l.src_reg], int(l.imm));
}

void print(inst_load_lit const& l) {
  printf("  LDR %s, [PC, #%s%d] (%x)\n", s_rn[l.t], l.add ? "" : "-", int(l.imm),
    unsigned(l.addr));
}

void print(inst_load_mult_inc_after const& l) {
  printf("  LDMIA %s!, { ", s_rn[l.base_reg]);
  for (int i = 0; i < 16; ++i) { if (l.regs & (1 << i)) { printf("%s ", s_rn[i]); } }
  printf("}\n");
}

void print(inst_load_reg const& l) {
  printf("  LDR_REG %s, [%s, %s <%s #%d>]\n", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_lshift_log_imm const& l) {
  printf("  LSL_IMM %s, %s, #%d\n", s_rn[l.dst_reg], s_rn[l.src_reg], int(l.imm));
}

void print(inst_lshift_log_reg const& l) {
  printf("  LSL_REG %s, %s\n", s_rn[l.dst_reg], s_rn[l.src_reg]);
}

void print(inst_mov const& m) {
  printf("  MOV %s, %s\n", s_rn[m.d], s_rn[m.m]);
}

void print(inst_mov_imm const& m) {
  printf("  MOV_IMM %s, #%d (%#x)\n", s_rn[m.d], int(m.imm), unsigned(m.imm));
}

void print(inst_mov_neg_imm const& m) {
  printf("  MOV_NEG_IMM %s, #%d (%#x)\n", s_rn[m.d], unsigned(m.imm), unsigned(m.imm));
};

void print(inst_or_reg_imm const& o) {
  printf("  ORR_IMM %s, %s, #%d\n", s_rn[o.d], s_rn[o.n], int(o.imm));
};

void print(inst_or_reg_reg const& o) {
  printf("  ORR_REG %s, %s, %s <%s #%d>\n", s_rn[o.d], s_rn[o.m], s_rn[o.n],
    s_sn[int(o.shift.t)], int(o.shift.n));
};

void print(inst_store_byte_imm const& s) {
  printf("  STRB_IMM %s, [%s, #%d]\n", s_rn[s.t], s_rn[s.n], int(s.imm));
}

void print(inst_store_imm const& s) {
  printf("  STR_IMM %s, [%s, #%d]\n", s_rn[s.t], s_rn[s.n], int(s.imm));
}

void print(inst_store_mult_dec_bef const& s) {
  printf("  STMDB %s!, { ", s_rn[s.n]);
  for (int i = 0; i < 16; ++i) { if (s.regs & (1 << i)) { printf("%s ", s_rn[i]); } }
  printf("}\n");
}

void print(inst_store_reg const& s) {
  printf("  STR_REG %s, [%s, %s <%s #%d>\n", s_rn[s.src_reg], s_rn[s.base_reg],
    s_rn[s.ofs_reg], s_sn[int(s.shift.t)], int(s.shift.n));
};

void print(inst_store_reg_byte const& s) {
  printf("  STR_REG_B %s, [%s, #%d]\n", s_rn[s.t], s_rn[s.n], int(s.imm));
};

void print(inst_store_reg_byte_unpriv const& s) {
  printf("  STRBT %s, [%s, #%d]\n", s_rn[s.t], s_rn[s.n], int(s.imm));
};

void print(inst_sub_imm const& s) {
  printf("  SUB_IMM %s, %s, #%d\n", s_rn[s.d], s_rn[s.n], int(s.imm));
}

void print(inst_sub_reg const& s) {
  printf("  SUB_REG %s, %s, %s <%s #%u>\n", s_rn[s.dst_reg], s_rn[s.op1_reg],
    s_rn[s.op2_reg], s_sn[int(s.shift.t)], unsigned(s.shift.n));
}

void print(inst_sub_rev_imm const& s) {
  printf("  RSB %s, %s, #%d\n", s_rn[s.d], s_rn[s.n], int(s.imm));
}

void print(inst_svc const& s) { printf("  SVC %x\n", unsigned(s.imm)); }

void print(inst_table_branch_byte const& t) {
  printf("  TBB [%s, %s]\n", s_rn[t.base_reg], s_rn[t.idx_reg]);
}

u32 decode_imm12(u32 imm12) { // 4.2.2 Operation (pg 4-9)
  if ((imm12 & 0xC00u) == 0) {
    u32 const imm8{imm12 & 0xFFu};
    switch ((imm12 >> 8u) & 3u) {
      case 0: return imm12;
      case 1: return (imm8 << 16) | imm8;
      case 2: return (imm8 << 24) | (imm8 << 8);
      case 3: return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
    }
  }
  u32 const x{0x80u | (imm12 & 0x7Fu)}, n{(imm12 >> 7u) & 0x1Fu};
  return (x >> n) | (x << (32 - n));
}

imm_shift decode_imm_shift(u8 const type, u8 const imm5) {
  switch (type & 3u) {  // 4.3.2 Shift Operations (pg 4-11)
    case 0b00: return imm_shift{ .t = imm_shift_type::LSL, .n = imm5 };
    case 0b01: return imm_shift{ .t = imm_shift_type::LSR, .n = imm5 ? imm5 : u8(32) };
    case 0b10: return imm_shift{ .t = imm_shift_type::ASR, .n = imm5 ? imm5 : u8(32) };
    case 0b11:
      if (imm5 == 0u) { return imm_shift{ .t = imm_shift_type::RRX, .n = 1 }; }
      return imm_shift{ .t = imm_shift_type::ROR, .n = imm5 };
  }
  __builtin_unreachable();
}

u32 sext(u32 x, unsigned sign_bit) {
  return u32((x ^ u32(1u << sign_bit)) - u32(1u << sign_bit));
}

bool is_16bit_inst(u16 w0) {
  // 3.1 Instruction set encoding, Table 3-1 (pg 3-2)
  return ((w0 & 0xF800u) == 0xE000u) || ((w0 & 0xE000u) != 0xE000u);
}

bool decode_16bit_inst(u16 const w0, inst& out_inst) {
  out_inst.len = 2;

  if ((w0 & 0xF800u) == 0xA800u) { // 4.5.5 ADD (SP + imm), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.i.add_sp_imm = { .d = u8((w0 >> 8u) & 7u), .imm = u16(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4140u) { // 4.6.2 ADC (reg), T1 encoding (pg 4-18)
    out_inst.type = inst_type::ADD_CARRY_REG;
    out_inst.i.add_carry_reg = { .d = u8(w0 & 7u), .n = u8(w0 & 7u),
      .m = u8((w0 >> 3u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1C00u) { // 4.6.3 ADD (imm), T1 encoding (pg 4-20)
    out_inst.type = inst_type::ADD_IMM;
    out_inst.i.add_imm = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .imm = u16((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x3000u) { // 4.6.3 ADD (imm), T2 encoding (pg 4-20)
    u8 const dn{u8((w0 >> 8u) & 7u)};
    out_inst.type = inst_type::ADD_IMM;
    out_inst.i.add_imm = { .imm = u8(w0 & 0xFFu), .d = dn, .n = dn };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4400u) { // 4.6.4 ADD (reg), T2 encoding (pg 4-22)
    u8 const dn{u8((w0 >> 7u) & 1u)}, rdn{u8(w0 & 7u)}, d{u8((dn << 3) | rdn)},
      m{u8((w0 >> 3u) & 7u)};
    if ((d == 13) || (m == 13)) {
      out_inst.type = inst_type::ADD_SP_IMM;
      out_inst.i.add_sp_imm = { .d = d, .imm = d };
    } else {
      out_inst.type = inst_type::ADD_REG;
      out_inst.i.add_reg = { .shift = decode_imm_shift(0b00, 0), .d = d, .n = d, .m = m };
    }
    return true;
  }

  if ((w0 & 0xFF80u) == 0xB000u) { // 4.6.5 ADD (SP + imm), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.i.add_sp_imm = { .d = u8(reg::SP), .imm = u16((w0 & 0x7Fu) << 2u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xA000u) { // 4.6.7 ADR, T1 encoding (pg 4-28)
    out_inst.type = inst_type::ADR;
    out_inst.i.adr = { .dst_reg = u8((w0 >> 8u) & 7u), .imm = u8((w0 & 0xFFu) << 2u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4000u) { // 4.6.9 AND, T1 encoding (pg 4-32)
    out_inst.type = inst_type::AND_REG;
    out_inst.i.and_reg = { .shift = decode_imm_shift(0b00, 0),
      .dst_reg = u8(w0 & 7u), .op1_reg = u8(w0 & 7u), .op2_reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800) == 0x1000u) { // 4.6.10 ASR (imm), T1 encoding (pg 4-34)
    out_inst.type = inst_type::RSHIFT_ARITH_IMM;
    out_inst.i.rshift_arith_imm = { .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u), .shift = decode_imm_shift(0b10, (w0 >> 6u) & 0x1Fu) };
    return true;
  }

  if ((w0 & 0xF000u) == 0xD000u) { // 4.6.12 B, T1 encoding (pg 4-38)
    cond_code const cc{cond_code(((w0 >> 8u) & 0xFu))};
    u32 const imm32{u32(sext((w0 & 0xFFu) << 1u, 8u))};
    if (u8(cc) == 0xFu) { // cc 0b1111 == SVC, 4.6.181 SVC (pg 4-375)
      out_inst.type = inst_type::SVC; out_inst.i.svc = { .imm = imm32 };
    } else {
      out_inst.type = inst_type::BRANCH; out_inst.i.branch = { .imm = imm32, .cc = cc,
        .addr = u32(out_inst.addr + 4u + imm32) };
    }
    return true;
  }

  if ((w0 & 0xF800u) == 0xE000u) { // 4.6.12 B, T2 encoding (pg 4-38)
    u32 const imm32{u32(sext((w0 & 0x7FFu) << 1u, 11u))};
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .cc = cond_code::AL2, .imm = imm32,
      .addr = u32(out_inst.addr + 4u + imm32)  };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4780u) { // 4.6.19 BLX (reg), T1 encoding (pg 4-52)
    out_inst.type = inst_type::BRANCH_LINK_XCHG_REG;
    out_inst.i.branch_link_xchg_reg = { .reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4700u) { // 4.6.20 BX, T1 encoding (pg 4-54)
    out_inst.type = inst_type::BRANCH_XCHG;
    out_inst.i.branch_xchg = { .m = u8((w0 >> 3u) & 0xFu)};
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB900u) { // 4.6.22 CBNZ, T1 encoding (pg 4-58)
    u32 const imm5{(w0 >> 3u) & 0x1Fu}, i{(w0 >> 9u) & 1u}, imm32{(imm5 << 1u) | (i << 6u)};
    out_inst.type = inst_type::CBNZ;
    out_inst.i.cmp_branch_nz = { .n = u8(w0 & 7u), .imm = u8(imm32),
      .addr = out_inst.addr + 4u + imm32 };
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB100u) { // 4.6.23 CBZ, T1 encoding (pg 4-60)
    u32 const imm5{(w0 >> 3u) & 0x1Fu}, i{(w0 >> 9u) & 1u}, imm32{(imm5 << 1u) | (i << 6u)};
    out_inst.type = inst_type::CBZ;
    out_inst.i.cmp_branch_z = { .n = u8(w0 & 7u), .imm = u8(imm32),
      .addr = out_inst.addr + 4u + imm32 };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2800u) { // 4.6.29 CMP (imm), T1 encoding (pg 4-72)
    out_inst.type = inst_type::CMP_IMM;
    out_inst.i.cmp_imm = { .reg = u8((w0 >> 8u) & 7u), .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4280u) { // 4.6.30 CMP (reg), T1 encoding (pg 4-74)
    out_inst.type = inst_type::CMP_REG;
    out_inst.i.cmp_reg = { .shift = decode_imm_shift(0b00, 0),
      .op1_reg = u8(w0 & 7u), .op2_reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0xBF00u) { // 4.6.39 IT, T1 encoding (pg 4-92)
    u8 const mask{u8(w0 & 0xFu)};
    if (mask == 0) { // T1 encoding note: '0000' = nop-compatible hint
      out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    } else {
      out_inst.type = inst_type::IF_THEN;
      out_inst.i.if_then = { .firstcond = u8((w0 >> 4u) & 0xFu), .mask = mask };
    }
    return true;
  }

  if ((w0 & 0xF800u) == 0x6800u) { // 4.6.43 LDR (imm), T1 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .imm = u16(((w0 >> 6u) & 0x1Fu) << 2u), .add = 1u,
      .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .index = 1u };
    return true;
  }

  // TODO: read label + imm, pass func start addr to parse
  if ((w0 & 0xF800u) == 0x4800u) { // 4.6.44 LDR (literal), T1 encoding (pg 4-102)
    u16 const imm{u16((w0 & 0xFFu) << 2u)};
    out_inst.type = inst_type::LOAD_LIT;
    out_inst.i.load_lit = { .imm = imm, .t = u8((w0 >> 8u) & 7u), .add = 1,
      .addr = u32(inst_align(out_inst.addr, 4) + imm + 4) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5800u) { // 4.6.45 LDR (register), T1 encoding (pg 4-104)
    out_inst.type = inst_type::LOAD_REG;
    out_inst.i.load_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7800u) { // 4.6.46 LDRB (imm), T1 encoding (pg 4-106)
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.i.load_byte_imm = { .imm = u8((w0 >> 6u) & 0x1Fu), .t = u8(w0 & 7u),
      .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5C00u) { // 4.6.48 LDRB (reg), T1 encoding (pg 4-110)
    out_inst.type = inst_type::LOAD_BYTE_REG;
    out_inst.i.load_byte_reg = { .dst_reg = u8(w0 & 7u), .base_reg = u8((w0 >> 3u) & 7u),
      .ofs_reg = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8800u) { // 4.6.55 LDRH (imm), T1 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.i.load_half_imm = { .imm = (u8)(((w0 >> 6u) & 0x1Fu) << 1u),
      .dst_reg = u8(w0 & 7u), .src_reg = u8((w0 >> 3u) & 7u) };
  }

  if ((w0 & 0xF800u) == 0) { // 4.6.68 LSL (imm), T1 encoding (pg 4-150)
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.i.lshift_log_imm = { .imm = u8((w0 >> 6u) & 0x1Fu), .dst_reg = u8(w0 & 7u),
      .src_reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4080u) { // 4.6.69 LSL (reg), T1 encoding (pg 4-152)
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.i.lshift_log_reg = { .dst_reg = u8(w0 & 7u), .src_reg = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x800u) { // 4.6.70 LSR (imm), T1 encoding (pg 4-154)
    out_inst.type = inst_type::RSHIFT_LOG;
    out_inst.i.rshift_log = { .dst_reg = u8(w0 & 7u), .src_reg = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b01, u8((w0 >> 6u) & 0x1Fu)) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2000u) { // 4.6.76 MOV (imm), T1 encoding (pg 4-166)
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm = { .imm = u8(w0 & 0xFFu), .d = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4600u) { // 4.6.77 MOV (reg), T1 encoding (pg 4-168)
    out_inst.type = inst_type::MOV;
    out_inst.i.mov = { .m = u8((w0 >> 3u) & 0xFu), .d = u8((w0 & 7u) | ((w0 & 8u) >> 4u)) };
    return true;
  }

  if (w0 == 0xBF00u) { // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    return true;
  }

  if ((w0 & 0xFFC0) == 0x4300) { // 4.6.92 ORR (reg), T1 encoding (pg 4-197)
    out_inst.type = inst_type::OR_REG_REG;
    out_inst.i.or_reg_reg = { .d = u8(w0 & 7u), .n = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0xBC00u) { // 4.6.98 POP, T1 encoding (pg 4-209)
    out_inst.type = inst_type::POP;
    out_inst.i.pop = { .reg_list = u16(((w0 & 0x100u) << 7) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0xB400u) { // 4.6.99 PUSH, T1 encoding (pg 4-211)
    out_inst.type = inst_type::PUSH;
    out_inst.i.push = { .reg_list = u16(((w0 & 0x0100u) << 6u) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4240u) { // 4.6.118 RSB (imm), T1 encoding (pg 4-249)
    out_inst.type = inst_type::SUB_REV_IMM;
    out_inst.i.sub_rev_imm = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .imm = 0 };
    return true;
  }

  if ((w0 & 0xF800u) == 0x6000u) { // 4.6.162 STR (imm), T1 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .imm = u16(((w0 >> 6u) & 0x1Fu) << 2u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x9000u) { // 4.6.162 STR (imm), T2 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .n = 13, .t = u8((w0 >> 8u) & 7u), .imm = u16(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5000u) { // 4.6.163 STR (reg), T1 encoding (pg 4-339)
    out_inst.type = inst_type::STORE_REG;
    out_inst.i.store_reg = { .src_reg = u8(w0 & 7u), .base_reg = u8((w0 >> 3u) & 7u),
      .ofs_reg = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7000u) { // 4.6.164 STRB (imm), T1 encoding (pg 4-341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16((w0 >> 6u) & 0x1Fu), .t = u8(w0 & 7u),
      .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1E00u) { // 4.6.176 SUB (imm), T1 encoding (pg 4-365)
    out_inst.type = inst_type::SUB_IMM;
    out_inst.i.sub_imm = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .imm = (w0 >> 6u) & 7u };
    return true;
  }

  if ((w0 & 0xF800u) == 0x3800u) { // 4.6.176 SUB (imm), T2 encoding (pg 4-365)
    out_inst.type = inst_type::SUB_IMM;
    out_inst.i.sub_imm = { .imm = w0 & 0xFFu, .d = u8((w0 >> 8u) & 7u),
      .n = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1A00u) { // 4.6.177 SUB (reg), T1 encoding (pg 4-367)
    out_inst.type = inst_type::SUB_REG;
    out_inst.i.sub_reg = { .shift = decode_imm_shift(0b00, 0),
      .dst_reg = u8(w0 & 7u), .op1_reg = u8((w0 >> 3u) & 7u),
      .op2_reg = u8((w0 >> 6u) & 7u) };
    return true;
  }

  return false;
}

bool decode_32bit_inst(u16 const w0, u16 const w1, inst& out_inst) {
  out_inst.len = 4;

  // 4.6.3 ADD (imm), T3 encoding (pg 4-20)
  if (((w0 & 0xFBE0u) == 0xF100u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 0x7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::ADD_IMM;
    out_inst.i.add_imm = { .n = u8(w0 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .imm = u16(decode_imm12((i << 11u) | (imm3 << 8u) | imm8)) };
    return true;
  }

  // 4.6.8 AND (imm), T1 encoding (pg 4-30)
  if (((w0 & 0xFBE0u) == 0xF000u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::AND_REG_IMM;
    out_inst.i.and_reg_imm = { .dst_reg = u8((w1 >> 8u) & 0xFu), .src_reg = u8(w0 & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.12 B, T3 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x8000u)) {
    cond_code const cc{cond_code((w0 >> 6u) & 0xFu)};
    if ((cc == cond_code::AL1) || (cc == cond_code::AL2)) { // cond<3:1> '111' is nop
      out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    } else {
      u32 const imm11{w1 & 0x7FFu}, imm6{w0 & 0x3Fu};
      u32 const j1{(w1 >> 13u) & 1u}, j2{(w1 >> 11u) & 1u};
      u32 const s{(w0 >> 10u) & 1u};
      u32 const imm32{
        sext((imm11 << 1u) | (imm6 << 11u) | (j1 << 17u) | (j2 << 18u) | (s << 19u), 19)};
      out_inst.type = inst_type::BRANCH;
      out_inst.i.branch = { .cc = cc, .imm = imm32};
    }
    return true;
  }

  // 4.6.12 B, T4 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x9000u)) {
    u32 const imm10{w0 & 0x3FFu}, imm11{w1 & 0x7FFu};
    u32 const s{(w0 >> 10u) & 1u};
    u32 const j1{(w1 >> 13u) & 1u}, j2{(w1 >> 11u) & 1u};
    u32 const i1{~(j1 ^ s) & 1u}, i2{~(j2 ^ s) & 1u};
    u32 const imm32{
      sext((s << 24u) | (i1 << 23u) | (i2 << 22u) | (imm10 << 12u) | (imm11 << 1u), 24)};
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .cc = cond_code::AL2, .imm = imm32,
      .addr = u32(out_inst.addr + 4u + imm32) };
    return true;
  }

  // 4.6.15 BIC (imm), T1 encoding (pg 4-44)
  if (((w0 & 0xFBE0u) == 0xF020u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::BIT_CLEAR_IMM;
    out_inst.i.bit_clear_imm = { .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  if ((w0 & 0xFF70u) == 0xEA20u) { // 4.6.16 BIC, T2 encoding (pg 4-46)
    out_inst.type = inst_type::BIT_CLEAR_REG;
    out_inst.i.bit_clear_reg = { .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .m = u8(w1 & 0xFu), .shift =
        decode_imm_shift(u8((w1 >> 4u) & 3u), u8(((w1 >> 6u) & 3u) | ((w1 >> 12u) & 7u))),
    };
    return true;
  }

  // 4.6.18 BL, T1 encoding (pg 4-50)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0xD000u)) {
    u32 const imm10{w0 & 0x3FFu}, imm11{w1 & 0x7FFu}, s{(w0 >> 10u) & 1u},
      j1{(w1 >> 13) & 1u}, j2{(w1 >> 11u) & 1u}, i1{~(j1 ^ s) & 1u}, i2{~(j2 ^ s) & 1u};
    u32 const imm32{
      sext((s << 24u) | (i1 << 23u) | (i2 << 22u) | (imm10 << 12u) | (imm11 << 1u), 24)};
    out_inst.type = inst_type::BRANCH_LINK;
    out_inst.i.branch_link = { .imm = imm32, .addr = u32(out_inst.addr + 4u + imm32) };
    return true;
  }

  // 4.6.26 CLZ, T1 encoding (pg 4-66)
  if (((w0 & 0xFFF0u) == 0xFAB0u) && ((w1 & 0xF0F0u) == 0xF080u)) {
    out_inst.type = inst_type::COUNT_LEADING_ZEROS;
    out_inst.i.count_leading_zeros = { .d = u8(w1 & 7u), .m = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8D0u) { // 4.6.43 LDR (imm), T3 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .n = u8(w0 & 0xFu), .t = u8((w1 >> 12u) & 7u), .add = 1u,
      .imm = u16(w1 & 0xFFFu), .index = 1u };
    return true;
  }

  // 4.6.43 LDR (immediate), T4 encoding (pg 4-100)
  if (((w0 & 0xFFF0u) == 0xF850u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const puw{u8((w1 >> 8u) & 7u)};
    if (puw == 7u) { return false; } // TODO: LDRT
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .t = u8((w1 >> 12u) & 0xFu), .add = u8((puw >> 1u) & 1u),
      .n = u8(w0 & 0xFu), .imm = u8(w1 & 0xFFu), .index = u8((puw >> 2u) & 1u) };
    return true;
  }

  // 4.6.45 LDR (register), T2 encoding (pg 4-104)
  if (((w0 & 0xFFF0u) == 0xF850u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::LOAD_REG;
    out_inst.i.load_reg = { .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu),
      .m = u8(w1 & 0xFu), .shift = { .t = imm_shift_type::LSL, .n = u8((w1 >> 4u) & 3u) } };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF890u) {  // 4.6.46 LDRB (imm), T2 encoding (pg 4-106)
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.i.load_byte_imm = { .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu),
      .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  if ((w0 & 0xFE50u) == 0xE850u) { // 4.6.50 LDRD (imm), T1 encoding (pg 4-114)
    out_inst.type = inst_type::LOAD_DBL_REG;
    out_inst.i.load_dbl_reg = { .imm = u16((w1 & 0xFFu) << 2u), .base = u8(w0 & 0xFu),
      .dst1_reg = u8((w1 >> 12u) & 0xFu), .dst2_reg = u8((w1 >> 8u) & 0xFu),
      .add = u8((w0 >> 7u) & 1u), .index = u8((w0 >> 8u) & 1u) };
    return true;
  }

  // 4.6.76 MOV (imm), T2 encoding (pg 4-166)
  if (((w0 & 0xFBEFu) == 0xF04Fu) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm = { .d = u8((w1 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.76 MOV (imm), T3 encoding (pg 4-166)
  if (((w0 & 0xFBF0u) == 0xF240u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u}, imm4{w0 & 0xFu};
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm = { .d = u8((w1 >> 8u) & 0xFu),
      .imm = (imm4 << 12u) | (i << 11u) | (imm3 << 8u) | imm8 };
    return true;
  }

  // 4.6.85 MVN (imm), T1 encoding (pg 4-183)
  if (((w0 & 0xFDEFu) == 0xF06Fu) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::MOV_NEG_IMM;
    out_inst.i.mov_neg_imm = { .d = u8((w0 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.88 NOP, T2 encoding (pg 4-189)
  if (((w0 & 0xFFF0u) == 0xF3A0u) && ((w1 & 0xD7FFu) == 0x8000u)) {
    // shouldn't need nop flag memory hints for static analysis (e.g. dsb, isb)
    out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    return true;
  }

  // 4.6.91 ORR (imm), T1 encoding (pg 4-195)
  if (((w0 & 0xFB40u) == 0xF040u) && ((w1 & 0x8000u) == 0)) {
    u8 const n{u8(w0 & 0xFu)};
    if (n != 15) { // T1 note: n=15 is 4.6.76 MOV T2 (pg 4-166)
      u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
      out_inst.type = inst_type::OR_REG_IMM;
      out_inst.i.or_reg_imm = { .d = u8((w1 >> 8u) & 0xFu), .n = n,
        .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    }
    return true;
  }

  if (w0 == 0xE8BDu) { // 4.6.98 POP, T2 encoding (pg 4-209)
    out_inst.type = inst_type::POP;
    out_inst.i.pop = { .reg_list = uint16_t(w1 & 0xDFFFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE900u) { // 4.6.160 STMDB, T1 encoding (pg 4-333)
    out_inst.type = inst_type::STORE_MULT_DEC_BEF;
    out_inst.i.store_mult_dec_bef = { .n = u8(w0 & 0xFu), .regs = u16(w1 & 0x5FFFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8C0u) { // 4.6.162 STR (imm), T3 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .t = u8(w1 >> 12u), .n = u8(w0 & 0xFu),
      .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF880u) { // 4.6.164 STRB (imm), T2 encoding (pg 4.341)
    out_inst.type = inst_type::STORE_REG_BYTE;
    out_inst.i.store_reg_byte = { .imm = u16(w1 & 0xFFFu), .t = u8((w1 >> 12u) & 0xFu),
      .n = u8(w0 & 0xFu), .add = 1u, .index = 1u };
    return true;
  }

  // 4.6.164 STRB (imm), T3 encoding (pg 4-341)
  if (((w0 & 0xFFF0u) == 0xF800u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const puw{u8((w1 >> 8u) & 7u)};
    if (puw == 0b110) {
      out_inst.type = inst_type::STORE_REG_BYTE_UNPRIV;
      out_inst.i.store_reg_byte_unpriv = {
        .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu) };
    } else {
      out_inst.type = inst_type::STORE_BYTE_IMM;
      out_inst.i.store_byte_imm = {
        .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu), .add = u8((puw >> 1u) & 1u) };
    }
    return true;
  }

  // 4.6.168 TBB, T1 encoding (pg 4-389)
  if (((w0 & 0xFFF0u) == 0xE8D0u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::TABLE_BRANCH_BYTE;
    out_inst.i.table_branch_byte = { .base_reg = u8(w0 & 0xFu), .idx_reg = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.176 SUB, T3 encoding (pg 4-365)
  if (((w0 & 0xFBE0u) == 0xF1A0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::SUB_IMM;
    out_inst.i.sub_imm = { .d = u8((w1 & 0xF) >> 8u), .n = u8(w0 & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.197 UBFX, T1 encoding (pg 4-407)
  if (((w0 & 0xFBF0u) == 0xF3C0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm2{(w1 >> 6u) & 3u}, imm3{(w1 >> 12u) & 7u };
    out_inst.type = inst_type::BITFIELD_EXTRACT_UNSIGNED;
    out_inst.i.bitfield_extract_unsigned = { .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .lsbit = u8((imm3 << 2u) | imm2), .widthminus1 = u8(w1 & 0x1Fu) };
    return true;
  }

  return false;
}
}

void inst_print(inst const& i) {
#define X(ENUM, TYPE) case inst_type::ENUM: print(i.i.TYPE); return;
  switch (i.type) { INST_TYPE_X_LIST() }
#undef X
  printf("  unknown\n");
}

bool inst_is_conditional_branch(inst const& i, u32& target) {
  switch (i.type) {
    case inst_type::BRANCH:
      target = i.i.branch.addr; return !cond_code_is_always(i.i.branch.cc);
    case inst_type::CBZ: target = i.i.cmp_branch_z.addr; return true;
    case inst_type::CBNZ: target = i.i.cmp_branch_nz.addr; return true;
    default: break;
  }

  return false;
}

bool inst_is_unconditional_branch(inst const& i, u32& label) {
  switch (i.type) {
    case inst_type::BRANCH:
      label = i.i.branch.addr; return cond_code_is_always(i.i.branch.cc);
    case inst_type::BRANCH_LINK: label = i.i.branch_link.addr; return true;
    case inst_type::BRANCH_LINK_XCHG_REG: label = 0; return true; // TODO: register state
    default: break;
  }

  return false;
}

u32 inst_align(u32 val, u32 align) { // Rounding and Aligning, A-16
  // If x and y are integers, Align(x,y) = y * (x DIV y) is an integer.
  return align * (val / align);
}

bool inst_decode(char const *text, u32 func_addr, u32 pc_addr, inst& out_inst) {
  out_inst.addr = func_addr + pc_addr;

  u16 w0;
  memcpy(&w0, &text[pc_addr], 2);
  printf("  %6x: %04x ", out_inst.addr, w0);
  if (is_16bit_inst(w0)) {
    printf("     ");
    if (!decode_16bit_inst(w0, out_inst)) { printf("  ?\n"); return false; }
    return true;
  }

  u16 w1;
  memcpy(&w1, &text[pc_addr + 2], 2);
  printf("%04x ", w1);
  if (!decode_32bit_inst(w0, w1, out_inst)) { printf("  ?\n"); return false; }
  return true;
}

