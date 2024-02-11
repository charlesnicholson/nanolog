#include "thumb2_inst.h"
#include "boilerplate.h"

#ifdef _MSC_VER
#include <windows.h>
#endif

namespace {

char const* cond_code_name(cond_code cc) {
#define X(NAME, VAL) \
  case cond_code::NAME: \
    return #NAME;
  switch (cc) { CONDITION_CODE_X_LIST() }
#undef X
  return "unknown";
}

#define X(NAME) #NAME,
char const* s_rn[] = { REGISTER_X_LIST() };
#undef X

#define X(NAME) #NAME,
char const* s_sn[] = { SHIFT_X_LIST() };
#undef X

u32 decode_imm12(u32 imm12) {  // 4.2.2 Operation (pg 4-9)
  if ((imm12 & 0xC00u) == 0) {
    u32 const imm8{ imm12 & 0xFFu };
    switch ((imm12 >> 8u) & 3u) {
      case 0:
        return imm12;
      case 1:
        return (imm8 << 16) | imm8;
      case 2:
        return (imm8 << 24) | (imm8 << 8);
      case 3:
        return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
    }
  }
  u32 const x{ 0x80u | (imm12 & 0x7Fu) }, n{ (imm12 >> 7u) & 0x1Fu };
  return (x >> n) | (x << (32 - n));
}

imm_shift decode_imm_shift(u8 const type, u8 const imm5) {
  switch (type & 3u) {  // 4.3.2 Shift Operations (pg 4-11)
    case 0b00:
      return imm_shift{ .t = imm_shift_type::LSL, .n = imm5 };
    case 0b01:
      return imm_shift{ .t = imm_shift_type::LSR, .n = imm5 ? imm5 : u8(32) };
    case 0b10:
      return imm_shift{ .t = imm_shift_type::ASR, .n = imm5 ? imm5 : u8(32) };
    case 0b11:
      if (imm5 == 0u) {
        return imm_shift{ .t = imm_shift_type::RRX, .n = 1 };
      }
      return imm_shift{ .t = imm_shift_type::ROR, .n = imm5 };
  }
#ifdef _MSC_VER
  __assume(0);
#else
  __builtin_unreachable();
#endif
}

float decode_vfp_imm8(u8 imm8, unsigned n) {
  // A6.4.1 Operation of modified immediate constants in floating-point instructions.
  // Page A-196
  // return imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19);
  (void)n;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
  u32 const replicate{ (-((imm8 >> 6u) & 1u)) & 0x1Fu }, imm8_5_0{ imm8 & 0x3Fu },
      not_imm8_6{ !((imm8 >> 6u) & 1u) }, imm8_7{ (imm8 >> 7u) & 1u },
      imm{ (imm8_7 << 31u) | (not_imm8_6 << 30u) | (replicate << 24u) |
           (imm8_5_0 << 19u) };
#ifdef _MSC_VER
#pragma warning(pop)
#endif
  float f;
  memcpy(&f, &imm, sizeof(f));
  return f;
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

  if ((w0 & 0xFFC0u) == 0x4140u) {  // 4.6.2 ADC (reg), T1 encoding (pg 4-18)
    out_inst.type = inst_type::ADD_CARRY_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.add_carry_reg = {
      .shift = decode_imm_shift(0b00, 0),
      .n = u8(w0 & 7u),
      .m = u8((w0 >> 3u) & 7u),
    };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1C00u) {  // 4.6.3 ADD (imm), T1 encoding (pg 4-20)
    out_inst.type = inst_type::ADD_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.add_imm = { .imm = u16((w0 >> 6u) & 7u), .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x3000u) {  // 4.6.3 ADD (imm), T2 encoding (pg 4-20)
    u8 const dn{ u8((w0 >> 8u) & 7u) };
    out_inst.type = inst_type::ADD_IMM;
    out_inst.dr = u16(1u << dn);
    out_inst.i.add_imm = { .imm = u8(w0 & 0xFFu), .n = dn };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4400u) {  // 4.6.4 ADD (reg), T2 encoding (pg 4-22)
    u8 const dn{ u8((w0 >> 7u) & 1u) }, rdn{ u8(w0 & 7u) }, d{ u8((dn << 3) | rdn) },
        m{ u8((w0 >> 3u) & 7u) };
    if ((d == 13) || (m == 13)) {  // 4.6.6 ADD (SP plus reg), T2 encoding (pg 4-26)
      out_inst.type = inst_type::ADD_SP_IMM;
      out_inst.dr = u16(1u << d);
      out_inst.i.add_sp_imm = { .imm = d };
      return true;
    }
    out_inst.type = inst_type::ADD_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.add_reg = { .shift = decode_imm_shift(0b00, 0), .n = d, .m = m };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1800u) {  // 4.6.4 ADD (reg), T1 encoding (pg 4-22)
    out_inst.type = inst_type::ADD_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.add_reg = { .shift = decode_imm_shift(0b00, 0),
                           .n = u8((w0 >> 3u) & 7u),
                           .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xA800u) {  // 4.5.5 ADD (SP + imm), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.add_sp_imm = { .imm = u16((w0 & 0xFFu) << 2u) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0xB000u) {  // 4.6.5 ADD (SP + imm), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.dr = u16(1u << reg::SP);
    out_inst.i.add_sp_imm = { .imm = u16((w0 & 0x7Fu) << 2u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xA000u) {  // 4.6.7 ADR, T1 encoding (pg 4-28)
    out_inst.type = inst_type::ADR;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.adr = { .imm = u8((w0 & 0xFFu) << 2u), .add = 1u };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4000u) {  // 4.6.9 AND, T1 encoding (pg 4-32)
    out_inst.type = inst_type::AND_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.and_reg = { .shift = decode_imm_shift(0b00, 0),
                           .n = u8(w0 & 7u),
                           .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800) == 0x1000u) {  // 4.6.10 ASR (imm), T1 encoding (pg 4-34)
    out_inst.type = inst_type::RSHIFT_ARITH_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.rshift_arith_imm = { .shift = decode_imm_shift(0b10, (w0 >> 6u) & 0x1Fu),
                                    .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4100u) {  // 4.6.11 ASR (reg), T1 encoding (pg 4-36)
    u8 const dn{ u8(w0 & 7u) };
    out_inst.type = inst_type::RSHIFT_ARITH_REG;
    out_inst.dr = u16(1u << dn);
    out_inst.i.rshift_arith_reg = { .n = dn, .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF000u) == 0xD000u) {  // 4.6.12 B, T1 encoding (pg 4-38)
    cond_code const cc{ cond_code(((w0 >> 8u) & 0xFu)) };
    u32 const imm32{ u32(sext((w0 & 0xFFu) << 1u, 8u)) };
    if (u8(cc) == 0xFu) {  // cc 0b1111 == SVC, 4.6.181 SVC (pg 4-375)
      out_inst.type = inst_type::SVC;
      out_inst.i.svc = { .imm = imm32 };
    }
    if (u8(cc) == 0xEu) {  // cc 0b1110 == undefined
      out_inst.type = inst_type::UNDEFINED;
    } else {
      out_inst.type = inst_type::BRANCH;
      out_inst.i.branch = { .imm = imm32,
                            .addr = u32(out_inst.addr + 4u + imm32),
                            .cc = cc };
    }
    return true;
  }

  if ((w0 & 0xF800u) == 0xE000u) {  // 4.6.12 B, T2 encoding (pg 4-38)
    u32 const imm32{ u32(sext((w0 & 0x7FFu) << 1u, 11u)) };
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .imm = imm32,
                          .addr = u32(out_inst.addr + 4u + imm32),
                          .cc = cond_code::AL2 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4380u) {  // 4.6.16 BIC (reg), T1 encoding (pg 4-46)
    u8 const dn{ u8(w0 & 7u) };
    out_inst.type = inst_type::BIT_CLEAR_REG;
    out_inst.dr = u16(1u << dn);
    out_inst.i.bit_clear_reg = { .shift = decode_imm_shift(0b00, 0),
                                 .n = dn,
                                 .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0xBE00u) {  // 4.6.17 BKPT, T1 encoding (pg 4-48)
    out_inst.type = inst_type::BREAKPOINT;
    out_inst.i.breakpoint = { .imm = u16(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4780u) {  // 4.6.19 BLX (reg), T1 encoding (pg 4-52)
    out_inst.type = inst_type::BRANCH_LINK_XCHG_REG;
    out_inst.i.branch_link_xchg_reg = { .reg = u8((w0 >> 3u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0x4700u) {  // 4.6.20 BX, T1 encoding (pg 4-54)
    out_inst.type = inst_type::BRANCH_XCHG;
    out_inst.i.branch_xchg = { .m = u8((w0 >> 3u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB900u) {  // 4.6.22 CBNZ, T1 encoding (pg 4-58)
    u32 const imm5{ (w0 >> 3u) & 0x1Fu }, i{ (w0 >> 9u) & 1u },
        imm32{ (imm5 << 1u) | (i << 6u) };
    out_inst.type = inst_type::CBNZ;
    out_inst.i.cmp_branch_nz = { .addr = out_inst.addr + 4u + imm32,
                                 .n = u8(w0 & 7u),
                                 .imm = u8(imm32) };
    return true;
  }

  if ((w0 & 0xFD00u) == 0xB100u) {  // 4.6.23 CBZ, T1 encoding (pg 4-60)
    u32 const imm5{ (w0 >> 3u) & 0x1Fu }, i{ (w0 >> 9u) & 1u },
        imm32{ (imm5 << 1u) | (i << 6u) };
    out_inst.type = inst_type::CBZ;
    out_inst.i.cmp_branch_z = { .addr = out_inst.addr + 4u + imm32,
                                .n = u8(w0 & 7u),
                                .imm = u8(imm32) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2800u) {  // 4.6.29 CMP (imm), T1 encoding (pg 4-72)
    out_inst.type = inst_type::CMP_IMM;
    out_inst.i.cmp_imm = { .imm = u8(w0 & 0xFFu), .n = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4280u) {  // 4.6.30 CMP (reg), T1 encoding (pg 4-74)
    out_inst.type = inst_type::CMP_REG;
    out_inst.i.cmp_reg = { .shift = decode_imm_shift(0b00, 0),
                           .n = u8(w0 & 7u),
                           .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4500u) {  // 4.6.30 CMP (reg), T2 encoding (pg 4-74)
    out_inst.type = inst_type::CMP_REG;
    out_inst.i.cmp_reg = { .shift = decode_imm_shift(0b00, 0),
                           .n = u8((w0 & 7u) | ((w0 >> 4u) & 8u)),
                           .m = u8((w0 >> 3u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE8u) == 0xB660u) {  // 4.6.31 CPS, T1 encoding (pg 4-76)
    u8 const im{ u8((w0 >> 4u) & 1u) };
    out_inst.type = inst_type::CHANGE_PROC_STATE;
    out_inst.i.change_proc_state = { .en = (im == 0),
                                     .dis = (im == 1),
                                     .cm = 0,
                                     .aff_a = u8((w0 >> 2u) & 1u),
                                     .aff_i = u8((w0 >> 1u) & 1u),
                                     .aff_f = u8(w0 & 1u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4040u) {  // 4.6.37 EOR (reg), T1 encoding (pg 4-88)
    u8 const rdn{ u8(w0 & 7u) };
    out_inst.type = inst_type::EXCL_OR_REG;
    out_inst.dr = u16(1u << rdn);
    out_inst.i.excl_or_reg = { .shift = decode_imm_shift(0b00, 0),
                               .n = rdn,
                               .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0xBF00u) {  // 4.6.39 IT, T1 encoding (pg 4-92)
    u8 const mask{ u8(w0 & 0xFu) };
    if (mask == 0) {  // T1 encoding note: '0000' = nop-compatible hint
      out_inst.type = inst_type::NOP;
      out_inst.i.nop = {};
      return true;
    }
    u8 cnt = 4u, tmp = mask;
    while (!(tmp & 1u)) {
      tmp >>= 1u;
      --cnt;
    }
    out_inst.type = inst_type::IF_THEN;
    out_inst.i.if_then = { .firstcond = u8((w0 >> 4u) & 0xFu), .mask = mask, .cnt = cnt };
    return true;
  }

  if ((w0 & 0xF800u) == 0xC800u) {  // 4.6.42 LDMIA, T1 encoding (pg 4-98)
    u8 const n{ u8((w0 >> 8u) & 7u) };
    out_inst.type = inst_type::LOAD_MULT_INC_AFTER;
    out_inst.dr = u16(w0 & 0xFFu);
    out_inst.i.load_mult_inc_after = { .n = n, .wback = !(out_inst.dr & (1u << n)) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x6800u) {  // 4.6.43 LDR (imm), T1 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_imm = { .imm = u16(((w0 >> 6u) & 0x1Fu) << 2u),
                            .n = u8((w0 >> 3u) & 7u),
                            .add = 1u,
                            .index = 1u };
    return true;
  }

  if ((w0 & 0xF800u) == 0x9800u) {  // 4.6.43 LDR (imm), T2 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.load_imm = { .imm = u16((w0 & 0xFFu) << 2u),
                            .n = 13u,
                            .add = 1u,
                            .index = 1u };
    return true;
  }

  if ((w0 & 0xF800u) == 0x4800u) {  // 4.6.44 LDR (literal), T1 encoding (pg 4-102)
    u16 const imm{ u16((w0 & 0xFFu) << 2u) };
    out_inst.type = inst_type::LOAD_LIT;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.load_lit = { .imm = imm,
                            .addr = u32(inst_align(out_inst.addr, 4) + imm + 4),
                            .add = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5800u) {  // 4.6.45 LDR (register), T1 encoding (pg 4-104)
    out_inst.type = inst_type::LOAD_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_reg = { .shift = decode_imm_shift(0b00, 0),
                            .n = u8((w0 >> 3u) & 7u),
                            .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7800u) {  // 4.6.46 LDRB (imm), T1 encoding (pg 4-106)
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_byte_imm = { .imm = u8((w0 >> 6u) & 0x1Fu),
                                 .n = u8((w0 >> 3u) & 7u),
                                 .add = 1u,
                                 .index = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5C00u) {  // 4.6.48 LDRB (reg), T1 encoding (pg 4-110)
    out_inst.type = inst_type::LOAD_BYTE_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_byte_reg = { .shift = decode_imm_shift(0b00, 0),
                                 .n = u8((w0 >> 3u) & 7u),
                                 .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8800u) {  // 4.6.55 LDRH (imm), T1 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_half_imm = { .imm = (u8)(((w0 >> 6u) & 0x1Fu) << 1u),
                                 .n = u8((w0 >> 3u) & 7u),
                                 .add = 1u,
                                 .index = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5A00u) {  // 4.6.57 LDRH (reg), T1 encoding (pg 4-128)
    out_inst.type = inst_type::LOAD_HALF_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_half_reg = { .shift = decode_imm_shift(0b00, 0),
                                 .n = u8((w0 >> 3u) & 7u),
                                 .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5600u) {  // 4.6.61 LDRSB (reg), T1 encoding (pg 4-136)
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_signed_byte_reg = { .shift = decode_imm_shift(0b00, 0),
                                        .n = u8((w0 >> 3u) & 7u),
                                        .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5E00u) {  // 4.6.65 LDRSH (reg), T1 encoding (pg 4-144)
    out_inst.type = inst_type::LOAD_SIGNED_HALF_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.load_signed_half_reg = { .shift = decode_imm_shift(0b00, 0),
                                        .n = u8((w0 >> 3u) & 7u),
                                        .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0) {  // 4.6.68 LSL (imm), T1 encoding (pg 4-150)
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.lshift_log_imm = { .shift = decode_imm_shift(0b00, u8((w0 >> 6u) & 0x1Fu)),
                                  .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4080u) {  // 4.6.69 LSL (reg), T1 encoding (pg 4-152)
    u8 const dn{ u8(w0 & 7u) };
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.dr = dn;
    out_inst.i.lshift_log_reg = { .n = dn, .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x800u) {  // 4.6.70 LSR (imm), T1 encoding (pg 4-154)
    out_inst.type = inst_type::RSHIFT_LOG_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.rshift_log_imm = { .shift = decode_imm_shift(0b01, u8((w0 >> 6u) & 0x1Fu)),
                                  .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x40C0u) {  // 4.6.71 LSR (reg), T1 encoding (pg 4-156)
    u8 const rdn{ u8(w0 & 7u) };
    out_inst.type = inst_type::RSHIFT_LOG_REG;
    out_inst.dr = u16(1u << rdn);
    out_inst.i.rshift_log_reg = { .n = rdn, .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2000u) {  // 4.6.76 MOV (imm), T1 encoding (pg 4-166)
    out_inst.type = inst_type::MOV_IMM;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.mov_imm = { .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4600u) {  // 4.6.77 MOV (reg), T1 encoding (pg 4-168)
    out_inst.type = inst_type::MOV_REG;
    out_inst.dr = u16(1u << ((w0 & 7u) | ((w0 & 0x80u) >> 4u)));
    out_inst.i.mov_reg = { .m = u8((w0 >> 3u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4340u) {  // 4.6.84 MUL, T1 encoding (pg 4-181)
    out_inst.type = inst_type::MUL;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.mul = { .n = u8((w0 >> 3u) & 7u), .m = u8(w0 & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x43C0u) {  // 4.6.86 MVN (reg), T1 encoding (pg 4-185)
    out_inst.type = inst_type::MOV_NEG_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.mov_neg_reg = { .shift = decode_imm_shift(0, 0), .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if (w0 == 0xBF00u) {  // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP;
    out_inst.i.nop = {};
    return true;
  }

  if ((w0 & 0xFFC0) == 0x4300) {  // 4.6.92 ORR (reg), T1 encoding (pg 4-197)
    out_inst.type = inst_type::OR_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.or_reg = { .shift = decode_imm_shift(0b00, 0),
                          .n = u8(w0 & 7u),
                          .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0xBC00u) {  // 4.6.98 POP, T1 encoding (pg 4-209)
    out_inst.type = inst_type::POP;
    out_inst.dr = u16(((w0 & 0x100u) << 7) | (w0 & 0xFFu));
    return true;
  }

  if ((w0 & 0xFE00u) == 0xB400u) {  // 4.6.99 PUSH, T1 encoding (pg 4-211)
    out_inst.type = inst_type::PUSH;
    out_inst.i.push = { .reg_list = u16(((w0 & 0x0100u) << 6u) | (w0 & 0xFFu)) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xBA00u) {  // 4.6.111 REV, T1 encoding (pg 4-235)
    out_inst.type = inst_type::BYTE_REV_WORD;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.byte_rev_word = { .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xBA40u) {  // 4.6.112 REV16, T1 encoding (pg 4-237)
    out_inst.type = inst_type::BYTE_REV_PACKED_HALF;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.byte_rev_packed_half = { .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xBAC0u) {  // 4.6.113 REVSH, T1 encoding (pg 4-239)
    out_inst.type = inst_type::BYTE_REV_SIGNED_HALF;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.byte_rev_signed_half = { .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4240u) {  // 4.6.118 RSB (imm), T1 encoding (pg 4-249)
    out_inst.type = inst_type::SUB_REV_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.sub_rev_imm = { .imm = 0, .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4180u) {  // 4.6.124 SBC (reg), T1 encoding (pg 4-261)
    u8 const rdn{ u8(w0 & 7u) };
    out_inst.type = inst_type::SUB_REG_CARRY;
    out_inst.dr = u16(1u << rdn);
    out_inst.i.sub_reg_carry = { .shift = decode_imm_shift(0, 0),
                                 .n = rdn,
                                 .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xC000u) {  // 4.6.161 STMIA, T1 encoding (pg 4-335)
    out_inst.type = inst_type::STORE_MULT_INC_AFTER;
    out_inst.i.store_mult_inc_after = { .regs = u8(w0 & 0xFFu),
                                        .n = u8((w0 >> 8u) & 7u),
                                        .wback = 1u };
    return true;
  }

  if ((w0 & 0xF800u) == 0x6000u) {  // 4.6.162 STR (imm), T1 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .imm = u16(((w0 >> 6u) & 0x1Fu) << 2u),
                             .t = u8(w0 & 7u),
                             .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x9000u) {  // 4.6.162 STR (imm), T2 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .imm = u16((w0 & 0xFFu) << 2u),
                             .t = u8((w0 >> 8u) & 7u),
                             .n = reg::SP };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5000u) {  // 4.6.163 STR (reg), T1 encoding (pg 4-339)
    out_inst.type = inst_type::STORE_REG;
    out_inst.i.store_reg = { .shift = decode_imm_shift(0b00, 0),
                             .t = u8(w0 & 7u),
                             .n = u8((w0 >> 3u) & 7u),
                             .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7000u) {  // 4.6.164 STRB (imm), T1 encoding (pg 4-341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16((w0 >> 6u) & 0x1Fu),
                                  .n = u8((w0 >> 3u) & 7u),
                                  .t = u8(w0 & 7u),
                                  .index = 1u,
                                  .add = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5400u) {  // 4.6.165 STRB (reg), T1 encoding (pg 4-343)
    out_inst.type = inst_type::STORE_BYTE_REG;
    out_inst.i.store_byte_reg = { .shift = decode_imm_shift(0b00, 0),
                                  .t = u8(w0 & 7u),
                                  .m = u8((w0 >> 6u) & 7u),
                                  .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8000u) {  // 4.6.172 STRH (imm), T1 encoding (pg 4-357)
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .imm = u16(((w0 >> 6u) & 0x1F) << 1u),
                                  .t = u8(w0 & 7u),
                                  .n = u8((w0 >> 3u) & 7u),
                                  .index = 1u,
                                  .add = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5200u) {  // 4.6.173 STRG (reg), T1 encoding (pg 4-359)
    out_inst.type = inst_type::STORE_HALF_REG;
    out_inst.i.store_half_reg = { .shift = decode_imm_shift(0b00, 0),
                                  .t = u8(w0 & 7u),
                                  .n = u8((w0 >> 3u) & 7u),
                                  .m = u8((w0 >> 6u) & 3u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1E00u) {  // 4.6.176 SUB (imm), T1 encoding (pg 4-365)
    out_inst.type = inst_type::SUB_IMM;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.sub_imm = { .imm = (w0 >> 6u) & 7u, .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x3800u) {  // 4.6.176 SUB (imm), T2 encoding (pg 4-365)
    out_inst.type = inst_type::SUB_IMM;
    out_inst.dr = u16(1u << ((w0 >> 8u) & 7u));
    out_inst.i.sub_imm = { .imm = w0 & 0xFFu, .n = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1A00u) {  // 4.6.177 SUB (reg), T1 encoding (pg 4-367)
    out_inst.type = inst_type::SUB_REG;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.sub_reg = { .shift = decode_imm_shift(0, 0),
                           .n = u8((w0 >> 3u) & 7u),
                           .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0xB080u) {  // 4.6.178 SUB (SP - imm), T1 encoding (pg 4-369)
    out_inst.type = inst_type::SUB_SP_IMM;
    out_inst.dr = u16(1u << 13);
    out_inst.i.sub_sp_imm = { .imm = (w0 & 0x7Fu) << 2u };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB240u) {  // 4.6.185 SXTB, T1 encoding (pg 4-383)
    out_inst.type = inst_type::EXTEND_SIGNED_BYTE;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.extend_signed_byte = { .m = u8((w0 >> 3u) & 7u), .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB200u) {
    out_inst.type = inst_type::EXTEND_SIGNED_HALF;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.extend_signed_half = { .m = u8((w0 >> 3u) & 7u), .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4200u) {  // 4.6.193 TST, T1 encoding (pg 4-399)
    out_inst.type = inst_type::TEST_REG;
    out_inst.i.test_reg = { .shift = decode_imm_shift(0b00, 0),
                            .n = u8(w0 & 7u),
                            .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB2C0u) {  // 4.6.224 UXTB, T1 encoding (pg 4-461)
    out_inst.type = inst_type::EXTEND_UNSIGNED_BYTE;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.extend_unsigned_byte = { .m = u8((w0 >> 3u) & 7u), .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB280u) {  // 4.6.226 UXTH, T1 encoding (pg 4-465)
    out_inst.type = inst_type::EXTEND_UNSIGNED_HALF;
    out_inst.dr = u16(1u << (w0 & 7u));
    out_inst.i.extend_unsigned_half = { .m = u8((w0 >> 3u) & 7u), .rotation = 0 };
    return true;
  }

  return false;
}

bool decode_32bit_inst(u16 const w0, u16 const w1, inst& out_inst) {
  out_inst.len = 4;

  // 4.6.1 ADC (imm), T1 encoding (pg 4-16)
  if (((w0 & 0xFBE0u) == 0xF140u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::ADD_CARRY_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.add_carry_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8),
                                 .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB40u) {  // 4.6.2 ADC (reg), T2 encoding (pg 4-18)
    u8 const imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 3u) };
    out_inst.type = inst_type::ADD_CARRY_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.add_carry_reg = { .shift = decode_imm_shift(u8((w1 >> 4u) & 3u),
                                                           u8((imm3 << 2u) | imm2)),
                                 .n = u8(w0 & 0xFu),
                                 .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.3 ADD (imm), T3 encoding (pg 4-20)
  if (((w0 & 0xFBE0u) == 0xF100u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 0x7u }, i{ (w0 >> 10u) & 1u },
        imm{ decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, s{ u8((w0 >> 4u) & 1u) }, n{ u8(w0 & 0xFu) };
    if ((s == 1) && (d == 15)) {  // 4.6.27 CMN (imm), T1 encoding (pg 4-68)
      out_inst.type = inst_type::CMP_NEG_IMM;
      out_inst.i.cmp_neg_imm = { .imm = imm, .n = n };
      return true;
    }
    out_inst.type = inst_type::ADD_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.add_imm = { .imm = imm, .n = n };
    return true;
  }

  // 4.6.3 ADD (imm), T4 encoding (pg 4-20)
  if (((w0 & 0xFBF0u) == 0xF200u) && ((w1 & 0x8000u) == 0)) {
    u8 const n{ u8(w0 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) };
    u32 const i{ (w0 >> 10u) & 1u }, imm3{ (w1 >> 12u) & 7u }, imm8{ w1 & 0xFFu },
        imm{ (i << 11u) | (imm3 << 8u) | imm8 };
    if (n == 15) {
      NL_LOG_ERR("SEE ADR on page 4-28");
      return false;
    }
    if (n == 13) {  // 4.6.5 ADD (SP plus imm), T4 encoding (pg 4-24)
      out_inst.type = inst_type::ADD_SP_IMM;
      out_inst.dr = u16(1u << d);
      out_inst.i.add_sp_imm = { .imm = u16(imm) };
      return true;
    }
    out_inst.type = inst_type::ADD_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.add_imm = { .imm = u16(imm), .n = n };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB00u) {  // 4.6.4 ADD (reg), T3 encoding (pg 4-22)
    u32 const imm3{ (w1 >> 12u) & 7u }, imm2{ (w1 >> 6u) & 3u };
    u8 const n{ u8(w0 & 0xFu) }, s{ u8((w0 >> 4u) & 1u) }, m{ u8(w1 & 0xFu) },
        d{ u8((w1 >> 8u) & 0xFu) }, type{ u8((w1 >> 4u) & 3u) },
        si{ u8((imm3 << 2u) | imm2) };
    if ((s == 1u) && (d == reg::PC)) {  // CMN (reg) pg 4-70
      return false;
    }
    if (n == u8(reg::SP)) {  // ADD (SP + reg), T3 encoding (pg 4-26)
      out_inst.type = inst_type::ADD_SP_REG;
      out_inst.dr = u16(1u << d);
      out_inst.i.add_sp_reg = { .shift = decode_imm_shift(type, si), .m = m };
      return true;
    }
    out_inst.type = inst_type::ADD_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.add_reg = { .shift = decode_imm_shift(type, si), .n = n, .m = m };
    return true;
  }

  // 4.6.8 AND (imm), T1 encoding (pg 4-30)
  if (((w0 & 0xFBE0u) == 0xF000u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::AND_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.and_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8),
                           .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA00u) {  // 4.6.9 AND (reg), T2 encoding (pg 4-32)
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) },
        d{ u8((w1 >> 8u) & 0xFu) }, s{ u8((w0 >> 4u) & 1u) };
    if ((d == 15) && (s == 1)) {  // 4.6.193 TST (reg), T2 encoding (pg 4-399)
      out_inst.type = inst_type::TEST_REG;
      out_inst.i.test_reg = { .shift = decode_imm_shift(u8((w1 >> 4u) & 3u),
                                                        u8((imm3 << 2u) | imm2)),
                              .n = u8(w0 & 0xFFu),
                              .m = u8(w1 & 0xFFu) };
      return true;
    }
    out_inst.type = inst_type::AND_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.and_reg = { .shift = decode_imm_shift(u8((w1 >> 4u) & 3u),
                                                     u8((imm3 << 2u) | imm2)),
                           .n = u8(w0 & 0xFu),
                           .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.10 ASR (imm), T2 encoding (pg 4-34)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0x20u)) {
    u8 const imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 3u) };
    out_inst.type = inst_type::RSHIFT_ARITH_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 7u));
    out_inst.i.rshift_arith_imm = { .shift =
                                        decode_imm_shift(0b10, u8((imm3 << 2u) | imm2)),
                                    .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.11 ASR (reg), T2 encoding (pg 4-36)
  if (((w0 & 0xFFE0u) == 0xFA40u) && ((w1 & 0xF0F0u) == 0xF000u)) {
    out_inst.type = inst_type::RSHIFT_ARITH_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.rshift_arith_reg = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.12 B, T3 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x8000u)) {
    u32 const imm11{ w1 & 0x7FFu }, imm6{ w0 & 0x3Fu }, j1{ (w1 >> 13u) & 1u },
        j2{ (w1 >> 11u) & 1u }, s{ (w0 >> 10u) & 1u },
        imm{ sext((s << 20u) | (j2 << 19u) | (j1 << 18u) | (imm6 << 12u) | (imm11 << 1u),
                  20) },
        addr{ out_inst.addr + 4u + imm };
    cond_code const cc{ cond_code((w0 >> 6u) & 0xFu) };
    if ((unsigned(cc) & 0xEu) == 0xEu) {  // 4.6.88 NOP, T2 encoding (pg 4-189)
      out_inst.type = inst_type::NOP;
      out_inst.i.nop = {};
      return true;
    }
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .imm = imm, .addr = addr, .cc = cc };
    return true;
  }

  // 4.6.12 B, T4 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x9000u)) {
    u32 const imm10{ w0 & 0x3FFu }, imm11{ w1 & 0x7FFu }, s{ (w0 >> 10u) & 1u },
        j1{ (w1 >> 13u) & 1u }, j2{ (w1 >> 11u) & 1u }, i1{ ~(j1 ^ s) & 1u },
        i2{ ~(j2 ^ s) & 1u },
        imm{ sext((s << 24u) | (i1 << 23u) | (i2 << 22u) | (imm10 << 12u) | (imm11 << 1u),
                  24) },
        addr{ out_inst.addr + 4u + imm };
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .imm = imm, .addr = addr, .cc = cond_code::AL2 };
    return true;
  }

  // 4.6.14 BFI, T1 encoding (pg 4-42)
  if (((w0 & 0xFBF0u) == 0xF360u) && ((w1 & 0x8000u) == 0)) {
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) },
        imm5{ u8((imm3 << 2u) | imm2) }, n{ u8(w0 & 0xFu) }, msbit{ u8(w1 & 0x1Fu) },
        d{ u8((w1 >> 8u) & 0xFu) };
    if (n == 15) {  // 4.6.13 BFC, T1 encoding (pg 4-40)
      out_inst.type = inst_type::BITFIELD_CLEAR;
      out_inst.i.bitfield_clear = { .d = d, .msbit = msbit, .lsbit = imm5 };
      return true;
    }
    out_inst.type = inst_type::BITFIELD_INSERT;
    out_inst.dr = u16(1u << d);
    out_inst.i.bitfield_insert = { .n = n, .msbit = msbit, .lsbit = imm5 };
    return true;
  }

  // 4.6.15 BIC (imm), T1 encoding (pg 4-44)
  if (((w0 & 0xFBE0u) == 0xF020u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::BIT_CLEAR_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.bit_clear_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8),
                                 .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA20u) {  // 4.6.16 BIC, T2 encoding (pg 4-46)
    out_inst.type = inst_type::BIT_CLEAR_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.bit_clear_reg = { .shift = decode_imm_shift(
                                     u8((w1 >> 4u) & 3u),
                                     u8(((w1 >> 6u) & 3u) | ((w1 >> 12u) & 7u))),
                                 .n = u8(w0 & 0xFu),
                                 .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.18 BL, T1 encoding (pg 4-50)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0xD000u)) {
    u32 const imm10{ w0 & 0x3FFu }, imm11{ w1 & 0x7FFu }, s{ (w0 >> 10u) & 1u },
        j1{ (w1 >> 13u) & 1u }, j2{ (w1 >> 11u) & 1u }, i1{ ~(j1 ^ s) & 1u },
        i2{ ~(j2 ^ s) & 1u };
    u32 const imm32{
      sext((s << 24u) | (i1 << 23u) | (i2 << 22u) | (imm10 << 12u) | (imm11 << 1u), 24)
    };
    out_inst.type = inst_type::BRANCH_LINK;
    out_inst.i.branch_link = { .imm = imm32, .addr = u32(out_inst.addr + 4u + imm32) };
    return true;
  }

  // 4.6.26 CLZ, T1 encoding (pg 4-66)
  if (((w0 & 0xFFF0u) == 0xFAB0u) && ((w1 & 0xF0F0u) == 0xF080u)) {
    out_inst.type = inst_type::COUNT_LEADING_ZEROS;
    out_inst.dr = u16(1u << (w1 & 7u));
    out_inst.i.count_leading_zeros = { .m = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  // 4.6.36 EOR (imm), T1 encoding (pg 4-86)
  if (((w0 & 0xFBE0u) == 0xF080u) && ((w1 & 0x8000u) == 0)) {
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, s{ u8((w0 >> 4u) & 1u) }, n{ u8(w0 & 0xFu) };
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u },
        imm{ decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    if ((s == 1) && (d == 15)) {  // 4.6.190 TEQ (imm), T1 encoding (pg 4-393)
      out_inst.type = inst_type::TEST_EQUIV_IMM;
      out_inst.i.test_equiv_imm = { .imm = imm, .n = n };
      return true;
    }
    out_inst.type = inst_type::EXCL_OR_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.excl_or_imm = { .imm = imm, .n = n };
    return true;
  }

  if ((w0 & 0xFFE0) == 0xEA80u) {  // 4.6.37 EOR (reg), T2 encoding (pg 4-88)
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, s{ u8((w0 >> 4u) & 1u) },
        imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 3u) }, m{ u8(w1 & 0xFu) },
        n{ u8(w0 & 0xFu) };
    imm_shift const shift{ decode_imm_shift(u8((w1 >> 4u) & 3u),
                                            u8((imm3 << 2u) | imm2)) };
    if ((d == 15) && (s == 1)) {  // 4.6.191 TEQ (reg), T1 encoding (pg 4-395)
      out_inst.type = inst_type::TEST_EQUIV_REG;
      out_inst.i.test_equiv_reg = { .shift = shift, .n = n, .m = m };
      return true;
    }
    out_inst.type = inst_type::EXCL_OR_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.excl_or_reg = { .shift = shift, .n = n, .m = m };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE910u) {
    out_inst.type = inst_type::LOAD_MULT_DEC_BEFORE;
    out_inst.dr = u16(w1 & 0xDFFFu);
    out_inst.i.load_mult_dec_before = { .n = u8(w0 & 0xFu), .wback = u8((w0 >> 5u) & 1u) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE890u) {  // 4.6.42 LDMIA, T2 encoding (pg 4-98)
    out_inst.type = inst_type::LOAD_MULT_INC_AFTER;
    out_inst.dr = u16(w1 & 0xDFFFu);
    out_inst.i.load_mult_inc_after = { .n = u8(w0 & 0xFu), .wback = u8((w0 >> 5u) & 1u) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8D0u) {  // 4.6.43 LDR (imm), T3 encoding (pg 4-100)
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) };
    u16 const imm{ u16(w1 & 0xFFFu) };
    if (n == 15) {  // 4.6.44 LDR (literal), T2 encoding (pg 4-102)
      out_inst.type = inst_type::LOAD_LIT;
      out_inst.dr = u16(1u << t);
      out_inst.i.load_lit = { .imm = imm,
                              .addr = u32(inst_align(out_inst.addr, 4) + imm + 4),
                              .add = u8((w0 >> 7u) & 1u) };
      return true;
    }
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_imm = { .imm = imm, .n = n, .add = 1u, .index = 1u };
    return true;
  }

  // 4.6.43 LDR (immediate), T4 encoding (pg 4-100)
  if (((w0 & 0xFFF0u) == 0xF850u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const p{ u8((w1 >> 10u) & 1u) }, u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) };
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_ERR("SEE LDRT on page 4-148\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));
    out_inst.i.load_imm = { .imm = u8(w1 & 0xFFu),
                            .n = u8(w0 & 0xFu),
                            .add = u,
                            .index = p };
    return true;
  }

  // 4.6.45 LDR (register), T2 encoding (pg 4-104)
  if (((w0 & 0xFFF0u) == 0xF850u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::LOAD_REG;
    out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));  // t == d
    out_inst.i.load_reg = { .shift = { .t = imm_shift_type::LSL,
                                       .n = u8((w1 >> 4u) & 3u) },
                            .n = u8(w0 & 0xFu),
                            .m = u8(w1 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF890u) {  // 4.6.46 LDRB (imm), T2 encoding (pg 4-106)
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));
    out_inst.i.load_byte_imm = { .imm = u16(w1 & 0xFFFu),
                                 .n = u8(w0 & 0xFu),
                                 .add = 1u,
                                 .index = 1u };
    return true;
  }

  // 4.6.46 LDRB (imm), T3 encoding (pg 4-106)
  if (((w0 & 0xFFF0u) == 0xF810u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) }, puw{ u8((w1 >> 8u) & 3u) };
    if (n == 15) {
      NL_LOG_ERR("SEE LDRB (literal) on page 4-108");
      return false;
    }
    if ((t == 15) && (puw == 0b110)) {
      NL_LOG_ERR("SEE LDRBT on page 4-112");
      return false;
    }
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_byte_imm = { .imm = u16(w1 & 0xFFu),
                                 .n = n,
                                 .add = u8((puw >> 1u) & 1u),
                                 .index = u8((puw >> 2u) & 1u) };
    return true;
  }

  // 4.6.48 LDRB (reg), T2 encoding (pg 4-110)
  if (((w0 & 0xFFF0u) == 0xF810u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) };
    if (t == 15) {
      NL_LOG_ERR("SEE PLD (register) on page 4-203");
      return false;
    }
    if (n == 15) {  // 4.6.47 LDRB (lit), T1 encoding (pg 4-108)
      if (t == 15) {
        NL_LOG_ERR("SEE PLD (immediate) on page 4-201");
        return false;
      }
      out_inst.type = inst_type::LOAD_BYTE_LIT;
      out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));
      out_inst.i.load_byte_lit = { .imm = u16(w1 & 0xFFFu), .add = u8((w0 >> 7u) & 1u) };
    } else {
      out_inst.type = inst_type::LOAD_BYTE_REG;
      out_inst.dr = u16(1u << t);
      out_inst.i.load_byte_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                             u8((w1 >> 4u) & 3u)),
                                   .n = n,
                                   .m = u8(w1 & 0xFu) };
    }
    return true;
  }

  if ((w0 & 0xFE50u) == 0xE850u) {  // 4.6.50 LDRD (imm), T1 encoding (pg 4-114)
    u8 const p{ u8((w0 >> 8u) & 1u) }, u{ u8((w0 >> 7u) & 1u) }, w{ u8((w0 >> 5u) & 1u) };
    if ((p == 0) && (w == 0)) {
      if (u == 0) {  // 4.6.51 LDREX, T1 encoding (pg 4-116)
        out_inst.type = inst_type::LOAD_EXCL;
        out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));
        out_inst.i.load_excl = { .imm = u16((w1 & 0xFFu) << 2u), .n = u8(w0 & 0xFu) };
        return true;
      } else {
        if ((w1 & 0xF0u) == 0x10) {  // 4.6.189 TBH, T1 encoding (pg 4-391)
          out_inst.type = inst_type::TABLE_BRANCH_HALF;
          out_inst.i.table_branch_half = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
          return true;
        }
        if ((w1 & 0xF0u) == 0) {  // 4.6.188 TBB, T1 encoding (pg 4-389)
          out_inst.type = inst_type::TABLE_BRANCH_BYTE;
          out_inst.i.table_branch_byte = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
          return true;
        }
        return false;
      }
    }
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, t2{ u8((w1 >> 8u) & 0xFu) };
    out_inst.type = inst_type::LOAD_DBL_REG;
    out_inst.dr = u16((1u << t) | (1u << t2));
    out_inst.i.load_dbl_reg = { .imm = u16((w1 & 0xFFu) << 2u),
                                .t = t,
                                .t2 = t2,
                                .n = u8(w0 & 0xFu),
                                .index = p,
                                .add = u };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8B0u) {  // 4.6.55 LDRH (imm), T2 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.dr = u16(1u << ((w1 >> 12u) & 0xFu));
    out_inst.i.load_half_imm = { .imm = u16(w1 & 0xFFFu),
                                 .n = u8(w0 & 0xFu),
                                 .add = 1u,
                                 .index = 1u };
    return true;
  }

  // 4.6.55 LDRH (imm), T3 encoding (pg 4-124)
  if (((w0 & 0xFFF0u) == 0xF830u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const p{ u8((w1 >> 10u) & 1u) }, u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) },
        n{ u8(w0 & 0xFu) }, t{ u8((w1 >> 12u) & 0xFu) };
    if (n == 15) {
      printf("SEE LDRH (literal) on page 4-126\n");
      return false;
    }
    if ((t == 15) && (p == 1) && (u == 0) && (w == 0)) {
      printf("SEE Memory hints on page 4-14\n");
      return false;
    }
    if ((p == 1) && (u == 1) && (w == 0)) {
      printf("SEE LDRHT on page 4-130\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_half_imm = { .imm = u16(w1 & 0xFFu), .n = n, .add = u, .index = p };
    return true;
  }

  // 4.6.57 LDRH (reg), T2 encoding (pg 4-128)
  if (((w0 & 0xFFF0u) == 0xF830u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, m{ u8(w1 & 0xFu) }, n{ u8(w0 & 0xFu) };
    imm_shift const shift{ decode_imm_shift(u8(imm_shift_type::LSL),
                                            u8((w1 >> 4u) & 3u)) };
    if (n == 15) {
      printf("SEE LDRH (literal) on page 4-126\n");
      return false;
    }
    if (t == 15) {
      printf("SEE Memory hints on page 4-14\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_HALF_REG;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_half_reg = { .shift = shift, .n = n, .m = m };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF990u) {  // 4.6.59 LDRSB (imm), T1 encoding (pg 4-132)
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_IMM;
    out_inst.dr = u16(1u << ((w0 >> 12u) & 0xFu));
    out_inst.i.load_signed_byte_imm = { .imm = u16(w1 & 0xFFFu),
                                        .n = u8(w0 & 0xFu),
                                        .index = 1u,
                                        .add = 1u };
    return true;
  }

  // 4.6.59 LDRSB (imm), T2 encoding (pg 4-132)
  if (((w0 & 0xFFF0u) == 0xF910u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const n{ u8(w0 & 0xFu) }, t{ u8((w1 >> 12u) & 0xFu) }, p{ u8((w1 >> 10u) & 1u) },
        u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) };
    u16 const imm{ u16(w1 & 0xFFu) };
    if (n == 15) {
      NL_LOG_DBG("SEE LDRSB (literal) on page 4-134;\n");
      return false;
    }
    if ((t == 15) && (p == 1) && (u == 0) && (w == 0)) {
      NL_LOG_DBG("SEE PLI (immediate) on page 4-205;\n");
      return false;
    }
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_DBG("SEE LDRSBT on page 4-138;\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_signed_byte_imm = { .imm = imm, .n = n, .index = p, .add = u };
    return true;
  }

  // 4.6.61 LDRSB (reg), T2 encoding (pg 4-136)
  if (((w0 & 0xFFF0u) == 0xF910u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, m{ u8(w1 & 0xFu) }, n{ u8(w0 & 0xFu) },
        shift{ u8((w1 >> 4u) & 3u) };
    if (t == 15) {
      printf("SEE PLI (register) on page 4-207\n");
      return false;
    }
    if (n == 15) {
      printf("SEE LDRSB (literal) on page 4-134\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_REG;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_signed_byte_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                                  shift),
                                        .n = n,
                                        .m = m };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF9B0u) {  // 4.6.63 LDRSH (imm), T1 encoding (pg 4-140)
    u8 const n{ u8(w0 & 0xFu) }, t{ u8((w1 >> 12u) & 0xFu) };
    if (n == 15) {
      NL_LOG_ERR("SEE LDRSH (literal) on page 4-142");
      return false;
    }
    if (t == 15) {
      NL_LOG_ERR("SEE Memory hints on page 4-14");
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_HALF_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_signed_half_imm = { .imm = u16(w1 & 0xFFFu),
                                        .n = n,
                                        .index = 1u,
                                        .add = 1u };
    return true;
  }

  // 4.6.63 LDRSH (imm), T2 encoding (pg 4-140)
  if (((w0 & 0xFFF0u) == 0xF930u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) }, p{ u8((w0 >> 10u) & 1u) },
        u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) };
    u16 const imm{ u16(w1 & 0xFFu) };
    if (n == 15) {
      NL_LOG_DBG("SEE LDRSH (literal) on page 4-142\n");
      return false;
    }
    if ((t == 15) && (p == 1) && (u == 0) && (w == 0)) {
      NL_LOG_DBG("SEE Memory hints on page 4-14\n");
      return false;
    }
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_DBG("SEE LDRSHT on page 4-146\n");
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_HALF_IMM;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_signed_half_imm = { .imm = imm, .n = n, .index = p, .add = u };
    return true;
  }

  // 4.6.65 LDRSH (reg), T2 encoding (pg 4-144)
  if (((w0 & 0xFFF0u) == 0xF930u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) };
    if (n == 15) {
      NL_LOG_ERR("SEE LDRSH (literal) on page 4-142");
      return false;
    }
    if (t == 15) {
      NL_LOG_ERR("SEE Memory hints on page 4-14");
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_HALF_REG;
    out_inst.dr = u16(1u << t);
    out_inst.i.load_signed_half_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                                  u8((w1 >> 4u) & 3u)),
                                        .n = n,
                                        .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.68 LSL (imm), T2 encoding (pg 4-150)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0)) {
    u8 const imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 3u) },
        imm{ u8((imm3 << 2u) | imm2) };
    if (imm == 0) {
      NL_LOG_DBG("4.6.68 LSL (imm), T2 encoding (pg 4-150)\n");
      return false;
    }
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.lshift_log_imm = { .shift = decode_imm_shift(0b00, imm),
                                  .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.69 LSL (reg), T2 encoding (pg 4-152)
  if (((w0 & 0xFFE0u) == 0xFA00u) && ((w1 & 0xF0F0u) == 0xF000u)) {
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.lshift_log_reg = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.70 LSR (imm), T2 encoding (pg 4-154)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0x10u)) {
    u8 const imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 7u) };
    out_inst.type = inst_type::RSHIFT_LOG_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.rshift_log_imm = { .shift = decode_imm_shift(0b01, u8((imm3 << 2u) | imm2)),
                                  .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.71 LSR (reg), T2 encoding (pg 4-156)
  if (((w0 & 0xFFE0u) == 0xFA20u) && ((w1 & 0xF0F0u) == 0xF000u)) {
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.lshift_log_reg = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.74 MLA, T1 encoding (pg 4-162)
  if (((w0 & 0xFFF0u) == 0xFB00u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_ACCUM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.mul_accum = { .n = u8(w0 & 0xFu),
                             .m = u8(w1 & 0xFu),
                             .a = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  // 4.6.75 MLS, T1 encoding (pg 4-164)
  if (((w0 & 0xFFF0u) == 0xFB00u) && ((w1 & 0xF0u) == 0x10u)) {
    out_inst.type = inst_type::MUL_SUB;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.mul_sub = { .n = u8(w0 & 0xFu),
                           .m = u8(w1 & 0xFu),
                           .a = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  // 4.6.76 MOV (imm), T2 encoding (pg 4-166)
  if (((w0 & 0xFBEFu) == 0xF04Fu) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::MOV_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.mov_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.76 MOV (imm), T3 encoding (pg 4-166)
  if (((w0 & 0xFBF0u) == 0xF240u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u },
        imm4{ w0 & 0xFu };
    out_inst.type = inst_type::MOV_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.mov_imm = { .imm = (imm4 << 12u) | (i << 11u) | (imm3 << 8u) | imm8 };
    return true;
  }

  // 4.6.85 MVN (imm), T2 encoding (pg 4-183)
  if (((w0 & 0xFBEFu) == 0xF06Fu) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::MOV_NEG_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.mov_neg_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.88 NOP, T2 encoding (pg 4-189)
  if (((w0 & 0xFFF0u) == 0xF3A0u) && ((w1 & 0xD7FFu) == 0x8000u)) {
    // don't need nop flag memory hints for static analysis (e.g. dsb, isb)
    out_inst.type = inst_type::NOP;
    out_inst.i.nop = {};
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA60u) {  // 4.6.90 ORN, T1 encoding (pg 4-193)
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, m{ u8(w1 & 0xFu) }, n{ u8(w0 & 0xFu) },
        imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) };
    imm_shift const shift{ decode_imm_shift(u8((w1 >> 4u) & 3u),
                                            u8((imm3 << 2u) | imm2)) };
    if (n == 15) {  // 4.6.86 MVN (reg), T2 encoding (pg 4-185)
      out_inst.type = inst_type::MOV_NEG_REG;
      out_inst.dr = u16(1u << d);
      out_inst.i.mov_neg_reg = { .shift = shift, .m = m };
      return true;
    }
    out_inst.type = inst_type::OR_NOT_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.or_not_reg = { .shift = shift, .n = n, .m = m };
    return true;
  }

  // 4.6.91 ORR (imm), T1 encoding (pg 4-195)
  if (((w0 & 0xFB40u) == 0xF040u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u },
        imm{ decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    u8 const n{ u8(w0 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) };
    if (n == 15) {  // 4.6.76 MOV (imm), T2 encoding (pg 4-166)
      out_inst.type = inst_type::MOV_IMM;
      out_inst.dr = u16(1u << d);
      out_inst.i.mov_imm = { .imm = imm };
      return true;
    }
    out_inst.type = inst_type::OR_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.or_imm = { .imm = imm, .n = n };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA40u) {  // 4.6.91 ORR (reg), T2 encoding (pg 4-197)
    u8 const imm3{ u8((w1 >> 12u) & 7u) }, imm2{ u8((w1 >> 6u) & 3u) }, n{ u8(w0 & 0xFu) },
        m{ u8(w1 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) };
    imm_shift const shift{ decode_imm_shift(u8((w1 >> 4u) & 3u),
                                            u8((imm3 << 2u) | imm2)) };
    if (n == 15) {
      out_inst.type = inst_type::MOV_REG;
      out_inst.dr = u16(1u << d);
      out_inst.i.mov_reg = { .m = m };
      return true;
    }
    out_inst.type = inst_type::OR_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.or_reg = { .shift = shift, .n = n, .m = m };
    return true;
  }

  // 4.6.93 PKH, T1 encoding (pg 4-199)
  if (((w0 & 0xFFF0u) == 0xEAC0u) && ((w1 & 0x10u) == 0)) {
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) },
        tb{ u8((w1 >> 5u) & 1u) };
    out_inst.type = inst_type::PACK_HALF;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.pack_half = { .shift =
                                 decode_imm_shift(u8(tb << 1u), u8((imm3 << 2u) | imm2)),
                             .n = u8(w0 & 0xFu),
                             .m = u8(w1 & 0xFu),
                             .tbform = tb };
    return true;
  }

  if (w0 == 0xE8BDu) {  // 4.6.98 POP, T2 encoding (pg 4-209)
    out_inst.dr = uint16_t(w1 & 0xDFFFu);
    out_inst.type = inst_type::POP;
    return true;
  }

  // 4.6.110 RBIT, T1 encoding (pg 4-233)
  if (((w0 & 0xFFF0u) == 0xFA90u) && ((w1 & 0xF0F0u) == 0xF0A0u)) {
    out_inst.type = inst_type::REVERSE_BITS;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.reverse_bits = { .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.112 REV16, T2 encoding (pg 4-237)
  if (((w0 & 0xFFF0u) == 0xFA90u) && ((w1 & 0xF0F0u) == 0xF090u)) {
    out_inst.type = inst_type::BYTE_REV_PACKED_HALF;
    out_inst.dr = u16(1u << (((w1 & 0xF00u) >> 8u) & 0xFu));
    out_inst.i.byte_rev_packed_half = { .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.118 RSB (imm), T2 encoding (pg 4-249)
  if (((w0 & 0xFBE0u) == 0xF1C0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::SUB_REV_IMM;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.sub_rev_imm = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8),
                               .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEBC0u) {
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) },
        imm{ u8((imm3 << 2u) | imm2) };
    out_inst.type = inst_type::SUB_REV_REG;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.sub_rev_reg = { .shift = decode_imm_shift(u8((w1 >> 4u) & 3u), imm),
                               .n = u8(w0 & 0xFu),
                               .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.123 SBC (imm), T1 encoding (pg 4-259)
  if (((w0 & 0xFBE0u) == 0xF160u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u };
    out_inst.type = inst_type::SUB_IMM_CARRY;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.sub_imm_carry = { .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8),
                                 .n = u8(w0 & 0xFu) };
    return true;
  }

  // 4.6.125 SBFX, T1 encoding (pg 4-263)
  if (((w0 & 0xFBF0u) == 0xF340u) && ((w1 & 0x8000u) == 0)) {
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) };
    out_inst.type = inst_type::BITFIELD_EXTRACT_SIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.bitfield_extract_signed = { .n = u8(w0 & 0xFu),
                                           .lsbit = u8((imm3 << 2u) | imm2),
                                           .widthminus1 = u8(w1 & 0x1Fu) };
    return true;
  }

  // 4.6.126 SDIV, T1 encoding (pg 4-265)
  if (((w0 & 0xFFF0u) == 0xFB90u) && ((w1 & 0xF0u) == 0xF0u)) {
    out_inst.type = inst_type::DIV_SIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.div_signed = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB60) {  // 4.6.124 SBC (reg), T2 encoding (pg 4-261)
    u32 const imm2{ (w1 >> 6u) & 3u }, imm3{ (w1 >> 12u) & 7u };
    out_inst.type = inst_type::SUB_REG_CARRY;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.sub_reg_carry = { .shift = decode_imm_shift(u8((w1 >> 4u) & 3u),
                                                           u8((imm3 << 2u) | imm2)),
                                 .n = u8(w0 & 0xFu),
                                 .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.127 SEL, T1 encoding (4-267)
  if (((w0 & 0xFFF0u) == 0xFAA0u) && ((w1 & 0xF0F0u) == 0xF080u)) {
    out_inst.type = inst_type::SELECT_BYTES;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.select_bytes = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.137 SMLABB, SMLABT, SMLATB, SMLATT, T1 encoding (pg 4-287)
  if (((w0 & 0xFFF0u) == 0xFB10u) && ((w1 & 0xC0u) == 0)) {
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, m{ u8(w1 & 0xFu) }, n{ u8(w0 & 0xFu) },
        a{ u8((w1 >> 12u) & 0xFu) }, M{ u8((w1 >> 4u) & 1u) }, N{ u8((w1 >> 5u) & 1u) };
    if (a == 15) {
      // 4.6.149 SMULBB, SMULBT, SMULTB, SMULTT, T1 encoding (pg 4-311)
      out_inst.type = inst_type::MUL_SIGNED_HALF;
      out_inst.dr = u16(1u << d);
      out_inst.i.mul_signed_half = { .n = n, .m = m, .n_high = N, .m_high = M };
      return true;
    }
    out_inst.type = inst_type::MUL_ACCUM_SIGNED_HALF;
    out_inst.dr = u16(1u << d);
    out_inst.i.mul_accum_signed_half = { .n = n,
                                         .m = m,
                                         .a = a,
                                         .n_high = N,
                                         .m_high = M };
    return true;
  }

  // 4.6.139 SMLAL, T1 encoding (pg 4-291)
  if (((w0 & 0xFFF0u) == 0xFBC0u) && ((w1 & 0xF0u) == 0)) {
    u8 const dlo{ u8((w1 >> 12u) & 0xFu) }, dhi{ u8((w1 >> 8u) & 0xFu) };
    out_inst.dr = u16((1u << dlo) | (1u << dhi));
    out_inst.type = inst_type::MUL_ACCUM_SIGNED_LONG;
    out_inst.i.mul_accum_signed_long = { .dlo = dlo,
                                         .dhi = dhi,
                                         .n = u8(w0 & 0xFu),
                                         .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.150 SMULL, T1 encoding (pg 4-313)
  if (((w0 & 0xFFF0u) == 0xFB80u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_SIGNED_LONG;
    out_inst.i.mul_signed_long = { .dlo = u8((w1 >> 12u) & 0xFu),
                                   .dhi = u8((w1 >> 8u) & 0xFu),
                                   .n = u8(w0 & 0xFu),
                                   .m = u8(w1 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE900u) {  // 4.6.160 STMDB, T1 encoding (pg 4-333)
    out_inst.type = inst_type::STORE_MULT_DEC_BEFORE;
    out_inst.i.store_mult_dec_before = { .regs = u16(w1 & 0x5FFFu), .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE880u) {  // 4.6.161 STMIA, T2 encoding (pg 4-335)
    out_inst.type = inst_type::STORE_MULT_INC_AFTER;
    out_inst.i.store_mult_inc_after = { .regs = u16(w1 & 0x5FFFu),
                                        .n = u8(w0 & 0xFu),
                                        .wback = u8((w0 >> 5u) & 1u) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8C0u) {  // 4.6.162 STR (imm), T3 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .imm = u16(w1 & 0xFFFu),
                             .t = u8(w1 >> 12u),
                             .n = u8(w0 & 0xFu) };
    return true;
  }

  // 4.6.162 STR (imm), T4 encoding (pg 4-337)
  if (((w0 & 0xFFF0u) == 0xF840) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, n{ u8(w0 & 0xFu) }, imm8{ u8(w1 & 0xFFu) },
        p{ u8((w1 >> 10u) & 1u) }, u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) };
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_ERR("SEE STRT on page 4-363");
      return false;
    }
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .imm = u16(imm8), .t = t, .n = n };
    return true;
  }

  // 4.6.163 STR (reg), T2 encoding (pg 4-339)
  if (((w0 & 0xFFF0u) == 0xF840u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::STORE_REG;
    out_inst.i.store_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                       u8((w1 >> 4u) & 3u)),
                             .t = u8((w1 >> 12u) & 0xFu),
                             .n = u8(w0 & 0xFu),
                             .m = u8(w1 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF880u) {  // 4.6.164 STRB (imm), T2 encoding (pg 4-341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16(w1 & 0xFFFu),
                                  .n = u8(w0 & 0xFu),
                                  .t = u8((w1 >> 12u) & 0xFu),
                                  .index = 1u,
                                  .add = 1u };
    return true;
  }

  // 4.6.164 STRB (imm), T3 encoding (pg 4-341)
  if (((w0 & 0xFFF0u) == 0xF800u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const p{ u8((w1 >> 10u) & 1u) }, u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) },
        imm8{ u8(w1 & 0xFFu) };
    if ((p == 1) && (u == 1) && (w == 0)) {  // 4.6.166 STRBT, T1 encoding (pg 4-345)
      out_inst.type = inst_type::STORE_BYTE_UNPRIV;
      out_inst.i.store_byte_unpriv = { .imm = u16(imm8),
                                       .t = u8((w1 >> 12u) & 0xFu),
                                       .n = u8(w0 & 0xFu) };
      return true;
    }
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16(imm8),
                                  .n = u8(w0 & 0xFu),
                                  .t = u8((w1 >> 12u) & 0xFu),
                                  .index = p,
                                  .add = u };
    return true;
  }

  // 4.6.165 STRB (reg), T2 encoding (pg 4-343)
  if (((w0 & 0xFFF0u) == 0xF800u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::STORE_BYTE_REG;
    out_inst.i.store_byte_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                            u8((w1 >> 4u) & 3u)),
                                  .t = u8((w1 >> 12u) & 0xFu),
                                  .m = u8(w1 & 0xFu),
                                  .n = u8(w0 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFE50u) == 0xE840u) {  // 4.6.167 STRD (imm), T1 encoding (pg 4-347)
    u8 const p{ u8((w0 >> 8u) & 1u) }, w{ u8((w0 >> 5u) & 1u) };
    if ((p == 0) && (w == 0)) {  // 4.6.168 STREX, T1 encoding (pg 4-349)
      out_inst.type = inst_type::STORE_EXCL;
      out_inst.i.store_excl = { .imm = u16((w1 & 0xFFu) << 2u),
                                .d = u8((w1 >> 8u) & 0xFu),
                                .t = u8((w1 >> 12u) & 0xFu),
                                .n = u8(w0 & 0xFu) };
      return true;
    }
    out_inst.type = inst_type::STORE_DOUBLE_IMM;
    out_inst.i.store_double_imm = { .imm = u16((w1 & 0xFFu) << 2u),
                                    .t = u8((w1 >> 12u) & 0xFu),
                                    .t2 = u8((w1 >> 8u) & 0xFu),
                                    .n = u8(w0 & 0xFu),
                                    .add = u8((w0 >> 7u) & 1u),
                                    .index = p };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEBA0u) {  // 4.6.177 SUB (reg), T2 encoding (pg 4-367)
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, n{ u8(w0 & 0xFu) }, s{ u8((w0 >> 4u) & 1u) },
        m{ u8(w1 & 0xFu) }, imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) };
    imm_shift const shift{ decode_imm_shift(u8((w1 >> 4u) & 3u), u8(imm3 << 2u) | imm2) };
    if ((d == 15) && (s == 1)) {  // 4.6.30 CMP (reg), T3 encoding (pg 4-74)
      out_inst.type = inst_type::CMP_REG;
      out_inst.i.cmp_reg = { .shift = shift, .n = n, .m = m };
      return true;
    }
    if (n == 13) {
      NL_LOG_ERR("SEE SUB (SP minus register) on page 4-371");
      return false;
    }
    out_inst.type = inst_type::SUB_REG;
    out_inst.dr = u16(1u << d);
    out_inst.i.sub_reg = { .shift = shift, .n = n, .m = m };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8A0u) {  // 4.6.172 STRH (imm), T2 encoding (pg 4-357)
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .imm = u16(w1 & 0xFFFu),
                                  .t = u8((w1 >> 12u) & 0xFu),
                                  .n = u8(w0 & 0xFu),
                                  .index = 1u,
                                  .add = 1u };
    return true;
  }

  // 4.6.172 STRH (imm), T3 encoding (pg 4-357)
  if (((w0 & 0xFFF0u) == 0xF820u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const n{ u8(w0 & 0xFu) }, t{ u8((w1 >> 12u) & 0xFu) }, imm{ u8(w1 & 0xFu) },
        p{ u8((w1 >> 10u) & 1u) }, u{ u8((w1 >> 9u) & 1u) }, w{ u8((w1 >> 8u) & 1u) };
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_DBG("SEE STRHT on page 4-361\n");
      return false;
    }
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .imm = imm, .t = t, .n = n, .index = p, .add = u };
    return true;
  }

  // 4.6.173 STRH (reg), T2 encoding (pg 4-359)
  if (((w0 & 0xFFF0u) == 0xF820u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::STORE_HALF_REG;
    out_inst.i.store_half_reg = { .shift = decode_imm_shift(u8(imm_shift_type::LSL),
                                                            u8((w1 >> 4u) & 3u)),
                                  .t = u8((w1 >> 12u) & 0xFu),
                                  .n = u8(w0 & 0xFu),
                                  .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.176 SUB (imm), T3 encoding (pg 4-365)
  if (((w0 & 0xFBE0u) == 0xF1A0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{ w1 & 0xFFu }, imm3{ (w1 >> 12u) & 7u }, i{ (w0 >> 10u) & 1u },
        imm{ decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, n{ u8(w0 & 0xFu) }, s{ u8((w0 >> 4u) & 1u) };
    if ((d == 15) && (s == 1)) {  // 4.6.29 CMP (imm), T2 encoding (pg 4-72)
      out_inst.type = inst_type::CMP_IMM;
      out_inst.i.cmp_imm = { .imm = imm, .n = n };
      return true;
    }
    if (n == 13) {  // 4.6.178 SUB (SP minus imm), T2 encoding (pg 4-369)
      out_inst.type = inst_type::SUB_SP_IMM;
      out_inst.dr = u16(1u << d);
      out_inst.i.sub_sp_imm = { .imm = imm };
      return true;
    }
    out_inst.type = inst_type::SUB_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.sub_imm = { .imm = imm, .n = n };
    return true;
  }

  // 4.6.176 SUB (imm), T4 encoding (pg 4-365)
  if (((w0 & 0xFBF0u) == 0xF2A0u) && ((w1 & 0x8000u) == 0)) {
    u8 const n{ u8(w0 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) };
    u16 const imm3{ u8((w1 >> 12u) & 7u) }, imm8{ u8(w1 & 0xFFu) },
        i{ u8((w0 >> 10u) & 1u) }, imm{ u16((i << 11u) | (imm3 << 8u) | imm8) };
    if (n == 15) {
      NL_LOG_ERR("SEE ADR on page 4-28");
      return false;
    }
    if (n == 13) {  // 4.6.178 SUB (SP minus imm), T3 encoding, (pg 4-369)
      out_inst.type = inst_type::SUB_SP_IMM;
      out_inst.dr = u16(1u << d);
      out_inst.i.sub_sp_imm = { .imm = imm };
      return true;
    }
    out_inst.type = inst_type::SUB_IMM;
    out_inst.dr = u16(1u << d);
    out_inst.i.sub_imm = { .imm = imm, .n = n };
    return true;
  }

  // 4.6.182 SXTAB, T1 encoding (pg 4-377)
  if (((w0 & 0xFFF0u) == 0xFA40u) && ((w1 & 0xF080u) == 0xF080u)) {
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, m{ u8(w1 & 0xFu) }, n{ u8(w0 & 0xFu) },
        rotation{ u8(((w1 >> 4u) & 3u) << 3u) };
    if (n == 15) {  // 4.6.185 SXTB, T2 encoding (pg 4-383)
      out_inst.type = inst_type::EXTEND_SIGNED_BYTE;
      out_inst.dr = u16(1u << d);
      out_inst.i.extend_signed_byte = { .m = m, .rotation = rotation };
      return true;
    }
    out_inst.type = inst_type::EXTEND_ADD_SIGNED_BYTE;
    out_inst.dr = u16(1u << d);
    out_inst.i.extend_add_signed_byte = { .n = n, .m = m, .rotation = rotation };
    return true;
  }

  // 4.6.184 SXTAH, T1 encoding (pg 4-381)
  if (((w0 & 0xFFF0u) == 0xFA00u) && ((w1 & 0xF080u) == 0xF080u)) {
    u8 const n{ u8(w0 & 0xFu) }, m{ u8(w1 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) },
        rotation{ u8(((w1 >> 4u) & 3u) << 3u) };
    if (n == 15) {  // 4.6.187 SXTH, T2 encoding (pg 4-387)
      out_inst.type = inst_type::EXTEND_SIGNED_HALF;
      out_inst.dr = u16(1u << d);
      out_inst.i.extend_signed_half = { .m = m, .rotation = rotation };
      return true;
    }
    out_inst.type = inst_type::EXTEND_ADD_SIGNED_HALF;
    out_inst.dr = u16(1u << d);
    out_inst.i.extend_add_signed_half = { .n = n, .m = m, .rotation = rotation };
    return true;
  }

  // 4.6.195 UADD8, T1 encoding (pg 4-403)
  if (((w0 & 0xFFF0u) == 0xFA80u) && ((w1 & 0xF0F0u) == 0xF040u)) {
    out_inst.type = inst_type::ADD_8_UNSIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.add_8_unsigned = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.197 UBFX, T1 encoding (pg 4-407)
  if (((w0 & 0xFBF0u) == 0xF3C0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm2{ (w1 >> 6u) & 3u }, imm3{ (w1 >> 12u) & 7u };
    out_inst.type = inst_type::BITFIELD_EXTRACT_UNSIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.bitfield_extract_unsigned = { .n = u8(w0 & 0xFu),
                                             .lsbit = u8((imm3 << 2u) | imm2),
                                             .widthminus1 = u8(w1 & 0x1Fu) };
    return true;
  }

  // 4.6.198 UDIV, T1 encoding (pg 4-409)
  if (((w0 & 0xFFF0u) == 0xFBB0) && ((w1 & 0xF0u) == 0xF0u)) {
    out_inst.type = inst_type::DIV_UNSIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8u) & 0xFu));
    out_inst.i.div_unsigned = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.206 UMLAL, T1 encoding (pg 4-425)
  if (((w0 & 0xFFF0u) == 0xFBE0u) && ((w1 & 0xF0u) == 0)) {
    u8 const dlo{ u8((w1 >> 12u) & 0xFu) }, dhi{ u8((w1 >> 8u) & 0xFu) };
    out_inst.type = inst_type::MUL_ACCUM_UNSIGNED_LONG;
    out_inst.dr = u16((1u << dlo) | (1u << dhi));
    out_inst.i.mul_accum_unsigned_long = { .dlo = dlo,
                                           .dhi = dhi,
                                           .n = u8(w0 & 0xFu),
                                           .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.207 UMULL, T1 encoding (pg 4-427)
  if (((w0 & 0xFFF0u) == 0xFBA0u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_UNSIGNED_LONG;
    out_inst.i.mul_unsigned_long = { .dlo = u8((w1 >> 12u) & 0xFu),
                                     .dhi = u8((w1 >> 8u) & 0xFu),
                                     .n = u8(w0 & 0xFu),
                                     .m = u8(w1 & 0xFu) };
    return true;
  }

  // 4.6.216 USAT, T1 encoding (pg 4-445)
  if (((w0 & 0xFBD0u) == 0xF380u) && ((w1 & 0x8000u) == 0)) {
    u8 const imm2{ u8((w1 >> 6u) & 3u) }, imm3{ u8((w1 >> 12u) & 7u) },
        imm5{ u8((imm3 << 2u) | imm2) }, sh{ u8((w0 >> 5u) & 1u) };
    out_inst.type = inst_type::SATURATE_UNSIGNED;
    out_inst.dr = u16(1u << ((w1 >> 8) & 0xFu));
    out_inst.i.saturate_unsigned = { .shift = decode_imm_shift(u8(sh << 1u), imm5),
                                     .n = u8(w0 & 0xFu),
                                     .saturate_to = u8(w1 & 0x1Fu) };
    return true;
  }

  // 4.6.221 UXTAB, T1 encoding (pg 4-455)
  if (((w0 & 0xFFF0u) == 0xFA50u) && ((w1 & 0xF080u) == 0xF080u)) {
    u8 const d{ u8((w1 >> 8u) & 0xFu) }, n{ u8(w0 & 0xFu) }, m{ u8(w1 & 0xFu) },
        rotation{ u8(((w1 >> 4u) & 3u) << 3u) };
    if (n == 15) {  // 4.6.224 UXTB, T2 encoding (pg 4-461)
      out_inst.type = inst_type::EXTEND_UNSIGNED_BYTE;
      out_inst.dr = u16(1u << d);
      out_inst.i.extend_unsigned_byte = { .m = m, .rotation = rotation };
      return true;
    }
    out_inst.type = inst_type::EXTEND_ADD_UNSIGNED_BYTE;
    out_inst.dr = u16(1u << d);
    out_inst.i.extend_add_unsigned_byte = { .n = n, .m = m, .rotation = rotation };
    return true;
  }

  // 4.6.223 UXTAH, T1 encoding (pg 4-459)
  if (((w0 & 0xFFF0u) == 0xFA10u) && ((w1 & 0xF080u) == 0xF080u)) {
    u8 const n{ u8(w0 & 0xFu) }, d{ u8((w1 >> 8u) & 0xFu) }, m{ u8(w1 & 0xFu) },
        rotation{ u8(((w1 >> 4u) & 3u) << 3u) };
    if (n == 15) {  // 4.6.226 UXTH, T2 encoding (pg 4-465)
      out_inst.type = inst_type::EXTEND_UNSIGNED_HALF;
      out_inst.dr = u16(1u << d);
      out_inst.i.extend_unsigned_half = { .m = m, .rotation = rotation };
      return true;
    }
    out_inst.type = inst_type::EXTEND_ADD_UNSIGNED_HALF;
    out_inst.dr = u16(1u << d);
    out_inst.i.extend_add_unsigned_half = { .n = n, .m = m, .rotation = rotation };
    return true;
  }

  // A7.7.221 VADD, T1 encoding (pg A7-566)
  if (((w0 & 0xFFB0u) == 0xEE30u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, N{ u8((w1 >> 7u) & 1u) }, M{ u8((w1 >> 5u) & 1u) },
        vn{ u8(w0 & 0xFu) }, vm{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) };
    out_inst.type = inst_type::VADD;
    out_inst.i.vadd = { .d = u8((vd << 1u) | D),
                        .n = u8((vn << 1u) | N),
                        .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.222 VCMP, T1 encoding (pg A7-567)
  if (((w0 & 0xFFBFu) == 0xEEB4u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, vd{ u8((w1 >> 12u) & 0xFu) }, vm{ u8(w1 & 0xFu) },
        M{ u8((w1 >> 5u) & 1u) };
    out_inst.type = inst_type::VCOMPARE;
    out_inst.i.vcompare = { .quiet_nan_exc = u8((w1 >> 7u) & 1u),
                            .with_zero = 0u,
                            .d = u8((vd << 1u) | D),
                            .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.222 VCMP, T2 encoding (pg A7-567)
  if (((w0 & 0xFFBFu) == 0xEEB5u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, vd{ u8((w1 >> 12u) & 0xFu) };
    out_inst.type = inst_type::VCOMPARE;
    out_inst.i.vcompare = { .quiet_nan_exc = u8((w1 >> 7u) & 1u),
                            .with_zero = 1u,
                            .d = u8((vd << 1u) | D),
                            .m = 0 };
    return true;
  }

  // A7.7.223 VCVT (between FP and int), T1 encoding (pg A7-569)
  if (((w0 & 0xFFB8u) == 0xEEB8u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const opc2{ u8(w0 & 7u) }, d{ u8(((w1 >> 11u) & 0x1Eu) | ((w0 >> 6u) & 1u)) },
        op{ u8((w1 >> 7u) & 1u) }, m{ u8(((w1 & 0xFu) << 1u) | ((w1 >> 5u) & 1u)) },
        to_int{ u8(!!(opc2 & 0b100)) };
    out_inst.type = inst_type::VCONVERT_FP_INT;
    if (to_int) {
      out_inst.i.vconvert_fp_int = { .d = d,
                                     .m = m,
                                     .to_int = to_int,
                                     .int_unsigned = ((opc2 & 1u) == 0),
                                     .round_zero = op };
    } else {
      out_inst.i.vconvert_fp_int = { .d = d,
                                     .m = m,
                                     .to_int = to_int,
                                     .int_unsigned = (op == 0),
                                     .round_zero = 0 };
    }
    return true;
  }

  // A7.7.226 VDIV, T1 encoding (pg A7-575)
  if (((w0 & 0xFFB0u) == 0xEE80u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const vm{ u8(w1 & 0xFu) }, vn{ u8(w0 & 0xFu) }, vd{ u8((w1 >> 12u) & 1u) },
        D{ u8((w0 >> 6u) & 1u) }, N{ u8((w1 >> 7u) & 1u) }, M{ u8((w1 >> 5u) & 1u) };
    out_inst.type = inst_type::VDIV;
    out_inst.i.vdiv = { .d = u8((vd << 1u) | D),
                        .n = u8((vn << 1u) | N),
                        .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.227 VFMA, VFMS, T1 encoding (pg A7-576)
  if (((w0 & 0xFFB0u) == 0xEEA0u) && ((w1 & 0xF10u) == 0xA00u)) {
    u8 const vn{ u8(w0 & 0xFu) }, vm{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) },
        N{ u8((w1 >> 7u) & 1u) }, M{ u8((w1 >> 5u) & 1u) }, D{ u8((w0 >> 6u) & 1u) };
    out_inst.type = inst_type::VMULT_ACCUM;
    out_inst.i.vmult_accum = { .op1_neg = u8((w1 >> 6u) & 1u),
                               .d = u8((vd << 1u) | D),
                               .n = u8((vn << 1u) | N),
                               .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.229 VLDM, T2 encoding (pg A7-579)
  if (((w0 & 0xFE10u) == 0xEC10u) && ((w1 & 0xF00u) == 0xA00u)) {
    u8 const p{ u8((w0 >> 8u) & 1u) }, u{ u8((w0 >> 7u) & 1u) }, w{ u8((w0 >> 5u) & 1u) },
        n{ u8(w0 & 0xFu) }, imm8{ u8(w1 & 0xFFu) }, D{ u8((w0 >> 6u) & 1u) },
        vd{ u8((w1 >> 12u) & 0xFu) };
    if ((p == 0) && (u == 0) && (w == 0)) {
      printf("See 64-bit transfers ... on page A6-199\n");
      return false;
    }
    if ((p == 0) && (u == 1) && (w == 1) && (n == 0b1101)) {
      printf("SEE VPOP\n");
      return false;
    }
    if ((p == 1) && (w == 0)) {  // A7.7.230 VLDR, T2 encoding (pg A7-581)
      out_inst.type = inst_type::VLOAD;
      out_inst.i.vload = { .imm = u16(imm8 << 2u),
                           .single_reg = 1u,
                           .add = u8((w0 >> 7u) & 1u),
                           .n = u8(w0 & 0xFu),
                           .d = u8((vd << 1) | D) };
      return true;
    }
    out_inst.type = inst_type::VLOAD_MULT;
    out_inst.i.vload_mult = { .imm = u32(imm8 << 2u),
                              .d = u8((vd << 1) | D),
                              .n = n,
                              .wback = w,
                              .regs = imm8,
                              .single_regs = 1u,
                              .add = u };
    return true;
  }

  // A7.7.230 VLDR, T1 encoding (pg A7-581)
  if (((w0 & 0xFF30u) == 0xED10u) && ((w1 & 0xF00u) == 0xB00u)) {
    out_inst.type = inst_type::VLOAD;
    out_inst.i.vload = {
      .imm = u8(w1 & 0xFu),
      .single_reg = 0,
      .add = u8((w0 >> 7) & 1),
      .n = u8(w0 & 0xFu),
      .d = u8(u8((w1 >> 12u) & 0xFu) | u8(((w0 >> 6) & 1) << 4u)),
    };
    return true;
  }

  // A7.7.232 VMOV (imm), T1 encoding (pg A7-585)
  if (((w0 & 0xFFB0u) == 0xEEB0u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const imm4h{ u8(w0 & 0xFu) }, imm4l{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) },
        D{ u8((w0 >> 6u) & 1u) };
    out_inst.type = inst_type::VMOV_IMM;
    out_inst.i.vmov_imm = { .imm = decode_vfp_imm8(u8((imm4h << 4u) | imm4l), 32),
                            .d = u8((D << 4u) | vd),
                            .regs = 1u };
    return true;
  }

  // A7.7.233 VMOV (reg), T1 encoding (pg A7-586)
  if (((w0 & 0xFFBFu) == 0xEEB0u) && ((w1 & 0xFD0u) == 0xA40u)) {
    u8 const vm{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) }, M{ u8((w1 >> 5u) & 1u) },
        D{ u8((w0 >> 6u) & 1u) };
    out_inst.type = inst_type::VMOV_REG;
    out_inst.i.vmov_reg = { .d = u8((vd << 1u) | D), .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.237 VMOV (2 ARM core regsters and a dword reg), T1 encoding (pg A7-590)
  if (((w0 & 0xFFE0u) == 0xEC40u) && ((w1 & 0xFD0u) == 0xB10u)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, t2{ u8(w0 & 0xFu) },
        to_arm_regs{ u8((w0 >> 4u) & 1u) };
    if (to_arm_regs) {
      out_inst.dr = u16((1u << t) | (1u << t2));
    }
    out_inst.type = inst_type::VMOV_REG_DOUBLE;
    out_inst.i.vmov_reg_double = { .t = t,
                                   .t2 = t2,
                                   .m = u8((w1 & 0xFu) | ((w1 >> 1u) & 0x10u)),
                                   .to_arm_regs = to_arm_regs };
    return true;
  }

  // A7.7.239 VMRS, T1 encoding (pg A7-592)
  if (((w0 & 0xFFF0u) == 0xEEF0u) && ((w1 & 0xF10u) == 0xA10u)) {
    out_inst.type = inst_type::VMOV_SPECIAL_FROM;
    out_inst.i.vmov_special_from = { .t = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  // A7.7.240 VMSR, T1 encoding (pg A7-593)
  if (((w0 & 0xFFF0u) == 0xEEE0u) && ((w1 & 0xF10u) == 0xA10u)) {
    out_inst.type = inst_type::VMOV_SPECIAL_TO;
    out_inst.i.vmov_special_to = { .t = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  // A7.7.236 VMOV (ARM core reg and single-precision reg), T1 encoding (pg A7-531)
  if (((w0 & 0xFFE0u) == 0xEE00u) && ((w1 & 0xF10u) == 0xA10u)) {
    u8 const t{ u8((w1 >> 12u) & 0xFu) }, to_arm_reg{ u8((w0 >> 4u) & 1u) };
    out_inst.type = inst_type::VMOV_REG_SINGLE;
    if (to_arm_reg) {
      out_inst.dr = u16(1u << t);
    }
    out_inst.i.vmov_reg_single = { .t = t,
                                   .n = u8(((w0 & 0xFu) << 1u) | ((w1 >> 7u) & 1u)),
                                   .to_arm_reg = to_arm_reg };
    return true;
  }

  // A7.7.241 VMUL, T1 encoding (pg A7-594)
  if (((w0 & 0xFFB0u) == 0xEE20u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, N{ u8((w1 >> 7u) & 1u) }, M{ u8((w1 >> 5u) & 1u) },
        vd{ u8((w1 >> 12u) & 0xFu) }, vm{ u8(w1 & 0xFu) }, vn{ u8(w0 & 0xFu) };
    out_inst.type = inst_type::VMUL;
    out_inst.i.vmul = { .d = u8((vd << 1u) | D),
                        .n = u8((vn << 1u) | N),
                        .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.242 VNEG, T1 encoding (pg A7-595)
  if (((w0 & 0xFFBFu) == 0xEEB1u) && ((w1 & 0xFD0u) == 0xA40u)) {
    u8 const vm{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) }, D{ u8((w0 >> 6u) & 1u) },
        M{ u8((w1 >> 5u) & 1u) };
    out_inst.type = inst_type::VNEG;
    out_inst.i.vneg = { .d = u8((vd << 1u) | D), .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.243 VNMUL, T2 encoding (pg A7-597)
  if (((w0 & 0xFFB0u) == 0xEE20u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const vd{ u8((w1 >> 12u) & 0xFu) }, vn{ u8(w0 & 0xFu) }, vm{ u8(w1 & 0xFu) },
        D{ u8((w0 >> 6u) & 1u) }, N{ u8((w1 >> 7u) & 1u) }, M{ u8((w1 >> 5u) & 1u) };
    out_inst.type = inst_type::VNMUL;
    out_inst.i.vnmul = { .d = u8((vd << 1u) | D),
                         .n = u8((vn << 1u) | N),
                         .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.244 VPOP, T1 encoding (pg A7-599)
  if (((w0 & 0xFFBFu) == 0xECBDu) && ((w1 & 0xF00u) == 0xB00u)) {
    u8 const vd{ u8((w1 >> 12u) & 0xFu) }, D{ u8((w0 >> 6u) & 1u) };
    u16 const imm8{ u16(w1 & 0xFFu) };
    out_inst.type = inst_type::VPOP;
    out_inst.i.vpop = { .imm = u16(imm8 << 2u),
                        .d = u8((D << 4u) | vd),
                        .single_regs = 0,
                        .regs = u8(imm8 / 2) };
    return true;
  }

  // A7.7.245 VPUSH, T2 encoding (pg A7-601)
  if (((w0 & 0xFFBFu) == 0xED2Du) && ((w1 & 0xF00u) == 0xB00u)) {
    u8 const vd{ u8((w1 >> 12u) & 0xFu) }, D{ u8((w0 >> 6u) & 1u) };
    u16 const imm8{ u16(w1 & 0xFFu) };
    out_inst.type = inst_type::VPUSH;
    out_inst.i.vpush = { .imm = u16(imm8 << 2u),
                         .d = u8((D << 4u) | vd),
                         .single_regs = 0,
                         .regs = u8(imm8 / 2) };
    return true;
  }

  // A7.7.246 VSQRT, T1 encoding (pg A7-603)
  if (((w0 & 0xFFBFu) == 0xEEB1u) && ((w1 & 0xFD0u) == 0xAC0u)) {
    u8 const vm{ u8(w1 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) }, M{ u8((w1 >> 5u) & 1u) },
        D{ u8((w0 >> 6u) & 1u) };
    out_inst.type = inst_type::VSQRT;
    out_inst.i.vsqrt = { .d = u8((vd << 1u) | D), .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.247 VSTM, T2 encoding (pg A7-605)
  if (((w0 & 0xFE10u) == 0xEC00u) && ((w1 & 0xF00u) == 0xA00u)) {
    u8 const n{ u8(w0 & 0xFu) }, vd{ u8((w1 >> 12u) & 0xFu) }, D{ u8((w1 >> 6u) & 1u) },
        imm{ u8(w1 & 0xFFu) }, p{ u8((w0 >> 8u) & 1u) }, u{ u8((w0 >> 7u) & 1u) },
        w{ u8((w0 >> 5u) & 1u) };
    if ((p == 0) && (u == 0) && (w == 0)) {
      printf("See 64-bit transfers ... on page A6-199\n");
      return false;
    }
    if ((p == 1) && (u == 0) && (w == 1) && (n == 0b1101)) {
      printf("SEE VPUSH\n");
      return false;
    }
    if ((p == u) && (w == 1)) {
      printf("SEE VSTR\n");
      return false;
    }
    out_inst.type = inst_type::VSTORE_MULT;
    out_inst.i.vstore_mult = { .imm = u16(imm << 2u),
                               .n = n,
                               .d = u8((vd << 1u) | D),
                               .list = imm,
                               .wb = w,
                               .single_regs = 1u,
                               .add = u };
    return true;
  }

  // A7.7.248 VSTR, T1 encoding (pg A7-607)
  if (((w0 & 0xFF30u) == 0xED00u) && ((w1 & 0xF00u) == 0xB00u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, vd{ u8((w1 >> 12u) & 0xFu) };
    u16 const imm8{ u16(w1 & 0xFFu) };
    out_inst.type = inst_type::VSTORE;
    out_inst.i.vstore = { .imm = u16(imm8 << 2u),
                          .single_reg = 1u,
                          .add = u8((w0 >> 7u) & 1u),
                          .d = u8((D << 4u) | vd),
                          .n = u8(w0 & 0xFu) };
    return true;
  }

  // A7.7.248 VSTR, T2 encoding (pg A7-607)
  if (((w0 & 0xFF30u) == 0xED00u) && ((w1 & 0xF00u) == 0xA00u)) {
    u8 const D{ u8((w0 >> 6u) & 1u) }, vd{ u8((w1 >> 12u) & 0xFu) };
    u16 const imm8{ u16(w1 & 0xFFu) };
    out_inst.type = inst_type::VSTORE;
    out_inst.i.vstore = { .imm = u16(imm8 << 2u),
                          .single_reg = 1u,
                          .add = u8((w0 >> 7u) & 1u),
                          .d = u8((vd << 1u) | D),
                          .n = u8(w0 & 0xFu) };
    return true;
  }

  // A7.7.249 VSUB, T1 encoding (pg  A7-609)
  if (((w0 & 0xFFB0u) == 0xEE30u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const vm{ u8(w1 & 0xFu) }, vn{ u8(w0 & 0xFu) }, M{ u8((w1 >> 5u) & 1u) },
        N{ u8((w1 >> 7u) & 1u) }, D{ u8((w0 >> 6u) & 1u) }, vd{ u8((w1 >> 12u) & 0xFu) };
    out_inst.type = inst_type::VSUB;
    out_inst.i.vsub = { .d = u8((vd << 1) | D),
                        .n = u8((vn << 1u) | N),
                        .m = u8((vm << 1u) | M) };
    return true;
  }

  return false;
}

}  // namespace

int inst_reg_from_bitmask(uint16_t reg_bitmask) {
  if (!reg_bitmask) {
    return -1;
  }
#ifdef _MSC_VER
  DWORD idx;
  _BitScanForward(&idx, reg_bitmask);
  return idx;
#else
  return __builtin_ctz(reg_bitmask);
#endif
}

bool inst_is_unconditional_branch(inst const& i, u32& label) {
  switch (i.type) {
    case inst_type::BRANCH:
      label = i.i.branch.addr;
      return cond_code_is_always(i.i.branch.cc);
    case inst_type::BRANCH_XCHG:
      label = 0;
      return true;
    case inst_type::BRANCH_LINK:
      label = i.i.branch_link.addr;
      return true;
    case inst_type::BRANCH_LINK_XCHG_REG:
      label = 0;
      return true;  // TODO: register state
    default:
      break;
  }
  return false;
}

u32 inst_align(u32 val, u32 align) {  // Rounding and Aligning, A-16
  // If x and y are integers, Align(x,y) = y * (x DIV y) is an integer.
  return align * (val / align);
}

bool inst_decode(byte const* text, u32 func_addr, u32 pc_addr, inst& out_inst) {
  out_inst.type = inst_type::UNKNOWN;
  out_inst.addr = func_addr + pc_addr;
  out_inst.dr = 0;
  out_inst.w1 = 0;

  memcpy(&out_inst.w0, &text[pc_addr], 2);
  if (is_16bit_inst(out_inst.w0)) {
    return decode_16bit_inst(out_inst.w0, out_inst);
  }
  memcpy(&out_inst.w1, &text[pc_addr + 2], 2);
  return decode_32bit_inst(out_inst.w0, out_inst.w1, out_inst);
}

char const* reg_name(int reg) {
  if ((reg < 0) || (reg > 15)) {
    return "<invalid>";
  }
  return s_rn[reg];
}

namespace {
char const* rn_mask(uint16_t dr) {
  if (!dr) {
    return "<invalid>";
  }
  return reg_name(inst_reg_from_bitmask(dr));
}
}  // namespace

void inst_print(inst const& i) {
  switch (i.type) {
    case inst_type::UNKNOWN:
      NL_LOG_DBG("??");
      break;

    case inst_type::ADD_CARRY_IMM: {
      auto const& a{ i.i.add_carry_imm };
      NL_LOG_DBG("ADC_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[a.n], int(a.imm));
    } break;

    case inst_type::ADD_CARRY_REG: {
      auto const& a{ i.i.add_carry_reg };
      NL_LOG_DBG("ADC_REG %s, %s, %s <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[a.n],
                 s_rn[a.m],
                 s_sn[int(a.shift.t)],
                 int(a.shift.n));
    } break;

    case inst_type::ADD_IMM: {
      auto const& a{ i.i.add_imm };
      NL_LOG_DBG("ADD_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[a.n], int(a.imm));
    } break;

    case inst_type::ADD_SP_IMM: {
      auto const& a{ i.i.add_sp_imm };
      NL_LOG_DBG("ADD %s, [%s, #%d]", rn_mask(i.dr), s_rn[reg::SP], (int)a.imm);
    } break;

    case inst_type::ADD_SP_REG: {
      auto const& a{ i.i.add_sp_reg };
      NL_LOG_DBG("ADD %s, %s, %s <%s, #%d>",
                 rn_mask(i.dr),
                 s_rn[reg::SP],
                 s_rn[a.m],
                 s_sn[int(a.shift.t)],
                 int(a.shift.n));
    } break;

    case inst_type::ADD_REG: {
      auto const& a{ i.i.add_reg };
      NL_LOG_DBG("ADD_REG %s, %s, %s <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[a.n],
                 s_rn[a.m],
                 s_sn[int(a.shift.t)],
                 int(a.shift.n));
    } break;

    case inst_type::ADD_8_UNSIGNED: {
      auto const& a{ i.i.add_8_unsigned };
      NL_LOG_DBG("UADD8 %s, %s, %s", rn_mask(i.dr), s_rn[a.n], s_rn[a.m]);
    } break;

    case inst_type::ADR: {
      auto const& a{ i.i.adr };
      NL_LOG_DBG("ADR %s, PC, #%c%d", rn_mask(i.dr), a.add ? '+' : '-', (int)a.imm);
    } break;

    case inst_type::AND_REG: {
      auto const& a{ i.i.and_reg };
      NL_LOG_DBG("AND_REG %s, %s, %s <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[a.n],
                 s_rn[a.m],
                 s_sn[int(a.shift.t)],
                 int(a.shift.n));
    } break;

    case inst_type::AND_IMM: {
      auto const& a{ i.i.and_imm };
      NL_LOG_DBG("AND_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[a.n], int(a.imm));
    } break;

    case inst_type::BIT_CLEAR_IMM: {
      auto const& b{ i.i.bit_clear_imm };
      NL_LOG_DBG("BIC_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[b.n], int(b.imm));
    } break;

    case inst_type::BIT_CLEAR_REG: {
      auto const& b{ i.i.bit_clear_reg };
      NL_LOG_DBG("BIC_REG %s, %s, %s, <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[b.n],
                 s_rn[b.m],
                 s_sn[int(b.shift.t)],
                 int(b.shift.n));
    } break;

    case inst_type::BITFIELD_CLEAR: {
      auto const& b{ i.i.bitfield_clear };
      NL_LOG_DBG("BFC %s, #%d, #%d", s_rn[b.d], int(b.lsbit), int(b.msbit - b.lsbit));
    } break;

    case inst_type::BITFIELD_EXTRACT_UNSIGNED: {
      auto const& b{ i.i.bitfield_extract_unsigned };
      NL_LOG_DBG("UBFX %s, %s, #%d, #%d",
                 rn_mask(i.dr),
                 s_rn[b.n],
                 int(b.lsbit),
                 int(b.widthminus1 + 1));
    } break;

    case inst_type::BITFIELD_EXTRACT_SIGNED: {
      auto const& b{ i.i.bitfield_extract_signed };
      NL_LOG_DBG("SBFX %s, %s, #%d, #%d",
                 rn_mask(i.dr),
                 s_rn[b.n],
                 int(b.lsbit),
                 int(b.widthminus1 + 1));
    } break;

    case inst_type::BITFIELD_INSERT: {
      auto const& b{ i.i.bitfield_insert };
      NL_LOG_DBG("BFI %s, %s, #%d, #%d",
                 rn_mask(i.dr),
                 s_rn[b.n],
                 int(b.lsbit),
                 int(b.msbit - b.lsbit));
    } break;

    case inst_type::BRANCH: {
      auto const& b{ i.i.branch };
      NL_LOG_DBG("B%s #%d (%x)",
                 b.cc >= cond_code::AL1 ? "" : cond_code_name(b.cc),
                 int(i32(b.imm)),
                 unsigned(b.addr));
    } break;

    case inst_type::BRANCH_LINK: {
      auto const& b{ i.i.branch_link };
      NL_LOG_DBG("BL #%d (%x)", unsigned(b.imm), unsigned(b.addr));
    } break;

    case inst_type::BRANCH_LINK_XCHG_REG:
      NL_LOG_DBG("BLX %s", s_rn[i.i.branch_link_xchg_reg.reg]);
      break;

    case inst_type::BRANCH_XCHG:
      NL_LOG_DBG("BX %s", s_rn[int(i.i.branch_xchg.m)]);
      break;

    case inst_type::BREAKPOINT:
      NL_LOG_DBG("BKPT 0x%04hx", i.i.breakpoint.imm);
      break;

    case inst_type::BYTE_REV_PACKED_HALF:
      NL_LOG_DBG("REV16 %s, %s", rn_mask(i.dr), s_rn[i.i.byte_rev_packed_half.m]);
      break;

    case inst_type::BYTE_REV_SIGNED_HALF:
      NL_LOG_DBG("REVSH %s, %s", rn_mask(i.dr), s_rn[i.i.byte_rev_signed_half.m]);
      break;

    case inst_type::BYTE_REV_WORD:
      NL_LOG_DBG("REV %s, %s", rn_mask(i.dr), s_rn[i.i.byte_rev_word.m]);
      break;

    case inst_type::CBNZ: {
      auto const& c{ i.i.cmp_branch_nz };
      NL_LOG_DBG("CBNZ %s, #%d (%x)", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
    } break;

    case inst_type::CBZ: {
      auto const& c{ i.i.cmp_branch_z };
      NL_LOG_DBG("CBZ %s, #%d (%x)", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
    } break;

    case inst_type::CHANGE_PROC_STATE: {
      auto const& c{ i.i.change_proc_state };
      NL_LOG_DBG("CPS%s %s%s%s",
                 c.en ? "IE" : (c.dis ? "ID" : ""),
                 c.aff_a ? "A" : "",
                 c.aff_f ? "F" : "",
                 c.aff_i ? "I" : "");
    } break;

    case inst_type::CMP_IMM: {
      auto const& c{ i.i.cmp_imm };
      NL_LOG_DBG("CMP_IMM %s, #%d", s_rn[c.n], int(c.imm));
    } break;

    case inst_type::CMP_NEG_IMM: {
      auto const& c{ i.i.cmp_neg_imm };
      NL_LOG_DBG("CMN_IMM %s, #%d", s_rn[c.n], int(c.imm));
    } break;

    case inst_type::CMP_REG: {
      auto const& c{ i.i.cmp_reg };
      NL_LOG_DBG("CMP_REG %s, %s <%s #%d>",
                 s_rn[c.n],
                 s_rn[c.m],
                 s_sn[int(c.shift.t)],
                 int(c.shift.n));
    } break;

    case inst_type::COUNT_LEADING_ZEROS:
      NL_LOG_DBG("CLZ %s, %s", rn_mask(i.dr), s_rn[i.i.count_leading_zeros.m]);
      break;

    case inst_type::DIV_SIGNED: {
      auto const& d{ i.i.div_signed };
      NL_LOG_DBG("SDIV %s, %s, %s", rn_mask(i.dr), s_rn[d.n], s_rn[d.m]);
    } break;

    case inst_type::DIV_UNSIGNED: {
      auto const& d{ i.i.div_unsigned };
      NL_LOG_DBG("UDIV %s, %s, %s", rn_mask(i.dr), s_rn[d.n], s_rn[d.m]);
    } break;

    case inst_type::EXCL_OR_IMM: {
      auto const& e{ i.i.excl_or_imm };
      NL_LOG_DBG("EOR_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[e.n], int(e.imm));
    } break;

    case inst_type::EXCL_OR_REG: {
      auto const& e{ i.i.excl_or_reg };
      NL_LOG_DBG("EOR_REG %s, %s, %s, <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[e.n],
                 s_rn[e.m],
                 s_sn[int(e.shift.t)],
                 int(e.shift.n));
    } break;

    case inst_type::EXTEND_ADD_SIGNED_BYTE: {
      auto const& e{ i.i.extend_add_signed_byte };
      NL_LOG_DBG("SXTAB %s, %s, %s, <%d>",
                 rn_mask(i.dr),
                 s_rn[e.n],
                 s_rn[e.m],
                 int(e.rotation));
    } break;

    case inst_type::EXTEND_ADD_SIGNED_HALF: {
      auto const& e{ i.i.extend_add_signed_half };
      NL_LOG_DBG("SXTAH %s, %s, %s, <%d>",
                 rn_mask(i.dr),
                 s_rn[e.n],
                 s_rn[e.m],
                 int(e.rotation));
    } break;

    case inst_type::EXTEND_ADD_UNSIGNED_BYTE: {
      auto const& e{ i.i.extend_add_unsigned_byte };
      NL_LOG_DBG("UXTAB %s, %s, %s, <%d>",
                 rn_mask(i.dr),
                 s_rn[e.n],
                 s_rn[e.m],
                 int(e.rotation));
    } break;

    case inst_type::EXTEND_SIGNED_BYTE: {
      auto const& e{ i.i.extend_signed_byte };
      NL_LOG_DBG("SXTB %s, %s, <%d>", rn_mask(i.dr), s_rn[e.m], int(e.rotation));
    } break;

    case inst_type::EXTEND_SIGNED_HALF: {
      auto const& e{ i.i.extend_signed_half };
      NL_LOG_DBG("SXTH %s, %s, <%d>", rn_mask(i.dr), s_rn[e.m], int(e.rotation));
    } break;

    case inst_type::EXTEND_UNSIGNED_BYTE: {
      auto const& u{ i.i.extend_unsigned_byte };
      NL_LOG_DBG("UXTB %s, %s, <%d>", rn_mask(i.dr), s_rn[u.m], int(u.rotation));
    } break;

    case inst_type::EXTEND_UNSIGNED_HALF: {
      auto const& u{ i.i.extend_unsigned_half };
      NL_LOG_DBG("UXTH %s, %s, <%d>", rn_mask(i.dr), s_rn[u.m], int(u.rotation));
    } break;

    case inst_type::EXTEND_ADD_UNSIGNED_HALF: {
      auto const& u{ i.i.extend_add_unsigned_half };
      NL_LOG_DBG("UXTAH %s, %s, %s, <#%d>",
                 rn_mask(i.dr),
                 s_rn[u.n],
                 s_rn[u.m],
                 int(u.rotation));
    } break;

    case inst_type::IF_THEN: {
      static char const* s_it[] = { "???", "EEE", "EE", "EET", "E", "ETE", "ET", "ETT",
                                    "",    "TEE", "TE", "TET", "T", "TTE", "TT", "TTT" };

      auto const& t{ i.i.if_then };
      NL_LOG_DBG("IT%s %s", s_it[t.mask], cond_code_name(cond_code(t.firstcond)));
    } break;

    case inst_type::LOAD_BYTE_IMM: {
      auto const& l{ i.i.load_byte_imm };
      NL_LOG_DBG("LDRB_IMM %s, [%s, #%d]", rn_mask(i.dr), s_rn[l.n], int(l.imm));
    } break;

    case inst_type::LOAD_BYTE_LIT: {
      auto const& l{ i.i.load_byte_lit };
      NL_LOG_DBG("LDRB_LIT %s, [%s, #%c%d]",
                 rn_mask(i.dr),
                 s_rn[reg::PC],
                 l.add ? '+' : '-',
                 int(l.imm));
    } break;

    case inst_type::LOAD_BYTE_REG: {
      auto const& l{ i.i.load_byte_reg };
      NL_LOG_DBG("LDRB_REG %s, [%s, %s, %s #%d]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 s_rn[l.m],
                 s_sn[int(l.shift.t)],
                 int(l.shift.n));
    } break;

    case inst_type::LOAD_DBL_REG: {
      auto const& l{ i.i.load_dbl_reg };
      NL_LOG_DBG("LDRD_REG %s, %s, [%s, #%s%d]",
                 rn_mask(i.dr),
                 s_rn[l.t2],
                 s_rn[l.n],
                 l.add ? "" : "-",
                 int(l.imm));
    } break;

    case inst_type::LOAD_EXCL: {
      auto const& l{ i.i.load_excl };
      NL_LOG_DBG("LDREX %s, [%s, #%d]", rn_mask(i.dr), s_rn[l.n], int(l.imm));
    } break;

    case inst_type::LOAD_HALF_IMM: {
      auto const& l{ i.i.load_half_imm };
      NL_LOG_DBG("LDRH_IMM %s, [%s, #%d]", rn_mask(i.dr), s_rn[l.n], int(l.imm));
    } break;

    case inst_type::LOAD_HALF_REG: {
      auto const& l{ i.i.load_half_reg };
      NL_LOG_DBG("LDRH_REG %s, [%s, %s, %s #%d]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 s_rn[l.m],
                 s_sn[int(l.shift.t)],
                 int(l.shift.n));
    } break;

    case inst_type::LOAD_SIGNED_BYTE_IMM: {
      auto const& l{ i.i.load_signed_byte_imm };
      NL_LOG_DBG("LDRSB_IMM %s, [%s, #%d]", rn_mask(i.dr), s_rn[l.n], int(l.imm));
    } break;

    case inst_type::LOAD_SIGNED_BYTE_REG: {
      auto const& l{ i.i.load_signed_byte_reg };
      NL_LOG_DBG("LDRSB_REG %s, [%s, %s, %s #%d]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 s_rn[l.m],
                 s_sn[int(l.shift.t)],
                 int(l.shift.n));
    } break;

    case inst_type::LOAD_SIGNED_HALF_IMM: {
      auto const& l{ i.i.load_signed_half_imm };
      NL_LOG_DBG("LDRSH_IMM %s, [%s, #%c%d]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 l.add ? '+' : '-',
                 int(l.imm));
    } break;

    case inst_type::LOAD_SIGNED_HALF_REG: {
      auto const& l{ i.i.load_signed_half_reg };
      NL_LOG_DBG("LDRSH_REG %s, [%s, %s, %s #%d]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 s_rn[l.m],
                 s_sn[int(l.shift.t)],
                 int(l.shift.n));
    } break;

    case inst_type::LOAD_IMM: {
      auto const& l{ i.i.load_imm };
      NL_LOG_DBG("LDR_IMM %s, [%s, #%d]", rn_mask(i.dr), s_rn[l.n], int(l.imm));
    } break;

    case inst_type::LOAD_LIT: {
      auto const& l{ i.i.load_lit };
      NL_LOG_DBG("LDR_LIT %s, [PC, #%s%d] (%x)",
                 rn_mask(i.dr),
                 l.add ? "" : "-",
                 int(l.imm),
                 unsigned(l.addr));
    } break;

    case inst_type::LOAD_MULT_DEC_BEFORE: {
      auto const& l{ i.i.load_mult_dec_before };
      NL_LOG_DBG("LDMDB %s%s, { ", s_rn[l.n], l.wback ? "!" : "");
      for (int b{ 0 }; b < 16; ++b) {
        if (i.dr & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::LOAD_MULT_INC_AFTER: {
      auto const& l{ i.i.load_mult_inc_after };
      NL_LOG_DBG("LDMIA %s%s, { ", s_rn[l.n], l.wback ? "!" : "");
      for (int b{ 0 }; b < 16; ++b) {
        if (i.dr & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::LOAD_REG: {
      auto const& l{ i.i.load_reg };
      NL_LOG_DBG("LDR_REG %s, [%s, %s <%s #%d>]",
                 rn_mask(i.dr),
                 s_rn[l.n],
                 s_rn[l.m],
                 s_sn[int(l.shift.t)],
                 int(l.shift.n));
    } break;

    case inst_type::LSHIFT_LOG_IMM: {
      auto const& l{ i.i.lshift_log_imm };
      NL_LOG_DBG("LSL_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[l.m], int(l.shift.n));
    } break;

    case inst_type::LSHIFT_LOG_REG: {
      auto const& l{ i.i.lshift_log_reg };
      NL_LOG_DBG("LSL_REG %s, %s, %s", rn_mask(i.dr), s_rn[l.n], s_rn[l.m]);
    } break;

    case inst_type::MOV_REG: {
      auto const& m{ i.i.mov_reg };
      NL_LOG_DBG("MOV %s, %s", rn_mask(i.dr), s_rn[m.m]);
    } break;

    case inst_type::MOV_IMM: {
      auto const& m{ i.i.mov_imm };
      NL_LOG_DBG("MOV_IMM %s, #%d (%#x)", rn_mask(i.dr), int(m.imm), unsigned(m.imm));
    } break;

    case inst_type::MOV_NEG_IMM: {
      auto const& m{ i.i.mov_neg_imm };
      NL_LOG_DBG("MOV_NEG_IMM %s, #%d (%#x)",
                 rn_mask(i.dr),
                 unsigned(m.imm),
                 unsigned(m.imm));
    } break;

    case inst_type::MOV_NEG_REG: {
      auto const& m{ i.i.mov_neg_reg };
      NL_LOG_DBG("MOV_NEG_REG %s, %s, %s #%d",
                 rn_mask(i.dr),
                 s_rn[m.m],
                 s_sn[int(m.shift.t)],
                 int(m.shift.n));
    } break;

    case inst_type::MUL: {
      auto const& m{ i.i.mul };
      NL_LOG_DBG("MUL %s, %s, %s", rn_mask(i.dr), s_rn[m.n], s_rn[m.m]);
    } break;

    case inst_type::MUL_ACCUM: {
      auto const& m{ i.i.mul_accum };
      NL_LOG_DBG("MLA %s, %s, %s, %s", rn_mask(i.dr), s_rn[m.n], s_rn[m.m], s_rn[m.a]);
    } break;

    case inst_type::MUL_ACCUM_SIGNED_HALF: {
      auto const& m{ i.i.mul_accum_signed_half };
      NL_LOG_DBG("SMLA%c%c %s, %s, %s, %s",
                 "BT"[m.n_high],
                 "BT"[m.m_high],
                 rn_mask(i.dr),
                 s_rn[m.n],
                 s_rn[m.m],
                 s_rn[m.a]);
    } break;

    case inst_type::MUL_ACCUM_SIGNED_LONG: {
      auto const& m{ i.i.mul_accum_signed_long };
      NL_LOG_DBG("SMLAL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
    } break;

    case inst_type::MUL_ACCUM_UNSIGNED_LONG: {
      auto const& m{ i.i.mul_accum_unsigned_long };
      NL_LOG_DBG("UMLAL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
    } break;

    case inst_type::MUL_SIGNED_HALF: {
      auto const& m{ i.i.mul_signed_half };
      NL_LOG_DBG("SMUL%c%c %s, %s, %s",
                 "BT"[m.n_high],
                 "BT"[m.m_high],
                 rn_mask(i.dr),
                 s_rn[m.n],
                 s_rn[m.m]);
    } break;

    case inst_type::MUL_SIGNED_LONG: {
      auto const& m{ i.i.mul_signed_long };
      NL_LOG_DBG("SMULL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
    } break;

    case inst_type::MUL_SUB: {
      auto const& m{ i.i.mul_sub };
      NL_LOG_DBG("MLS %s, %s, %s, %s", rn_mask(i.dr), s_rn[m.n], s_rn[m.m], s_rn[m.a]);
    } break;

    case inst_type::MUL_UNSIGNED_LONG: {
      auto const& m{ i.i.mul_unsigned_long };
      NL_LOG_DBG("UMULL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
    } break;

    case inst_type::NOP:
      NL_LOG_DBG("NOP");
      break;

    case inst_type::OR_NOT_REG: {
      auto const& o{ i.i.or_not_reg };
      NL_LOG_DBG("ORN_REG %s, %s, %s, %s #%d",
                 rn_mask(i.dr),
                 s_rn[o.n],
                 s_rn[o.m],
                 s_sn[int(o.shift.t)],
                 int(o.shift.n));
    } break;

    case inst_type::OR_IMM: {
      auto const& o{ i.i.or_imm };
      NL_LOG_DBG("ORR_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[o.n], int(o.imm));
    } break;

    case inst_type::OR_REG: {
      auto const& o{ i.i.or_reg };
      NL_LOG_DBG("ORR_REG %s, %s, %s <%s #%d>",
                 rn_mask(i.dr),
                 s_rn[o.n],
                 s_rn[o.m],
                 s_sn[int(o.shift.t)],
                 int(o.shift.n));
    } break;

    case inst_type::PACK_HALF: {
      auto const& p{ i.i.pack_half };
      NL_LOG_DBG("PKH%s %s, %s, %s, %s #%d",
                 p.tbform ? "TB" : "BT",
                 rn_mask(i.dr),
                 s_rn[p.n],
                 s_rn[p.m],
                 s_sn[int(p.shift.t)],
                 int(p.shift.n));
    } break;

    case inst_type::PUSH: {
      NL_LOG_DBG("PUSH { ");
      for (auto b{ 0 }; b < 16; ++b) {
        if (i.i.push.reg_list & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::POP: {
      NL_LOG_DBG("POP { ");
      for (auto b{ 0 }; b < 16; ++b) {
        if (i.dr & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::REVERSE_BITS: {
      auto const& r{ i.i.reverse_bits };
      NL_LOG_DBG("RBIT %s, %s", rn_mask(i.dr), s_rn[r.m]);
    } break;

    case inst_type::RSHIFT_ARITH_IMM: {
      auto const& r{ i.i.rshift_arith_imm };
      NL_LOG_DBG("ASR_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[r.m], int(r.shift.n));
    } break;

    case inst_type::RSHIFT_ARITH_REG: {
      auto const& r{ i.i.rshift_arith_reg };
      NL_LOG_DBG("ASR_REG %s, %s, %s", rn_mask(i.dr), s_rn[r.n], s_rn[r.m]);
    } break;

    case inst_type::RSHIFT_LOG_IMM: {
      auto const& r{ i.i.rshift_log_imm };
      NL_LOG_DBG("LSR_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[r.m], int(r.shift.n));
    } break;

    case inst_type::RSHIFT_LOG_REG: {
      auto const& r{ i.i.rshift_log_reg };
      NL_LOG_DBG("LSR_REG %s, %s, %s", rn_mask(i.dr), s_rn[r.m], s_rn[r.n]);
    } break;

    case inst_type::SATURATE_UNSIGNED: {
      auto const& s{ i.i.saturate_unsigned };
      NL_LOG_DBG("USAT %s, #%d, %s <%s #%d>",
                 rn_mask(i.dr),
                 int(s.saturate_to),
                 s_rn[s.n],
                 s_sn[int(s.shift.t)],
                 int(s.shift.n));
    } break;

    case inst_type::SELECT_BYTES: {
      auto const& s{ i.i.select_bytes };
      NL_LOG_DBG("SEL %s, %s, %s", rn_mask(i.dr), s_rn[s.n], s_rn[s.m]);
    } break;

    case inst_type::STORE_BYTE_IMM: {
      auto const& s{ i.i.store_byte_imm };
      NL_LOG_DBG("STRB_IMM %s, [%s, #%c%d]",
                 s_rn[s.t],
                 s_rn[s.n],
                 s.add ? '+' : '-',
                 int(s.imm));
    } break;

    case inst_type::STORE_BYTE_REG: {
      auto const& s{ i.i.store_byte_reg };
      NL_LOG_DBG("STRB_REG %s, [%s, %s, %s #%d]",
                 s_rn[s.t],
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 int(s.shift.n));
    } break;

    case inst_type::STORE_BYTE_UNPRIV: {
      auto const& s{ i.i.store_byte_unpriv };
      NL_LOG_DBG("STRBT %s, [%s, #%d]", s_rn[s.t], s_rn[s.n], int(s.imm));
    } break;

    case inst_type::STORE_DOUBLE_IMM: {
      auto const& s{ i.i.store_double_imm };
      NL_LOG_DBG("STRD %s, %s, [%s], #%d", s_rn[s.t], s_rn[s.t2], s_rn[s.n], int(s.imm));
    } break;

    case inst_type::STORE_EXCL: {
      auto const& s{ i.i.store_excl };
      NL_LOG_DBG("STREX %s, %s, [%s, #%d]", s_rn[s.d], s_rn[s.t], s_rn[s.n], int(s.imm));
    } break;

    case inst_type::STORE_HALF_IMM: {
      auto const& s{ i.i.store_half_imm };
      NL_LOG_DBG("STRH %s, [%s, #%c%d]",
                 s_rn[s.t],
                 s_rn[s.n],
                 s.add ? '+' : '-',
                 int(s.imm));
    } break;

    case inst_type::STORE_HALF_REG: {
      auto const& s{ i.i.store_half_reg };
      NL_LOG_DBG("STRH %s, [%s, %s, %s #%d]",
                 s_rn[s.t],
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 int(s.shift.n));
    } break;

    case inst_type::STORE_IMM: {
      auto const& s{ i.i.store_imm };
      NL_LOG_DBG("STR_IMM %s, [%s, #%d]", s_rn[s.t], s_rn[s.n], int(s.imm));
    } break;

    case inst_type::STORE_MULT_DEC_BEFORE: {
      auto const& s{ i.i.store_mult_dec_before };
      NL_LOG_DBG("STMDB %s!, { ", s_rn[s.n]);
      for (int b{ 0 }; b < 16; ++b) {
        if (s.regs & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::STORE_MULT_INC_AFTER: {
      auto const& s{ i.i.store_mult_inc_after };
      NL_LOG_DBG("STMIA %s%s, { ", s_rn[s.n], s.wback ? "!" : "");
      for (int b{ 0 }; b < 16; ++b) {
        if (s.regs & (1u << b)) {
          NL_LOG_DBG("%s ", s_rn[b]);
        }
      }
      NL_LOG_DBG("}");
    } break;

    case inst_type::STORE_REG: {
      auto const& s{ i.i.store_reg };
      NL_LOG_DBG("STR_REG %s, [%s, %s <%s #%d>",
                 s_rn[s.t],
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 int(s.shift.n));
    } break;

    case inst_type::SUB_IMM: {
      auto const& s{ i.i.sub_imm };
      NL_LOG_DBG("SUB_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[s.n], int(s.imm));
    } break;

    case inst_type::SUB_IMM_CARRY: {
      auto const& s{ i.i.sub_imm_carry };
      NL_LOG_DBG("SUB_IMM_CARRY %s, %s, #%d", rn_mask(i.dr), s_rn[s.n], int(s.imm));
    } break;

    case inst_type::SUB_REG: {
      auto const& s{ i.i.sub_reg };
      NL_LOG_DBG("SUB_REG %s, %s, %s <%s #%u>",
                 rn_mask(i.dr),
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 unsigned(s.shift.n));
    } break;

    case inst_type::SUB_REG_CARRY: {
      auto const& s{ i.i.sub_reg_carry };
      NL_LOG_DBG("SUB_REG_CARRY %s, %s, %s <%s #%u>",
                 rn_mask(i.dr),
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 unsigned(s.shift.n));
    } break;

    case inst_type::SUB_REV_IMM: {
      auto const& s{ i.i.sub_rev_imm };
      NL_LOG_DBG("RSB_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[s.n], int(s.imm));
    } break;

    case inst_type::SUB_REV_REG: {
      auto const& s{ i.i.sub_rev_reg };
      NL_LOG_DBG("RSB_REG %s, %s, %s, %s #%d",
                 rn_mask(i.dr),
                 s_rn[s.n],
                 s_rn[s.m],
                 s_sn[int(s.shift.t)],
                 int(s.shift.n));
    } break;

    case inst_type::SUB_SP_IMM: {
      auto const& s{ i.i.sub_sp_imm };
      NL_LOG_DBG("SUB_IMM %s, %s, #%d", rn_mask(i.dr), s_rn[reg::SP], int(s.imm));
    } break;

    case inst_type::SVC:
      NL_LOG_DBG("SVC %x", unsigned(i.i.svc.imm));
      break;

    case inst_type::TABLE_BRANCH_BYTE: {
      auto const& t{ i.i.table_branch_byte };
      NL_LOG_DBG("TBB [%s, %s]", s_rn[t.n], s_rn[t.m]);
    } break;

    case inst_type::TABLE_BRANCH_HALF: {
      auto const& t{ i.i.table_branch_half };
      NL_LOG_DBG("TBH [%s, %s]", s_rn[t.n], s_rn[t.m]);
    } break;

    case inst_type::TEST_EQUIV_IMM: {
      auto const& t{ i.i.test_equiv_imm };
      NL_LOG_DBG("TEQ_IMM %s, #%d", s_rn[t.n], int(t.imm));
    } break;

    case inst_type::TEST_EQUIV_REG: {
      auto const& t{ i.i.test_equiv_reg };
      NL_LOG_DBG("TEQ_REG %s, %s", s_rn[t.n], s_rn[t.m]);
    } break;

    case inst_type::TEST_REG: {
      auto const& t{ i.i.test_reg };
      NL_LOG_DBG("TST %s, %s, %s #%d",
                 s_rn[t.n],
                 s_rn[t.m],
                 s_sn[int(t.shift.t)],
                 int(t.shift.n));
    } break;

    case inst_type::UNDEFINED:
      NL_LOG_DBG("UDF");
      break;

    case inst_type::VADD: {
      auto const& v{ i.i.vadd };
      NL_LOG_DBG("VADD.F32 S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
    } break;

    case inst_type::VCOMPARE: {
      auto const& v{ i.i.vcompare };
      NL_LOG_DBG("VCMP%s.F32 S%d, ", v.quiet_nan_exc ? "E" : "", int(v.d));
      if (v.with_zero) {
        NL_LOG_DBG("#0.0");
      } else {
        NL_LOG_DBG("S%d", int(v.m));
      }
    } break;

    case inst_type::VCONVERT_FP_INT: {
      auto const& v{ i.i.vconvert_fp_int };
      NL_LOG_DBG("VCVT.");
      NL_LOG_DBG("%c32.", v.to_int ? (v.int_unsigned ? 'U' : 'S') : 'F');
      NL_LOG_DBG("%c32 ", v.to_int ? 'F' : (v.int_unsigned ? 'U' : 'S'));
      NL_LOG_DBG("S%d, S%d", int(v.d), int(v.m));
    } break;

    case inst_type::VDIV: {
      auto const& v{ i.i.vdiv };
      NL_LOG_DBG("VDIV S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
    } break;

    case inst_type::VMULT_ACCUM: {
      auto const& v{ i.i.vmult_accum };
      NL_LOG_DBG("VFM%c.F32 S%d, S%d, S%d",
                 v.op1_neg ? 'S' : 'A',
                 int(v.d),
                 int(v.n),
                 int(v.m));
    } break;

    case inst_type::VLOAD: {
      auto const& v{ i.i.vload };
      NL_LOG_DBG("VLDR S%d, [%s, #%d]", int(v.d), s_rn[v.n], int(v.imm));
    } break;

    case inst_type::VLOAD_MULT: {
      auto const& v{ i.i.vload_mult };
      NL_LOG_DBG("VLDM%s %s, {%x}", v.add ? "IA" : "DB", s_rn[v.n], unsigned(v.regs));
    } break;

    case inst_type::VMOV_IMM: {
      auto const& v{ i.i.vmov_imm };
      NL_LOG_DBG("VMOV_IMM.F32 S%d, #%f", int(v.d), double(v.imm));
    } break;

    case inst_type::VMOV_REG: {
      auto const& v{ i.i.vmov_reg };
      NL_LOG_DBG("VMOV_REG.F32 S%d, S%d", int(v.d), int(v.m));
    } break;

    case inst_type::VMOV_REG_DOUBLE: {
      auto const& v{ i.i.vmov_reg_double };
      if (v.to_arm_regs) {
        NL_LOG_DBG("VMOV %s, %s, D%u", s_rn[v.t], s_rn[v.t2], unsigned(v.m));
      } else {
        NL_LOG_DBG("VMOV D%u, %s, %s", unsigned(v.m), s_rn[v.t], s_rn[v.t2]);
      }
    } break;

    case inst_type::VMOV_REG_SINGLE: {
      auto const& v{ i.i.vmov_reg_single };
      if (v.to_arm_reg) {
        NL_LOG_DBG("VMOV %s, S%u", s_rn[v.t], unsigned(v.n));
      } else {
        NL_LOG_DBG("VMOV S%u, %s", unsigned(v.n), s_rn[v.t]);
      }
    } break;

    case inst_type::VMOV_SPECIAL_FROM: {
      auto const& v{ i.i.vmov_special_from };
      NL_LOG_DBG("VMRS %s, FPSCR", v.t == 0b1111 ? "APSR_nzcv" : s_rn[v.t]);
    } break;

    case inst_type::VMOV_SPECIAL_TO: {
      auto const& v{ i.i.vmov_special_to };
      NL_LOG_DBG("VMSR FPSCR, %s", s_rn[v.t]);
    } break;

    case inst_type::VMUL: {
      auto const& v{ i.i.vmul };
      NL_LOG_DBG("VMUL.F32 S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
    } break;

    case inst_type::VNEG: {
      auto const& v{ i.i.vneg };
      NL_LOG_DBG("VNEG.F32 S%d, S%d", int(v.d), int(v.m));
    } break;

    case inst_type::VNMUL: {
      auto const& v{ i.i.vnmul };
      NL_LOG_DBG("VNMUL.F32 S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
    } break;

    case inst_type::VPOP: {
      auto const& v{ i.i.vpop };
      NL_LOG_DBG("VPOP { %x }", v.regs);  // TODO: print the list, don't care right now
    } break;

    case inst_type::VPUSH: {
      auto const& v{ i.i.vpush };
      NL_LOG_DBG("VPUSH { %x }", v.regs);  // TODO: print the list, don't care right now
    } break;

    case inst_type::VSTORE: {
      auto const& v{ i.i.vstore };
      NL_LOG_DBG("VSTR %c%d, [%s, #%d]",
                 v.single_reg ? 'S' : 'D',
                 int(v.d),
                 s_rn[v.n],
                 int(v.imm));
    } break;

    case inst_type::VSTORE_MULT: {
      auto const& v{ i.i.vstore_mult };
      NL_LOG_DBG("VSTM%s %s%s, { %x }",
                 v.add ? "IA" : "DB",
                 s_rn[v.n],
                 v.wb ? "!" : "",
                 unsigned(v.list));
    } break;

    case inst_type::VSUB: {
      auto const& v{ i.i.vsub };
      NL_LOG_DBG("VSUB S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
    } break;

    case inst_type::VSQRT: {
      auto const& v{ i.i.vsqrt };
      NL_LOG_DBG("VSQRT.F32 S%d, S%d", int(v.d), int(v.m));
    } break;
  }
}
