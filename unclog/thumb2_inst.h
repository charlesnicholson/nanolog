#pragma once

#include "boilerplate.h"

// Condition Codes

#define CONDITION_CODE_X_LIST() \
  X(EQ, 0b0000) X(NE, 0b0001) X(CS, 0b0010) X(CC, 0b0011) \
  X(MI, 0b0100) X(PL, 0b0101) X(VS, 0b0110) X(VC, 0b0111) \
  X(HS, 0b1000) X(LS, 0b1001) X(GE, 0b1010) X(LT, 0b1011) \
  X(GT, 0b1100) X(LE, 0b1101) X(AL1, 0b1110) X(AL2, 0b1111)

#define X(NAME, VAL) NAME = VAL,
enum class cond_code : u8 { CONDITION_CODE_X_LIST() };
#undef X

inline bool cond_code_is_always(cond_code cc) { return cc >= cond_code::AL1; }

// Registers

#define REGISTER_X_LIST() \
  X(R0) X(R1) X(R2) X(R3) X(R4) X(R5) X(R6) X(R7) X(R8) X(R9) X(R10) X(R11) X(R12) \
  X(SP) X(LR) X(PC)

#define X(NAME) NAME,
namespace reg { enum reg_e : u8 { REGISTER_X_LIST() }; }
#undef X

char const *reg_name(unsigned reg);

// Immediate Shift

#define SHIFT_X_LIST() X(LSL) X(LSR) X(ASR) X(RRX) X(ROR)

#define X(NAME) NAME,
enum class imm_shift_type : u8 { SHIFT_X_LIST() };
#undef X

struct imm_shift { imm_shift_type t; u8 n; };

// Instructions

#define INST_TYPE_X_LIST() \
  X(UNKNOWN, unknown, {}) \
  X(ADD_CARRY_IMM, add_carry_imm, { u32 imm; u8 d, n; }) \
  X(ADD_CARRY_REG, add_carry_reg, { imm_shift shift; u8 d, n, m; }) \
  X(ADD_IMM, add_imm, { u32 imm; u8 d, n; }) \
  X(ADD_SP_IMM, add_sp_imm, { u16 imm; u8 d; }) \
  X(ADD_SP_REG, add_sp_reg, { imm_shift shift; u8 d, m; }) \
  X(ADD_REG, add_reg, { imm_shift shift; u8 d, n, m; }) \
  X(ADD_8_UNSIGNED, add_8_unsigned, { u8 d, n, m; }) \
  X(ADR, adr, { u8 d, imm, add; }) \
  X(AND_REG, and_reg, { imm_shift shift; u8 d, n, m; }) \
  X(AND_IMM, and_imm, { u32 imm; u8 d, n; }) \
  X(BIT_CLEAR_IMM, bit_clear_imm, { u32 imm; u8 d, n; }) \
  X(BIT_CLEAR_REG, bit_clear_reg, { imm_shift shift; u8 d, n, m; }) \
  X(BITFIELD_CLEAR, bitfield_clear, { u8 d, msbit, lsbit; }) \
  X(BITFIELD_EXTRACT_UNSIGNED, bitfield_extract_unsigned, { u8 d, n, lsbit, widthminus1; }) \
  X(BITFIELD_EXTRACT_SIGNED, bitfield_extract_signed, { u8 d, n, lsbit, widthminus1; }) \
  X(BITFIELD_INSERT, bitfield_insert, { u8 d, n, msbit, lsbit; }) \
  X(BRANCH, branch, { u32 imm; u32 addr; cond_code cc; }) \
  X(BRANCH_LINK, branch_link, { u32 imm, addr; }) \
  X(BRANCH_LINK_XCHG_REG, branch_link_xchg_reg, { u8 reg; }) \
  X(BRANCH_XCHG, branch_xchg, { u8 m; }) \
  X(BREAKPOINT, breakpoint, { u16 imm; }) \
  X(BYTE_REV_PACKED_HALF, byte_rev_packed_half, { u8 d, m; }) \
  X(BYTE_REV_SIGNED_HALF, byte_rev_signed_half, { u8 d, m; }) \
  X(BYTE_REV_WORD, byte_rev_word, { u8 d, m; }) \
  X(CBNZ, cmp_branch_nz, { u32 addr; u8 n, imm; }) \
  X(CBZ, cmp_branch_z, { u32 addr; u8 n, imm; }) \
  X(CHANGE_PROC_STATE, change_proc_state, { u8 en, dis, cm, aff_a, aff_i, aff_f; }) \
  X(CMP_IMM, cmp_imm, { u32 imm; u8 n; }) \
  X(CMP_NEG_IMM, cmp_neg_imm, { u32 imm; u8 n; }) \
  X(CMP_REG, cmp_reg, { imm_shift shift; u8 n, m; }) \
  X(COUNT_LEADING_ZEROS, count_leading_zeros, { u8 d, m; }) \
  X(DIV_SIGNED, div_signed, { u8 d, n, m; }) \
  X(DIV_UNSIGNED, div_unsigned, { u8 d, n, m; }) \
  X(EXCL_OR_IMM, excl_or_imm, { u32 imm; u8 d, n; }) \
  X(EXCL_OR_REG, excl_or_reg, { imm_shift shift; u8 d, n, m; }) \
  X(EXTEND_ADD_SIGNED_BYTE, extend_add_signed_byte, { u8 d, n, m, rotation; }) \
  X(EXTEND_ADD_SIGNED_HALF, extend_add_signed_half, { u8 d, n, m, rotation; }) \
  X(EXTEND_SIGNED_BYTE, extend_signed_byte, { u8 d, m, rotation; }) \
  X(EXTEND_SIGNED_HALF, extend_signed_half, { u8 d, m, rotation; }) \
  X(EXTEND_UNSIGNED_BYTE, extend_unsigned_byte, { u8 d, m, rotation; }) \
  X(EXTEND_UNSIGNED_HALF, extend_unsigned_half, { u8 d, m, rotation; }) \
  X(EXTEND_UNSIGNED_HALF_ADD, extend_unsigned_half_add, { u8 d, n, m, rotation; }) \
  X(IF_THEN, if_then, { u8 firstcond, mask, cnt; }) \
  X(LOAD_BYTE_IMM, load_byte_imm, { u16 imm; u8 t, n, add, index; }) \
  X(LOAD_BYTE_LIT, load_byte_lit, { u16 imm; u8 t, add; }) \
  X(LOAD_BYTE_REG, load_byte_reg, { imm_shift shift; u8 t, n, m; }) \
  X(LOAD_DBL_REG, load_dbl_reg, { u16 imm; u8 t, t2, n, index, add; }) \
  X(LOAD_EXCL, load_excl, { u16 imm; u8 t, n; }) \
  X(LOAD_HALF_IMM, load_half_imm, { u16 imm; u8 t, n, add, index; }) \
  X(LOAD_HALF_REG, load_half_reg, { imm_shift shift; u8 t, n, m; }) \
  X(LOAD_SIGNED_BYTE_IMM, load_signed_byte_imm, { u16 imm; u8 t, n, index, add; }) \
  X(LOAD_SIGNED_BYTE_REG, load_signed_byte_reg, { imm_shift shift; u8 t, n, m; }) \
  X(LOAD_SIGNED_HALF_IMM, load_signed_half_imm, { u16 imm; u8 t, n, index, add; }) \
  X(LOAD_SIGNED_HALF_REG, load_signed_half_reg, { imm_shift shift; u8 t, n, m; }) \
  X(LOAD_IMM, load_imm, { u16 imm; u8 n, t, add, index; }) \
  X(LOAD_LIT, load_lit, { u32 imm, addr; u8 t, add; }) \
  X(LOAD_MULT_DEC_BEFORE, load_mult_dec_before, { u16 regs; u8 n, wback; }) \
  X(LOAD_MULT_INC_AFTER, load_mult_inc_after, { u16 regs; u8 n, wback; }) \
  X(LOAD_REG, load_reg, { imm_shift shift; u8 t, n, m; }) \
  X(LSHIFT_LOG_IMM, lshift_log_imm, { imm_shift shift; u8 d, m; }) \
  X(LSHIFT_LOG_REG, lshift_log_reg, { u8 d, n, m; }) \
  X(MOV_REG, mov_reg, { u8 d, m; }) \
  X(MOV_IMM, mov_imm, { u32 imm; u8 d; }) \
  X(MOV_NEG_IMM, mov_neg_imm, { u32 imm; u8 d; }) \
  X(MOV_NEG_REG, mov_neg_reg, { imm_shift shift; u8 d, m; }) \
  X(MUL, mul, { u8 d, n, m; }) \
  X(MUL_ACCUM, mul_accum, { u8 d, n, m, a; }) \
  X(MUL_ACCUM_SIGNED_HALF, mul_accum_signed_half, { u8 d, n, m, a, n_high, m_high; }) \
  X(MUL_ACCUM_SIGNED_LONG, mul_accum_signed_long, { u8 dlo, dhi, n, m; }) \
  X(MUL_ACCUM_UNSIGNED_LONG, mul_accum_unsigned_long, { u8 dlo, dhi, n, m; }) \
  X(MUL_SUB, mul_sub, { u8 d, n, m, a; }) \
  X(MUL_UNSIGNED_LONG, mul_unsigned_long, { u8 dlo, dhi, n, m; }) \
  X(NOP, nop, {}) \
  X(OR_NOT_REG, or_not_reg, { imm_shift shift; u8 d, n, m; }) \
  X(OR_IMM, or_imm, { u32 imm; u8 d, n; }) \
  X(OR_REG, or_reg, { imm_shift shift; u8 d, n, m; }) \
  X(PACK_HALF, pack_half, { imm_shift shift; u8 d, n, m, tbform; }) \
  X(PUSH, push, { u16 reg_list; }) \
  X(POP, pop, { u16 reg_list; }) \
  X(REVERSE_BITS, reverse_bits, { u8 d, m; }) \
  X(RSHIFT_ARITH_IMM, rshift_arith_imm, { imm_shift shift; u8 d, m; }) \
  X(RSHIFT_ARITH_REG, rshift_arith_reg, { u8 d, n, m; }) \
  X(RSHIFT_LOG_IMM, rshift_log_imm, { imm_shift shift; u8 d, m; }) \
  X(RSHIFT_LOG_REG, rshift_log_reg, { u8 d, n, m; }) \
  X(SATURATE_UNSIGNED, saturate_unsigned, { imm_shift shift; u8 d, n, saturate_to; }) \
  X(SELECT_BYTES, select_bytes, { u8 d, n, m; }) \
  X(STORE_BYTE_IMM, store_byte_imm, { u16 imm; u8 n, t, index, add; }) \
  X(STORE_BYTE_REG, store_byte_reg, { imm_shift shift; u8 t, m, n; }) \
  X(STORE_BYTE_UNPRIV, store_byte_unpriv, { u16 imm; u8 t, n; }) \
  X(STORE_DOUBLE_IMM, store_double_imm, { u16 imm; u8 t, t2, n, add, index; }) \
  X(STORE_EXCL, store_excl, { u16 imm; u8 d, t, n; }) \
  X(STORE_HALF_IMM, store_half_imm, { u16 imm; u8 t, n, index, add; }) \
  X(STORE_HALF_REG, store_half_reg, { imm_shift shift; u8 t, n, m; }) \
  X(STORE_IMM, store_imm, { u16 imm; u8 t, n; }) \
  X(STORE_MULT_DEC_BEFORE, store_mult_dec_before, { u16 regs; u8 n; }) \
  X(STORE_MULT_INC_AFTER, store_mult_inc_after, { u16 regs; u8 n, wback; }) \
  X(STORE_REG, store_reg, { imm_shift shift; u8 t, n, m; }) \
  X(SUB_IMM, sub_imm, { u32 imm; u8 d, n; }) \
  X(SUB_IMM_CARRY, sub_imm_carry, { u32 imm; u8 d, n; }) \
  X(SUB_REG, sub_reg, { imm_shift shift; u8 d, n, m; }) \
  X(SUB_REG_CARRY, sub_reg_carry, { imm_shift shift; u8 d, n, m; }) \
  X(SUB_REV_IMM, sub_rev_imm, { u32 imm; u8 d, n; }) \
  X(SUB_REV_REG, sub_rev_reg, { imm_shift shift; u8 d, n, m; }) \
  X(SUB_SP_IMM, sub_sp_imm, { u32 imm; u8 d; }) \
  X(SVC, svc, { u32 imm; }) \
  X(TABLE_BRANCH_BYTE, table_branch_byte, { u8 n, m; }) \
  X(TABLE_BRANCH_HALF, table_branch_half, { u8 n, m; }) \
  X(TEST_EQUIV_IMM, test_equiv_imm, { u32 imm; u8 n; }) \
  X(TEST_EQUIV_REG, test_equiv_reg, { imm_shift shift; u8 n, m; }) \
  X(TEST_REG, test_reg, { imm_shift shift; u8 n, m; }) \
  X(VADD, vadd, { u8 d, n, m; }) \
  X(VCOMPARE, vcompare, { u8 quiet_nan_exc, with_zero, d, m; }) \
  X(VCONVERT_FP_INT, vconvert_fp_int, { u8 d, m, to_int, int_unsigned, round_zero; }) \
  X(VDIV, vdiv, { u8 d, n, m; }) \
  X(VMULT_ACCUM, vmult_accum, { u8 op1_neg, d, n, m; }) \
  X(VLOAD, vload, { u16 imm; u8 single_reg, add, n, d; }) \
  X(VLOAD_MULT, vload_mult, { u32 imm; u8 d, n, wback, regs, single_regs, add; }) \
  X(VMOV_IMM, vmov_imm, { float imm; u8 d, regs; }) \
  X(VMOV_REG, vmov_reg, { u8 d, m; }) \
  X(VMOV_REG_DOUBLE, vmov_reg_double, { u8 t, t2, m, to_arm_regs; }) \
  X(VMOV_REG_SINGLE, vmov_reg_single, { u8 t, n, to_arm_reg; }) \
  X(VMOV_SPECIAL_FROM, vmov_special_from, { u8 t; }) \
  X(VMOV_SPECIAL_TO, vmov_special_to, { u8 t; }) \
  X(VMUL, vmul, { u8 d, n, m; }) \
  X(VNEG, vneg, { u8 d, m; }) \
  X(VPOP, vpop, { u16 imm; u8 d, single_regs, regs; }) \
  X(VPUSH, vpush, { u16 imm; u8 d, single_regs, regs; }) \
  X(VSTORE, vstore, { u16 imm; u8 single_reg, add, d, n; }) \
  X(VSTORE_MULT, vstore_mult, { u16 imm; u8 n, d, list, wb, single_regs, add; }) \
  X(VSUB, vsub, { u8 d, n, m; }) \
  X(VSQRT, vsqrt, { u8 d, m; })

#define X(ENUM, TYPE, ...) ENUM,
enum class inst_type : u8 { INST_TYPE_X_LIST() };
#undef X

#define X(ENUM, TYPE, ...) struct inst_##TYPE __VA_ARGS__;
INST_TYPE_X_LIST()
#undef X

struct inst {
  u32 addr;
  u16 w0, w1;
#define X(ENUM, TYPE, ...) inst_##TYPE TYPE;
  union { INST_TYPE_X_LIST() } i;
#undef X
  inst_type type;
  u8 len; // 2 or 4
};

bool inst_is_unconditional_branch(inst const& i, u32& label);
u32 inst_align(u32 val, u32 align);
bool inst_decode(byte const *text, u32 func_addr, u32 pc_addr, inst& out_inst);
void inst_print(inst const& i);
