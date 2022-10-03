#pragma once

#include "nl_types.h"

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

// Immediate Shift

#define SHIFT_X_LIST() X(LSL) X(LSR) X(ASR) X(RRX) X(ROR)

#define X(NAME) NAME,
enum class imm_shift_type : u8 { SHIFT_X_LIST() };
#undef X

struct imm_shift { imm_shift_type t; u8 n; };

// Instructions

#define INST_TYPE_X_LIST() \
  X(UNKNOWN, unknown) \
  X(ADD_CARRY_IMM, add_carry_imm) \
  X(ADD_CARRY_REG, add_carry_reg) \
  X(ADD_IMM, add_imm) \
  X(ADD_SP_IMM, add_sp_imm) \
  X(ADD_SP_REG, add_sp_reg) \
  X(ADD_REG, add_reg) \
  X(ADR, adr) \
  X(AND_REG, and_reg) \
  X(AND_IMM, and_imm) \
  X(BIT_CLEAR_IMM, bit_clear_imm) \
  X(BIT_CLEAR_REG, bit_clear_reg) \
  X(BITFIELD_EXTRACT_UNSIGNED, bitfield_extract_unsigned) \
  X(BITFIELD_EXTRACT_SIGNED, bitfield_extract_signed) \
  X(BITFIELD_INSERT, bitfield_insert) \
  X(BRANCH, branch) \
  X(BRANCH_LINK, branch_link) \
  X(BRANCH_LINK_XCHG_REG, branch_link_xchg_reg) \
  X(BRANCH_XCHG, branch_xchg) \
  X(BYTE_REV_PACKED_HALF, byte_rev_packed_half) \
  X(CBNZ, cmp_branch_nz) \
  X(CBZ, cmp_branch_z) \
  X(CHANGE_PROC_STATE, change_proc_state) \
  X(CMP_IMM, cmp_imm) \
  X(CMP_NEG_IMM, cmp_neg_imm) \
  X(CMP_REG, cmp_reg) \
  X(COUNT_LEADING_ZEROS, count_leading_zeros) \
  X(DIV_SIGNED, div_signed) \
  X(DIV_UNSIGNED, div_unsigned) \
  X(EXCL_OR_IMM, excl_or_imm) \
  X(EXCL_OR_REG, excl_or_reg) \
  X(EXTEND_SIGNED_BYTE, extend_signed_byte) \
  X(EXTEND_UNSIGNED_BYTE, extend_unsigned_byte) \
  X(EXTEND_UNSIGNED_HALF, extend_unsigned_half) \
  X(IF_THEN, if_then) \
  X(LOAD_BYTE_IMM, load_byte_imm) \
  X(LOAD_BYTE_LIT, load_byte_lit) \
  X(LOAD_BYTE_REG, load_byte_reg) \
  X(LOAD_DBL_REG, load_dbl_reg) \
  X(LOAD_EXCL, load_excl) \
  X(LOAD_HALF_IMM, load_half_imm) \
  X(LOAD_HALF_REG, load_half_reg) \
  X(LOAD_SIGNED_BYTE_IMM, load_signed_byte_imm) \
  X(LOAD_SIGNED_HALF_IMM, load_signed_half_imm) \
  X(LOAD_SIGNED_HALF_REG, load_signed_half_reg) \
  X(LOAD_IMM, load_imm) \
  X(LOAD_LIT, load_lit) \
  X(LOAD_MULT_INC_AFTER, load_mult_inc_after) \
  X(LOAD_REG, load_reg) \
  X(LSHIFT_LOG_IMM, lshift_log_imm) \
  X(LSHIFT_LOG_REG, lshift_log_reg) \
  X(MOV, mov) \
  X(MOV_IMM, mov_imm) \
  X(MOV_NEG_IMM, mov_neg_imm) \
  X(MOV_NEV_REG, mov_neg_reg) \
  X(MUL, mul) \
  X(MUL_ACCUM, mul_accum) \
  X(MUL_ACCUM_SIGNED_LONG, mul_accum_signed_long) \
  X(MUL_SUB, mul_sub) \
  X(NOP, nop) \
  X(OR_REG_IMM, or_reg_imm) \
  X(OR_REG_REG, or_reg_reg) \
  X(PUSH, push) \
  X(POP, pop) \
  X(REVERSE_BITS, reverse_bits) \
  X(RSHIFT_ARITH_IMM, rshift_arith_imm) \
  X(RSHIFT_LOG_IMM, rshift_log_imm) \
  X(RSHIFT_LOG_REG, rshift_log_reg) \
  X(STORE_BYTE_IMM, store_byte_imm) \
  X(STORE_EXCL, store_excl) \
  X(STORE_HALF_IMM, store_half_imm) \
  X(STORE_IMM, store_imm) \
  X(STORE_MULT_DEC_BEF, store_mult_dec_bef) \
  X(STORE_MULT_INC_AFTER, store_mult_inc_after) \
  X(STORE_REG, store_reg) \
  X(STORE_REG_BYTE_IMM, store_reg_byte_imm) \
  X(STORE_REG_BYTE_REG, store_reg_byte_reg) \
  X(STORE_REG_BYTE_UNPRIV, store_reg_byte_unpriv) \
  X(STORE_REG_HALF_REG, store_reg_half_reg) \
  X(STORE_REG_DOUBLE_IMM, store_reg_double_imm) \
  X(SUB_IMM, sub_imm) \
  X(SUB_IMM_CARRY, sub_imm_carry) \
  X(SUB_REG, sub_reg) \
  X(SUB_REG_CARRY, sub_reg_carry) \
  X(SUB_REV_IMM, sub_rev_imm) \
  X(SUB_SP_IMM, sub_sp_imm) \
  X(SVC, svc) \
  X(TABLE_BRANCH_BYTE, table_branch_byte) \
  X(TEST_EQUIV, test_equiv) \
  X(TEST_REG, test_reg) \
  X(VCONVERT_FP_INT, vconvert_fp_int) \
  X(VMOV_SINGLE, vmov_single) \
  X(VMOV_DOUBLE, vmov_double)

#define X(ENUM, TYPE) ENUM,
enum class inst_type : u8 { INST_TYPE_X_LIST() };
#undef X

struct inst_unknown {};
struct inst_add_carry_imm { u32 imm; u8 d, n; };
struct inst_add_carry_reg { imm_shift shift; u8 d, n, m; };
struct inst_add_imm { u32 imm; u8 d, n; };
struct inst_add_sp_imm { u16 imm; u8 d; };
struct inst_add_sp_reg { imm_shift shift; u8 d, m; };
struct inst_add_reg { imm_shift shift; u8 d, n, m; };
struct inst_adr { u8 dst_reg, imm; };
struct inst_and_reg { imm_shift shift; u8 d, n, m; };
struct inst_and_imm { u32 imm; u8 d, n; };
struct inst_bit_clear_imm { u32 imm; u8 d, n; };
struct inst_bit_clear_reg { imm_shift shift; u8 d, n, m; };
struct inst_bitfield_extract_signed { u8 d, n, lsbit, widthminus1; };
struct inst_bitfield_extract_unsigned { u8 d, n, lsbit, widthminus1; };
struct inst_bitfield_insert { u8 d, n, msbit, lsbit; };
struct inst_branch { u32 imm; u32 addr; cond_code cc; };
struct inst_branch_link { u32 imm, addr; };
struct inst_branch_link_xchg_reg { u8 reg; };
struct inst_branch_xchg { u8 m; };
struct inst_byte_rev_packed_half { u8 d, m; };
struct inst_cmp_branch_nz { u32 addr; u8 n, imm; };
struct inst_cmp_branch_z { u32 addr; u8 n, imm; };
struct inst_change_proc_state { u8 enable, disable, changemode, aff_a, aff_i, aff_f; };
struct inst_cmp_imm { u32 imm; u8 n; };
struct inst_cmp_neg_imm { u32 imm; u8 n; };
struct inst_cmp_reg { imm_shift shift; u8 n, m; };
struct inst_count_leading_zeros { u8 d, m; };
struct inst_div_signed { u8 d, n, m; };
struct inst_div_unsigned { u8 d, n, m; };
struct inst_excl_or_imm { u32 imm; u8 d, n; };
struct inst_excl_or_reg { imm_shift shift; u8 d, n, m; };
struct inst_extend_signed_byte { u8 d, m, rotation; };
struct inst_extend_unsigned_byte { u8 d, m, rotation; };
struct inst_extend_unsigned_half { u8 d, m, rotation; };
struct inst_if_then { u8 firstcond, mask; };
struct inst_load_byte_imm { u16 imm; u8 t, n, add, index; };
struct inst_load_byte_lit { u16 imm; u8 t, add; };
struct inst_load_byte_reg { imm_shift shift; u8 t, n, m; };
struct inst_load_dbl_reg { u16 imm; u8 t, t2, n, index, add; };
struct inst_load_excl { u16 imm; u8 t, n; };
struct inst_load_half_imm { u16 imm; u8 t, n, add, index; };
struct inst_load_half_reg { imm_shift shift; u8 t, n, m; };
struct inst_load_imm { u16 imm; u8 n, t, add, index; };
struct inst_load_lit { u32 imm, addr; u8 t, add; };
struct inst_load_mult_inc_after { u16 regs; u8 n, wback; };
struct inst_load_reg { imm_shift shift; u8 t, n, m; };
struct inst_load_signed_byte_imm { u16 imm; u8 t, n, index, add; };
struct inst_load_signed_half_imm { u16 imm; u8 t, n, index, add; };
struct inst_load_signed_half_reg { imm_shift shift; u8 t, n, m; };
struct inst_lshift_log_imm { imm_shift shift; u8 d, m; };
struct inst_lshift_log_reg { imm_shift shift; u8 d, n, m; };
struct inst_mov { u8 d, m; };
struct inst_mov_imm { u32 imm; u8 d; };
struct inst_mov_neg_imm { u32 imm; u8 d; };
struct inst_mov_neg_reg { imm_shift shift; u8 d, m; };
struct inst_mul { u8 d, n, m; };
struct inst_mul_accum { u8 d, n, m, a; };
struct inst_mul_accum_signed_long { u8 dlo, dhi, n, m; };
struct inst_mul_sub { u8 d, n, m, a; };
struct inst_or_reg_imm { u32 imm; u8 d, n; };
struct inst_or_reg_reg { u32 imm; imm_shift shift; u8 d, n, m; };
struct inst_push { u16 reg_list; };
struct inst_pop { u16 reg_list; };
struct inst_nop {};
struct inst_reverse_bits { u8 d, m; };
struct inst_rshift_log_imm { imm_shift shift; u8 d, m; };
struct inst_rshift_log_reg { u8 d, n, m; };
struct inst_rshift_arith_imm { imm_shift shift; u8 dst_reg, src_reg; };
struct inst_store_byte_imm { u16 imm; u8 t, n, add; };
struct inst_store_excl { u16 imm; u8 d, t, n; };
struct inst_store_imm { u8 t, n; u16 imm; };
struct inst_store_half_imm { u16 imm; u8 t, n, index, add; };
struct inst_store_mult_dec_bef { u16 regs; u8 n; };
struct inst_store_mult_inc_after { u16 regs; u8 n, wback; };
struct inst_store_reg { imm_shift shift; u8 t, n, m; };
struct inst_store_reg_byte_imm { u16 imm; u8 n, t, index, add; };
struct inst_store_reg_byte_reg { imm_shift shift; u8 t, m, n; };
struct inst_store_reg_byte_unpriv { u16 imm; u8 t, n; };
struct inst_store_reg_half_reg { imm_shift shift; u8 t, n, m; };
struct inst_store_reg_double_imm { u16 imm; u8 t, t2, n, add, index; };
struct inst_sub_imm { u32 imm; u8 d, n; };
struct inst_sub_imm_carry { u32 imm; u8 d, n; };
struct inst_sub_reg { imm_shift shift; u8 d, n, m; };
struct inst_sub_reg_carry { imm_shift shift; u8 d, n, m; };
struct inst_sub_rev_imm { u32 imm; u8 d, n; };
struct inst_sub_sp_imm { u32 imm; u8 d; };
struct inst_svc { u32 imm; };
struct inst_table_branch_byte { u8 n, m; };
struct inst_test_equiv { u32 imm; u8 n; };
struct inst_test_reg { imm_shift shift; u8 n, m; };
struct inst_vconvert_fp_int { u8 d, m, to_int, int_unsigned, round_zero; };
struct inst_vmov_double { u8 t, t2, m, to_arm_regs; };
struct inst_vmov_single { u8 t, n, to_arm_reg; };

struct inst {
  u32 addr;
  u16 w0, w1;
#define X(ENUM, TYPE) inst_##TYPE TYPE;
  union { INST_TYPE_X_LIST() } i;
#undef X
  inst_type type;
  u8 len; // 2 or 4
};

bool inst_is_conditional_branch(inst const& i, u32& target);
bool inst_is_unconditional_branch(inst const& i, u32& label);
bool inst_is_goto(inst const& i, u32& label);
u32 inst_align(u32 val, u32 align);
bool inst_decode(char const *text, u32 func_addr, u32 pc_addr, inst& out_inst);
void inst_print(inst const& i);
