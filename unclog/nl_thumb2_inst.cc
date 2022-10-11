#include "nl_thumb2_inst.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace {

char const *cond_code_name(cond_code cc) {
#define X(NAME, VAL) case cond_code::NAME: return #NAME;
  switch (cc) { CONDITION_CODE_X_LIST() }
#undef X
  return "unknown";
}

#define X(NAME) #NAME,
char const *s_rn[] = { REGISTER_X_LIST() };
#undef X

#define X(NAME) #NAME,
char const *s_sn[] = { SHIFT_X_LIST() };
#undef X

void print(inst_unknown const&) { NL_LOG_DBG("??"); }

void print(inst_add_carry_imm const& a) {
  NL_LOG_DBG("ADC_IMM %s, %s, #%d", s_rn[a.d], s_rn[a.n], int(a.imm));
}

void print(inst_add_carry_reg const& a) {
  NL_LOG_DBG("ADC_REG %s, %s, %s <%s #%d>", s_rn[a.d], s_rn[a.n], s_rn[a.m],
    s_sn[int(a.shift.t)], int(a.shift.n));
}

void print(inst_add_imm const& a) {
  NL_LOG_DBG("ADD_IMM %s, %s, #%d", s_rn[a.d], s_rn[a.n], int(a.imm));
}

void print(inst_add_sp_imm const& a) {
  NL_LOG_DBG("ADD %s, [%s, #%d]", s_rn[a.d], s_rn[reg::SP], (int)a.imm);
}

void print(inst_add_sp_reg const& a) {
  NL_LOG_DBG("ADD %s, %s, %s <%s, #%d>", s_rn[a.d], s_rn[reg::SP], s_rn[a.m],
    s_sn[int(a.shift.t)], int(a.shift.n));
}

void print(inst_add_reg const& a) {
  NL_LOG_DBG("ADD_REG %s, %s, %s <%s #%d>", s_rn[a.d], s_rn[a.n], s_rn[a.m],
    s_sn[int(a.shift.t)], int(a.shift.n));
}

void print(inst_add_8_unsigned const& a) {
  NL_LOG_DBG("UADD8 %s, %s, %s", s_rn[a.d], s_rn[a.n], s_rn[a.m]);
}

void print(inst_adr const& a) {
  NL_LOG_DBG("ADR %s, PC, #%d", s_rn[a.dst_reg], (int)a.imm);
}

void print(inst_and_reg const& a) {
  NL_LOG_DBG("AND_REG %s, %s, %s <%s #%d>", s_rn[a.d], s_rn[a.n], s_rn[a.m],
    s_sn[int(a.shift.t)], int(a.shift.n));
}

void print(inst_and_imm const& a) {
  NL_LOG_DBG("AND_IMM %s, %s, #%d", s_rn[a.d], s_rn[a.n], int(a.imm));
}

void print(inst_pack_half const& p) {
  NL_LOG_DBG("PKH%s %s, %s, %s, %s #%d", p.tbform ? "TB" : "BT", s_rn[p.d], s_rn[p.n],
    s_rn[p.m], s_sn[int(p.shift.t)], int(p.shift.n));
}

void print(inst_push const& p) {
  NL_LOG_DBG("PUSH { ");
  for (int i = 0; i < 16; ++i) { if (p.reg_list & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_pop const& p) {
  NL_LOG_DBG("POP { ");
  for (int i = 0; i < 16; ++i) { if (p.reg_list & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_nop const&) { NL_LOG_DBG("NOP"); }
void print(inst_reverse_bits const& r) { NL_LOG_DBG("RBIT %s, %s", s_rn[r.d], s_rn[r.m]); }

void print(inst_rshift_log_imm const& r) {
  NL_LOG_DBG("LSR_IMM %s, %s, #%d", s_rn[r.d], s_rn[r.m], int(r.shift.n));
}

void print(inst_rshift_log_reg const& r) {
  NL_LOG_DBG("LSR_REG %s, %s, %s", s_rn[r.d], s_rn[r.m], s_rn[r.n]);
}

void print(inst_rshift_arith_imm const& r) {
  NL_LOG_DBG("ASR %s, %s, #%d", s_rn[r.d], s_rn[r.m], int(r.shift.n));
}

void print(inst_bit_clear_imm const& b) {
  NL_LOG_DBG("BIC_IMM %s, %s, #%d", s_rn[b.d], s_rn[b.n], int(b.imm));
}

void print(inst_bit_clear_reg const& b) {
  NL_LOG_DBG("BIC_REG %s, %s, %s, <%s #%d>", s_rn[b.d], s_rn[b.n], s_rn[b.m],
    s_sn[int(b.shift.t)], int(b.shift.n));
}

void print(inst_bitfield_extract_signed const& b) {
  NL_LOG_DBG("SBFX %s, %s, #%d, #%d", s_rn[b.d], s_rn[b.n], int(b.lsbit),
    int(b.widthminus1 + 1));
}

void print(inst_bitfield_extract_unsigned const& b) {
  NL_LOG_DBG("UBFX %s, %s, #%d, #%d", s_rn[b.d], s_rn[b.n], int(b.lsbit),
    int(b.widthminus1 + 1));
}

void print(inst_bitfield_insert const& b) {
  NL_LOG_DBG("BFI %s, %s, #%d, #%d", s_rn[b.d], s_rn[b.n], int(b.lsbit),
    int(b.msbit - b.lsbit));
}

void print(inst_branch const& i) {
  NL_LOG_DBG("B%s #%d (%x)", i.cc >= cond_code::AL1 ? "" : cond_code_name(i.cc),
    int(i32(i.imm)), unsigned(i.addr));
}

void print(inst_branch_link const& i) {
  NL_LOG_DBG("BL #%d (%x)", unsigned(i.imm), unsigned(i.addr));
}

void print(inst_branch_link_xchg_reg const& b) { NL_LOG_DBG("BLX %s", s_rn[b.reg]); }
void print(inst_branch_xchg const& i) { NL_LOG_DBG("BX %s", s_rn[int(i.m)]); }
void print(inst_breakpoint const& b) { NL_LOG_DBG("BKPT 0x%04hx", b.imm); }

void print(inst_byte_rev_packed_half const& b) {
  NL_LOG_DBG("REV16 %s, %s", s_rn[b.d], s_rn[b.m]);
}

void print(inst_byte_rev_word const& b) { NL_LOG_DBG("REV %s, %s", s_rn[b.d], s_rn[b.m]); }

void print(inst_cmp_branch_nz const& c) {
  NL_LOG_DBG("CBNZ %s, #%d (%x)", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
}

void print(inst_cmp_branch_z const& c) {
  NL_LOG_DBG("CBZ %s, #%d (%x)", s_rn[c.n], unsigned(c.imm), unsigned(c.addr));
}

void print(inst_change_proc_state const& c) {
  NL_LOG_DBG("CPS%s %s%s%s", c.en ? "IE" : (c.dis ? "ID" : ""),
    c.aff_a ? "A" : "", c.aff_f ? "F" : "", c.aff_i ? "I" : "");
}

void print(inst_cmp_imm const& c) { NL_LOG_DBG("CMP_IMM %s, #%d", s_rn[c.n], int(c.imm)); }
void print(inst_cmp_neg_imm const& c) { NL_LOG_DBG("CMN_IMM %s, #%d", s_rn[c.n], int(c.imm)); }

void print(inst_cmp_reg const& c) {
  NL_LOG_DBG("CMP_REG %s, %s <%s #%d>", s_rn[c.n], s_rn[c.m], s_sn[int(c.shift.t)],
    int(c.shift.n));
}

void print(inst_if_then const& i) {
  NL_LOG_DBG("IT %x, %x", unsigned(i.firstcond), unsigned(i.mask));
}

void print(inst_count_leading_zeros const& c) {
  NL_LOG_DBG("CLZ %s, %s", s_rn[c.d], s_rn[c.m]);
}

void print(inst_div_signed const& d) {
  NL_LOG_DBG("SDIV %s, %s, %s", s_rn[d.d], s_rn[d.n], s_rn[d.m]);
}

void print(inst_div_unsigned const& d) {
  NL_LOG_DBG("UDIV %s, %s, %s", s_rn[d.d], s_rn[d.n], s_rn[d.m]);
}

void print(inst_excl_or_imm const& e) {
  NL_LOG_DBG("EOR_IMM %s, %s, #%d", s_rn[e.d], s_rn[e.n], int(e.imm));
}

void print(inst_excl_or_reg const& e) {
  NL_LOG_DBG("EOR_REG %s, %s, %s, <%s #%d>", s_rn[e.d], s_rn[e.n], s_rn[e.m],
    s_sn[int(e.shift.t)], int(e.shift.n));
}

void print(inst_extend_unsigned_byte const& u) {
  NL_LOG_DBG("UXTB %s, %s, <%d>", s_rn[u.d], s_rn[u.m], int(u.rotation));
}

void print(inst_extend_unsigned_half const& u) {
  NL_LOG_DBG("UXTH %s, %s, <%d>", s_rn[u.d], s_rn[u.m], int(u.rotation));
}

void print(inst_extend_add_signed_byte const &e) {
  NL_LOG_DBG("SXTAB %s, %s, %s, <%d>", s_rn[e.d], s_rn[e.n], s_rn[e.m], int(e.rotation));
}

void print(inst_extend_signed_byte const& u) {
  NL_LOG_DBG("SXTB %s, %s, <%d>", s_rn[u.d], s_rn[u.m], int(u.rotation));
}

void print(inst_extend_signed_half const& e) {
  NL_LOG_DBG("SXTH %s, %s, <%d>", s_rn[e.d], s_rn[e.m], int(e.rotation));
}

void print(inst_load_byte_imm const& l) {
  NL_LOG_DBG("LDRB_IMM %s, [%s, #%d]", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_byte_lit const& l) {
  NL_LOG_DBG("LDRB_LIT %s, [%s, #%c%d]", s_rn[l.t], s_rn[reg::PC], l.add ? '+' : '-',
    int(l.imm));
}

void print(inst_load_byte_reg const& l) {
  NL_LOG_DBG("LDRB_REG %s, [%s, %s, %s #%d]", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_load_dbl_reg const& l) {
  NL_LOG_DBG("LDRD_REG %s, %s, [%s, #%s%d]", s_rn[l.t], s_rn[l.t2], s_rn[l.n],
    l.add ? "" : "-", int(l.imm));
}

void print(inst_load_excl const& l) {
  NL_LOG_DBG("LDREX %s, [%s, #%d]", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_imm const& l) {
  NL_LOG_DBG("LDR_IMM %s, [%s, #%d]", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_half_imm const& l) {
  NL_LOG_DBG("LDRH_IMM %s, [%s, #%d]", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_half_reg const& l) {
  NL_LOG_DBG("LDRH_REG %s, [%s, %s, %s #%d]", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_load_lit const& l) {
  NL_LOG_DBG("LDR_LIT %s, [PC, #%s%d] (%x)", s_rn[l.t], l.add ? "" : "-", int(l.imm),
    unsigned(l.addr));
}

void print(inst_load_mult_dec_before const& l) {
  NL_LOG_DBG("LDMDB %s%s, { ", s_rn[l.n], l.wback ? "!" : "");
  for (int i = 0; i < 16; ++i) { if (l.regs & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_load_mult_inc_after const& l) {
  NL_LOG_DBG("LDMIA %s%s, { ", s_rn[l.n], l.wback ? "!" : "");
  for (int i = 0; i < 16; ++i) { if (l.regs & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_load_reg const& l) {
  NL_LOG_DBG("LDR_REG %s, [%s, %s <%s #%d>]", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_load_signed_byte_imm const& l) {
  NL_LOG_DBG("LDRSB_IMM %s, [%s, #%d]", s_rn[l.t], s_rn[l.n], int(l.imm));
}

void print(inst_load_signed_byte_reg const& l) {
  NL_LOG_DBG("LDRSB_REG %s, [%s, %s, %s #%d]", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_load_signed_half_imm const& l) {
  NL_LOG_DBG("LDRSH_IMM %s, [%s, #%c%d]", s_rn[l.t], s_rn[l.n], l.add ? '+' : '-',
    int(l.imm));
}

void print(inst_load_signed_half_reg const& l) {
  NL_LOG_DBG("LDRSH_REG %s, [%s, %s, %s #%d]", s_rn[l.t], s_rn[l.n], s_rn[l.m],
    s_sn[int(l.shift.t)], int(l.shift.n));
}

void print(inst_lshift_log_imm const& l) {
  NL_LOG_DBG("LSL_IMM %s, %s, #%d", s_rn[l.d], s_rn[l.m], int(l.shift.n));
}

void print(inst_lshift_log_reg const& l) {
  NL_LOG_DBG("LSL_REG %s, %s, %s", s_rn[l.d], s_rn[l.n], s_rn[l.m]);
}

void print(inst_mov_reg const& m) { NL_LOG_DBG("MOV %s, %s", s_rn[m.d], s_rn[m.m]); }

void print(inst_mov_imm const& m) {
  NL_LOG_DBG("MOV_IMM %s, #%d (%#x)", s_rn[m.d], int(m.imm), unsigned(m.imm));
}

void print(inst_mov_neg_imm const& m) {
  NL_LOG_DBG("MOV_NEG_IMM %s, #%d (%#x)", s_rn[m.d], unsigned(m.imm), unsigned(m.imm));
}

void print(inst_mov_neg_reg const& m) {
  NL_LOG_DBG("MOV_NEG_REG %s, %s, %s #%d", s_rn[m.d], s_rn[m.m], s_sn[int(m.shift.t)],
    int(m.shift.n));
}

void print(inst_mul const& m) { NL_LOG_DBG("MUL %s, %s, %s", s_rn[m.d], s_rn[m.n], s_rn[m.m]); }

void print(inst_mul_accum const& m) {
  NL_LOG_DBG("MLA %s, %s, %s, %s", s_rn[m.d], s_rn[m.n], s_rn[m.m], s_rn[m.a]);
}

void print(inst_mul_accum_signed_long const& m) {
  NL_LOG_DBG("SMLAL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
}

void print(inst_mul_accum_unsigned_long const& m) {
  NL_LOG_DBG("UMLAL %s, %s, %s, %s", s_rn[m.dlo], s_rn[m.dhi], s_rn[m.n], s_rn[m.m]);
}

void print(inst_mul_sub const& m) {
  NL_LOG_DBG("MLS %s, %s, %s, %s", s_rn[m.d], s_rn[m.n], s_rn[m.m], s_rn[m.a]);
}

void print(inst_or_not_reg const& o) {
  NL_LOG_DBG("ORN_REG %s, %s, %s, %s #%d", s_rn[o.d], s_rn[o.n], s_rn[o.m],
    s_sn[int(o.shift.t)], int(o.shift.n));
}

void print(inst_or_imm const& o) {
  NL_LOG_DBG("ORR_IMM %s, %s, #%d", s_rn[o.d], s_rn[o.n], int(o.imm));
}

void print(inst_or_reg const& o) {
  NL_LOG_DBG("ORR_REG %s, %s, %s <%s #%d>", s_rn[o.d], s_rn[o.n], s_rn[o.m],
    s_sn[int(o.shift.t)], int(o.shift.n));
}

void print(inst_select_bytes const& s) {
  NL_LOG_DBG("SEL %s, %s, %s", s_rn[s.d], s_rn[s.n], s_rn[s.m]);
}

void print(inst_store_byte_imm const& s) {
  NL_LOG_DBG("STRB_IMM %s, [%s, #%c%d]", s_rn[s.t], s_rn[s.n], s.add ? '+' : '-',
    int(s.imm));
}

void print(inst_store_excl const& s) {
  NL_LOG_DBG("STREX %s, %s, [%s, #%d]", s_rn[s.d], s_rn[s.t], s_rn[s.n], int(s.imm));
}

void print(inst_store_half_imm const& s) {
  NL_LOG_DBG("STRH %s, [%s, #%c%d]", s_rn[s.t], s_rn[s.n], s.add ? '+' : '-', int(s.imm));
}

void print(inst_store_imm const& s) {
  NL_LOG_DBG("STR_IMM %s, [%s, #%d]", s_rn[s.t], s_rn[s.n], int(s.imm));
}

void print(inst_store_mult_dec_bef const& s) {
  NL_LOG_DBG("STMDB %s!, { ", s_rn[s.n]);
  for (int i = 0; i < 16; ++i) { if (s.regs & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_store_mult_inc_after const& s) {
  NL_LOG_DBG("STMIA %s%s, { ", s_rn[s.n], s.wback ? "!" : "");
  for (int i = 0; i < 16; ++i) { if (s.regs & (1 << i)) { NL_LOG_DBG("%s ", s_rn[i]); } }
  NL_LOG_DBG("}");
}

void print(inst_store_reg const& s) {
  NL_LOG_DBG("STR_REG %s, [%s, %s <%s #%d>", s_rn[s.t], s_rn[s.n], s_rn[s.m],
    s_sn[int(s.shift.t)], int(s.shift.n));
}

void print(inst_store_byte_reg const& s) {
  NL_LOG_DBG("STRB_REG %s, [%s, %s, %s #%d]", s_rn[s.t], s_rn[s.n], s_rn[s.m],
    s_sn[int(s.shift.t)], int(s.shift.n));
}

void print(inst_store_byte_unpriv const& s) {
  NL_LOG_DBG("STRBT %s, [%s, #%d]", s_rn[s.t], s_rn[s.n], int(s.imm));
}

void print(inst_store_half_reg const& s) {
  NL_LOG_DBG("STRH %s, [%s, %s, %s #%d]", s_rn[s.t], s_rn[s.n], s_rn[s.m], s_sn[int(s.shift.t)],
    int(s.shift.n));
}

void print(inst_store_double_imm const &s) {
  NL_LOG_DBG("STRD %s, %s, [%s], #%d", s_rn[s.t], s_rn[s.t2], s_rn[s.n], int(s.imm));
}

void print(inst_sub_imm const& s) {
  NL_LOG_DBG("SUB_IMM %s, %s, #%d", s_rn[s.d], s_rn[s.n], int(s.imm));
}

void print(inst_sub_sp_imm const& s) {
  NL_LOG_DBG("SUB_IMM %s, %s, #%d", s_rn[s.d], s_rn[reg::SP], int(s.imm));
}

void print(inst_sub_imm_carry const &s) {
  NL_LOG_DBG("SUB_IMM_CARRY %s, %s, #%d", s_rn[s.d], s_rn[s.n], int(s.imm));
}

void print(inst_sub_reg const& s) {
  NL_LOG_DBG("SUB_REG %s, %s, %s <%s #%u>", s_rn[s.d], s_rn[s.n], s_rn[s.m],
    s_sn[int(s.shift.t)], unsigned(s.shift.n));
}

void print(inst_sub_reg_carry const& s) {
  NL_LOG_DBG("SUB_REG_CARRY %s, %s, %s <%s #%u>", s_rn[s.d], s_rn[s.n],
    s_rn[s.m], s_sn[int(s.shift.t)], unsigned(s.shift.n));
}

void print(inst_sub_rev_imm const& s) {
  NL_LOG_DBG("RSB_IMM %s, %s, #%d", s_rn[s.d], s_rn[s.n], int(s.imm));
}

void print(inst_sub_rev_reg const& s) {
  NL_LOG_DBG("RSB_REG %s, %s, %s, %s #%d", s_rn[s.d], s_rn[s.n], s_rn[s.m],
    s_sn[int(s.shift.t)], int(s.shift.n));
}

void print(inst_svc const& s) { NL_LOG_DBG("SVC %x", unsigned(s.imm)); }

void print(inst_table_branch_byte const& t) {
  NL_LOG_DBG("TBB [%s, %s]", s_rn[t.n], s_rn[t.m]);
}

void print(inst_table_branch_half const& t) {
  NL_LOG_DBG("TBH [%s, %s]", s_rn[t.n], s_rn[t.m]);
}

void print(inst_test_equiv_imm const& t) {
  NL_LOG_DBG("TEQ_IMM %s, #%d", s_rn[t.n], int(t.imm));
}

void print(inst_test_equiv_reg const& t) {
  NL_LOG_DBG("TEQ_REG %s, %s", s_rn[t.n], s_rn[t.m]);
}

void print(inst_test_reg const& t) {
  NL_LOG_DBG("TST %s, %s, %s #%d", s_rn[t.n], s_rn[t.m], s_sn[int(t.shift.t)],
    int(t.shift.n));
}

void print(inst_vadd const& v) {
  NL_LOG_DBG("VADD.F32 S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
}

void print(inst_vcompare const& v) {
  NL_LOG_DBG("VCMP%s.F32 S%d, ", v.quiet_nan_exc ? "E" : "", int(v.d));
  if (v.with_zero) { NL_LOG_DBG("#0.0"); } else { NL_LOG_DBG("S%d", int(v.m)); }
}

void print(inst_vconvert_fp_int const& v) {
  NL_LOG_DBG("VCVT.");
  NL_LOG_DBG("%c32.", v.to_int ? (v.int_unsigned ? 'U' : 'S') : 'F');
  NL_LOG_DBG("%c32 ", v.to_int ? 'F' : (v.int_unsigned ? 'U' : 'S'));
  NL_LOG_DBG("S%d, S%d", int(v.d), int(v.m));
}

void print(inst_vdiv const& v) {
  NL_LOG_DBG("VDIV S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
}

void print(inst_vload const& v) {
  NL_LOG_DBG("VLDR S%d, [%s, #%d]", int(v.d), s_rn[v.n], int(v.imm));
}

void print(inst_vload_mult const& v) {
  NL_LOG_DBG("VLDM%s %s, {%x}", v.add ? "IA" : "DB", s_rn[v.n], unsigned(v.list));
}

void print(inst_vmov_imm const& v) {
  NL_LOG_DBG("VMOV_IMM.F32 S%d, #%f", int(v.d), double(v.imm));
}

void print(inst_vmov_reg const& v) {
  NL_LOG_DBG("VMOV_REG.F32 S%d, S%d", int(v.d), int(v.m));
}

void print(inst_vmov_reg_double const& v) {
  if (v.to_arm_regs) {
    NL_LOG_DBG("VMOV %s, %s, D%u", s_rn[v.t], s_rn[v.t2], unsigned(v.m));
  } else {
    NL_LOG_DBG("VMOV D%u, %s, %s", unsigned(v.m), s_rn[v.t], s_rn[v.t2]);
  }
}

void print(inst_vmov_reg_single const& v) {
  if (v.to_arm_reg) {
    NL_LOG_DBG("VMOV %s, S%u", s_rn[v.t], unsigned(v.n));
  } else {
    NL_LOG_DBG("VMOV S%u, %s", unsigned(v.n), s_rn[v.t]);
  }
}

void print(inst_vmov_special_from const& v) {
  NL_LOG_DBG("VMRS %s, FPSCR", v.t == 0b1111 ? "APSR_nzcv" : s_rn[v.t]);
}

void print(inst_vmov_special_to const& v) { NL_LOG_DBG("VMSR FPSCR, %s", s_rn[v.t]); }

void print(inst_vmul const& v) {
  NL_LOG_DBG("VMUL.F32 S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
}

void print(inst_vneg const& v) {
  NL_LOG_DBG("VNEG.F32 S%d, S%d", int(v.d), int(v.m));
}

void print(inst_vpop const& v) {
  NL_LOG_DBG("VPOP { %x }", v.regs); // TODO: print the list, don't care right now
}

void print(inst_vpush const& v) {
  NL_LOG_DBG("VPUSH { %x }", v.regs); // TODO: print the list, don't care right now
}

void print(inst_vstore const& v) {
  NL_LOG_DBG("VSTR %c%d, [%s, #%d]", v.single_reg ? 'S' : 'D', int(v.d), s_rn[v.n], int(v.imm));
}

void print(inst_vsub const& v) {
  NL_LOG_DBG("VSUB S%d, S%d, S%d", int(v.d), int(v.n), int(v.m));
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

float decode_vfp_imm8(u8 imm8, unsigned n) {
  // A6.4.1 Operation of modified immediate constants in floating-point instructions.
  // Page A-196
  // return imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19);

  assert(n == 32);
  u32 const replicate{(-((imm8 >> 6u) & 1u)) & 0x1Fu}, imm8_5_0{imm8 & 0x3Fu},
    not_imm8_6{!((imm8 >> 6u) & 1u)}, imm8_7{(imm8 >> 7u) & 1u},
    imm {(imm8_7 << 31u) | (not_imm8_6 << 30u) | (replicate << 24u) | (imm8_5_0 << 19u)};
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
    if ((d == 13) || (m == 13)) { // 4.6.6 ADD (SP plus reg), T2 encoding (pg 4-26)
      out_inst.type = inst_type::ADD_SP_IMM;
      out_inst.i.add_sp_imm = { .d = d, .imm = d };
      return true;
    }
    out_inst.type = inst_type::ADD_REG;
    out_inst.i.add_reg = { .shift = decode_imm_shift(0b00, 0), .d = d, .n = d, .m = m };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x1800u) { // 4.6.4 ADD (reg), T1 encoding (pg 4-22)
    out_inst.type = inst_type::ADD_REG;
    out_inst.i.add_reg = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0xA800u) { // 4.5.5 ADD (SP + imm), T1 encoding (pg 4-24)
    out_inst.type = inst_type::ADD_SP_IMM;
    out_inst.i.add_sp_imm = { .d = u8((w0 >> 8u) & 7u), .imm = u16((w0 & 0xFFu) << 2u) };
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
      .d = u8(w0 & 7u), .n = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800) == 0x1000u) { // 4.6.10 ASR (imm), T1 encoding (pg 4-34)
    out_inst.type = inst_type::RSHIFT_ARITH_IMM;
    out_inst.i.rshift_arith_imm = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b10, (w0 >> 6u) & 0x1Fu) };
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

  if ((w0 & 0xFFC0u) == 0x4380u) { // 4.6.16 BIC (reg), T1 encoding (pg 4-46)
    u8 const dn{u8(w0 & 7u)};
    out_inst.type = inst_type::BIT_CLEAR_REG;
    out_inst.i.bit_clear_reg = { .d = dn, .n = dn, .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0xBE00u) { // 4.6.17 BKPT, T1 encoding (pg 4-48)
    out_inst.type = inst_type::BREAKPOINT;
    out_inst.i.breakpoint = { .imm = u16(w0 & 0xFFu) };
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
    out_inst.i.cmp_imm = { .n = u8((w0 >> 8u) & 7u), .imm = u8(w0 & 0xFFu) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4280u) { // 4.6.30 CMP (reg), T1 encoding (pg 4-74)
    out_inst.type = inst_type::CMP_REG;
    out_inst.i.cmp_reg = { .shift = decode_imm_shift(0b00, 0),
      .n = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4500u) { // 4.6.30 CMP (reg), T2 encoding (pg 4-74)
    out_inst.type = inst_type::CMP_REG;
    out_inst.i.cmp_reg = { .n = u8((w0 & 7u) | ((w0 >> 4u) & 8u)),
      .m = u8((w0 >> 3u) & 0xFu), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xFFE8u) == 0xB660u) { // 4.6.31 CPS, T1 encoding (pg 4-76)
    u8 const im{u8((w0 >> 4u) & 1u)};
    out_inst.type = inst_type::CHANGE_PROC_STATE;
    out_inst.i.change_proc_state = { .en = (im == 0), .dis = (im == 1), .cm = 0,
      .aff_a = u8((w0 >> 2u) & 1u), .aff_f = u8(w0 & 1u), .aff_i = u8((w0 >> 1u) & 1u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4040u) { // 4.6.37 EOR (reg), T1 encoding (pg 4-88)
    u8 const rdn{u8(w0 & 7u)};
    out_inst.type = inst_type::EXCL_OR_REG;
    out_inst.i.excl_or_reg = { .d = rdn, .n = rdn, .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b00, 0) };
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

  if ((w0 & 0xF800u) == 0xC800u) { // 4.6.42 LDMIA, T1 encoding (pg 4-98)
    u16 const regs{u16(w0 & 0xFFu)};
    u8 const n{u8((w0 >> 8u) & 7u)};
    out_inst.type = inst_type::LOAD_MULT_INC_AFTER;
    out_inst.i.load_mult_inc_after = { .n = n, .regs = regs, .wback = !(regs & (1u << n)) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x6800u) { // 4.6.43 LDR (imm), T1 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .imm = u16(((w0 >> 6u) & 0x1Fu) << 2u), .add = 1u,
      .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .index = 1u };
    return true;
  }

  if ((w0 & 0xF800u) == 0x9800u) { // 4.6.43 LDR (imm), T2 encoding (pg 4-100)
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .n = 13u, .index = 1u, .add = 1u, .t = u8((w0 >> 8u) & 7u),
      .imm = u16((w0 & 0xFFu) << 2u) };
    return true;
  }

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
    out_inst.i.load_byte_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8800u) { // 4.6.55 LDRH (imm), T1 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.i.load_half_imm = { .imm = (u8)(((w0 >> 6u) & 0x1Fu) << 1u), .add = 1u,
      .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .index = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5A00u) { // 4.6.57 LDRH (reg), T1 encoding (pg 4-128)
    out_inst.type = inst_type::LOAD_HALF_REG;
    out_inst.i.load_half_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5600u) {
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_REG;
    out_inst.i.load_signed_byte_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0) { // 4.6.68 LSL (imm), T1 encoding (pg 4-150)
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.i.lshift_log_imm = { .shift = decode_imm_shift(0b00, u8((w0 >> 6u) & 0x1Fu)),
      .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4080u) { // 4.6.69 LSL (reg), T1 encoding (pg 4-152)
    u8 const dn{u8(w0 & 7u)};
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.i.lshift_log_reg = { .d = dn, .n = dn, .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x800u) { // 4.6.70 LSR (imm), T1 encoding (pg 4-154)
    out_inst.type = inst_type::RSHIFT_LOG_IMM;
    out_inst.i.rshift_log_imm = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b01, u8((w0 >> 6u) & 0x1Fu)) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x40C0u) { // 4.6.71 LSR (reg), T1 encoding (pg 4-156)
    u8 const rdn{u8(w0 & 7u)};
    out_inst.type = inst_type::RSHIFT_LOG_REG;
    out_inst.i.rshift_log_reg = { .d = rdn, .n = rdn, .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x2000u) { // 4.6.76 MOV (imm), T1 encoding (pg 4-166)
    out_inst.type = inst_type::MOV_IMM;
    out_inst.i.mov_imm = { .imm = u8(w0 & 0xFFu), .d = u8((w0 >> 8u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF00u) == 0x4600u) { // 4.6.77 MOV (reg), T1 encoding (pg 4-168)
    out_inst.type = inst_type::MOV_REG;
    out_inst.i.mov_reg = { .m = u8((w0 >> 3u) & 0xFu),
      .d = u8((w0 & 7u) | ((w0 & 0x80u) >> 4u)) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4340u) { // 4.6.84 MUL, T1 encoding (pg 4-181)
    out_inst.type = inst_type::MUL;
    out_inst.i.mul = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .m = u8(w0 & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x43C0u) { // 4.6.86 MVN (reg), T1 encoding (pg 4-185)
    out_inst.type = inst_type::MOV_NEG_REG;
    out_inst.i.mov_neg_reg = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if (w0 == 0xBF00u) { // 4.6.88 NOP (pg 4-189)
    out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    return true;
  }

  if ((w0 & 0xFFC0) == 0x4300) { // 4.6.92 ORR (reg), T1 encoding (pg 4-197)
    out_inst.type = inst_type::OR_REG;
    out_inst.i.or_reg = { .d = u8(w0 & 7u), .n = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
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

  if ((w0 & 0xFFC0u) == 0xBA00u) { // 4.6.111 REV, T1 encoding (pg 4-235)
    out_inst.type = inst_type::BYTE_REV_WORD;
    out_inst.i.byte_rev_word = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xBA40u) { // 4.6.112 REV16, T1 encoding (pg 4-237)
    out_inst.type = inst_type::BYTE_REV_PACKED_HALF;
    out_inst.i.byte_rev_packed_half = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u)};
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4240u) { // 4.6.118 RSB (imm), T1 encoding (pg 4-249)
    out_inst.type = inst_type::SUB_REV_IMM;
    out_inst.i.sub_rev_imm = { .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .imm = 0 };
    return true;
  }

  if ((w0 & 0xF800u) == 0xC000u) { // 4.6.161 STMIA, T1 encoding (pg 4-335)
    out_inst.type = inst_type::STORE_MULT_INC_AFTER;
    out_inst.i.store_mult_inc_after = { .n = u8((w0 >> 8u) & 7u), .regs = u8(w0 & 0xFFu),
      .wback = 1u };
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
    out_inst.i.store_imm = { .n = reg::SP, .t = u8((w0 >> 8u) & 7u),
      .imm = u16((w0 & 0xFFu) << 2u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5000u) { // 4.6.163 STR (reg), T1 encoding (pg 4-339)
    out_inst.type = inst_type::STORE_REG;
    out_inst.i.store_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x7000u) { // 4.6.164 STRB (imm), T1 encoding (pg 4-341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16((w0 >> 6u) & 0x1Fu), .t = u8(w0 & 7u),
      .n = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5400u) {  // 4.6.165 STRB (reg), T1 encoding (pg 4-343)
    out_inst.type = inst_type::STORE_BYTE_REG;
    out_inst.i.store_byte_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 7u), .shift = decode_imm_shift(0b00, 0) };
    return true;
  }

  if ((w0 & 0xF800u) == 0x8000u) { // 4.6.172 STRH (imm), T1 encoding (pg 4-357)
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .imm = u16(((w0 >> 6u) & 0x1F) << 1u), .index = 1u, .add = 1u };
    return true;
  }

  if ((w0 & 0xFE00u) == 0x5200u) { // 4.6.173 STRG (reg), T1 encoding (pg 4-359)
    out_inst.type = inst_type::STORE_HALF_REG;
    out_inst.i.store_half_reg = { .t = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u),
      .m = u8((w0 >> 6u) & 3u), .shift = decode_imm_shift(0b00, 0) };
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
      .d = u8(w0 & 7u), .n = u8((w0 >> 3u) & 7u), .m = u8((w0 >> 6u) & 7u) };
    return true;
  }

  if ((w0 & 0xFF80u) == 0xB080u) { // 4.6.178 SUB (SP - imm), T1 encoding (pg 4-369)
    out_inst.type = inst_type::SUB_SP_IMM;
    out_inst.i.sub_sp_imm = { .d = u8(13u), .imm = (w0 & 0x7Fu) << 2u };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB240u) { // 4.6.185 SXTB, T1 encoding (pg 4-383)
    out_inst.type = inst_type::EXTEND_SIGNED_BYTE;
    out_inst.i.extend_signed_byte = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB200u) {
    out_inst.type = inst_type::EXTEND_SIGNED_HALF;
    out_inst.i.extend_signed_half = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0x4200u) { // 4.6.193 TST, T1 encoding (pg 4-399)
    out_inst.type = inst_type::TEST_REG;
    out_inst.i.test_reg = { .shift = decode_imm_shift(0b00, 0), .n = u8(w0 & 7u),
      .m = u8((w0 >> 3u) & 7u) };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB2C0u) { // 4.6.224 UXTB, T1 encoding (pg 4-461)
    out_inst.type = inst_type::EXTEND_UNSIGNED_BYTE;
    out_inst.i.extend_unsigned_byte = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .rotation = 0 };
    return true;
  }

  if ((w0 & 0xFFC0u) == 0xB280u) { // 4.6.226 UXTH, T1 encoding (pg 4-465)
    out_inst.type = inst_type::EXTEND_UNSIGNED_HALF;
    out_inst.i.extend_unsigned_half = { .d = u8(w0 & 7u), .m = u8((w0 >> 3u) & 7u),
      .rotation = 0 };
    return true;
  }

  return false;
}

bool decode_32bit_inst(u16 const w0, u16 const w1, inst& out_inst) {
  out_inst.len = 4;

  // 4.6.1 ADC (imm), T1 encoding (pg 4-16)
  if (((w0 & 0xFBE0u) == 0xF140u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::ADD_CARRY_IMM;
    out_inst.i.add_carry_imm = { .n = u8(w0 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB40u) { // 4.6.2 ADC (reg), T2 encoding (pg 4-18)
    u8 const imm3{u8((w1 >> 12u) & 7u)}, imm2{u8((w1 >> 6u) & 3u)};
    out_inst.type = inst_type::ADD_CARRY_REG;
    out_inst.i.add_carry_reg = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu),
      .shift = decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2)) };
    return true;
  }

  // 4.6.3 ADD (imm), T3 encoding (pg 4-20)
  if (((w0 & 0xFBE0u) == 0xF100u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 0x7u}, i{(w0 >> 10u) & 1u},
      imm{decode_imm12((i << 11u) | (imm3 << 8u) | imm8)};
    u8 const d{u8((w1 >> 8u) & 0xFu)}, s{u8((w0 >> 4u) & 1u)},
      n{u8(w0 & 0xFu)};
    if ((s == 1) && (d == 15)) { // 4.6.27 CMN (imm), T1 encoding (pg 4-68)
      out_inst.type = inst_type::CMP_NEG_IMM;
      out_inst.i.cmp_neg_imm = { .n = n, .imm = imm };
      return true;
    }
    out_inst.type = inst_type::ADD_IMM;
    out_inst.i.add_imm = { .n = n, .d = d, .imm = imm };
    return true;
  }

  // 4.6.3 ADD (imm), T4 encoding (pg 4-20)
  if (((w0 & 0xFBF0u) == 0xF200u) && ((w1 & 0x8000u) == 0)) {
    u8 const n{u8(w0 & 0xFu)}, d{u8((w1 >> 8u) & 0xFu)};
    u32 const i{(w0 >> 10u) & 1u}, imm3{(w1 >> 12u) & 7u}, imm8{w1 & 0xFFu},
      imm{(i << 11u) | (imm3 << 8u) | imm8};
    if (n == 15) { // "SEE ADR on page 4-28"
      return false;
    }
    if (n == 13) { // 4.6.5 ADD (SP plus imm), T4 encoding (pg 4-24)
      out_inst.type = inst_type::ADD_SP_IMM;
      out_inst.i.add_sp_imm = { .d = d, .imm = u16(imm) };
      return true;
    }
    out_inst.type = inst_type::ADD_IMM;
    out_inst.i.add_imm = { .n = n, .d = d, .imm = u16(imm) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB00u) { // 4.6.4 ADD (reg), T3 encoding (pg 4-22)
    u32 const imm3{(w1 >> 12u) & 7u}, imm2{(w1 >> 6u) & 3u};
    u8 const n{u8(w0 & 0xFu)}, s{u8((w0 >> 4u) & 1u)}, m{u8(w1 & 0xFu)},
      d{u8((w1 >> 8u) & 0xFu)}, type{u8((w1 >> 4u) & 3u)}, si{u8((imm3 << 2u) | imm2)};
    if ((s == 1u) && (d == reg::PC)) { // CMN (reg) pg 4-70
      return false;
    }
    if (n == u8(reg::SP)) { // ADD (SP + reg), T3 encoding (pg 4-26)
      out_inst.type = inst_type::ADD_SP_REG;
      out_inst.i.add_sp_reg = { .m = m, .d = d, .shift = decode_imm_shift(type, si) };
      return true;
    }
    out_inst.type = inst_type::ADD_REG;
    out_inst.i.add_reg = { .m = m, .n = n, .d = d, .shift = decode_imm_shift(type, si) };
    return true;
  }

  // 4.6.8 AND (imm), T1 encoding (pg 4-30)
  if (((w0 & 0xFBE0u) == 0xF000u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::AND_IMM;
    out_inst.i.and_imm = { .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xEA00u) { // 4.6.9 AND (reg), T2 encoding (pg 4-32)
    u8 const imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)},
      d{u8((w1 >> 8u) & 0xFu)}, s{u8((w0 >> 4u) & 1u)};
    if ((d == 15) && (s == 1)) { // "SEE TST (register) on page 4-399"
      return false;
    }
    out_inst.type = inst_type::AND_REG;
    out_inst.i.and_reg = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu),
      .d = d, .shift = decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2)) };
    return true;
  }

  // 4.6.10 ASR (imm), T2 encoding (pg 4-34)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0x20u)) {
    u8 const imm3{u8((w1 >> 12u) & 7u)}, imm2{u8((w1 >> 6u) & 3u)};
    out_inst.type = inst_type::RSHIFT_ARITH_IMM;
    out_inst.i.rshift_arith_imm = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 7u),
      .shift = decode_imm_shift(0b10, u8((imm3 << 2u) | imm2)) };
    return true;
  }

  // 4.6.12 B, T3 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x8000u)) {
    u32 const imm11{w1 & 0x7FFu}, imm6{w0 & 0x3Fu}, j1{(w1 >> 13u) & 1u},
      j2{(w1 >> 11u) & 1u}, s{(w0 >> 10u) & 1u},
      imm{sext((s << 20u) | (j2 << 19u) | (j1 << 18u) | (imm6 << 12u) | (imm11 << 1u), 20)},
      addr{out_inst.addr + 4u + imm};
    cond_code const cc{cond_code((w0 >> 6u) & 0xFu)};
    if ((unsigned(cc) & 0xEu) == 0xEu) { // 4.6.88 NOP, T2 encoding (pg 4-189)
      out_inst.type = inst_type::NOP; out_inst.i.nop = {};
      return true;
    }
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .cc = cc, .imm = imm, .addr = addr };
    return true;
  }

  // 4.6.12 B, T4 encoding (pg 4-38)
  if (((w0 & 0xF800u) == 0xF000u) && ((w1 & 0xD000u) == 0x9000u)) {
    u32 const imm10{w0 & 0x3FFu}, imm11{w1 & 0x7FFu}, s{(w0 >> 10u) & 1u},
      j1{(w1 >> 13u) & 1u}, j2{(w1 >> 11u) & 1u}, i1{~(j1 ^ s) & 1u}, i2{~(j2 ^ s) & 1u},
      imm{sext((s << 24u) | (i1 << 23u) | (i2 << 22u) | (imm10 << 12u) | (imm11 << 1u), 24)},
      addr{out_inst.addr + 4u + imm};
    out_inst.type = inst_type::BRANCH;
    out_inst.i.branch = { .cc = cond_code::AL2, .imm = imm, .addr = addr };
    return true;
  }

  // 4.6.14 BFI, T1 encoding (pg 4-42)
  if (((w0 & 0xFBF0u) == 0xF360u) && ((w1 & 0x8000u) == 0)) {
    u8 const imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)}, n{u8(w1 & 0xFu)};
    if (n == 15) { // "SEE BFC on page 4-40"
      return false;
    }
    out_inst.type = inst_type::BITFIELD_INSERT;
    out_inst.i.bitfield_insert = { .d = u8((w1 >> 8u) & 0xFu), .n = n,
      .msbit = u8(w1 & 0x1Fu), .lsbit = u8((imm3 << 2u) | imm2) };
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

  if ((w0 & 0xFFE0u) == 0xEA20u) { // 4.6.16 BIC, T2 encoding (pg 4-46)
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
      j1{(w1 >> 13u) & 1u}, j2{(w1 >> 11u) & 1u}, i1{~(j1 ^ s) & 1u}, i2{~(j2 ^ s) & 1u};
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

  // 4.6.36 EOR (imm), T1 encoding (pg 4-86)
  if (((w0 & 0xFBE0u) == 0xF080u) && ((w1 & 0x8000u) == 0)) {
    u8 const d{u8((w1 >> 8u) & 0xFu)}, s{u8((w0 >> 4u) & 1u)}, n{u8(w0 & 0xFu)};
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u},
      imm{decode_imm12((i << 11u) | (imm3 << 8u) | imm8)};
    if ((s == 1) && (d == 15)) { // 4.6.190 TEQ (imm), T1 encoding (pg 4-393)
      out_inst.type = inst_type::TEST_EQUIV_IMM;
      out_inst.i.test_equiv_imm = { .n = n, .imm = imm };
      return true;
    }
    out_inst.type = inst_type::EXCL_OR_IMM;
    out_inst.i.excl_or_imm = { .n = n, .d = d, .imm = imm };
    return true;
  }

  if ((w0 & 0xFFE0) == 0xEA80u) { // 4.6.37 EOR (reg), T2 encoding (pg 4-88)
    u8 const d{u8((w1 >> 8u) & 0xFu)}, s{u8((w0 >> 4u) & 1u)}, imm3{u8((w1 >> 12u) & 7u)},
      imm2{u8((w1 >> 6u) & 3u)}, m{u8(w1 & 0xFu)}, n{u8(w0 & 0xFu)};
    imm_shift const shift{decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2))};
    if ((d == 15) && (s == 1)) { // 4.6.191 TEQ (reg), T1 encoding (pg 4-395)
      out_inst.type = inst_type::TEST_EQUIV_REG;
      out_inst.i.test_equiv_reg = { .m = m, .n = n, .shift = shift };
      return true;
    }
    out_inst.type = inst_type::EXCL_OR_REG;
    out_inst.i.excl_or_reg = { .d = d, .n = n, .m = m, .shift = shift };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE910u) {
    out_inst.type = inst_type::LOAD_MULT_DEC_BEFORE;
    out_inst.i.load_mult_dec_before = { .n = u8(w0 & 0xFu), .wback = u8((w0 >> 5u) & 1u),
      .regs = u16(w1 & 0xDFFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE890u) { // 4.6.42 LDMIA, T2 encoding (pg 4-98)
    out_inst.type = inst_type::LOAD_MULT_INC_AFTER;
    out_inst.i.load_mult_inc_after = { .n = u8(w0 & 0xFu), .wback = u8((w0 >> 5u) & 1u),
      .regs = u16(w1 & 0xDFFFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8D0u) { // 4.6.43 LDR (imm), T3 encoding (pg 4-100)
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)};
    u16 const imm{u16(w1 & 0xFFFu)};
    if (n == 15) { // 4.6.44 LDR (literal), T2 encoding (pg 4-102)
      out_inst.type = inst_type::LOAD_LIT;
      out_inst.i.load_lit = { .t = t, .imm = imm, .add = u8((w0 >> 7u) & 1u),
        .addr = u32(inst_align(out_inst.addr, 4) + imm + 4) };
      return true;
    }
    out_inst.type = inst_type::LOAD_IMM;
    out_inst.i.load_imm = { .n = n, .t = t, .add = 1u, .imm = imm, .index = 1u };
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
      .imm = u16(w1 & 0xFFFu), .index = 1u, .add = 1u };
    return true;
  }

  // 4.6.46 LDRB (imm), T3 encoding (pg 4-106)
  if (((w0 & 0xFFF0u) == 0xF810u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)}, puw{u8((w1 >> 8u) & 3u)};
    if (n == 15) { // "SEE LDRB (literal) on page 4-108"
      return false;
    }
    if ((t == 15) && (puw == 0b110)) { // "SEE LDRBT on page 4-112"
      return false;
    }
    out_inst.type = inst_type::LOAD_BYTE_IMM;
    out_inst.i.load_byte_imm = { .add = u8((puw >> 1u) & 1u), .index = u8((puw >> 2u) & 1u),
      .t = t, .n = n, .imm = u16(w1 & 0xFFu) };
    return true;
  }

  // 4.6.48 LDRB (reg), T2 encoding (pg 4-110)
  if (((w0 & 0xFFF0u) == 0xF810u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)};
    if (t == 15) { // "SEE PLD (register) on page 4-203"
      return false;
    }
    if (n == 15) { // "SEE LDRB (literal) on page 4-108"
      if (t == 15) { // "SEE PLD (immediate) on page 4-201"
        return false;
      }
      out_inst.type = inst_type::LOAD_BYTE_LIT;
      out_inst.i.load_byte_lit = { .imm = u16(w1 & 0xFFFu), .t = u8((w1 >> 12u) & 0xFu),
        .add = u8((w0 >> 7u) & 1u) };
    } else {
      out_inst.type = inst_type::LOAD_BYTE_REG;
      out_inst.i.load_byte_reg = { .m = u8(w1 & 0xFu), .n = n, .t = t,
        .shift = decode_imm_shift(u8(imm_shift_type::LSL), u8((w1 >> 4u) & 3u)) };
    }
    return true;
  }

  if ((w0 & 0xFE50u) == 0xE850u) { // 4.6.50 LDRD (imm), T1 encoding (pg 4-114)
    u8 const p{u8((w0 >> 8u) & 1u)}, u{u8((w0 >> 7u) & 1u)}, w{u8((w0 >> 5u) & 1u)};
    if ((p == 0) && (w == 0)) {
      if (u == 0) { // 4.6.51 LDREX, T1 encoding (pg 4-116)
        out_inst.type = inst_type::LOAD_EXCL;
        out_inst.i.load_excl = { .imm = u16((w1 & 0xFFu) << 2u), .n = u8(w0 & 0xFu),
          .t = u8((w1 >> 12u) & 0xFu) };
        return true;
      } else {
        if ((w1 & 0xF0u) == 0x10) { // 4.6.189 TBH, T1 encoding (pg 4-391)
          out_inst.type = inst_type::TABLE_BRANCH_HALF;
          out_inst.i.table_branch_half = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
          return true;
        }
        if ((w1 & 0xF0u) == 0) { // 4.6.188 TBB, T1 encoding (pg 4-389)
          out_inst.type = inst_type::TABLE_BRANCH_BYTE;
          out_inst.i.table_branch_byte = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu) };
          return true;
        }
        return false;
      }
    }
    out_inst.type = inst_type::LOAD_DBL_REG;
    out_inst.i.load_dbl_reg = { .imm = u16((w1 & 0xFFu) << 2u), .n = u8(w0 & 0xFu),
      .t = u8((w1 >> 12u) & 0xFu), .t2 = u8((w1 >> 8u) & 0xFu), .add = u, .index = p };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8B0u) { // 4.6.55 LDRH (imm), T2 encoding (pg 4-124)
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.i.load_half_imm = { .imm = u16(w1 & 0xFFFu), .t = u8((w1 >> 12u) & 0xFu),
      .n = u8(w0 & 0xFu), .add = 1u, .index = 1u };
    return true;
  }

  // 4.6.55 LDRH (imm), T3 encoding (pg 4-124)
  if (((w0 & 0xFFF0u) == 0xF830u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const p{u8((w1 >> 10u) & 1u)}, u{u8((w1 >> 9u) & 1u)}, w{u8((w1 >> 8u) & 1u)},
      n{u8(w0 & 0xFu)}, t{u8((w1 >> 12u) & 0xFu)};
    if (n == 15) { // "SEE LDRH (literal) on page 4-126"
      return false;
    }
    if ((t == 15) && (p == 1) && (u == 0) && (w == 0)) { // "SEE Memory hints on page 4-14"
      return false;
    }
    if ((p == 1) && (u == 1) && (w == 0)) { // "SEE LDRHT on page 4-130"
      return false;
    }
    out_inst.type = inst_type::LOAD_HALF_IMM;
    out_inst.i.load_half_imm = { .n = n, .t = t, .imm = u16(w1 & 0xFFu), .add = u,
      .index = p };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF990u) { // 4.6.59 LDRSB (imm), T1 encoding (pg 4-132)
    out_inst.type = inst_type::LOAD_SIGNED_BYTE_IMM;
    out_inst.i.load_signed_byte_imm = { .imm = u16(w1 & 0xFFFu), .n = u8(w0 & 0xFu),
      .add = 1u, .index = 1u, .t = u8((w0 >> 12u) & 0xFu) };
    return true;
  }

  // 4.6.59 LDRSB (imm), T2 encoding (pg 4-132)
  if (((w0 & 0xFFF0u) == 0xF910u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const n{u8(w0 & 0xFu)}, t{u8((w1 >> 12u) & 0xFu)}, p{u8((w1 >> 10u) & 1u)},
      u{u8((w1 >> 9u) & 1u)}, w{u8((w1 >> 8u) & 1u)};
    u16 const imm{u16(w1 & 0xFFu)};
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
    out_inst.i.load_signed_byte_imm = { .index = p, .add = u, .t = t, .n = n, .imm = imm };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF9B0u) { // 4.6.63 LDRSH (imm), T1 encoding (pg 4-140)
    u8 const n{u8(w0 & 0xFu)}, t{u8((w1 >> 12u) & 0xFu)};
    if (n == 15) { // "SEE LDRSH (literal) on page 4-142"
      return false;
    }
    if (t == 15) { // "SEE Memory hints on page 4-14"
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_HALF_IMM;
    out_inst.i.load_signed_half_imm = { .add = 1u, .index = 1u, .n = n, .t = t,
      .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  // 4.6.63 LDRSH (imm), T2 encoding (pg 4-140)
  if (((w0 & 0xFFF0u) == 0xF930u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)}, p{u8((w0 >> 10u) & 1u)},
      u{u8((w1 >> 9u) & 1u)}, w{u8((w1 >> 8u) & 1u)};
    u16 const imm{u16(w1 & 0xFFu)};
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
    out_inst.i.load_signed_half_imm = { .n = n, .t = t, .add = u, .index = p, .imm = imm };
    return true;
  }

  // 4.6.65 LDRSH (reg), T2 encoding (pg 4-144)
  if (((w0 & 0xFFF0u) == 0xF930u) && ((w1 & 0xFC0u) == 0)) {
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)};
    if (n == 15) { // "SEE LDRSH (literal) on page 4-142"
      return false;
    }
    if (t == 15) { // "SEE Memory hints on page 4-14"
      return false;
    }
    out_inst.type = inst_type::LOAD_SIGNED_HALF_REG;
    out_inst.i.load_signed_half_reg = { .n = n, .t = t, .m = u8(w1 & 0xFu),
      .shift = decode_imm_shift(u8(imm_shift_type::LSL), u8((w1 >> 4u) & 3u)) };
    return true;
  }

  // 4.6.68 LSL (imm), T2 encoding (pg 4-150)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0)) {
    u8 const imm3{u8((w1 >> 12u) & 7u)}, imm2{u8((w1 >> 6u) & 3u)},
      imm{u8((imm3 << 2u) | imm2)};
    if (imm == 0) { // "SEE MOV (register) on page 4-168"
      NL_LOG_DBG("4.6.68 LSL (imm), T2 encoding (pg 4-150)\n");
      return false;
    }
    out_inst.type = inst_type::LSHIFT_LOG_IMM;
    out_inst.i.lshift_log_imm = { .d = u8((w1 >> 8u) & 0xFu), .m = u8(w1 & 0xFu),
      .shift = decode_imm_shift(0b00, imm) };
    return true;
  }

  // 4.6.69 LSL (reg), T2 encoding (pg 4-152)
  if (((w0 & 0xFFE0u) == 0xFA00u) && ((w1 & 0xF0F0u) == 0xF000u)) {
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.i.lshift_log_reg = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .n = u8(w0 & 0xFu) };
    return true;
  }

  // 4.6.70 LSR (imm), T2 encoding (pg 4-154)
  if (((w0 & 0xFFEFu) == 0xEA4Fu) && ((w1 & 0x30u) == 0x10u)) {
    u8 const imm3{u8((w1 >> 12u) & 7u)}, imm2{u8((w1 >> 6u) & 7u)};
    out_inst.type = inst_type::RSHIFT_LOG_IMM;
    out_inst.i.rshift_log_imm = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .shift = decode_imm_shift(0b01, u8((imm3 << 2u) | imm2)) };
    return true;
  }

  // 4.6.71 LSR (reg), T2 encoding (pg 4-156)
  if (((w0 & 0xFFE0u) == 0xFA20u) && ((w1 & 0xF0F0u) == 0xF000u)) {
    out_inst.type = inst_type::LSHIFT_LOG_REG;
    out_inst.i.lshift_log_reg = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  // 4.6.74 MLA, T1 encoding (pg 4-162)
  if (((w0 & 0xFFF0u) == 0xFB00u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_ACCUM;
    out_inst.i.mul_accum = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu), .a = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  // 4.6.75 MLS, T1 encoding (pg 4-164)
  if (((w0 & 0xFFF0u) == 0xFB00u) && ((w1 & 0xF0u) == 0x10u)) {
    out_inst.type = inst_type::MUL_SUB;
    out_inst.i.mul_sub = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu), .a = u8((w1 >> 12u) & 0xFu) };
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

  // 4.6.85 MVN (imm), T2 encoding (pg 4-183)
  if (((w0 & 0xFBEFu) == 0xF06Fu) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::MOV_NEG_IMM;
    out_inst.i.mov_neg_imm = { .d = u8((w1 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.88 NOP, T2 encoding (pg 4-189)
  if (((w0 & 0xFFF0u) == 0xF3A0u) && ((w1 & 0xD7FFu) == 0x8000u)) {
    // shouldn't need nop flag memory hints for static analysis (e.g. dsb, isb)
    out_inst.type = inst_type::NOP; out_inst.i.nop = {};
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA60u) { // 4.6.90 ORN, T1 encoding (pg 4-193)
    u8 const d{u8((w1 >> 8u) & 0xFu)}, m{u8(w1 & 0xFu)}, n{u8(w0 & 0xFu)},
      imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)};
    imm_shift const shift{decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2))};
    if (n == 15) { // 4.6.86 MVN (reg), T2 encoding (pg 4-185)
      out_inst.type = inst_type::MOV_NEG_REG;
      out_inst.i.mov_neg_reg = { .d = d, .m = m, .shift = shift };
      return true;
    }
    out_inst.type = inst_type::OR_NOT_REG;
    out_inst.i.or_not_reg = { .d = d, .m = m, .n = n, .shift = shift };
    return true;
  }

  // 4.6.91 ORR (imm), T1 encoding (pg 4-195)
  if (((w0 & 0xFB40u) == 0xF040u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u},
      imm{decode_imm12((i << 11u) | (imm3 << 8u) | imm8)};
    u8 const n{u8(w0 & 0xFu)}, d{u8((w1 >> 8u) & 0xFu)};
    if (n == 15) { // 4.6.76 MOV (imm), T2 encoding (pg 4-166)
      out_inst.type = inst_type::MOV_IMM;
      out_inst.i.mov_imm = { .d = d, .imm = imm };
      return true;
    }
    out_inst.type = inst_type::OR_IMM;
    out_inst.i.or_imm = { .d = d, .n = n, .imm = imm };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEA40u) { // 4.6.91 ORR (reg), T2 encoding (pg 4-197)
    u8 const imm3{u8((w1 >> 12u) & 7u)}, imm2{u8((w1 >> 6u) & 3u)},
       n{u8(w0 & 0xFu)}, m{u8(w1 & 0xFu)}, d{u8((w1 >> 8u) & 0xFu)};
    imm_shift const shift{decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2))};
    if (n == 15) {
      out_inst.type = inst_type::MOV_REG;
      out_inst.i.mov_reg = { .d = d, .m = m };
      return true;
    }
    out_inst.type = inst_type::OR_REG;
    out_inst.i.or_reg = { .d = d, .n = n, .m = m, .shift = shift };
    return true;
  }

  // 4.6.93 PKH, T1 encoding (pg 4-199)
  if (((w0 & 0xFFF0u) == 0xEAC0u) && ((w1 & 0x10u) == 0)) {
    u8 const imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)}, tb{u8((w1 >> 5u) & 1u)};
    out_inst.type = inst_type::PACK_HALF;
    out_inst.i.pack_half = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .tbform = tb, .shift = decode_imm_shift(u8(tb << 1u), u8((imm3 << 2u) | imm2)),
      .d = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  if (w0 == 0xE8BDu) { // 4.6.98 POP, T2 encoding (pg 4-209)
    out_inst.type = inst_type::POP; out_inst.i.pop = { .reg_list = uint16_t(w1 & 0xDFFFu) };
    return true;
  }

  // 4.6.110 RBIT, T1 encoding (pg 4-233)
  if (((w0 & 0xFFF0u) == 0xFA90u) && ((w1 & 0xF0F0u) == 0xF0A0u)) {
    out_inst.type = inst_type::REVERSE_BITS;
    out_inst.i.reverse_bits = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  // 4.6.118 RSB (imm), T2 encoding (pg 4-249)
  if (((w0 & 0xFBE0u) == 0xF1C0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::SUB_REV_IMM;
    out_inst.i.sub_rev_imm = { .n = u8(w0 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEBC0u) {
    u8 const imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)},
      imm{u8((imm3 << 2u) | imm2)};
    out_inst.type = inst_type::SUB_REV_REG;
    out_inst.i.sub_rev_reg = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu), .shift = decode_imm_shift(u8((w1 >> 4u) & 3u), imm) };
    return true;
  }

  // 4.6.123 SBC (imm), T1 encoding (pg 4-259)
  if (((w0 & 0xFBE0u) == 0xF160u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u};
    out_inst.type = inst_type::SUB_IMM_CARRY;
    out_inst.i.sub_imm_carry = { .n = u8(w0 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .imm = decode_imm12((i << 11u) | (imm3 << 8u) | imm8) };
    return true;
  }

  // 4.6.125 SBFX, T1 encoding (pg 4-263)
  if (((w0 & 0xFBF0u) == 0xF340u) && ((w1 & 0x8000u) == 0)) {
    u8 const imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)};
    out_inst.type = inst_type::BITFIELD_EXTRACT_SIGNED;
    out_inst.i.bitfield_extract_signed = { .n = u8(w0 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .lsbit = u8((imm3 << 2u) | imm2), .widthminus1 = u8(w1 & 0x1Fu) };
    return true;
  }

  // 4.6.126 SDIV, T1 encoding (pg 4-265)
  if (((w0 & 0xFFF0u) == 0xFB90u) && ((w1 & 0xF0u) == 0xF0u)) {
    out_inst.type = inst_type::DIV_SIGNED;
    out_inst.i.div_signed = { .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .m = u8(w1 & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEB60) { // 4.6.124 SBC (reg), T2 encoding (pg 4-261)
    u32 const imm2{(w1 >> 6u) & 3u}, imm3{(w1 >> 12u) & 7u};
    out_inst.type = inst_type::SUB_REG_CARRY;
    out_inst.i.sub_reg_carry = {
      .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu), .n = u8(w0 & 0xFu),
      .shift = decode_imm_shift(u8((w1 >> 4u) & 3u), u8((imm3 << 2u) | imm2)) };
    return true;
  }

  // 4.6.127 SEL, T1 encoding (4-267)
  if (((w0 & 0xFFF0u) == 0xFAA0u) && ((w1 & 0xF0F0u) == 0xF080u)) {
    out_inst.type = inst_type::SELECT_BYTES;
    out_inst.i.select_bytes = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu) };
    return true;
  }

  // 4.6.139 SMLAL, T1 encoding (pg 4-291)
  if (((w0 & 0xFFF0u) == 0xFBC0u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_ACCUM_SIGNED_LONG;
    out_inst.i.mul_accum_signed_long = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .dhi = u8((w1 >> 8u) & 0xFu), .dlo = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE900u) { // 4.6.160 STMDB, T1 encoding (pg 4-333)
    out_inst.type = inst_type::STORE_MULT_DEC_BEF;
    out_inst.i.store_mult_dec_bef = { .n = u8(w0 & 0xFu), .regs = u16(w1 & 0x5FFFu) };
    return true;
  }

  if ((w0 & 0xFFD0u) == 0xE880u) { // 4.6.161 STMIA, T2 encoding (pg 4-335)
    out_inst.type = inst_type::STORE_MULT_INC_AFTER;
    out_inst.i.store_mult_inc_after = { .regs = u16(w1 & 0x5FFFu), .n = u8(w0 & 0xFu),
      .wback = u8((w0 >> 5u) & 1u) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8C0u) { // 4.6.162 STR (imm), T3 encoding (pg 4-337)
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .t = u8(w1 >> 12u), .n = u8(w0 & 0xFu),
      .imm = u16(w1 & 0xFFFu) };
    return true;
  }

  // 4.6.162 STR (imm), T4 encoding (pg 4-337)
  if (((w0 & 0xFFF0u) == 0xF840) && ((w1 & 0x800u) == 0x800u)) {
    u8 const t{u8((w1 >> 12u) & 0xFu)}, n{u8(w0 & 0xFu)}, imm8{u8(w1 & 0xFFu)},
      p{u8((w1 >> 10u) & 1u)}, u{u8((w1 >> 9u) & 1u)}, w{u8((w1 >> 8u) & 1u)};
    if ((p == 1) && (u == 1) && (w == 0)) { // "SEE STRT on page 4-363"
      return false;
    }
    out_inst.type = inst_type::STORE_IMM;
    out_inst.i.store_imm = { .t = t, .n = n, .imm = u16(imm8) };
    return true;
  }

  // 4.6.163 STR (reg), T2 encoding (pg 4-339)
  if (((w0 & 0xFFF0u) == 0xF840u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::STORE_REG;
    out_inst.i.store_reg = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .shift = decode_imm_shift(u8(imm_shift_type::LSL), u8((w1 >> 4u) & 3u)),
      .t = u8((w1 >> 12u) & 0xFu) };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF880u) { // 4.6.164 STRB (imm), T2 encoding (pg 4.341)
    out_inst.type = inst_type::STORE_BYTE_IMM;
    out_inst.i.store_byte_imm = { .imm = u16(w1 & 0xFFFu), .t = u8((w1 >> 12u) & 0xFu),
      .n = u8(w0 & 0xFu), .add = 1u, .index = 1u };
    return true;
  }

  // 4.6.164 STRB (imm), T3 encoding (pg 4-341)
  if (((w0 & 0xFFF0u) == 0xF800u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const puw{u8((w1 >> 8u) & 7u)};
    if (puw == 0b110) {
      out_inst.type = inst_type::STORE_BYTE_UNPRIV;
      out_inst.i.store_byte_unpriv = {
        .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu) };
    } else {
      out_inst.type = inst_type::STORE_BYTE_IMM;
      out_inst.i.store_byte_imm = {
        .t = u8((w1 >> 12u) & 0xFu), .n = u8(w0 & 0xFu), .add = u8((puw >> 1u) & 1u) };
    }
    return true;
  }

  // 4.6.165 STRB (reg), T2 encoding (pg 4-343)
  if (((w0 & 0xFFF0u) == 0xF800u) && ((w1 & 0xFC0u) == 0)) {
    out_inst.type = inst_type::STORE_BYTE_REG;
    out_inst.i.store_byte_reg = { .n = u8(w0 & 0xFu), .m = u8(w1 & 0xFu),
      .t = u8((w1 >> 12u) & 0xFu),
      .shift = decode_imm_shift(u8(imm_shift_type::LSL), u8((w1 >> 4u) & 3u))};
    return true;
  }

  if ((w0 & 0xFE50u) == 0xE840u) { // 4.6.167 STRD (imm), T1 encoding (pg 4-347)
    u8 const p{u8((w0 >> 8u) & 1u)}, w{u8((w0 >> 5u) & 1u)};
    if ((p == 0) && (w == 0)) {  // 4.6.168 STREX, T1 encoding (pg 4-349)
      out_inst.type = inst_type::STORE_EXCL;
      out_inst.i.store_excl = { .imm = u16((w1 & 0xFFu) << 2u), .n = u8(w0 & 0xFu),
        .t = u8((w1 >> 12u) & 0xFu), .d = u8((w1 >> 8u) & 0xFu) };
      return true;
    }
    out_inst.type = inst_type::STORE_DOUBLE_IMM;
    out_inst.i.store_double_imm = { .imm = u16((w1 & 0xFFu) << 2u), .n = u8(w0 & 0xFu),
      .t = u8((w1 >> 12u) & 0xFu), .t2 = u8((w1 >> 8u) & 0xFu), .add = u8((w0 >> 7u) & 1u),
      .index = p };
    return true;
  }

  if ((w0 & 0xFFE0u) == 0xEBA0u) { // 4.6.177 SUB (reg), T2 encoding (pg 4-367)
    u8 const d{u8((w1 >> 8u) & 0xFu)}, n{u8(w0 & 0xFu)}, s{u8((w0 >> 4u) & 1u)},
      m{u8(w1 & 0xFu)}, imm2{u8((w1 >> 6u) & 3u)}, imm3{u8((w1 >> 12u) & 7u)};
    imm_shift const shift{decode_imm_shift(u8((w1 >> 4u) & 3u), u8(imm3 << 2u) | imm2)};
    if ((d == 15) && (s == 1)) { // 4.6.30 CMP (reg), T3 encoding (pg 4-74)
      out_inst.type = inst_type::CMP_REG;
      out_inst.i.cmp_reg = { .n = n, .m = m, .shift = shift };
      return true;
    }
    if (n == 13) { // "SEE SUB (SP minus register) on page 4-371"
      return false;
    }
    out_inst.type = inst_type::SUB_REG;
    out_inst.i.sub_reg = { .d = d, .n = n, .m = m, .shift = shift };
    return true;
  }

  if ((w0 & 0xFFF0u) == 0xF8A0u) { // 4.6.172 STRH (imm), T2 encoding (pg 4-357)
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .n = u8(w0 & 0xFu), .imm = u16(w1 & 0xFFFu), .add = 1u,
      .t = u8((w1 >> 12u) & 0xFu), .index = 1u };
    return true;
  }

  // 4.6.172 STRH (imm), T3 encoding (pg 4-357)
  if (((w0 & 0xFFF0u) == 0xF820u) && ((w1 & 0x800u) == 0x800u)) {
    u8 const n{u8(w0 & 0xFu)}, t{u8((w1 >> 12u) & 0xFu)}, imm{u8(w1 & 0xFu)},
      p{u8((w1 >> 10u) & 1u)}, u{u8((w1 >> 9u) & 1u)}, w{u8((w1 >> 8u) & 1u)};
    if ((p == 1) && (u == 1) && (w == 0)) {
      NL_LOG_DBG("SEE STRHT on page 4-361\n");
      return false;
    }
    out_inst.type = inst_type::STORE_HALF_IMM;
    out_inst.i.store_half_imm = { .index = p, .add = u, .t = t, .n = n, .imm = imm };
    return true;
  }

  // 4.6.176 SUB (imm), T3 encoding (pg 4-365)
  if (((w0 & 0xFBE0u) == 0xF1A0u) && ((w1 & 0x8000u) == 0)) {
    u32 const imm8{w1 & 0xFFu}, imm3{(w1 >> 12u) & 7u}, i{(w0 >> 10u) & 1u},
      imm{decode_imm12((i << 11u) | (imm3 << 8u) | imm8)};
    u8 const d{u8((w1 >> 8u) & 0xFu)}, n{u8(w0 & 0xFu)}, s{u8((w0 >> 4u) & 1u)};
    if ((d == 15) && (s == 1)) { // 4.6.29 CMP (imm), T2 encoding (pg 4-72)
      out_inst.type = inst_type::CMP_IMM;
      out_inst.i.cmp_imm = { .n = n, .imm = imm };
      return true;
    }
    if (n == 13) { // 4.6.178 SUB (SP minus imm), T2 encoding (pg 4-369)
      out_inst.type = inst_type::SUB_SP_IMM;
      out_inst.i.sub_sp_imm = { .d = d, .imm = imm };
      return true;
    }
    out_inst.type = inst_type::SUB_IMM;
    out_inst.i.sub_imm = { .d = d, .n = n, .imm = imm };
    return true;
  }

  // 4.6.176 SUB (imm), T4 encoding (pg 4-365)
  if (((w0 & 0xFBF0u) == 0xF2A0u) && ((w1 & 0x8000u) == 0)) {
    u8 const n{u8(w0 & 0xFu)}, d{u8((w1 >> 8u) & 0xFu)};
    u16 const imm3{u8((w1 >> 12u) & 7u)}, imm8{u8(w1 & 0xFFu)}, i{u8((w0 >> 10u) & 1u)},
      imm{u16((i << 11u) | (imm3 << 8u) | imm8)};
    if (n == 15) { // "SEE ADR on page 4-28"
      return false;
    }
    if (n == 13) { // 4.6.178 SUB (SP minus imm), T3 encoding, (pg 4-369)
      out_inst.type = inst_type::SUB_SP_IMM;
      out_inst.i.sub_sp_imm = { .d = d, .imm = imm };
      return true;
    }
    out_inst.type = inst_type::SUB_IMM;
    out_inst.i.sub_imm = { .d = d, .n = n, .imm = imm };
    return true;
  }

  // 4.6.182 SXTAB, T1 encoding (pg 4-377)
  if (((w0 & 0xFFF0u) == 0xFA40u) && ((w1 & 0xF080u) == 0xF080u)) {
    u8 const d{u8((w1 >> 8u) & 0xFu)}, m{u8(w1 & 0xFu)}, n{u8(w0 & 0xFu)},
      rotation{u8(((w1 >> 4u) & 3u) << 3u)};
    if (n == 15) { // 4.6.185 SXTB, T2 encoding (pg 4-383)
      out_inst.type = inst_type::EXTEND_SIGNED_BYTE;
      out_inst.i.extend_signed_byte = { .rotation = rotation, .d = d, .m = m };
      return true;
    }
    out_inst.type = inst_type::EXTEND_ADD_SIGNED_BYTE;
    out_inst.i.extend_add_signed_byte = { .d = d, .m = m, .n = n, .rotation = rotation };
    return true;
  }

  // 4.6.195 UADD8, T1 encoding (pg 4-403)
  if (((w0 & 0xFFF0u) == 0xFA80u) && ((w1 & 0xF0F0u) == 0xF040u)) {
    out_inst.type = inst_type::ADD_8_UNSIGNED;
    out_inst.i.add_8_unsigned = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .d = u8((w1 >> 8u) & 0xFu) };
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

  // 4.6.198 UDIV, T1 encoding (pg 4-409)
  if (((w0 & 0xFFF0u) == 0xFBB0) && ((w1 & 0xF0u) == 0xF0u)) {
    out_inst.type = inst_type::DIV_UNSIGNED;
    out_inst.i.div_unsigned = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .n = u8(w0 & 0xFu) };
    return true;
  }

  // 4.6.206 UMLAL, T1 encoding (pg 4-425)
  if (((w0 & 0xFFF0u) == 0xFBE0u) && ((w1 & 0xF0u) == 0)) {
    out_inst.type = inst_type::MUL_ACCUM_UNSIGNED_LONG;
    out_inst.i.mul_accum_unsigned_long = { .m = u8(w1 & 0xFu), .n = u8(w0 & 0xFu),
      .dlo = u8((w1 >> 12u) & 0xFu), .dhi = u8((w1 >> 8u) & 0xFu)};
    return true;
  }

  // 4.6.224 UXTB, T2 encoding (pg 4-461)
  if ((w0 == 0xFA5Fu) && ((w1 & 0xF080u) == 0xF080u)) {
    out_inst.type = inst_type::EXTEND_UNSIGNED_BYTE;
    out_inst.i.extend_unsigned_byte = { .m = u8(w1 & 0xFu), .d = u8((w1 >> 8u) & 0xFu),
      .rotation = u8(((w1 >> 4u) & 3u) << 2u) };
    return true;
  }

  // A7.7.221 VADD, T1 encoding (pg A7-566)
  if (((w0 & 0xFFB0u) == 0xEE30u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const D{u8((w0 >> 6u) & 1u)}, N{u8((w1 >> 7u) & 1u)}, M{u8((w1 >> 5u) & 1u)},
      vn{u8(w0 & 0xFu)}, vm{u8(w1 & 0xFu)}, vd{u8((w1 >> 12u) & 0xFu)};
    out_inst.type = inst_type::VADD;
    out_inst.i.vadd = { .d = u8((vd << 1u) | D), .n = u8((vn << 1u) | N),
      .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.222 VCMP, T1 encoding (pg A7-567)
  if (((w0 & 0xFFBFu) == 0xEEB4u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const D{u8((w0 >> 6u) & 1u)}, vd{u8((w1 >> 12u) & 0xFu)};
    out_inst.type = inst_type::VCOMPARE;
    out_inst.i.vcompare = { .with_zero = 0u, .quiet_nan_exc = u8((w1 >> 7u) & 1u),
      .d = u8((vd << 1u) | D) };
    return true;
  }

  // A7.7.222 VCMP, T2 encoding (pg A7-567)
  if (((w0 & 0xFFBFu) == 0xEEB5u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const D{u8((w0 >> 6u) & 1u)}, vd{u8((w1 >> 12u) & 0xFu)};
    out_inst.type = inst_type::VCOMPARE;
    out_inst.i.vcompare = { .quiet_nan_exc = u8((w1 >> 7u) & 1u), .with_zero = 1u,
      .d = u8((vd << 1u) | D) };
    return true;
  }

  // A7.7.223 VCVT (between FP and int), T1 encoding (pg A7-569)
  if (((w0 & 0xFFB8u) == 0xEEB8u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const opc2{u8(w0 & 7u)}, d{u8(((w1 >> 11u) & 0x1Eu) | ((w0 >> 6u) & 1u))},
      op{u8((w1 >> 7u) & 1u)}, m{u8(((w1 & 0xFu) << 1u) | ((w1 >> 5u) & 1u))},
      to_int{u8(!!(opc2 & 0b100))};
    out_inst.type = inst_type::VCONVERT_FP_INT;
    if (to_int) {
      out_inst.i.vconvert_fp_int = { .m = m, .d = d, .int_unsigned = ((opc2 & 1u) == 0),
        .round_zero = op, .to_int = to_int };
    } else {
      out_inst.i.vconvert_fp_int = { .m = m, .d = d, .int_unsigned = (op == 0),
        .round_zero = 0, .to_int = to_int };
    }
    return true;
  }

  // A7.7.226 VDIV, T1 encoding (pg A7-575)
  if (((w0 & 0xFFB0u) == 0xEE80u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const vm{u8(w1 & 0xFu)}, vn{u8(w0 & 0xFu)}, vd{u8((w1 >> 12u) & 1u)},
      D{u8((w0 >> 6u) & 1u)}, N{u8((w1 >> 7u) & 1u)}, M{u8((w1 >> 5u) & 1u)};
    out_inst.type = inst_type::VDIV;
    out_inst.i.vdiv = { .d = u8((vd << 1u) | D), .n = u8((vn << 1u) | N),
      .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.229 VLDM, T2 encoding (pg A7-579)
  if (((w0 & 0xFE10u) == 0xEC10u) && ((w1 & 0xF00u) == 0xA00u)) {
    u8 const p{u8((w0 >> 8u) & 1u)}, u{u8((w0 >> 7u) & 1u)}, w{u8((w0 >> 5u) & 1u)},
      n{u8(w0 & 0xFu)}, imm8{u8(w1 & 0xFFu)};
    if ((p == 0) && (u == 0) && (w == 0)) {
      printf("See 64-bit transfers ... on page A6-199\n");
      return false;
    }
    if ((p == 0) && (u == 1) && (w == 1) && (n == 0b1101)) {
      printf("SEE VPOP\n");
      return false;
    }
    if ((p == 1) && (w == 0)) { // A7.7.230 VLDR, T2 encoding (pg A7-581)
      u8 const D{u8((w0 >> 6u) & 1u)}, vd{u8((w1 >> 12u) & 0xFu)};
      out_inst.type = inst_type::VLOAD;
      out_inst.i.vload = { .single_reg = 1u, .add = u8((w0 >> 7u) & 1u), .n = u8(w0 & 0xFu),
        .d = u8((vd << 1) | D), .imm = u16(imm8 << 2u) };
      return true;
    }
    out_inst.type = inst_type::VLOAD_MULT;
    out_inst.i.vload_mult = { .single_regs = 1u, .n = n, .list = imm8, .add = u,
      .imm = u16(imm8 << 2u) };
    return true;
  }

  // A7.7.232 VMOV (imm), T1 encoding (pg A7-585)
  if (((w0 & 0xFFB0u) == 0xEEB0u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const imm4h{u8(w0 & 0xFu)}, imm4l{u8(w1 & 0xFu)}, vd{u8((w1 >> 12u) & 0xFu)},
      D{u8((w0 >> 6u) & 1u)};
    out_inst.type = inst_type::VMOV_IMM;
    out_inst.i.vmov_imm = { .d = u8((D << 4u) | vd), .regs = 1u,
      .imm = decode_vfp_imm8(u8((imm4h << 4u) | imm4l), 32) };
    return true;
  }

  // A7.7.233 VMOV (reg), T1 encoding (pg A7-586)
  if (((w0 & 0xFFBFu) == 0xEEB0u) && ((w1 & 0xFD0u) == 0xA40u)) {
    u8 const vm{u8(w1 & 0xFu)}, vd{u8((w1 >> 12u) & 0xFu)}, M{u8((w1 >> 5u) & 1u)},
      D{u8((w0 >> 6u) & 1u)};
    out_inst.type = inst_type::VMOV_REG;
    out_inst.i.vmov_reg = { .d = u8((vd << 1u) | D), .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.237 VMOV (2 ARM core regsters and a dword reg), T1 encoding (pg A7-590)
  if (((w0 & 0xFFE0u) == 0xEC40u) && ((w1 & 0xFD0u) == 0xB10u)) {
    out_inst.type = inst_type::VMOV_REG_DOUBLE;
    out_inst.i.vmov_reg_double = { .m = u8((w1 & 0xFu) | ((w1 >> 1u) & 0x10u)),
      .t2 = u8(w0 & 0xFu), .t = u8((w1 >> 12u) & 0xFu), .to_arm_regs = u8((w0 >> 4u) & 1u) };
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

  // A7.7.240 VMOV (ARM core reg and single-precision reg), T1 encoding (pg A7-531)
  if (((w0 & 0xFFE0u) == 0xEE00u) && ((w1 & 0xF10u) == 0xA10u)) {
    out_inst.type = inst_type::VMOV_REG_SINGLE;
    out_inst.i.vmov_reg_single = { .to_arm_reg = u8((w0 >> 4u) & 1u),
      .t = u8((w1 >> 12u) & 0xFu), .n = u8(((w0 & 0xFu) << 1u) | ((w1 >> 7u) & 1u)) };
    return true;
  }

  // A7.7.241 VMUL, T1 encoding (pg A7-594)
  if (((w0 & 0xFFB0u) == 0xEE20u) && ((w1 & 0xF50u) == 0xA00u)) {
    u8 const D{u8((w0 >> 6u) & 1u)}, N{u8((w1 >> 7u) & 1u)}, M{u8((w1 >> 5u) & 1u)},
      vd{u8((w1 >> 12u) & 0xFu)}, vm{u8(w1 & 0xFu)}, vn{u8(w0 & 0xFu)};
    out_inst.type = inst_type::VMUL;
    out_inst.i.vmul = { .n = u8((vn << 1u) | N), .m = u8((vm << 1u) | M),
      .d = u8((vd << 1u) | D) };
    return true;
  }

  // A7.7.242 VNEG, T1 encoding (pg A7-595)
  if (((w0 & 0xFFBFu) == 0xEEB1u) && ((w1 & 0xFD0u) == 0xA40u)) {
    u8 const vm{u8(w1 & 0xFu)}, vd{u8((w1 >> 12u) & 0xFu)}, D{u8((w0 >> 6u) & 1u)},
      M{u8((w1 >> 5u) & 1u)};
    out_inst.type = inst_type::VNEG;
    out_inst.i.vneg = { .d = u8((vd << 1u) | D), .m = u8((vm << 1u) | M) };
    return true;
  }

  // A7.7.244 VPOP, T1 encoding (pg A7-599)
  if (((w0 & 0xFFBFu) == 0xECBDu) && ((w1 & 0xF00u) == 0xB00u)) {
    u8 const vd{u8((w1 >> 12u) & 0xFu)}, D{u8((w0 >> 6u) & 1u)};
    u16 const imm8{u16(w1 & 0xFFu)};
    out_inst.type = inst_type::VPOP;
    out_inst.i.vpop = { .single_regs = 0, .regs = u8(imm8 / 2), .imm = u16(imm8 << 2u),
      .d = u8((D << 4u) | vd) };
    return true;
  }

  // A7.7.245 VPUSH, T2 encoding (pg A7-601)
  if (((w0 & 0xFFBFu) == 0xED2Du) && ((w1 & 0xF00u) == 0xB00u)) {
    u8 const vd{u8((w1 >> 12u) & 0xFu)}, D{u8((w0 >> 6u) & 1u)};
    u16 const imm8{u16(w1 & 0xFFu)};
    out_inst.type = inst_type::VPUSH;
    out_inst.i.vpush = { .single_regs = 0, .regs = u8(imm8 / 2), .imm = u16(imm8 << 2u),
      .d = u8((D << 4u) | vd) };
    return true;
  }

  // A7.7.248 VSTR, T2 encoding (pg A7-607)
  if (((w0 & 0xFF30u) == 0xED00u) && ((w1 & 0xF00u) == 0xA00u)) {
    u8 const D{u8((w0 >> 6u) & 1u)}, vd{u8((w1 >> 12u) & 0xFu)};
    u16 const imm8{u16(w1 & 0xFFu)};
    out_inst.type = inst_type::VSTORE;
    out_inst.i.vstore = { .single_reg = 1u, .add = u8((w0 >> 7u) & 1u), .n = u8(w0 & 0xFu),
      .d = u8((vd << 1u) | D), .imm = u16(imm8 << 2u) };
    return true;
  }

  // A7.7.249 VSUB, T1 encoding (pg  A7-609)
  if (((w0 & 0xFFB0u) == 0xEE30u) && ((w1 & 0xF50u) == 0xA40u)) {
    u8 const vm{u8(w1 & 0xFu)}, vn{u8(w0 & 0xFu)}, M{u8((w1 >> 5u) & 1u)},
      N{u8((w1 >> 7u) & 1u)}, D{u8((w0 >> 6u) & 1u)}, vd{u8((w1 >> 12u) & 0xFu)};
    out_inst.type = inst_type::VSUB;
    out_inst.i.vsub = { .d = u8((vd << 1) | D), .n = u8((vn << 1u) | N),
      .m = u8((vm << 1u) | M) };
    return true;
  }

  return false;
}
}

void inst_print(inst const& i) {
#define X(ENUM, TYPE, ...) case inst_type::ENUM: print(i.i.TYPE); return;
  switch (i.type) { INST_TYPE_X_LIST() }
#undef X
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
    case inst_type::BRANCH_XCHG: label = 0; return true;
    case inst_type::BRANCH_LINK: label = i.i.branch_link.addr; return true;
    case inst_type::BRANCH_LINK_XCHG_REG: label = 0; return true; // TODO: register state
    default: break;
  }
  return false;
}

bool inst_is_goto(inst const& i, u32& label) {
  switch (i.type) {
    case inst_type::BRANCH:
      label = i.i.branch.addr; return cond_code_is_always(i.i.branch.cc);
    default: break;
  }
  return false;
}

bool inst_is_table_branch(inst const& i) {
  return (i.type == inst_type::TABLE_BRANCH_HALF) ||
    (i.type == inst_type::TABLE_BRANCH_BYTE);
}

u32 inst_align(u32 val, u32 align) { // Rounding and Aligning, A-16
  // If x and y are integers, Align(x,y) = y * (x DIV y) is an integer.
  return align * (val / align);
}

bool inst_decode(char const *text, u32 func_addr, u32 pc_addr, inst& out_inst) {
  out_inst.type = inst_type::UNKNOWN;
  out_inst.addr = func_addr + pc_addr;
  out_inst.w1 = 0;

  memcpy(&out_inst.w0, &text[pc_addr], 2);
  if (is_16bit_inst(out_inst.w0)) {
    return decode_16bit_inst(out_inst.w0, out_inst);
  }

  memcpy(&out_inst.w1, &text[pc_addr + 2], 2);
  return decode_32bit_inst(out_inst.w0, out_inst.w1, out_inst);
}

