#include "nl_elf.h"
#include "nl_print.h"
#include "nl_thumb2.h"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <queue>
#include <string_view>
#include <unordered_map>

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#include "nanoprintf.h"

using u32_vec_t = std::vector<uint32_t>;
using imm_addr_pq_t = std::priority_queue<uint32_t, u32_vec_t, std::greater<uint32_t>>;
using sym_addr_map_t = std::unordered_map<uint32_t, std::vector<elf_symbol32 const*>>;

struct nl_str_desc {
  unsigned guid = 0;
  std::vector<npf_format_spec_t> args;
  char const *str = nullptr;
};

using nl_str_desc_map_t = std::unordered_map<std::string_view, nl_str_desc>;

struct state {
  elf elf;
  elf_section_hdr32 const *nl_hdr;
  std::vector<elf_symbol32 const*> nl_funcs;
  sym_addr_map_t non_nl_funcs_sym_map;
  nl_str_desc_map_t nl_str_desc_map;
};

struct nl_str_ref {
  elf_symbol32 const *func; // function the nanolog call was found in.
  uint32_t addr; // address of the 32-bit immediate load target
  uint32_t imm; // value of the 32-bit immediate load target
  char const *str; // nanolog format string
};

using nl_str_refs_t = std::vector<nl_str_ref>;

namespace {
elf_section_hdr32 const *find_nl_hdr(elf_section_hdr32 const *sec_hdrs,
                                     char const *sec_names,
                                     int sec_n) {
  for (int i = 0; i < sec_n; ++i) {
    elf_section_hdr32 const& sh = sec_hdrs[i];
    if (sh.sh_type && !strcmp(".nanolog", &sec_names[sh.sh_name])) { return &sh; }
  }
  return nullptr;
}

bool load(state& s) {
  if (!load_elf(s.elf, "nrf52832_xxaa.out")) { return false; }
  elf const& e = s.elf;

  // nanolog section
  s.nl_hdr = find_nl_hdr(e.sec_hdrs, e.sec_names, (int)e.elf_hdr->e_shnum);
  assert(s.nl_hdr);

  // nanolog functions, and non-nanolog-function-addr-to-symbol-map
  auto n = e.symtab_hdr->sh_size / e.symtab_hdr->sh_entsize;
  for (auto i = 0u; i < n; ++i) {
    elf_symbol32 const& sym = e.symtab[i];
    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }

    if (strstr(&e.strtab[sym.st_name], "nanolog_") == &e.strtab[sym.st_name]) {
      s.nl_funcs.push_back(&sym);
    } else {
      auto found = s.non_nl_funcs_sym_map.find(sym.st_value);
      if (found == s.non_nl_funcs_sym_map.end()) {
        bool ok;
        std::tie(found, ok) = s.non_nl_funcs_sym_map.insert({sym.st_value, {}});
        assert(ok);
      }
      found->second.push_back(&sym);
    }
  }

  return true;
}

void print(nl_str_desc const &d) {
  printf("Log string descriptor:\n");
  printf("  guid: %d\n", d.guid);
  printf("  str: \"%s\"\n", d.str);
  if (!d.args.empty()) {
    printf("  args:\n");
    for (auto const& arg : d.args) {
      printf("    conv: %d lenmod: %d prec: %d precopt: %d fw: %d fwopt: %d lj: %c"
                " lzp: %c af: %c pp: %c uc: %c\n",
             arg.conv_spec,
             arg.length_modifier,
             arg.prec,
             arg.prec_opt,
             arg.field_width,
             arg.field_width_opt,
             arg.left_justified ? arg.left_justified : ' ',
             arg.leading_zero_pad ? arg.leading_zero_pad : ' ',
             arg.alt_form ? arg.alt_form : ' ',
             arg.prepend ? arg.prepend : ' ',
             arg.case_adjust ? arg.case_adjust : ' ');
    }
  }
}

elf_symbol32 const *get_nl_func(state const& s, uint32_t cand) {
  for (auto const *nl_func : s.nl_funcs) {
    if ((nl_func->st_value & ~1u) == cand) { return nl_func; }
  }

  return nullptr;
}

static bool is_32bit_instr(uint16_t const hw1, uint16_t const hw2) {
  // this could be a single simd instruction
  bool const dp_imm = ((hw1 & 0xF800) == 0xF000) && ((hw2 & 0x8000) == 0x0000);
  bool const dp_nimm = (hw1 & 0xEE00) == 0xEA00;
  bool const ls_mem = (hw1 & 0xFE00) == 0xF800;
  bool const ls_de_tb = (hw1 & 0xFE40) == 0xE840;
  bool const lsm_rfe_srs = (hw1 & 0xFE40) == 0xE800;
  bool const b_misc = ((hw1 & 0xF800) == 0xF000) && ((hw2 & 0x8000) == 0x8000);
  bool const coproc = (hw1 & 0xFF00) == 0x7F00;
  return dp_imm || dp_nimm || ls_mem || ls_de_tb || lsm_rfe_srs || b_misc || coproc;
}

static bool is_bl_imm(uint16_t const hw1, uint16_t const hw2) {
  return ((hw1 & 0xF800) == 0xF000) && ((hw2 & 0xD000) == 0xD000);
}

static bool is_ld_lit(uint16_t const inst) {
  return (inst & 0xF800) == 0x4800;
}

void accumulate_log_str_refs_from_func(state const& s,
                                       sym_addr_map_t::value_type const& func,
                                       nl_str_refs_t& nl_str_refs) {

  elf_symbol32 const& func_sym = *func.second[0];
  elf_section_hdr32 const& func_sec_hdr = s.elf.sec_hdrs[func_sym.st_shndx];
  uint32_t const func_start = (func_sym.st_value - func_sec_hdr.sh_addr) & ~1u;
  uint32_t const func_end = func_start + func_sym.st_size;

  printf("Scanning %s: %x (%x-%x):\n",
         &s.elf.strtab[func_sym.st_name],
         func_sym.st_value,
         func_start,
         func_end);

  imm_addr_pq_t imm_addrs;
  uint32_t last_seen_r0_load = 0;

  auto i = func_start;
  while (i < func_end) {
    bool on_imm_addr = false;
    while (!imm_addrs.empty() && (imm_addrs.top() == i)) {
      on_imm_addr = true;
      imm_addrs.pop();
    }
    if (on_imm_addr) { i += 4; continue; }

    uint16_t w0;
    memcpy(&w0, &s.elf.bytes[i + func_sec_hdr.sh_offset], 2);
    i += 2;

    if (i < func_end) {
      uint16_t w1;
      memcpy(&w1, &s.elf.bytes[i + func_sec_hdr.sh_offset], 2);

      if (is_32bit_instr(w0, w1)) {
        i += 2;
        if (is_bl_imm(w0, w1)) {
          uint32_t const sbit = (w0 >> 10u) & 1u;
          uint32_t const sext = ((sbit ^ 1u) - 1u) & 0xFF000000u;
          uint32_t const j1 = (w1 >> 13u) & 1u;
          uint32_t const j2 = (w1 >> 11u) & 1u;
          uint32_t const i1 = (1u - (j1 ^ sbit)) << 23u;
          uint32_t const i2 = (1u - (j2 ^ sbit)) << 22u;
          uint32_t const imm10 = (w0 & 0x3FFu) << 12u;
          uint32_t const imm11 = (w1 & 0x7FFu) << 1u;
          uint32_t const imm32 = sext | i1 | i2 | imm10 | imm11;
          uint32_t const target = i + imm32 + func_sec_hdr.sh_addr;

          elf_symbol32 const* nl_func = get_nl_func(s, target);
          if (nl_func) {
            assert(last_seen_r0_load);

            uint32_t const imm32_offset =
              func_sec_hdr.sh_offset + (last_seen_r0_load - func_sec_hdr.sh_addr);

            uint32_t nl_str_imm32;
            memcpy(&nl_str_imm32, &s.elf.bytes[imm32_offset], 4);

            uint32_t const log_str_off =
              s.nl_hdr->sh_offset + (nl_str_imm32 - s.nl_hdr->sh_addr);

            printf("  Found bl @ %x: (%x %s), load r0 from 0x%08x: \"%s\"\n",
                   func_sec_hdr.sh_addr + i - 4,
                   target,
                   &s.elf.strtab[nl_func->st_name],
                   last_seen_r0_load,
                   &s.elf.bytes[log_str_off]);

            nl_str_refs.push_back({func.second[0],
                                       last_seen_r0_load,
                                       nl_str_imm32,
                                       &s.elf.bytes[log_str_off]});
          }

          continue;
        }
      }
    }

    if (is_ld_lit(w0)) { // ldr rX, [pc, #YY]
      uint32_t const rt = (w0 >> 8u) & 7u;
      uint32_t const imm = ((i + 2u) & ~3u) + ((w0 & 0xFFu) << 2u);
      imm_addrs.push(imm);
      if (!rt) { last_seen_r0_load = imm + func_sec_hdr.sh_addr; }
      continue;
    }
  }
}

nl_str_refs_t get_log_str_refs(state const& s) {
  nl_str_refs_t log_str_refs;

  for (auto const& func_syms : s.non_nl_funcs_sym_map) {
    accumulate_log_str_refs_from_func(s, func_syms, log_str_refs);
  }

  return log_str_refs;
}

nl_str_desc_map_t build_nl_str_desc_map(nl_str_refs_t const& nl_str_refs) {
  unsigned guid = 0;
  nl_str_desc_map_t m;
  for (auto const &nl_str_ref : nl_str_refs) {
    auto [val, inserted] = m.insert({nl_str_ref.str, nl_str_desc{}});
    if (inserted) {
      val->second.guid = guid++;
      val->second.str = nl_str_ref.str;

      char const *cur = nl_str_ref.str;
      while (*cur) {
        npf_format_spec_t fs;
        int const n = (*cur != '%') ? 0 : npf_parse_format_spec(cur, &fs);
        if (n) {
          val->second.args.push_back(fs);
          cur += n;
        } else {
          ++cur;
        }
      }
    }
  }
  return m;
}
}

int main(int, char const *[]) {
  state s;
  load(s);
  elf const& e = s.elf;

  /*
  print(*s.elf_hdr);
  printf("\n");
  for (auto i = 0u; i < s.elf_hdr->e_phnum; ++i) { print(s.prog_hdrs[i]); }
  printf("\n");
  */

  for (auto i = 0u; i < e.elf_hdr->e_shnum; ++i) { nl_print(e.sec_hdrs[i], e.sec_names); }
  printf("\n");

  printf("Non-nanolog functions:\n");
  for (auto const& sym_entry : s.non_nl_funcs_sym_map) {
    printf("  0x%08x ", sym_entry.first);
    for (auto const* sym : sym_entry.second) {
      printf("%s ", &e.strtab[sym->st_name]);
    }
    printf("\n");
  }
  printf("\n");

  printf("Nanolog public functions:\n");
  for (auto const& nl_func : s.nl_funcs) {
    printf("  0x%08x %s\n", nl_func->st_value & ~1u, &e.strtab[nl_func->st_name]);
  }
  printf("\n");

  for (auto const& func_syms : s.non_nl_funcs_sym_map) {
    thumb2_find_log_strs_in_func(e, *func_syms.second[0]);
  }
  return 0;

  //nl_str_refs_t const nl_str_refs = get_log_str_refs(s);
  //printf("\n");

  //printf(".nanolog string references:\n");
  //for (auto const& nl_str_ref : nl_str_refs) {
  //  printf("  0x%08x %x \"%s\"\n",
  //         nl_str_ref.addr,
  //         nl_str_ref.imm,
  //         nl_str_ref.str);
  //}
  //printf("\n");

  //nl_str_desc_map_t const nl_str_desc_map = build_nl_str_desc_map(nl_str_refs);
  //for (auto const& nl_str_desc : nl_str_desc_map) {
  //  print(nl_str_desc.second);
  //}

  //return 0;
}
