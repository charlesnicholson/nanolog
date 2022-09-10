#include "nl_elf.h"
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
  if (!nl_elf_load(s.elf, "nrf52832_xxaa.out")) { return false; }
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

  for (auto i = 0u; i < e.elf_hdr->e_shnum; ++i) {
    nl_elf_print(e.sec_hdrs[i], e.sec_names);
  }
  printf("\n");

  printf("Non-nanolog functions:\n");
  for (auto const& sym_entry : s.non_nl_funcs_sym_map) {
    printf("  0x%08x ", sym_entry.first);
    for (auto const* sym : sym_entry.second) {
      printf("%s", &e.strtab[sym->st_name]);
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
