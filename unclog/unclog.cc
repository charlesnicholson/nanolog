#include "nl_elf.h"
#include "nl_thumb2.h"
#include "nl_stats.h"
#include "../nanolog.h"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <queue>
#include <unordered_map>

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 1
#include "nanoprintf.h"

using u32_vec_t = std::vector<uint32_t>;
using imm_addr_pq_t = std::priority_queue<u32, u32_vec_t, std::greater<u32>>;
using sym_addr_map_t = std::unordered_map<u32, std::vector<elf_symbol32 const*>>;
using str_addr_map_t = std::unordered_map<u32, char const *>;

struct state {
  elf elf;
  elf_section_hdr32 const *nl_hdr;
  std::vector<elf_symbol32 const*> nl_funcs;
  sym_addr_map_t non_nl_funcs_sym_map;
  str_addr_map_t missed_nl_strs_map;
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
    elf_section_hdr32 const& sh{sec_hdrs[i]};
    if (sh.sh_type && !strcmp(".nanolog", &sec_names[sh.sh_name])) { return &sh; }
  }
  return nullptr;
}

bool load(state& s, char const *filename) {
  if (!nl_elf_load(s.elf, filename)) { return false; }
  elf const& e{s.elf};

  // nanolog section
  s.nl_hdr = find_nl_hdr(e.sec_hdrs, e.sec_names, (int)e.elf_hdr->e_shnum);
  assert(s.nl_hdr);

  {  // populate the "missed strings" map
    u32 const nl_str_off{s.nl_hdr->sh_offset}, nl_str_addr{s.nl_hdr->sh_addr};
    char const *src{&e.bytes[nl_str_off]}, *b{src};
    u32 rem{s.nl_hdr->sh_size};
    auto& m{s.missed_nl_strs_map};
    while (rem) {
      auto [iter, inserted] = m.insert({u32(uintptr_t(src - b) + nl_str_addr), src});
      assert(inserted);
      u32 const n{u32(strlen(src) + 1)};
      rem -= n; src += n;
      while (rem && !*src) { --rem; ++src; }
    }
  }

  // nanolog functions, and non-nanolog-function-addr-to-symbol-map
  auto const n{e.symtab_hdr->sh_size / e.symtab_hdr->sh_entsize};
  for (auto i{0u}; i < n; ++i) {
    elf_symbol32 const& sym{e.symtab[i]};
    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }

    if (strstr(&e.strtab[sym.st_name], "nanolog_") == &e.strtab[sym.st_name]) {
      s.nl_funcs.push_back(&sym);
    } else {
      auto found{s.non_nl_funcs_sym_map.find(sym.st_value)};
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

void convert_strings_to_bins(std::vector<char const *> const& fmt_strs,
                             std::vector<u32>& fmt_bin_addrs,
                             std::vector<unsigned char>& fmt_bin_mem) {
  for (auto str: fmt_strs) {
    fmt_bin_addrs.push_back(unsigned(fmt_bin_mem.size()));
    auto guid{fmt_bin_addrs.empty() ? 0 : unsigned(fmt_bin_addrs.size() - 1)};

    fmt_bin_mem.push_back(NL_BINARY_PREFIX_MARKER);

    do { // varint encode
      u8 b{u8(guid & 0x7Fu)};
      if (guid >>= 7u) { b |= 0x80; }
      fmt_bin_mem.push_back(b);
    } while (guid);

    int field_count{0};
    char const *cur{str};
    while (*cur) {
      npf_format_spec_t fs;
      int const n{(*cur != '%') ? 0 : npf_parse_format_spec(cur, &fs)};
      if (!n) { ++cur; continue; }
      cur += n;

      bool added_field{false};
      unsigned char field{0};

      switch (fs.conv_spec) {
        case NPF_FMT_SPEC_CONV_WRITEBACK:
        case NPF_FMT_SPEC_CONV_PERCENT:
          break;

        case NPF_FMT_SPEC_CONV_CHAR:
          switch (fs.length_modifier) {
            case NPF_FMT_SPEC_LEN_MOD_NONE:
              field = char(NL_VARARG_TYPE_SCALAR_1_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LONG:
              field = char(NL_VARARG_TYPE_WINT_T); added_field = true; break;
            default: break;
          } break;

        case NPF_FMT_SPEC_CONV_POINTER:
        case NPF_FMT_SPEC_CONV_STRING:
          field = char(NL_VARARG_TYPE_POINTER); added_field = true; break;

        case NPF_FMT_SPEC_CONV_BINARY:
        case NPF_FMT_SPEC_CONV_OCTAL:
        case NPF_FMT_SPEC_CONV_HEX_INT:
        case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
        case NPF_FMT_SPEC_CONV_SIGNED_INT:
          switch (fs.length_modifier) {
            case NPF_FMT_SPEC_LEN_MOD_CHAR:
              field = char(NL_VARARG_TYPE_SCALAR_1_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_SHORT:
              field = char(NL_VARARG_TYPE_SCALAR_2_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_NONE:
            case NPF_FMT_SPEC_LEN_MOD_LONG:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_SIZET:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT:
              field = char(NL_VARARG_TYPE_SCALAR_4_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LARGE_LONG_LONG:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_INTMAX:
              field = char(NL_VARARG_TYPE_SCALAR_8_BYTE); added_field = true; break;
            default: break;
          } break;

        case NPF_FMT_SPEC_CONV_FLOAT_DEC:
        case NPF_FMT_SPEC_CONV_FLOAT_SCI:
        case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
        case NPF_FMT_SPEC_CONV_FLOAT_HEX:
          switch (fs.length_modifier) {
            case NPF_FMT_SPEC_LEN_MOD_NONE:
              field = char(NL_VARARG_TYPE_DOUBLE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LONG:
              field = char(NL_VARARG_TYPE_LONG_DOUBLE); added_field = true; break;
            default: break;
          } break;
      }

      if (added_field) {
        if (field_count++ & 1) {
          fmt_bin_mem[fmt_bin_mem.size() - 1] |= (unsigned char)(field << 4u);
        } else {
          fmt_bin_mem.push_back((unsigned char)field);
        }
      }
    }

    if (field_count & 1) {
      fmt_bin_mem[fmt_bin_mem.size() - 1] |=
        (unsigned char)(NL_VARARG_TYPE_END_OF_LIST << 4u);
    } else {
      fmt_bin_mem.push_back(NL_VARARG_TYPE_END_OF_LIST);
    }
  }
}

void on_log(int sev, char const *fmt, va_list args) {
  (void)sev;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  vprintf(fmt, args);
#pragma GCC diagnostic pop
}

}

int main(int argc, char const *argv[]) {
  nanolog_set_log_handler(on_log);

  assert(argc > 1);
  state s;
  load(s, argv[1]);
  auto const& e{s.elf};

  printf("Nanolog public functions:\n");
  for (auto const& nl_func : s.nl_funcs) {
    printf("  0x%08x %s\n", nl_func->st_value & ~1u, &e.strtab[nl_func->st_name]);
  }
  printf("\n");

  analysis_stats stats;

  std::vector<func_log_call_analysis> log_call_funcs;
  for (auto const& [_, syms] : s.non_nl_funcs_sym_map) {
    func_log_call_analysis lca{*syms[0]};
    thumb2_analyze_func(e, lca.func, s.nl_funcs, lca, stats);
    if (!lca.log_calls.empty()) { log_call_funcs.push_back(lca); }
  }

  printf("\n%u instructions decoded, %u paths analyzed\n\n",
    stats.decoded_insts, stats.analyzed_paths);

  printf("\nLog calls:\n");
  for (auto const& func: log_call_funcs) {
    printf("  %s\n", &e.strtab[func.func.st_name]);
    for (auto const& call: func.log_calls) {
      reg_mut_node const& r0_mut = func.reg_muts[call.node_idx];

      printf("    %x: %s r0 at %x: ", call.log_func_call_addr, fmt_str_strat_name(call.s),
        r0_mut.i.addr);

      switch (call.s) {
        case fmt_str_strat::DIRECT_LOAD:
          printf("literal at %x: ", r0_mut.i.i.load_lit.addr);
          break;

        case fmt_str_strat::MOV_FROM_DIRECT_LOAD:
          printf("from r%u at %x, literal at %x: ",
            r0_mut.i.i.mov_reg.m,
            func.reg_muts[r0_mut.par_idxs[0]].i.addr,
            func.reg_muts[r0_mut.par_idxs[0]].i.i.load_lit.addr);
          break;

        case fmt_str_strat::ADD_IMM_FROM_BASE_REG:
          printf("add imm from base: ");
          break;
      }

      printf("\"%s\"\n",
        &e.bytes[s.nl_hdr->sh_offset + (call.fmt_str_addr - s.nl_hdr->sh_addr)]);

      s.missed_nl_strs_map.erase(call.fmt_str_addr);
    }
  }

  if (!s.missed_nl_strs_map.empty()) {
    printf("\nMissed format strings:\n");
    for (auto const& [addr, str]: s.missed_nl_strs_map) {
      printf("  %x: \"%s\"\n", addr, str);
    }
  }

  std::vector<char const *> fmt_strs;
  for (auto const *ofs{&e.bytes[s.nl_hdr->sh_offset]}; auto const& func: log_call_funcs) {
    for (auto const& log_call: func.log_calls) {
      fmt_strs.push_back(ofs + (log_call.fmt_str_addr - s.nl_hdr->sh_addr));
    }
  }

  std::vector<u32> fmt_bin_addrs;
  fmt_bin_addrs.reserve(fmt_strs.size());
  std::vector<unsigned char> fmt_bin_mem;
  fmt_bin_mem.reserve(s.nl_hdr->sh_size);
  convert_strings_to_bins(fmt_strs, fmt_bin_addrs, fmt_bin_mem);

  printf("\n%u strings, %u addrs, %u string size, %u bin size\n\n",
    unsigned(fmt_strs.size()), unsigned(fmt_bin_addrs.size()),
    unsigned(s.nl_hdr->sh_size), unsigned(fmt_bin_mem.size()));

  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    unsigned char const *src = &fmt_bin_mem[fmt_bin_addrs[i]];
    printf("  %s\n", fmt_strs[i]);
    printf("    %02hhX ", *src);

    do { ++src; printf("%02hhX ", *src); } while (*src & 0x80);

    do {
      printf("%02hhX ", *++src);
    } while (((*src & 0xFu) != NL_VARARG_TYPE_END_OF_LIST) &&
             ((*src >> 4u) != NL_VARARG_TYPE_END_OF_LIST));

    printf("\n");
  }

  return 0;
}
