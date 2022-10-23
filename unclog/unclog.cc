#include "nl_args.h"
#include "nl_bin_strings.h"
#include "nl_elf.h"
#include "nl_thumb2.h"
#include "nl_stats.h"
#include "../nanolog.h"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <queue>
#include <unordered_map>

namespace {

using sym_addr_map_t = std::unordered_map<u32, std::vector<elf_symbol32 const*>>;

struct state {
  elf elf;
  elf_section_hdr32 const *nl_hdr;
  std::vector<elf_symbol32 const*> nl_funcs;
  sym_addr_map_t non_nl_funcs_sym_map;
  std::unordered_map<u32, char const *> missed_nl_strs_map;
};

elf_section_hdr32 const *find_nl_hdr(elf_section_hdr32 const *sec_hdrs, char const *sec_names, int sec_n) {
  auto const it = std::find_if(sec_hdrs, &sec_hdrs[sec_n],
    [&sec_names](auto const& sh) { return sh.sh_type && !strcmp(".nanolog", &sec_names[sh.sh_name]); });
  return (it == &sec_hdrs[sec_n]) ? nullptr : &*it;
}

bool load(state& s, char const *filename) {
  if (!nl_elf_load(s.elf, filename)) { return false; }

  // nanolog section
  s.nl_hdr = find_nl_hdr(s.elf.sec_hdrs, s.elf.sec_names, (int)s.elf.elf_hdr->e_shnum);
  assert(s.nl_hdr);

  {  // populate the "missed strings" map
    u32 const nl_str_off{s.nl_hdr->sh_offset}, nl_str_addr{s.nl_hdr->sh_addr};
    char const *src{&s.elf.bytes[nl_str_off]}, *b{src};
    u32 rem{s.nl_hdr->sh_size};
    auto& m{s.missed_nl_strs_map};
    while (rem) {
      auto [iter, inserted] = m.insert({u32(uintptr_t(src - b) + nl_str_addr), src});
      assert(inserted);
      u32 const n{u32(strlen(src) + 1)};
      rem -= n; src += n;
      while (rem && !*src) { --rem; ++src; } // arm-gcc aligns to even addresses
    }
  }

  // nanolog functions, and non-nanolog-function-addr-to-symbol-map
  auto const n{s.elf.symtab_hdr->sh_size / s.elf.symtab_hdr->sh_entsize};
  for (auto i{0u}; i < n; ++i) {
    elf_symbol32 const& sym{s.elf.symtab[i]};
    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }

    if (strstr(&s.elf.strtab[sym.st_name], "nanolog_") == &s.elf.strtab[sym.st_name]) {
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

  args cmd_args;
  if (!args_parse(argv, argc, cmd_args)) {
    NL_LOG_ERR("Arg parse failure");
    return 1;
  }

  state s;
  load(s, cmd_args.input_file);

  printf("Nanolog public functions:\n");
  for (auto const& nl_func : s.nl_funcs) {
    printf("  0x%08x %s\n", nl_func->st_value & ~1u, &s.elf.strtab[nl_func->st_name]);
  }
  printf("\n");

  analysis_stats stats;

  std::vector<func_log_call_analysis> log_call_funcs;
  for (auto const& [_, syms] : s.non_nl_funcs_sym_map) {
    func_log_call_analysis lca{*syms[0]};
    thumb2_analyze_func(s.elf, lca.func, s.nl_funcs, lca, stats);
    if (!lca.log_calls.empty()) { log_call_funcs.push_back(lca); }
  }

  printf("\n%u instructions decoded, %u paths analyzed\n\n",
    stats.decoded_insts, stats.analyzed_paths);

  printf("\nLog calls:\n");
  for (auto const& func: log_call_funcs) {
    printf("  %s\n", &s.elf.strtab[func.func.st_name]);
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
        &s.elf.bytes[s.nl_hdr->sh_offset + (call.fmt_str_addr - s.nl_hdr->sh_addr)]);

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
  for (auto const *ofs{&s.elf.bytes[s.nl_hdr->sh_offset]};
       auto const& func: log_call_funcs) {
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
