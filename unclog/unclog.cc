#include "args.h"
#include "emit.h"
#include "elf.h"
#include "thumb2.h"
#include "stats.h"

#include <unordered_map>

namespace {

struct state {
  elf e;
  elf_section_hdr32 const *nl_hdr = nullptr;
  std::vector<elf_symbol32 const*> nl_funcs;
  std::unordered_map<u32, std::vector<elf_symbol32 const*>> non_nl_funcs_sym_map;
  std::unordered_map<u32, char const *> missed_nl_strs_map;
  std::unordered_set<u32> noreturn_func_addrs;
  unsigned log_str_cnt = 0;
};

elf_section_hdr32 const *find_nl_hdr(elf_section_hdr32 const *sec_hdrs,
                                     char const *sec_names,
                                     int sec_n) {
  auto const it = std::find_if(sec_hdrs, &sec_hdrs[sec_n], [&sec_names](auto const& sh) {
    return sh.sh_type && !strcmp(".nanolog", &sec_names[sh.sh_name]); });
  return (it == &sec_hdrs[sec_n]) ? nullptr : &*it;
}

bool load(state& s, std::vector<char const *> const& noreturn_funcs, char const *filename) {
  if (!nl_elf_load(s.e, filename)) { return false; }

  s.nl_hdr = find_nl_hdr(s.e.sec_hdrs, s.e.sec_names, (int)s.e.elf_hdr->e_shnum);
  if (!s.nl_hdr) { NL_LOG_ERR("%s has no .nanolog section\n", filename); return false; }

  {  // populate the "missed strings" map
    auto const nl_str_off{s.nl_hdr->sh_offset}, nl_str_addr{s.nl_hdr->sh_addr};
    auto const *src{(char const *)&s.e.bytes[nl_str_off]}, *base{src};
    u32 rem{s.nl_hdr->sh_size};
    while (rem) {
      s.missed_nl_strs_map.insert({u32(uintptr_t(src - base) + nl_str_addr), src});
      u32 const n{u32(strlen(src) + 1)};
      rem -= n; src += n;
      while (rem && !*src) { --rem; ++src; } // arm-gcc aligns to even addresses
    }
    s.log_str_cnt = unsigned(s.missed_nl_strs_map.size());
  }

  for (auto i{0u}, n{s.e.symtab_hdr->sh_size / s.e.symtab_hdr->sh_entsize}; i < n; ++i) {
    elf_symbol32 const& sym{s.e.symtab[i]};
    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }
    char const *name{&s.e.strtab[sym.st_name]};

    if (strstr(name, "nanolog_") == name) {
      s.nl_funcs.push_back(&sym);
    } else {
      { // noreturn functions
        auto found{std::find_if(std::begin(noreturn_funcs), std::end(noreturn_funcs),
          [name](char const *f) { return !strcmp(f, name); })};
        if (found != std::end(noreturn_funcs)) {
          s.noreturn_func_addrs.insert({u32(sym.st_value & ~1u)});
        }
      }

      { // non-nanolog-function-address to symbol map
        auto found{s.non_nl_funcs_sym_map.find(sym.st_value)};
        if (found == std::end(s.non_nl_funcs_sym_map)) {
          found = s.non_nl_funcs_sym_map.insert({sym.st_value, {}}).first;
        }
        found->second.push_back(&sym);
      }
    }
  }

  return true;
}

bytes_ptr patch_elf(state const& s,
                    std::vector<func_log_call_analysis> const& log_call_funcs,
                    std::vector<u32> const& fmt_bin_addrs,
                    byte_vec const& fmt_bin_mem) {
  bytes_ptr pe{alloc_bytes(16, s.e.len)};
  memcpy(&pe[0], &s.e.bytes[0], s.e.len);
  memset(&pe[s.nl_hdr->sh_offset], 0, s.nl_hdr->sh_size);
  memcpy(&pe[s.nl_hdr->sh_offset], fmt_bin_mem.data(), fmt_bin_mem.size());
  auto *patched_nl_hdr{
    (elf_section_hdr32 *)(&pe[0] + (uintptr_t(s.nl_hdr) - uintptr_t(&s.e.bytes[0])))};
  patched_nl_hdr->sh_size = u32(fmt_bin_mem.size());

  return thumb2_patch_fmt_strs(s.e, *s.nl_hdr, &pe[0], log_call_funcs, fmt_bin_addrs) ?
    std::move(pe) : bytes_ptr{};
}

bool write_file(void const* buf, unsigned len, char const *output_file) {
  bool const ok{[&]() { // undefined to remove() an open file pointer
    file_ptr f{open_file(output_file, "wb")};
    if (!f.get()) {
      NL_LOG_ERR("Unable to open output file %s\n", output_file);
      return false;
    }
    return std::fwrite(buf, 1, len, f.get()) == len;
  }()};

  if (!ok) { std::remove(output_file); }
  return ok;
}

void on_log(void *, int, char const *fmt, va_list args) {
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  vprintf(fmt, args);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
}

}

int main(int argc, char const *argv[]) {
  nanolog_set_log_handler(on_log);

  args cmd_args;
  if (!args_parse(argv, argc, cmd_args)) { return 1; }
  cmd_args.noreturn_funcs.push_back("exit");
  cmd_args.noreturn_funcs.push_back("_exit");
  cmd_args.noreturn_funcs.push_back("_mainCRTStartup");

  nanolog_set_log_threshold(cmd_args.log_threshold);

  state s;
  if (!load(s, cmd_args.noreturn_funcs, cmd_args.input_elf)) { return 1; }

  analysis_stats stats;

  std::vector<func_log_call_analysis> log_call_funcs;
  for (auto const& [_, syms] : s.non_nl_funcs_sym_map) {
    func_log_call_analysis lca{*syms[0]};
    switch (NL_EXPECT(thumb2_analyze_func(s.e, lca.func, *s.nl_hdr, s.nl_funcs,
            s.noreturn_func_addrs, lca, stats), thumb2_analyze_func_ret::SUCCESS)) {
      case thumb2_analyze_func_ret::SUCCESS: break;

      case thumb2_analyze_func_ret::ERR_INSTRUCTION_DECODE:
        NL_LOG_ERR("Error decoding instruction, aborting");
        if (nanolog_get_log_threshold() > NL_SEV_DEBUG) {
          NL_LOG_ERR("  (re-run with -vv to see decoding error)\n");
        }
        return 1;

      case thumb2_analyze_func_ret::ERR_SIMULATE_LOGIC_INCOMPLETE:
        NL_LOG_ERR("Error simulating function, aborting");
        if (nanolog_get_log_threshold() > NL_SEV_DEBUG) {
          NL_LOG_ERR("  (re-run with -vv to see simulation error)\n");
        }
        return 1;

      case thumb2_analyze_func_ret::ERR_UNKNOWN_LOG_CALL_STRATEGY:
        NL_LOG_ERR("Error analyzing log call strategy, aborting");
        if (nanolog_get_log_threshold() > NL_SEV_DEBUG) {
          NL_LOG_ERR("  (re-run with -vv to see details)\n");
        }
        return 1;

      case thumb2_analyze_func_ret::ERR_RAN_OFF_END_OF_FUNC: {
        NL_LOG_ERR("\"%s\" simulation error: simulator ran off the end of the function.  "
                   "If any of the following functions have noreturn semantics, "
                   "add them to the command-line as \"--noreturn-func\" arguments:\n",
          &s.e.strtab[lca.func.st_name]);

        for (u32_set const subs{lca.subs.begin(), lca.subs.end()}; auto addr : subs) {
          auto const found{s.non_nl_funcs_sym_map.find(addr | 1)};
          NL_LOG_ERR("  %s\n", &s.e.strtab[found->second[0]->st_name], addr);
        }
        NL_LOG_ERR("\n");
      } break;
    }

    if (!lca.log_calls.empty()) { log_call_funcs.push_back(lca); }
  }

  NL_LOG_DBG("\n%u instructions decoded, %u paths analyzed\n\n",
    stats.decoded_insts, stats.analyzed_paths);

  NL_LOG_DBG("\nLog calls:\n");
  for (auto const& f : log_call_funcs) {
    NL_LOG_DBG("  %s\n", &s.e.strtab[f.func.st_name]);
    for (auto const& lc : f.log_calls) {
      reg_mut_node const& r0_mut = f.reg_muts[lc.node_idx];

      NL_LOG_DBG("    %x: %s r0 at %x: ", lc.log_func_call_addr, fmt_str_strat_name(lc.s),
        r0_mut.i.addr);

      switch (lc.s) {
        case fmt_str_strat::DIRECT_LOAD:
          NL_LOG_DBG("literal at %x: ", r0_mut.i.i.load_lit.addr);
          break;

        case fmt_str_strat::MOV_FROM_DIRECT_LOAD:
          NL_LOG_DBG("from r%u at %x, literal at %x: ",
            r0_mut.i.i.mov_reg.m,
            f.reg_muts[r0_mut.par_idxs[0]].i.addr,
            f.reg_muts[r0_mut.par_idxs[0]].i.i.load_lit.addr);
          break;

        case fmt_str_strat::ADD_IMM_FROM_BASE_REG:
          NL_LOG_DBG("add imm from base: ");
          break;
      }

      NL_LOG_DBG("\"%s\"\n",
        &s.e.bytes[s.nl_hdr->sh_offset + (lc.fmt_str_addr - s.nl_hdr->sh_addr)]);

      s.missed_nl_strs_map.erase(lc.fmt_str_addr);
    }
  }

  if (!s.missed_nl_strs_map.empty()) {
    NL_LOG_ERR("\nMissed format strings:\n");
    for (auto const& [addr, str] : s.missed_nl_strs_map) {
      NL_LOG_ERR("  %x: \"%s\"\n", addr, str);
    }
    return 1;
  }

  std::vector<char const *> fmt_strs;
  std::vector<u8> fmt_str_sevs;
  fmt_strs.reserve(s.log_str_cnt);
  fmt_str_sevs.reserve(s.log_str_cnt);
  for (auto const *ofs{&s.e.bytes[s.nl_hdr->sh_offset]}; auto const& f : log_call_funcs) {
    for (auto const& lc : f.log_calls) {
      fmt_strs.push_back((char const *)(ofs + (lc.fmt_str_addr - s.nl_hdr->sh_addr)));
      fmt_str_sevs.push_back(lc.severity);
    }
  }

  u32_vec fmt_bin_addrs;
  fmt_bin_addrs.reserve(fmt_strs.size());
  byte_vec fmt_bin_mem;
  fmt_bin_mem.reserve(s.nl_hdr->sh_size);
  emit_bin_fmt_strs(fmt_strs, fmt_bin_addrs, fmt_bin_mem);

  NL_LOG_INF("\n%u strings, %u addrs, %u string size, %u bin size\n\n",
    unsigned(fmt_strs.size()), unsigned(fmt_bin_addrs.size()),
    unsigned(s.nl_hdr->sh_size), unsigned(fmt_bin_mem.size()));

  if (NL_UNLIKELY(nanolog_get_log_threshold() == NL_SEV_DEBUG)) {
    for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
      unsigned char const *src{&fmt_bin_mem[fmt_bin_addrs[i]]};
      NL_LOG_DBG("  %s\n", fmt_strs[i]);
      NL_LOG_DBG("    %02hhX ", *src);

      do { ++src; NL_LOG_DBG("%02hhX ", *src); } while (*src & 0x80);

      do {
        NL_LOG_DBG("%02hhX ", *++src);
      } while (((*src & 0xFu) != NL_ARG_TYPE_LOG_END) &&
               ((*src >> 4u) != NL_ARG_TYPE_LOG_END));

      NL_LOG_DBG("\n");
    }
  }

  bytes_ptr patched_elf{patch_elf(s, log_call_funcs, fmt_bin_addrs, fmt_bin_mem)};
  if (!patched_elf) { return 3; }
  if (!write_file(&patched_elf[0], s.e.len, cmd_args.output_elf)) { return 1; }
  if (!emit_json_manifest(fmt_strs, fmt_str_sevs, cmd_args.output_json)) { return 2; }
  return 0;
}
