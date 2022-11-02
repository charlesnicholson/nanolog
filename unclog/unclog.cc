#include "nl_args.h"
#include "nl_emit.h"
#include "nl_elf.h"
#include "nl_thumb2.h"
#include "nl_stats.h"

#include <unordered_map>

namespace {

struct state {
  elf e;
  elf_section_hdr32 const *nl_hdr;
  std::vector<elf_symbol32 const*> nl_funcs;
  std::unordered_map<u32, std::vector<elf_symbol32 const*>> non_nl_funcs_sym_map;
  std::unordered_map<u32, char const *> missed_nl_strs_map;
  std::unordered_set<u32> noreturn_func_addrs;
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
      auto [iter, inserted]{
        s.missed_nl_strs_map.insert({u32(uintptr_t(src - base) + nl_str_addr), src})};
      assert(inserted);
      u32 const n{u32(strlen(src) + 1)};
      rem -= n; src += n;
      while (rem && !*src) { --rem; ++src; } // arm-gcc aligns to even addresses
    }
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
          bool ok;
          std::tie(found, ok) = s.non_nl_funcs_sym_map.insert({sym.st_value, {}});
          assert(ok);
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
  (void)log_call_funcs;
  (void)fmt_bin_addrs;
  bytes_ptr pe{new (std::align_val_t{16}) byte[s.e.len]};
  memcpy(&pe[0], &s.e.bytes[0], s.e.len);
  memset(&pe[s.nl_hdr->sh_offset], 0, s.nl_hdr->sh_size);
  memcpy(&pe[s.nl_hdr->sh_offset], fmt_bin_mem.data(), fmt_bin_mem.size());
  auto *patched_nl_hdr{
    (elf_section_hdr32 *)(&pe[0] + (uintptr_t(s.nl_hdr) - uintptr_t(&s.e.bytes[0])))};
  patched_nl_hdr->sh_size = u32(fmt_bin_mem.size());
  thumb2_patch_fmt_strs(s.e, *s.nl_hdr, &pe[0], log_call_funcs, fmt_bin_addrs);
  return pe;
}

bool write_file(void const* buf, unsigned len, char const *output_file) {
  FILE *fp{std::fopen(output_file, "wb")};
  if (!fp) { printf("Unable to open output file %s\n", output_file); return false; }
  bool const ok{std::fwrite(buf, 1, len, fp) == len};
  std::fclose(fp);
  if (!ok) { std::remove(output_file); }
  return ok;
}

void on_log(void *, int, char const *fmt, va_list args) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  vprintf(fmt, args);
#pragma GCC diagnostic pop
}

}

int main(int argc, char const *argv[]) {
  nanolog_set_log_handler(on_log);

  args cmd_args;
  if (!args_parse(argv, argc, cmd_args)) { return 1; }
  cmd_args.noreturn_funcs.push_back("exit");
  cmd_args.noreturn_funcs.push_back("_exit");
  cmd_args.noreturn_funcs.push_back("_mainCRTStartup");

  state s;
  load(s, cmd_args.noreturn_funcs, cmd_args.input_elf);

  NL_LOG_DBG("Nanolog public functions:\n");
  for (auto const& nl_func : s.nl_funcs) {
    NL_LOG_DBG("  0x%08x %s\n", nl_func->st_value & ~1u, &s.e.strtab[nl_func->st_name]);
  }
  NL_LOG_DBG("\n");

  analysis_stats stats;

  std::vector<func_log_call_analysis> log_call_funcs;
  for (auto const& [_, syms] : s.non_nl_funcs_sym_map) {
    func_log_call_analysis lca{*syms[0]};
    if (!thumb2_analyze_func(s.e,
                             lca.func,
                             *s.nl_hdr,
                             s.nl_funcs,
                             s.noreturn_func_addrs,
                             lca,
                             stats)) {
      NL_LOG_ERR("thumb2_analyze_func failed, aborting");
      return 1;
    }

    if (!lca.log_calls.empty()) { log_call_funcs.push_back(lca); }
  }

  NL_LOG_INF("\n%u instructions decoded, %u paths analyzed\n\n",
    stats.decoded_insts, stats.analyzed_paths);

  printf("\nLog calls:\n");
  for (auto const& func: log_call_funcs) {
    printf("  %s\n", &s.e.strtab[func.func.st_name]);
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
        &s.e.bytes[s.nl_hdr->sh_offset + (call.fmt_str_addr - s.nl_hdr->sh_addr)]);

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
  std::vector<u8> fmt_str_sevs;
  for (auto const *ofs{&s.e.bytes[s.nl_hdr->sh_offset]}; auto const& func: log_call_funcs) {
    for (auto const& log_call: func.log_calls) {
      fmt_strs.push_back((char const *)(ofs + (log_call.fmt_str_addr - s.nl_hdr->sh_addr)));
      fmt_str_sevs.push_back(log_call.severity);
    }
  }

  std::vector<u32> fmt_bin_addrs;
  fmt_bin_addrs.reserve(fmt_strs.size());
  byte_vec fmt_bin_mem;
  fmt_bin_mem.reserve(s.nl_hdr->sh_size);
  emit_bin_fmt_strs(fmt_strs, fmt_bin_addrs, fmt_bin_mem);

  printf("\n%u strings, %u addrs, %u string size, %u bin size\n\n",
    unsigned(fmt_strs.size()), unsigned(fmt_bin_addrs.size()),
    unsigned(s.nl_hdr->sh_size), unsigned(fmt_bin_mem.size()));

  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    unsigned char const *src{&fmt_bin_mem[fmt_bin_addrs[i]]};
    printf("  %s\n", fmt_strs[i]);
    printf("    %02hhX ", *src);

    do { ++src; printf("%02hhX ", *src); } while (*src & 0x80);

    do {
      printf("%02hhX ", *++src);
    } while (((*src & 0xFu) != NL_ARG_TYPE_LOG_END) &&
             ((*src >> 4u) != NL_ARG_TYPE_LOG_END));

    printf("\n");
  }

  bytes_ptr patched_elf{patch_elf(s, log_call_funcs, fmt_bin_addrs, fmt_bin_mem)};
  if (!write_file(&patched_elf[0], s.e.len, cmd_args.output_elf)) { return 1; }
  if (!emit_json_manifest(fmt_strs, fmt_str_sevs, cmd_args.output_json)) { return 2; }
  return 0;
}
