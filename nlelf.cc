#include <cassert>
#include <cstdio>
#include <cstdint>
#include <queue>
#include <string_view>
#include <unordered_map>
#include <vector>

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#include "nanoprintf.h"

#define ELF_OSABI_X_LIST() \
  X(ELF_OSABI_SYSTEM_V, 0x00) \
  X(ELF_OSABI_HP_UX, 0x01) \
  X(ELF_OSABI_NETBSD, 0x02) \
  X(ELF_OSABI_LINUX, 0x03) \
  X(ELF_OSABI_GNU_HURD, 0x04) \
  X(ELF_OSABI_SOLARIS, 0x06) \
  X(ELF_OSABI_AIX, 0x07) \
  X(ELF_OSABI_IRIX, 0x08) \
  X(ELF_OSABI_FREEBSD, 0x09) \
  X(ELF_OSABI_TRU64, 0x0A) \
  X(ELF_OSABI_NOVELL_MODESTO, 0x0B) \
  X(ELF_OSABI_OPENBSD, 0x0C) \
  X(ELF_OSABI_OPENVSM, 0x0D) \
  X(ELF_OSABI_NONSTOP, 0x0E) \
  X(ELF_OSABI_AROS, 0x0F) \
  X(ELF_OSABI_FENIXOS, 0x10) \
  X(ELF_OSABI_NUXI_CLOUDABI, 0x11) \
  X(ELF_OSABI_STRATUS_OPENVOS, 0x12)

#define ELF_TYPE_X_LIST() \
  X(ELF_TYPE_NONE, 0x00) \
  X(ELF_TYPE_REL, 0x01) \
  X(ELF_TYPE_EXEC, 0x02) \
  X(ELF_TYPE_DYN, 0x03) \
  X(ELF_TYPE_CORE, 0x04) \
  X(ELF_TYPE_LO_OS, 0xFE00) \
  X(ELF_TYPE_HI_OS, 0xFEFF) \
  X(ELF_TYPE_LO_PROC, 0xFF00) \
  X(ELF_TYPE_HI_PROC, 0xFFFF)

#define ELF_SEC_TYPE_X_LIST() \
  X(ELF_SEC_TYPE_NULL, 0x0) \
  X(ELF_SEC_TYPE_PROGBITS, 0x1) \
  X(ELF_SEC_TYPE_SYMTAB, 0x2) \
  X(ELF_SEC_TYPE_STRTAB, 0x3) \
  X(ELF_SEC_TYPE_RELA, 0x4) \
  X(ELF_SEC_TYPE_HASH, 0x5) \
  X(ELF_SEC_TYPE_DYNAMIC, 0x6) \
  X(ELF_SEC_TYPE_NOTE, 0x7) \
  X(ELF_SEC_TYPE_NOBITS, 0x8) \
  X(ELF_SEC_TYPE_REL, 0x9) \
  X(ELF_SEC_TYPE_SHLIB, 0x0A) \
  X(ELF_SEC_TYPE_DYNSYM, 0x0B) \
  X(ELF_SEC_TYPE_INIT_ARRAY, 0x0E) \
  X(ELF_SEC_TYPE_FINI_ARRAY, 0x0F) \
  X(ELF_SEC_TYPE_PREINIT_ARRAY, 0x10) \
  X(ELF_SEC_TYPE_GROUP, 0x11) \
  X(ELF_SEC_TYPE_SYMTAB_SHNDX, 0x12) \
  X(ELF_SEC_TYPE_ARM_ATTRIBUTES, 0x70000003)

#define ELF_SEC_FLAGS_X_LIST() \
  X(ELF_SEC_FLAGS_WRITE, 0x1) \
  X(ELF_SEC_FLAGS_ALLOC, 0x2) \
  X(ELF_SEC_FLAGS_EXEC, 0x4) \
  X(ELF_SEC_FLAGS_MERGE, 0x10) \
  X(ELF_SEC_FLAGS_STRINGS, 0x20) \
  X(ELF_SEC_FLAGS_INFO_LINK, 0x40) \
  X(ELF_SEC_FLAGS_LINK_ORDER, 0x80) \
  X(ELF_SEC_FLAGS_OS_NONCONFORMING, 0x100) \
  X(ELF_SEC_FLAGS_GROUP, 0x200) \
  X(ELF_SEC_FLAGS_TLS, 0x400)

#define ELF_SYM_BIND_X_LIST() \
  X(ELF_SYM_BIND_LOCAL, 0) \
  X(ELF_SYM_BIND_GLOBAL, 1) \
  X(ELF_SYM_BIND_WEAK, 2) \
  X(ELF_SYM_BIND_LOOS, 10) \
  X(ELF_SYM_BIND_HIOS, 12) \
  X(ELF_SYM_BIND_LOPROC, 13) \
  X(ELF_SYM_BIND_HIPROC, 15)

#define ELF_SYM_TYPE_X_LIST() \
  X(ELF_SYM_TYPE_NULL, 0) \
  X(ELF_SYM_TYPE_OBJECT, 1) \
  X(ELF_SYM_TYPE_FUNC, 2) \
  X(ELF_SYM_TYPE_SECTION, 3) \
  X(ELF_SYM_TYPE_FILE, 4) \
  X(ELF_SYM_TYPE_COMMON, 5) \
  X(ELF_SYM_TYPE_TLS, 6) \
  X(ELF_SYM_TYPE_LOOS, 10) \
  X(ELF_SYM_TYPE_HIOS, 12) \
  X(ELF_SYM_TYPE_LOPROC, 13) \
  X(ELF_SYM_TYPE_HIPROC, 15)

// elf_osabi
#define X(NAME, VAL) NAME = VAL,
enum elf_osabi { ELF_OSABI_X_LIST() };
#undef X
#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void print(elf_osabi eo) { switch (eo) { ELF_OSABI_X_LIST() default: break; } }
#undef X

// elf_type
#define X(NAME, VAL) NAME = VAL,
enum elf_type { ELF_TYPE_X_LIST() };
#undef X
#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void print(elf_type et) { switch (et) { ELF_TYPE_X_LIST() default: break; } }
#undef X

// elf_sec_type
#define X(NAME, VAL) NAME = VAL,
enum elf_sec_type { ELF_SEC_TYPE_X_LIST() };
#undef X
#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void print(elf_sec_type est) { switch (est) { ELF_SEC_TYPE_X_LIST() default: break; } }
#undef X

// elf_sec_flags
#define X(NAME, VAL) NAME = VAL,
enum elf_sec_flags { ELF_SEC_FLAGS_X_LIST() };
#undef X
#define X(NAME, VAL) if (esf & VAL) { printf("%s ", #NAME); }
void print(elf_sec_flags esf) { ELF_SEC_FLAGS_X_LIST() }
#undef X

// elf_sym_bind
#define X(NAME, VAL) NAME = VAL,
enum elf_sym_bind { ELF_SYM_BIND_X_LIST() };
#undef X
#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void print(elf_sym_bind esb) { switch (esb) { ELF_SYM_BIND_X_LIST() default: break; } }
#undef X

// elf_sym_type
#define X(NAME, VAL) NAME = VAL,
enum elf_sym_type { ELF_SYM_TYPE_X_LIST() };
#undef X
#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void print(elf_sym_type est) { switch (est) { ELF_SYM_TYPE_X_LIST() default: break; } }
#undef X

struct elf_hdr32 {
  uint8_t e_ident_mag[4];
  uint8_t e_ident_class;
  uint8_t e_ident_data;
  uint8_t e_ident_version;
  uint8_t e_ident_osabi;
  uint8_t e_ident_abiversion;
  uint8_t e_ident_pad[7];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct elf_prog_hdr32 {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
};

struct elf_section_hdr32 {
  uint32_t sh_name;
  uint32_t sh_type;
  uint32_t sh_flags;
  uint32_t sh_addr;
  uint32_t sh_offset;
  uint32_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint32_t sh_addralign;
  uint32_t sh_entsize;
};

struct elf_symbol32 {
  uint32_t st_name;
  uint32_t st_value;
  uint32_t st_size;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
};

using u32_vec_t = std::vector<uint32_t>;
using imm_addr_pq_t = std::priority_queue<uint32_t, u32_vec_t, std::greater<uint32_t>>;
using sym_addr_map_t = std::unordered_map<uint32_t, std::vector<elf_symbol32 const*>>;

struct log_str_desc {
  unsigned guid;
  std::vector<npf_format_spec_t> args;
};

using log_str_desc_map_t = std::unordered_map<std::string_view, log_str_desc>;

struct state {
  std::vector<char> elf;
  sym_addr_map_t non_nl_funcs_sym_map;
  std::vector<elf_symbol32 const*> nl_funcs;
  elf_section_hdr32 const *nl_hdr;
  elf_hdr32 *elf_hdr;
  elf_section_hdr32 const *sec_hdrs;
  elf_prog_hdr32 const *prog_hdrs;
  char const *sec_names;
  elf_symbol32 const *symtab;
  unsigned sym_count;
  char const *strtab;
};

struct nl_log_str_ref {
  elf_symbol32 const *func; // function the nanolog call was found in.
  uint32_t addr; // address of the 32-bit immediate load target
  uint32_t imm; // value of the 32-bit immediate load target
  char const *str; // nanolog format string
};

using nl_log_str_refs_t = std::vector<nl_log_str_ref>;

namespace {
std::vector<char> load_file(char const *fn) { // TODO: mmap
  FILE *f = fopen(fn, "rb");
  assert(f);
  fseek(f, 0, SEEK_END);
  long const len = ftell(f);
  rewind(f);
  std::vector<char> v((unsigned long)len);
  size_t const r = fread(v.data(), 1, (size_t)len, f);
  fclose(f);
  assert(r == (size_t)len);
  return v;
}

elf_section_hdr32 const *find_nl_hdr(elf_section_hdr32 const *sec_hdrs,
                                     char const *sec_names,
                                     int sec_n) {
  for (int i = 0; i < sec_n; ++i) {
    elf_section_hdr32 const& sh = sec_hdrs[i];
    if (sh.sh_type && !strcmp(".nanolog", &sec_names[sh.sh_name])) { return &sh; }
  }
  return nullptr;
}

elf_section_hdr32 const *find_symtab_hdr(elf_section_hdr32 const *sec_hdrs, int sec_n) {
  for (int i = 0; i < sec_n; ++i) {
    if (sec_hdrs[i].sh_type == ELF_SEC_TYPE_SYMTAB) { return &sec_hdrs[i]; }
  }
  return nullptr;
}

elf_section_hdr32 const *find_strtab_hdr(elf_section_hdr32 const *sec_hdrs,
                                         char const *sec_names,
                                         int sec_n) {
  for (int i = 0; i < sec_n; ++i) {
    elf_section_hdr32 const& sh = sec_hdrs[i];
    if ((sh.sh_type == ELF_SEC_TYPE_STRTAB) && !strcmp(".strtab", &sec_names[sh.sh_name])) {
      return &sec_hdrs[i];
    }
  }
  return nullptr;
}

void load_elf(state& s) {
  s.elf = load_file("nrf52832_xxaa.out");
  s.elf_hdr = (elf_hdr32*)(s.elf.data());
  assert(s.elf_hdr->e_shentsize == sizeof(elf_section_hdr32));

  s.sec_hdrs = (elf_section_hdr32 const*)(s.elf.data() + s.elf_hdr->e_shoff);
  s.prog_hdrs = (elf_prog_hdr32 const*)(s.elf.data() + s.elf_hdr->e_phoff);
  s.sec_names = s.elf.data() + s.sec_hdrs[s.elf_hdr->e_shstrndx].sh_offset;

  // symbol table
  elf_section_hdr32 const *symtab_hdr = find_symtab_hdr(s.sec_hdrs, (int)s.elf_hdr->e_shnum);
  assert(symtab_hdr);
  assert(symtab_hdr->sh_entsize == sizeof(elf_symbol32));
  s.symtab = (elf_symbol32 const*)(s.elf.data() + symtab_hdr->sh_offset);
  s.sym_count = symtab_hdr->sh_size / symtab_hdr->sh_entsize;

  // string table
  elf_section_hdr32 const *strtab_hdr =
    find_strtab_hdr(s.sec_hdrs, s.sec_names, (int)s.elf_hdr->e_shnum);
  assert(symtab_hdr);
  s.strtab = s.elf.data() + strtab_hdr->sh_offset;

  // nanolog section
  s.nl_hdr = find_nl_hdr(s.sec_hdrs, s.sec_names, (int)s.elf_hdr->e_shnum);
  assert(s.nl_hdr);

  // nanolog functions, and non-nanolog-function-addr-to-symbol-map
  for (auto i = 0u; i < s.sym_count; ++i) {
    elf_symbol32 const& sym = s.symtab[i];
    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }

    if (strstr(&s.strtab[sym.st_name], "nanolog_") == &s.strtab[sym.st_name]) {
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
}

void print(const elf_hdr32& h) {
  printf("ELF Header:\n");
  printf("  ident magic: 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\n",
         h.e_ident_mag[0],
         h.e_ident_mag[1],
         h.e_ident_mag[2],
         h.e_ident_mag[3]);
  printf("  ident class: 0x%02hhx\n", h.e_ident_class);
  printf("  ident data:  0x%02hhx\n", h.e_ident_data);
  printf("  ident version: 0x%02hhx\n", h.e_ident_version);
  printf("  ident osabi: 0x%02hhx\n", h.e_ident_osabi);
  printf("  ident abiversion: 0x%02hhx\n", h.e_ident_abiversion);
  printf("  type: 0x%04hx\n", h.e_type);
  printf("  machine: 0x%04hx\n", h.e_machine);
  printf("  version: %d\n", (int)h.e_version);
  printf("  entry: 0x%08x\n", h.e_entry);
  printf("  phoff: 0x%08x\n", h.e_phoff);
  printf("  shoff: 0x%08x\n", h.e_shoff);
  printf("  flags: 0x%08x\n", h.e_flags);
  printf("  ehsize: 0x%04hx\n", h.e_ehsize);
  printf("  phentsize: 0x%04hx\n", h.e_phentsize);
  printf("  phnum: %hu\n", h.e_phnum);
  printf("  shnum: %hu\n", h.e_shnum);
  printf("  shentsize: 0x%04hx\n", h.e_shentsize);
  printf("  shstrndx: %hu\n", h.e_shstrndx);
}

void print(elf_prog_hdr32 const& p) {
  printf("ELF Program Header:\n");
  printf("  type:   0x%08x (", p.p_type);
  switch (p.p_type) {
    case 0x00000001: printf("LOAD"); break;
    case 0x00000002: printf("DYNAMIC"); break;
    case 0x00000003: printf("INTERP"); break;
    case 0x00000004: printf("NOTE"); break;
    case 0x00000005: printf("SHLIB"); break;
    case 0x00000006: printf("PHDR"); break;
    case 0x00000007: printf("TLS"); break;
    case 0x70000000: printf("ARM_ARCHEXT"); break;
    case 0x70000001: printf("ARM_EXIDX"); break;
  }
  printf(")\n");
  printf("  offset: 0x%08x\n", p.p_offset);
  printf("  vaddr:  0x%08x\n", p.p_vaddr);
  printf("  paddr:  0x%08x\n", p.p_paddr);
  printf("  filesz: 0x%08x\n", p.p_filesz);
  printf("  memsz:  0x%08x\n", p.p_memsz);
  printf("  align:  %u\n", (unsigned)p.p_align);
}

void print(elf_section_hdr32 const& s, char const *sec_names) {
  printf("ELF Section Header:\n");
  printf("  name:      %s\n", &sec_names[s.sh_name]);

  printf("  type:      0x%08x ( ", elf_sec_type(s.sh_type));
  print(elf_sec_type(s.sh_type));
  printf(" )\n");

  printf("  flags:     0x%08x ", s.sh_flags);
  if (s.sh_flags) {
    printf("( ");
    print(elf_sec_flags(s.sh_flags));
    printf(")");
  }
  printf("\n");

  printf("  addr:      0x%08x\n", s.sh_addr);
  printf("  offset:    0x%08x\n", s.sh_offset);
  printf("  size:      0x%08x\n", s.sh_size);
  printf("  link:      0x%08x\n", s.sh_link);
  printf("  info:      0x%08x\n", s.sh_info);
  printf("  addralign: %d\n", (int)s.sh_addralign);
  printf("  entsize:   0x%08x\n", s.sh_entsize);
}

void print(elf_symbol32 const& s, char const *strtab) {
  printf("ELF Symbol:\n");
  printf("  name: %s\n", &strtab[s.st_name]);
  printf("  value: 0x%04x\n", s.st_value);
  printf("  size: %u\n", s.st_size);
  printf("  info: 0x%02hhx\n", s.st_info);
  printf("  other: 0x%02hhx\n", s.st_other);
  printf("  shndx: %hu\n", s.st_shndx);
}

elf_symbol32 const * get_nl_func(state const& s, uint32_t cand) {
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
                                       nl_log_str_refs_t& nl_log_str_refs) {

  elf_symbol32 const& func_sym = *func.second[0];
  elf_section_hdr32 const& func_sec_hdr = s.sec_hdrs[func_sym.st_shndx];
  uint32_t const func_start = (func_sym.st_value - func_sec_hdr.sh_addr) & ~1u;
  uint32_t const func_end = func_start + func_sym.st_size;

  printf("Scanning %s: %x (%x-%x):\n", &s.strtab[func_sym.st_name], func_sym.st_value, func_start, func_end);

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
    memcpy(&w0, &s.elf[i + func_sec_hdr.sh_offset], 2);
    i += 2;

    if (i < func_end) {
      uint16_t w1;
      memcpy(&w1, &s.elf[i + func_sec_hdr.sh_offset], 2);

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
            memcpy(&nl_str_imm32, &s.elf[imm32_offset], 4);

            uint32_t const log_str_off =
              s.nl_hdr->sh_offset + (nl_str_imm32 - s.nl_hdr->sh_addr);

            printf("  Found bl @ %x: (%x %s), load r0 from 0x%08x: \"%s\"\n",
                   func_sec_hdr.sh_addr + i - 4,
                   target,
                   &s.strtab[nl_func->st_name],
                   last_seen_r0_load,
                   &s.elf[log_str_off]);

            nl_log_str_refs.push_back(
              {func.second[0], last_seen_r0_load, nl_str_imm32, &s.elf[log_str_off]});
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

nl_log_str_refs_t get_log_str_refs(state const& s) {
  nl_log_str_refs_t log_str_refs;

  for (const auto& func_syms : s.non_nl_funcs_sym_map) {
    accumulate_log_str_refs_from_func(s, func_syms, log_str_refs);
  }

  return log_str_refs;
}
}

int main(int, char const *[]) {
  state s;
  load_elf(s);

  /*
  print(*s.elf_hdr);
  printf("\n");
  for (auto i = 0u; i < s.elf_hdr->e_phnum; ++i) { print(s.prog_hdrs[i]); }
  printf("\n");
  */

  for (auto i = 0u; i < s.elf_hdr->e_shnum; ++i) { print(s.sec_hdrs[i], s.sec_names); }
  printf("\n");
  printf("%d symbols found\n", s.sym_count);

  printf("\n");
  printf("Non-nanolog functions:\n");
  for (auto const& e : s.non_nl_funcs_sym_map) {
    printf("  0x%08x ", e.first);
    for (auto const* sym : e.second) {
      printf("%s ", &s.strtab[sym->st_name]);
    }
    printf("\n");
  }

  printf("\n");
  printf("Nanolog public functions:\n");
  for (auto const& nl_func : s.nl_funcs) {
    printf("  0x%08x %s\n", nl_func->st_value & ~1u, &s.strtab[nl_func->st_name]);
  }

  printf("\n");
  nl_log_str_refs_t const nl_log_str_refs = get_log_str_refs(s);
  printf("\n");

  printf(".nanolog string references:\n");
  for (const auto& nl_log_str_ref : nl_log_str_refs) {
    printf("  0x%08x %x \"%s\"\n",
           nl_log_str_ref.addr,
           nl_log_str_ref.imm,
           nl_log_str_ref.str);
  }

  return 0;
}
