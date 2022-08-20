#include <cassert>
#include <cstdio>
#include <cstdint>
#include <queue>
#include <vector>

enum elf_osabi {
  ELF_OSABI_SYSTEM_V = 0x00,
  ELF_OSABI_HP_UX = 0x01,
  ELF_OSABI_NETBSD = 0x02,
  ELF_OSABI_LINUX = 0x03,
  ELF_OSABI_GNU_HURD = 0x04,
  ELF_OSABI_SOLARIS = 0x06,
  ELF_OSABI_AIX = 0x07,
  ELF_OSABI_IRIX = 0x08,
  ELF_OSABI_FREEBSD = 0x09,
  ELF_OSABI_TRU64 = 0x0A,
  ELF_OSABI_NOVELL_MODESTO = 0x0B,
  ELF_OSABI_OPENBSD = 0x0C,
  ELF_OSABI_OPENVSM = 0x0D,
  ELF_OSABI_NONSTOP = 0x0E,
  ELF_OSABI_AROS = 0x0F,
  ELF_OSABI_FENIXOS = 0x10,
  ELF_OSABI_NUXI_CLOUDABI = 0x11,
  ELF_OSABI_STRATUS_OPENVOS = 0x12,
};

enum elf_type {
  ELF_TYPE_NONE = 0x00,
  ELF_TYPE_REL = 0x01,
  ELF_TYPE_EXEC = 0x02,
  ELF_TYPE_DYN = 0x03,
  ELF_TYPE_CORE = 0x04,
  ELF_TYPE_LO_OS = 0xFE00,
  ELF_TYPE_HI_OS = 0xFEFF,
  ELF_TYPE_LO_PROC = 0xFF00,
  ELF_TYPE_HI_PROC = 0xFFFF,
};

enum elf_sec_type {
  ELF_SEC_TYPE_NULL = 0x0,
  ELF_SEC_TYPE_PROGBITS = 0x1,
  ELF_SEC_TYPE_SYMTAB = 0x2,
  ELF_SEC_TYPE_STRTAB = 0x3,
  ELF_SEC_TYPE_RELA = 0x4,
  ELF_SEC_TYPE_HASH = 0x5,
  ELF_SEC_TYPE_DYNAMIC = 0x6,
  ELF_SEC_TYPE_NOTE = 0x7,
  ELF_SEC_TYPE_NOBITS = 0x8,
  ELF_SEC_TYPE_REL = 0x9,
  ELF_SEC_TYPE_SHLIB = 0x0A,
  ELF_SEC_TYPE_DYNSYM = 0x0B,
  ELF_SEC_TYPE_INIT_ARRAY = 0x0E,
  ELF_SEC_TYPE_FINI_ARRAY = 0x0F,
  ELF_SEC_TYPE_PREINIT_ARRAY = 0x10,
  ELF_SEC_TYPE_GROUP = 0x11,
  ELF_SEC_TYPE_SYMTAB_SHNDX = 0x12,
};

enum elf_sec_flags {
  ELF_SEC_FLAGS_WRITE = 0x1,
  ELF_SEC_FLAGS_ALLOC = 0x2,
  ELF_SEC_FLAGS_EXEC = 0x4,
  ELF_SEC_FLAGS_MERGE = 0x10,
  ELF_SEC_FLAGS_STRINGS = 0x20,
  ELF_SEC_FLAGS_INFO_LINK = 0x40,
  ELF_SEC_FLAGS_LINK_ORDER = 0x80,
  ELF_SEC_FLAGS_OS_NONCONFORMING = 0x100,
  ELF_SEC_FLAGS_GROUP = 0x200,
  ELF_SEC_FLAGS_TLS = 0x400,
};

enum elf_sym_bind {
  ELF_SYM_BIND_LOCAL = 0,
  ELF_SYM_BIND_GLOBAL = 1,
  ELF_SYM_BIND_WEAK = 2,
  ELF_SYM_BIND_LOOS = 10,
  ELF_SYM_BIND_HIOS = 12,
  ELF_SYM_BIND_LOPROC = 13,
  ELF_SYM_BIND_HIPROC = 15,
};

enum elf_sym_type {
  ELF_SYM_TYPE_NULL = 0,
  ELF_SYM_TYPE_OBJECT = 1,
  ELF_SYM_TYPE_FUNC = 2,
  ELF_SYM_TYPE_SECTION = 3,
  ELF_SYM_TYPE_FILE = 4,
  ELF_SYM_TYPE_COMMON = 5,
  ELF_SYM_TYPE_TLS = 6,
  ELF_SYM_TYPE_LOOS = 10,
  ELF_SYM_TYPE_HIOS = 12,
  ELF_SYM_TYPE_LOPROC = 13,
  ELF_SYM_TYPE_SPARC_REGISTER = 13,
  ELF_SYM_TYPE_HIPROC = 15,
};

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

struct state {
  std::vector<char> elf;
  elf_hdr32 *elf_hdr;
  elf_section_hdr32 const *sec_hdrs;
  elf_prog_hdr32 const *prog_hdrs;
  char const *sec_names;
  elf_section_hdr32 const *nl_hdr;
  elf_symbol32 const *symtab;
  unsigned sym_count;
  char const *strtab;
};

using u32_vec_t = std::vector<uint32_t>;
using imm_addr_pq_t = std::priority_queue<uint32_t, u32_vec_t, std::greater<uint32_t>>;

namespace {
std::vector<char> load_elf(char const *elf) { // TODO: mmap
  FILE *f = fopen(elf, "rb");
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

  printf("  type:      0x%08x ( ", s.sh_type);
  switch (s.sh_type) {
    case ELF_SEC_TYPE_PROGBITS: printf("PROGBITS "); break;
    case ELF_SEC_TYPE_SYMTAB: printf("SYMTAB "); break;
    case ELF_SEC_TYPE_STRTAB: printf("STRTAB "); break;
    case ELF_SEC_TYPE_RELA: printf("RELA "); break;
    case ELF_SEC_TYPE_HASH: printf("HASH "); break;
    case ELF_SEC_TYPE_DYNAMIC: printf("DYNAMIC "); break;
    case ELF_SEC_TYPE_NOTE: printf("NOTE "); break;
    case ELF_SEC_TYPE_NOBITS: printf("NOBITS "); break;
    case ELF_SEC_TYPE_REL: printf("REL "); break;
    case ELF_SEC_TYPE_SHLIB: printf("SHLIB "); break;
    case ELF_SEC_TYPE_DYNSYM: printf("DYNSYM "); break;
    case ELF_SEC_TYPE_INIT_ARRAY: printf("INIT_ARRAY "); break;
    case ELF_SEC_TYPE_FINI_ARRAY: printf("FINI_ARRAY "); break;
    case ELF_SEC_TYPE_PREINIT_ARRAY: printf("PREINIT_ARRAY "); break;
    case ELF_SEC_TYPE_GROUP: printf("GROUP "); break;
    case ELF_SEC_TYPE_SYMTAB_SHNDX: printf("SYMTAB_SHNDX "); break;
    case 0x70000003: printf("ARM_ATTRIBUTES "); break;
    default: break;
  }
  printf(")\n");

  printf("  flags:     0x%08x ", s.sh_flags);
  if (s.sh_flags) {
    printf("( ");
    if (s.sh_flags & 0x1) { printf("WRITE "); }
    if (s.sh_flags & 0x2) { printf("ALLOC "); }
    if (s.sh_flags & 0x4) { printf("EXEC "); }
    if (s.sh_flags & 0x10) { printf("MERGE "); }
    if (s.sh_flags & 0x20) { printf("STRINGS "); }
    if (s.sh_flags & 0x40) { printf("INFO_LINK "); }
    if (s.sh_flags & 0x80) { printf("LINK_ORDER "); }
    if (s.sh_flags & 0x100) { printf("OS_NONCONFORMING "); }
    if (s.sh_flags & 0x200) { printf("GROUP "); }
    if (s.sh_flags & 0x400) { printf("TLS "); }
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

//void print(elf_symbol32 const *symtab, int n, char const *names) {
//  for (int i = 0; i < n; ++i) {
//    elf_symbol32 const& s = symtab[i];
//    bool const func = (s.st_info & 0xF) == 2;
//    if (func) { printf("  0x%08x %s\n", s.st_value, &names[s.st_name]); }
//  }
//}

void print_functions(u32_vec_t const& func_addrs, state const& s) {
  elf_symbol32 const *symtab = s.symtab;
  char const *names = s.strtab;
  for (auto func_addr : func_addrs) {
    for (auto i = 0u; i < s.sym_count; ++i) {
      if (func_addr == symtab[i].st_value) {
        printf("  0x%08x %4x %s\n", func_addr, symtab[i].st_size, &names[symtab[i].st_name]);
        break;
      }
    }
  }
}

elf_section_hdr32 const *find_nl_hdr(elf_section_hdr32 const *sec_hdrs, char const *sec_names, int sec_n) {
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

void accumulate_log_str_refs_from_progbits_sec(state const& s,
                                               elf_section_hdr32 const& sh,
                                               u32_vec_t& log_str_refs) {
  uint32_t const nl_start = s.nl_hdr->sh_addr;
  uint32_t const nl_end = nl_start + s.nl_hdr->sh_size;

  uint32_t const n = sh.sh_offset + sh.sh_size;
  uint32_t i = sh.sh_offset;
  imm_addr_pq_t imm_addrs;

  while (i < n) {
    bool matched = false;
    while (!imm_addrs.empty() && (i == imm_addrs.top())) { // pc-rel 32-bit imm load?
      matched = true;
      imm_addrs.pop();
      uint32_t imm;
      memcpy(&imm, &s.elf[i], sizeof(imm));
      if ((imm >= nl_start) && (imm < nl_end)) { log_str_refs.push_back(i); }
    }

    if (matched) {
      i += 4;
      continue;
    }

    uint16_t inst;
    memcpy(&inst, &s.elf[i], 2);

    if (((inst & 0xF000) == 0xF000) || ((inst & 0xE800) == 0xE800)) { // 32-bit instr
      i += 4;
      continue;
    }

    if ((inst >> 11) != 0b01001) { // load from literal pool = 0b01001...
      i += 2;
      continue;
    }

    uint32_t const imm = ((i + 4) & uint32_t(~3)) + ((inst & 0xFF) * 4);
    imm_addrs.push(imm);
    i += 2;
  }
}

u32_vec_t get_log_str_refs(state const& s) {
  u32_vec_t log_str_refs;

  for (auto i = 0u; i < s.elf_hdr->e_shnum; ++i) {
    elf_section_hdr32 const &sh = s.sec_hdrs[i];
    if (&sh == s.nl_hdr) { continue; }
    if (sh.sh_type != ELF_SEC_TYPE_PROGBITS) { continue; }
    if (!(sh.sh_flags & ELF_SEC_FLAGS_ALLOC)) { continue; }
    if (sh.sh_size < sizeof(uint32_t)) { continue; }

    printf("get_log_str_refs: searching section %s\n", &s.sec_names[sh.sh_name]);
    accumulate_log_str_refs_from_progbits_sec(s, sh, log_str_refs);
  }

  return log_str_refs;
}

u32_vec_t get_func_addrs(state const& s) {
  u32_vec_t func_addrs;
  for (auto i = 0u; i < s.sym_count; ++i) {
    elf_symbol32 const& sym = s.symtab[i];
    char const *name = &s.strtab[sym.st_name];

    if ((sym.st_info & 0xF) != ELF_SYM_TYPE_FUNC) { continue; }
    if (strstr(name, "nanolog_") == name) { continue; }
    func_addrs.push_back(sym.st_value);
  }

  std::sort(std::begin(func_addrs), std::end(func_addrs));
  return func_addrs;
}

void load(state& s) {
  s.elf = load_elf("nrf52832_xxaa.out");
  s.elf_hdr = reinterpret_cast<elf_hdr32*>(s.elf.data());
  assert(s.elf_hdr->e_shentsize == sizeof(elf_section_hdr32));

  s.sec_hdrs = reinterpret_cast<elf_section_hdr32 const*>(s.elf.data() + s.elf_hdr->e_shoff);
  s.prog_hdrs = reinterpret_cast<elf_prog_hdr32 const*>(s.elf.data() + s.elf_hdr->e_phoff);
  s.sec_names = s.elf.data() + s.sec_hdrs[s.elf_hdr->e_shstrndx].sh_offset;

  // nanolog section
  s.nl_hdr = find_nl_hdr(s.sec_hdrs, s.sec_names, (int)s.elf_hdr->e_shnum);
  assert(s.nl_hdr);

  // symbol table
  elf_section_hdr32 const *symtab_hdr = find_symtab_hdr(s.sec_hdrs, (int)s.elf_hdr->e_shnum);
  assert(symtab_hdr);
  assert(symtab_hdr->sh_entsize == sizeof(elf_symbol32));
  s.symtab = reinterpret_cast<elf_symbol32 const*>(s.elf.data() + symtab_hdr->sh_offset);
  s.sym_count = symtab_hdr->sh_size / symtab_hdr->sh_entsize;

  // string table
  elf_section_hdr32 const *strtab_hdr =
    find_strtab_hdr(s.sec_hdrs, s.sec_names, (int)s.elf_hdr->e_shnum);
  assert(symtab_hdr);
  s.strtab = s.elf.data() + strtab_hdr->sh_offset;
}
}

int main(int, char const *[]) {
  state s;
  load(s);

  print(*s.elf_hdr);
  printf("\n");
  for (auto i = 0u; i < s.elf_hdr->e_phnum; ++i) { print(s.prog_hdrs[i]); }
  printf("\n");
  for (auto i = 0u; i < s.elf_hdr->e_shnum; ++i) { print(s.sec_hdrs[i], s.sec_names); }
  printf("\n");
  printf("%d symbols found\n", s.sym_count);

  u32_vec_t func_addrs = get_func_addrs(s);
  printf("%d functions\n", (int)func_addrs.size());
  print_functions(func_addrs, s);

  u32_vec_t log_str_refs = get_log_str_refs(s);
  printf("nanolog string refs:\n");
  for (auto log_str_ref : log_str_refs) {
    printf("  0x%08x\n", log_str_ref);
  }

  return 0;
}
