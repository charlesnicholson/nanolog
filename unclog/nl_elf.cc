#include "nl_elf.h"

namespace {
bytes_ptr load_file(char const *fn, unsigned& out_len) {
  file_ptr f{open_file(fn, "rb")};
  if (!f.get()) { return bytes_ptr{}; }
  std::fseek(f.get(), 0, SEEK_END);
  unsigned const len{unsigned(std::ftell(f.get()))};
  bytes_ptr contents{new (std::align_val_t{16}) byte[len]};
  std::rewind(f.get());
  auto const r{std::fread(&contents[0], 1, len, f.get())};
  assert(r == len);
  out_len = len;
  return contents;
}

elf_section_hdr32 const *find_symtab_hdr(elf_section_hdr32 const *sec_hdrs, int sec_n) {
  for (auto i{0}; i < sec_n; ++i) {
    if (sec_hdrs[i].sh_type == ELF_SEC_TYPE_SYMTAB) { return &sec_hdrs[i]; }
  }
  return nullptr;
}

elf_section_hdr32 const *find_strtab_hdr(elf_section_hdr32 const *sec_hdrs,
                                         char const *sec_names,
                                         int sec_n) {
  for (auto i{0}; i < sec_n; ++i) {
    elf_section_hdr32 const& sh{sec_hdrs[i]};
    if ((sh.sh_type == ELF_SEC_TYPE_STRTAB) && !strcmp(".strtab", &sec_names[sh.sh_name])) {
      return &sec_hdrs[i];
    }
  }
  return nullptr;
}
}

bool nl_elf_load(elf& e, char const* filename) {
  e.bytes = load_file(filename, e.len);
  if (!e.bytes) { return false; }

  e.elf_hdr = (elf_hdr32*)&e.bytes[0];
  assert(e.elf_hdr->e_shentsize == sizeof(elf_section_hdr32));

  e.sec_hdrs = (elf_section_hdr32 const *)&e.bytes[e.elf_hdr->e_shoff];
  e.prog_hdrs = (elf_prog_hdr32 const *)&e.bytes[e.elf_hdr->e_phoff];
  e.sec_names = (char const *)(&e.bytes[0] + e.sec_hdrs[e.elf_hdr->e_shstrndx].sh_offset);

  // symbol table
  e.symtab_hdr = find_symtab_hdr(e.sec_hdrs, (int)e.elf_hdr->e_shnum);
  assert(e.symtab_hdr);
  assert(e.symtab_hdr->sh_entsize == sizeof(elf_symbol32));
  e.symtab = (elf_symbol32 const *)&e.bytes[e.symtab_hdr->sh_offset];

  // string table
  auto const *strtab_hdr{find_strtab_hdr(e.sec_hdrs, e.sec_names, (int)e.elf_hdr->e_shnum)};
  assert(strtab_hdr);
  e.strtab = (char const *)&e.bytes[strtab_hdr->sh_offset];

  return true;
}

#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void nl_elf_print(elf_osabi eo) { switch (eo) { ELF_OSABI_X_LIST() default: break; } }
#undef X

#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void nl_elf_print(elf_type et) { switch (et) { ELF_TYPE_X_LIST() default: break; } }
#undef X

#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void nl_elf_print(elf_sec_type est) { switch (est) { ELF_SEC_TYPE_X_LIST() default: break; } }
#undef X

#define X(NAME, VAL) if (esf & VAL) { printf("%s ", #NAME); }
void nl_elf_print(elf_sec_flags esf) { ELF_SEC_FLAGS_X_LIST() }
#undef X

#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void nl_elf_print(elf_sym_bind esb) { switch (esb) { ELF_SYM_BIND_X_LIST() default: break; } }
#undef X

#define X(NAME, VAL) case VAL: printf("%s", #NAME); break;
void nl_elf_print(elf_sym_type est) { switch (est) { ELF_SYM_TYPE_X_LIST() default: break; } }
#undef X

void nl_elf_print(const elf_hdr32& h) {
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

void nl_elf_print(elf_prog_hdr32 const& p) {
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

void nl_elf_print(elf_section_hdr32 const& s, char const *sec_names) {
  printf("ELF Section Header:\n");
  printf("  name:      %s\n", &sec_names[s.sh_name]);

  printf("  type:      0x%08x ( ", elf_sec_type(s.sh_type));
  nl_elf_print(elf_sec_type(s.sh_type));
  printf(" )\n");

  printf("  flags:     0x%08x ", s.sh_flags);
  if (s.sh_flags) {
    printf("( ");
    nl_elf_print(elf_sec_flags(s.sh_flags));
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

void nl_elf_print(elf_symbol32 const& s, char const *strtab) {
  printf("ELF Symbol:\n");
  printf("  name: %s\n", &strtab[s.st_name]);
  printf("  value: 0x%04x\n", s.st_value);
  printf("  size: %u\n", s.st_size);
  printf("  info: 0x%02hhx\n", s.st_info);
  printf("  other: 0x%02hhx\n", s.st_other);
  printf("  shndx: %hu\n", s.st_shndx);
}

