#include "nl_elf.h"
#include <cstdlib>

namespace {
bool load_file(char const *fn, std::vector<char>& contents) {
  FILE *f = fopen(fn, "rb");
  if (!f) { return false; }
  fseek(f, 0, SEEK_END);
  long const len = ftell(f);
  rewind(f);
  contents.resize((unsigned long)len);
  size_t const r = fread(contents.data(), 1, (size_t)len, f);
  fclose(f);
  assert(r == (size_t)len);
  return true;
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
    if ((sh.sh_type == ELF_SEC_TYPE_STRTAB) &&
        !strcmp(".strtab", &sec_names[sh.sh_name])) {
      return &sec_hdrs[i];
    }
  }
  return nullptr;
}
}

bool load_elf(elf& e, char const* filename) {
  if (!load_file(filename, e.bytes)) { return false; }

  e.elf_hdr = (elf_hdr32*)&e.bytes[0];
  assert(e.elf_hdr->e_shentsize == sizeof(elf_section_hdr32));

  e.sec_hdrs = (elf_section_hdr32 const*)&e.bytes[e.elf_hdr->e_shoff];
  e.prog_hdrs = (elf_prog_hdr32 const*)&e.bytes[e.elf_hdr->e_phoff];
  e.sec_names = e.bytes.data() + e.sec_hdrs[e.elf_hdr->e_shstrndx].sh_offset;

  // symbol table
  e.symtab_hdr = find_symtab_hdr(e.sec_hdrs, (int)e.elf_hdr->e_shnum);
  assert(e.symtab_hdr);
  assert(e.symtab_hdr->sh_entsize == sizeof(elf_symbol32));
  e.symtab = (elf_symbol32 const*)&e.bytes[e.symtab_hdr->sh_offset];

  // string table
  elf_section_hdr32 const *strtab_hdr =
    find_strtab_hdr(e.sec_hdrs, e.sec_names, (int)e.elf_hdr->e_shnum);
  assert(strtab_hdr);
  e.strtab = &e.bytes[strtab_hdr->sh_offset];

  return true;
}

