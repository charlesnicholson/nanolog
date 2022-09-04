#pragma once

#include <cstdint>
#include <vector>

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

#define X(NAME, VAL) NAME = VAL,
enum elf_osabi { ELF_OSABI_X_LIST() };
#undef X

#define X(NAME, VAL) NAME = VAL,
enum elf_type { ELF_TYPE_X_LIST() };
#undef X

#define X(NAME, VAL) NAME = VAL,
enum elf_sec_type { ELF_SEC_TYPE_X_LIST() };
#undef X

#define X(NAME, VAL) NAME = VAL,
enum elf_sec_flags { ELF_SEC_FLAGS_X_LIST() };
#undef X

#define X(NAME, VAL) NAME = VAL,
enum elf_sym_bind { ELF_SYM_BIND_X_LIST() };
#undef X

#define X(NAME, VAL) NAME = VAL,
enum elf_sym_type { ELF_SYM_TYPE_X_LIST() };
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

struct elf {
  std::vector<char> bytes;
  elf_hdr32 *elf_hdr;
  elf_section_hdr32 const *sec_hdrs;
  elf_prog_hdr32 const *prog_hdrs;
  char const *sec_names;
  elf_section_hdr32 const *symtab_hdr;
  elf_symbol32 const *symtab;
  char const *strtab;
};

bool nl_elf_load(elf& e, char const *filename);

void nl_elf_print(elf_osabi eo);
void nl_elf_print(elf_type et);
void nl_elf_print(elf_sec_type est);
void nl_elf_print(elf_sec_flags esf);
void nl_elf_print(elf_sym_bind esb);
void nl_elf_print(elf_sym_type est);
void nl_elf_print(elf_hdr32 const& h);
void nl_elf_print(elf_prog_hdr32 const& p);
void nl_elf_print(elf_section_hdr32 const& s, char const *sec_names);
void nl_elf_print(elf_symbol32 const& s, char const *strtab);

