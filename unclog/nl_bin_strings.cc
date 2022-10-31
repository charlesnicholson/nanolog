#include "nl_bin_strings.h"

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 1
#include "nanoprintf.h"

void convert_strings_to_bins(std::vector<char const *> const& fmt_strs,
                             std::vector<u32>& fmt_bin_addrs,
                             std::vector<unsigned char>& fmt_bin_mem) {
  for (auto str: fmt_strs) {
    fmt_bin_addrs.push_back(unsigned(fmt_bin_mem.size()));
    auto guid{fmt_bin_addrs.empty() ? 0 : unsigned(fmt_bin_addrs.size() - 1)};

    fmt_bin_mem.push_back(NL_BINARY_PREFIX_MARKER);

    do { // varint encode
      fmt_bin_mem.push_back(u8((guid & 0x7Fu) | 0x80));
      guid >>= 7u;
    } while (guid);
    fmt_bin_mem[fmt_bin_mem.size() - 1] &= ~0x80;

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
              field = char(NL_ARG_TYPE_SCALAR_1_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LONG:
              field = char(NL_ARG_TYPE_WINT_T); added_field = true; break;
            default: break;
          } break;

        case NPF_FMT_SPEC_CONV_POINTER:
          field = char(NL_ARG_TYPE_POINTER); added_field = true; break;

        case NPF_FMT_SPEC_CONV_STRING:
          field = char(NL_ARG_TYPE_STRING); added_field = true; break;

        case NPF_FMT_SPEC_CONV_BINARY:
        case NPF_FMT_SPEC_CONV_OCTAL:
        case NPF_FMT_SPEC_CONV_HEX_INT:
        case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
        case NPF_FMT_SPEC_CONV_SIGNED_INT:
          switch (fs.length_modifier) {
            case NPF_FMT_SPEC_LEN_MOD_CHAR:
              field = char(NL_ARG_TYPE_SCALAR_1_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_SHORT:
              field = char(NL_ARG_TYPE_SCALAR_2_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_NONE:
            case NPF_FMT_SPEC_LEN_MOD_LONG:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_SIZET:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT:
              field = char(NL_ARG_TYPE_SCALAR_4_BYTE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LARGE_LONG_LONG:
            case NPF_FMT_SPEC_LEN_MOD_LARGE_INTMAX:
              field = char(NL_ARG_TYPE_SCALAR_8_BYTE); added_field = true; break;
            default: break;
          } break;

        case NPF_FMT_SPEC_CONV_FLOAT_DEC:
        case NPF_FMT_SPEC_CONV_FLOAT_SCI:
        case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
        case NPF_FMT_SPEC_CONV_FLOAT_HEX:
          switch (fs.length_modifier) {
            case NPF_FMT_SPEC_LEN_MOD_NONE:
              field = char(NL_ARG_TYPE_DOUBLE); added_field = true; break;
            case NPF_FMT_SPEC_LEN_MOD_LONG:
              field = char(NL_ARG_TYPE_LONG_DOUBLE); added_field = true; break;
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
      fmt_bin_mem[fmt_bin_mem.size() - 1] |= (unsigned char)(NL_ARG_TYPE_LOG_END << 4u);
    } else {
      fmt_bin_mem.push_back(NL_ARG_TYPE_LOG_END);
    }
  }
}

