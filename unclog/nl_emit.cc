#include "nl_emit.h"

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 1
#include "nanoprintf.h"

namespace {
std::string& to_json(char const *s, std::string& out) {
  char hex_str[16];
  out.clear();
  while (*s) {
    switch (*s) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (*s <= 0x1F) {
          snprintf(hex_str, sizeof(hex_str), "\\u%04hhx", *s);
          out = hex_str;
        } else {
          out += *s;
        }
    }
    ++s;
  }
  return out;
}

char const *to_severity(unsigned sev) {
  switch (sev) {
    case NL_SEV_DBG: return "debug";
    case NL_SEV_INFO: return "info";
    case NL_SEV_WARN: return "warning";
    case NL_SEV_ERR: return "error";
    case NL_SEV_CRIT: return "critical";
    case NL_SEV_ASSERT: return "assert";
    default: break;
  }
  return "unknown";
}

std::string& to_python(char const *s, std::string& out) {
  out.clear();
  while (*s) {
    npf_format_spec_t fs;
    int const n{(*s != '%') ? 0 : npf_parse_format_spec(s, &fs)};
    if (!n) { out += *s++; continue; }
    s += n;
    if (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT) { out += '%'; continue; }
    out += "{}"; // TODO: switch on fs.conv_type
  }
  return out;
}
}

bool emit_json_manifest(std::vector<char const *> const& fmt_strs,
                        std::vector<u8> const& fmt_str_sevs,
                        char const *json_filename) {
  file_ptr f{std::fopen(json_filename, "wt"),
    [](FILE *fp) { return fp ? std::fclose(fp) : 0; }};

  if (!f.get()) {
    NL_LOG_ERR("Unable to open output json file %s", json_filename);
    return false;
  }

  std::string lang, json;
  lang.reserve(2048);
  json.reserve(2048);

  std::fprintf(f.get(), "[\n");
  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    std::fprintf(f.get(), "  {\n");
    std::fprintf(f.get(), "    \"guid\": %u,\n", i);
    std::fprintf(f.get(), "    \"severity\": \"%s\",\n", to_severity(fmt_str_sevs[i]));

    std::fprintf(f.get(), "    \"c_printf\": \"%s\",\n",
      to_json(fmt_strs[i], json).c_str());

    std::fprintf(f.get(), "    \"python\": \"%s\",\n",
      to_json(to_python(fmt_strs[i], lang).c_str(), json).c_str());

    std::fprintf(f.get(), "    \"format_specifiers\": [\n");
    std::fprintf(f.get(), "    ]\n");

    std::fprintf(f.get(), "  }%s\n", (i < (n - 1)) ? "," : "");
  }
  std::fprintf(f.get(), "]\n");
  return true;
}

void emit_bin_fmt_strs(std::vector<char const *> const& fmt_strs,
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

