#include "emit.h"

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 1
#include "nanoprintf.h"

#ifdef _MSC_VER
#pragma warning(disable: 4701) // maybe uninitialized; spurious w/nanoprintf
#endif

namespace {
std::string& emit_escaped_json(char const *s, std::string& out) {
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
          char buf[16];
          std::snprintf(buf, sizeof(buf), "\\u%04hhx", *s);
          out = buf;
        } else {
          out += *s;
        }
    }
    ++s;
  }
  return out;
}

char const *emit_severity(unsigned sev) {
  switch (sev) {
    case NL_SEV_DEBUG: return "debug";
    case NL_SEV_INFO: return "info";
    case NL_SEV_WARNING: return "warning";
    case NL_SEV_ERROR: return "error";
    case NL_SEV_CRITICAL: return "critical";
    case NL_SEV_ASSERT: return "assert";
    case UNCLOG_SEV_DYNAMIC: return "dynamic";
    default: break;
  }
  return "unknown";
}

std::string& emit_python(char const *s, std::string& out) {
  char tmp[16];

  out.clear();
  while (*s) {
    npf_format_spec_t fs;
    int const n{(*s != '%') ? 0 : npf_parse_format_spec(s, &fs)};

    if (NL_LIKELY(!n)) {
      switch (*s) {
        case '{': out += "{{"; break;
        case '}': out += "}}"; break;
        default: out += *s;
      }
      ++s;
      continue;
    }

    s += n;

    if (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT) { out += '%'; continue; }
    if (fs.conv_spec == NPF_FMT_SPEC_CONV_WRITEBACK) { continue; }

    out += "{:";
    if (fs.leading_zero_pad) { out += '0'; }
    if (fs.prepend) { out += fs.prepend; }
    if (fs.alt_form) { out += '#'; }

    switch (fs.field_width_opt) {
      case NPF_FMT_SPEC_OPT_NONE: break;
      case NPF_FMT_SPEC_OPT_STAR: out += "{}"; break;
      case NPF_FMT_SPEC_OPT_LITERAL:
        snprintf(tmp, sizeof(tmp), "%d", (int)fs.field_width); out += tmp;
        break;
    }

    switch (fs.conv_spec) { // python doesn't allow precision for integer types
      case NPF_FMT_SPEC_CONV_STRING:
      case NPF_FMT_SPEC_CONV_FLOAT_DEC:
      case NPF_FMT_SPEC_CONV_FLOAT_SCI:
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
      case NPF_FMT_SPEC_CONV_FLOAT_HEX:
        switch (fs.prec_opt) {
          case NPF_FMT_SPEC_OPT_NONE: break;
          case NPF_FMT_SPEC_OPT_STAR: out += ".{}"; break;
          case NPF_FMT_SPEC_OPT_LITERAL:
            snprintf(tmp, sizeof(tmp), ".%d", (int)fs.prec); out += tmp;
            break;
        }
        break;

      case NPF_FMT_SPEC_CONV_POINTER:
      case NPF_FMT_SPEC_CONV_CHAR:
      case NPF_FMT_SPEC_CONV_BINARY:
      case NPF_FMT_SPEC_CONV_OCTAL:
      case NPF_FMT_SPEC_CONV_HEX_INT:
      case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
      case NPF_FMT_SPEC_CONV_SIGNED_INT:
      default: break;
    }

    switch (fs.conv_spec) {
      case NPF_FMT_SPEC_CONV_POINTER:
      case NPF_FMT_SPEC_CONV_HEX_INT: out += fs.case_adjust ? 'x' : 'X'; break;
      case NPF_FMT_SPEC_CONV_CHAR: out += 'c'; break;
      case NPF_FMT_SPEC_CONV_BINARY: out += 'b'; break;
      case NPF_FMT_SPEC_CONV_OCTAL: out += 'o'; break;
      case NPF_FMT_SPEC_CONV_FLOAT_DEC: out += fs.case_adjust ? 'f' : 'F'; break;
      case NPF_FMT_SPEC_CONV_FLOAT_HEX:
      case NPF_FMT_SPEC_CONV_FLOAT_SCI: out += fs.case_adjust ? 'e' : 'E'; break;
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST: out += fs.case_adjust ? 'g' : 'G'; break;
      default: break;
    }

    out += '}';
  }
  return out;
}

std::string& emit_format_specifiers(char const *s, std::string& out) {
  out.clear();
  bool first = true;
  while (*s) {
    npf_format_spec_t fs;
    int const n{(*s != '%') ? 0 : npf_parse_format_spec(s, &fs)};
    s += n;
    if (NL_LIKELY(!n)) { ++s; continue; }
    if (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT) { continue; }

    out += ",\n";
    if (first) { out += "    \"format_specifiers\": [\n"; }
    first = false;

    out += "      {\n        \"type\": ";
    switch (fs.conv_spec) {
      case NPF_FMT_SPEC_CONV_WRITEBACK: out += "\"writeback\""; break;
      case NPF_FMT_SPEC_CONV_CHAR: out += "\"char\""; break;
      case NPF_FMT_SPEC_CONV_POINTER: out += "\"pointer\""; break;
      case NPF_FMT_SPEC_CONV_STRING: out += "\"string\""; break;
      case NPF_FMT_SPEC_CONV_BINARY: out += "\"binary\""; break;
      case NPF_FMT_SPEC_CONV_OCTAL: out += "\"octal\""; break;
      case NPF_FMT_SPEC_CONV_HEX_INT: out += "\"hex\""; break;
      case NPF_FMT_SPEC_CONV_UNSIGNED_INT: out += "\"unsigned\""; break;
      case NPF_FMT_SPEC_CONV_SIGNED_INT: out += "\"int\""; break;
      case NPF_FMT_SPEC_CONV_FLOAT_DEC: out += "\"float-decimal\""; break;
      case NPF_FMT_SPEC_CONV_FLOAT_SCI: out += "\"float-scientific\""; break;
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST: out += "\"float-shortest\""; break;
      case NPF_FMT_SPEC_CONV_FLOAT_HEX: out += "\"float-hex\""; break;
      default: break;
    }

    if (fs.length_modifier != NPF_FMT_SPEC_LEN_MOD_NONE) {
      out += ",\n        \"length\": ";
      switch (fs.length_modifier) {
        case NPF_FMT_SPEC_LEN_MOD_NONE: break;
        case NPF_FMT_SPEC_LEN_MOD_SHORT: out += "\"short\""; break;
        case NPF_FMT_SPEC_LEN_MOD_LONG_DOUBLE: out += "\"long-double\""; break;
        case NPF_FMT_SPEC_LEN_MOD_CHAR: out += "\"char\""; break;
        case NPF_FMT_SPEC_LEN_MOD_LONG: out += "\"long\""; break;
        case NPF_FMT_SPEC_LEN_MOD_LARGE_LONG_LONG:
        case NPF_FMT_SPEC_LEN_MOD_LARGE_INTMAX:
        case NPF_FMT_SPEC_LEN_MOD_LARGE_SIZET:
        case NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT: out += "\"large\""; break;
        default: break;
      }
    }

    if (fs.field_width_opt != NPF_FMT_SPEC_OPT_NONE) {
      out += ",\n        \"field-width\": ";
      if (fs.field_width_opt == NPF_FMT_SPEC_OPT_STAR) {
        out += "\"dynamic\"";
      } else {
        char num[16];
        std::snprintf(num, sizeof(num), "%d", fs.field_width);
        out += num;
      }
    }

    if (fs.prec_opt != NPF_FMT_SPEC_OPT_NONE) {
      out += ",\n        \"precision\": ";
      if (fs.prec_opt == NPF_FMT_SPEC_OPT_STAR) {
        out += "\"dynamic\"";
      } else {
        char num[16];
        std::snprintf(num, sizeof(num), "%d", fs.prec);
        out += num;
      }
    }

    if (fs.alt_form) { out += ",\n        \"alternate-form\": true"; }
    if (fs.leading_zero_pad) { out += ",\n        \"leading-zero-pad\": true"; }
    if (fs.left_justified) { out += ",\n        \"left-justified\": true"; }

    if (fs.prepend) {
      out += ",\n        \"positive-prefix\": \"";
      out += fs.prepend;
      out += '\"';
    }

    if (!fs.case_adjust) {
      switch (fs.conv_spec) {
        case NPF_FMT_SPEC_CONV_BINARY:
        case NPF_FMT_SPEC_CONV_POINTER:
        case NPF_FMT_SPEC_CONV_HEX_INT:
        case NPF_FMT_SPEC_CONV_FLOAT_DEC:
        case NPF_FMT_SPEC_CONV_FLOAT_SCI:
        case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
        case NPF_FMT_SPEC_CONV_FLOAT_HEX: out += ",\n        \"uppercase\": true"; break;
        default: break;
      }
    }

    out += "\n      }";
  }

  out += '\n';
  if (!first) { out += "    ]\n"; }
  return out;
}
}

bool emit_json_manifest(std::vector<char const *> const& fmt_strs,
                        std::vector<u8> const& fmt_str_sevs,
                        char const *json_filename) {
  file_ptr f{open_file(json_filename, "wt")};

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
    std::fprintf(f.get(), "    \"severity\": \"%s\",\n", emit_severity(fmt_str_sevs[i]));

    std::fprintf(f.get(), "    \"c_printf\": \"%s\",\n",
      emit_escaped_json(fmt_strs[i], json).c_str());

    std::fprintf(f.get(), "    \"python\": \"%s\"",
      emit_escaped_json(emit_python(fmt_strs[i], lang).c_str(), json).c_str());

    std::fprintf(f.get(), "%s", emit_format_specifiers(fmt_strs[i], lang).c_str());

    std::fprintf(f.get(), "  }%s\n", (i < (n - 1)) ? "," : "");
  }
  std::fprintf(f.get(), "]\n");
  return true;
}

void emit_bin_fmt_str(char const *str, unsigned guid, byte_vec& fmt_bin_mem) {
  fmt_bin_mem.push_back(NL_BINARY_LOG_MARKER);

  { // guid
    char guid_enc[16];
    unsigned guid_enc_len;
    nanolog_varint_encode(guid, guid_enc, sizeof(guid_enc), &guid_enc_len);
    fmt_bin_mem.insert(fmt_bin_mem.end(), guid_enc, guid_enc + guid_enc_len);
  }

  int field_count{0};
  char const *cur{str};
  while (*cur) {
    npf_format_spec_t fs;
    int const n{(*cur != '%') ? 0 : npf_parse_format_spec(cur, &fs)};
    if (NL_LIKELY(!n)) { ++cur; continue; }
    cur += n;

    if ((fs.conv_spec == NPF_FMT_SPEC_CONV_WRITEBACK) ||
        (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT)) { continue; }

    if (fs.field_width_opt == NPF_FMT_SPEC_OPT_STAR) {
      if (field_count++ & 1) {
        fmt_bin_mem[fmt_bin_mem.size() - 1] |= byte(NL_ARG_TYPE_FIELD_WIDTH_STAR);
      } else {
        fmt_bin_mem.push_back(byte(NL_ARG_TYPE_FIELD_WIDTH_STAR));
      }
    }

    if (fs.prec_opt == NPF_FMT_SPEC_OPT_STAR) {
      if (field_count++ & 1) {
        fmt_bin_mem[fmt_bin_mem.size() - 1] |= byte(NL_ARG_TYPE_PRECISION_STAR);
      } else {
        fmt_bin_mem.push_back(byte(NL_ARG_TYPE_PRECISION_STAR));
      }
    }

    byte field{0xFF};

    switch (fs.conv_spec) {
      case NPF_FMT_SPEC_CONV_CHAR:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_NONE: field = byte(NL_ARG_TYPE_SCALAR_1_BYTE); break;
          case NPF_FMT_SPEC_LEN_MOD_LONG: field = byte(NL_ARG_TYPE_WINT_T); break;
          default: break;
        } break;

      case NPF_FMT_SPEC_CONV_POINTER: field = byte(NL_ARG_TYPE_POINTER); break;
      case NPF_FMT_SPEC_CONV_STRING: field = byte(NL_ARG_TYPE_STRING); break;

      case NPF_FMT_SPEC_CONV_BINARY:
      case NPF_FMT_SPEC_CONV_OCTAL:
      case NPF_FMT_SPEC_CONV_HEX_INT:
      case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
      case NPF_FMT_SPEC_CONV_SIGNED_INT:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_CHAR: field = byte(NL_ARG_TYPE_SCALAR_1_BYTE); break;
          case NPF_FMT_SPEC_LEN_MOD_SHORT: field = byte(NL_ARG_TYPE_SCALAR_2_BYTE); break;
          case NPF_FMT_SPEC_LEN_MOD_NONE:
          case NPF_FMT_SPEC_LEN_MOD_LONG:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_SIZET:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT:
            field = byte(NL_ARG_TYPE_SCALAR_4_BYTE); break;
          case NPF_FMT_SPEC_LEN_MOD_LARGE_LONG_LONG:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_INTMAX:
            field = byte(NL_ARG_TYPE_SCALAR_8_BYTE); break;
          default: break;
        } break;

      case NPF_FMT_SPEC_CONV_FLOAT_DEC:
      case NPF_FMT_SPEC_CONV_FLOAT_SCI:
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
      case NPF_FMT_SPEC_CONV_FLOAT_HEX:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_NONE: field = byte(NL_ARG_TYPE_DOUBLE); break;
          case NPF_FMT_SPEC_LEN_MOD_LONG: field = byte(NL_ARG_TYPE_LONG_DOUBLE); break;
          default: break;
        } break;

      default: break;
    }

    if (field != 0xFF) {
      if (field_count++ & 1) {
        fmt_bin_mem[fmt_bin_mem.size() - 1] |= byte(field << 4u);
      } else {
        fmt_bin_mem.push_back(byte(field));
      }
    }
  }

  if (field_count & 1) {
    fmt_bin_mem[fmt_bin_mem.size() - 1] |= byte(NL_ARG_TYPE_LOG_END << 4u);
  } else {
    fmt_bin_mem.push_back(byte(NL_ARG_TYPE_LOG_END));
  }
}

void emit_bin_fmt_strs(std::vector<char const *> const& fmt_strs,
                       std::vector<u32>& fmt_bin_addrs,
                       byte_vec& fmt_bin_mem) {
  for (auto str : fmt_strs) {
    fmt_bin_addrs.push_back(unsigned(fmt_bin_mem.size()));
    auto guid{fmt_bin_addrs.empty() ? 0 : unsigned(fmt_bin_addrs.size() - 1)};
    emit_bin_fmt_str(str, guid, fmt_bin_mem);
  }
}

