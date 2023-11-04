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
#pragma warning(disable : 4701)  // maybe uninitialized; spurious w/nanoprintf
#endif

namespace {
std::string& emit_escaped_json(char const* s, std::string& out) {
  out.clear();
  while (*s) {
    switch (*s) {
        // clang-format off
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      // clang-format on
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

char const* emit_severity(unsigned sev) {
  switch (sev) {
      // clang-format off
    case NL_SEV_DEBUG: return "debug";
    case NL_SEV_INFO: return "info";
    case NL_SEV_WARNING: return "warning";
    case NL_SEV_ERROR: return "error";
    case NL_SEV_CRITICAL: return "critical";
    case NL_SEV_ASSERT: return "assert";
    case UNCLOG_SEV_DYNAMIC: return "dynamic";
    default: break;
      // clang-format on
  }
  return "unknown";
}

std::string& emit_python(char const* s, std::string& out) {
  char tmp[16];

  out.clear();
  while (*s) {
    npf_format_spec_t fs;
    int const n{ (*s != '%') ? 0 : npf_parse_format_spec(s, &fs) };

    if (NANOLOG_LIKELY(!n)) {
      switch (*s) {
          // clang-format off
        case '{': out += "{{"; break;
        case '}': out += "}}"; break;
        default: out += *s;
          // clang-format on
      }
      ++s;
      continue;
    }

    s += n;

    if (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT) {
      out += '%';
      continue;
    }
    if (fs.conv_spec == NPF_FMT_SPEC_CONV_WRITEBACK) {
      continue;
    }

    out += "{:";
    if (fs.leading_zero_pad) {
      out += '0';
    }
    if (fs.prepend) {
      out += fs.prepend;
    }
    if (fs.alt_form) {
      out += '#';
    }

    switch (fs.field_width_opt) {
        // clang-format off
      case NPF_FMT_SPEC_OPT_NONE: break;
      case NPF_FMT_SPEC_OPT_STAR: out += "{}"; break;
      case NPF_FMT_SPEC_OPT_LITERAL:
        snprintf(tmp, sizeof(tmp), "%d", (int)fs.field_width); out += tmp;
        break;
        // clang-format on
    }

    switch (fs.conv_spec) {  // python doesn't allow precision for integer types
      case NPF_FMT_SPEC_CONV_STRING:
      case NPF_FMT_SPEC_CONV_FLOAT_DEC:
      case NPF_FMT_SPEC_CONV_FLOAT_SCI:
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
      case NPF_FMT_SPEC_CONV_FLOAT_HEX:
        switch (fs.prec_opt) {
            // clang-format off
          case NPF_FMT_SPEC_OPT_NONE: break;
          case NPF_FMT_SPEC_OPT_STAR: out += ".{}"; break;
          case NPF_FMT_SPEC_OPT_LITERAL:
            snprintf(tmp, sizeof(tmp), ".%d", (int)fs.prec); out += tmp;
            break;
            // clang-format on
        }
        break;

      case NPF_FMT_SPEC_CONV_POINTER:
      case NPF_FMT_SPEC_CONV_CHAR:
      case NPF_FMT_SPEC_CONV_BINARY:
      case NPF_FMT_SPEC_CONV_OCTAL:
      case NPF_FMT_SPEC_CONV_HEX_INT:
      case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
      case NPF_FMT_SPEC_CONV_SIGNED_INT:
      default:
        break;
    }

    switch (fs.conv_spec) {
        // clang-format off
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
        // clang-format on
    }

    out += '}';
  }
  return out;
}

std::string& emit_format_specifiers(char const* s, std::string& out) {
  out.clear();
  bool first{ true };
  while (*s) {
    npf_format_spec_t fs;
    int const n{ (*s != '%') ? 0 : npf_parse_format_spec(s, &fs) };
    s += n;
    if (NANOLOG_LIKELY(!n)) {
      ++s;
      continue;
    }
    if (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT) {
      continue;
    }

    out += ",\n";
    if (first) {
      out += "    \"format_specifiers\": [\n";
    }
    first = false;

    out += "      {\n        \"type\": ";
    switch (fs.conv_spec) {
        // clang-format off
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
        // clang-format on
    }

    if (fs.length_modifier != NPF_FMT_SPEC_LEN_MOD_NONE) {
      out += ",\n        \"length\": ";
      switch (fs.length_modifier) {
          // clang-format off
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
          // clang-format on
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

    if (fs.alt_form) {
      out += ",\n        \"alternate-form\": true";
    }
    if (fs.leading_zero_pad) {
      out += ",\n        \"leading-zero-pad\": true";
    }
    if (fs.left_justified) {
      out += ",\n        \"left-justified\": true";
    }

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
        case NPF_FMT_SPEC_CONV_FLOAT_HEX:
          out += ",\n        \"uppercase\": true";
          break;
        default:
          break;
      }
    }

    out += "\n      }";
  }

  out += '\n';
  if (!first) {
    out += "    ]\n";
  }
  return out;
}

bool parse_assert_string(char const* s,
                         char const*& assert_file_start,
                         int& assert_file_len,
                         char const*& assert_line_start,
                         int& assert_line_len) {
  assert_file_start = s;

  auto i{ 0 };
  while (s[i]) {
    if (s[i] == '(') {
      assert_file_len = i;
      break;
    }
    ++i;
  }

  if (!s[i]) {
    return false;
  }

  auto const line_start_off{ ++i };
  assert_line_start = &s[line_start_off];

  while (s[i]) {
    if (s[i] == ')') {
      assert_line_len = i - line_start_off;
      break;
    }
    ++i;
  }

  return s[i];
}
}  // namespace

bool emit_json_manifest(std::vector<char const*> const& fmt_strs,
                        std::vector<u8> const& fmt_str_sevs,
                        std::vector<char const*> const& fmt_funcs,
                        char const* json_filename) {
  file_ptr f{ open_file(json_filename, "wt") };

  if (!f.get()) {
    NL_LOG_ERR("Unable to open output json file %s", json_filename);
    return false;
  }

  std::string lang, json;
  lang.reserve(2048);
  json.reserve(2048);

  std::fprintf(f.get(), "[\n");
  for (auto i{ 0u }, n{ unsigned(fmt_strs.size()) }; i < n; ++i) {
    std::fprintf(f.get(), "  {\n");
    std::fprintf(f.get(), "    \"guid\": %u,\n", i);
    std::fprintf(f.get(), "    \"severity\": \"%s\",\n", emit_severity(fmt_str_sevs[i]));

    if (fmt_str_sevs[i] == NL_SEV_ASSERT) {
      char const* assert_file_start;
      int assert_file_len;
      char const* assert_line_start;
      int assert_line_len;
      parse_assert_string(fmt_strs[i],
                          assert_file_start,
                          assert_file_len,
                          assert_line_start,
                          assert_line_len);
      std::fprintf(f.get(),
                   "    \"assert_file\": \"%.*s\",\n",
                   assert_file_len,
                   assert_file_start);
      std::fprintf(f.get(),
                   "    \"assert_line\": \"%.*s\",\n",
                   assert_line_len,
                   assert_line_start);
    }

    std::fprintf(f.get(), "    \"function\": \"%s\",\n", fmt_funcs[i]);

    std::fprintf(f.get(),
                 "    \"c_printf\": \"%s\",\n",
                 emit_escaped_json(fmt_strs[i], json).c_str());

    std::fprintf(f.get(),
                 "    \"python\": \"%s\"",
                 emit_escaped_json(emit_python(fmt_strs[i], lang).c_str(), json).c_str());

    std::fprintf(f.get(), "%s", emit_format_specifiers(fmt_strs[i], lang).c_str());
    std::fprintf(f.get(), "  }%s\n", (i < (n - 1)) ? "," : "");
  }
  std::fprintf(f.get(), "]\n");
  return true;
}

namespace {
void emit_nibble(byte val, byte_vec& v, bool& lo_nibble) {
  if (lo_nibble) {
    v.push_back(val);
  } else {
    v[v.size() - 1] |= byte(val << 4u);
  }
  lo_nibble = !lo_nibble;
}
}  // namespace

void emit_bin_fmt_str(char const* str, unsigned guid, byte_vec& fmt_bin_mem) {
  fmt_bin_mem.push_back(NL_BINARY_LOG_MARKER);

  {  // guid
    char guid_enc[16];
    unsigned guid_enc_len;
    nanolog_varint_encode(guid, guid_enc, sizeof(guid_enc), &guid_enc_len);
    fmt_bin_mem.insert(fmt_bin_mem.end(), guid_enc, guid_enc + guid_enc_len);
  }

  bool lo_nibble{ true };
  char const* cur{ str };
  while (*cur) {
    npf_format_spec_t fs;
    int const n{ (*cur != '%') ? 0 : npf_parse_format_spec(cur, &fs) };
    if (NANOLOG_LIKELY(!n)) {
      ++cur;
      continue;
    }
    cur += n;

    if ((fs.conv_spec == NPF_FMT_SPEC_CONV_WRITEBACK) ||
        (fs.conv_spec == NPF_FMT_SPEC_CONV_PERCENT)) {
      continue;
    }

    if (fs.field_width_opt == NPF_FMT_SPEC_OPT_STAR) {
      emit_nibble(NL_ARG_TYPE_FIELD_WIDTH_STAR, fmt_bin_mem, lo_nibble);
    }

    if (fs.prec_opt == NPF_FMT_SPEC_OPT_STAR) {
      emit_nibble(NL_ARG_TYPE_PRECISION_STAR, fmt_bin_mem, lo_nibble);
    }

    switch (fs.conv_spec) {
      case NPF_FMT_SPEC_CONV_CHAR:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_NONE:
            emit_nibble(NL_ARG_TYPE_SCALAR_1_BYTE, fmt_bin_mem, lo_nibble);
            break;
          case NPF_FMT_SPEC_LEN_MOD_LONG:
            emit_nibble(NL_ARG_TYPE_WINT_T, fmt_bin_mem, lo_nibble);
            break;
          default:
            break;
        }
        break;

      case NPF_FMT_SPEC_CONV_POINTER:
        emit_nibble(NL_ARG_TYPE_POINTER, fmt_bin_mem, lo_nibble);
        break;

      case NPF_FMT_SPEC_CONV_STRING:
        if (fs.prec_opt == NPF_FMT_SPEC_OPT_LITERAL) {
          emit_nibble(NL_ARG_TYPE_STRING_PRECISION_LITERAL, fmt_bin_mem, lo_nibble);
          char lit_enc[16];
          unsigned lit_enc_len{ 0 };
          nanolog_varint_encode(unsigned(fs.prec), lit_enc, sizeof(lit_enc), &lit_enc_len);
          fmt_bin_mem.insert(fmt_bin_mem.end(), lit_enc, lit_enc + lit_enc_len);
          lo_nibble = true;
        }
        emit_nibble(NL_ARG_TYPE_STRING, fmt_bin_mem, lo_nibble);
        break;

      case NPF_FMT_SPEC_CONV_BINARY:
      case NPF_FMT_SPEC_CONV_OCTAL:
      case NPF_FMT_SPEC_CONV_HEX_INT:
      case NPF_FMT_SPEC_CONV_UNSIGNED_INT:
      case NPF_FMT_SPEC_CONV_SIGNED_INT:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_CHAR:
            emit_nibble(NL_ARG_TYPE_SCALAR_1_BYTE, fmt_bin_mem, lo_nibble);
            break;
          case NPF_FMT_SPEC_LEN_MOD_SHORT:
            emit_nibble(NL_ARG_TYPE_SCALAR_2_BYTE, fmt_bin_mem, lo_nibble);
            break;
          case NPF_FMT_SPEC_LEN_MOD_NONE:
          case NPF_FMT_SPEC_LEN_MOD_LONG:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_SIZET:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT:
            emit_nibble(NL_ARG_TYPE_SCALAR_4_BYTE, fmt_bin_mem, lo_nibble);
            break;
          case NPF_FMT_SPEC_LEN_MOD_LARGE_LONG_LONG:
          case NPF_FMT_SPEC_LEN_MOD_LARGE_INTMAX:
            emit_nibble(NL_ARG_TYPE_SCALAR_8_BYTE, fmt_bin_mem, lo_nibble);
            break;
          default:
            break;
        }
        break;

      case NPF_FMT_SPEC_CONV_FLOAT_DEC:
      case NPF_FMT_SPEC_CONV_FLOAT_SCI:
      case NPF_FMT_SPEC_CONV_FLOAT_SHORTEST:
      case NPF_FMT_SPEC_CONV_FLOAT_HEX:
        switch (fs.length_modifier) {
          case NPF_FMT_SPEC_LEN_MOD_NONE:
            emit_nibble(NL_ARG_TYPE_DOUBLE, fmt_bin_mem, lo_nibble);
            break;
          case NPF_FMT_SPEC_LEN_MOD_LONG:
            emit_nibble(NL_ARG_TYPE_LONG_DOUBLE, fmt_bin_mem, lo_nibble);
            break;
          default:
            break;
        }
        break;

      default:
        break;
    }
  }

  emit_nibble(NL_ARG_TYPE_LOG_END, fmt_bin_mem, lo_nibble);
}

void emit_bin_fmt_strs(std::vector<char const*> const& fmt_strs,
                       std::vector<u32>& fmt_bin_addrs,
                       byte_vec& fmt_bin_mem) {
  for (auto guid{ 0u }; auto str : fmt_strs) {
    fmt_bin_addrs.push_back(unsigned(fmt_bin_mem.size()));
    emit_bin_fmt_str(str, guid++, fmt_bin_mem);
  }
}
