#include "nl_json.h"
#include <cstdio>
#include <string>
#include <memory>

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

std::string& to_python(char const *s, std::string& out) {
  out.clear();

  while (*s) {
    npf_format_spec_t fs;
    int const n{(*s != '%') ? 0 : npf_parse_format_spec(s, &fs)};
    if (!n) { out += *s++; continue; }
    s += n;
    out += "{}";

    //switch (fs.conv_spec) {
    //  case NPF_FMT_SPEC_CONV_WRITEBACK:
    //  case NPF_FMT_SPEC_CONV_PERCENT:
    //    break;
  }
  return out;
}
}

bool json_write_manifest(std::vector<char const *> const& fmt_strs, char const *fn) {
  file_ptr f{std::fopen(fn, "wt"), [](FILE *fp) { return fp ? std::fclose(fp) : 0; }};

  if (!f.get()) {
    NL_LOG_ERR("Unable to open output json file %s", fn);
    return false;
  }

  std::string lang, json;
  lang.reserve(2048);
  json.reserve(2048);

  std::fprintf(f.get(), "[\n");
  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    fputs("  {\n", f.get());
    fprintf(f.get(), "    \"guid\": %u,\n", i);

    fprintf(f.get(), "    \"c_printf\": \"");
    fputs(to_json(fmt_strs[i], json).c_str(), f.get());
    fputs("\",\n", f.get());

    fprintf(f.get(), "    \"python_format\": \"");
    fputs(to_json(to_python(fmt_strs[i], lang).c_str(), json).c_str(), f.get());
    fputs("\"\n", f.get());

    fprintf(f.get(), "  }%s\n", (i < (n - 1)) ? "," : "");
  }
  std::fprintf(f.get(), "]\n");
  return true;
}
