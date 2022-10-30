#include "nl_json.h"
#include <cstdio>
#include <string>
#include <memory>

namespace {

std::string& print_c_printf(char const *s, std::string& out_line) {
  char hex_str[16];
  out_line.clear();
  while (*s) {
    switch (*s) {
      case '"': out_line += "\\\""; break;
      case '\\': out_line += "\\\\"; break;
      case '\b': out_line += "\\b"; break;
      case '\f': out_line += "\\f"; break;
      case '\n': out_line += "\\n"; break;
      case '\r': out_line += "\\r"; break;
      case '\t': out_line += "\\t"; break;
      default:
        if (*s <= 0x1F) {
          snprintf(hex_str, sizeof(hex_str), "\\u%04hhx", *s);
          out_line += hex_str;
        } else {
          out_line += *s;
        }
    }
    ++s;
  }
  return out_line;
}

}

bool json_write_manifest(std::vector<char const *> const& fmt_strs,
                         char const *json_filename) {
  std::unique_ptr<FILE, int(*)(FILE*)> fp(std::fopen(json_filename, "wt"),
    [](FILE *f)->int{ return f ? std::fclose(f) : 0; });

  if (!fp.get()) {
    NL_LOG_ERR("Unable to open output json file %s", json_filename);
    return false;
  }

  std::string line;
  line.reserve(16384);

  std::fprintf(fp.get(), "[\n");
  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    fputs("  {\n", fp.get());
    fprintf(fp.get(), "    \"guid\": %u,\n", i);

    fprintf(fp.get(), "    \"c_printf\": \"");
    fputs(print_c_printf(fmt_strs[i], line).c_str(), fp.get());
    fputs("\",\n", fp.get());

    fprintf(fp.get(), "    \"python_format\": \"");
    fputs("\"\n", fp.get());

    fprintf(fp.get(), "  }%s\n", (i < n - 1) ? "," : "");
  }
  std::fprintf(fp.get(), "]\n");
  return true;
}
