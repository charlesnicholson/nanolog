#include "nl_json.h"
#include <cstdio>
#include <string>

struct file_closer {
  explicit file_closer(FILE *fp_) : fp(fp_) {}
  ~file_closer() { if (fp) { std::fclose(fp); } }
  FILE *fp;
};

bool json_write_manifest(std::vector<char const *> const& fmt_strs,
                         char const *json_filename) {
  file_closer const fc(std::fopen(json_filename, "wt"));
  if (!fc.fp) {
    NL_LOG_ERR("Unable to open output json file %s", json_filename);
    return false;
  }

  std::string line;
  line.reserve(16384);
  char hex_str[16];

  std::fprintf(fc.fp, "[\n");
  for (auto i{0u}, n{unsigned(fmt_strs.size())}; i < n; ++i) {
    line.clear();
    line += "  \"";
    char const *cur{fmt_strs[i]};
    while (*cur) {
      switch (*cur) {
        case '"': line += "\\\""; break;
        case '\\': line += "\\\\"; break;
        case '\b': line += "\\b"; break;
        case '\f': line += "\\f"; break;
        case '\n': line += "\\n"; break;
        case '\r': line += "\\r"; break;
        case '\t': line += "\\t"; break;
        default:
          if (*cur <= 0x1F) {
            snprintf(hex_str, sizeof(hex_str), "\\u%04hhx", *cur);
            line += hex_str;
          } else {
            line += *cur;
          }
      }
      ++cur;
    }
    line += '"';
    if (i < n-1) { line += ','; }
    line += '\n';

    fputs(line.c_str(), fc.fp);
  }
  std::fprintf(fc.fp, "]\n");
  return true;
}
