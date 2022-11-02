#include "nl_args.h"
#include "../nanolog.h"
#include <cstring>

namespace {
void print_usage() {
  NL_LOG_INF("Usage: unclog <input-file> "
             "<-o output-elf> "
             "<-j output-json> "
             "[--noreturn-func foo]\n");
}
}

enum next_token {
  ANYTHING,
  OUTPUT_ELF,
  OUTPUT_JSON,
  NORETURN_FUNC,
};

bool args_parse(char const *argv[], int const argc, args& out_args) {
  bool ok{true};
  next_token nt{ANYTHING};

  for (int i{1}; i < argc; ++i) {
    if (!ok) { break; }

    switch (nt) {
      case OUTPUT_ELF:
        out_args.output_elf = argv[i];
        nt = ANYTHING;
        break;

      case OUTPUT_JSON:
        out_args.output_json = argv[i];
        nt = ANYTHING;
        break;

      case NORETURN_FUNC:
        if (argv[i][0] == '-') { ok = false; break; }
        out_args.noreturn_funcs.push_back(argv[i]);
        nt = ANYTHING;
        break;

      case ANYTHING:
        if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output-elf")) {
          if (out_args.output_elf) { ok = false; break; }
          nt = OUTPUT_ELF;
          break;
        }

        if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--output-json")) {
          if (out_args.output_json) { ok = false; break; }
          nt = OUTPUT_JSON;
          break;
        }

        if (!strcmp(argv[i], "--noreturn-func")) {
          nt = NORETURN_FUNC;
          break;
        }

        if (argv[i][0] == '-') { ok = false; break; }
        if (out_args.input_elf) { ok = false; break; }
        out_args.input_elf = argv[i];
        break;
    }
  }

  ok = ok && (nt == ANYTHING) && out_args.input_elf && out_args.output_elf &&
       out_args.output_json;

  if (!ok) { print_usage(); }
  return ok;
}
