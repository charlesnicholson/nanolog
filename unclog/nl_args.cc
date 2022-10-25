#include "nl_args.h"
#include "../nanolog.h"
#include <cstring>

namespace {
void print_usage() {
  NL_LOG_INFO("Usage: unclog <input-file> <-o output-file> [--noreturn-func foo]\n");
}
}

enum next_token {
  ANYTHING,
  OUTPUT_FILE,
  NORETURN_FUNC,
};

bool args_parse(char const *argv[], int const argc, args& out_args) {
  bool ok{true};
  next_token nt{ANYTHING};

  for (int i{1}; i < argc; ++i) {
    if (!ok) { break; }

    switch (nt) {
      case OUTPUT_FILE:
        out_args.output_file = argv[i];
        nt = ANYTHING;
        break;

      case NORETURN_FUNC:
        if (argv[i][0] == '-') { ok = false; break; }
        out_args.noreturn_funcs.push_back(argv[i]);
        nt = ANYTHING;
        break;

      case ANYTHING:
        if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output-file")) {
          if (out_args.output_file) { ok = false; break; }
          nt = OUTPUT_FILE;
          break;
        }

        if (!strcmp(argv[i], "--noreturn-func")) {
          nt = NORETURN_FUNC;
          break;
        }

        if (argv[i][0] == '-') { ok = false; break; }
        if (out_args.input_file) { ok = false; break; }
        out_args.input_file = argv[i];
        break;
    }
  }

  ok = ok && (nt == ANYTHING) && out_args.input_file && out_args.output_file;
  if (!ok) { print_usage(); }
  return ok;
}
