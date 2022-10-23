#include "nl_args.h"
#include <cstdio>
#include <cstring>

namespace {
void print_usage() { printf("Usage: unclog <input-file> <-o output-file>\n"); }
}

enum next_token {
  ANYTHING,
  OUTPUT_FILE,
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

      case ANYTHING:
        if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output-file")) {
          if (out_args.output_file) { ok = false; break; }
          nt = OUTPUT_FILE;
          break;
        }

        if (argv[i][0] == '-') { ok = false; break; }
        if (out_args.input_file) { ok = false; break; }
        out_args.input_file = argv[i];
        break;
    }
  }

  if (!ok || (nt != ANYTHING)) { print_usage(); }
  return ok;
}
