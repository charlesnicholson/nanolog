#include "nl_args.h"

bool args_parse(char const *argv[], int const argc, args& out_args) {
  if (argc != 3) { return false; }
  out_args.input_file = argv[1];
  out_args.output_file = argv[2];
  return true;
}
