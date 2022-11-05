#pragma once
#include "nl_boilerplate.h"

struct args {
  bool verbose = false;
  char const *input_elf = nullptr;
  char const *output_elf = nullptr;
  char const *output_json = nullptr;
  std::vector<char const *> noreturn_funcs;
};

bool args_parse(char const *argv[], int const argc, args& out_args);
