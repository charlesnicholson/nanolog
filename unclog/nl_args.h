#pragma once

#include <vector>

struct args {
  char const *input_file = nullptr;
  char const *output_file = nullptr;
  std::vector<char const *> noreturn_funcs;
};

bool args_parse(char const *argv[], int const argc, args& out_args);
