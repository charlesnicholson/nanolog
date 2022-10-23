#pragma once

struct args {
  char const *input_file = nullptr;
  char const *output_file = nullptr;
};

bool args_parse(char const *argv[], int const argc, args& out_args);
