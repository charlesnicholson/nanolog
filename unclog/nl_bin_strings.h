#pragma once

#include "nl_boilerplate.h"

void convert_strings_to_bins(std::vector<char const *> const& fmt_strs,
                             std::vector<u32>& fmt_bin_addrs,
                             std::vector<unsigned char>& fmt_bin_mem);
