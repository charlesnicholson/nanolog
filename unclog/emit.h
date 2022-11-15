#pragma once

#include "boilerplate.h"

void emit_bin_fmt_strs(std::vector<char const *> const& fmt_strs,
                       u32_vec& fmt_bin_addrs,
                       byte_vec& fmt_bin_mem);

bool emit_json_manifest(std::vector<char const *> const& fmt_strs,
                        std::vector<u8> const& fmt_str_sevs,
                        char const *json_filename);
