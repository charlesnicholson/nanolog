#pragma once
#include "nl_boilerplate.h"

bool json_write_manifest(std::vector<char const *> const& fmt_strs,
                         std::vector<u8> const& fmt_str_sevs,
                         char const *json_filename);
