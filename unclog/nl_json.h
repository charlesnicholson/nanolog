#pragma once
#include "nl_boilerplate.h"

bool json_write_manifest(std::vector<char const *> const& fmt_strs,
                         char const *json_filename);
