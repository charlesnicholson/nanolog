#pragma once

#include "../nanolog.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

template <typename ...Args> void unused(Args&& ...args) { (void)sizeof...(args); }

using i8 = int8_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using i32 = int32_t;

using u32_set = std::unordered_set<u32>;
using u32_vec = std::vector<u32>;

using byte = unsigned char;
using byte_vec = std::vector<byte>;
using bytes_ptr = std::unique_ptr<byte[]>;
using file_ptr = std::unique_ptr<FILE, decltype(&fclose)>;

inline file_ptr open_file(char const *fn, char const *mode) {
  auto file_ptr_close = [](FILE *fp) { return fp ? std::fclose(fp) : 0; };
  return file_ptr{std::fopen(fn, mode), file_ptr_close};
}

inline bytes_ptr alloc_bytes(size_t align, size_t len) {
  return bytes_ptr{static_cast<byte *>(std::aligned_alloc(align, len))};
}
