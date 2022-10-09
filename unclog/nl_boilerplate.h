#pragma once

#include <cstdint>

using i8 = int8_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using i32 = int32_t;

template <typename ...Args> void unused(Args&& ...args) { (void)sizeof...(args); }

#ifdef NANOLOG_VERBOSE
#include <cstdio>
#define NL_LOG_DBG(...) printf(__VA_ARGS__)
#else
#define NL_LOG_DBG(...) unused(__VA_ARGS__)
#endif
