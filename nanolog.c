#include "nanolog.h"
#include <stddef.h>

#ifndef NANOLOG_HOST_TOOL
#include <stdint.h>
#include <wchar.h>
#endif

static nanolog_log_handler_cb_t s_log_handler = NULL;

nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler) {
  s_log_handler = handler;
  return NANOLOG_RET_SUCCESS;
}

#define STAMP_NL_FUNC(sev, SEV) \
  void nanolog_log_##sev(char const *fmt, ...) { \
    va_list args; va_start(args, fmt); \
    if (s_log_handler) { s_log_handler(NL_SEV_##SEV, fmt, args); } \
    va_end(args); \
  }

STAMP_NL_FUNC(dbg, DBG)
STAMP_NL_FUNC(info, INFO)
STAMP_NL_FUNC(warn, WARN)
STAMP_NL_FUNC(err, ERR)
STAMP_NL_FUNC(crit, CRIT)
STAMP_NL_FUNC(assert, ASSERT)
#undef STAMP_NL_FUNC

#ifndef NANOLOG_HOST_TOOL // Only target code uses binary extraction runtime

nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary) {
  if (!fmt || !out_is_binary) { return NANOLOG_RET_ERR_BAD_ARG; }
  *out_is_binary = (fmt[0] == NL_BINARY_PREFIX_MARKER);
  return NANOLOG_RET_SUCCESS;
}

// ARMv7 conventions

_Static_assert(sizeof(signed char) == 1, "");
_Static_assert(sizeof(unsigned char) == 1, "");
_Static_assert(sizeof(signed short) == 2, "");
_Static_assert(sizeof(unsigned short) == 2, "");
_Static_assert(sizeof(int) == 4, "");
_Static_assert(sizeof(unsigned) == 4, "");
_Static_assert(sizeof(long) == 4, "");
_Static_assert(sizeof(unsigned long) == 4, "");
_Static_assert(sizeof(size_t) == 4, "");
_Static_assert(sizeof(ptrdiff_t) == 4, "");
_Static_assert(sizeof(long long) == 8, "");
_Static_assert(sizeof(unsigned long long) == 8, "");
_Static_assert(sizeof(intmax_t) == 8, "");
_Static_assert(sizeof(uintmax_t) == 8, "");

static void nanolog_extract_and_dispatch(nanolog_binary_field_handler_cb_t cb,
                                         void *ctx,
                                         nl_arg_type_t type,
                                         va_list args) {
  switch (type) {
    case NL_ARG_TYPE_SCALAR_1_BYTE: {
      char const c = (char)va_arg(args, int); cb(ctx, type, &c, sizeof(c));
    } break;

    case NL_ARG_TYPE_SCALAR_2_BYTE: {
      short const s = (short)va_arg(args, int); cb(ctx, type, &s, sizeof(s));
    } break;

    case NL_ARG_TYPE_SCALAR_4_BYTE: {
      int const i = va_arg(args, int); cb(ctx, type, &i, sizeof(i));
    } break;

    case NL_ARG_TYPE_SCALAR_8_BYTE: {
      long long const ll = va_arg(args, long long); cb(ctx, type, &ll, sizeof(ll));
    } break;

    case NL_ARG_TYPE_STRING: {
      unsigned char vi[8];
      char const *s = va_arg(args, char const *);
      unsigned sl = 0, vil = 0;
      for (char const *c = s; *c; ++c, ++sl); // gcc recognizes this as strlen
      for (unsigned sl_vi = sl; sl_vi; ++vil, sl_vi >>= 7u) {
        vi[vil] = (unsigned char)((sl_vi & 0x7Fu) | 0x80u);
      }
      vi[vil++] &= ~0x80u;
      cb(ctx, NL_ARG_TYPE_STRING_LEN_VARINT, vi, vil);
      cb(ctx, NL_ARG_TYPE_STRING, s, sl);
    } break;

    case NL_ARG_TYPE_POINTER: {
      void *const v = va_arg(args, void *); cb(ctx, type, &v, sizeof(v));
    } break;

    case NL_ARG_TYPE_DOUBLE: {
      double const d = va_arg(args, double); cb(ctx, type, &d, sizeof(d));
    } break;
    case NL_ARG_TYPE_LONG_DOUBLE: {
      long double const ld = va_arg(args, long double); cb(ctx, type, &ld, sizeof(ld));
    } break;

    case NL_ARG_TYPE_WINT_T: {
      wint_t const w = va_arg(args, wint_t); cb(ctx, type, &w, sizeof(w));
    } break;

    case NL_ARG_TYPE_END_OF_LIST: cb(ctx, type, NULL, 0); break;

    // never happens
    case NL_ARG_TYPE_GUID:
    case NL_ARG_TYPE_STRING_LEN_VARINT:
      break;
  }
}

nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       char const *fmt,
                                       va_list args) {
  if (!cb || !fmt) { return NANOLOG_RET_ERR_BAD_ARG; }

  unsigned char const *src = (unsigned char const*)fmt;
  if (*src++ != NL_BINARY_PREFIX_MARKER) { return NANOLOG_RET_INVALID_PAYLOAD; }

  { // GUID is varint-encoded, ends at first byte w/o a high "continuation" bit (0x80)
    unsigned char const *guid = src;
    while (*src & 0x80) { ++src; }
    cb(ctx, NL_ARG_TYPE_GUID, guid, (unsigned)(++src - guid));
  }

  // Types are packed, two per byte, low nibble first.
  for (nl_arg_type_t type; ; ++src) {
    type = (nl_arg_type_t)(*src & 0xFu);
    nanolog_extract_and_dispatch(cb, ctx, type, args);
    if (type == NL_ARG_TYPE_END_OF_LIST) { break; }
    type = (nl_arg_type_t)(*src >> 4u);
    nanolog_extract_and_dispatch(cb, ctx, type, args);
    if (type == NL_ARG_TYPE_END_OF_LIST) { break; }
  }

  return NANOLOG_RET_SUCCESS;
}

#endif // NANOLOG_HOST_TOOL

