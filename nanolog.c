#include "nanolog.h"
#include <stddef.h>

static nanolog_log_handler_cb_t s_log_handler = NULL;

nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler) {
  s_log_handler = handler;
  return NANOLOG_RET_SUCCESS;
}

#ifndef NANOLOG_HOST_TOOL // Only target code uses binary extraction runtime

#include <stdint.h>
#include <wchar.h>

nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary) {
  if (!fmt || !out_is_binary) { return NANOLOG_RET_ERR_BAD_ARG; }
  *out_is_binary = (fmt[0] == NL_BINARY_PREFIX_MARKER);
  return NANOLOG_RET_SUCCESS;
}

//_Static_assert(sizeof(long) == sizeof(size_t), ""); // ssize_t isn't standard
//typedef union { // All the legal printf argument types
//  char scalar_1_byte;
//  short scalar_2_byte;
//  int scalar_4_byte;
//  long long scalar_8_byte;
//  void *ptr;
//  double dbl;
//  long double long_dbl;
//} nl_extract_t;

//#define NL_EXTRACT_CB(FIELD, CAST_TO, EXTRACT_AS) \
//  FIELD = (CAST_TO)va_arg(args, EXTRACT_AS); cb(ctx, &FIELD, sizeof(FIELD));
//#define NL_EXTRACT_CB_SAME(FIELD, TYPE) NL_EXTRACT_CB(FIELD, TYPE, TYPE)

nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       char const *fmt,
                                       va_list args) {
  if (!cb || !fmt) { return NANOLOG_RET_ERR_BAD_ARG; }

  unsigned char const *src = (unsigned char const*)fmt;
  if (*src != NL_BINARY_PREFIX_MARKER) { return NANOLOG_RET_INVALID_PAYLOAD; }
  ++src;

  uint32_t guid = 0; {
    unsigned ofs = 0;
    do { guid |= ((*src & 0x7Fu) << ofs); ofs += 7; } while (*src & 0x80u);
  }

//  nl_extract_t e;
//  while (*src != 0xFF) {
//    switch (*src++) {
//  NL_VARARG_TYPE_SCALAR_1_BYTE = 0,
//  NL_VARARG_TYPE_SCALAR_2_BYTE = 1,
//  NL_VARARG_TYPE_SCALAR_4_BYTE = 2,
//  NL_VARARG_TYPE_SCALAR_8_BYTE = 3,
//  NL_VARARG_TYPE_POINTER = 4,
//  NL_VARARG_TYPE_DOUBLE = 5,
//  NL_VARARG_TYPE_LONG_DOUBLE = 6,
//  NL_VARARG_TYPE_WINT_T = 7,
//  NL_VARARG_TYPE_END_OF_LIST = 0xF,
//
//      case NL_VARARG_TYPE_SCHAR: NL_EXTRACT_CB(e.sc, signed char, int); break;
//      case NL_VARARG_TYPE_UCHAR: NL_EXTRACT_CB(e.uc, unsigned char, int); break;
//      case NL_VARARG_TYPE_SHORT: NL_EXTRACT_CB(e.ss, short, int); break;
//      case NL_VARARG_TYPE_USHORT: NL_EXTRACT_CB(e.us, unsigned short, int); break;
//      case NL_VARARG_TYPE_SINT: NL_EXTRACT_CB_SAME(e.si, int); break;
//      case NL_VARARG_TYPE_UINT: NL_EXTRACT_CB_SAME(e.ui, unsigned int); break;
//      case NL_VARARG_TYPE_SLONG: NL_EXTRACT_CB_SAME(e.sl, long); break;
//      case NL_VARARG_TYPE_ULONG: NL_EXTRACT_CB_SAME(e.ul,  unsigned long); break;
//      case NL_VARARG_TYPE_SLONG_LONG: NL_EXTRACT_CB_SAME(e.sll, long long); break;
//      case NL_VARARG_TYPE_ULONG_LONG: NL_EXTRACT_CB_SAME(e.ull, unsigned long long); break;
//      case NL_VARARG_TYPE_SSIZE_T: NL_EXTRACT_CB_SAME(e.ssizet, long); break;
//      case NL_VARARG_TYPE_SIZE_T: NL_EXTRACT_CB_SAME(e.sizet, size_t); break;
//      case NL_VARARG_TYPE_SINTMAX_T: NL_EXTRACT_CB_SAME(e.sim, intmax_t); break;
//      case NL_VARARG_TYPE_UINTMAX_T: NL_EXTRACT_CB_SAME(e.uim, uintmax_t); break;
//      case NL_VARARG_TYPE_WINT_T: NL_EXTRACT_CB_SAME(e.wintt, wint_t); break;
//      case NL_VARARG_TYPE_CHAR_PTR: NL_EXTRACT_CB_SAME(e.cp, char *); break;
//      case NL_VARARG_TYPE_WCHAR_T_PTR: NL_EXTRACT_CB_SAME(e.wcp, wchar_t *); break;
//      case NL_VARARG_TYPE_PTRDIFF_T: NL_EXTRACT_CB_SAME(e.pdt, ptrdiff_t); break;
//      case NL_VARARG_TYPE_UPTRDIFF_T: NL_EXTRACT_CB_SAME(e.updt, uintptr_t); break;
//      case NL_VARARG_TYPE_DOUBLE: NL_EXTRACT_CB_SAME(e.d, double); break;
//      case NL_VARARG_TYPE_LONG_DOUBLE: NL_EXTRACT_CB_SAME(e.ld, long double); break;
//      default: return NANOLOG_RET_INVALID_PAYLOAD;
//    }
//  }

  return NANOLOG_RET_SUCCESS;
}

#endif // NANOLOG_HOST_TOOL

#undef NL_EXTRACT_CB
#undef NL_EXTRACT_CB_SAME

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

