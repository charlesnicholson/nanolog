#include "nanolog.h"

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

_Static_assert(NL_BINARY_PREFIX_MARKER >= NL_VARARG_LAST_PLUS_ONE_DO_NOT_USE, "");

static nanolog_log_handler_cb_t s_log_handler = NULL;

nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler) {
  s_log_handler = handler;
  return NANOLOG_RET_SUCCESS;
}

nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary) {
  if (!fmt || !out_is_binary) { return NANOLOG_RET_ERR_BAD_ARG; }
  *out_is_binary = (fmt[0] == NL_BINARY_PREFIX_MARKER);
  return NANOLOG_RET_SUCCESS;
}

_Static_assert(sizeof(long) == sizeof(size_t), ""); // ssize_t isn't standard
typedef union { // All the legal printf argument types
  signed char sc; unsigned char uc;
  short ss; unsigned short us;
  int si; unsigned int ui;
  long sl; unsigned long ul;
  long long sll; unsigned long long ull;
  long ssizet; size_t sizet;
  intmax_t sim; uintmax_t uim;
  wint_t wintt;
  char *cp; wchar_t *wcp;
  ptrdiff_t pdt; uintptr_t updt;
  double d; long double ld;
} nl_extract_t;

#define NL_EXTRACT_CB(FIELD, CAST_TO, EXTRACT_AS) \
  FIELD = (CAST_TO)va_arg(args, EXTRACT_AS); cb(ctx, &FIELD, sizeof(FIELD));
#define NL_EXTRACT_CB_SAME(FIELD, TYPE) NL_EXTRACT_CB(FIELD, TYPE, TYPE)

nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       char const *fmt,
                                       va_list args) {
  if (!cb || !fmt) { return NANOLOG_RET_ERR_BAD_ARG; }

  unsigned char const *src = (unsigned char const*)fmt;
  if (*src != NL_BINARY_PREFIX_MARKER) { return NANOLOG_RET_INVALID_PAYLOAD; }

  cb(ctx, src, 4); // binary marker and format string guid
  src += 4;

  nl_extract_t e;
  while (*src != 0xFF) {
    switch (*src++) {
      case NL_VARARG_TYPE_SCHAR: NL_EXTRACT_CB(e.sc, signed char, int); break;
      case NL_VARARG_TYPE_UCHAR: NL_EXTRACT_CB(e.uc, unsigned char, int); break;
      case NL_VARARG_TYPE_SHORT: NL_EXTRACT_CB(e.ss, short, int); break;
      case NL_VARARG_TYPE_USHORT: NL_EXTRACT_CB(e.us, unsigned short, int); break;
      case NL_VARARG_TYPE_SINT: NL_EXTRACT_CB_SAME(e.si, int); break;
      case NL_VARARG_TYPE_UINT: NL_EXTRACT_CB_SAME(e.ui, unsigned int); break;
      case NL_VARARG_TYPE_SLONG: NL_EXTRACT_CB_SAME(e.sl, long); break;
      case NL_VARARG_TYPE_ULONG: NL_EXTRACT_CB_SAME(e.ul,  unsigned long); break;
      case NL_VARARG_TYPE_SLONG_LONG: NL_EXTRACT_CB_SAME(e.sll, long long); break;
      case NL_VARARG_TYPE_ULONG_LONG: NL_EXTRACT_CB_SAME(e.ull, unsigned long long); break;
      case NL_VARARG_TYPE_SSIZE_T: NL_EXTRACT_CB_SAME(e.ssizet, long); break;
      case NL_VARARG_TYPE_SIZE_T: NL_EXTRACT_CB_SAME(e.sizet, size_t); break;
      case NL_VARARG_TYPE_SINTMAX_T: NL_EXTRACT_CB_SAME(e.sim, intmax_t); break;
      case NL_VARARG_TYPE_UINTMAX_T: NL_EXTRACT_CB_SAME(e.uim, uintmax_t); break;
      case NL_VARARG_TYPE_WINT_T: NL_EXTRACT_CB_SAME(e.wintt, wint_t); break;
      case NL_VARARG_TYPE_CHAR_PTR: NL_EXTRACT_CB_SAME(e.cp, char *); break;
      case NL_VARARG_TYPE_WCHAR_T_PTR: NL_EXTRACT_CB_SAME(e.wcp, wchar_t *); break;
      case NL_VARARG_TYPE_PTRDIFF_T: NL_EXTRACT_CB_SAME(e.pdt, ptrdiff_t); break;
      case NL_VARARG_TYPE_UPTRDIFF_T: NL_EXTRACT_CB_SAME(e.updt, uintptr_t); break;
      case NL_VARARG_TYPE_DOUBLE: NL_EXTRACT_CB_SAME(e.d, double); break;
      case NL_VARARG_TYPE_LONG_DOUBLE: NL_EXTRACT_CB_SAME(e.ld, long double); break;
      default: return NANOLOG_RET_INVALID_PAYLOAD;
    }
  }

  return NANOLOG_RET_SUCCESS;
}

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

