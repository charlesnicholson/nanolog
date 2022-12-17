#include "nanolog.h"

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

static nanolog_handler_cb_t s_log_handler = NULL;
static unsigned s_log_threshold = NL_SEV_DEBUG;

nanolog_ret_t nanolog_set_threshold(unsigned severity) {
  if (severity > NL_SEV_ASSERT) { return NANOLOG_RET_ERR_BAD_ARG; }
  s_log_threshold = severity;
  return NANOLOG_RET_SUCCESS;
}

unsigned nanolog_get_threshold(void) { return s_log_threshold; }

nanolog_ret_t nanolog_set_handler(nanolog_handler_cb_t handler) {
  s_log_handler = handler;
  return NANOLOG_RET_SUCCESS;
}

void nanolog_log_sev(char const *fmt, unsigned sev, ...) {
  if (!s_log_handler || (s_log_threshold > sev)) { return; }
  va_list a; va_start(a, sev);
  s_log_handler(NULL, sev | NL_DYNAMIC_SEV_BIT, fmt, a);
  va_end(a);
}

void nanolog_log_sev_ctx(char const *fmt, unsigned sev, void* ctx, ...) {
  if (!s_log_handler || (s_log_threshold > sev)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(ctx, sev | NL_DYNAMIC_SEV_BIT, fmt, a);
  va_end(a);
}

void nanolog_log_debug(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_DEBUG, fmt, a); va_end(a);
}

void nanolog_log_debug_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_DEBUG, fmt, a); va_end(a);
}

void nanolog_log_info(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_INFO, fmt, a); va_end(a);
}

void nanolog_log_info_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_INFO, fmt, a); va_end(a);
}

void nanolog_log_warning(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_WARNING, fmt, a); va_end(a);
}

void nanolog_log_warning_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_WARNING, fmt, a); va_end(a);
}

void nanolog_log_error(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_ERROR, fmt, a); va_end(a);
}

void nanolog_log_error_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_ERROR, fmt, a); va_end(a);
}

void nanolog_log_critical(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_CRITICAL, fmt, a); va_end(a);
}

void nanolog_log_critical_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_CRITICAL, fmt, a); va_end(a);
}

void nanolog_log_assert(char const *fmt, ...) {
  if (!s_log_handler) { return; }
  va_list a; va_start(a, fmt); s_log_handler(NULL, NL_SEV_ASSERT, fmt, a); va_end(a);
}

void nanolog_log_assert_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler) { return; }
  va_list a; va_start(a, ctx); s_log_handler(ctx, NL_SEV_ASSERT, fmt, a); va_end(a);
}

nanolog_ret_t nanolog_fmt_is_binary(char const *fmt, int *out_is_binary) {
  if (!fmt || !out_is_binary) { return NANOLOG_RET_ERR_BAD_ARG; }
  *out_is_binary = (fmt[0] == NL_BINARY_LOG_MARKER);
  return NANOLOG_RET_SUCCESS;
}

static void nanolog_extract_and_dispatch(nanolog_binary_field_handler_cb_t cb,
                                         void *ctx,
                                         nl_arg_type_t type,
                                         va_list args) {
  switch (type) {
    case NL_ARG_TYPE_SCALAR_1_BYTE: {
      char const c = (char)va_arg(args, int);
      cb(ctx, type, &c, sizeof(c));
    } break;

    case NL_ARG_TYPE_SCALAR_2_BYTE: {
      short const s = (short)va_arg(args, int);
      cb(ctx, type, &s, sizeof(s));
    } break;

    case NL_ARG_TYPE_SCALAR_4_BYTE: {
      int const i = va_arg(args, int);
      cb(ctx, type, &i, sizeof(i));
    } break;

    case NL_ARG_TYPE_SCALAR_8_BYTE: {
      long long const ll = va_arg(args, long long);
      cb(ctx, type, &ll, sizeof(ll));
    } break;

    case NL_ARG_TYPE_STRING: {
      unsigned char vi[8];
      char const *s = va_arg(args, char const *);
      unsigned sl = 0, vil = 0;
      for (char const *c = s; *c; ++c, ++sl); // gcc recognizes this as strlen
      for (unsigned sl_vi = sl; sl_vi; ++vil, sl_vi >>= 7) {
        vi[vil] = (unsigned char)((sl_vi & 0x7F) | 0x80);
      }
      vi[vil++] &= 0x7F;
      cb(ctx, NL_ARG_TYPE_STRING_LEN_VARINT, vi, vil);
      cb(ctx, NL_ARG_TYPE_STRING, s, sl);
    } break;

    case NL_ARG_TYPE_POINTER: {
      void *const v = va_arg(args, void *);
      cb(ctx, type, &v, sizeof(v));
    } break;

    case NL_ARG_TYPE_DOUBLE: {
      double const d = va_arg(args, double);
      cb(ctx, type, &d, sizeof(d));
    } break;

    case NL_ARG_TYPE_LONG_DOUBLE: {
      long double const ld = va_arg(args, long double);
      cb(ctx, type, &ld, sizeof(ld));
    } break;

    case NL_ARG_TYPE_WINT_T: {
      wint_t const w = va_arg(args, wint_t);
      cb(ctx, type, &w, sizeof(w));
    } break;

    case NL_ARG_TYPE_FIELD_WIDTH_STAR:
    case NL_ARG_TYPE_PRECISION_STAR: {
      unsigned char vi[8], vil = 0;
      int i = va_arg(args, int);
      do { vi[vil++] = (unsigned char)((i & 0x7F) | 0x80); i >>= 7; } while (i);
      vi[vil - 1] &= 0x7F;
      cb(ctx, type, vi, vil);
    } break;

    case NL_ARG_TYPE_STRING_PRECISION_LITERAL:
      break;

    case NL_ARG_TYPE_LOG_END: cb(ctx, type, NULL, 0); break;

    // never happens
    case NL_ARG_TYPE_LOG_START:
    case NL_ARG_TYPE_GUID:
    case NL_ARG_TYPE_STRING_LEN_VARINT:
    case NL_ARG_TYPE_DYNAMIC_SEVERITY:
      break;
  }
}

nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       unsigned sev,
                                       char const *fmt,
                                       va_list args) {
  (void)sev;
  if (!cb || !fmt) { return NANOLOG_RET_ERR_BAD_ARG; }

  unsigned char const *src = (unsigned char const *)fmt;
  if (*src++ != NL_BINARY_LOG_MARKER) { return NANOLOG_RET_INVALID_PAYLOAD; }

  // About to log, tell user so they can transmit timestamp etc
  cb(ctx, NL_ARG_TYPE_LOG_START, NULL, 0);

  if (sev & NL_DYNAMIC_SEV_BIT) { // nanolog_log_sev[_ctx]
    _Static_assert(NL_DYNAMIC_SEV_BIT > 255, "");
    uint8_t const sev_byte = (uint8_t)sev;
    cb(ctx, NL_ARG_TYPE_DYNAMIC_SEVERITY, &sev_byte, 1);
  }

  { // GUID is varint-encoded, ends at first byte w/o a high "continuation" bit (0x80)
    unsigned char const *guid = src;
    while (*src & 0x80) { ++src; }
    cb(ctx, NL_ARG_TYPE_GUID, guid, (unsigned)(++src - guid));
  }

  // Types are packed, two per byte, low nibble first.
  for (;; ++src) {
    nl_arg_type_t type = (nl_arg_type_t)(*src & 0xF);
    nanolog_extract_and_dispatch(cb, ctx, type, args);
    if (type == NL_ARG_TYPE_LOG_END) { break; }
    type = (nl_arg_type_t)(*src >> 4);
    nanolog_extract_and_dispatch(cb, ctx, type, args);
    if (type == NL_ARG_TYPE_LOG_END) { break; }
  }

  return NANOLOG_RET_SUCCESS;
}

// ARMv7-M conventions

#ifdef __arm__
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
#endif

