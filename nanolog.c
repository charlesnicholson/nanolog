#include "nanolog.h"

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#ifdef _MSC_VER
#include <assert.h>  // _Static_assert on msvc
#endif

static nanolog_handler_cb_t s_log_handler = NULL;
static unsigned s_log_threshold = NL_SEV_DEBUG;

nanolog_ret_t nanolog_set_threshold(unsigned severity) {
  if (severity > NL_SEV_ASSERT) {
    return NANOLOG_RET_ERR_BAD_ARG;
  }
  s_log_threshold = severity;
  return NANOLOG_RET_SUCCESS;
}

unsigned nanolog_get_threshold(void) {
  return s_log_threshold;
}

nanolog_ret_t nanolog_set_log_handler(nanolog_handler_cb_t handler) {
  s_log_handler = handler;
  return NANOLOG_RET_SUCCESS;
}

nanolog_handler_cb_t nanolog_get_log_handler(void) {
  return s_log_handler;
}

#ifdef _MSC_VER
#define NL_NOINLINE __declspec(noinline)
#define NL_FALLTHROUGH
#elif defined(__GNUC__) || defined(__clang__)
#define NL_NOINLINE __attribute__((noinline))
#define NL_FALLTHROUGH __attribute__((fallthrough))
#else
#error Unrecognized compiler, please implement NL_NOINLINE
#endif

// clang-format off
NL_NOINLINE void nanolog_log_sev(unsigned sev, char const *func, char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > sev)) {
    return;
  }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){ .sev = sev | NL_DYNAMIC_SEV_BIT,
      .log_ctx = NULL, .assert_file = NULL, .assert_line = 0, .log_func = func,
      .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_sev_ctx(unsigned sev, void *ctx, char const *func,
    char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > sev)) {
    return;
  }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){ .sev = sev | NL_DYNAMIC_SEV_BIT,
      .log_ctx = ctx, .assert_file = NULL, .assert_line = 0, .log_func = func,
      .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_sev_buf(unsigned sev, void *ctx, char const *func,
    void const *buf, unsigned len, char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > sev)) {
    return;
  }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){ .sev = sev | NL_DYNAMIC_SEV_BIT,
      .log_ctx = ctx, .assert_file = NULL, .assert_line = 0, .log_func = func,
      .log_buf = buf, .log_buf_len = len }, fmt, a);
  va_end(a);
}
// clang-format on

nanolog_ret_t nanolog_fmt_is_binary(char const *fmt, bool *out_is_binary) {
  if (!fmt || !out_is_binary) {
    return NANOLOG_RET_ERR_BAD_ARG;
  }
  *out_is_binary = (fmt[0] == NL_BINARY_LOG_MARKER);
  return NANOLOG_RET_SUCCESS;
}

nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       nanolog_log_details_t const *details,
                                       char const *fmt,
                                       va_list args) {
  if (!cb || !fmt) {
    return NANOLOG_RET_ERR_BAD_ARG;
  }

  unsigned char const *src = (unsigned char const *)fmt;
  if (*src++ != NL_BINARY_LOG_MARKER) {
    return NANOLOG_RET_ERR_INVALID_PAYLOAD;
  }

  // About to log, tell user so they can transmit timestamp etc
  cb(details->log_ctx, NL_ARG_TYPE_LOG_START, NULL, 0);

  {  // GUID is varint-encoded, ends at first byte w/o a high "continuation" bit (0x80)
    unsigned char const *guid = src;
    while (*src & 0x80) {
      ++src;
    }
    cb(details->log_ctx, NL_ARG_TYPE_GUID, guid, (unsigned)(++src - guid));
  }

  if (details->sev & NL_DYNAMIC_SEV_BIT) {  // nanolog_log_sev[_ctx]
    _Static_assert(NL_DYNAMIC_SEV_BIT > 255, "");
    uint8_t const sev_byte = (uint8_t)details->sev;
    cb(details->log_ctx, NL_ARG_TYPE_DYNAMIC_SEVERITY, &sev_byte, 1);
  }

  // Types are packed, two per byte, low nibble first.
  int bit_index = 0, have_prec = 0;
  int32_t prec = 0;
  nl_arg_type_t type;
  do {
    type = (nl_arg_type_t)((*src >> bit_index) & 0xF);
    src += ((bit_index ^= 4) == 0);

    switch (type) {
      case NL_ARG_TYPE_SCALAR_1_BYTE: {
        char const c = (char)va_arg(args, int);
        cb(details->log_ctx, type, &c, sizeof(c));
      } break;

      case NL_ARG_TYPE_SCALAR_2_BYTE: {
        short const s = (short)va_arg(args, int);
        cb(details->log_ctx, type, &s, sizeof(s));
      } break;

      case NL_ARG_TYPE_SCALAR_4_BYTE: {
        int const i = va_arg(args, int);
        cb(details->log_ctx, type, &i, sizeof(i));
      } break;

      case NL_ARG_TYPE_SCALAR_8_BYTE: {
        long long const ll = va_arg(args, long long);
        cb(details->log_ctx, type, &ll, sizeof(ll));
      } break;

      case NL_ARG_TYPE_STRING: {
        char const *s = va_arg(args, char const *);
        unsigned sl = 0, len_enc_len = 0;
        for (char const *c = s; *c && (!have_prec || (sl < (unsigned)prec)); ++c, ++sl)
          ;
        unsigned char len_enc[8];
        if (nanolog_varint_encode(sl, len_enc, sizeof(len_enc), &len_enc_len) !=
            NANOLOG_RET_SUCCESS) {
          return NANOLOG_RET_ERR_INTERNAL;
        }
        cb(details->log_ctx, NL_ARG_TYPE_STRING_LEN, len_enc, len_enc_len);
        cb(details->log_ctx, NL_ARG_TYPE_STRING, s, sl);
      } break;

      case NL_ARG_TYPE_POINTER: {
        void *const v = va_arg(args, void *);
        cb(details->log_ctx, type, &v, sizeof(v));
      } break;

      case NL_ARG_TYPE_DOUBLE: {
        double const d = va_arg(args, double);
        cb(details->log_ctx, type, &d, sizeof(d));
      } break;

      case NL_ARG_TYPE_LONG_DOUBLE: {
        long double const ld = va_arg(args, long double);
        cb(details->log_ctx, type, &ld, sizeof(ld));
      } break;

      case NL_ARG_TYPE_WINT_T: {
        wint_t const w = va_arg(args, wint_t);
        cb(details->log_ctx, type, &w, sizeof(w));
      } break;

      case NL_ARG_TYPE_PRECISION_STAR:
        have_prec = 1;
        NL_FALLTHROUGH;
      case NL_ARG_TYPE_FIELD_WIDTH_STAR: {
        unsigned char vi[8];
        unsigned vil = 0;
        prec = (int32_t)va_arg(args, int);
        if (nanolog_varint_encode(nanolog_zigzag_encode(prec), vi, sizeof(vi), &vil) !=
            NANOLOG_RET_SUCCESS) {
          return NANOLOG_RET_ERR_INTERNAL;
        }
        if (have_prec && (prec < 0)) {
          have_prec = 0;
        }
        cb(details->log_ctx, type, vi, vil);
      } break;

      case NL_ARG_TYPE_STRING_PRECISION_LITERAL: {
        src += !!bit_index;
        bit_index = 0;
        unsigned len;
        uint32_t val;
        if (nanolog_varint_decode(src, &val, &len) != NANOLOG_RET_SUCCESS) {
          return NANOLOG_RET_ERR_INVALID_PAYLOAD;
        }
        prec = (int32_t)val;
        have_prec = 1;
        src += len;
      } break;

      case NL_ARG_TYPE_BUFFER:
      case NL_ARG_TYPE_LOG_END:
      case NL_ARG_TYPE_LOG_START:
      case NL_ARG_TYPE_GUID:
      case NL_ARG_TYPE_STRING_LEN:
      case NL_ARG_TYPE_DYNAMIC_SEVERITY:
        break;
    }

    if ((type != NL_ARG_TYPE_PRECISION_STAR) &&
        (type != NL_ARG_TYPE_STRING_PRECISION_LITERAL)) {
      have_prec = 0;
    }
  } while (type != NL_ARG_TYPE_LOG_END);

  if (details->log_buf_len) {
    cb(details->log_ctx, NL_ARG_TYPE_BUFFER, details->log_buf, details->log_buf_len);
  }
  cb(details->log_ctx, NL_ARG_TYPE_LOG_END, NULL, 0);
  return NANOLOG_RET_SUCCESS;
}

nanolog_ret_t nanolog_varint_decode(void const *p, uint32_t *out_val, unsigned *out_len) {
  if (!p || !out_val || !out_len) {
    return NANOLOG_RET_ERR_BAD_ARG;
  }
  uint32_t val = 0;
  unsigned len = 1;
  for (unsigned char const *src = (unsigned char const *)p;; ++src, ++len) {
    val = (val << 7) | (*src & 0x7F);
    if (!(*src & 0x80)) {
      break;
    }
  }
  *out_val = val;
  *out_len = len;
  return NANOLOG_RET_SUCCESS;
}

nanolog_ret_t nanolog_varint_encode(uint32_t val,
                                    void *out_buf,
                                    unsigned buf_max,
                                    unsigned *out_len) {
  if (!out_buf || !out_len || !buf_max) {
    return NANOLOG_RET_ERR_BAD_ARG;
  }
  unsigned len = 0;
  {  // precompute length and check that the encoding fits
    unsigned val_tmp = val;
    do {
      ++len;
      val_tmp >>= 7;
    } while (val_tmp && (len <= buf_max));
    if (len > buf_max) {
      return NANOLOG_RET_ERR_EXHAUSTED;
    }
  }

  unsigned char *dst = (unsigned char *)out_buf;
  unsigned i = len;
  do {
    dst[--i] = (unsigned char)(val | 0x80);
    val >>= 7;
  } while (val);
  dst[len - 1] &= 0x7F;
  *out_len = len;
  return NANOLOG_RET_SUCCESS;
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
uint32_t nanolog_zigzag_encode(int32_t val) {
  return ((uint32_t)val << 1) ^ -((uint32_t)val >> 31);
}

int32_t nanolog_zigzag_decode(uint32_t val) {
  return (int32_t)((val >> 1) ^ -(val & 1));
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

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

// Boring combination explosion of log functions invoked by macros. These functions could
// be macro-generated but that often makes debugging more opaque.

// clang-format off

NL_NOINLINE void nanolog_log_debug(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_debug_func(char const *fmt, char const *func, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, func);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_debug_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_debug_ctx_func(
    char const *fmt, char const *func, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_debug_buf(
    char const *fmt, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_debug_buf_func(
    char const *fmt, char const *func, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_DEBUG)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_DEBUG, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info_func(char const *fmt, char const *func, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, func);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info_ctx_func(
    char const *fmt, char const *func, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info_buf(
    char const *fmt, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_info_buf_func(
    char const *fmt, char const *func, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_INFO)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_INFO, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning_func(char const *fmt, char const *func, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, func);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning_ctx_func(
    char const *fmt, char const *func, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning_buf(
    char const *fmt, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_warning_buf_func(
    char const *fmt, char const *func, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_WARNING)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_WARNING, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error_func(char const *fmt, char const *func, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, func);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error_ctx_func(
    char const *fmt, char const *func, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error_buf(
    char const *fmt, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_error_buf_func(
    char const *fmt, char const *func, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_ERROR)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_ERROR, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical(char const *fmt, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, fmt);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical_func(char const *fmt, char const *func, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, func);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = NULL, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical_ctx(char const *fmt, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical_ctx_func(
    char const *fmt, char const *func, void *ctx, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, ctx);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = NULL, .log_buf_len = 0 }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical_buf(
    char const *fmt, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = NULL, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}

NL_NOINLINE void nanolog_log_critical_buf_func(
    char const *fmt, char const *func, void *ctx, void const *buf, unsigned buf_len, ...) {
  if (!s_log_handler || (s_log_threshold > NL_SEV_CRITICAL)) { return; }
  va_list a; va_start(a, buf_len);
  s_log_handler(&(nanolog_log_details_t){
    .sev = NL_SEV_CRITICAL, .log_ctx = ctx, .assert_file = NULL, .assert_line = 0,
    .log_func = func, .log_buf = buf, .log_buf_len = buf_len }, fmt, a);
  va_end(a);
}
// clang-format on

#if NANOLOG_PROVIDE_ASSERT_MACROS == 1
void nanolog_assert_fail(char const *msg, ...) {
  (void)msg;
}

void nanolog_assert_fail_file_line(char const *msg, char const *file, int line, ...) {
  (void)msg;
  (void)file;
  (void)line;
}

void nanolog_assert_fail_ctx(char const *msg, void *ctx, ...) {
  (void)msg;
  (void)ctx;
}

void nanolog_assert_fail_ctx_file_line(char const *msg,
                                       void *ctx,
                                       char const *file,
                                       int line) {
  (void)msg;
  (void)ctx;
  (void)file;
  (void)line;
}
#endif
