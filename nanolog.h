#ifndef NANOLOG_H
#define NANOLOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NL_SEV_DBG 0
#define NL_SEV_INFO 1
#define NL_SEV_WARN 2
#define NL_SEV_ERR 3
#define NL_SEV_CRIT 4
#define NL_SEV_ASSERT 5

// Configure the log threshold, log calls below this level will expand to nothing.

#ifndef NL_LOG_SEVERITY_THRESHOLD
#define NL_LOG_SEVERITY_THRESHOLD NL_SEV_DBG
#endif

// Public API

typedef void (*nanolog_log_handler_cb_t)(int sev, char const *fmt, va_list args);
typedef void (*nanolog_binary_field_handler_cb_t)(void *ctx, void const *p, unsigned len);

typedef enum {
  NANOLOG_RET_SUCCESS = 0,
  NANOLOG_RET_ERR_BAD_ARG,
  NANOLOG_RET_INVALID_PAYLOAD,
} nanolog_ret_t;

nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler);

// Writes 1 to |out_is_binary| if fmt is a rewritten binary spec, 0 if ASCII.
nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary);

// Calls |cb| with |ctx| for every
nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       char const *fmt,
                                       va_list args);

// Boilerplate, has to be before the public logging macros

#ifdef NANOLOG_NO_SECTIONS
#define NL_ATTR_SEC(SEV)
#else
#define NL_STR_PASTE(X) #X
#define NL_STR(X) NL_STR_PASTE(X)
#define NL_ATTR_SEC(SEV) \
  __attribute__((section(".nanolog." #SEV "." NL_STR(__LINE__) "." NL_STR(__COUNTER__))))
#endif

// Public logging macros

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_DBG
#define NL_LOG_DBG(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#else
#define NL_LOG_DBG(FMT, ...) do { static char const NL_ATTR_SEC(DBG) s_fmt[] = FMT; \
  nanolog_log_dbg(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_INFO
#define NL_LOG_INFO(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_INFO(FMT, ...) do { static char const NL_ATTR_SEC(INFO) s_fmt[] = FMT; \
  nanolog_log_inf(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_WARN
#define NL_LOG_WARN(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_WARN(FMT, ...) do { static char const NL_ATTR_SEC(WARN) s_fmt[] = FMT; \
  nanolog_log_warn(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_ERR
#define NL_LOG_ERR(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_ERR(FMT, ...) do { static char const NL_ATTR_SEC(ERR) s_fmt[] = FMT; \
  nanolog_log_err(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_CRIT
#define NL_LOG_CRIT(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_CRIT(FMT, ...) do { static char const NL_ATTR_SEC(CRIT) s_fmt[] = FMT; \
  nanolog_log_crit(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_ASSERT
#define NL_LOG_ASSERT(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_ASSERT(FMT, ...) do { static char const NL_ATTR_SEC(ASSERT) s_fmt[] = FMT; \
  nanolog_log_assert(s_fmt, ##__VA_ARGS__); } while(0)
#endif

// Private logging API (use the macros, not these)

void nanolog_log_dbg(char const *fmt, ...);
void nanolog_log_info(char const *fmt, ...);
void nanolog_log_warn(char const *fmt, ...);
void nanolog_log_err(char const *fmt, ...);
void nanolog_log_crit(char const *fmt, ...);
void nanolog_log_assert(char const *fmt, ...);

// Private binary log vararg extraction types (from printf specification)

typedef enum {
  NL_VARARG_TYPE_SCHAR = 0,
  NL_VARARG_TYPE_UCHAR = 1,
  NL_VARARG_TYPE_SHORT = 2,
  NL_VARARG_TYPE_USHORT = 3,
  NL_VARARG_TYPE_SINT = 4,
  NL_VARARG_TYPE_UINT = 5,
  NL_VARARG_TYPE_SLONG = 6,
  NL_VARARG_TYPE_ULONG = 7,
  NL_VARARG_TYPE_SLONG_LONG = 8,
  NL_VARARG_TYPE_ULONG_LONG = 9,
  NL_VARARG_TYPE_SSIZE_T = 10,
  NL_VARARG_TYPE_SIZE_T = 11,
  NL_VARARG_TYPE_SINTMAX_T = 12,
  NL_VARARG_TYPE_UINTMAX_T = 13,
  NL_VARARG_TYPE_WINT_T = 14,
  NL_VARARG_TYPE_CHAR_PTR = 15,
  NL_VARARG_TYPE_WCHAR_T_PTR = 16,
  NL_VARARG_TYPE_PTRDIFF_T = 17,
  NL_VARARG_TYPE_UPTRDIFF_T = 18,
  NL_VARARG_TYPE_DOUBLE = 19,
  NL_VARARG_TYPE_LONG_DOUBLE = 20,
  NL_VARARG_TYPE_VOID_PTR = 21,

  NL_VARARG_LAST_PLUS_ONE_DO_NOT_USE,
} nl_vararg_type_t;

// Rewritten elf file format payloads start with this byte instead of printable ascii.
enum { NL_BINARY_PREFIX_MARKER = 0x1F, NL_BINARY_TERM_MARKER = 0xFF, };

#ifdef __cplusplus
}
#endif

#endif
