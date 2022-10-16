#ifndef NANOLOG_H
#define NANOLOG_H

#include <stdarg.h>

typedef enum {
  NL_SEV_DBG,
  NL_SEV_INFO,
  NL_SEV_WARN,
  NL_SEV_ERR,
  NL_SEV_CRIT,
  NL_SEV_ASSERT,
} nl_sev_t;

// Configure the log threshold, log calls below this level will expand to nothing.

#ifndef NL_LOG_SEVERITY_THRESHOLD
#define NL_LOG_SEVERITY_THRESHOLD NL_SEV_DBG
#endif

// Public API

typedef void (*nanolog_log_handler_cb_t)(nl_sev_t sev, char const *fmt, va_list args);
typedef void (*nanolog_binary_field_handler_cb_t)(void *ctx, void const *p, unsigned len);

void nanolog_set_log_handler(nanolog_log_handler_cb_t handler);

int nanolog_log_is_binary(char const *fmt);

void nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                              void *ctx,
                              char const *fmt,
                              va_list args);

// Public logging macros

#define NL_STR_PASTE(X) #X
#define NL_STR(X) NL_STR_PASTE(X)
#define NL_ATTR_SEC(SEV) \
  __attribute__((section(".nanolog." #SEV "." NL_STR(__LINE__) "." NL_STR(__COUNTER__))))

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_DBG
#define NL_LOG_DBG(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_DBG(FMT, ...) do { static char const NL_ATTR_SEC(DBG) s_fmt[] = FMT; \
  nanolog_log_dbg(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_INFO
#define NL_LOG_INFO(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_INFO(FMT, ...) do { static char const NL_ATTR_SEC(INFO) s_fmt[] = FMT; \
  nanolog_log_inf(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_WARN
#define NL_LOG_WARN(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_WARN(FMT, ...) do { static char const NL_ATTR_SEC(WARN) s_fmt[] = FMT; \
  nanolog_log_warn(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_ERR
#define NL_LOG_ERR(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_ERR(FMT, ...) do { static char const NL_ATTR_SEC(ERR) s_fmt[] = FMT; \
  nanolog_log_err(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_CRIT
#define NL_LOG_CRIT(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_CRIT(FMT, ...) do { static char const NL_ATTR_SEC(CRIT) s_fmt[] = FMT; \
  nanolog_log_crit(s_fmt, ##__VA_ARGS__); } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD >= NL_SEV_ASSERT
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

// Binary log vararg extraction types (from printf specification)

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
} nl_vararg_type_t;

#endif
