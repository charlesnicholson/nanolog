#ifndef NANOLOG_H
#define NANOLOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NL_SEV_DEBUG 0
#define NL_SEV_INFO 1
#define NL_SEV_WARNING 2
#define NL_SEV_ERROR 3
#define NL_SEV_CRITICAL 4
#define NL_SEV_ASSERT 5

// Configure log threshold, function-like log macros below this will expand to nothing.

#ifndef NL_LOG_SEVERITY_THRESHOLD
#define NL_LOG_SEVERITY_THRESHOLD NL_SEV_DEBUG
#endif

// Public API

typedef enum {
  NANOLOG_RET_SUCCESS = 0,
  NANOLOG_RET_ERR_BAD_ARG,
  NANOLOG_RET_INVALID_PAYLOAD,
} nanolog_ret_t;

typedef void (*nanolog_log_handler_cb_t)(void *ctx, int sev, char const *fmt, va_list args);

// Install a handler to be called on every log macro invocation.
nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler);

// Writes 1 to |out_is_binary| if fmt is a rewritten binary spec, 0 if ASCII.
nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary);

typedef void (*nanolog_binary_field_handler_cb_t)(void *ctx,
                                                  nl_arg_type_t type,
                                                  void const *p,
                                                  unsigned len);
// Calls |cb| with |ctx| with every arg.
nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       void *ctx,
                                       char const *fmt,
                                       va_list args);

// Boilerplate, has to be before the public logging macros

#ifdef NANOLOG_HOST_TOOL
#define NL_ATTR_SEC(SEV)
#else
#define NL_STR_EVAL(X) #X
#define NL_STR(X) NL_STR_EVAL(X)
#define NL_ATTR_SEC(SEV) \
  __attribute__((section(".nanolog." #SEV "." NL_STR(__LINE__) "." NL_STR(__COUNTER__))))
#endif

// Public logging macros

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_DEBUG
#define NL_LOG_DBG(FMT, ...) do { \
    static char const NL_ATTR_SEC(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_DBG_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_ctx((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#else
#define NL_LOG_DBG(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_DBG_CTX(CTX, FMT, ...) (void)sizeof((CTX, FMT, ##__VA_ARGS__))
#endif

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_INFO
#define NL_LOG_INF(FMT, ...) do { \
    static char const NL_ATTR_SEC(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_INF_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_ctx((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#else
#define NL_LOG_INF(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_INF_CTX(CTX, FMT, ...) (void)sizeof((CTX, FMT, ##__VA_ARGS__))
#endif

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_WARNING
#define NL_LOG_WRN(FMT, ...) do { \
    static char const NL_ATTR_SEC(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_WRN_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_ctx((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#else
#define NL_LOG_WRN(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_WRN_CTX(CTX, FMT, ...) (void)sizeof((CTX, FMT, ##__VA_ARGS__))
#endif

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_ERROR
#define NL_LOG_ERR(FMT, ...) do { \
    static char const NL_ATTR_SEC(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_ERR_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error_ctx((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#else
#define NL_LOG_ERR(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_ERR_CTX(CTX, FMT, ...) (void)sizeof((CTX, FMT, ##__VA_ARGS__))
#endif

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_CRITICAL
#define NL_LOG_CRIT(FMT, ...) do { \
    static char const NL_ATTR_SEC(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_CRIT_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#else
#define NL_LOG_CRT(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_CRT_CTX(CTX, FMT, ...) (void)sizeof((CTX, FMT, ##__VA_ARGS__))
#endif

#define NL_LOG_ASSERT(FMT, ...) do { \
    static char const NL_ATTR_SEC(ASSERT) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_assert(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#define NL_LOG_ASSERT_CTX(CTX, FMT, ...) do { \
    static char const NL_ATTR_SEC(ASSERT) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_assert_ctx((void *)CTX, s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)

// Optional top-level minimal-footprint assert macros

#ifdef NANOLOG_ASSERTS_ENABLED

#ifdef __GNUC__
#define NL_UNLIKELY(COND) __builtin_expect((COND), 0)
#else
#define NL_UNLIKELY(COND) COND
#endif

#define NL_ASSERT(COND) do { \
    if (NL_UNLIKELY(!(COND))) { \
      NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\""); \
    } \
  } while(0)

#define NL_ASSERT_MSG(COND, FMT, ...) do { \
    if (NL_UNLIKELY(!(COND))) { \
      NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\" " FMT, ##__VA_ARGS__); \
    } \
  } while(0)

#define NL_ASSERT_FAIL() NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL")
#define NL_ASSERT_FAIL_MSG(FMT, ...) \
  NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): " FMT, ##__VA_ARGS__);
#endif

// Implementation details

enum { NL_BINARY_LOG_MARKER = 0x1F };  // starts replacement binary payloads

typedef enum {
  // Values bit-packed into binary string replacements.
  NL_ARG_TYPE_SCALAR_1_BYTE = 0,
  NL_ARG_TYPE_SCALAR_2_BYTE = 1,
  NL_ARG_TYPE_SCALAR_4_BYTE = 2,
  NL_ARG_TYPE_SCALAR_8_BYTE = 3,
  NL_ARG_TYPE_STRING = 4,
  NL_ARG_TYPE_POINTER = 5,
  NL_ARG_TYPE_DOUBLE = 6,
  NL_ARG_TYPE_LONG_DOUBLE = 7,
  NL_ARG_TYPE_WINT_T = 8,
  NL_ARG_TYPE_LOG_END = 0xF,
  // Synthetic values emitted by runtime, not packed into binary
  NL_ARG_TYPE_LOG_START = 0xAA,
  NL_ARG_TYPE_GUID = 0xAB,
  NL_ARG_TYPE_STRING_LEN_VARINT = 0xAC,
} nl_arg_type_t;

// Private logging API (use the macros, not these)

void nanolog_log_debug(char const *fmt, ...);
void nanolog_log_debug_ctx(void *ctx, char const *fmt, ...);
void nanolog_log_info(char const *fmt, ...);
void nanolog_log_info_ctx(void *ctx, char const *fmt, ...);
void nanolog_log_warning(char const *fmt, ...);
void nanolog_log_warning_ctx(void *ctx, char const *fmt, ...);
void nanolog_log_error(char const *fmt, ...);
void nanolog_log_error_ctx(void *ctx, char const *fmt, ...);
void nanolog_log_critical(char const *fmt, ...);
void nanolog_log_critical_ctx(void *ctx, char const *fmt, ...);
void nanolog_log_assert(char const *fmt, ...);
void nanolog_log_assert_ctx(void *ctx, char const *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
