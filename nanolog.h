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

// Configure log threshold, function-like log macros below this will expand to nothing.

#ifndef NL_LOG_SEVERITY_THRESHOLD
#define NL_LOG_SEVERITY_THRESHOLD NL_SEV_DBG
#endif

// Public API

typedef enum {
  NANOLOG_RET_SUCCESS = 0,
  NANOLOG_RET_ERR_BAD_ARG,
  NANOLOG_RET_INVALID_PAYLOAD,
} nanolog_ret_t;

enum { NL_BINARY_PREFIX_MARKER = 0x1F };  // starts replacement binary payloads

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

// Install a handler to be called on every log macro invocation.
typedef void (*nanolog_log_handler_cb_t)(int sev, char const *fmt, va_list args);
nanolog_ret_t nanolog_set_log_handler(nanolog_log_handler_cb_t handler);

// Writes 1 to |out_is_binary| if fmt is a rewritten binary spec, 0 if ASCII.
nanolog_ret_t nanolog_log_is_binary(char const *fmt, int *out_is_binary);

// Calls |cb| with |ctx| with every arg.
typedef void (*nanolog_binary_field_handler_cb_t)(void *ctx,
                                                  nl_arg_type_t type,
                                                  void const *p,
                                                  unsigned len);

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

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_DBG
#define NL_LOG_DBG(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#else
#define NL_LOG_DBG(FMT, ...) do { \
    static char const NL_ATTR_SEC(DBG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_dbg(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_INFO
#define NL_LOG_INFO(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_INFO(FMT, ...) do { \
    static char const NL_ATTR_SEC(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_WARN
#define NL_LOG_WARN(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_WARN(FMT, ...) do { \
    static char const NL_ATTR_SEC(WARN) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warn(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_ERR
#define NL_LOG_ERR(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_ERR(FMT, ...) do { \
    static char const NL_ATTR_SEC(ERR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_err(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#endif

#if NL_LOG_SEVERITY_THRESHOLD > NL_SEV_CRIT
#define NL_LOG_CRIT(FMT, ...) (void)sizeof((void)(FMT, ##__VA_ARGS__))
#else
#define NL_LOG_CRIT(FMT, ...) do { \
    static char const NL_ATTR_SEC(CRIT) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_crit(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)
#endif

#define NL_LOG_ASSERT(FMT, ...) do { \
    static char const NL_ATTR_SEC(ASSERT) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_assert(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while(0)

// Optional top-level assert macros

#ifdef NANOLOG_ASSERTS_ENABLED
#define NL_ASSERT(COND) do { \
    if (!(COND)) { NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\""); } \
  } while(0)

#define NL_ASSERT_MSG(COND, FMT, ...) do { \
    if (!(COND)) { \
      NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\" " FMT, ##__VA_ARGS__); \
    } \
  } while(0)

#define NL_ASSERT_FAIL() NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL")
#define NL_ASSERT_FAIL_MSG(FMT, ...) \
    NL_LOG_ASSERT(__FILE__ "(" NL_STR(__LINE__) "): " FMT, ##__VA_ARGS__);
#endif

// Private logging API (use the macros, not these)

void nanolog_log_dbg(char const *fmt, ...);
void nanolog_log_info(char const *fmt, ...);
void nanolog_log_warn(char const *fmt, ...);
void nanolog_log_err(char const *fmt, ...);
void nanolog_log_crit(char const *fmt, ...);
void nanolog_log_assert(char const *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
