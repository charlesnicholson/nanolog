#ifndef NANOLOG_H
#define NANOLOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

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

// Configure function capturing: log handler will receive the current function name, at the
// cost of slightly higher call-site register pressure and larger binary images.
// They're mostly useful for ASCII builds.
// For binary logs, the generated manifest always contains them; don't serialize them!

#ifndef NANOLOG_LOG_CAPTURE_FUNCTION_NAMES
#define NANOLOG_LOG_CAPTURE_FUNCTION_NAMES 1
#endif

// Configure whether the nanolog assert macros are enabled.
#ifndef NANOLOG_PROVIDE_ASSERT_MACROS
#define NANOLOG_PROVIDE_ASSERT_MACROS 1
#endif

// Configure whether the nanolog assert macros capture file + line.
// (File + line are always baked into the failure string, which may be binary)
#ifndef NANOLOG_ASSERT_CAPTURE_FILE_LINE
#define NANOLOG_ASSERT_CAPTURE_FILE_LINE 1
#endif

// Public API

typedef enum {
  NANOLOG_RET_SUCCESS = 0,
  NANOLOG_RET_ERR_BAD_ARG,
  NANOLOG_RET_ERR_INVALID_PAYLOAD,
  NANOLOG_RET_ERR_EXHAUSTED,
  NANOLOG_RET_ERR_INTERNAL,
} nanolog_ret_t;

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
  NL_ARG_TYPE_FIELD_WIDTH_STAR = 9,
  NL_ARG_TYPE_PRECISION_STAR = 10,
  NL_ARG_TYPE_STRING_PRECISION_LITERAL = 11,
  NL_ARG_TYPE_LOG_END = 0xF,

  // Synthetic values emitted by runtime, not pre-baked into patched elf
  NL_ARG_TYPE_LOG_START = 0xAA,
  NL_ARG_TYPE_GUID = 0xAB,
  NL_ARG_TYPE_STRING_LEN = 0xAC,
  NL_ARG_TYPE_DYNAMIC_SEVERITY = 0xAD,
  NL_ARG_TYPE_BUFFER = 0xAE,
} nl_arg_type_t;

typedef struct nanolog_log_details {
  unsigned sev;
  void *handler_ctx;        // nanolog_set_log_handler
  void *log_ctx;            // LOG_<SEV>_CTX or log_sev_ctx or ASSERT_CTX
  char const *assert_file;  // if NANOLOG_ASSERT_CAPTURE_FILE_LINE
  int assert_line;          // if NANOLOG_ASSERT_CAPTURE_FILE_LINE
  char const *log_func;     // if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES
  void const *log_buf;      // LOG_<SEV>_BUF or log_sev_buf
  unsigned log_buf_len;     // LOG_<SEV>_BUF or log_sev_buf
} nanolog_log_details_t;

typedef void (*nanolog_handler_cb_t)(nanolog_log_details_t const *details,
                                     char const *fmt,
                                     va_list args);

// Install a handler to be called on every log macro invocation.
nanolog_ret_t nanolog_set_log_handler(nanolog_handler_cb_t handler, void *ctx);
nanolog_handler_cb_t nanolog_get_log_handler(void);

// Set the runtime log threshold for enabled log calls
nanolog_ret_t nanolog_set_threshold(unsigned severity);
unsigned nanolog_get_threshold(void);

// Writes true to |out_is_binary| if fmt is a rewritten binary spec, false if ASCII.
nanolog_ret_t nanolog_fmt_is_binary(char const *fmt, bool *out_is_binary);

typedef void (*nanolog_binary_field_handler_cb_t)(void *ctx,
                                                  nl_arg_type_t type,
                                                  void const *p,
                                                  unsigned len);

// Calls |cb| with every arg. Serialize all non-NULL payloads as-is to your target.
nanolog_ret_t nanolog_parse_binary_log(nanolog_binary_field_handler_cb_t cb,
                                       nanolog_log_details_t const *details,
                                       char const *fmt,
                                       va_list args);

// Direct log functions, for dynamic runtime severity.
void nanolog_log_sev(char const *fmt, unsigned sev, char const *func, ...);
void nanolog_log_sev_ctx(char const *fmt, unsigned sev, void *ctx, char const *func, ...);
void nanolog_log_sev_buf(char const *fmt,
                         unsigned sev,
                         void *ctx,
                         char const *func,
                         void const *buf,
                         unsigned len,
                         ...);

#if NANOLOG_PROVIDE_ASSERT_MACROS == 1
typedef void (*nanolog_assert_handler_cb_t)(void);
nanolog_ret_t nanolog_set_assert_handler(nanolog_assert_handler_cb_t handler);
nanolog_assert_handler_cb_t nanolog_get_assert_handler(void);
#endif

// Public logging macros

////// DEBUG

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_DEBUG
#if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_DBG(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_func(s_nanolog_fmt_str, __func__, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_DBG_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_ctx_func(s_nanolog_fmt_str, \
                               __func__, \
                               (void *)(CTX), \
                               ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_DBG_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_buf_func(s_nanolog_fmt_str, \
                               __func__, \
                               (void *)(CTX), \
                               BUF, \
                               BUF_LEN, \
                               FMT, \
                               ##__VA_ARGS__); \
  } while (0)
#else  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_DBG(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_DBG_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_ctx(s_nanolog_fmt_str, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_DBG_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(DEBUG) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_debug_buf(s_nanolog_fmt_str, \
                          (void *)(CTX), \
                          BUF, \
                          BUF_LEN, \
                          FMT, \
                          ##__VA_ARGS__); \
  } while (0)
#endif  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#else   // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_DEBUG
#define NL_LOG_DBG(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_DBG_CTX(CTX, FMT, ...) (void)sizeof((FMT, CTX, ##__VA_ARGS__))
#define NL_LOG_DBG_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  (void)sizeof((CTX, BUF, BUF_LEN, FMT, ##__VA_ARGS__))
#endif  // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_DEBUG

////// INFO

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_INFO
#if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_INF(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_func(s_nanolog_fmt_str, __func__, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_INF_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_ctx_func(s_nanolog_fmt_str, __func__, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_INF_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_buf_func(s_nanolog_fmt_str, \
                              __func__, \
                              (void *)(CTX), \
                              BUF, \
                              BUF_LEN, \
                              FMT, \
                              ##__VA_ARGS__); \
  } while (0)
#else  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_INF(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_INF_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_ctx(s_nanolog_fmt_str, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_INF_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(INFO) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_info_buf(s_nanolog_fmt_str, \
                         (void *)(CTX), \
                         BUF, \
                         BUF_LEN, \
                         FMT, \
                         ##__VA_ARGS__); \
  } while (0)
#endif  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#else   // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_INFO
#define NL_LOG_INF(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_INF_CTX(CTX, FMT, ...) (void)sizeof((FMT, CTX, ##__VA_ARGS__))
#define NL_LOG_INF_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  (void)sizeof((CTX, BUF, BUF_LEN, FMT, ##__VA_ARGS__))
#endif  // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_INFO

////// WARNING

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_WARNING
#if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_WRN(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_func(s_nanolog_fmt_str, __func__, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_WRN_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_ctx_func(s_nanolog_fmt_str, \
                                 __func__, \
                                 (void *)(CTX), \
                                 ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_WRN_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_buf_func(s_nanolog_fmt_str, \
                                 __func__, \
                                 (void *)(CTX), \
                                 BUF, \
                                 BUF_LEN, \
                                 FMT, \
                                 ##__VA_ARGS__); \
  } while (0)
#else  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_WRN(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_WRN_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_ctx(s_nanolog_fmt_str, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_WRN_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(WARNING) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_buf(s_nanolog_fmt_str, \
                            (void *)(CTX), \
                            BUF, \
                            BUF_LEN, \
                            FMT, \
                            ##__VA_ARGS__); \
  } while (0)
#endif  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#else   // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_WARNING
#define NL_LOG_WRN(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_WRN_CTX(CTX, FMT, ...) (void)sizeof((FMT, CTX, ##__VA_ARGS__))
#define NL_LOG_WRN_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  (void)sizeof((CTX, BUF, BUF_LEN, FMT, ##__VA_ARGS__))
#endif  // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_WARNING

////// ERROR

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_ERROR
#if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_ERR(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error_func(s_nanolog_fmt_str, __func__, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_ERR_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error_ctx_func(s_nanolog_fmt_str, \
                               __func__, \
                               (void *)(CTX), \
                               ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_ERR_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_buf_func(s_nanolog_fmt_str, \
                                 __func__, \
                                 (void *)(CTX), \
                                 BUF, \
                                 BUF_LEN, \
                                 FMT, \
                                 ##__VA_ARGS__); \
  } while (0)
#else  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_ERR(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_ERR_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_error_ctx(s_nanolog_fmt_str, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_ERR_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(ERROR) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_warning_buf(s_nanolog_fmt_str, \
                            (void *)(CTX), \
                            BUF, \
                            BUF_LEN, \
                            FMT, \
                            ##__VA_ARGS__); \
  } while (0)
#endif  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#else   // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_ERROR
#define NL_LOG_ERR(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_ERR_CTX(CTX, FMT, ...) (void)sizeof((FMT, CTX, ##__VA_ARGS__))
#define NL_LOG_ERR_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  (void)sizeof((CTX, BUF, BUF_LEN, FMT, ##__VA_ARGS__))
#endif  // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_ERROR

////// CRITICAL

#if NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_CRITICAL
#if NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_CRT(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical_func(s_nanolog_fmt_str, __func__, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_CRT_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical_func(s_nanolog_fmt_str, __func__, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_CRT_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical_buf_func(s_nanolog_fmt_str, \
                                  __func__, \
                                  (void *)(CTX), \
                                  BUF, \
                                  BUF_LEN, \
                                  FMT, \
                                  ##__VA_ARGS__); \
  } while (0)
#else  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#define NL_LOG_CRT(FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical(s_nanolog_fmt_str, ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_CRT_CTX(CTX, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical(s_nanolog_fmt_str, (void *)(CTX), ##__VA_ARGS__); \
  } while (0)
#define NL_LOG_CRT_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  do { \
    static char const NANOLOG_SECTION(CRITICAL) s_nanolog_fmt_str[] = FMT; \
    nanolog_log_critical_buf(s_nanolog_fmt_str, \
                             (void *)(CTX), \
                             BUF, \
                             BUF_LEN, \
                             FMT, \
                             ##__VA_ARGS__); \
  } while (0)
#endif  // NANOLOG_LOG_CAPTURE_FUNCTION_NAMES == 1
#else   // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_CRITICAL
#define NL_LOG_CRT(FMT, ...) (void)sizeof((FMT, ##__VA_ARGS__))
#define NL_LOG_CRT_CTX(CTX, FMT, ...) (void)sizeof((FMT, CTX, ##__VA_ARGS__))
#define NL_LOG_CRT_BUF(CTX, BUF, BUF_LEN, FMT, ...) \
  (void)sizeof((CTX, BUF, BUF_LEN, FMT, ##__VA_ARGS__))
#endif  // NL_LOG_SEVERITY_THRESHOLD <= NL_SEV_CRITICAL

// Optional top-level minimal-footprint assert macros

#if NANOLOG_PROVIDE_ASSERT_MACROS == 1
#if NANOLOG_ASSERT_CAPTURE_FILE_LINE == 1
#define NL_ASSERT(COND) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_file_line(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\"", \
                                    __FILE__, \
                                    __LINE__); \
    } \
  } while (0)
#define NL_ASSERT_CTX(CTX, COND) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_ctx_file_line(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\"", \
                                        (CTX), \
                                        __FILE__, \
                                        __LINE__); \
    } \
  } while (0)
#define NL_ASSERT_MSG(COND, FMT, ...) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_file_line(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND \
                                                                  "\" " FMT, \
                                    __FILE__, \
                                    __LINE__, \
                                    ##__VA_ARGS__); \
    } \
  } while (0)
#define NL_ASSERT_MSG_CTX(CTX, COND, FMT, ...) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_ctx_file_line(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND \
                                                                      "\" " FMT, \
                                        (CTX), \
                                        __FILE__, \
                                        __LINE__, \
                                        ##__VA_ARGS__); \
    } \
  } while (0)
#define NL_ASSERT_FAIL() \
  nanolog_assert_fail_file_line(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL", \
                                __FILE__, \
                                __LINE__)
#define NL_ASSERT_FAIL_CTX(CTX) \
  nanolog_assert_fail_ctx_file_line(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL", (CTX))
#define NL_ASSERT_FAIL_MSG(FMT, ...) \
  nanolog_assert_fail_file_line(__FILE__ "(" NL_STR(__LINE__) "): " FMT, \
                                __FILE__, \
                                __LINE__, \
                                ##__VA_ARGS__);
#define NL_ASSERT_FAIL_MSG_CTX(CTX, FMT, ...) \
  nanolog_assert_fail_ctx_file_line(__FILE__ "(" NL_STR(__LINE__) "): " FMT, \
                                    (CTX), \
                                    __FILE__, \
                                    __LINE__, \
                                    ##__VA_ARGS__);
#else  // NANOLOG_ASSERT_CAPTURE_FILE_LINE == 1
#define NL_ASSERT(COND) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\""); \
    } \
  } while (0)
#define NL_ASSERT_CTX(CTX, COND) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_ctx(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\"", (CTX)); \
    } \
  } while (0)
#define NL_ASSERT_MSG(COND, FMT, ...) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\" " FMT, \
                          ##__VA_ARGS__); \
    } \
  } while (0)
#define NL_ASSERT_MSG_CTX(CTX, COND, FMT, ...) \
  do { \
    if (NANOLOG_UNLIKELY(!(COND))) { \
      nanolog_assert_fail_ctx(__FILE__ "(" NL_STR(__LINE__) "): \"" #COND "\" " FMT, \
                              (CTX), \
                              ##__VA_ARGS__); \
    } \
  } while (0)
#define NL_ASSERT_FAIL() \
  nanolog_assert_fail(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL")
#define NL_ASSERT_FAIL_CTX(CTX) \
  nanolog_assert_fail_ctx(__FILE__ "(" NL_STR(__LINE__) "): ASSERT FAIL", (CTX))
#define NL_ASSERT_FAIL_MSG(FMT, ...) \
  nanolog_assert_fail(__FILE__ "(" NL_STR(__LINE__) "): " FMT, ##__VA_ARGS__);
#define NL_ASSERT_FAIL_MSG_CTX(CTX, FMT, ...) \
  nanolog_assert_fail_ctx(__FILE__ "(" NL_STR(__LINE__) "): " FMT, (CTX), ##__VA_ARGS__);
#endif  // NANOLOG_ASSERT_CAPTURE_FILE_LINE == 1
#endif  // NANOLOG_PROVIDE_ASSERT_MACROS == 1

// Implementation details

#ifdef __cplusplus
#define NANOLOG_NORETURN [[noreturn]]
#else
#define NANOLOG_NORETURN _Noreturn
#endif

#ifdef _MSC_VER
#define NANOLOG_NOINLINE __declspec(noinline)
#define NANOLOG_FALLTHROUGH
#elif defined(__GNUC__) || defined(__clang__)
#define NANOLOG_NOINLINE __attribute__((noinline))
#define NANOLOG_FALLTHROUGH __attribute__((fallthrough))
#else
#error Unrecognized compiler, please implement NANOLOG_NOINLINE
#endif

#define NL_STR_EVAL(X) #X
#define NL_STR(X) NL_STR_EVAL(X)

#ifdef __arm__
#define NANOLOG_SECTION(SEV) \
  __attribute__((section(".nanolog." #SEV "." NL_STR(__LINE__) "." NL_STR(__COUNTER__))))
#else
#define NANOLOG_SECTION(SEV)
#endif

#ifdef __GNUC__
#define NANOLOG_LIKELY(COND) __builtin_expect(!!(COND), 1)
#define NANOLOG_UNLIKELY(COND) __builtin_expect(!!(COND), 0)
#define NANOLOG_EXPECT(COND, VAL) __builtin_expect(COND, VAL)
#else
#define NANOLOG_LIKELY(COND) COND
#define NANOLOG_UNLIKELY(COND) COND
#define NANOLOG_EXPECT(COND, VAL) COND
#endif


enum {
  NL_BINARY_LOG_MARKER = 0x1F,  // starts replacement binary payloads
  NL_DYNAMIC_SEV_BIT = 1 << 8,  // or'd into severity from nanolog_log_sev
};

// Internal helper functions

uint32_t nanolog_zigzag_encode(int32_t val);
int32_t nanolog_zigzag_decode(uint32_t val);

nanolog_ret_t nanolog_varint_encode(uint32_t val,
                                    void *out_buf,
                                    unsigned buf_max,
                                    unsigned *out_len);

nanolog_ret_t nanolog_varint_decode(void const *p, uint32_t *out_val, unsigned *out_len);

// Partial applications of the various parameters, to minimize call-site footprint.

void nanolog_log_debug(char const *fmt, ...);
void nanolog_log_debug_func(char const *fmt, char const *func, ...);
void nanolog_log_debug_ctx(char const *fmt, void *ctx, ...);
void nanolog_log_debug_ctx_func(char const *fmt, char const *func, void *ctx, ...);
void nanolog_log_debug_buf(char const *fmt,
                           void *ctx,
                           void const *buf,
                           unsigned buf_len,
                           ...);
void nanolog_log_debug_buf_func(char const *fmt,
                                char const *func,
                                void *ctx,
                                void const *buf,
                                unsigned buf_len,
                                ...);

void nanolog_log_info(char const *fmt, ...);
void nanolog_log_info_func(char const *fmt, char const *func, ...);
void nanolog_log_info_ctx(char const *fmt, void *ctx, ...);
void nanolog_log_info_ctx_func(char const *fmt, char const *func, void *ctx, ...);
void nanolog_log_info_buf(char const *fmt,
                          void *ctx,
                          void const *buf,
                          unsigned buf_len,
                          ...);
void nanolog_log_info_buf_func(char const *fmt,
                               char const *func,
                               void *ctx,
                               void const *buf,
                               unsigned buf_len,
                               ...);

void nanolog_log_warning(char const *fmt, ...);
void nanolog_log_warning_func(char const *fmt, char const *func, ...);
void nanolog_log_warning_ctx(char const *fmt, void *ctx, ...);
void nanolog_log_warning_ctx_func(char const *fmt, char const *func, void *ctx, ...);
void nanolog_log_warning_buf(char const *fmt,
                             void *ctx,
                             void const *buf,
                             unsigned buf_len,
                             ...);
void nanolog_log_warning_buf_func(char const *fmt,
                                  char const *func,
                                  void *ctx,
                                  void const *buf,
                                  unsigned buf_len,
                                  ...);

void nanolog_log_error(char const *fmt, ...);
void nanolog_log_error_func(char const *fmt, char const *func, ...);
void nanolog_log_error_ctx(char const *fmt, void *ctx, ...);
void nanolog_log_error_ctx_func(char const *fmt, char const *func, void *ctx, ...);
void nanolog_log_error_buf(char const *fmt,
                           void *ctx,
                           void const *buf,
                           unsigned buf_len,
                           ...);
void nanolog_log_error_buf_func(char const *fmt,
                                char const *func,
                                void *ctx,
                                void const *buf,
                                unsigned buf_len,
                                ...);

void nanolog_log_critical(char const *fmt, ...);
void nanolog_log_critical_func(char const *fmt, char const *func, ...);
void nanolog_log_critical_ctx(char const *fmt, void *ctx, ...);
void nanolog_log_critical_ctx_func(char const *fmt, char const *func, void *ctx, ...);
void nanolog_log_critical_buf(char const *fmt,
                              void *ctx,
                              void const *buf,
                              unsigned buf_len,
                              ...);
void nanolog_log_critical_buf_func(char const *fmt,
                                   char const *func,
                                   void *ctx,
                                   void const *buf,
                                   unsigned buf_len,
                                   ...);

#if NANOLOG_PROVIDE_ASSERT_MACROS == 1
NANOLOG_NORETURN void nanolog_assert_fail(char const *fmt, ...);
NANOLOG_NORETURN void nanolog_assert_fail_file_line(char const *fmt,
                                                    char const *file,
                                                    int line,
                                                    ...);
NANOLOG_NORETURN void nanolog_assert_fail_ctx(char const *fmt, void *ctx, ...);
NANOLOG_NORETURN void nanolog_assert_fail_ctx_file_line(char const *fmt,
                                                        void *ctx,
                                                        char const *file,
                                                        int line,
                                                        ...);
#endif

#ifdef __cplusplus
}
#endif

#endif
