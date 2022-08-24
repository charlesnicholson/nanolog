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

typedef void (*nanolog_handler_cb_t)(nl_sev_t sev, char const *fmt, va_list args);
void nanolog_set_handler(nanolog_handler_cb_t handler);

void nanolog_log_dbg(char const *fmt, ...);
void nanolog_log_inf(char const *fmt, ...);

#define NL_LOG_DBG(FMT, ...) \
  do { \
    static char const __attribute__ ((section(".nanolog"))) s_fmt[] = FMT; \
    nanolog_log_dbg(s_fmt, ##__VA_ARGS__); \
  } while(0)

#define NL_LOG_INF(FMT, ...) \
  do { \
    static char const __attribute__ ((section(".nanolog"))) s_fmt[] = FMT; \
    nanolog_log_inf(s_fmt, ##__VA_ARGS__); \
  } while(0)

#endif
