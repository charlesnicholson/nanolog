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

typedef void (*nl_handler_cb_t)(nl_sev_t sev, char const *fmt, va_list args);
void nl_set_handler(nl_handler_cb_t handler);

void nl_log_dbg(char const *fmt, ...);

#define NL_LOG_DBG(FMT, ...) \
  do { \
    static char const __attribute__ ((section(".nanolog"))) s_fmt[] = FMT; \
    nl_log_dbg(s_fmt, ##__VA_ARGS__); \
  } while(0)

#endif
