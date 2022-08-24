#include "nanolog.h"

#include <stddef.h>

static nanolog_handler_cb_t s_handler = NULL;
void nanolog_set_handler(nanolog_handler_cb_t handler) {
  s_handler = handler;
}

void nanolog_log_dbg(char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  if (s_handler) {
    s_handler(NL_SEV_DBG, fmt, args);
  }
  va_end(args);
}

void nanolog_log_inf(char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  if (s_handler) {
    s_handler(NL_SEV_INFO, fmt, args);
  }
  va_end(args);
}

