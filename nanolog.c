#include "nanolog.h"

#include <stddef.h>

static nl_handler_cb_t s_handler = NULL;
void nl_set_handler(nl_handler_cb_t handler) {
  s_handler = handler;
}

void nl_log_dbg(char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  if (s_handler) {
    s_handler(NL_SEV_DBG, fmt, args);
  }
  va_end(args);
}

