#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#include "err.h"
#include "misc.h"
#include "strvec.h"

void
err_push(err_t **p, const char *fmt, ...)
{
  if(p == NULL)
    return;
  va_list ap;
  va_start(ap, fmt);
  err_t *e = calloc(1, sizeof(err_t));
  e->err_msg = fmtv(fmt, ap);
  va_end(ap);
  e->err_prev = *p;
  *p = e;
}

void
err_pushsys(err_t **p, const char *fmtstr, ...)
{
  if(p == NULL)
    return;

  const int syserr = errno;

  va_list ap;
  va_start(ap, fmtstr);
  err_t *e = calloc(1, sizeof(err_t));
  scoped_char *x = fmtv(fmtstr, ap);
  va_end(ap);

  e->err_syserr = syserr;
  e->err_msg = fmt("%s -- %s", x, strerror(syserr));
  e->err_prev = *p;
  *p = e;
}


void
err_release(err_t **p)
{
  err_t *e, *n;
  for(e = *p; e != NULL; e = n) {
    n = e->err_prev;
    free(e->err_msg);
    free(e);
  }
  *p = NULL;
}

char *
err_str(const err_t *e)
{
  if(e == NULL)
    return NULL;

  scoped_strvec(v);
  for(; e != NULL; e = e->err_prev) {
    strvec_push(&v, e->err_msg);
  }

  return strvec_join(&v, " because ");
}
