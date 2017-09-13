#pragma once

typedef struct err {
  struct err *err_prev;
  char *err_msg;
  int err_syserr;
} err_t;

void err_push(err_t **p, const char *fmt, ...);

void err_pushsys(err_t **p, const char *fmt, ...);

void err_release(err_t **p);

char *err_str(const err_t *p);

#define scoped_err_t err_t __attribute__((cleanup(err_release)))
