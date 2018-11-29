/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "trace.h"
#include "misc.h"
#include "mbuf.h"

static int dosyslog;
static int dostdout;
static void (*tracecb)(int level, const char *msg);

/**
 *
 */
void
tracev(int level, const char *fmt, va_list ap)
{
  if(dosyslog) {
    va_list aq;
    va_copy(aq, ap);
    vsyslog(level & 7, fmt, aq);
    va_end(aq);
  }

  const int dostderr = isatty(2);

  if(!(dostderr || dostdout || tracecb))
    return;

  scoped_char *buf = fmtv(fmt, ap);

  if(tracecb)
    tracecb(level, buf);

  if(dostdout) {
    printf("%s\n", buf);
    fflush(stdout);
  }
  if(dostderr) {
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    time_t tim = tv.tv_sec;
    localtime_r(&tim, &tm);

    const char *sgr = "";
    switch(level & 7) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
      sgr = "\033[31m";
      break;
    case LOG_WARNING:
      sgr = "\033[33m";
      break;
    case LOG_NOTICE:
      sgr = "\033[35m";
      break;
    case LOG_INFO:
      sgr = "\033[32m";
      break;
    case LOG_DEBUG:
      sgr = "\033[36m";
      break;
    }


    fprintf(stderr, "%s%4d-%02d-%02d %02d:%02d:%02d.%03d %s\033[0m\n",
            sgr,
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            (int)tv.tv_usec / 1000,
            buf);
  }
}


/**
 *
 */
void
trace(int level, const char *fmt, ...)
{
  char *s = mystrdupa(fmt);
  decolorize(s);
  va_list ap;
  va_start(ap, fmt);
  tracev(level, s, ap);
  va_end(ap);
}

/**
 *
 */
void
decolorize(char *s)
{
  char *d = s;
  while(*s) {
    if(*s == '\003') {
      s++;
      if(*s >= '0' && *s <= '9')
        s++;
      if(*s >= '0' && *s <= '9')
        s++;
      continue;
    }
    *d++ = *s++;
  }
  *d = 0;
}


/**
 *
 */
void
enable_syslog(const char *program, const char *facility)
{
  unsigned int f;
  const char *x;
  if(!strcmp(facility, "daemon")) {
    f = LOG_DAEMON;
  } else if((x = mystrbegins(facility, "local")) != NULL) {
    f = atoi(x);
    if(f > 7) {
      fprintf(stderr, "Invalid syslog config -- %s\n", facility);
      exit(1);
    }
    static const int locals[8] = {
      LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3,
      LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7};
    f = locals[f];
  } else {
    fprintf(stderr, "Invalid syslog config -- %s\n", facility);
    exit(1);
  }

  dosyslog = 1;
  openlog(program, LOG_PID, f);

}

/**
 *
 */
void
hexdump(const char *pfx, const void *data_, int len)
{
  int i, j, k;
  const uint8_t *data = data_;
  char buf[100];
  
  for(i = 0; i < len; i+= 16) {
    int p = snprintf(buf, sizeof(buf), "0x%06x: ", i);

    for(j = 0; j + i < len && j < 16; j++) {
      p += snprintf(buf + p, sizeof(buf) - p, "%s%02x ",
		    j==8 ? " " : "", data[i+j]);
    }
    const int cnt = (17 - j) * 3 + (j < 8);
    for(k = 0; k < cnt; k++)
      buf[p + k] = ' ';
    p += cnt;

    for(j = 0; j + i < len && j < 16; j++)
      buf[p++] = data[i+j] < 32 || data[i+j] > 126 ? '.' : data[i+j];
    buf[p] = 0;
    trace(LOG_DEBUG, "%s: %s", pfx, buf);
  }
}

/**
 *
 */
void
trace_enable_stdout(void)
{
  dostdout = 1;
}


/**
 *
 */
void
trace_set_callback(void (*cb)(int level, const char *msg))
{
  tracecb = cb;
}


void
xlog(int level, const xlog_kv_t *kv, const char *fmt, ...)
{
  char tmp[64];
  va_list ap;
  va_start(ap, fmt);
  scoped_char *primary_msg = fmtv(fmt, ap);
  va_end(ap);

  scoped_mbuf_t mq = MBUF_INITIALIZER(mq);
  const char *prefix = "";
  mbuf_append_str(&mq, " {");
  while(kv != NULL) {
    if(kv->key == NULL)
      break;
    if(kv->type == XLOG_TYPE_STRING && kv->value_str == NULL) {
      kv++;
      continue;
    }
    mbuf_append_str(&mq, prefix);
    prefix = ", ";
    switch(kv->type) {
    case XLOG_TYPE_STRING:
      mbuf_append_and_escape_jsonstr(&mq, kv->key, 0);
      mbuf_append_str(&mq, ":");
      mbuf_append_and_escape_jsonstr(&mq, kv->value_str, 0);
      break;
    case XLOG_TYPE_INT:
      mbuf_append_and_escape_jsonstr(&mq, kv->key, 0);
      snprintf(tmp, sizeof(tmp), ":%"PRId64, kv->value_int);
      mbuf_append_str(&mq, tmp);
      break;
    case XLOG_TYPE_LINK:
      kv = kv->next;
      prefix = "";
      continue;
    }
    kv++;
  }
  mbuf_append_str(&mq, "}");

  const char *json = mbuf_pullup(&mq, mq.mq_size);
  trace(level, "%s%.*s", primary_msg, (int)mq.mq_size, json);
}

