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

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trace.h"
#include "misc.h"

static int dosyslog;

/**
 *
 */
void
tracev(int level, const char *fmt, va_list ap)
{
  if(dosyslog) {
    va_list aq;
    va_copy(aq, ap);
    vsyslog(level, fmt, aq);
    va_end(aq);
  }

  if(!isatty(2))
    return;

  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
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
  int f;
  const char *x;
  if(!strcmp(facility, "daemon"))
    f = LOG_DAEMON;
  else if((x = mystrbegins(facility, "local")) != NULL)
    f = LOG_LOCAL0 + atoi(x);
  else {
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

