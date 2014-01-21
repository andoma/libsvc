/*
 *  Copyright (C) 2013 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
  openlog("doozer", LOG_PID, f);

}

/**
 *
 */
void
hexdump(const char *pfx, const void *data_, int len)
{
  int i, j;
  const uint8_t *data = data_;
  char buf[100];
  
  for(i = 0; i < len; i+= 16) {
    int p = snprintf(buf, sizeof(buf), "0x%06x: ", i);

    for(j = 0; j + i < len && j < 16; j++) {
      p += snprintf(buf + p, sizeof(buf) - p, "%s%02x ",
		    j==8 ? " " : "", data[i+j]);
    }
    const int cnt = (17 - j) * 3 + (j < 8);
    for(int i = 0; i < cnt; i++)
      buf[p + i] = ' ';
    p += cnt;

    for(j = 0; j + i < len && j < 16; j++)
      buf[p++] = data[i+j] < 32 || data[i+j] > 126 ? '.' : data[i+j];
    buf[p] = 0;
    trace(LOG_DEBUG, "%s: %s", pfx, buf);
  }
}

