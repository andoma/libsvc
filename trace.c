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

#include <pthread.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "queue.h"
#include "trace.h"
#include "misc.h"
#include "mbuf.h"
#include "stream.h"
#include "libsvc.h"

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif


static int dosyslog;
static int dostdout;
static int dostderr;
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
  } else if(!strcmp(facility, "mail")) {
    f = LOG_MAIL;
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
trace_set_outputs(int to_stdout, int to_stderr)
{
  dostdout = to_stdout;
  dostderr = to_stderr;
}

void
trace_enable_stdout(void)
{
  dostdout = 1;
}


static void  __attribute__((constructor))
trace_init(void)
{
  dostderr = isatty(2);
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


#ifdef WITH_ASYNCIO


SIMPLEQ_HEAD(traceline_queue, traceline);

struct traceline {
  SIMPLEQ_ENTRY(traceline) link;
  char *procname;
  char *msg;
  int pid;
  int pri;
  struct timeval tv;
};

#define MAX_TRACELINES_IN_RAM 10000

static LIST_HEAD(, tracesink) tracesinks;

typedef struct tracesink {
  LIST_ENTRY(tracesink) ts_link;
  struct traceline_queue ts_lines;
  int ts_num_tracelines;
  int ts_num_tracelines_dropped;
  int ts_level;
  pthread_cond_t ts_cond;
  int ts_mark;
  pthread_t ts_tid;
  int ts_running;

  char *ts_host;
  int ts_port;
  char *ts_format;
  int ts_tls;
  char *ts_hostname;

  int ts_started;
  pthread_cond_t ts_started_cond;

} tracesink_t;



static pthread_mutex_t trace_mutex = PTHREAD_MUTEX_INITIALIZER;




static const char months[12][4] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *facilities[] = {
  "kernel",
  "user",
  "mail",
  "daemon",
  "security",
  "syslog",
  "lps",
  "news",
  "uucp",
  "clock",
  "security",
  "ftp",
  "ntp",
  "audit",
  "alert",
  "clock",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7",
};




static void
send_traceline(struct timeval *tv, int pid, int pri,
             const char *procname, const char *msg)
{
  tracesink_t *ls;
  const int level = pri & 7;
  LIST_FOREACH(ls, &tracesinks, ts_link) {
    if(level > ls->ts_level)
      continue; // Skip levels that are higher than the configured limit
    if(ls->ts_num_tracelines >= MAX_TRACELINES_IN_RAM) {
      ls->ts_num_tracelines_dropped++;
    } else {
      struct traceline *l = malloc(sizeof(struct traceline));
      l->tv = *tv;
      l->pid = pid;
      l->pri = pri;
      l->procname = strdup(procname);
      l->msg = strdup(msg);
      SIMPLEQ_INSERT_TAIL(&ls->ts_lines, l, link);
      ls->ts_num_tracelines++;
      pthread_cond_signal(&ls->ts_cond);
    }
  }
}



static void
writetrace(int pri, const char *procname, int pid, const char *msg)
{
  //  const int level = pri & 7;
  scoped_char *line = NULL;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  struct tm tm;
  localtime_r(&tv.tv_sec, &tm);

  if(procname == NULL) {
    const int fac = pri >> 3;
    if(fac > 23) {
      procname = "unknown";
    } else {
      procname = facilities[fac];
    }
  }

  if(pid == 0) {
    line = fmt("%s %2d %02d:%02d:%02d %s: %s\n",
               months[tm.tm_mon], tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec,
               procname, msg);
  } else {
    line = fmt("%s %2d %02d:%02d:%02d %s[%d]: %s\n",
               months[tm.tm_mon], tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec,
               procname, pid, msg);
  }

  pthread_mutex_lock(&trace_mutex);

  send_traceline(&tv, pid, pri, procname, msg);

  pthread_mutex_unlock(&trace_mutex);
}



static void *
remote_syslog_thread(void *aux)
{
  tracesink_t *ts = aux;

  char hostnamebuf[128] = {};
  char errbuf[512];
  struct traceline *l;

  const char *hostname = ts->ts_hostname;

  while(ts->ts_running) {
    stream_t *s =
      stream_connect(ts->ts_host, ts->ts_port, 5000,
                     errbuf, sizeof(errbuf),
                     ts->ts_tls ? (STREAM_CONNECT_F_SSL |
                                   STREAM_CONNECT_F_SSL_DONT_VERIFY) : 0);
    pthread_mutex_lock(&trace_mutex);
    if(!ts->ts_started) {
      ts->ts_started = 1;
      pthread_cond_signal(&ts->ts_started_cond);
    }
    pthread_mutex_unlock(&trace_mutex);

    if(s == NULL) {
      trace(LOG_WARNING, "syslog: Unable to connect to %s:%d -- %s",
            ts->ts_host, ts->ts_port, errbuf);
      sleep(10);
      continue;
    }
    trace(LOG_DEBUG, "syslog: Connected to %s:%d", ts->ts_host, ts->ts_port);

    if(hostname == NULL) {
      hostname = hostnamebuf;
      if(gethostname(hostnamebuf, sizeof(hostnamebuf) - 1))
        hostname = "none";
    }

    pthread_mutex_lock(&trace_mutex);

    const char *errmsg = NULL;
    while(s != NULL) {
      l = SIMPLEQ_FIRST(&ts->ts_lines);
      if(l == NULL) {
        if(!ts->ts_running)
          break;
        pthread_cond_wait(&ts->ts_cond, &trace_mutex);
        continue;
      }
      SIMPLEQ_REMOVE_HEAD(&ts->ts_lines, link);
      ts->ts_num_tracelines--;
      pthread_mutex_unlock(&trace_mutex);

      struct tm tm;
      localtime_r(&l->tv.tv_sec, &tm); // We are always in UTC

      char pri_str[16];
      snprintf(pri_str, sizeof(pri_str), "%d", l->pri);

      char pid_str[16];
      snprintf(pid_str, sizeof(pid_str), "%d", l->pid);

      char rfc3339_date[64];
      snprintf(rfc3339_date, sizeof(rfc3339_date),
               "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
               tm.tm_year + 1900,
               tm.tm_mon + 1,
               tm.tm_mday,
               tm.tm_hour,
               tm.tm_min,
               tm.tm_sec,
               (int)(l->tv.tv_usec / 1000));

      const char *tokens[] = {
        "PRI", pri_str,
        "RFC3339DATE", rfc3339_date,
        "HOSTNAME", hostname,
        "PROCESS", l->procname,
        "PID", pid_str,
        "MSG", l->msg,
        NULL
      };

      char *output = str_replace_tokens(fmt("%s\n", ts->ts_format),
                                        "${", "}", tokens);

      int len = strlen(output);
      int ret = stream_write(s, output, len);
      free(output);
      if(ret != len) {
        errmsg = ret < 0 ? strerror(errno) : "Write failed";
        stream_close(s);
        s = NULL;
      }
      pthread_mutex_lock(&trace_mutex);
      if(ret != len) {
        SIMPLEQ_INSERT_HEAD(&ts->ts_lines, l, link);
        ts->ts_num_tracelines++;
        break;
      }
      free(l->msg);
      free(l->procname);
      free(l);
    }

    pthread_mutex_unlock(&trace_mutex);

    if(s != NULL) {
      stream_close(s);
    }


    trace(LOG_DEBUG, "syslog: Disconnected from %s:%d -- %s",
          ts->ts_host, ts->ts_port, errmsg ?: "No error");
  }
  return NULL;
}


static void
trace_syslog_cb(int level, const char *msg)
{
  writetrace(level | LOG_LOCAL0, PROGNAME, getpid(), msg);
}

static tracesink_t *syslog_logsink;

static void
stop_log(void)
{
  pthread_mutex_lock(&trace_mutex);
  syslog_logsink->ts_running = 0;
  pthread_cond_signal(&syslog_logsink->ts_cond);
  pthread_mutex_unlock(&trace_mutex);
  pthread_join(syslog_logsink->ts_tid, NULL);
}

void
trace_enable_builtin_syslog(const char *host, int port,
                            const char *format, int tls,
                            const char *hostname,
                            int wait_for_connection)
{
  if(syslog_logsink)
    return;

  tracesink_t *ts = calloc(1, sizeof(tracesink_t));
  SIMPLEQ_INIT(&ts->ts_lines);
  pthread_cond_init(&ts->ts_cond, NULL);
  pthread_cond_init(&ts->ts_started_cond, NULL);

  ts->ts_host = strdup(host);
  ts->ts_port = port;
  ts->ts_format = strdup(format);
  ts->ts_tls = tls;
  ts->ts_hostname = hostname ? strdup(hostname) : NULL;

  ts->ts_running = 1;
  ts->ts_level = LOG_DEBUG;

  pthread_mutex_lock(&trace_mutex);
  LIST_INSERT_HEAD(&tracesinks, ts, ts_link);
  pthread_mutex_unlock(&trace_mutex);

  pthread_create(&ts->ts_tid, NULL, remote_syslog_thread, ts);

  tracecb = trace_syslog_cb;

  syslog_logsink = ts;

  if(wait_for_connection) {

    pthread_mutex_lock(&trace_mutex);
    while(!ts->ts_started) {
      pthread_cond_wait(&ts->ts_started_cond, &trace_mutex);
    }
    pthread_mutex_unlock(&trace_mutex);
  }

  if(tls) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    OPENSSL_atexit(stop_log);
    return;
#endif
  }
  atexit(stop_log);
}
#endif
