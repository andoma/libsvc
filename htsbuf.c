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

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/param.h>

#include "htsbuf.h"
#include "misc.h"

/**
 *
 */
void
htsbuf_queue_init(htsbuf_queue_t *hq, unsigned int maxsize)
{
  TAILQ_INIT(&hq->hq_q);
  hq->hq_size = 0;
  hq->hq_alloc_size = 1000;
}


/**
 *
 */
void
htsbuf_queue_init2(htsbuf_queue_t *hq, unsigned int alloc_size)
{
  TAILQ_INIT(&hq->hq_q);
  hq->hq_size = 0;
  hq->hq_alloc_size = alloc_size;
}


/**
 *
 */
void
htsbuf_data_free(htsbuf_queue_t *hq, htsbuf_data_t *hd)
{
  TAILQ_REMOVE(&hq->hq_q, hd, hd_link);
  free(hd->hd_data);
  free(hd);
}


/**
 *
 */
void
htsbuf_queue_flush(htsbuf_queue_t *hq)
{
  htsbuf_data_t *hd;

  hq->hq_size = 0;

  while((hd = TAILQ_FIRST(&hq->hq_q)) != NULL)
    htsbuf_data_free(hq, hd);
}

/**
 *
 */
void
htsbuf_append(htsbuf_queue_t *hq, const void *buf, size_t len)
{
  htsbuf_data_t *hd = TAILQ_LAST(&hq->hq_q, htsbuf_data_queue);
  int c;
  hq->hq_size += len;

  if(hd != NULL) {
    /* Fill out any previous buffer */
    c = MIN(hd->hd_data_size - hd->hd_data_len, len);
    memcpy(hd->hd_data + hd->hd_data_len, buf, c);
    hd->hd_data_len += c;
    buf += c;
    len -= c;
  }
  if(len == 0)
    return;
  
  hd = malloc(sizeof(htsbuf_data_t));
  TAILQ_INSERT_TAIL(&hq->hq_q, hd, hd_link);
  
  c = MAX(len, hq->hq_alloc_size);

  hd->hd_data = malloc(c);
  hd->hd_data_size = c;
  hd->hd_data_len = len;
  hd->hd_data_off = 0;
  memcpy(hd->hd_data, buf, len);
}

/**
 *
 */
void
htsbuf_append_prealloc(htsbuf_queue_t *hq, const void *buf, size_t len)
{
  htsbuf_data_t *hd;

  hq->hq_size += len;

  hd = malloc(sizeof(htsbuf_data_t));
  TAILQ_INSERT_TAIL(&hq->hq_q, hd, hd_link);
  
  hd->hd_data = (void *)buf;
  hd->hd_data_size = len;
  hd->hd_data_len = len;
  hd->hd_data_off = 0;
}

/**
 *
 */
size_t
htsbuf_read(htsbuf_queue_t *hq, void *buf, size_t len)
{
  size_t r = 0;
  int c;

  htsbuf_data_t *hd;
  
  while(len > 0) {
    hd = TAILQ_FIRST(&hq->hq_q);
    if(hd == NULL)
      break;

    c = MIN(hd->hd_data_len - hd->hd_data_off, len);
    memcpy(buf, hd->hd_data + hd->hd_data_off, c);

    r += c;
    buf += c;
    len -= c;
    hd->hd_data_off += c;
    hq->hq_size -= c;
    if(hd->hd_data_off == hd->hd_data_len)
      htsbuf_data_free(hq, hd);
  }
  return r;
}


/**
 *
 */
int
htsbuf_find(htsbuf_queue_t *hq, uint8_t v)
{
  htsbuf_data_t *hd;
  int i, o = 0;

  TAILQ_FOREACH(hd, &hq->hq_q, hd_link) {
    for(i = hd->hd_data_off; i < hd->hd_data_len; i++) {
      if(hd->hd_data[i] == v) 
	return o + i - hd->hd_data_off;
    }
    o += hd->hd_data_len - hd->hd_data_off;
  }
  return -1;
}



/**
 *
 */
size_t
htsbuf_peek(htsbuf_queue_t *hq, void *buf, size_t len)
{
  size_t r = 0;
  int c;

  htsbuf_data_t *hd = TAILQ_FIRST(&hq->hq_q);
  
  while(len > 0 && hd != NULL) {
    c = MIN(hd->hd_data_len - hd->hd_data_off, len);
    memcpy(buf, hd->hd_data + hd->hd_data_off, c);

    r += c;
    buf += c;
    len -= c;

    hd = TAILQ_NEXT(hd, hd_link);
  }
  return r;
}

/**
 *
 */
size_t
htsbuf_drop(htsbuf_queue_t *hq, size_t len)
{
  size_t r = 0;
  int c;
  htsbuf_data_t *hd;
  
  while(len > 0) {
    hd = TAILQ_FIRST(&hq->hq_q);
    if(hd == NULL)
      break;

    c = MIN(hd->hd_data_len - hd->hd_data_off, len);
    len -= c;
    hd->hd_data_off += c;
    hq->hq_size -= c;
    r += c;
    if(hd->hd_data_off == hd->hd_data_len)
      htsbuf_data_free(hq, hd);
  }
  return r;
}

/**
 *
 */
void
htsbuf_vqprintf(htsbuf_queue_t *hq, const char *fmt, va_list ap)
{
  char buf[10000];
  htsbuf_append(hq, buf, vsnprintf(buf, sizeof(buf), fmt, ap));
}


/**
 *
 */
void
htsbuf_qprintf(htsbuf_queue_t *hq, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  htsbuf_vqprintf(hq, fmt, ap);
  va_end(ap);
}


void
htsbuf_appendq(htsbuf_queue_t *hq, htsbuf_queue_t *src)
{
  htsbuf_data_t *hd;

  hq->hq_size += src->hq_size;
  src->hq_size = 0;

  while((hd = TAILQ_FIRST(&src->hq_q)) != NULL) {
    TAILQ_REMOVE(&src->hq_q, hd, hd_link);
    TAILQ_INSERT_TAIL(&hq->hq_q, hd, hd_link);
  }
}


void
htsbuf_dump_raw_stderr(htsbuf_queue_t *hq)
{
  htsbuf_data_t *hd;
  char n = '\n';

  TAILQ_FOREACH(hd, &hq->hq_q, hd_link) {
    if(write(2, hd->hd_data + hd->hd_data_off,
	     hd->hd_data_len - hd->hd_data_off)
       != hd->hd_data_len - hd->hd_data_off)
      break;
  }
  if(write(2, &n, 1) != 1)
    return;
}

/**
 *
 */
void
htsbuf_append_and_escape_xml(htsbuf_queue_t *hq, const char *s)
{
  const char *c = s;
  const char *e = s + strlen(s);
  if(e == s)
    return;

  while(1) {
    const char *esc;
    switch(*c++) {
    case '<':  esc = "&lt;";   break;
    case '>':  esc = "&gt;";   break;
    case '&':  esc = "&amp;";  break;
    case '\'': esc = "&apos;"; break;
    case '"':  esc = "&quot;"; break;
    default:   esc = NULL;     break;
    }
    
    if(esc != NULL) {
      htsbuf_append(hq, s, c - s - 1);
      htsbuf_append(hq, esc, strlen(esc));
      s = c;
    }
    
    if(c == e) {
      htsbuf_append(hq, s, c - s);
      break;
    }
  }
}


/**
 *
 */
void
htsbuf_append_and_escape_url(htsbuf_queue_t *hq, const char *s)
{
  const char *c = s;
  const char *e = s + strlen(s);
  char C;
  if(e == s)
    return;

  while(1) {
    const char *esc;
    C = *c++;
    char buf[4];

    if((C >= '0' && C <= '9') ||
       (C >= 'a' && C <= 'z') ||
       (C >= 'A' && C <= 'Z') ||
       C == '_' ||
       C == '~' ||
       C == '.' ||
       C == '-') {
      esc = NULL;
    } else {
      static const char hexchars[16] = "0123456789ABCDEF";
      buf[0] = '%';
      buf[1] = hexchars[(C >> 4) & 0xf];
      buf[2] = hexchars[C & 0xf];;
      buf[3] = 0;
      esc = buf;
    }

    if(esc != NULL) {
      htsbuf_append(hq, s, c - s - 1);
      htsbuf_append(hq, esc, strlen(esc));
      s = c;
    }
    
    if(c == e) {
      htsbuf_append(hq, s, c - s);
      break;
    }
  }
}


/**
 *
 */
void
htsbuf_append_and_escape_jsonstr(htsbuf_queue_t *hq, const char *str)
{
  const char *s = str;

  htsbuf_append(hq, "\"", 1);

  while(*s != 0) {
    if(*s == '"' || *s == '/' || *s == '\\' || *s == '\n' || *s == '\r' || *s == '\t') {
      htsbuf_append(hq, str, s - str);

      if(*s == '"')
	htsbuf_append(hq, "\\\"", 2);
      else if(*s == '/')
	htsbuf_append(hq, "\\/", 2);
      else if(*s == '\n')
	htsbuf_append(hq, "\\n", 2);
      else if(*s == '\r')
	htsbuf_append(hq, "\\r", 2);
      else if(*s == '\t')
	htsbuf_append(hq, "\\t", 2);
      else
	htsbuf_append(hq, "\\\\", 2);
      s++;
      str = s;
    } else {
      s++;
    }
  }
  htsbuf_append(hq, str, s - str);
  htsbuf_append(hq, "\"", 1);
}



/**
 *
 */
char *
htsbuf_to_string(htsbuf_queue_t *hq)
{
  char *r = malloc_add(hq->hq_size, 1);
  r[hq->hq_size] = 0;
  htsbuf_read(hq, r, hq->hq_size);
  return r;
}
