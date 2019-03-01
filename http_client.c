/******************************************************************************
* Copyright (C) 2013 - 2016 Andreas Smas
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

#include <sys/param.h>

#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "misc.h"
#include "memstream.h"
#include "sock.h"
#include "http_client.h"
#include "ntv.h"
#include "strvec.h"
#include "dbl.h"
#include "mbuf.h"
#include "err.h"


char *
http_client_ntv_to_args(const ntv_t *ntv)
{
  char buf[32];
  scoped_strvec(args);
  NTV_FOREACH(f, ntv) {
    const char *str;
    switch(f->ntv_type) {
    case NTV_STRING:
      str = url_escape_tmp(f->ntv_string, URL_ESCAPE_PARAM);
      break;
    case NTV_DOUBLE:
      my_double2str(buf, sizeof(buf), f->ntv_double);
      str = buf;
      break;
    case NTV_INT:
      snprintf(buf, sizeof(buf), "%" PRId64, f->ntv_s64);
      str = buf;
      break;
    default:
      continue;
    }
    strvec_push_alloced(&args, fmt("%s=%s", f->ntv_name, str));
  }
  return strvec_join(&args, "&");
}


void
http_client_response_free(http_client_response_t *hcr)
{
  ntv_release(hcr->hcr_json_result);
  ntv_release(hcr->hcr_headers);
  ntv_release(hcr->hcr_headers_listified);
  free(hcr->hcr_primary_ip);
  free(hcr->hcr_body);
  memset(hcr, 0, sizeof(http_client_response_t));
}


typedef struct http_client_file {
  char *url;
  int64_t fpos;
  void *hcf_buf;
} http_client_file_t;


/**
 *
 */
static ssize_t
hof_read(void *fh, char *buf, size_t size)
{
  http_client_file_t *hcf = fh;
  char range[100];
  snprintf(range, sizeof(range), "bytes=%"PRId64"-%"PRId64,
           hcf->fpos, hcf->fpos + size - 1);

  scoped_http_result(hcr);

  if(http_client_request(&hcr, hcf->url,
                         HCR_HEADER("Range", range),
                         NULL)) {
    return -1;
  }

  if(hcr.hcr_http_status != 206)
    return -1;

  size_t xferd = MIN(size, hcr.hcr_bodysize);
  memcpy(buf, hcr.hcr_body, xferd);
  hcf->fpos += xferd;
  return xferd;
}


/**
 *
 */
static int
hof_close(void *fh)
{
  http_client_file_t *hcf = fh;
  free(hcf->hcf_buf);
  free(hcf->url);
  free(hcf);
  return 0;
}


#ifdef __APPLE__

static int
hof_read2(void *fh, char *buf, int size)
{
  return hof_read(fh, buf, size);
}


/**
 *
 */
static fpos_t
hof_seek(void *fh, fpos_t offset, int whence)
{
  http_client_file_t *hcf = fh;
  switch(whence) {
  case SEEK_SET:
    hcf->fpos = offset;
    break;
  case SEEK_CUR:
    hcf->fpos += offset;
    break;
  case SEEK_END:
    return -1;
  }
  return hcf->fpos;
}

#else
/**
 *
 */
static int
hof_seek(void *fh, off64_t *offsetp, int whence)
{
  http_client_file_t *hcf = fh;
  switch(whence) {
  case SEEK_SET:
    hcf->fpos = *offsetp;
    break;
  case SEEK_CUR:
    hcf->fpos += *offsetp;
    break;
  case SEEK_END:
    return -1;
  }
  *offsetp = hcf->fpos;
  return 0;
}

static cookie_io_functions_t hof_functions = {
  .read  = hof_read,
  .seek  = hof_seek,
  .close = hof_close,
};
#endif

/**
 *
 */
FILE *
http_open_file(const char *url)
{
  http_client_file_t *hcf = calloc(1, sizeof(http_client_file_t));
  hcf->url = strdup(url);

  FILE *fp;
#ifdef __APPLE__
  fp = funopen(hcf, hof_read2, NULL, hof_seek, hof_close);
#else
  fp = fopencookie(hcf, "rb", hof_functions);
#endif
  if(fp != NULL) {
    size_t buffer_size = 65536;
    hcf->hcf_buf = malloc(buffer_size);
    setvbuf(fp, hcf->hcf_buf, _IOFBF, 65536);
  }
  return fp;
}




typedef struct http_streamed_file {

  pthread_t hsf_thread;
  pthread_mutex_t hsf_mutex;
  pthread_cond_t hsf_cond;
  char *hsf_url;

  mbuf_t hsf_buffer;
  int hsf_open;
  int hsf_eof;
  int hsf_need;

  int hsf_read_status;
  char hsf_errmsg[512];

  int hsf_written;
  int hsf_read;

  http_client_auth_cb_t *hsf_auth_cb;
  void *hsf_opaque;
  int hsf_flags;

  void *hsf_handle;

} http_streamed_file_t;


static int
hsf_write(void *aux, const char *data, int size)
{
  http_streamed_file_t *hsf = aux;

  pthread_mutex_lock(&hsf->hsf_mutex);
  while(hsf->hsf_buffer.mq_size > hsf->hsf_need && hsf->hsf_open)
    pthread_cond_wait(&hsf->hsf_cond, &hsf->hsf_mutex);
  mbuf_append(&hsf->hsf_buffer, data, size);
  hsf->hsf_written += size;
  pthread_cond_signal(&hsf->hsf_cond);
  pthread_mutex_unlock(&hsf->hsf_mutex);

  if(!hsf->hsf_open)
    return 0;
  return size;
}

#ifndef __APPLE__
static ssize_t
hsf_write2(void *cookie, const char *buf, size_t size)
{
  return hsf_write(cookie, buf, size);
}


static cookie_io_functions_t hsf_write_functions = {
  .write  = hsf_write2,
};
#endif

static void *
http_stream_file_thread(void *aux)
{
  http_streamed_file_t *hsf = aux;

  FILE *fp;
#ifdef __APPLE__
  fp = funopen(hsf, NULL, hsf_write, NULL, NULL);
#else
  fp = fopencookie(hsf, "wb", hsf_write_functions);
#endif

  scoped_http_result(hcr);
  hsf->hsf_read_status =
    http_client_request(&hcr, hsf->hsf_url,
                        HCR_OUTPUTFILE(fp),
                        HCR_ERRBUF(hsf->hsf_errmsg, sizeof(hsf->hsf_errmsg)),
                        HCR_FLAGS(hsf->hsf_flags),
                        HCR_AUTHCB(hsf->hsf_auth_cb, hsf->hsf_opaque),
                        NULL);

  fclose(fp);

  pthread_mutex_lock(&hsf->hsf_mutex);
  hsf->hsf_eof = 1;
  pthread_cond_signal(&hsf->hsf_cond);
  pthread_mutex_unlock(&hsf->hsf_mutex);

  return NULL;
}



static int
hsf_read(void *aux, char *data, int size)
{
  http_streamed_file_t *hsf = aux;
  pthread_mutex_lock(&hsf->hsf_mutex);
  hsf->hsf_need = MIN(size, 65536);
  while(!hsf->hsf_eof && hsf->hsf_buffer.mq_size < hsf->hsf_need) {
    pthread_cond_wait(&hsf->hsf_cond, &hsf->hsf_mutex);
  }

  int r = mbuf_read(&hsf->hsf_buffer, data, size);
  hsf->hsf_read += r;
  pthread_cond_signal(&hsf->hsf_cond);
  pthread_mutex_unlock(&hsf->hsf_mutex);
  return r;
}


static int
hsf_close(void *aux)
{
  http_streamed_file_t *hsf = aux;

  pthread_mutex_lock(&hsf->hsf_mutex);
  hsf->hsf_open = 0;
  pthread_cond_signal(&hsf->hsf_cond);
  pthread_mutex_unlock(&hsf->hsf_mutex);


  pthread_join(hsf->hsf_thread, NULL);

  mbuf_clear(&hsf->hsf_buffer);
  free(hsf->hsf_url);
  free(hsf);
  return 0;
}


#ifndef __APPLE__

static ssize_t
hsf_read2(void *fh, char *buf, size_t size)
{
  return hsf_read(fh, buf, size);
}


static cookie_io_functions_t hsf_read_functions = {
  .read  = hsf_read2,
  .close = hsf_close,
};
#endif

/**
 *
 */
FILE *
http_stream_file(const char *url, void *opaque,
                 http_client_auth_cb_t *auth_cb, int flags)
{
  http_streamed_file_t *hsf = calloc(1, sizeof(http_streamed_file_t));
  hsf->hsf_url = strdup(url);
  hsf->hsf_opaque = opaque;
  hsf->hsf_auth_cb = auth_cb;
  hsf->hsf_flags = flags;

  pthread_mutex_init(&hsf->hsf_mutex, NULL);
  pthread_cond_init(&hsf->hsf_cond, NULL);
  hsf->hsf_open = 1;
  mbuf_init(&hsf->hsf_buffer);
  FILE *fp;
#ifdef __APPLE__
  fp = funopen(hsf, hsf_read, NULL, NULL, hsf_close);
#else
  fp = fopencookie(hsf, "rb", hsf_read_functions);
#endif
  if(fp != NULL) {
    setvbuf(fp, NULL, _IOFBF, 65536);
  }
  pthread_create(&hsf->hsf_thread, NULL, http_stream_file_thread, hsf);
  return fp;
}
