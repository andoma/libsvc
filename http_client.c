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
#include "fpipe.h"
#include "trace.h"

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
      my_double2str(buf, sizeof(buf), f->ntv_double, -1, DBL_TYPE_GENERIC);
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

  char *hsf_url;

  http_client_auth_cb_t *hsf_auth_cb;
  void *hsf_opaque;
  int hsf_flags;

  FILE *hsf_writer;

  fpipe_t *hsf_pipe; // Valid as long as we keep hsf_writer open

  int hsf_min_speed;

  const char *hsf_http_proxy;

} http_streamed_file_t;



static void *
http_read_file_thread(void *aux)
{
  http_streamed_file_t *hsf = aux;
  char errbuf[512];

  scoped_http_result(hcr);
  int r =
    http_client_request(&hcr, hsf->hsf_url,
                        HCR_OUTPUTFILE(hsf->hsf_writer),
                        HCR_FLAGS(hsf->hsf_flags),
                        HCR_ERRBUF(errbuf, sizeof(errbuf)),
                        HCR_AUTHCB(hsf->hsf_auth_cb, hsf->hsf_opaque),
                        HCR_MIN_SPEED(hsf->hsf_min_speed),
                        HCR_HTTP_PROXY(hsf->hsf_http_proxy),
                        NULL);


  if(r) {
    if(hsf->hsf_flags & HCR_READ_FILE_LOG_ERRORS) {
      trace(LOG_ERR, "%s: %s: %s", __FUNCTION__, hsf->hsf_url, errbuf);
    }
    fpipe_set_error(hsf->hsf_pipe);
  }

  fclose(hsf->hsf_writer);
  free(hsf->hsf_url);
  free(hsf);
  return NULL;
}

/**
 *
 */
FILE *
http_read_file_va(const char *url, ...)
{
  int tag;
  va_list ap;
  va_start(ap, url);

  http_streamed_file_t *hsf = calloc(1, sizeof(http_streamed_file_t));
  hsf->hsf_url = strdup(url);

  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case HCR_TAG_AUTHCB:
      hsf->hsf_auth_cb = va_arg(ap, http_client_auth_cb_t *);
      hsf->hsf_opaque = va_arg(ap, void *);
      break;
    case HCR_TAG_FLAGS:
      hsf->hsf_flags = va_arg(ap, int);
      break;
    case HCR_TAG_MIN_SPEED:
      hsf->hsf_min_speed = va_arg(ap, int);
      break;
    case HCR_TAG_HTTP_PROXY:
      hsf->hsf_http_proxy = va_arg(ap, const char*);
      break;
    default:
      abort();
    }
  }

  FILE *fp;

  hsf->hsf_pipe = fpipe(&fp, &hsf->hsf_writer);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, http_read_file_thread, hsf);
  pthread_attr_destroy(&attr);

  return fp;
}



/**
 *
 */
FILE *
http_read_file(const char *url, void *opaque,
               http_client_auth_cb_t *auth_cb, int flags)
{
  http_streamed_file_t *hsf = calloc(1, sizeof(http_streamed_file_t));
  hsf->hsf_url = strdup(url);
  hsf->hsf_opaque = opaque;
  hsf->hsf_auth_cb = auth_cb;
  hsf->hsf_flags = flags;

  FILE *fp;

  hsf->hsf_pipe = fpipe(&fp, &hsf->hsf_writer);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t tid;
  pthread_create(&tid, &attr, http_read_file_thread, hsf);
  pthread_attr_destroy(&attr);

  return fp;
}
