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

#include <curl/curl.h>

#include "misc.h"
#include "memstream.h"
#include "sock.h"
#include "http_client.h"
#include "ntv.h"
#include "strvec.h"
#include "dbl.h"
#include "curlhelpers.h"
#include "mbuf.h"

static pthread_key_t http_client_key;

/**
 *
 */
static CURL *
get_handle(void)
{
  CURL *curl = pthread_getspecific(http_client_key);
  if(curl == NULL) {
    curl = curl_easy_init();
    pthread_setspecific(http_client_key, curl);
  }
  return curl;
}


static void
set_handle(CURL *c)
{
  if(c != NULL) {
    CURL *curl = pthread_getspecific(http_client_key);
    if(curl != NULL) {
      curl_easy_cleanup(curl);
    }
  }

  pthread_setspecific(http_client_key, c);
}



static char *
ntv_to_args(const ntv_t *ntv)
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


/**
 *
 */
static size_t
hdrfunc(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  http_client_response_t *hcr = userdata;
  char *argv[2];
  size_t len = size * nmemb;
  char *line = alloca(len + 1);
  memcpy(line, ptr, len);
  line[len] = 0;

  line[strcspn(line, "\n\r")] = 0;
  if(str_tokenize(line, argv, 2, -1) != 2)
    return len;
  char *c;
  if((c = strrchr(argv[0], ':')) == NULL)
    return len;
  *c = 0;

  ntv_set_str(hcr->hcr_headers, argv[0], argv[1]);
  return len;
}


static struct curl_slist *
append_header(struct curl_slist *slist, const char *a, const char *b)
{
  if(a != NULL && b != NULL) {
    char *r = NULL;
    if(asprintf(&r, "%s: %s", a, b) != -1) {
      slist = curl_slist_append(slist, r);
      free(r);
    }
  }
  return slist;
}


int
http_client_request(http_client_response_t *hcr, const char *url, ...)
{
  char *errbuf = NULL;
  size_t errsize = 0;
  int flags = 0;
  int tag;
  struct curl_slist *slist = NULL;

  FILE *sendf = NULL;

  http_client_auth_cb_t *auth_cb = NULL;
  void *auth_opaque = NULL;
  FILE *outfile = NULL;
  va_list apx, ap;
  int memfile = 0;
  va_start(apx, url);

  CURL *curl = get_handle();
  int auth_retry_code = 0;
  memset(hcr, 0, sizeof(http_client_response_t));

 retry:
  va_copy(ap, apx);

  hcr->hcr_headers = ntv_create_map();

  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case HCR_TAG_ERRBUF:
      errbuf  = va_arg(ap, char *);
      errsize = va_arg(ap, size_t);
      break;

    case HCR_TAG_AUTHCB:
      auth_cb = va_arg(ap, http_client_auth_cb_t *);
      auth_opaque = va_arg(ap, void *);
      break;

    case HCR_TAG_FLAGS:
      flags = va_arg(ap, int);
      break;

    case HCR_TAG_TIMEOUT:
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)va_arg(ap, int));
      break;

    case HCR_TAG_HEADER: {
      const char *a = va_arg(ap, const char *);
      const char *b = va_arg(ap, const char *);
      slist = append_header(slist, a, b);
      break;
    }

    case HCR_TAG_PUTDATA: {
      void *data = va_arg(ap, void *);
      curl_off_t putdatasize = va_arg(ap, size_t);
      sendf = open_buffer_read(data, putdatasize);
      slist = append_header(slist, "Content-Type", va_arg(ap, const char *));

      curl_easy_setopt(curl, CURLOPT_READDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_SEEKDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_PUT, 1L);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, putdatasize);
      break;
    }

    case HCR_TAG_POSTDATA: {
      void *data = va_arg(ap, void *);
      curl_off_t putdatasize = va_arg(ap, size_t);
      sendf = open_buffer_read(data, putdatasize);
      slist = append_header(slist, "Content-Type", va_arg(ap, const char *));

      curl_easy_setopt(curl, CURLOPT_READDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_SEEKDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      break;
    }

    case HCR_TAG_POSTFIELDS: {
      void *data = va_arg(ap, void *);
      long datalen = va_arg(ap, size_t);

      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, datalen);
      break;
    }

    case HCR_TAG_POSTARGS: {
      char *str = ntv_to_args(va_arg(ap, const ntv_t *));
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, str);
      free(str);
      break;
    }

    case HCR_TAG_POSTJSON: {
      char *json = ntv_json_serialize_to_str(va_arg(ap, const ntv_t *), 0);
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json);
      free(json);
      slist = append_header(slist, "Content-Type", "application/json");
      break;
    }

    case HCR_TAG_VERB:
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, va_arg(ap, const char *));
      break;

    case HCR_TAG_USERNPASS:
      curl_easy_setopt(curl, CURLOPT_USERNAME, va_arg(ap, const char *));
      curl_easy_setopt(curl, CURLOPT_PASSWORD, va_arg(ap, const char *));
      break;

    case HCR_TAG_OUTPUTFILE:
      outfile = va_arg(ap, FILE *);
      break;

    default:
      abort();
    }
  }

  va_end(ap);

  if(outfile == NULL) {
    outfile = open_buffer(&hcr->hcr_body, &hcr->hcr_bodysize);
    memfile = 1;
  }

  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

  curl_easy_setopt(curl, CURLOPT_URL, url);

  if(!(flags & HCR_NO_FOLLOW_REDIRECT))
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, PROGNAME);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, hdrfunc);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, hcr);

  if(flags & HCR_DECODE_BODY_AS_JSON)
    slist = append_header(slist, "Accept", "application/json");

  if(!(flags & HCR_NO_FAIL_ON_ERROR))
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

  if(flags & HCR_VERBOSE)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  if(flags & HCR_ACCEPT_GZIP)
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");

  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &libsvc_curl_sock_fn);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);

  if(auth_cb) {
    set_handle(NULL);
    const char *auth = auth_cb(auth_opaque, auth_retry_code);
    set_handle(curl);
    if(auth)
      slist = append_header(slist, "Authorization", auth);
  }

  if(slist != NULL)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  CURLcode result = curl_easy_perform(curl);

  if(sendf != NULL)
    fclose(sendf);

  if(slist != NULL) {
    curl_slist_free_all(slist);
    slist = NULL;
  }
  fflush(outfile);
  if(memfile) {
    fwrite("", 1, 1, outfile); // Write one extra byte to null terminate
    fclose(outfile);
    hcr->hcr_bodysize--; // Adjust for extra null termination
  }


  long long_http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &long_http_code);

  if(long_http_code == 401 && auth_cb && auth_retry_code == 0) {
    auth_retry_code = 401;
    http_client_response_free(hcr);
    curl_easy_reset(curl);
    goto retry;
  }

  hcr->hcr_http_status = long_http_code;

  hcr->hcr_transport_status = "OK";

  int rval = 0;
  if(result) {
    if(result == CURLE_HTTP_RETURNED_ERROR) {
      snprintf(errbuf, errsize, "HTTP Error %lu", long_http_code);
      snprintf(hcr->hcr_errbuf, sizeof(hcr->hcr_errbuf), "HTTP Error %lu",
               long_http_code);
      hcr->hcr_transport_status = hcr->hcr_errbuf;
    } else {
      snprintf(errbuf, errsize, "%s", curl_easy_strerror(result));
      hcr->hcr_transport_status = curl_easy_strerror(result);
    }
    rval = 1;
  } else if(memfile) {
    rval = 0;
    if(flags & HCR_DECODE_BODY_AS_JSON) {
      if((hcr->hcr_json_result =
          ntv_json_deserialize(hcr->hcr_body, errbuf, errsize)) == NULL) {
        if(errbuf != NULL)
          hcr->hcr_transport_status = errbuf;
        else
          hcr->hcr_transport_status = "Bad JSON";
        rval = 1;
      }
    }
  }

  curl_easy_reset(curl);

  va_end(apx);

  return rval;
}

void
http_client_response_free(http_client_response_t *hcr)
{
  ntv_release(hcr->hcr_json_result);
  ntv_release(hcr->hcr_headers);
  ntv_release(hcr->hcr_headers_listified);
  free(hcr->hcr_body);
  memset(hcr, 0, sizeof(http_client_response_t));
}


typedef struct http_client_file {
  char *url;
  int64_t fpos;
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
    setvbuf(fp, NULL, _IOFBF, 65536);
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
                        HCR_FLAGS(HCR_ACCEPT_GZIP),
                        NULL);

  pthread_mutex_lock(&hsf->hsf_mutex);
  hsf->hsf_eof = 1;
  pthread_cond_signal(&hsf->hsf_cond);
  pthread_mutex_unlock(&hsf->hsf_mutex);

  fclose(fp);
  return NULL;
}



static int
hsf_read(void *aux, char *data, int size)
{
  http_streamed_file_t *hsf = aux;
  //  printf("want %d\n", size);
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
http_stream_file(const char *url)
{
  http_streamed_file_t *hsf = calloc(1, sizeof(http_streamed_file_t));
  hsf->hsf_url = strdup(url);

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

/**
 *
 */
static void
http_client_thread_cleanup(void *aux)
{
  curl_easy_cleanup(aux);
}


/**
 *
 */
static void __attribute__((constructor))
http_client_init(void)
{
  pthread_key_create(&http_client_key, http_client_thread_cleanup);
}



