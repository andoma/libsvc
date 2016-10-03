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
#include "curlhelpers.h"


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

  va_list ap;
  va_start(ap, url);

  CURL *curl = get_handle();

  memset(hcr, 0, sizeof(http_client_response_t));
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

    case HCR_TAG_POSTNTV: {
      char *json = ntv_json_serialize_to_str(va_arg(ap, const ntv_t *), 0);
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json);
      free(json);
      slist = append_header(slist, "Content-Type", "application/json");
      break;
    }

    default:
      abort();
    }
  }

  FILE *f = open_buffer(&hcr->hcr_body, &hcr->hcr_bodysize);


  curl_easy_setopt(curl, CURLOPT_URL, url);

  if(!(flags & HCR_NO_FOLLOW_REDIRECT))
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
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

  if(slist != NULL)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  if(auth_cb) {
    set_handle(NULL);
    const char *auth = auth_cb(auth_opaque, 0);
    set_handle(curl);
    if(auth)
      slist = append_header(slist, "Authorization", auth);

  }

  CURLcode result = curl_easy_perform(curl);

  if(sendf != NULL)
    fclose(sendf);

  if(slist != NULL)
    curl_slist_free_all(slist);

  fwrite("", 1, 1, f); // Write one extra byte to null terminate
  fclose(f);
  hcr->hcr_bodysize--; // Adjust for extra null termination

  long long_http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &long_http_code);
  hcr->hcr_http_status = long_http_code;

  int rval = 0;
  if(result) {
    if(result == CURLE_HTTP_RETURNED_ERROR) {
      snprintf(errbuf, errsize, "HTTP Error %lu", long_http_code);
    } else {
      snprintf(errbuf, errsize, "%s", curl_easy_strerror(result));
    }
    rval = 1;
  } else {
    rval = 0;
    if(flags & HCR_DECODE_BODY_AS_JSON) {
      if((hcr->hcr_json_result = ntv_json_deserialize(hcr->hcr_body,
                                                      errbuf, errsize)) == NULL)
        rval = 1;

    }
  }

  curl_easy_reset(curl);

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



