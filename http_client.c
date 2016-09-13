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

#include <curl/curl.h>

#include "misc.h"
#include "memstream.h"
#include "sock.h"
#include "http_client.h"
#include "ntv.h"
#include "curlhelpers.h"

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



int
http_client_request(http_client_response_t *hcr, const char *url, ...)
{
  char *errbuf = NULL;
  size_t errsize = 0;
  long timeout = 0;
  int flags = 0;
  int tag;
  struct curl_slist *slist = NULL;

  va_list ap;
  va_start(ap, url);

  memset(hcr, 0, sizeof(http_client_response_t));
  hcr->hcr_headers = ntv_create_map();

  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case HCR_TAG_ERRBUF:
      errbuf  = va_arg(ap, char *);
      errsize = va_arg(ap, size_t);
      break;

    case HCR_TAG_FLAGS:
      flags = va_arg(ap, int);
      break;

    case HCR_TAG_TIMEOUT:
      timeout = va_arg(ap, int);
      break;

    case HCR_TAG_HEADER: {
      const char *a = va_arg(ap, const char *);
      const char *b = va_arg(ap, const char *);

      if(a != NULL && b != NULL) {
        char *r = NULL;
        if(asprintf(&r, "%s: %s", a, b) != -1) {
          slist = curl_slist_append(slist, r);
          free(r);
        }
      }
      break;
    }

    default:
      abort();
    }
  }

  FILE *f = open_buffer(&hcr->hcr_body, &hcr->hcr_bodysize);

  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);

  if(!(flags & HCR_NO_FOLLOW_REDIRECT))
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, PROGNAME);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, hdrfunc);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, hcr);

  if(!(flags & HCR_NO_FAIL_ON_ERROR))
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

  if(flags & HCR_VERBOSE)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &libsvc_curl_sock_fn);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);
  if(timeout)
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

  if(slist != NULL)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  CURLcode result = curl_easy_perform(curl);

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
    snprintf(errbuf, errsize, "%s", curl_easy_strerror(result));
    rval = 1;
  } else {
    rval = 0;
    if(flags & HCR_DECODE_BODY_AS_JSON) {
      if((hcr->hcr_json_result = ntv_json_deserialize(hcr->hcr_body,
                                                      errbuf, errsize)) == NULL)
        rval = 1;

    }
  }

  curl_easy_cleanup(curl);
  return rval;
}

void
http_client_response_free(http_client_response_t *hcr)
{
  ntv_release(hcr->hcr_json_result);
  ntv_release(hcr->hcr_headers);
  ntv_release(hcr->hcr_headers_listified);
  free(hcr->hcr_body);
}

