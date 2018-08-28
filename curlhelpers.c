/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
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

#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>

#include "curlhelpers.h"
#include "redblack.h"
#include "talloc.h"
#include "misc.h"
#include "memstream.h"
#include "sock.h"
#include "ntv.h"

size_t
libsvc_curl_waste_output(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  return size * nmemb;
}


/**
 *
 */
curl_socket_t
libsvc_curl_sock_fn(void *clientp,
                    curlsocktype purpose,
                    struct curl_sockaddr *a)
{
  return libsvc_socket(a->family, a->socktype, a->protocol);
}

/**
 *
 */
RB_HEAD(cache_entry_tree, cache_entry);

typedef struct cache_entry {
  RB_ENTRY(cache_entry) ce_link;
  char *ce_url;
  char *ce_auth;

  char *ce_etag;
  time_t ce_expire;

  int ce_status; // If -1, request is pending

  char *ce_response;
} cache_entry_t;

static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cache_cond  = PTHREAD_COND_INITIALIZER;
static struct cache_entry_tree cache_entries;


/**
 *
 */
static int
cache_entry_cmp(const cache_entry_t *a, const cache_entry_t *b)
{
  int x = strcmp(a->ce_url, b->ce_url);
  if(x)
    return x;
  return strcmp(a->ce_auth ?: "", b->ce_auth ?: "");
}


/**
 *
 */
static size_t
hdrfunc(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  cache_entry_t *ce = userdata;
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

  if(!strcasecmp(argv[0], "etag")) {
    free(ce->ce_etag);
    ce->ce_etag = strdup(argv[1]);
  }

  if(!strcasecmp(argv[0], "cache-control")) {
    const char *ma = strstr(argv[1], "max-age=");
    if(ma != NULL) {
      int max_age = atoi(ma + strlen("max-age="));
      ce->ce_expire = time(NULL) + max_age;
    }
  }
  return len;
}


/**
 *
 */
ntv_t *
libsvc_http_json_get(const char *url, const char *auth,
                     char *errbuf, size_t errlen)
{
  cache_entry_t *ce;
  static cache_entry_t *skel;
  time_t now = time(NULL);

  pthread_mutex_lock(&cache_mutex);

  if(skel == NULL)
    skel = calloc(1, sizeof(cache_entry_t));

  skel->ce_url = (char *)url;
  skel->ce_auth = (char *)auth;

  ce = RB_INSERT_SORTED(&cache_entries, skel, ce_link,
                        cache_entry_cmp);

  if(ce == NULL) {
    // Nothing found -> New item 'skel' was inserted
    ce = skel;
    skel = NULL;

    ce->ce_url  = strdup(url);
    ce->ce_auth = auth ? strdup(auth) : NULL;
  }

  while(ce->ce_status == -1)
    pthread_cond_wait(&cache_cond, &cache_mutex);

  if(ce->ce_expire > now) {

    if(ce->ce_status == 200) {
      ntv_t *m = ntv_json_deserialize(ce->ce_response, errbuf, errlen);
      pthread_mutex_unlock(&cache_mutex);
      return m;
    }

    if(ce->ce_status >= 400) {
      snprintf(errbuf, errlen, "HTTP Error %d", ce->ce_status);
      pthread_mutex_unlock(&cache_mutex);
      return NULL;
    }
  }

  ce->ce_status = -1;


  char *out;
  size_t outlen;
  FILE *f = open_buffer(&out, &outlen);

  struct curl_slist *slist = NULL;

  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libsvc");
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, hdrfunc);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, ce);

  slist = curl_slist_append(slist, "Accept: application/json");

  if(auth != NULL)
    slist = curl_slist_append(slist, tsprintf("Authorization: %s", auth));

  if(ce->ce_etag != NULL)
    slist = curl_slist_append(slist, tsprintf("If-None-Match: %s",
                                              ce->ce_etag));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  ce->ce_expire = 0;
  free(ce->ce_etag);
  ce->ce_etag = NULL;

  pthread_mutex_unlock(&cache_mutex);
  CURLcode result = curl_easy_perform(curl);
  curl_slist_free_all(slist);

  pthread_mutex_lock(&cache_mutex);

  pthread_cond_broadcast(&cache_cond);

  fwrite("", 1, 1, f);
  fclose(f);

  if(result) {
    snprintf(errbuf, errlen, "%s", curl_easy_strerror(result));
    curl_easy_cleanup(curl);
    ce->ce_expire = 0;
    ce->ce_status = 0;

    free(ce->ce_response);
    ce->ce_response = NULL;

    pthread_mutex_unlock(&cache_mutex);
    free(out);
    return NULL;
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  ce->ce_status = http_code;

  if(http_code == 304) {

    ce->ce_status = 200;

  } else if(http_code == 200) {

    free(ce->ce_response);
    ce->ce_response = out;
    out = NULL;

  } else {

    snprintf(errbuf, errlen, "HTTP Error %lu", http_code);
    free(ce->ce_response);
    ce->ce_response = NULL;

  }

  free(out);
  curl_easy_cleanup(curl);

  ntv_t *m = NULL;
  if(ce->ce_response != NULL)
    m = ntv_json_deserialize(ce->ce_response, errbuf, errlen);

  pthread_mutex_unlock(&cache_mutex);
  return m;
}

