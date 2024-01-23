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
#include "err.h"

static pthread_mutex_t curl_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static CURL *curl_pool;  // A "pool" of one is also a pool

/**
 *
 */
static CURL *
get_handle(void)
{
  CURL *c;
  pthread_mutex_lock(&curl_pool_mutex);
  if(curl_pool != NULL) {
    c = curl_pool;
    curl_pool = NULL;
  } else {
    c = curl_easy_init();
  }
  pthread_mutex_unlock(&curl_pool_mutex);
  return c;
}


static void
put_handle(CURL *c)
{
  pthread_mutex_lock(&curl_pool_mutex);
  if(curl_pool != NULL) {
    curl_easy_cleanup(curl_pool);
  }
  curl_pool = c;
  pthread_mutex_unlock(&curl_pool_mutex);
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
  char *name = argv[0];
  for(int i = 0; name[i]; i++) {
    name[i] = tolower(name[i]);
  }
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



typedef struct outfile_wrapper {
  FILE *outputfile;
  CURL *curl;
} outfile_wrapper_t;


static size_t
wrapper_write(const void *ptr, size_t size, size_t nmemb, outfile_wrapper_t *ow)
{
  long long_http_code = 0;
  curl_easy_getinfo(ow->curl, CURLINFO_RESPONSE_CODE, &long_http_code);
  if(long_http_code >= 300)
    return nmemb;

  return fwrite(ptr, size, nmemb, ow->outputfile);
}


int
http_client_request(http_client_response_t *hcr, const char *url, ...)
{
  scoped_char *redirect_location = NULL;
  extern const char *libsvc_app_version;
  err_t **err = NULL;
  char *errbuf = NULL;
  size_t errsize = 0;
  int flags = 0;
  int tag;
  struct curl_slist *slist = NULL;
  int disable_auth = 0;
  FILE *sendf = NULL;
  scoped_char *www_authenticate_header = NULL;

  http_client_auth_cb_t *auth_cb = NULL;
  void *auth_opaque = NULL;
  FILE *outfile = NULL;
  FILE *infile = NULL;
  va_list apx, ap;
  int memfile = 0;
  va_start(apx, url);

  outfile_wrapper_t ow = {};
  CURL *curl = get_handle();
  int auth_retry_code = 0;
  memset(hcr, 0, sizeof(http_client_response_t));

#if CURL_AT_LEAST_VERSION(7,56,0)
  curl_mime *form = NULL;
#endif
 retry:
  auth_cb = NULL;
  ow.curl = NULL;
  va_copy(ap, apx);

  hcr->hcr_headers = ntv_create_map();

  int have_accept_header = 0;

  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case HCR_TAG_ERRBUF:
      errbuf  = va_arg(ap, char *);
      errsize = va_arg(ap, size_t);
      break;

    case HCR_TAG_ERR:
      err     = va_arg(ap, err_t **);
      break;

    case HCR_TAG_AUTHCB:
      if(disable_auth) {
        va_arg(ap, http_client_auth_cb_t *);
        va_arg(ap, void *);
      } else {
        auth_cb = va_arg(ap, http_client_auth_cb_t *);
        auth_opaque = va_arg(ap, void *);
      }
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
      if(a != NULL && b != NULL) {
        if(!strcmp(a, "Accept")) {
          have_accept_header = 1;
        }
        slist = append_header(slist, a, b);
      }
      break;
    }

    case HCR_TAG_PUTDATA: {
      void *data = va_arg(ap, void *);
      if(data == NULL) {
        (void)va_arg(ap, size_t);
        (void)va_arg(ap, const char *);
        break;
      }
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
      if(data == NULL) {
        (void)va_arg(ap, size_t);
        (void)va_arg(ap, const char *);
        break;
      }
      curl_off_t putdatasize = va_arg(ap, size_t);
      sendf = open_buffer_read(data, putdatasize);
      slist = append_header(slist, "Content-Type", va_arg(ap, const char *));

      curl_easy_setopt(curl, CURLOPT_READDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_SEEKDATA, sendf);
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, putdatasize);
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
      const ntv_t *args = va_arg(ap, const ntv_t *);
      if(args != NULL) {
        scoped_char *str = http_client_ntv_to_args(args);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, str);
      }
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

    case HCR_TAG_POSTFILE: {
      infile = va_arg(ap, FILE *);
      if(infile == NULL) {
        (void)va_arg(ap, const char *);
        break;
      }
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_READDATA, infile);
      curl_easy_setopt(curl, CURLOPT_SEEKDATA, infile);

      const char *ct = va_arg(ap, const char *);
      slist = append_header(slist, "Content-Type", ct);
      slist = curl_slist_append(slist, "Transfer-Encoding: chunked");
      break;
    }

    case HCR_TAG_VERB: {
      const char *verb = va_arg(ap, const char *);
      if(verb != NULL) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, verb);
      }
      break;
    }

    case HCR_TAG_USERNPASS:
      if(disable_auth) {
        va_arg(ap, const char *);
        va_arg(ap, const char *);
      } else {
        const char *username = va_arg(ap, const char *);
        const char *password = va_arg(ap, const char *);
        if(username != NULL && password != NULL) {
          curl_easy_setopt(curl, CURLOPT_USERNAME, username);
          curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        }
      }
      break;

    case HCR_TAG_OUTPUTFILE:
      ow.curl = curl;
      ow.outputfile = va_arg(ap, FILE *);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wrapper_write);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ow);
      outfile = NULL;
      break;

    case HCR_TAG_MIN_SPEED: {
      int min_speed = va_arg(ap, int);
      if(min_speed) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 15L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, (long)min_speed);
      }
      break;
    }

    case HCR_TAG_HTTP_PROXY:
      const char *http_proxy = va_arg(ap, const char*);
      if(http_proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_proxy);
      }
      break;

#if CURL_AT_LEAST_VERSION(7,56,0)
    case HCR_TAG_MULTIPARTFILE: {
      const char *fieldname = va_arg(ap, const char *);
      if(fieldname != NULL) {
        form = curl_mime_init(curl);
        curl_mimepart *field = curl_mime_addpart(form);
        curl_mime_name(field, fieldname);
        const char *mpf_data = va_arg(ap, const char *);
        size_t mpf_size = va_arg(ap, size_t);

        curl_mime_data(field, mpf_data, mpf_size);
        curl_mime_filename(field, "file");
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
      } else {
        va_arg(ap, const char *);
        va_arg(ap, size_t);
      }
    }
      break;
#endif
    default:
      abort();
    }
  }

  va_end(ap);

  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

  if(ow.curl == NULL) {
    if(outfile == NULL) {
      outfile = open_buffer(&hcr->hcr_body, &hcr->hcr_bodysize);
      memfile = 1;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);

  curl_easy_setopt(curl, CURLOPT_USERAGENT, libsvc_app_version ?: PROGNAME);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, hdrfunc);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, hcr);

  if(flags & HCR_DECODE_BODY_AS_JSON && !have_accept_header) {
    slist = append_header(slist, "Accept", "application/json");
  }

  if(flags & HCR_VERBOSE)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  if(flags & HCR_ACCEPT_GZIP)
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");

  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &libsvc_curl_sock_fn);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);

  if(auth_cb) {
    const char *auth = auth_cb(auth_opaque, auth_retry_code,
                               www_authenticate_header);
    if(auth)
      slist = append_header(slist, "Authorization", auth);
  }

  if(slist != NULL)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  CURLcode result = curl_easy_perform(curl);

  if(sendf != NULL)
    fclose(sendf);

#if CURL_AT_LEAST_VERSION(7,56,0)
  if(form)
    curl_mime_free(form);
#endif
  if(slist != NULL) {
    curl_slist_free_all(slist);
    slist = NULL;
  }

  if(outfile != NULL)
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
    strset(&www_authenticate_header,
           ntv_get_str(hcr->hcr_headers, "www-authenticate"));

    http_client_response_free(hcr);
    curl_easy_reset(curl);
    outfile = NULL;
    goto retry;
  }

  char *newurl;
  if(!(flags & HCR_NO_FOLLOW_REDIRECT) && long_http_code / 100 == 3 &&
     !curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &newurl)) {
    disable_auth = 1;
    strset(&redirect_location, newurl);
    url = redirect_location;
    http_client_response_free(hcr);
    curl_easy_reset(curl);
    outfile = NULL;
    goto retry;
  }

  hcr->hcr_http_status = long_http_code;

  hcr->hcr_transport_status = "OK";
  char *primary_ip = NULL;
  if(!curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip)) {
    hcr->hcr_primary_ip = strdup(primary_ip);
  }

  int rval = 0;
  if(result) {
    snprintf(errbuf, errsize, "%s", curl_easy_strerror(result));
    hcr->hcr_transport_status = curl_easy_strerror(result);
    err_push(err, "%s", curl_easy_strerror(result));
    hcr->hcr_local_error = 1;
    rval = 1;
  } else if(!(flags & HCR_NO_FAIL_ON_ERROR) &&
            long_http_code >= 400) {

    snprintf(errbuf, errsize, "HTTP Error %lu", long_http_code);
    snprintf(hcr->hcr_errbuf, sizeof(hcr->hcr_errbuf), "HTTP Error %lu",
             long_http_code);
    hcr->hcr_transport_status = hcr->hcr_errbuf;
    err_push(err, "HTTP Error %lu", long_http_code);
    rval = 1;

  } else if(memfile) {
    rval = 0;
    if(flags & HCR_DECODE_BODY_AS_JSON) {
      char e[512];
      if((hcr->hcr_json_result =
          ntv_json_deserialize(hcr->hcr_body, e, sizeof(e))) == NULL) {

        hcr->hcr_malformed_json = 1;

        err_push(err, "%s", e);

        if(errbuf != NULL)
          snprintf(errbuf, errsize, "%s", e);

        if(errbuf != NULL)
          hcr->hcr_transport_status = errbuf;
        else
          hcr->hcr_transport_status = "Bad JSON";
        rval = 1;
      }
    }
  }

  curl_easy_reset(curl);
  put_handle(curl);
  va_end(apx);

  return rval;
}
