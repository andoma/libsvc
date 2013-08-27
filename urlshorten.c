#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fnmatch.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>

#include <curl/curl.h>

#include "libsvc/misc.h"
#include "libsvc/htsmsg_json.h"
#include "libsvc/trace.h"
#include "libsvc/cfg.h"

#include "urlshorten.h"

const char *
urlshorten(const char *input)
{

  static __thread char rbuf[512];
  char url[2048];
  char esc_inp[1024];


  cfg_root(root);
  const char *username = cfg_get_str(root, CFG("bitly", "login"), NULL);
  const char *apikey   = cfg_get_str(root, CFG("bitly", "apikey"), NULL);

  if(username == NULL || apikey == NULL)
    return input;

  CURL *curl = curl_easy_init();
  if(curl == NULL)
    return input;

  url_escape(esc_inp, sizeof(esc_inp), input, URL_ESCAPE_PARAM);
  snprintf(url, sizeof(url),
           "http://api.bit.ly/v3/shorten?login=%s&apikey=%s&longUrl=%s",
           username, apikey, esc_inp);

  char *out = NULL;
  size_t outlen = 0;

  FILE *f = open_memstream(&out, &outlen);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
  CURLcode result = curl_easy_perform(curl);
  fwrite("", 1, 1, f); // NULL terminate output
  fclose(f);
  curl_easy_cleanup(curl);

  if(result) {
    free(out);
    return input;
  }

  char errbuf[512];
  htsmsg_t *m = htsmsg_json_deserialize(out, errbuf, sizeof(errbuf));
  free(out);
  if(m == NULL) {
    trace(LOG_INFO, "Unable to parse bit.ly result: %s", errbuf);
    return input;
  }

  const char *status = htsmsg_get_str(m, "status_txt");
  int code           = htsmsg_get_u32_or_default(m, "status_code", 0);

  if(code != 200) {
    trace(LOG_ERR, "Bit.ly error %d: %s", code, status);
    htsmsg_destroy(m);
    return input;
  }

  htsmsg_t *data = htsmsg_get_map(m, "data");
  const char *s = data ? htsmsg_get_str(data, "url") : NULL;
  if(s == NULL) {
    trace(LOG_INFO, "No 'data.url' in bit.ly result");
    htsmsg_destroy(m);
    return input;
  }

  snprintf(rbuf, sizeof(rbuf), "%s", s);
  htsmsg_destroy(m);
  return rbuf;
}
