#pragma once

#include <curl/curl.h>

#include "htsmsg.h"

size_t libsvc_curl_waste_output(char *ptr, size_t size, size_t nmemb,
                                void *userdata);

curl_socket_t libsvc_curl_sock_fn(void *clientp,
                                  curlsocktype purpose,
                                  struct curl_sockaddr *a);


htsmsg_t *libsvc_http_json_get(const char *url, const char *auth,
                               char *errbuf, size_t errlen);

htsmsg_t *libsvc_http_json_post(const char *url, const char *auth,
                                char *errbuf, size_t errlen,
                                const void *payload, size_t payloadlen);
