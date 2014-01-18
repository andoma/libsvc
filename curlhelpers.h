#pragma once

#include <curl/curl.h>

size_t libsvc_curl_waste_output(char *ptr, size_t size, size_t nmemb,
                                void *userdata);

curl_socket_t libsvc_curl_sock_fn(void *clientp,
                                  curlsocktype purpose,
                                  struct curl_sockaddr *a);

