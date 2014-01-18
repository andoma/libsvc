#include <fcntl.h>

#include "curlhelpers.h"

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
  int fd = socket(a->family, a->socktype, a->protocol);
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
  return fd;
}

