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

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <poll.h>
#include <stdint.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>

#include "dial.h"
#include "sock.h"
#include "trace.h"

#include <netinet/in.h>
#include <arpa/inet.h>

/**
 *
 */
static int
getstreamsocket(int family)
{
  int fd;
  int val = 1;

  fd = libsvc_socket(family, SOCK_STREAM, 0);
  if(fd == -1)
    return -errno;

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
  return fd;
}





static tcp_stream_t *
dial_one(const struct sockaddr *sa, socklen_t slen, int timeout, const tcp_ssl_info_t *tsi,
         const char *hostname, char *errbuf, size_t errlen)
{
  char addrtxt[512];
  int err;
  socklen_t sockerrlen = sizeof(err);

  switch(sa->sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr,
              addrtxt, sizeof(addrtxt));
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr,
              addrtxt, sizeof(addrtxt));
    break;
  default:
    snprintf(errbuf, errlen, "Invalid address family %d", sa->sa_family);
    return NULL;
  }

  int fd = getstreamsocket(sa->sa_family);
  int r = connect(fd, sa, slen);
  if(r == -1) {
    if(errno == EINPROGRESS) {
      struct pollfd pfd;

      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;

      r = poll(&pfd, 1, timeout);
      if(r == 0) {
        /* Timeout */
        close(fd);
        snprintf(errbuf, errlen, "Connection to %s timed out",
                 addrtxt);
        return NULL;
      }

      if(r == -1) {
        snprintf(errbuf, errlen, "Connection to %s failed -- %s",
                 addrtxt, strerror(errno));
        close(fd);
        return NULL;
      }

      getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &sockerrlen);
    } else {
      err = errno;
    }
  } else {
    err = 0;
  }

  if(err != 0) {
    close(fd);
    snprintf(errbuf, errlen, "Connection to %s failed -- %s",
             addrtxt, strerror(err));
    return NULL;
  }

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

  int val = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

  val = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

#ifdef TCP_KEEPIDLE
  val = 30;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
#endif

#ifdef TCP_KEEPINVL
  val = 15;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));
#endif

#ifdef TCP_KEEPCNT
  val = 5;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));
#endif

  if(tsi != NULL)
    return tcp_stream_create_ssl_from_fd(fd, hostname, tsi,
                                         errbuf, errlen);

  return tcp_stream_create_from_fd(fd);
}


/**
 *
 */
tcp_stream_t *
dial(const char *hostname, int port, int timeout, const tcp_ssl_info_t *tsi,
     char *errbuf, size_t errlen)
{
  char service[10];
  snprintf(service, sizeof(service), "%u", port);
  struct addrinfo *res = NULL;
  const int gai_err = getaddrinfo(hostname, service, NULL, &res);
  if(gai_err) {
    snprintf(errbuf, errlen, "Unable to resolve %s -- %s", hostname,
             gai_strerror(gai_err));
    return NULL;
  }

  tcp_stream_t *ts = NULL;

  const struct addrinfo *ai = res;
  while(ai) {

    ts = dial_one(ai->ai_addr, ai->ai_addrlen, timeout, tsi, hostname, errbuf, errlen);
    if(ts != NULL)
      break;
    ai = ai->ai_next;
  }
  freeaddrinfo(res);
  return ts;
}
