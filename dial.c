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


/**
 *
 */
tcp_stream_t *
dial(const char *hostname, int port, int timeout, const tcp_ssl_info_t *tsi,
     char *errbuf, size_t errlen)
{
  struct hostent *hp;
  char *tmphstbuf;
  int fd, val, r, err, herr;
#if !defined(__APPLE__)
  struct hostent hostbuf;
  size_t hstbuflen;
  int res;
#endif
  struct sockaddr_in6 in6;
  struct sockaddr_in in;
  socklen_t sockerrlen = sizeof(int);

  if(!strcmp(hostname, "localhost")) {
    if((fd = getstreamsocket(AF_INET)) < 0) {
      snprintf(errbuf, errlen, "%s", strerror(-fd));
      return NULL;
    }

    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r = connect(fd, (struct sockaddr *)&in, sizeof(struct sockaddr_in));

  } else {

#if defined(__APPLE__)
    herr = 0;
    tmphstbuf = NULL; /* free NULL is a nop */
    /* TODO: AF_INET6 */
    hp = gethostbyname(hostname);
    if(hp == NULL)
      herr = h_errno;
#else
    hstbuflen = 1024;
    tmphstbuf = malloc(hstbuflen);

    while((res = gethostbyname_r(hostname, &hostbuf, tmphstbuf, hstbuflen,
                                 &hp, &herr)) == ERANGE) {
      hstbuflen *= 2;
      tmphstbuf = realloc(tmphstbuf, hstbuflen);
    }
#endif
    if(herr != 0) {
      free(tmphstbuf);
      switch(herr) {
      case HOST_NOT_FOUND: {
        snprintf(errbuf, errlen, "Host not found");
        return NULL;
      }

      default:
        snprintf(errbuf, errlen, "Resolver error");
        return NULL;
      }

    } else if(hp == NULL) {
      free(tmphstbuf);
      snprintf(errbuf, errlen, "Resolver error");
      return NULL;
    }

    if((fd = getstreamsocket(hp->h_addrtype)) < 0) {
      free(tmphstbuf);
      snprintf(errbuf, errlen, "%s", strerror(-fd));
      return NULL;
    }

    switch(hp->h_addrtype) {
    case AF_INET:
      memset(&in, 0, sizeof(in));
      in.sin_family = AF_INET;
      in.sin_port = htons(port);
      int num_addr = 0;
      while(hp->h_addr_list[num_addr])
        num_addr++;

      if(num_addr == 0) {
        close(fd);
        free(tmphstbuf);
        snprintf(errbuf, errlen, "No address");
        return NULL;
      }
      int a = rand() % num_addr;
      memcpy(&in.sin_addr, hp->h_addr_list[a], sizeof(struct in_addr));
      r = connect(fd, (struct sockaddr *)&in, sizeof(struct sockaddr_in));
      break;

    case AF_INET6:
      memset(&in6, 0, sizeof(in6));
      in6.sin6_family = AF_INET6;
      in6.sin6_port = htons(port);
      memcpy(&in6.sin6_addr, hp->h_addr_list[0], sizeof(struct in6_addr));
      r = connect(fd, (struct sockaddr *)&in, sizeof(struct sockaddr_in6));
      break;

    default:
      close(fd);
      free(tmphstbuf);
      snprintf(errbuf, errlen, "Address family not supported");
      return NULL;
    }

    free(tmphstbuf);
  }

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
        snprintf(errbuf, errlen, "Connection timed out");
        return NULL;
      }

      if(r == -1) {
        snprintf(errbuf, errlen, "Connection failed -- %s", strerror(errno));
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
    snprintf(errbuf, errlen, "Connection failed -- %s", strerror(err));
    return NULL;
  }

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

  val = 1;
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
