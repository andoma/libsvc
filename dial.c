#include <sys/types.h>
#include <sys/socket.h>

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


/**
 *
 */
static int
getstreamsocket(int family)
{
  int fd;
  int val = 1;

  fd = socket(family, SOCK_STREAM, 0);
  if(fd == -1)
    return -errno;

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
  return fd;
}


/**
 *
 */
int
dial(const char *hostname, int port, int timeout)
{
  struct hostent *hp;
  char *tmphstbuf;
  int fd, val, r, err, herr;
  struct hostent hostbuf;
  size_t hstbuflen;
  int res;
  struct sockaddr_in6 in6;
  struct sockaddr_in in;
  socklen_t errlen = sizeof(int);

  if(!strcmp(hostname, "localhost")) {
    if((fd = getstreamsocket(AF_INET)) < 0)
      return fd;

    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r = connect(fd, (struct sockaddr *)&in, sizeof(struct sockaddr_in));

  } else {

    hstbuflen = 1024;
    tmphstbuf = malloc(hstbuflen);

    while((res = gethostbyname_r(hostname, &hostbuf, tmphstbuf, hstbuflen,
                                 &hp, &herr)) == ERANGE) {
      hstbuflen *= 2;
      tmphstbuf = realloc(tmphstbuf, hstbuflen);
    }

    if(herr != 0) {
      free(tmphstbuf);
      switch(herr) {
      case HOST_NOT_FOUND:
        return -ENOENT;

      default:
        return -ENXIO;
      }

    } else if(hp == NULL) {
      free(tmphstbuf);
      return -EIO;
    }

    if((fd = getstreamsocket(hp->h_addrtype)) < 0) {
      free(tmphstbuf);
      return fd;
    }

    switch(hp->h_addrtype) {
    case AF_INET:
      memset(&in, 0, sizeof(in));
      in.sin_family = AF_INET;
      in.sin_port = htons(port);
      memcpy(&in.sin_addr, hp->h_addr_list[0], sizeof(struct in_addr));
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
      free(tmphstbuf);
      return -EPROTONOSUPPORT;
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
        return -ETIMEDOUT;
      }

      if(r == -1) {
        int r = -errno;
        close(fd);
        return r;
      }

      getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen);
    } else {
      err = errno;
    }
  } else {
    err = 0;
  }

  if(err != 0) {
    close(fd);
    return -err;
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

  return fd;
}
