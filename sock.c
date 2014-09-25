/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
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

#ifdef linux
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "sock.h"

/**
 *
 */
int
libsvc_accept(int fd, struct sockaddr *sa, socklen_t *addrlen)
{
  int r;
#ifdef linux
  r = accept4(fd, sa, addrlen, SOCK_CLOEXEC);
#else
  r = accept(fd, sa, addrlen);
  if(r >= 0)
    fcntl(r, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
  return r;
}


/**
 *
 */
int
libsvc_socket(int domain, int type, int protocol)
{
  int fd;
#ifdef linux
  fd = socket(domain, type | SOCK_CLOEXEC, protocol);
#else
  fd = socket(domain, type, protocol);
  if(fd >= 0)
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
  return fd;
}

/**
 *
 */
int
libsvc_pipe(int pipefd[2])
{
#ifdef linux
  return pipe2(pipefd, O_CLOEXEC);
#else
  if(pipe(pipefd) == -1)
    return -1;
  fcntl(pipefd[0], F_SETFD, fcntl(pipefd[0], F_GETFD) | FD_CLOEXEC);
  fcntl(pipefd[1], F_SETFD, fcntl(pipefd[1], F_GETFD) | FD_CLOEXEC);
  return 0;
#endif
}

