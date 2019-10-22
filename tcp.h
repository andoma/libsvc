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

#pragma once

#include <netinet/in.h>
#include <poll.h>
#include "htsbuf.h"
#include "mbuf.h"

typedef struct tcp_stream tcp_stream_t;

void tcp_init(const char *extra_ca);

void tcp_server_init(void);


typedef void (tcp_server_callback_t)(tcp_stream_t *ts, void *opaque,
				     struct sockaddr_in *peer,
				     struct sockaddr_in *self);

void *tcp_server_create(int port, const char *bindaddr,
                        tcp_server_callback_t *start, void *opaque);

tcp_stream_t *tcp_stream_create_from_fd(int fd);


typedef struct tcp_ssl_info {
  const char *key;
  const char *cert;
  int no_verify;
} tcp_ssl_info_t;

tcp_stream_t *tcp_stream_create_ssl_from_fd(int fd, const char *hostname,
                                            const tcp_ssl_info_t *tsi,
                                            char *errbuf, size_t errlen);

void tcp_close(tcp_stream_t *ts);

int tcp_read(tcp_stream_t *ts, void *buf, size_t len);

int tcp_read_line(tcp_stream_t *ts, char *buf, const size_t bufsize);

int tcp_read_data(tcp_stream_t *ts, char *buf, const size_t bufsize);

htsbuf_queue_t *tcp_read_buffered(tcp_stream_t *ts);

int tcp_write_queue(tcp_stream_t *ts, mbuf_t *q);

int tcp_write(tcp_stream_t *ts, const void *buf, const size_t bufsize);

void tcp_nonblock(tcp_stream_t *ts, int on);

int tcp_sendfile(tcp_stream_t *ts, int fd, int64_t bytes);

void tcp_prepare_poll(tcp_stream_t *ts, struct pollfd *pfd);

int tcp_can_read(tcp_stream_t *ts, struct pollfd *pfd);

int tcp_get_errno(tcp_stream_t *ts);

int tcp_steal_fd(tcp_stream_t *ts);

void tcp_shutdown(tcp_stream_t *ts);

void tcp_server_stop(void);
