#pragma once

/*
 *  tvheadend, TCP common functions
 *  Copyright (C) 2007 Andreas Öman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <netinet/in.h>
#include "htsbuf.h"

typedef struct tcp_stream {
  int ts_fd;
  htsbuf_queue_t ts_spill;

  int (*ts_write)(struct tcp_stream *ts, const void *data, int len);

  int (*ts_read)(struct tcp_stream *ts, void *data, int len, int waitall);

} tcp_stream_t;

void tcp_server_init(void);


typedef void (tcp_server_callback_t)(tcp_stream_t *ts, void *opaque,
				     struct sockaddr_in *peer,
				     struct sockaddr_in *self);

void *tcp_server_create(int port, const char *bindaddr,
                        tcp_server_callback_t *start, void *opaque);

void tcp_close(tcp_stream_t *ts);

int tcp_read(tcp_stream_t *ts, void *buf, size_t len);

int tcp_read_line(tcp_stream_t *ts, char *buf, const size_t bufsize);

int tcp_read_data(tcp_stream_t *ts, char *buf, const size_t bufsize);

int tcp_write_queue(tcp_stream_t *ts, htsbuf_queue_t *q);

int tcp_write(tcp_stream_t *ts, const void *buf, const size_t bufsize);

void tcp_nonblock(tcp_stream_t *ts, int on);

tcp_stream_t *tcp_stream_create_from_fd(int fd);

int tcp_sendfile(tcp_stream_t *ts, int fd, int64_t bytes);

#if 0
int tcp_read_timeout(tcp_stream_t *ts, void *buf, size_t len, int timeout);
#endif

