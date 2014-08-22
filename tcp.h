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
#include <poll.h>
#include "htsbuf.h"

typedef struct tcp_stream tcp_stream_t;

void tcp_init(void);

void tcp_server_init(void);


typedef void (tcp_server_callback_t)(tcp_stream_t *ts, void *opaque,
				     struct sockaddr_in *peer,
				     struct sockaddr_in *self);

void *tcp_server_create(int port, const char *bindaddr,
                        tcp_server_callback_t *start, void *opaque);

tcp_stream_t *tcp_stream_create_from_fd(int fd);

tcp_stream_t *tcp_stream_create_ssl_from_fd(int fd);

void tcp_close(tcp_stream_t *ts);

int tcp_read(tcp_stream_t *ts, void *buf, size_t len);

int tcp_read_line(tcp_stream_t *ts, char *buf, const size_t bufsize);

int tcp_read_data(tcp_stream_t *ts, char *buf, const size_t bufsize);

int tcp_write_queue(tcp_stream_t *ts, htsbuf_queue_t *q);

int tcp_write(tcp_stream_t *ts, const void *buf, const size_t bufsize);

void tcp_nonblock(tcp_stream_t *ts, int on);

int tcp_sendfile(tcp_stream_t *ts, int fd, int64_t bytes);

void tcp_prepare_poll(tcp_stream_t *ts, struct pollfd *pfd);

int tcp_can_read(tcp_stream_t *ts, struct pollfd *pfd);

int tcp_get_errno(tcp_stream_t *ts);

int tcp_steal_fd(tcp_stream_t *ts);
