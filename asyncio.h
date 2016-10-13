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


#include <sys/socket.h>
#include "htsbuf.h"
#include "atomic.h"

/**************************************************************************
 * Timers
 **************************************************************************/


typedef struct asyncio_timer {
  LIST_ENTRY(asyncio_timer) at_link;
  int64_t at_expire;
  void (*at_fn)(void *opaque);
  void *at_opaque;
} asyncio_timer_t;

void asyncio_timer_init(asyncio_timer_t *at, void (*fn)(void *opaque),
			void *opque);

void asyncio_timer_arm_delta(asyncio_timer_t *at, uint64_t delta);

void asyncio_timer_disarm(asyncio_timer_t *at);

int64_t asyncio_now(void);

/**************************************************************************
 * IO
 **************************************************************************/


typedef struct asyncio_dns_req asyncio_dns_req_t;

struct async_fd;

void asyncio_init(void);

typedef int (asyncio_accept_cb_t)(void *opaque, int fd,
                                  struct sockaddr *peer,
                                  struct sockaddr *self);

typedef int (asyncio_connect_cb_t)(void *opaque, const char *msg);

typedef void (asyncio_error_cb_t)(void *opaque, int error);

typedef void (asyncio_read_cb_t)(void *opaque, struct htsbuf_queue *hq);

typedef void (asyncio_poll_cb_t)(struct async_fd *);

/**
 *
 */
typedef struct async_fd {
  asyncio_poll_cb_t *af_pollerr;
  asyncio_error_cb_t *af_error;
  asyncio_accept_cb_t *af_accept;
  asyncio_poll_cb_t *af_pollin;
  asyncio_poll_cb_t *af_pollout;
  asyncio_read_cb_t *af_bytes_avail;
  asyncio_connect_cb_t *af_connect;

  void *af_opaque;

  htsbuf_queue_t af_sendq;
  htsbuf_queue_t af_recvq;

  char *af_hostname;

  asyncio_dns_req_t *af_dns_req;
  
  asyncio_timer_t af_timer;

  pthread_mutex_t af_sendq_mutex;

  atomic_t af_refcount;
  int af_fd;
  int af_epoll_flags;
  uint16_t af_port;

  uint16_t af_flags;
#define AF_SENDQ_MUTEX        0x1
} async_fd_t;


async_fd_t *asyncio_bind(const char *bindaddr,
                         int port,
                         asyncio_accept_cb_t *cb,
                         void *opaque);

async_fd_t *asyncio_connect(const char *hostname,
			    int port, int timeout,
			    asyncio_connect_cb_t *cb,
			    asyncio_read_cb_t *read,
			    asyncio_error_cb_t *err,
			    void *opaque);

async_fd_t *asyncio_stream(int fd, 
			   asyncio_read_cb_t *read,
			   asyncio_error_cb_t *err,
			   void *opaque);


// Multithread safe version of asyncio_stream()
async_fd_t *asyncio_stream_mt(int fd,
                              asyncio_read_cb_t *read,
                              asyncio_error_cb_t *err,
                              void *opaque);

void asyncio_close(async_fd_t *af);

void asyncio_send(async_fd_t *af, const void *buf, size_t len, int cork);

void asyncio_send_with_hdr(async_fd_t *af,
                           const void *hdr_buf, size_t hdr_len,
                           const void *buf, size_t len,
                           int cork);

void asyncio_sendq(async_fd_t *af, htsbuf_queue_t *hq, int cork);

void asyncio_sendq_with_hdr(async_fd_t *af, const void *hdr_buf, size_t hdr_len,
                            htsbuf_queue_t *q, int cork);

void asyncio_reconnect(async_fd_t *af, int delay);

void asyncio_enable_read(async_fd_t *fd);

void asyncio_shutdown(async_fd_t *fd);

void async_fd_retain(async_fd_t *af);

void async_fd_release(async_fd_t *af);

/*************************************************************************
 * Workers
 *************************************************************************/

int asyncio_add_worker(void (*fn)(void));

void asyncio_wakeup_worker(int id);

void asyncio_run_task(void (*fn)(void *aux), void *aux);

/************************************************************************
 * Async DNS
 ************************************************************************/


#define ASYNCIO_DNS_STATUS_QUEUED    1
#define ASYNCIO_DNS_STATUS_PENDING   2
#define ASYNCIO_DNS_STATUS_COMPLETED 3
#define ASYNCIO_DNS_STATUS_FAILED    4

asyncio_dns_req_t *asyncio_dns_lookup_host(const char *hostname,
					   void (*cb)(void *opaque,
						      int status,
						      const void *data),
					   void *opaque);

void asyncio_dns_cancel(asyncio_dns_req_t *req);

