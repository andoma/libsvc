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
#include "mbuf.h"
#include "atomic.h"

/**************************************************************************
 * Timers
 **************************************************************************/


typedef struct asyncio_timer {
  LIST_ENTRY(asyncio_timer) at_link;
  int64_t at_expire;
  void (*at_fn)(void *opaque, int64_t now);
  void *at_opaque;
} asyncio_timer_t;

void asyncio_timer_init(asyncio_timer_t *at, void (*fn)(void *opaque,
                                                        int64_t now),
			void *opaque);

void asyncio_timer_arm_delta(asyncio_timer_t *at, uint64_t delta);

void asyncio_timer_disarm(asyncio_timer_t *at);

int64_t asyncio_now(void);

int64_t asyncio_get_monotime(void);

/**************************************************************************
 * IO
 **************************************************************************/

#define ASYNCIO_FLAG_THREAD_SAFE     0x1
#define ASYNCIO_FLAG_SSL_VERIFY_CERT 0x2
#define ASYNCIO_FLAG_NO_DELAY        0x4

typedef struct asyncio_sslctx asyncio_sslctx_t;

typedef struct asyncio_fd asyncio_fd_t;

void asyncio_init(void);

typedef int (asyncio_accept_cb_t)(void *opaque, int fd,
                                  struct sockaddr *peer,
                                  struct sockaddr *self);

typedef void (asyncio_error_cb_t)(void *opaque, int error);

typedef void (asyncio_read_cb_t)(void *opaque, struct mbuf *hq);

typedef void (asyncio_poll_cb_t)(struct asyncio_fd *);

asyncio_fd_t *asyncio_bind(const char *bindaddr,
                           int port,
                           asyncio_accept_cb_t *cb,
                           void *opaque, int flags);

asyncio_fd_t *asyncio_dgram(int fd, asyncio_poll_cb_t *input,
                          void *opaque);

asyncio_fd_t *asyncio_connect(int fd, asyncio_error_cb_t *cb, void *opaque);

asyncio_fd_t *asyncio_stream(int fd,
                             asyncio_read_cb_t *read,
                             asyncio_error_cb_t *err,
                             void *opaque,
                             int flags,
                             asyncio_sslctx_t *sslctx,
                             const char *hostname,
                             const char *title);

int asyncio_detach(asyncio_fd_t *af);

void asyncio_close(asyncio_fd_t *af);

int asyncio_send(asyncio_fd_t *af, const void *buf, size_t len, int cork);

int asyncio_send_with_hdr(asyncio_fd_t *af,
                          const void *hdr_buf, size_t hdr_len,
                          const void *buf, size_t len,
                          int cork, int queue_index);

int asyncio_sendq(asyncio_fd_t *af, mbuf_t *hq, int cork, int queue_index);

int asyncio_sendq_with_hdr(asyncio_fd_t *af, const void *hdr_buf,
                           size_t hdr_len, mbuf_t *q,
                           int cork, int queue_index);

void asyncio_send_lock(asyncio_fd_t *af);

void asyncio_send_unlock(asyncio_fd_t *af);

int asyncio_sendq_with_hdr_locked(asyncio_fd_t *af, const void *hdr_buf,
                                  size_t hdr_len, mbuf_t *q,
                                  int cork, int queue_index);

void asyncio_process_pending(asyncio_fd_t *fd);

void asyncio_shutdown(asyncio_fd_t *fd);

void asyncio_fd_retain(asyncio_fd_t *af);

void asyncio_fd_release(asyncio_fd_t *af);

int asyncio_wait_send_buffer(asyncio_fd_t *af, int size);

size_t asyncio_fd_get_queue_length(asyncio_fd_t *af, int queue_index);

const char *asyncio_fd_get_sni_name(asyncio_fd_t *af);

int asyncio_get_fd(asyncio_fd_t *af);

/*************************************************************************
 * Workers
 *************************************************************************/

int asyncio_add_worker(void (*fn)(void));

void asyncio_wakeup_worker(int id);

void asyncio_run_task(void (*fn)(void *aux), void *aux);

void asyncio_run_task_blocking(void (*fn)(void *aux), void *aux);

/************************************************************************
 * SSL / TLS
 ************************************************************************/

asyncio_sslctx_t *asyncio_sslctx_server_from_files(const char *priv_key_file,
                                                   const char *cert_file);

asyncio_sslctx_t *asyncio_sslctx_server_from_pem(const char *priv_key_pem,
                                                 const char *cert_pem);

typedef struct {
  const char *hostname;
  const char *priv_key_pem;
  const char *cert_pem;
} asyncio_sslhost_t;

asyncio_sslctx_t *asyncio_sslctx_server_hosts(const asyncio_sslhost_t *hosts,
                                              size_t num_hosts);

asyncio_sslctx_t *asyncio_sslctx_client(void);

void asyncio_sslctx_free(asyncio_sslctx_t *ctx);
