/*
 *  Copyright (C) 2013 Andreas Öman
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

#include <sys/sendfile.h>
#include <sys/param.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <poll.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tcp.h"
#include "trace.h"
#include "talloc.h"



static SSL_CTX *ssl_ctx;
static pthread_mutex_t *ssl_locks;


struct tcp_stream {
  int ts_fd;
  char ts_nonblock;

  SSL *ts_ssl;

  htsbuf_queue_t ts_spill;
  htsbuf_queue_t ts_sendq;

  int (*ts_write)(struct tcp_stream *ts, const void *data, int len);

  int (*ts_read)(struct tcp_stream *ts, void *data, int len, int waitall);

  int ts_read_status;
  int ts_write_status;

};


/**
 *
 */
int
tcp_get_errno(tcp_stream_t *ts)
{
  int err = 0;
  socklen_t len = sizeof(err);
  getsockopt(ts->ts_fd, SOL_SOCKET, SO_ERROR, &err, &len);
  return err;
}


/**
 *
 */
void
tcp_close(tcp_stream_t *ts)
{
  if(ts->ts_ssl != NULL) {
    SSL_shutdown(ts->ts_ssl);
    SSL_free(ts->ts_ssl);
  }

  htsbuf_queue_flush(&ts->ts_spill);
  htsbuf_queue_flush(&ts->ts_sendq);
  int r = close(ts->ts_fd);
  if(r)
    printf("Close failed!\n");
  free(ts);
}


/**
 *
 */
static int
os_write_try(tcp_stream_t *ts)
{
  htsbuf_data_t *hd;
  htsbuf_queue_t *q = &ts->ts_sendq;
  int len;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {

    len = hd->hd_data_len - hd->hd_data_off;
    assert(len > 0);

    int r = write(ts->ts_fd, hd->hd_data + hd->hd_data_off, len);
    if(r < 1)
      return -1;

    hd->hd_data_off += r;

    if(r != len)
      return -1;

    assert(hd->hd_data_off == hd->hd_data_len);

    TAILQ_REMOVE(&q->hq_q, hd, hd_link);
    free(hd->hd_data);
    free(hd);
  }
  return 0;
}


/**
 *
 */
static int
os_read(struct tcp_stream *ts, void *data, int len, int waitall)
{
  return recv(ts->ts_fd, data, len, waitall ? MSG_WAITALL : 0);
}


/**
 *
 */
static int
os_write(struct tcp_stream *ts, const void *data, int len)
{
  if(!ts->ts_nonblock)
    return write(ts->ts_fd, data, len);

  htsbuf_append(&ts->ts_sendq, data, len);
  os_write_try(ts);
  return len;
}


/**
 *
 */
static int
ssl_read(struct tcp_stream *ts, void *data, int len, int waitall)
{
  assert(waitall == 0); // Not supported atm.

  if(ts->ts_write_status == SSL_ERROR_WANT_READ) {
    errno = EAGAIN;
    return -1;
  }

  ts->ts_read_status = 0;
  int r = SSL_read(ts->ts_ssl, data, len);
  int err = SSL_get_error(ts->ts_ssl, r);
  switch(err) {
  case SSL_ERROR_NONE:
    return r;

  case SSL_ERROR_ZERO_RETURN:
    errno = ECONNRESET;
    return -1;

  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
    ts->ts_read_status = err;
    errno = EAGAIN;
    return -1;

  default:
    errno = EREMOTEIO;
    return -1;
  }
}


/**
 *
 */
static void
ssl_write_try(tcp_stream_t *ts)
{
  htsbuf_data_t *hd;
  htsbuf_queue_t *q = &ts->ts_sendq;
  int len;

  ts->ts_write_status = 0;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {

    len = hd->hd_data_len - hd->hd_data_off;
    assert(len > 0);

    int r = SSL_write(ts->ts_ssl, hd->hd_data + hd->hd_data_off, len);
    int err = SSL_get_error(ts->ts_ssl, r);

    switch(err) {
    case SSL_ERROR_NONE:
      hd->hd_data_off += r;

      assert(hd->hd_data_off <= hd->hd_data_len);

      if(hd->hd_data_off == hd->hd_data_len) {
        TAILQ_REMOVE(&q->hq_q, hd, hd_link);
        free(hd->hd_data);
        free(hd);
      }
      continue;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      ts->ts_write_status = err;
      return;

    default:
      return;
    }
  }
}


/**
 *
 */
static int
ssl_write(struct tcp_stream *ts, const void *data, int len)
{
  if(!ts->ts_nonblock) {
    int r = SSL_write(ts->ts_ssl, data, len);
    if(r > 0)
      return r;
    errno = EREMOTEIO;
    return -1;
  }

  htsbuf_append(&ts->ts_sendq, data, len);

  if(ts->ts_read_status != SSL_ERROR_WANT_WRITE)
    ssl_write_try(ts);

  return len;
}


/**
 *
 */
void
tcp_prepare_poll(tcp_stream_t *ts, struct pollfd *pfd)
{
  assert(ts->ts_nonblock);

  pfd->fd = ts->ts_fd;
  pfd->events = POLLERR | POLLHUP;

  if(ts->ts_ssl != NULL) {

    if(ts->ts_read_status == SSL_ERROR_WANT_WRITE) {
      pfd->events |= POLLOUT;
    } else {
      pfd->events |= POLLIN;
      ssl_write_try(ts);
    }

    if(ts->ts_write_status == SSL_ERROR_WANT_WRITE)
      pfd->events |= POLLOUT;
    else if(ts->ts_write_status == SSL_ERROR_WANT_READ)
      pfd->events |= POLLIN;

  } else {

    pfd->events |= POLLIN;
    if(os_write_try(ts))
      pfd->events |= POLLOUT;
  }
}


/**
 *
 */
int
tcp_can_read(tcp_stream_t *ts, struct pollfd *pfd)
{
  if(ts->ts_ssl == NULL)
    return pfd->revents & POLLIN;

  if(ts->ts_write_status == SSL_ERROR_WANT_READ)
    return 0;

  return 1;
}


/**
 *
 */
tcp_stream_t *
tcp_stream_create_from_fd(int fd)
{
  tcp_stream_t *ts = calloc(1, sizeof(tcp_stream_t));

  ts->ts_fd = fd;
  htsbuf_queue_init(&ts->ts_spill, INT32_MAX);
  htsbuf_queue_init(&ts->ts_sendq, INT32_MAX);

  ts->ts_write = os_write;
  ts->ts_read  = os_read;

  return ts;
}


/**
 *
 */
tcp_stream_t *
tcp_stream_create_ssl_from_fd(int fd)
{
  char errmsg[120];

  tcp_stream_t *ts = calloc(1, sizeof(tcp_stream_t));
  ts->ts_fd = fd;

  if((ts->ts_ssl = SSL_new(ssl_ctx)) == NULL)
    goto bad;

  if(SSL_set_fd(ts->ts_ssl, fd) == 0)
    goto bad;

  if(SSL_connect(ts->ts_ssl) <= 0)
    goto bad;

  SSL_set_mode(ts->ts_ssl, SSL_MODE_AUTO_RETRY);

  ts->ts_fd = fd;
  htsbuf_queue_init(&ts->ts_spill, INT32_MAX);
  htsbuf_queue_init(&ts->ts_sendq, INT32_MAX);

  ts->ts_write = ssl_write;
  ts->ts_read  = ssl_read;
  return ts;

 bad:
  ERR_error_string(ERR_get_error(), errmsg);
  trace(LOG_ERR, "SSL Problem: %s", errmsg);

  tcp_close(ts);
  errno = EREMOTEIO;
  return NULL;
}


/**
 *
 */
int
tcp_sendfile(tcp_stream_t *ts, int fd, int64_t bytes)
{
  while(bytes > 0) {
    int chunk = MIN(1024 * 1024 * 1024, bytes);
    int r = sendfile(ts->ts_fd, fd, NULL, chunk);
    if(r < 1)
      return -1;
    bytes -= r;
  }
  return 0;
}


/**
 *
 */
int
tcp_write(tcp_stream_t *ts, const void *buf, const size_t bufsize)
{
  return ts->ts_write(ts, buf, bufsize);
}


/**
 *
 */
void
tcp_nonblock(tcp_stream_t *ts, int on)
{
  ts->ts_nonblock = on;
  int flags = fcntl(ts->ts_fd, F_GETFL);

  if(on)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  fcntl(ts->ts_fd, F_SETFL, flags);
}



/**
 *
 */
int
tcp_write_queue(tcp_stream_t *ts, htsbuf_queue_t *q)
{
  htsbuf_data_t *hd;
  int l, err = 0;

  while((hd = TAILQ_FIRST(&q->hq_q)) != NULL) {
    TAILQ_REMOVE(&q->hq_q, hd, hd_link);

    while(!err) {

      l = hd->hd_data_len - hd->hd_data_off;
      if(l == 0)
        break;
      int r = ts->ts_write(ts, hd->hd_data + hd->hd_data_off, l);
      if(r > 0) {
        hd->hd_data_off += r;
      } else {
        err = 1;
      }
    }
    free(hd->hd_data);
    free(hd);
  }
  q->hq_size = 0;
  return err;
}


/**
 *
 */
static int
tcp_fill_htsbuf_from_fd(tcp_stream_t *ts, htsbuf_queue_t *hq)
{
  htsbuf_data_t *hd = TAILQ_LAST(&hq->hq_q, htsbuf_data_queue);
  int c;

  if(hd != NULL) {
    /* Fill out any previous buffer */
    c = hd->hd_data_size - hd->hd_data_len;

    if(c > 0) {

      c = ts->ts_read(ts, hd->hd_data + hd->hd_data_len, c, 0);
      if(c < 1)
	return -1;

      hd->hd_data_len += c;
      hq->hq_size += c;
      return 0;
    }
  }

  hd = malloc(sizeof(htsbuf_data_t));

  hd->hd_data_size = 1000;
  hd->hd_data = malloc(hd->hd_data_size);

  c = ts->ts_read(ts, hd->hd_data, hd->hd_data_size, 0);
  if(c < 1) {
    free(hd->hd_data);
    free(hd);
    return -1;
  }
  hd->hd_data_len = c;
  hd->hd_data_off = 0;
  TAILQ_INSERT_TAIL(&hq->hq_q, hd, hd_link);
  hq->hq_size += c;
  return 0;
}


/**
 *
 */
int
tcp_read_line(tcp_stream_t *ts, char *buf, const size_t bufsize)
{
  int len;

  while(1) {
    len = htsbuf_find(&ts->ts_spill, 0xa);

    if(len == -1) {
      if(tcp_fill_htsbuf_from_fd(ts, &ts->ts_spill) < 0)
	return -1;
      continue;
    }
    
    if(len >= bufsize - 1)
      return -1;

    htsbuf_read(&ts->ts_spill, buf, len);
    buf[len] = 0;
    while(len > 0 && buf[len - 1] < 32)
      buf[--len] = 0;
    htsbuf_drop(&ts->ts_spill, 1); /* Drop the \n */
    return 0;
  }
}



/**
 *
 */
int
tcp_read_data(tcp_stream_t *ts, char *buf, const size_t bufsize)
{
  int x, tot = htsbuf_read(&ts->ts_spill, buf, bufsize);

  if(tot == bufsize)
    return 0;

  x = ts->ts_read(ts, buf + tot, bufsize - tot, 1);
  if(x != bufsize - tot)
    return -1;

  return 0;
}


/**
 *
 */
int
tcp_read(tcp_stream_t *ts, void *buf, size_t len)
{
  return ts->ts_read(ts, buf, len, 0);
}




static unsigned long
ssl_tid_fn(void)
{
  return (unsigned long)pthread_self();
}

static void
ssl_lock_fn(int mode, int n, const char *file, int line)
{
  if(mode & CRYPTO_LOCK)
    pthread_mutex_lock(&ssl_locks[n]);
  else
    pthread_mutex_unlock(&ssl_locks[n]);
}



/**
 *
 */
void
tcp_init(void)
{
  SSL_library_init();
  SSL_load_error_strings();
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());

  int i, n = CRYPTO_num_locks();
  ssl_locks = malloc(sizeof(pthread_mutex_t) * n);
  for(i = 0; i < n; i++)
    pthread_mutex_init(&ssl_locks[i], NULL);

  CRYPTO_set_locking_callback(ssl_lock_fn);
  CRYPTO_set_id_callback(ssl_tid_fn);
}
