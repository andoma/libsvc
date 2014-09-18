#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dial.h"
#include "websocket_client.h"
#include "atomic.h"

/**
 *
 */
struct ws_client {
  pthread_t wsc_tid;
  tcp_stream_t *wsc_ts;

  int wsc_pipe[2];

  void (*wsc_input)(void *aux, int opcode, const void *buf, size_t len);
  void *wsc_aux;

  atomic_t wsc_refcount;

  pthread_mutex_t wsc_sendq_mutex;
  htsbuf_queue_t wsc_sendq;
  int wsc_zombie;
};


/**
 *
 */
static void
wsc_append_header(ws_client_t *wsc, int opcode, size_t len)
{
  uint8_t hdr[14]; // max header length
  int hlen;
  hdr[0] = 0x80 | (opcode & 0xf);
  if(len <= 125) {
    hdr[1] = len;
    hlen = 2;
  } else if(len < 65536) {
    hdr[1] = 126;
    hdr[2] = len >> 8;
    hdr[3] = len;
    hlen = 4;
  } else {
    hdr[1] = 127;
    uint64_t u64 = len;
#if defined(__LITTLE_ENDIAN__)
    u64 = __builtin_bswap64(u64);
#endif
    memcpy(hdr + 2, &u64, sizeof(uint64_t));
    hlen = 10;
  }
  htsbuf_append(&wsc->wsc_sendq, hdr, hlen);
}


/**
 *
 */
static void
wsc_write_buf(ws_client_t *wsc, int opcode, const void *data, size_t len)
{
  pthread_mutex_lock(&wsc->wsc_sendq_mutex);
  if(!wsc->wsc_zombie) {
    wsc_append_header(wsc, opcode, len);
    htsbuf_append(&wsc->wsc_sendq, data, len);
  }
  pthread_mutex_unlock(&wsc->wsc_sendq_mutex);
}


/**
 *
 */
static void
wsc_read(ws_client_t *wsc, struct htsbuf_queue *hq)
{
  uint8_t hdr[14]; // max header length
  const uint8_t *m;

  while(1) {
    int p = htsbuf_peek(hq, &hdr, 14);

    if(p < 2)
      return;

    int opcode  = hdr[0] & 0xf;
    int64_t len = hdr[1] & 0x7f;
    int hoff = 2;

    if(len == 126) {
      if(p < 4)
        return;
      len = hdr[2] << 8 | hdr[3];
      hoff = 4;
    } else if(len == 127) {
      if(p < 10)
        return;
      memcpy(&len, hdr + 2, sizeof(uint64_t));
#if defined(__LITTLE_ENDIAN__)
      len = __builtin_bswap64(len);
#endif
      hoff = 10;
    }

    if(hdr[1] & 0x80) {
      if(p < hoff + 4)
        return;
      m = hdr + hoff;

      hoff += 4;
    } else {
      m = NULL;
    }

    if(hq->hq_size < hoff + len)
      return;

    uint8_t *d = malloc(len+1);
    htsbuf_drop(hq, hoff);
    htsbuf_read(hq, d, len);
    d[len] = 0;

    if(m != NULL) {
      int i;
      for(i = 0; i < len; i++)
        d[i] ^= m[i&3];
    }

    if(opcode == 9) {
      // PING
      wsc_write_buf(wsc, 10, d, len);
    } else {
      wsc->wsc_input(wsc->wsc_aux, opcode, d, len);
    }
    free(d);
  }
}


/**
 *
 */
static void
wsc_sendq(ws_client_t *wsc)
{
  pthread_mutex_lock(&wsc->wsc_sendq_mutex);
  tcp_write_queue(wsc->wsc_ts, &wsc->wsc_sendq);
  pthread_mutex_unlock(&wsc->wsc_sendq_mutex);
}


/**
 *
 */
static void
wsc_release(ws_client_t *wsc)
{
  if(atomic_dec(&wsc->wsc_refcount))
    return;
  htsbuf_queue_flush(&wsc->wsc_sendq);
  pthread_mutex_destroy(&wsc->wsc_sendq_mutex);
  free(wsc);
}


/**
 *
 */
static void *
wsc_thread(void *aux)
{
  ws_client_t *wsc = aux;

  struct pollfd fds[2];

  fds[0].fd = wsc->wsc_pipe[0];
  fds[0].events = POLLIN | POLLERR;

  tcp_nonblock(wsc->wsc_ts, 1);

  while(1) {

    wsc_sendq(wsc);

    tcp_prepare_poll(wsc->wsc_ts, &fds[1]);
    int r = poll(fds, 2, -1);

    if(r == -1) {
      if(errno == EINTR)
        continue;
      break;
    }


    if(fds[0].revents & (POLLERR | POLLHUP)) {
      // Pipe closed, bye bye
      break;
    }

    if(fds[0].revents & POLLIN) {
      char c;
      if(read(wsc->wsc_pipe[0], &c, 1) != 1)
        break;

      // Pipe input, something to send. We transfer from sendq to tcp_stream every
      // poll round using wsc_sendq() so there's nothing special to do here.
    }

    if(fds[1].revents & (POLLERR | POLLHUP)) {
      // websocket connection closed, bye bye
      break;
    }

    if(tcp_can_read(wsc->wsc_ts, &fds[1])) {
      htsbuf_queue_t *hq = tcp_read_buffered(wsc->wsc_ts);
      if(hq != NULL) {
        wsc_read(wsc, hq);
      }
    }
  }

  pthread_mutex_lock(&wsc->wsc_sendq_mutex);
  wsc->wsc_zombie = 1;
  pthread_mutex_unlock(&wsc->wsc_sendq_mutex);

  wsc->wsc_input(wsc->wsc_aux, 0, NULL, 0);

  close(wsc->wsc_pipe[0]);
  tcp_close(wsc->wsc_ts);
  wsc_release(wsc);
  return NULL;
}


/**
 *
 */
void
ws_client_close(ws_client_t *wsc)
{
  close(wsc->wsc_pipe[1]);
  wsc->wsc_pipe[1] = -1;
  wsc_release(wsc);
}


/**
 *
 */
void
ws_client_send(ws_client_t *wsc, int opcode, const void *data, size_t len)
{
  char c = 1;
  if(wsc->wsc_pipe[1] == -1)
    return;

  wsc_write_buf(wsc, opcode, data, len);

  if(write(wsc->wsc_pipe[1], &c, 1) != 1) {
    perror("write");
  }
}

/**
 *
 */
ws_client_t *
ws_client_connect(const char *hostname, int port, const char *path, int ssl,
                  void (*input)(void *aux, int opcode, const void *buf, size_t len),
                  void *aux)
{
  char buf[1024];
  tcp_stream_t *ts = dial(hostname, port, 20, ssl);

  if(ts == NULL) {
    perror("dial");
    return NULL;
  }

  snprintf(buf, sizeof(buf),
           "GET %s HTTP/1.0\r\n"
           "Host: %s\r\n"
           "Connection: Upgrade\r\n"
           "Upgrade: websocket\r\n"
           "Sec-WebSocket-Key: 123\r\n"
           "\r\n",
           path, hostname);

  tcp_write(ts, buf, strlen(buf));

  int code = -1;

  while(1) {
    int l = tcp_read_line(ts, buf, sizeof(buf));
    if(l < 0)
      break;

    if(code == -1) {
      if(!strncmp(buf, "HTTP/1.0 ", 9) || !strncmp(buf, "HTTP/1.1 ", 9)) {
        code = atoi(buf + 9);
      } else {
        code = 0;
      }
    }

    if(strlen(buf) == 0)
      break;
  }

  if(code != 101) {
    tcp_close(ts);
    return NULL;
  }


  ws_client_t *wsc = calloc(1, sizeof(ws_client_t));

  wsc->wsc_ts = ts;
  wsc->wsc_input = input;
  wsc->wsc_aux = aux;

  if(pipe2(wsc->wsc_pipe, O_CLOEXEC)) {
    free(wsc);
    tcp_close(ts);
    return NULL;
  }

  pthread_mutex_init(&wsc->wsc_sendq_mutex, NULL);
  htsbuf_queue_init(&wsc->wsc_sendq, 0);

  atomic_set(&wsc->wsc_refcount, 1);
  return wsc;
}


/**
 *
 */
void
ws_client_start(ws_client_t *wsc)
{
  atomic_inc(&wsc->wsc_refcount);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&wsc->wsc_tid, &attr, wsc_thread, wsc);
  pthread_attr_destroy(&attr);
}
