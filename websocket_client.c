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
#include "sock.h"
#include "misc.h"
#include "bytestream.h"


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
  uint8_t wsc_pending_ping;

  prng_t wsc_maskgenerator;

  union {
    uint8_t u8[4];
    uint32_t u32;
  } wsc_mask;

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

  hdr[1] |= 0x80; // Set mask-bit
  htsbuf_append(&wsc->wsc_sendq, hdr, hlen);

  // Append mask (not included in payload length)
  wsc->wsc_mask.u32 = prng_get(&wsc->wsc_maskgenerator);
  htsbuf_append(&wsc->wsc_sendq, &wsc->wsc_mask.u8, 4);
}


/**
 *
 */
static void
wsc_write_buf(ws_client_t *wsc, int opcode, const void *data, size_t len)
{
  uint8_t *buf = malloc(len);
  memcpy(buf, data, len);

  pthread_mutex_lock(&wsc->wsc_sendq_mutex);
  if(!wsc->wsc_zombie) {
    wsc_append_header(wsc, opcode, len);

    for(int i = 0; i < len; i++)
      buf[i] ^= wsc->wsc_mask.u8[i & 3];

    htsbuf_append_prealloc(&wsc->wsc_sendq, buf, len);
  } else {
    free(buf);
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
      len = rd64_be(hdr + 2);
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
    uint8_t *d = malloc_add(len, 1);
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
    } else if(opcode == 10) {
      wsc->wsc_pending_ping = 0;

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
static void
wsc_send_ping(ws_client_t *wsc)
{
  uint8_t data = 0;
  wsc->wsc_pending_ping = 1;
  wsc_write_buf(wsc, 9 /* PING */, &data, 1); // Just some data
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
    int r = poll(fds, 2, 30000);

    if(r == 0) {
      if(wsc->wsc_pending_ping)
        break;

      wsc_send_ping(wsc);
      continue;
    }

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
      if(hq == NULL)
        break; // Read error
      wsc_read(wsc, hq);
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
int
ws_client_send(ws_client_t *wsc, int opcode, const void *data, size_t len)
{
  char c = 1;
  if(wsc->wsc_pipe[1] == -1)
    return -1;

  wsc_write_buf(wsc, opcode, data, len);

  if(write(wsc->wsc_pipe[1], &c, 1) != 1) {
    return -1;
  }
  return 0;
}

/**
 *
 */
ws_client_t *
ws_client_connect(const char *hostname, int port, const char *path,
                  const tcp_ssl_info_t *tsi,
                  void (*input)(void *aux, int opcode, const void *buf, size_t len),
                  void *aux, int timeout, char *errbuf, size_t errlen,
                  const char *username, const char *password)
{
  char buf[1024];
  tcp_stream_t *ts = dial(hostname, port, timeout, tsi, errbuf, errlen);

  if(ts == NULL)
    return NULL;

  uint8_t nonce[16];
  get_random_bytes(nonce, sizeof(nonce));
  char key[32];
  base64_encode(key, sizeof(key), nonce, sizeof(nonce));
  scoped_char *auth = NULL;

  if(username != NULL && password != NULL) {
    scoped_char *cat = fmt("%s:%s", username, password);
    int size = BASE64_SIZE(strlen(cat));
    char *b64 = alloca(size);
    base64_encode(b64, size, (void *)cat, strlen(cat));
    auth = fmt("Authorization: basic %s\r\n", b64);
  }

  snprintf(buf, sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Connection: Upgrade\r\n"
           "Upgrade: websocket\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "%s"
           "\r\n",
           path, hostname, key, auth ?: "");

  tcp_write(ts, buf, strlen(buf));

  int code = -1;

  while(1) {
    int l = tcp_read_line(ts, buf, sizeof(buf));
    if(l < 0)
      break;
    if(code == -1) {
      if(!strncmp(buf, "HTTP/1.1 ", 9)) {
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
    snprintf(errbuf, errlen, "HTTP Error %d", code);
    return NULL;
  }


  ws_client_t *wsc = calloc(1, sizeof(ws_client_t));

  wsc->wsc_ts = ts;
  wsc->wsc_input = input;
  wsc->wsc_aux = aux;

  prng_init(&wsc->wsc_maskgenerator);

  if(libsvc_pipe(wsc->wsc_pipe)) {
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
