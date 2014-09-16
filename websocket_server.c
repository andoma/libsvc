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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <errno.h>
#include "websocket_server.h"
#include "http.h"
#include "misc.h"
#include "asyncio.h"

TAILQ_HEAD(ws_server_data_queue, ws_server_data);

#define WSGUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct ws_server_path {
  websocket_connected_t *wsp_connected;
  websocket_receive_t *wsp_receive;
  websocket_disconnected_t *wsp_disconnected;
} ws_server_path_t;


/**
 *
 */
typedef struct ws_server_data {
  TAILQ_ENTRY(ws_server_data) wsd_link;
  void *wsd_data;
  int wsd_opcode;
  int wsd_arg;

#define WSD_OPCODE_DISCONNECT -1

} ws_server_data_t;

/**
 *
 */
struct ws_server_connection {
  async_fd_t *wsc_af;

  void *wsc_opaque;

  const ws_server_path_t *wsc_path;

  struct ws_server_data_queue wsc_queue;

  pthread_mutex_t wsc_mutex;
  pthread_cond_t wsc_cond;
  int wsc_thread_running;

  struct htsmsg *wsc_session;

};


/**
 *
 */
htsmsg_t *
websocket_http_session(ws_server_connection_t *wsc)
{
  return wsc->wsc_session;
}

/**
 *
 */
static void
wsc_destroy(ws_server_connection_t *wsc)
{
  pthread_cond_destroy(&wsc->wsc_cond);
  pthread_mutex_destroy(&wsc->wsc_mutex);
  asyncio_close(wsc->wsc_af);
  if(wsc->wsc_session != NULL)
    htsmsg_destroy(wsc->wsc_session);
  free(wsc);
}


/**
 *
 */
static void *
wsc_dispatch_thread(void *aux)
{
  ws_server_connection_t *wsc = aux;
  ws_server_data_t *wsd;
  const ws_server_path_t *wsp = wsc->wsc_path;

  pthread_mutex_lock(&wsc->wsc_mutex);

  while(1) {
    wsd = TAILQ_FIRST(&wsc->wsc_queue);
    if(wsd == NULL) {
      struct timespec t;
      t.tv_sec = time(NULL) + 5;
      t.tv_nsec = 0;
      if(pthread_cond_timedwait(&wsc->wsc_cond,
                                &wsc->wsc_mutex, &t) == ETIMEDOUT) {
        break;
      }
      continue;
    }

    TAILQ_REMOVE(&wsc->wsc_queue, wsd, wsd_link);
    pthread_mutex_unlock(&wsc->wsc_mutex);


    switch(wsd->wsd_opcode) {
    case WSD_OPCODE_DISCONNECT:
      wsp->wsp_disconnected(wsc->wsc_opaque, wsd->wsd_arg);
      free(wsd);
      wsc_destroy(wsc);
      return NULL;

    default:
      wsp->wsp_receive(wsc->wsc_opaque,
                       wsd->wsd_opcode, wsd->wsd_data, wsd->wsd_arg);
    }

    pthread_mutex_lock(&wsc->wsc_mutex);
  }
  wsc->wsc_thread_running = 0;
  pthread_mutex_unlock(&wsc->wsc_mutex);
  return NULL;
}



/**
 *
 */
static void
ws_enq_data(ws_server_connection_t *wsc, int opcode, void *data, int arg)
{
  ws_server_data_t *wsd = malloc(sizeof(ws_server_data_t));
  wsd->wsd_data = data;
  wsd->wsd_opcode = opcode;
  wsd->wsd_arg = arg;

  pthread_mutex_lock(&wsc->wsc_mutex);
  TAILQ_INSERT_TAIL(&wsc->wsc_queue, wsd, wsd_link);
  if(!wsc->wsc_thread_running) {
    pthread_t id;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&id, &attr, wsc_dispatch_thread, wsc);
    pthread_attr_destroy(&attr);
    wsc->wsc_thread_running = 1;
  } else {
    pthread_cond_signal(&wsc->wsc_cond);
  }
  pthread_mutex_unlock(&wsc->wsc_mutex);
}


/**
 *
 */
static void
websocket_send_hdr(ws_server_connection_t *wsc, int opcode, size_t len)
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
  asyncio_send(wsc->wsc_af, hdr, hlen, 1);
}


/**
 *
 */
void
websocket_send(ws_server_connection_t *wsc, int opcode,
               const void *data, size_t len)
{
  websocket_send_hdr(wsc, opcode, len);
  asyncio_send(wsc->wsc_af, data, len, 0);
}


/**
 *
 */
void
websocket_sendq(ws_server_connection_t *wsc, int opcode, htsbuf_queue_t *hq)
{
  websocket_send_hdr(wsc, opcode, hq->hq_size);
  asyncio_sendq(wsc->wsc_af, hq, 0);
}


void
websocket_send_json(ws_server_connection_t *wsc, htsmsg_t *msg)
{
  htsbuf_queue_t hq;
  htsbuf_queue_init(&hq, 0);

  htsmsg_json_serialize(msg, &hq, 0);
  websocket_sendq(wsc, 1, &hq);
}


/**
 *
 */
static void
websocket_read_cb(void *opaque, struct htsbuf_queue *hq)
{
  ws_server_connection_t *wsc = opaque;
  uint8_t hdr[14]; // max header length
  while(1) {
    int p = htsbuf_peek(hq, &hdr, 14);
    const uint8_t *m;
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
      websocket_send(wsc, 10, d, len);
      free(d);
    } else {
      ws_enq_data(wsc, opcode, d, len);
    }
  }
}


/**
 *
 */
static void
websocket_err_cb(void *opaque, int error)
{
  ws_server_connection_t *wsc = opaque;
  asyncio_shutdown(wsc->wsc_af);
  ws_enq_data(wsc, WSD_OPCODE_DISCONNECT, NULL, error);
}


static int
websocket_http_callback(http_connection_t *hc, const char *remain,
                        void *opaque)
{
  ws_server_path_t *wsp = opaque;

  const char *c = http_arg_get(&hc->hc_args, "Connection");
  const char *u = http_arg_get(&hc->hc_args, "Upgrade");

  if(strcasecmp(c?:"", "Upgrade") || strcasecmp(u?:"", "websocket"))
    return 405;

  SHA_CTX shactx;
  char sig[64];
  uint8_t d[20];
  const char *k = http_arg_get(&hc->hc_args, "Sec-WebSocket-Key");

  if(k == NULL)
    return 400;

  SHA1_Init(&shactx);
  SHA1_Update(&shactx, (const void *)k, strlen(k));
  SHA1_Update(&shactx, (const void *)WSGUID, strlen(WSGUID));
  SHA1_Final(d, &shactx);

  base64_encode(sig, sizeof(sig), d, 20);

  htsbuf_queue_t out;
  htsbuf_queue_init(&out, 0);

  htsbuf_qprintf(&out,
                 "HTTP/1.%d 101 Switching Protocols\r\n"
                 "Connection: Upgrade\r\n"
                 "Upgrade: websocket\r\n"
                 "Sec-WebSocket-Accept: %s\r\n"
                 "\r\n",
                 hc->hc_version,
                 sig);

  tcp_write_queue(hc->hc_ts, &out);

  // Steal socket
  int fd = tcp_steal_fd(hc->hc_ts);

  ws_server_connection_t *wsc = calloc(1, sizeof(ws_server_connection_t));
  async_fd_t *af = asyncio_stream_mt(fd, websocket_read_cb,
                                     websocket_err_cb, wsc);

  TAILQ_INIT(&wsc->wsc_queue);
  pthread_mutex_init(&wsc->wsc_mutex, NULL);
  pthread_cond_init(&wsc->wsc_cond, NULL);

  wsc->wsc_af = af;
  wsc->wsc_path = wsp;
  wsc->wsc_session = hc->hc_session_received;
  wsc->wsc_opaque = wsp->wsp_connected(wsc);

  hc->hc_session_received = NULL;

  asyncio_enable_read(af);

  /* Returning -1 will just terminate the session. However the socket
     will still stay alive since we stole it above
  */
  return -1;
}



void
websocket_route_add(const char *path,
                    websocket_connected_t *connected,
                    websocket_receive_t *receive,
                    websocket_disconnected_t *disconnected)
{
  ws_server_path_t *wsp = calloc(1, sizeof(ws_server_path_t));
  wsp->wsp_connected    = connected;
  wsp->wsp_receive      = receive;
  wsp->wsp_disconnected = disconnected;

  http_path_add(path, wsp, websocket_http_callback);
}


