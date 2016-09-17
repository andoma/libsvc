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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <errno.h>
#include "websocket.h"
#include "websocket_server.h"
#include "http.h"
#include "misc.h"
#include "asyncio.h"
#include "task.h"
#include "ntv.h"

TAILQ_HEAD(ws_server_data_queue, ws_server_data);

#define WSGUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define PING_INTERVAL 5

typedef struct ws_server_path {
  websocket_prepare_t *wsp_prepare;
  websocket_connected_t *wsp_connected;
  websocket_receive_t *wsp_receive;
  websocket_disconnected_t *wsp_disconnected;
} ws_server_path_t;


/**
 *
 */
typedef struct ws_server_data {
  TAILQ_ENTRY(ws_server_data) wsd_link;
  ws_server_connection_t *wsd_wsc;
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

  task_group_t *wsc_task_group;

  asyncio_timer_t wsc_timer;

  struct ntv *wsc_session;
  char *wsc_peeraddr;
  int wsc_ping_wait;

  websocket_state_t wsc_state;
};


/**
 *
 */
const struct ntv *
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
  asyncio_close(wsc->wsc_af);
  free(wsc->wsc_peeraddr);
  ntv_release(wsc->wsc_session);
  websocket_free(&wsc->wsc_state);
  task_group_destroy(wsc->wsc_task_group);
  free(wsc);
}


/**
 *
 */
static void
ws_dispatch_data(void *aux)
{
  ws_server_data_t *wsd = aux;
  ws_server_connection_t *wsc = wsd->wsd_wsc;
  const ws_server_path_t *wsp = wsc->wsc_path;

  switch(wsd->wsd_opcode) {
  case WSD_OPCODE_DISCONNECT:
    wsp->wsp_disconnected(wsc->wsc_opaque, wsd->wsd_arg);
    wsc_destroy(wsc);
    break;

  default:
    wsp->wsp_receive(wsc->wsc_opaque,
                     wsd->wsd_opcode, wsd->wsd_data, wsd->wsd_arg);
    free(wsd->wsd_data);
    break;
  }
  free(wsd);
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
  wsd->wsd_wsc = wsc;
  task_run_in_group(ws_dispatch_data, wsd, wsc->wsc_task_group);
}


/**
 *
 */
static void
websocket_send_hdr(ws_server_connection_t *wsc, int opcode, size_t len)
{
  htsbuf_queue_t q;
  htsbuf_queue_init(&q, 0);
  websocket_append_hdr(&q, opcode, len);
  asyncio_sendq(wsc->wsc_af, &q, 1);
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

void
websocket_send_json_ntv(ws_server_connection_t *wsc, ntv_t *msg)
{
  htsbuf_queue_t hq;
  htsbuf_queue_init(&hq, 0);

  ntv_json_serialize(msg, &hq, 0);
  websocket_sendq(wsc, 1, &hq);
}


void
websocket_send_close(ws_server_connection_t *wsc, int code,
                     const char *reason)
{
  htsbuf_queue_t hq;
  htsbuf_queue_init(&hq, 0);
  uint16_t code16 = htons(code);
  htsbuf_append(&hq, &code16, 2);
  if(reason)
    htsbuf_append(&hq, reason, strlen(reason));

  websocket_sendq(wsc, 8, &hq);
}


/**
 *
 */
static void
websocket_err_cb(void *opaque, int error)
{
  ws_server_connection_t *wsc = opaque;
  asyncio_shutdown(wsc->wsc_af);
  asyncio_timer_disarm(&wsc->wsc_timer);
  ws_enq_data(wsc, WSD_OPCODE_DISCONNECT, NULL, error);
}

/**
 *
 */
static int
websocket_packet(void *opaque, int opcode, uint8_t **data, int len)
{
  ws_server_connection_t *wsc = opaque;


  wsc->wsc_ping_wait = 0;

  switch(opcode) {
  case 8:
    return 1;

  case 9:
    websocket_send(wsc, 10, *data, len);
    return 0;

  case 10:
    return 0;

  default:
    ws_enq_data(wsc, opcode, *data, len);
    *data = NULL;
    return 0;
  }
}


/**
 *
 */
static void
websocket_read_cb(void *opaque, struct htsbuf_queue *hq)
{
  ws_server_connection_t *wsc = opaque;

  if(websocket_parse(hq, websocket_packet, wsc, &wsc->wsc_state))
    websocket_err_cb(wsc, 0);
}

static void
timer_cb(void *aux)
{
  ws_server_connection_t *wsc = aux;

  if(wsc->wsc_ping_wait == 2) {
    websocket_err_cb(wsc, ETIMEDOUT);
    return;
  }
  uint32_t ping = 0;
  websocket_send(wsc, 9, &ping, 4);
  wsc->wsc_ping_wait++;
  asyncio_timer_arm(&wsc->wsc_timer, asyncio_now() + PING_INTERVAL * 1000000);
}


static void
start_websocket(void *aux)
{
  ws_server_connection_t *wsc = aux;

  asyncio_enable_read(wsc->wsc_af);

  asyncio_timer_init(&wsc->wsc_timer, timer_cb, wsc);
  asyncio_timer_arm(&wsc->wsc_timer, asyncio_now() + PING_INTERVAL * 1000000);
}



static int
websocket_http_callback(http_connection_t *hc, const char *remain,
                        void *opaque)
{
  ws_server_path_t *wsp = opaque;

  const char *c = http_arg_get(&hc->hc_args, "Connection");
  const char *u = http_arg_get(&hc->hc_args, "Upgrade");
  char selected_protocol[512];

  if(strcasecmp(c?:"", "Upgrade") || strcasecmp(u?:"", "websocket"))
    return 405;

  SHA_CTX shactx;
  char sig[64];
  uint8_t d[20];
  const char *k = http_arg_get(&hc->hc_args, "Sec-WebSocket-Key");

  if(k == NULL)
    return 400;

  selected_protocol[0] = 0;
  int prep_result = 0;

  const char *p = http_arg_get(&hc->hc_args, "Sec-WebSocket-Protocol");

  if(wsp->wsp_prepare != NULL) {
    prep_result = wsp->wsp_prepare(p, remain, selected_protocol,
                                   sizeof(selected_protocol));
    if(prep_result < 0)
      return -prep_result;
  }


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
                 "Sec-WebSocket-Accept: %s\r\n",
                 hc->hc_version,
                 sig);

  if(selected_protocol[0]) {
    htsbuf_qprintf(&out, "Sec-WebSocket-Protocol: %s\r\n",
                   selected_protocol);
  }

  htsbuf_qprintf(&out, "\r\n");

  tcp_write_queue(hc->hc_ts, &out);

  // Steal socket
  int fd = tcp_steal_fd(hc->hc_ts);

  ws_server_connection_t *wsc = calloc(1, sizeof(ws_server_connection_t));

  wsc->wsc_task_group = task_group_create();

  wsc->wsc_af = asyncio_stream_mt(fd, websocket_read_cb,
                                  websocket_err_cb, wsc);

  TAILQ_INIT(&wsc->wsc_queue);
  wsc->wsc_path = wsp;

  wsc->wsc_peeraddr = strdup(hc->hc_peer_addr);

  // Steal session information
  wsc->wsc_session = hc->hc_session_received;
  hc->hc_session_received = NULL;

  wsc->wsc_opaque = wsp->wsp_connected(wsc, remain, prep_result);

  asyncio_run_task(start_websocket, wsc);

  /* Returning -1 will just terminate the session. However the socket
     will still stay alive since we stole it above
  */
  return -1;
}


/**
 *
 */
const char *
websocket_get_peeraddr(ws_server_connection_t *wsc)
{
  return wsc->wsc_peeraddr;
}


void
websocket_route_add(const char *path,
                    websocket_prepare_t *prepare,
                    websocket_connected_t *connected,
                    websocket_receive_t *receive,
                    websocket_disconnected_t *disconnected)
{
  ws_server_path_t *wsp = calloc(1, sizeof(ws_server_path_t));
  wsp->wsp_prepare      = prepare;
  wsp->wsp_connected    = connected;
  wsp->wsp_receive      = receive;
  wsp->wsp_disconnected = disconnected;

  http_path_add(path, wsp, websocket_http_callback);
}


