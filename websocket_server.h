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

#include "htsbuf.h"
#include "htsmsg_json.h"

struct ntv;
struct http_connection;

typedef struct ws_server_connection ws_server_connection_t;

typedef int (websocket_prepare_t)(const char *protocols,
                                  const char *remain,
                                  char *selected_protocol,
                                  size_t selected_protocol_len,
                                  struct http_connection *hc);

typedef void *(websocket_connected_t)(ws_server_connection_t *wsc,
                                      const char *remain,
                                      int prep); 

typedef void (websocket_receive_t)(void *opaque, int opcode,
                                   const uint8_t *data, size_t len);

typedef void (websocket_disconnected_t)(void *opaque, int error);

void websocket_route_add(const char *path,
                         websocket_prepare_t *prepare,
                         websocket_connected_t *connected,
                         websocket_receive_t *receive,
                         websocket_disconnected_t *error);

void websocket_send(ws_server_connection_t *wss, int opcode,
                    const void *data, size_t len);

void websocket_sendq(ws_server_connection_t *wss,
                     int opcode, htsbuf_queue_t *hq);

void websocket_send_json(ws_server_connection_t *wss, struct htsmsg *msg);

void websocket_send_json_ntv(ws_server_connection_t *wss, struct ntv *msg);

void websocket_send_close(ws_server_connection_t *wss, int code,
                          const char *reason);

const struct ntv *websocket_http_session(ws_server_connection_t *wsc);

const char *websocket_get_peeraddr(ws_server_connection_t *wsc);

void websocket_server_turn_on_debug(ws_server_connection_t *wsc);
