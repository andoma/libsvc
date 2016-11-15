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
struct http_request;
struct http_connection;

typedef int (websocket_connected_t)(struct http_request *hr);

typedef void (websocket_receive_t)(void *opaque, int opcode,
                                   const uint8_t *data, size_t len);

typedef void (websocket_disconnected_t)(void *opaque, int error);

void websocket_route_add(const char *path,
                         websocket_connected_t *connected,
                         websocket_receive_t *receive,
                         websocket_disconnected_t *error);

void websocket_send(struct http_connection *hc,
                    int opcode, const void *data, size_t len);

void websocket_sendq(struct http_connection *hc,
                     int opcode, htsbuf_queue_t *hq);


void websocket_send_json_ntv(struct http_connection *hc, struct ntv *msg);

void websocket_send_close(struct http_connection *hc, int code,
                          const char *reason);

int websocket_session_start(struct http_request *hr,
                            void *opaque,
                            const char *selected_protocol);
