#pragma once

#include "htsbuf.h"
#include "htsmsg_json.h"

typedef struct ws_server_connection ws_server_connection_t;

typedef void *(websocket_connected_t)(ws_server_connection_t *wsc);

typedef void (websocket_receive_t)(void *opaque, int opcode,
                                   const uint8_t *data, size_t len);

typedef void (websocket_disconnected_t)(void *opaque, int error);

void websocket_route_add(const char *path,
                         websocket_connected_t *connected,
                         websocket_receive_t *receive,
                         websocket_disconnected_t *error);

void websocket_send(ws_server_connection_t *wss, int opcode,
                    const void *data, size_t len);

void websocket_sendq(ws_server_connection_t *wss,
                     int opcode, htsbuf_queue_t *hq);

void websocket_send_json(ws_server_connection_t *wss, htsmsg_t *msg);

htsmsg_t *websocket_http_session(ws_server_connection_t *wsc);
