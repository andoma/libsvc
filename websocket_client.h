#pragma once

typedef struct websocket_client websocket_client_t;

extern websocket_client_t *websocket_connect(const char *hostname, int port,
                                             const char *path, int ssl,
                                             void (*input)(void *aux, int opcode,
                                                           const void *buf, size_t len),
                                             void *aux);

extern void websocket_write(websocket_client_t *wsc, int opcode, const void *data, size_t len);

extern void websocket_close(websocket_client_t *wsc);
