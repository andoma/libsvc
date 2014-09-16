#pragma once

typedef struct ws_client ws_client_t;

extern ws_client_t *ws_client_connect(const char *hostname, int port,
                                      const char *path, int ssl,
                                      void (*input)(void *aux, int opcode,
                                                    const void *buf, size_t len),
                                      void *aux);

extern void ws_client_send(ws_client_t *wsc, int opcode,
                           const void *data, size_t len);

extern void ws_client_close(ws_client_t *wsc);
