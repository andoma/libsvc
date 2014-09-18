#pragma once

#include "tcp.h"

typedef struct ws_client ws_client_t;

extern ws_client_t *ws_client_connect(const char *hostname, int port,
                                      const char *path,
                                      const tcp_ssl_info_t *tsi,
                                      void (*input)(void *aux, int opcode,
                                                    const void *buf, size_t len),
                                      void *aux, int timeout,
                                      char *errbuf, size_t errlen);

extern void ws_client_send(ws_client_t *wsc, int opcode,
                           const void *data, size_t len);


extern void ws_client_start(ws_client_t *wsc);

extern void ws_client_close(ws_client_t *wsc);
