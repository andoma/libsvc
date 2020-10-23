#pragma once
#include "tcp.h"

typedef struct ws_client ws_client_t;






enum {
  WSC_TAG_END,
  WSC_TAG_FLAGS,
  WSC_TAG_AUTH,
  WSC_TAG_TIMEOUT,
  WSC_TAG_USERNPASS,
  WSC_TAG_URL,
  WSC_TAG_HOSTPORTPATH,
};


#define WSC_FLAGS(a)              WSC_TAG_FLAGS, a
#define WSC_AUTH(a)               WSC_TAG_AUTH, a
#define WSC_TIMEOUT(a)            WSC_TAG_TIMEOUT, a
#define WSC_USERNPASS(a, b)       WSC_TAG_USERNPASS, a, b
#define WSC_URL(a)                WSC_TAG_URL, a
#define WSC_HOSTPORTPATH(a, b, c) WSC_TAG_HOSTPORTPATH, a, (int)b, c
#define WSC_SSL(a)                WSC_TA_SSL, a


typedef void (wsc_fn_t)(void *opaque, int opcode,
                        const void *buf, size_t len);

ws_client_t *ws_client_create(wsc_fn_t *fn, void *opaque, ...)
  __attribute__((__sentinel__(0)));


int ws_client_send(ws_client_t *wsc, int opcode,
                   const void *data, size_t len);

void ws_client_send_close(ws_client_t *wsc, int code, const char *msg);

void ws_client_start(ws_client_t *wsc);

void ws_client_destroy(ws_client_t *wsc);
