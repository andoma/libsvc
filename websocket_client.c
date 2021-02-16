#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "websocket_client.h"
#include "http_parser.h"
#include "misc.h"
#include "dial.h"
#include "atomic.h"
#include "asyncio.h"
#include "task.h"
#include "websocket.h"
#include "trace.h"

struct ws_client {

  wsc_fn_t *wsc_fn;
  void *wsc_opaque;

  char *wsc_hostname;
  char *wsc_path;
  char *wsc_auth;
  atomic_t wsc_refcount;
  int wsc_use_tls;
  int wsc_port;
  int wsc_timeout;
  int wsc_debug;
  int wsc_stopped;

  asyncio_fd_t *wsc_af;

  http_parser wsc_http_parser;

  enum {
    WSC_STATE_HTTP,
    WSC_STATE_WEBSOCKET,
    WSC_STATE_CLOSED,
  } wsc_state;

  websocket_state_t wsc_ws_parser;

  task_group_t *wsc_task_group;

  pthread_mutex_t wsc_send_mutex;

  struct mbuf wsc_holdq;

  prng_t wsc_maskgenerator;

  asyncio_timer_t wsc_ka_timer;

  int wsc_ka_misses;

};


static void
wsc_free(ws_client_t *wsc)
{
  if(wsc->wsc_af != NULL)
    asyncio_fd_release(wsc->wsc_af);

  free(wsc->wsc_hostname);
  free(wsc->wsc_path);
  free(wsc->wsc_auth);
  task_group_destroy(wsc->wsc_task_group);
  websocket_free(&wsc->wsc_ws_parser);
  mbuf_clear(&wsc->wsc_holdq);
  free(wsc);
}


static void
wsc_release(ws_client_t *wsc)
{
  if(atomic_dec(&wsc->wsc_refcount))
    return;
  wsc_free(wsc);
}






static void
wsc_send_request(ws_client_t *wsc)
{
  const char *auth = wsc->wsc_auth;

  uint8_t nonce[16];
  get_random_bytes(nonce, sizeof(nonce));
  char key[32];
  base64_encode(key, sizeof(key), nonce, sizeof(nonce));

  scoped_char *req =
    fmt("GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "%s%s%s"
        "\r\n",
        wsc->wsc_path, wsc->wsc_hostname, key,
        auth ? "Authorization: " : "",
        auth ?: "",
        auth ? "\r\n" : "");

  asyncio_send(wsc->wsc_af, req, strlen(req), 0);
}



typedef struct {
  int opcode;
  uint8_t *data;
  int len;
  ws_client_t *wsc;
} msg_t;


static void
msg_dispatch(void *arg)
{
  msg_t *m = arg;
  ws_client_t *wsc = m->wsc;
  wsc->wsc_fn(wsc->wsc_opaque, m->opcode, m->data, m->len);
  free(m->data);
  wsc_release(m->wsc);
  free(m);
}


static void
websocket_dispatch(ws_client_t *wsc, msg_t *msg, int opcode)
{
  msg->opcode = opcode;
  msg->wsc = wsc;
  atomic_inc(&wsc->wsc_refcount);
  task_run_in_group(msg_dispatch, msg, wsc->wsc_task_group);
}


static void
websocket_dispatch_close(ws_client_t *wsc, const char *str)
{
  if(wsc->wsc_state == WSC_STATE_CLOSED)
    return;

  asyncio_timer_disarm(&wsc->wsc_ka_timer);

  if(wsc->wsc_debug)
    trace(LOG_DEBUG, "%s:%d closed: %s", wsc->wsc_hostname,
          wsc->wsc_port, str);

  wsc->wsc_state = WSC_STATE_CLOSED;

  msg_t *msg = malloc(sizeof(msg_t));
  msg->data = (void *)strdup(str);
  msg->len = strlen(str);
  websocket_dispatch(wsc, msg, 0);
}


static void
websocket_send_ctrl(ws_client_t *wsc, int opcode, const void *data, int len)
{
  uint8_t hdr[WEBSOCKET_MAX_HDR_LEN];
  int hlen = websocket_build_hdr(hdr, opcode, len, 0);
  assert(hlen <= 10);
  hdr[1] |= 0x80; // Masking

  union {
    uint8_t u8[4];
    uint32_t u32;
  } mask;

  mask.u32 = prng_get(&wsc->wsc_maskgenerator);
  memcpy(hdr + hlen, mask.u8, 4);
  hlen += 4;

  const uint8_t *s = data;
  uint8_t *masked_data = malloc(len);
  for(int i = 0; i < len; i++)
    masked_data[i] = s[i] ^ mask.u8[i & 3];

  asyncio_send_with_hdr(wsc->wsc_af, hdr, hlen, masked_data, len, 0, 0);
  free(masked_data);
}



static int
websocket_packet_input(void *arg, int opcode,
                       uint8_t **data, int len, int flags)
{
  ws_client_t *wsc = arg;

  if(opcode == WS_OPCODE_PONG) {
    wsc->wsc_ka_misses = 0;
    return 0;
  }

  if(opcode == WS_OPCODE_PING) {
    websocket_send_ctrl(wsc, WS_OPCODE_PONG, *data, len);
    return 0;
  }

  assert(wsc->wsc_state == WSC_STATE_WEBSOCKET);

  msg_t *msg = malloc(sizeof(msg_t));
  msg->data = *data;
  *data = NULL; // Steal data
  msg->len = len;

  websocket_dispatch(wsc, msg, opcode);
  return 0;
}


static int
http_headers_complete(http_parser *p)
{
  ws_client_t *wsc = p->data;

  if(p->status_code == 101) {
    if(wsc->wsc_debug)
      trace(LOG_DEBUG, "%s:%d websocket connection established",
            wsc->wsc_hostname, wsc->wsc_port);

    pthread_mutex_lock(&wsc->wsc_send_mutex);
    asyncio_sendq(wsc->wsc_af, &wsc->wsc_holdq, 0, 0);
    wsc->wsc_state = WSC_STATE_WEBSOCKET;
    pthread_mutex_unlock(&wsc->wsc_send_mutex);
    return 2;
  } else {
    websocket_dispatch_close(wsc, http_status_str(p->status_code));
    return 1;
  }
  return 0;
}

static const http_parser_settings parser_settings = {
  .on_headers_complete = http_headers_complete,
};


static void
read_cb(void *arg, struct mbuf *mq)
{
  ws_client_t *wsc = arg;

  if(wsc->wsc_state == WSC_STATE_CLOSED) {
    mbuf_drop(mq, mq->mq_size);
    return;
  }

  while(wsc->wsc_state == WSC_STATE_HTTP) {
    mbuf_data_t *md = TAILQ_FIRST(&mq->mq_buffers);
    if(md == NULL)
      return;

    size_t r = http_parser_execute(&wsc->wsc_http_parser, &parser_settings,
                                   (const void *)md->md_data + md->md_data_off,
                                   md->md_data_len - md->md_data_off);
    mbuf_drop(mq, r);
    if(wsc->wsc_http_parser.http_errno) {
      websocket_dispatch_close(wsc, http_errno_name(wsc->wsc_http_parser.http_errno));
      return;
    }
  }

  if(websocket_parse(mq, websocket_packet_input, wsc, &wsc->wsc_ws_parser)) {
    websocket_dispatch_close(wsc, "Websocket protocol error");
  }
}


static void
err_cb(void *arg, int error)
{
  ws_client_t *wsc = arg;
  websocket_dispatch_close(wsc, strerror(error));
}









typedef struct {
  ws_client_t *wsc;
  int fd;
  char errbuf[128];
} dial_result_t;



static void
wsc_async_trace(void *opaque, const char *msg)
{
  ws_client_t *wsc = opaque;
  trace(LOG_DEBUG, "%s:%d %s", wsc->wsc_hostname, wsc->wsc_port, msg);
}

static void
wsc_dial_done(void *arg)
{
  dial_result_t *dr = arg;
  ws_client_t *wsc = dr->wsc;
  int fd = dr->fd;

  if(fd == -1) {
    // Dial failed
    websocket_dispatch_close(wsc, dr->errbuf);
    free(dr);
    return;
  }
  free(dr);

  if(wsc->wsc_stopped) {
    close(fd);
    wsc_release(wsc);
    return;
  }

  asyncio_sslctx_t *sslctx = asyncio_sslctx_client();

  wsc->wsc_af = asyncio_stream(fd, read_cb, err_cb, wsc,
                               ASYNCIO_FLAG_THREAD_SAFE |
                               ASYNCIO_FLAG_SSL_VERIFY_CERT |
                               ASYNCIO_FLAG_NO_DELAY,
                               sslctx, wsc->wsc_hostname,
                               "wsclient",
                               wsc->wsc_debug ? wsc_async_trace : NULL);

  wsc_send_request(wsc);

  asyncio_sslctx_free(sslctx);

  asyncio_timer_arm_delta(&wsc->wsc_ka_timer, 10 * 1000 * 1000);
}





static void
wsc_dial(void *arg)
{
  ws_client_t *wsc = arg;

  dial_result_t *dr = malloc(sizeof(dial_result_t));
  dr->wsc = wsc;
  dr->fd = dialfd(wsc->wsc_hostname, wsc->wsc_port, wsc->wsc_timeout,
                  dr->errbuf, sizeof(dr->errbuf), wsc->wsc_debug);
  asyncio_run_task(wsc_dial_done, dr);
}


static void
wsc_stop(void *arg)
{
  ws_client_t *wsc = arg;
  wsc->wsc_stopped = 1;

  asyncio_timer_disarm(&wsc->wsc_ka_timer);

  if(wsc->wsc_af != NULL)
    asyncio_close(wsc->wsc_af);
  wsc_release(wsc);
}


void
ws_client_destroy(ws_client_t *wsc)
{
  asyncio_run_task_blocking(wsc_stop, wsc);
  wsc_release(wsc);
}


void
ws_client_start(ws_client_t *wsc)
{
  atomic_inc(&wsc->wsc_refcount);
  task_run(wsc_dial, wsc);
}


int
ws_client_send(ws_client_t *wsc, int opcode,
               const void *data, size_t len)
{
  uint8_t hdr[WEBSOCKET_MAX_HDR_LEN];
  int hlen = websocket_build_hdr(hdr, opcode, len, 0);
  assert(hlen <= 10);
  hdr[1] |= 0x80; // Masking

  union {
    uint8_t u8[4];
    uint32_t u32;
  } mask;

  mask.u32 = prng_get(&wsc->wsc_maskgenerator);
  memcpy(hdr + hlen, mask.u8, 4);
  hlen += 4;

  const uint8_t *s = data;
  uint8_t *masked_data = malloc(len);
  for(int i = 0; i < len; i++)
    masked_data[i] = s[i] ^ mask.u8[i & 3];

  pthread_mutex_lock(&wsc->wsc_send_mutex);
  if(wsc->wsc_state == WSC_STATE_WEBSOCKET) {
    asyncio_send_with_hdr(wsc->wsc_af, hdr, hlen, masked_data, len, 0, 0);
  } else {
    mbuf_append(&wsc->wsc_holdq, hdr, hlen);
    mbuf_append(&wsc->wsc_holdq, masked_data, len);
  }
  pthread_mutex_unlock(&wsc->wsc_send_mutex);
  free(masked_data);
  return 0;
}


void
ws_client_send_close(ws_client_t *wsc, int code, const char *msg)
{
  size_t msglen = strlen(msg);
  uint8_t buf[2 + msglen];
  buf[0] = code >> 8;
  buf[1] = code;
  memcpy(buf + 2, msg, msglen);
  ws_client_send(wsc, WS_OPCODE_CLOSE, buf, 2 + msglen);
}



static void
wsc_timer(void *arg, int64_t now)
{
  uint32_t ping_payload = 0;
  ws_client_t *wsc = arg;
  wsc->wsc_ka_misses++;

  switch(wsc->wsc_state) {
  case WSC_STATE_HTTP:
    websocket_dispatch_close(wsc, "HTTP negotiation timed out");
    return;

  case WSC_STATE_WEBSOCKET:
    websocket_send_ctrl(wsc, WS_OPCODE_PING, &ping_payload, 4);
    if(wsc->wsc_ka_misses == 3) {
      // Connection timeout
      websocket_dispatch_close(wsc, "Connection timeout");
      return;
    }
    break;

  default:
    abort();
  }

  asyncio_timer_arm_delta(&wsc->wsc_ka_timer, 10 * 1000 * 1000);
}



static char *
get_field(const struct http_parser_url *p, const char *url,
          enum http_parser_url_fields field)
{
  if(!(p->field_set & 1 << field))
    return NULL;
  char *buf = malloc(p->field_data[field].len + 1);
  buf[p->field_data[field].len] = 0;
  return memcpy(buf, url + p->field_data[field].off, p->field_data[field].len);
}


static int
parse_url(ws_client_t *wsc, const char *url)
{
  struct http_parser_url p = {};
  http_parser_url_init(&p);
  if(http_parser_parse_url(url, strlen(url), 0, &p))
    return -1;

  scoped_char *schema = get_field(&p, url, UF_SCHEMA);
  if(schema == NULL)
    return -1;

  free(wsc->wsc_hostname);
  wsc->wsc_hostname = get_field(&p, url, UF_HOST);

  free(wsc->wsc_path);

  scoped_char *query = get_field(&p, url, UF_QUERY);
  if(query != NULL) {
    scoped_char *path = get_field(&p, url, UF_PATH);
    wsc->wsc_path = fmt("%s?%s", path, query);
  } else {
    free(wsc->wsc_path);
    wsc->wsc_path = get_field(&p, url, UF_PATH);
  }

  wsc->wsc_use_tls = !strcmp(schema, "wss");
  wsc->wsc_port = p.port ?: (wsc->wsc_use_tls ? 443 : 80);
  return 0;
}


ws_client_t *
ws_client_create(wsc_fn_t *fn, void *opaque, ...)
{
  va_list ap;
  va_start(ap, opaque);

  int tag;
  int err = 0;
  int flags;
  ws_client_t *wsc = calloc(1, sizeof(ws_client_t));
  wsc->wsc_fn = fn;
  wsc->wsc_opaque = opaque;
  wsc->wsc_task_group = task_group_create();
  wsc->wsc_timeout = 5000;
  asyncio_timer_init(&wsc->wsc_ka_timer, wsc_timer, wsc);

  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case WSC_TAG_AUTH:
      strset(&wsc->wsc_auth, va_arg(ap, const char *));
      break;
    case WSC_TAG_TIMEOUT:
      wsc->wsc_timeout = va_arg(ap, int);
      break;
    case WSC_TAG_URL:
      err = parse_url(wsc, va_arg(ap, const char *));
      break;
    case WSC_TAG_FLAGS:
      flags = va_arg(ap, int);
      if(flags & WSC_DEBUG)
        wsc->wsc_debug = 1;
      break;
    default:
      fprintf(stderr, "%s can't handle tag %d\n", __FUNCTION__, tag);
      abort();
    }
    if(err) {
      va_end(ap);
      wsc_free(wsc);
      return NULL;
    }
  }

  prng_init(&wsc->wsc_maskgenerator);
  mbuf_init(&wsc->wsc_holdq);
  http_parser_init(&wsc->wsc_http_parser, HTTP_RESPONSE);
  wsc->wsc_http_parser.data = wsc;
  atomic_set(&wsc->wsc_refcount, 1);
  va_end(ap);
  return wsc;
}

