#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "websocket_client.h"
#include "http_parser.h"
#include "misc.h"
#include "atomic.h"
#include "stream.h"
#include "task.h"
#include "websocket.h"
#include "trace.h"
#include "ntv.h"

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

  stream_t *wsc_stream;
  pthread_t wsc_thread;

  http_parser wsc_http_parser;

  enum {
    WSC_STATE_HTTP,
    WSC_STATE_WEBSOCKET,
    WSC_STATE_CLOSED,
  } wsc_state;

  websocket_state_t wsc_ws_parser;

  task_group_t *wsc_task_group;

  pthread_mutex_t wsc_send_mutex;
  pthread_cond_t wsc_state_cond;

  struct mbuf wsc_holdq;

  prng_t wsc_maskgenerator;

  int wsc_ka_misses;

  char *wsc_offered_protocol;

  char *wsc_received_protocol;

  char *wsc_header_name;
  char *wsc_header_val;

  ntv_t *wsc_headers;
};


static void
wsc_free(ws_client_t *wsc)
{
  free(wsc->wsc_hostname);
  free(wsc->wsc_path);
  free(wsc->wsc_auth);
  task_group_destroy(wsc->wsc_task_group);
  websocket_free(&wsc->wsc_ws_parser);
  mbuf_clear(&wsc->wsc_holdq);
  free(wsc->wsc_offered_protocol);
  free(wsc->wsc_received_protocol);
  free(wsc->wsc_header_name);
  free(wsc->wsc_header_val);
  ntv_release(wsc->wsc_headers);
  pthread_mutex_destroy(&wsc->wsc_send_mutex);
  pthread_cond_destroy(&wsc->wsc_state_cond);
  free(wsc);
}


static void
wsc_release(ws_client_t *wsc)
{
  if(atomic_dec(&wsc->wsc_refcount))
    return;
  wsc_free(wsc);
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

  if(wsc->wsc_debug)
    trace(LOG_DEBUG, "%s:%d closed: %s", wsc->wsc_hostname,
          wsc->wsc_port, str);

  pthread_mutex_lock(&wsc->wsc_send_mutex);
  wsc->wsc_state = WSC_STATE_CLOSED;
  pthread_cond_signal(&wsc->wsc_state_cond);
  pthread_mutex_unlock(&wsc->wsc_send_mutex);

  msg_t *msg = malloc(sizeof(msg_t));
  msg->data = (void *)strdup(str);
  msg->len = strlen(str);
  websocket_dispatch(wsc, msg, 0);
}


static int
stream_write_hdr_and_data(ws_client_t *wsc, const uint8_t *hdr, int hlen,
                          const void *data, size_t len)
{
  if(stream_write(wsc->wsc_stream, hdr, hlen) < 0)
    return -1;
  if(len > 0 && stream_write(wsc->wsc_stream, data, len) < 0)
    return -1;
  return 0;
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

  stream_write_hdr_and_data(wsc, hdr, hlen, masked_data, len);
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
append(char **dst, const char *src, size_t len)
{
  size_t curlen = *dst ? strlen(*dst) : 0;
  char *x = realloc(*dst, curlen + len + 1);
  if(x == NULL)
    return -1;
  memcpy(x + curlen, src, len);
  x[curlen + len] = 0;
  *dst = x;
  return 0;
}

static void
lc_str(char *x)
{
  for(; *x; x++) {
    if(*x >= 'A' && *x <= 'Z')
      *x = *x + 32;
  }
}

static void
copy_header(ws_client_t *wsc, http_parser *p)
{
  if(wsc->wsc_header_name != NULL && wsc->wsc_header_val != NULL) {
    lc_str(wsc->wsc_header_name);
    ntv_set_str(wsc->wsc_headers, wsc->wsc_header_name, wsc->wsc_header_val);
  }

  strset(&wsc->wsc_header_name, NULL);
  strset(&wsc->wsc_header_val, NULL);
}

static int
on_header_field(http_parser *p, const char *at, size_t length)
{
  ws_client_t *wsc = p->data;
  copy_header(wsc, p);
  return append(&wsc->wsc_header_name, at, length);
}

static int
on_header_value(http_parser *p, const char *at, size_t length)
{
  ws_client_t *wsc = p->data;
  return append(&wsc->wsc_header_val, at, length);
}



static int
http_headers_complete(http_parser *p)
{
  ws_client_t *wsc = p->data;
  copy_header(wsc, p);

  const char *protocol = ntv_get_str(wsc->wsc_headers, "sec-websocket-protocol");
  if(protocol != NULL) {
    wsc->wsc_received_protocol = strdup(protocol);
    lc_str(wsc->wsc_received_protocol);
  }

  if(p->status_code == 101) {
    if(wsc->wsc_debug)
      trace(LOG_DEBUG, "%s:%d websocket connection established",
            wsc->wsc_hostname, wsc->wsc_port);
    return 0;
  } else {
    return 1;
  }
}

static const http_parser_settings parser_settings = {
  .on_header_field = on_header_field,
  .on_header_value = on_header_value,
  .on_headers_complete = http_headers_complete,
};


static void
flush_holdq(ws_client_t *wsc)
{
  mbuf_data_t *md;
  TAILQ_FOREACH(md, &wsc->wsc_holdq.mq_buffers, md_link) {
    size_t len = md->md_data_len - md->md_data_off;
    if(len > 0)
      stream_write(wsc->wsc_stream, md->md_data + md->md_data_off, len);
  }
  mbuf_clear(&wsc->wsc_holdq);
}


static void *
wsc_thread_fn(void *arg)
{
  ws_client_t *wsc = arg;
  char errbuf[256];

  // Connect
  int flags = 0;
  if(wsc->wsc_use_tls)
    flags |= STREAM_CONNECT_F_SSL;
  if(wsc->wsc_debug)
    flags |= STREAM_DEBUG;
  flags |= STREAM_CLOCK_MONOTONIC;

  stream_t *s = stream_connect(wsc->wsc_hostname, wsc->wsc_port,
                               wsc->wsc_timeout, errbuf, sizeof(errbuf),
                               flags);
  if(s == NULL) {
    websocket_dispatch_close(wsc, errbuf);
    wsc_release(wsc);
    return NULL;
  }

  wsc->wsc_stream = s;

  if(wsc->wsc_stopped) {
    stream_close(s);
    wsc->wsc_stream = NULL;
    wsc_release(wsc);
    return NULL;
  }

  // Send HTTP upgrade request
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
        "%s%s%s"
        "\r\n",
        wsc->wsc_path, wsc->wsc_hostname, key,
        wsc->wsc_offered_protocol ? "Sec-WebSocket-Protocol: " : "",
        wsc->wsc_offered_protocol ?: "",
        wsc->wsc_offered_protocol ? "\r\n" : "",
        auth ? "Authorization: " : "",
        auth ?: "",
        auth ? "\r\n" : "");

  if(stream_write(s, req, strlen(req)) < 0) {
    websocket_dispatch_close(wsc, "Failed to send HTTP upgrade request");
    stream_close(s);
    wsc->wsc_stream = NULL;
    wsc_release(wsc);
    return NULL;
  }

  // Read HTTP response
  mbuf_t readbuf = MBUF_INITIALIZER(readbuf);
  int http_done = 0;
  int http_ok = 0;

  while(!http_done && !wsc->wsc_stopped) {
    uint8_t buf[4096];

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t deadline = ts.tv_sec * (int64_t)1000000 + ts.tv_nsec / 1000
      + (int64_t)wsc->wsc_timeout * 1000;

    ssize_t n = stream_read_timeout(s, buf, sizeof(buf), 0, deadline);
    if(n <= 0) {
      if(n < 0 && errno == ETIMEDOUT)
        websocket_dispatch_close(wsc, "HTTP negotiation timed out");
      else
        websocket_dispatch_close(wsc, n == 0 ? "Connection closed during HTTP upgrade" : strerror(errno));
      mbuf_clear(&readbuf);
      stream_close(s);
      wsc->wsc_stream = NULL;
      wsc_release(wsc);
      return NULL;
    }

    size_t parsed = http_parser_execute(&wsc->wsc_http_parser, &parser_settings,
                                        (const char *)buf, n);

    if(wsc->wsc_http_parser.http_errno) {
      websocket_dispatch_close(wsc,
        http_errno_name(wsc->wsc_http_parser.http_errno));
      mbuf_clear(&readbuf);
      stream_close(s);
      wsc->wsc_stream = NULL;
      wsc_release(wsc);
      return NULL;
    }

    if(wsc->wsc_http_parser.upgrade) {
      // Headers complete, check status
      if(wsc->wsc_http_parser.status_code == 101) {
        http_ok = 1;
      } else {
        scoped_char *errmsg = fmt("HTTP upgrade failed: %s",
                                  http_status_str(wsc->wsc_http_parser.status_code));
        websocket_dispatch_close(wsc, errmsg);
        mbuf_clear(&readbuf);
        stream_close(s);
        wsc->wsc_stream = NULL;
        wsc_release(wsc);
        return NULL;
      }
      // Any remaining data after HTTP headers is websocket data
      if(parsed < (size_t)n)
        mbuf_append(&readbuf, buf + parsed, n - parsed);
      http_done = 1;
    }
  }

  if(wsc->wsc_stopped || !http_ok) {
    mbuf_clear(&readbuf);
    stream_close(s);
    wsc->wsc_stream = NULL;
    wsc_release(wsc);
    return NULL;
  }

  // Transition to websocket state - flush holdq
  pthread_mutex_lock(&wsc->wsc_send_mutex);
  flush_holdq(wsc);
  wsc->wsc_state = WSC_STATE_WEBSOCKET;
  pthread_cond_signal(&wsc->wsc_state_cond);
  pthread_mutex_unlock(&wsc->wsc_send_mutex);

  // Process any leftover data from HTTP response
  if(readbuf.mq_size > 0) {
    if(websocket_parse(&readbuf, websocket_packet_input, wsc,
                       &wsc->wsc_ws_parser)) {
      websocket_dispatch_close(wsc, "Websocket protocol error");
      mbuf_clear(&readbuf);
      stream_close(s);
      wsc->wsc_stream = NULL;
      wsc_release(wsc);
      return NULL;
    }
  }

  // Websocket read loop
  wsc->wsc_ka_misses = 0;

  while(!wsc->wsc_stopped) {
    uint8_t buf[4096];

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t deadline = ts.tv_sec * (int64_t)1000000 + ts.tv_nsec / 1000
      + 10 * 1000000LL;  // 10 second timeout

    ssize_t n = stream_read_timeout(s, buf, sizeof(buf), 0, deadline);

    if(wsc->wsc_stopped)
      break;

    if(n < 0) {
      if(errno == ETIMEDOUT) {
        // Send ping
        uint32_t ping_payload = 0;
        pthread_mutex_lock(&wsc->wsc_send_mutex);
        if(wsc->wsc_state == WSC_STATE_WEBSOCKET)
          websocket_send_ctrl(wsc, WS_OPCODE_PING, &ping_payload, 4);
        pthread_mutex_unlock(&wsc->wsc_send_mutex);

        wsc->wsc_ka_misses++;
        if(wsc->wsc_ka_misses >= 3) {
          websocket_dispatch_close(wsc, "Connection timeout");
          break;
        }
        continue;
      }
      websocket_dispatch_close(wsc, strerror(errno));
      break;
    }

    if(n == 0) {
      websocket_dispatch_close(wsc, "Connection closed");
      break;
    }

    wsc->wsc_ka_misses = 0;

    mbuf_append(&readbuf, buf, n);
    if(websocket_parse(&readbuf, websocket_packet_input, wsc,
                       &wsc->wsc_ws_parser)) {
      websocket_dispatch_close(wsc, "Websocket protocol error");
      break;
    }
  }

  mbuf_clear(&readbuf);
  stream_close(s);
  wsc->wsc_stream = NULL;
  wsc_release(wsc);
  return NULL;
}


void
ws_client_destroy(ws_client_t *wsc)
{
  wsc->wsc_stopped = 1;
  if(wsc->wsc_stream != NULL)
    stream_shutdown(wsc->wsc_stream, 1);
  pthread_join(wsc->wsc_thread, NULL);
  wsc_release(wsc);
}


void
ws_client_start(ws_client_t *wsc)
{
  atomic_inc(&wsc->wsc_refcount);
  pthread_create(&wsc->wsc_thread, NULL, wsc_thread_fn, wsc);
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
  for(size_t i = 0; i < len; i++)
    masked_data[i] = s[i] ^ mask.u8[i & 3];

  pthread_mutex_lock(&wsc->wsc_send_mutex);
  if(wsc->wsc_state == WSC_STATE_WEBSOCKET) {
    stream_write_hdr_and_data(wsc, hdr, hlen, masked_data, len);
  } else {
    mbuf_append(&wsc->wsc_holdq, hdr, hlen);
    mbuf_append(&wsc->wsc_holdq, masked_data, len);
  }
  pthread_mutex_unlock(&wsc->wsc_send_mutex);
  free(masked_data);
  return 0;
}

int
ws_client_sendq(ws_client_t *wsc, int opcode, mbuf_t *mq)
{
  uint8_t hdr[WEBSOCKET_MAX_HDR_LEN];
  size_t len = mq->mq_size;
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

  // Linearize the mbuf, mask it, and send
  uint8_t *buf = malloc(len);
  mbuf_read(mq, buf, len);
  for(size_t i = 0; i < len; i++)
    buf[i] = buf[i] ^ mask.u8[i & 3];

  pthread_mutex_lock(&wsc->wsc_send_mutex);
  if(wsc->wsc_state == WSC_STATE_WEBSOCKET) {
    stream_write_hdr_and_data(wsc, hdr, hlen, buf, len);
  } else {
    mbuf_append(&wsc->wsc_holdq, hdr, hlen);
    mbuf_append(&wsc->wsc_holdq, buf, len);
  }
  pthread_mutex_unlock(&wsc->wsc_send_mutex);
  free(buf);
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
  wsc->wsc_headers = ntv_create_map();

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
    case WSC_TAG_PROTOCOL:
      strset(&wsc->wsc_offered_protocol, va_arg(ap, const char *));
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

  pthread_mutex_init(&wsc->wsc_send_mutex, NULL);
  pthread_cond_init(&wsc->wsc_state_cond, NULL);
  return wsc;
}


const char *
ws_client_get_hostname(ws_client_t *wsc)
{
  return wsc->wsc_hostname;
}

char *
ws_client_get_protocol(ws_client_t *wsc)
{
  pthread_mutex_lock(&wsc->wsc_send_mutex);
  while(wsc->wsc_state == WSC_STATE_HTTP)
    pthread_cond_wait(&wsc->wsc_state_cond, &wsc->wsc_send_mutex);
  char *r =
    wsc->wsc_received_protocol ? strdup(wsc->wsc_received_protocol) : NULL;
  pthread_mutex_unlock(&wsc->wsc_send_mutex);
  return r;
}
