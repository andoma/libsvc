/******************************************************************************
* Copyright (C) 2013 - 2018 Andreas Smas
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
#include <stdlib.h>
#include <string.h>

#include "memstream.h"
#include "ntv.h"
#include "http_client.h"
#include "err.h"
#include "misc.h"
#include "strvec.h"
#include "http_parser.h"
#include "dial.h"
#include "trace.h"
#include "mbuf.h"






static char *
get_url_comp(const char *base, const struct http_parser_url *pu, int field)
{
  if(!(pu->field_set & (1 << field)))
     return NULL;
  const uint16_t len = pu->field_data[field].len;
  if(len == 0)
    return NULL;
  char *r = malloc_add(len, 1);
  memcpy(r, base + pu->field_data[field].off, len);
  r[len] = 0;
  return r;
}


typedef struct http_response_ctx {

  mbuf_t *response_buffer;
  FILE *response_file;

  http_client_response_t *hcr;

  int done;
  int trace;
  char *header_name;
  char *header_val;
  char *status_str;
  size_t received_body_bytes;
} http_response_ctx_t;

static void
ctxtrace(http_response_ctx_t *ctx, const char *format, ...)
{
  if(!ctx->trace)
    return;

  va_list ap;
  va_start(ap, format);
  scoped_char *msg = fmtv(format, ap);
  va_end(ap);

  trace(LOG_DEBUG, "%s", msg);
}









static void
http_response_ctx_cleanup(http_response_ctx_t *ctx)
{
  free(ctx->status_str);
  free(ctx->header_name);
  free(ctx->header_val);
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


static int
on_status(http_parser *p, const char *at, size_t length)
{
  http_response_ctx_t *ctx = p->data;
  return append(&ctx->status_str, at, length);
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
copy_header(http_response_ctx_t *ctx, http_parser *p)
{
  if(ctx->header_name != NULL && ctx->header_val != NULL) {
    lc_str(ctx->header_name);
    ctxtrace(ctx, "< %s: %s", ctx->header_name, ctx->header_val);
    ntv_set_str(ctx->hcr->hcr_headers, ctx->header_name, ctx->header_val);
  } else {
    ctxtrace(ctx, "< %d: %s", p->status_code, ctx->status_str);
  }

  strset(&ctx->header_name, NULL);
  strset(&ctx->header_val, NULL);
}

static int
on_header_field(http_parser *p, const char *at, size_t length)
{
  http_response_ctx_t *ctx = p->data;
  copy_header(ctx, p);
  return append(&ctx->header_name, at, length);
}

static int
on_header_value(http_parser *p, const char *at, size_t length)
{
  http_response_ctx_t *ctx = p->data;
  return append(&ctx->header_val, at, length);
}

static int
on_headers_complete(http_parser *p)
{
  http_response_ctx_t *ctx = p->data;
  copy_header(ctx, p);
  return 0;
}

static int
on_body(http_parser *p, const char *at, size_t length)
{
  http_response_ctx_t *ctx = p->data;

  ctx->received_body_bytes += length;

  if(ctx->response_file != NULL) {
    // We only really write to file if status is OK,
    // Otherwise we may taint it with redirect/401 bodys
    // and we may not be able to rewind the FILE
    if(p->status_code >= 200 && p->status_code <= 299) {
      if(fwrite(at, 1, length, ctx->response_file) != length)
        return 1;
    }
  } else {
    mbuf_append(ctx->response_buffer, at, length);
  }
  return 0;
}

static int
on_message_complete(http_parser *p)
{
  http_response_ctx_t *ctx = p->data;
  ctx->done = 1;
  return 0;
}

static const http_parser_settings parser_settings = {
  .on_status           = on_status,
  .on_header_field     = on_header_field,
  .on_header_value     = on_header_value,
  .on_headers_complete = on_headers_complete,
  .on_body             = on_body,
  .on_message_complete = on_message_complete,
};




static int
http_do_request(const char *url,
                char **error,
                const char *verb,
                const strvec_t *headers,
                int timeout,
                http_client_response_t *hcr,
                mbuf_t *request_buffer,
                FILE *request_file,
                mbuf_t *response_buffer,
                FILE *response_file,
                int trace)
{
  http_response_ctx_t ctx = { .hcr = hcr,
                              .response_file = response_file,
                              .response_buffer = response_buffer,
                              .trace = trace};

  extern const char *libsvc_app_version;

  char buf[65536];
  char errbuf[512];
  scoped_char *hostname = NULL;
  scoped_char *schema = NULL;

  if(timeout == 0)
    timeout = 60 * 1000;

  struct http_parser_url pu;
  http_parser_url_init(&pu);
  if(http_parser_parse_url(url, strlen(url), 0, &pu)) {
    *error = strdup("Malformed URL");
    return -1;
  }

  if((schema = get_url_comp(url, &pu, UF_SCHEMA)) == NULL) {
    *error = strdup("Malformed URL (No schema)");
    return -1;
  }

  if((hostname = get_url_comp(url, &pu, UF_HOST)) == NULL) {
    *error = strdup("Malformed URL (No host)");
    return -1;
  }

  // Path is everything from URL start of path until end of string
  const char *path;
  if(pu.field_set & (1 << UF_PATH)) {
    path = url + pu.field_data[UF_PATH].off;
  } else {
    path = "/";
  }

  int port = 0;
  tcp_stream_t *ts = NULL;
  if(!strcmp(schema, "http")) {
    port = pu.port ?: 80;
    ctxtrace(&ctx, "Connecting to %s:%d", hostname, port);
    ts = dial(hostname, port, timeout, NULL, errbuf, sizeof(errbuf));
  } else if(!strcmp(schema, "https")) {
    tcp_ssl_info_t tsi = {};
    port = pu.port ?: 443;
    ctxtrace(&ctx, "Connecting to %s:%d (TLS)", hostname, port);
    ts = dial(hostname, port, timeout, &tsi, errbuf, sizeof(errbuf));
  } else {
    *error = strdup("Unsupported URL schema");
    return -1;
  }

  if(ts == NULL) {
    *error = fmt("Unable to connect to %s:%d -- %s", hostname, port, errbuf);
    return -1;
  }

  scoped_strvec(req);
  strvec_pushf(&req, "%s %s HTTP/1.1", verb, path);
  strvec_pushf(&req, "Host: %s", hostname);
  strvec_pushf(&req, "User-Agent: %s", libsvc_app_version ?: PROGNAME);

  if(request_file != NULL) {
    strvec_push(&req, "Transfer-Encoding: chunked");
  } else if(strcmp(verb, "GET")) {
    strvec_pushf(&req, "Content-Length: %zd", request_buffer->mq_size);
  }

  for(int i = 0; i < headers->count; i++) {
    strvec_push(&req, strvec_get(headers, i));
  }

  if(ctx.trace) {
    for(int i = 0; i < req.count; i++) {
      ctxtrace(&ctx, "> %s", strvec_get(&req, i));
    }
  }

  strvec_push(&req, "");
  strvec_push(&req, "");

  scoped_char *str = strvec_join(&req, "\r\n");
  tcp_write(ts, str, strlen(str));

  // Transfer request body
  if(request_file != NULL) {
    char chunk_header[64];
    size_t total = 0;
    while(!feof(request_file)) {
      size_t bytes = fread(buf, 1, sizeof(buf), request_file);
      if(bytes == 0) {
        *error = strdup("Read failed");
        tcp_close(ts);
        return -1;
      }
      total += bytes;
      snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", bytes);
      tcp_write(ts, chunk_header, strlen(chunk_header));
      tcp_write(ts, buf, bytes);
    }
    tcp_write(ts, "0\r\n\r\n", 5);
    ctxtrace(&ctx, "Sent body %zd bytes", total);

  } else if(strcmp(verb, "GET")) {
    ctxtrace(&ctx, "Sending body %zd bytes", request_buffer->mq_size);
    tcp_write_queue(ts, request_buffer);
  }

  http_parser p;
  http_parser_init(&p, HTTP_RESPONSE);

  p.data = &ctx;
  while(!ctx.done) {
    int r = tcp_read(ts, buf, sizeof(buf));
    if(r < 0) {
      tcp_close(ts);
      http_response_ctx_cleanup(&ctx);
      *error = strdup("Read error");
      return -1;
    }
    http_parser_execute(&p, &parser_settings, buf, r);
    if(p.http_errno) {
      tcp_close(ts);
      http_response_ctx_cleanup(&ctx);
      ctxtrace(&ctx, "%s", http_errno_description(p.http_errno));
      *error = strdup(http_errno_description(p.http_errno));
      return -1;
    }
  }

  ctxtrace(&ctx, "Received body %zd bytes", ctx.received_body_bytes);

  *error = ctx.status_str;
  ctx.status_str = NULL;

  tcp_close(ts);

  http_response_ctx_cleanup(&ctx);
  return p.status_code;
}







int
http_client_request(http_client_response_t *hcr, const char *url, ...)
{
  va_list apx, ap;

  err_t **err = NULL;
  char *errbuf = NULL;
  size_t errsize = 0;
  int flags = 0;
  int timeout = 0;

  scoped_char *www_authenticate_header = NULL;
  scoped_char *location = NULL;
  int num_redirects = 0;

  http_client_auth_cb_t *auth_cb  = NULL;
  void *auth_opaque = NULL;

  FILE *response_file = NULL;
  scoped_mbuf_t response_buffer = MBUF_INITIALIZER(response_buffer);

  FILE *request_file = NULL;
  scoped_mbuf_t request_buffer = MBUF_INITIALIZER(request_buffer);

  const char *verb = "GET";
  const char *verb_override = NULL;
  int auth_retry_code = 0;
  int disable_auth = 0;

  scoped_strvec(request_headers);

  va_start(apx, url);

  memset(hcr, 0, sizeof(http_client_response_t));

 retry:

  mbuf_clear(&request_buffer);
  mbuf_clear(&response_buffer);

  strvec_reset(&request_headers);
  va_copy(ap, apx);

  hcr->hcr_headers = ntv_create_map();

  int tag;
  while((tag = va_arg(ap, int)) != 0) {
    switch(tag) {
    case HCR_TAG_ERRBUF:
      errbuf  = va_arg(ap, char *);
      errsize = va_arg(ap, size_t);
      break;

    case HCR_TAG_ERR:
      err     = va_arg(ap, err_t **);
      break;

    case HCR_TAG_AUTHCB:
      auth_cb = va_arg(ap, http_client_auth_cb_t *);
      auth_opaque = va_arg(ap, void *);
      break;

    case HCR_TAG_FLAGS:
      flags = va_arg(ap, int);
      break;

    case HCR_TAG_TIMEOUT:
      timeout = va_arg(ap, int) * 1000;
      break;

    case HCR_TAG_HEADER: {
      const char *a = va_arg(ap, const char *);
      const char *b = va_arg(ap, const char *);
      if(a != NULL && b != NULL)
        strvec_pushf(&request_headers, "%s: %s", a, b);
      break;
    }

    case HCR_TAG_PUTDATA: {
      void *data = va_arg(ap, void *);
      if(data == NULL) {
        (void)va_arg(ap, size_t);
        (void)va_arg(ap, const char *);
        break;
      }
      mbuf_append(&request_buffer, data, va_arg(ap, size_t));
      strvec_pushf(&request_headers, "Content-Type: %s",
                   va_arg(ap, const char *));
      verb = "PUT";
      break;
    }
    case HCR_TAG_POSTDATA: {
      void *data = va_arg(ap, void *);
      if(data == NULL) {
        (void)va_arg(ap, size_t);
        (void)va_arg(ap, const char *);
        break;
      }
      mbuf_append(&request_buffer, data, va_arg(ap, size_t));
      strvec_pushf(&request_headers, "Content-Type: %s",
                   va_arg(ap, const char *));
      verb = "POST";
      break;
    }

    case HCR_TAG_POSTFIELDS: {
      void *data = va_arg(ap, void *);
      size_t datalen = va_arg(ap, size_t);

      mbuf_append(&request_buffer, data, datalen);
      strvec_push(&request_headers,
                  "Content-Type: application/x-www-form-urlencoded");
      verb = "POST";
      break;
    }

    case HCR_TAG_POSTARGS: {
      const ntv_t *args = va_arg(ap, const ntv_t *);
      if(args != NULL) {
        char *str = http_client_ntv_to_args(args);
        mbuf_append_prealloc(&request_buffer, str, strlen(str));
        strvec_push(&request_headers,
                    "Content-Type: application/x-www-form-urlencoded");
        verb = "POST";
      }
      break;
    }

    case HCR_TAG_POSTJSON: {
      ntv_json_serialize(va_arg(ap, const ntv_t *), &request_buffer, 0);
      strvec_push(&request_headers, "Content-Type: application-json");
      verb = "POST";
      break;
    }

    case HCR_TAG_POSTFILE: {
      request_file = va_arg(ap, FILE *);
      if(request_file == NULL) {
        (void)va_arg(ap, const char *);
        break;
      }
      strvec_pushf(&request_headers, "Content-Type: %s",
                   va_arg(ap, const char *));
      break;
    }

    case HCR_TAG_VERB:
      verb_override = va_arg(ap, const char *);
      break;

    case HCR_TAG_USERNPASS: {
      const char *u = va_arg(ap, const char *);
      const char *p = va_arg(ap, const char *);
      scoped_char *c = fmt("%s:%s", u, p);
      scoped_char *b64 = base64_encode_a(c, strlen(c), BASE64_STANDARD);
      strvec_pushf(&request_headers, "Authorization: Basic %s", b64);
      break;
    }

    case HCR_TAG_OUTPUTFILE:
      response_file = va_arg(ap, FILE *);
      break;

    default:
      abort();
    }
  }

  va_end(ap);

  if(auth_cb && !disable_auth) {
    const char *auth = auth_cb(auth_opaque, auth_retry_code,
                               www_authenticate_header);
    if(auth)
      strvec_pushf(&request_headers, "Authorization: %s", auth);
  }

  if(flags & HCR_DECODE_BODY_AS_JSON)
    strvec_push(&request_headers, "Accept: application/json");

  scoped_char *errstr = NULL;

  const int http_status_code =
    http_do_request(url, &errstr, verb_override ?: verb,
                    &request_headers, timeout, hcr,
                    &request_buffer,  request_file,
                    &response_buffer, response_file,
                    !!(flags & HCR_VERBOSE));

  if(response_file != NULL)
    fflush(response_file);

  if(http_status_code == -1) {
    goto bad;
  }

  hcr->hcr_http_status = http_status_code;

  free(hcr->hcr_body);
  hcr->hcr_bodysize = response_buffer.mq_size;
  hcr->hcr_body = mbuf_clear_to_string(&response_buffer);

  switch(http_status_code) {
  case 300 ... 399:
    if(!(flags & HCR_NO_FOLLOW_REDIRECT)) {
      num_redirects++;
      if(num_redirects == 10) {
        strset(&errstr, "Too many redirects");
        goto bad;
      }
      strset(&location, ntv_get_str(hcr->hcr_headers, "location"));
      if(location == NULL) {
        strset(&errstr, "Redirect without location");
        goto bad;
      }

      disable_auth = 1;
      url = location;
      goto retry;
    }
    break;

  case 401:
    if(auth_cb && auth_retry_code == 0) {
      auth_retry_code = 401;
      strset(&www_authenticate_header,
             ntv_get_str(hcr->hcr_headers, "www-authenticate"));
      http_client_response_free(hcr);
      strset(&errstr, NULL);
      goto retry;
    }
    // FALLTHRU
  case 400:
  case 402 ... 999:
    if(!(flags & HCR_NO_FAIL_ON_ERROR)) {
      snprintf(errbuf, errsize, "%d %s", http_status_code, errstr);
      snprintf(hcr->hcr_errbuf, sizeof(hcr->hcr_errbuf), "%d %s",
               http_status_code, errstr);
      err_push(err, "%d %s", http_status_code, errstr);
      hcr->hcr_transport_status = hcr->hcr_errbuf;
      va_end(apx);
      return -1;
    }
  }

  if(http_status_code >= 200 && http_status_code <= 299
     && flags & HCR_DECODE_BODY_AS_JSON) {
    char e[512];
    if((hcr->hcr_json_result =
        ntv_json_deserialize(hcr->hcr_body, e, sizeof(e))) == NULL) {

      hcr->hcr_malformed_json = 1;

      err_push(err, "%s", e);

      if(errbuf != NULL)
        snprintf(errbuf, errsize, "%s", e);

      if(errbuf != NULL)
        hcr->hcr_transport_status = errbuf;
      else
        hcr->hcr_transport_status = "Bad JSON";
      va_end(apx);
      return -1;
    }
  }

  va_end(apx);
  return 0;

 bad:
  snprintf(errbuf, errsize, "%s", errstr);
  snprintf(hcr->hcr_errbuf, sizeof(hcr->hcr_errbuf), "%s", errstr);
  err_push(err, "%s", errstr);
  hcr->hcr_transport_status = hcr->hcr_errbuf;
  hcr->hcr_local_error = 1;
  va_end(apx);
  return -1;
}


int
http_client_get_http_code(void *handle)
{
  return 0;
}
