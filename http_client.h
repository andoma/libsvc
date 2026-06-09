#pragma once

#include <stdio.h>

struct ntv;

typedef struct http_client_response {

  char *hcr_body;
  size_t hcr_bodysize;

  struct ntv *hcr_json_result;

  struct ntv *hcr_headers;

  struct ntv *hcr_headers_listified;

  int hcr_http_status;

  int hcr_malformed_json;

  int hcr_local_error;

  const char *hcr_transport_status;

  char hcr_errbuf[32];

  char *hcr_primary_ip;

} http_client_response_t;

typedef char *(http_client_auth_cb_t)(void *opaque, int http_status,
                                     const char *authenticate_header);

// Connection/transfer phases reported through HCR_PHASE_CB. The first three
// values match dial.h's CONN_PHASE_* so the stream-layer callback forwards
// without translation. Only the builtin HTTP backend reports phases; the
// curl backend ignores the callback.
typedef enum {
  HTTP_PHASE_RESOLVING  = 0, // DNS lookup
  HTTP_PHASE_CONNECTING = 1, // TCP connect
  HTTP_PHASE_TLS        = 2, // TLS handshake
  HTTP_PHASE_REQUEST    = 3, // request sent, awaiting response headers
  HTTP_PHASE_STREAMING  = 4, // response body flowing
} http_phase_t;

typedef void (http_phase_cb_t)(void *opaque, http_phase_t phase);

// Polled periodically during connect/transfer. Return nonzero to abort the
// request promptly.
typedef int (http_abort_cb_t)(void *opaque);


enum {
  HCR_TAG_END,
  HCR_TAG_ERRBUF,
  HCR_TAG_ERR,
  HCR_TAG_FLAGS,
  HCR_TAG_HEADER,
  HCR_TAG_TIMEOUT,
  HCR_TAG_PUTDATA,
  HCR_TAG_POSTDATA,
  HCR_TAG_POSTFIELDS,
  HCR_TAG_POSTJSON,
  HCR_TAG_POSTARGS,
  HCR_TAG_AUTHCB,
  HCR_TAG_VERB,
  HCR_TAG_USERNPASS,
  HCR_TAG_OUTPUTFILE,
  HCR_TAG_POSTFILE,
  HCR_TAG_MULTIPARTFILE,
  HCR_TAG_MIN_SPEED,
  HCR_TAG_HTTP_PROXY,
  HCR_TAG_PHASE_CB,
  HCR_TAG_ABORT_CB,
};


#define HCR_DECODE_BODY_AS_JSON         0x1
#define HCR_NO_FAIL_ON_ERROR            0x2
#define HCR_NO_FOLLOW_REDIRECT          0x4
#define HCR_VERBOSE                     0x8
#define HCR_ACCEPT_GZIP                 0x10
#define HCR_READ_FILE_LOG_ERRORS        0x20

#define HCR_ERRBUF(a, b)      HCR_TAG_ERRBUF, a, (size_t)(b)
#define HCR_ERR(a)            HCR_TAG_ERR, a
#define HCR_FLAGS(a)          HCR_TAG_FLAGS, a
#define HCR_HEADER(a, b)      HCR_TAG_HEADER, a, b
#define HCR_TIMEOUT(a)        HCR_TAG_TIMEOUT, a
#define HCR_PUTDATA(data, len, ct)  HCR_TAG_PUTDATA, data, (size_t)(len), ct
#define HCR_POSTDATA(data, len, ct)  HCR_TAG_POSTDATA, data, (size_t)(len), ct
#define HCR_POSTFIELDS(data, len) HCR_TAG_POSTFIELDS, data, (size_t)(len)
#define HCR_POSTJSON(ntv) HCR_TAG_POSTJSON, ntv
#define HCR_POSTARGS(ntv) HCR_TAG_POSTARGS, ntv
#define HCR_POSTFILE(file, ct)  HCR_TAG_POSTFILE, file, ct
#define HCR_AUTHCB(cb, opaque) HCR_TAG_AUTHCB, cb, opaque
#define HCR_VERB(v) HCR_TAG_VERB, v
#define HCR_USERNPASS(a, b) HCR_TAG_USERNPASS, a, b
#define HCR_OUTPUTFILE(a) HCR_TAG_OUTPUTFILE, a
#define HCR_MULTIPARTFILE(a,b,c) HCR_TAG_MULTIPARTFILE, a, b, c
#define HCR_MIN_SPEED(a) HCR_TAG_MIN_SPEED, a
#define HCR_HTTP_PROXY(a) HCR_TAG_HTTP_PROXY, a
#define HCR_PHASE_CB(cb, opaque) HCR_TAG_PHASE_CB, cb, opaque
#define HCR_ABORT_CB(cb, opaque) HCR_TAG_ABORT_CB, cb, opaque

int http_client_request(http_client_response_t *hcr, const char *url, ...)
  __attribute__((__sentinel__(0)));

void http_client_response_free(http_client_response_t *hcr);

#define scoped_http_result(x) \
  http_client_response_t x \
  __attribute__((cleanup(http_client_response_free))) = {}

FILE *http_open_file(const char *url);

FILE *http_read_file(const char *url, void *opaque,
                     http_client_auth_cb_t *auth_cb, int flags);

FILE *http_read_file_va(const char *url, ...)
  __attribute__((__sentinel__(0)));


int http_client_get_http_code(void *handle);

char *http_client_ntv_to_args(const struct ntv *ntv);
