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

typedef const char *(http_client_auth_cb_t)(void *opaque, int http_status,
                                            const char *authenticate_header);


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

int http_client_request(http_client_response_t *hcr, const char *url, ...)
  __attribute__((__sentinel__(0)));

void http_client_response_free(http_client_response_t *hcr);

#define scoped_http_result(x) \
  http_client_response_t x \
  __attribute__((cleanup(http_client_response_free))) = {}

FILE *http_open_file(const char *url);

FILE *http_read_file(const char *url, void *opaque,
                     http_client_auth_cb_t *auth_cb, int flags);

int http_client_get_http_code(void *handle);

char *http_client_ntv_to_args(const struct ntv *ntv);
