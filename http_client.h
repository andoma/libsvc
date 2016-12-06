#pragma once


typedef struct http_client_response {

  char *hcr_body;
  size_t hcr_bodysize;

  struct ntv *hcr_json_result;

  struct ntv *hcr_headers;

  struct ntv *hcr_headers_listified;

  int hcr_http_status;

  const char *hcr_transport_status;

  char hcr_errbuf[32];

} http_client_response_t;

typedef const char *(http_client_auth_cb_t)(void *opaque, int http_status);


enum {
  HCR_TAG_END,
  HCR_TAG_ERRBUF,
  HCR_TAG_FLAGS,
  HCR_TAG_HEADER,
  HCR_TAG_TIMEOUT,
  HCR_TAG_PUTDATA,
  HCR_TAG_POSTDATA,
  HCR_TAG_POSTFIELDS,
  HCR_TAG_POSTNTV,
  HCR_TAG_AUTHCB,
  HCR_TAG_VERB,
};


#define HCR_DECODE_BODY_AS_JSON         0x1
#define HCR_NO_FAIL_ON_ERROR            0x2
#define HCR_NO_FOLLOW_REDIRECT          0x4
#define HCR_VERBOSE                     0x8
#define HCR_ACCEPT_GZIP                 0x10

#define HCR_ERRBUF(a, b)      HCR_TAG_ERRBUF, a, (size_t)(b)
#define HCR_FLAGS(a)          HCR_TAG_FLAGS, a
#define HCR_HEADER(a, b)      HCR_TAG_HEADER, a, b
#define HCR_TIMEOUT(a)        HCR_TAG_TIMEOUT, a
#define HCR_PUTDATA(data, len, ct)  HCR_TAG_PUTDATA, data, (size_t)(len), ct
#define HCR_POSTDATA(data, len, ct)  HCR_TAG_POSTDATA, data, (size_t)(len), ct
#define HCR_POSTFIELDS(data, len) HCR_TAG_POSTFIELDS, data, (size_t)(len)
#define HCR_POSTJSON(ntv) HCR_TAG_POSTNTV, ntv
#define HCR_AUTHCB(cb, opaque) HCR_TAG_AUTHCB, cb, opaque
#define HCR_VERB(v) HCR_TAG_VERB, v

int http_client_request(http_client_response_t *hcr, const char *url, ...)
  __attribute__((__sentinel__(0)));

void http_client_response_free(http_client_response_t *hcr);

#define scoped_http_result(x) \
  http_client_response_t x \
  __attribute__((cleanup(http_client_response_free))) = {}

FILE *http_open_file(const char *url);
