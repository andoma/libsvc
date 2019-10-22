#pragma once

struct ntv;


typedef struct {
  const char *id;
  const char *secret;
  const char *token;
} aws_creds_t;

aws_creds_t aws_get_creds(void);

aws_creds_t aws_get_creds_or_fail(void);

char *aws_sig4_canonical_request_hash(const char *http_method,
                                      const char *canonical_uri,
                                      const struct ntv *query_args,
                                      const struct ntv *headers,
                                      const char *hashed_payload);

char *aws_sig4_gen_signature(const char *http_method,
                             const char *uri,
                             const ntv_t *query_args,
                             const ntv_t *headers,
                             const char *payload_hash,
                             time_t timestamp,
                             aws_creds_t creds,
                             const char *service,
                             const char *region);

char *aws_sig4_gen_auth_header(const char *http_method,
                               const char *uri,
                               const ntv_t *query_args,
                               const ntv_t *headers,
                               const char *payload_hash,
                               time_t timestamp,
                               aws_creds_t creds,
                               const char *service,
                               const char *region);

char *aws_SHA256_hex(const void *data, size_t len);

char *aws_isodate(time_t timestamp);


char *aws_s3_make_url(const char *method,
                      const char *region,
                      const char *bucket,
                      const char *path,
                      aws_creds_t creds);

struct ntv *aws_invoke(const char *region,
                       const char *service,
                       const char *target,
                       aws_creds_t creds,
                       struct ntv *req);

const char *aws_invoked_transient_error(const ntv_t *response);

const char *aws_invoked_error(const ntv_t *response);

const ntv_t *aws_invoked_result(const ntv_t *response);

void aws_test(void);
