#pragma once

struct ntv;

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
                             const char *aws_key_id,
                             const char *aws_key_secret,
                             const char *service,
                             const char *region);


void aws_test(void);
