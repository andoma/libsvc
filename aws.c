#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "ntv.h"
#include "misc.h"
#include "strvec.h"
#include "dbl.h"

#include "aws.h"

/*
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 */


static char *
ntv_to_escaped_str(const ntv_t *f)
{
  char dblbuf[32];
  switch(f->ntv_type) {
  case NTV_STRING:
    return url_escape_alloc(f->ntv_string, URL_ESCAPE_PARAM);
  case NTV_DOUBLE:
    my_double2str(dblbuf, sizeof(dblbuf), f->ntv_double, -1);
    return strdup(dblbuf);
  case NTV_INT:
    return fmt("%"PRId64, f->ntv_s64);
  default:
    return strdup("");
  }
}


static char *
ntv_to_canonical_query_args(const ntv_t *ntv)
{
  if(ntv == NULL)
    return strdup("");

  scoped_strvec(args);
  NTV_FOREACH(f, ntv) {
    scoped_char *val = ntv_to_escaped_str(f);
    scoped_char *key = url_escape_alloc(f->ntv_name, URL_ESCAPE_PARAM);
    scoped_char *kv = fmt("%s=%s", key, val);
    strvec_insert_sorted(&args, kv);
  }
  return strvec_join(&args, "&");
}



static void
lowercase(char *s)
{
  while(*s) {
    if(*s >= 'A' && *s <= 'Z')
      *s += 32;
    s++;
  }
}


char *
aws_SHA256_hex(const void *data, size_t len)
{
  uint8_t crdigest[32];
  SHA256((void *)data, len, crdigest);
  char crhex[65];
  bin2hex(crhex, sizeof(crhex), crdigest, sizeof(crdigest));
  return strdup(crhex);
}


char *
aws_sig4_canonical_request_hash(const char *http_method,
                                const char *uri,
                                const ntv_t *query_args,
                                const ntv_t *headers,
                                const char *payload_hash)
{
  scoped_char *canonical_uri =
    url_escape_alloc(uri, URL_ESCAPE_PATH);

  scoped_char *canonical_query_string =
    ntv_to_canonical_query_args(query_args);

  scoped_char *canonical_headers = NULL;
  scoped_char *signed_headers = NULL;

  if(headers != NULL) {
    scoped_strvec(canonical_headers_vec);
    scoped_strvec(signed_headers_vec);
    NTV_FOREACH_TYPE(f, headers, NTV_STRING) {
      scoped_char *header = strdup(f->ntv_name);
      lowercase(header);
      strvec_insert_sorted(&signed_headers_vec, header);
      scoped_char *ch = fmt("%s:%s\n", header, f->ntv_string);
      strvec_insert_sorted(&canonical_headers_vec, ch);
    }
    canonical_headers = strvec_join(&canonical_headers_vec, "");
    signed_headers = strvec_join(&signed_headers_vec, ";");
  }

  scoped_char *canonical_request =
    fmt("%s\n"
        "%s\n"
        "%s\n"
        "%s\n"
        "%s\n"
        "%s",
        http_method,
        canonical_uri,
        canonical_query_string,
        canonical_headers ?: "",
        signed_headers ?: "",
        payload_hash);

  return aws_SHA256_hex(canonical_request, strlen(canonical_request));
}


char *
aws_sig4_gen_signature(const char *http_method,
                       const char *uri,
                       const ntv_t *query_args,
                       const ntv_t *headers,
                       const char *payload_hash,
                       time_t timestamp,
                       const char *aws_key_id,
                       const char *aws_key_secret,
                       const char *service,
                       const char *region)
{
  struct tm tm0, *tm;
  tm = gmtime_r(&timestamp, &tm0);
  char timestamp_str[32];
  snprintf(timestamp_str, sizeof(timestamp_str),
           "%04d%02d%02dT%02d%02d%02dZ",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec);

  scoped_char *crhex =
    aws_sig4_canonical_request_hash(http_method, uri, query_args,
                                    headers, payload_hash);
  uint8_t key[32];

  scoped_char *string_to_sign =
    fmt("AWS4-HMAC-SHA256\n"
        "%s\n"
        "%8.8s/%s/%s/aws4_request\n"
        "%s",
        timestamp_str,
        timestamp_str,
        region,
        service,
        crhex);

  char tmp[128];
  snprintf(tmp, sizeof(tmp), "AWS4%s", aws_key_secret);
  HMAC(EVP_sha256(), tmp, strlen(tmp), (void *)timestamp_str, 8, key, NULL);
  HMAC(EVP_sha256(), key, 32, (void *)region, strlen(region), key, NULL);
  HMAC(EVP_sha256(), key, 32, (void *)service, strlen(service), key, NULL);
  HMAC(EVP_sha256(), key, 32, (void *)"aws4_request", 12, key, NULL);

  HMAC(EVP_sha256(), key, 32, (void *)string_to_sign, strlen(string_to_sign),
       key, NULL);

  char *result = malloc(65);
  bin2hex(result, 65, key, 32);
  return result;
}



void
aws_test(void)
{
  const char *key_id = "AKIAIOSFODNN7EXAMPLE"; // Test from documentation article
  const char *secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const time_t t = 1369353600; // 20130524T000000Z
  const char *region = "us-east-1";

  if(1) {
    const char *content_hash =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    scoped_ntv_t *headers =
      ntv_map("x-amz-date", ntv_str("20130524T000000Z"),
              "host", ntv_str("examplebucket.s3.amazonaws.com"),
              "Range", ntv_str("bytes=0-9"),
              "x-amz-content-sha256", ntv_str(content_hash),
              NULL);

    scoped_char *hash =
      aws_sig4_canonical_request_hash("GET",
                                      "/test.txt",
                                      NULL,
                                      headers,
                                      content_hash);

    assert(!strcmp(hash, "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"));


    scoped_char *signature =
      aws_sig4_gen_signature("GET",
                             "/test.txt",
                             NULL,
                             headers,
                             content_hash,
                             t,
                             key_id,
                             secret,
                             "s3",
                             region);

    assert(!strcmp(signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"));

  }

  if(1) {
    const char *content_hash =
      "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
    scoped_ntv_t *headers =
      ntv_map("x-amz-date", ntv_str("20130524T000000Z"),
              "Date", ntv_str("Fri, 24 May 2013 00:00:00 GMT"),
              "x-amz-storage-class", ntv_str("REDUCED_REDUNDANCY"),
              "host", ntv_str("examplebucket.s3.amazonaws.com"),
              "x-amz-content-sha256", ntv_str(content_hash),
              NULL);

    scoped_char *hash =
      aws_sig4_canonical_request_hash("PUT",
                                      "/test$file.text",
                                      NULL,
                                      headers,
                                      content_hash);

    assert(!strcmp(hash, "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"));
  }

  if(1) {
    scoped_char *content_hash = aws_SHA256_hex("", 0);

    scoped_ntv_t *headers =
      ntv_map("x-amz-date", ntv_str("20130524T000000Z"),
              "host", ntv_str("examplebucket.s3.amazonaws.com"),
              "x-amz-content-sha256", ntv_str(content_hash),
              NULL);

    scoped_ntv_t *query_args =
      ntv_map("lifecycle", ntv_boolean(true),
              NULL);

    scoped_char *hash =
      aws_sig4_canonical_request_hash("GET",
                                      "/",
                                      query_args,
                                      headers,
                                      content_hash);
    assert(!strcmp(hash, "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca"));
  }

  if(1) {
    scoped_char *content_hash = aws_SHA256_hex("", 0);

    scoped_ntv_t *headers =
      ntv_map("x-amz-date", ntv_str("20130524T000000Z"),
              "host", ntv_str("examplebucket.s3.amazonaws.com"),
              "x-amz-content-sha256", ntv_str(content_hash),
              NULL);

    scoped_ntv_t *query_args =
      ntv_map("prefix", ntv_str("J"),
              "max-keys", ntv_int(2),
              NULL);

    scoped_char *hash =
      aws_sig4_canonical_request_hash("GET",
                                      "/",
                                      query_args,
                                      headers,
                                      content_hash);
    assert(!strcmp(hash, "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7"));
  }

}
