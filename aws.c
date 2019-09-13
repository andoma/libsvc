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
#include "http_client.h"

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
aws_isodate(time_t timestamp)
{
  struct tm tm0, *tm;
  tm = gmtime_r(&timestamp, &tm0);
  return fmt("%04d%02d%02dT%02d%02d%02dZ",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
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
  scoped_char *timestamp_str = aws_isodate(timestamp);

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



char *
aws_sig4_gen_auth_header(const char *http_method,
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
  scoped_char *signature =
    aws_sig4_gen_signature(http_method, uri, query_args, headers, payload_hash,
                           timestamp, aws_key_id, aws_key_secret, service,
                           region);

  scoped_char *isodate = aws_isodate(timestamp);

  scoped_char *signed_headers = NULL;

  if(headers != NULL) {
    scoped_strvec(signed_headers_vec);
    NTV_FOREACH_TYPE(f, headers, NTV_STRING) {
      scoped_char *header = strdup(f->ntv_name);
      lowercase(header);
      strvec_insert_sorted(&signed_headers_vec, header);
    }
    signed_headers = strvec_join(&signed_headers_vec, ";");
  }

  return fmt("AWS4-HMAC-SHA256 Credential=%s/%8.8s/%s/%s/aws4_request,"
             "SignedHeaders=%s,"
             "Signature=%s",
             aws_key_id,
             isodate,
             region,
             service,
             signed_headers,
             signature);
}


char *
aws_s3_make_url(const char *method,
                const char *region,
                const char *bucket,
                const char *path,
                const char *key_id,
                const char *key_secret)
{
  if(*path == '/')
    path++;
  scoped_char *canonical_path = fmt("/%s/%s", bucket, path);
  scoped_char *host = fmt("s3-%s.amazonaws.com", region);
  time_t timestamp = time(NULL);

  scoped_char *isodate = aws_isodate(timestamp);

  scoped_char *credential = fmt("%s/%8.8s/%s/s3/aws4_request",
                                key_id, isodate, region);

  scoped_ntv_t *query_args =
    ntv_map("X-Amz-Algorithm", ntv_str("AWS4-HMAC-SHA256"),
            "X-Amz-Credential", ntv_str(credential),
            "X-Amz-Date", ntv_str(isodate),
            "X-Amz-Expires", ntv_int(86400),
            "X-Amz-SignedHeaders", ntv_str("host"),
            NULL);

  scoped_ntv_t *headers = ntv_map("host", ntv_str(host),
                                  NULL);
  time_t now = time(NULL);
  scoped_char *signature =
    aws_sig4_gen_signature(method,
                           canonical_path,
                           query_args,
                           headers,
                           "UNSIGNED-PAYLOAD",
                           now,
                           key_id,
                           key_secret,
                           "s3",
                           region);

  ntv_set(query_args, "X-Amz-Signature", signature);

  scoped_char *args = http_client_ntv_to_args(query_args);

  return fmt("https://%s%s?%s", host, canonical_path, args);
}


const char *
aws_invoked_transient_error(const ntv_t *response)
{
  const ntv_t *error = ntv_get_map(response, "error");
  if(error == NULL)
    return NULL;
  const char *type = ntv_get_str(error, "__type");
  if(type == NULL || strcmp(type, "Transient"))
    return NULL;
  return ntv_get_str(error, "Message") ?: "Unspecified Transient Error";
}

const char *
aws_invoked_error(const ntv_t *response)
{
  const ntv_t *error = ntv_get_map(response, "error");
  if(error == NULL)
    return NULL;
  return ntv_get_str(error, "Message") ?: "Unspecified Error";
}

const ntv_t *
aws_invoked_result(const ntv_t *response)
{
  return ntv_get_map(response, "result");
}


ntv_t *
aws_invoke(const char *region,
           const char *service,
           const char *target,
           const char *aws_key_id,
           const char *aws_key_secret,
           const char *security_token,
           ntv_t *req)
{
  char errbuf[512];
  scoped_char *body = ntv_json_serialize_to_str(req, 0);
  ntv_release(req);
  scoped_char *bodyhash = aws_SHA256_hex(body, strlen(body));

  scoped_char *host = fmt("%s.%s.amazonaws.com", service, region);

  time_t now = time(NULL);
  scoped_char *isodate = aws_isodate(now);

  scoped_ntv_t *headers =
    ntv_map("host", ntv_str(host),
            "x-amz-target", ntv_str(target),
            "x-amz-date", ntv_str(isodate),
            "x-amz-security-token", ntv_str(security_token),
            NULL);

  scoped_char *auth_header =
    aws_sig4_gen_auth_header("POST", "/", NULL, headers, bodyhash, now,
                             aws_key_id, aws_key_secret, service, region);

  scoped_char *url = fmt("https://%s", host);

  scoped_http_result(hcr);
  if(http_client_request(&hcr, url,
                         HCR_TIMEOUT(20),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON |
                                   HCR_NO_FAIL_ON_ERROR),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_HEADER("x-amz-target", target),
                         HCR_HEADER("x-amz-date", isodate),
                         HCR_HEADER("x-amz-security-token", security_token),
                         HCR_HEADER("x-amz-content-sha256", bodyhash),
                         HCR_HEADER("authorization", auth_header),
                         HCR_POSTDATA(body, strlen(body),
                                     "application/x-amz-json-1.1"),
                         NULL)) {
    return ntv_map("error", ntv_map("__type", ntv_str("Transient"),
                                    "Message", ntv_str(errbuf),
                                    NULL),
                   NULL);
  }

  if(hcr.hcr_json_result != NULL) {

    ntv_t *result = hcr.hcr_json_result;
    hcr.hcr_json_result = NULL;

    if(hcr.hcr_http_status >= 500) {
      ntv_set(result, "__type", "Transient");
    }

    if(hcr.hcr_http_status >= 400) {
      return ntv_map("error", result,
                     NULL);
    }
    return ntv_map("result", result,
                   NULL);
  }

  return ntv_map("error", ntv_map("__type", hcr.hcr_http_status >= 500 ?
                                  ntv_str("Transient") : NULL,
                                  "Message", ntv_str(hcr.hcr_body),
                                  NULL),
                 NULL);
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
