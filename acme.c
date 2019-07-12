#include <unistd.h>
#include <string.h>

#include "misc.h"
#include "ntv.h"
#include "http_client.h"
#include "trace.h"
#include "memstream.h"
#include "strvec.h"
#include "acme.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>


static char *
b64(const void *data, size_t len)
{
  char *r = base64_encode_a(data, len, BASE64_URL);
  char *e = strchr(r, '=');
  if(e)
    *e = 0;
  return r;
}

static char *
b64s(const char *str)
{
  return b64(str, strlen(str));
}

static char *
b64_bn(const BIGNUM *n)
{
  const int len = BN_num_bytes(n);
  uint8_t data[len];
  BN_bn2bin(n, data);
  return b64(data, len);
}

static ntv_t *
make_jwk(RSA *rsa)
{
  const BIGNUM *bn_e, *bn_n;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
  const BIGNUM *bn_d;
  RSA_get0_key(rsa, &bn_n, &bn_e, &bn_d);
#else
  bn_e = rsa->e;
  bn_n = rsa->n;
#endif
  scoped_char *e = b64_bn(bn_e);
  scoped_char *n = b64_bn(bn_n);
  return ntv_map("e",   ntv_str(e),
                 "kty", ntv_str("RSA"),
                 "n",   ntv_str(n),
                 NULL);
}

static char *
generate_request(const char *url,
                 const ntv_t *payload,
                 const char *kid,
                 const char *nonce,
                 RSA *rsa)
{
  scoped_ntv_t *protected =
    ntv_map("alg", ntv_str("RS256"),
            "url", ntv_str(url),
            "kid", ntv_str(kid),
            "nonce", ntv_str(nonce),
            NULL);

  if(kid == NULL)
    ntv_set(protected, "jwk", make_jwk(rsa));

  scoped_char *protected_json = ntv_json_serialize_to_str(protected, 0);
  scoped_char *protected_b64  = b64s(protected_json);
  scoped_char *payload_json   = ntv_json_serialize_to_str(payload, 0);
  scoped_char *payload_b64    = b64s(payload_json);
  scoped_char *tosign         = fmt("%s.%s", protected_b64, payload_b64);

  uint8_t digest[32];
  SHA256((void *)tosign, strlen(tosign), digest);

  unsigned int sig_len = RSA_size(rsa);
  unsigned char sig[sig_len];

  int ret = RSA_sign(NID_sha256, digest, sizeof(digest), sig, &sig_len, rsa);
  if(!ret)
    return NULL;
  scoped_char *signature_b64 = b64(sig, sig_len);
  scoped_ntv_t *body = ntv_map("protected", ntv_str(protected_b64),
                               "payload",   ntv_str(payload_b64),
                               "signature", ntv_str(signature_b64),
                               NULL);
  return ntv_json_serialize_to_str(body, 0);
}


static char *
get_nonce(http_client_response_t *hcr)
{
  const char *nonce = ntv_get_str(hcr->hcr_headers, "replay-nonce");
  return nonce ? strdup(nonce) : NULL;
}


static char *
new_nonce(const ntv_t *directory)
{
  const char *url = ntv_get_str(directory, "newNonce");
  if(url == NULL)
    return NULL;

  scoped_http_result(hcr);
  http_client_request(&hcr, url, NULL);
  return get_nonce(&hcr);
}


static int
acme_POST(http_client_response_t *hcr, const char *url,
          ntv_t *payload, const char *kid, char **nonce, RSA *rsa)
{
  scoped_char *req = generate_request(url, payload, kid, *nonce, rsa);
  ntv_release(payload);
  char errbuf[512];

  if(http_client_request(hcr, url,
                         HCR_POSTDATA(req, strlen(req),
                                      "application/jose+json"),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON | HCR_ACCEPT_GZIP),
                         NULL)) {
    trace(LOG_WARNING, "ACME: POST failed %s %s %s",
          url, errbuf, hcr->hcr_body);
    return -1;
  }

  strset(nonce, NULL);
  *nonce = get_nonce(hcr);
  return 0;
}


static char *
make_CSR(const strvec_t *domains, RSA *rsa)
{
  X509_REQ *x509_req = X509_REQ_new();
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, rsa);
  X509_REQ_set_pubkey(x509_req, pkey);

  const char *cn = strvec_get(domains, 0);

  X509_NAME *name = X509_REQ_get_subject_name(x509_req);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (unsigned char *)cn, -1, -1, 0);

  if(domains->count > 1) {
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    for(int i = 1; i < domains->count; i++) {
      scoped_char *dns_alt = fmt("DNS:%s", strvec_get(domains, i));

      X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL,
                                                NID_subject_alt_name,
                                                dns_alt);
      sk_X509_EXTENSION_push(exts, ext);
    }

    X509_REQ_add_extensions(x509_req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  }

  X509_REQ_sign(x509_req, pkey, EVP_sha256());
  EVP_PKEY_free(pkey);

  //  X509_REQ_print_fp(stdout, x509_req);

  size_t buflen = 0;
  scoped_char *buf = NULL;
  FILE *fp = open_buffer(&buf, &buflen);
  i2d_X509_REQ_fp(fp, x509_req);
  X509_REQ_free(x509_req);
  fclose(fp);
  return b64(buf, buflen);
}

static int
acme_process_auth(const acme_callbacks_t *callbacks, void *opaque,
                  const char *auth_url, const char *kid, char **nonce, RSA *rsa)
{
  char errbuf[512];
  scoped_http_result(auth_get);
  if(http_client_request(&auth_get, auth_url,
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON | HCR_ACCEPT_GZIP),
                         NULL)) {
    trace(LOG_WARNING, "ACME: GET failed %s %s", auth_url, errbuf);
    return -1;
  }

  const ntv_t *identifier =
    ntv_get_map(auth_get.hcr_json_result, "identifier");

  const char *type = ntv_get_str(identifier, "type");
  const char *domainname = ntv_get_str(identifier, "value");
  if(type == NULL || domainname == NULL )
    return -1;
  if(strcmp(type, "dns"))
    return -1;

  const ntv_t *challenges =
    ntv_get_list(auth_get.hcr_json_result, "challenges");

  trace(LOG_DEBUG, "ACME: Processing %s auth for %s", type, domainname);

  NTV_FOREACH_TYPE(c, challenges, NTV_MAP) {
    const char *type = ntv_get_str(c, "type");
    const char *token  = ntv_get_str(c, "token");
    const char *url    = ntv_get_str(c, "url");
    const char *status = ntv_get_str(c, "status");

    if(type == NULL || token == NULL || url == NULL || status == NULL)
      continue;

    unsigned char digest[32];
    scoped_ntv_t *jwk = make_jwk(rsa);
    scoped_char *jwk_json = ntv_json_serialize_to_str(jwk, 0);
    SHA256((void *)jwk_json, strlen(jwk_json), digest);
    scoped_char *digest_b64 = b64(digest, sizeof(digest));
    scoped_char *key_auth = fmt("%s.%s", token, digest_b64);


    if(callbacks->present_http_01 != NULL && !strcmp(type, "http-01")) {

      if(callbacks->present_http_01(opaque, domainname, token, key_auth))
        continue;

    } else if(callbacks->present_dns_01 != NULL && !strcmp(type, "dns-01")) {

      SHA256((void *)key_auth, strlen(key_auth), digest);
      scoped_char *proof = b64(digest, sizeof(digest));

      if(callbacks->present_dns_01(opaque, domainname, proof))
        continue;

    } else {
      continue;
    }

    scoped_http_result(proof_req);
    if(acme_POST(&proof_req, url, ntv_create_map(), kid, nonce, rsa)) {
      return -1;
    }


    while(1) {
      scoped_http_result(auth_check);
      if(http_client_request(&auth_check, auth_url,
                             HCR_ERRBUF(errbuf, sizeof(errbuf)),
                             HCR_FLAGS(HCR_DECODE_BODY_AS_JSON |
                                       HCR_ACCEPT_GZIP),
                             NULL)) {
        return -1;
      }

      const char *status = ntv_get_str(auth_check.hcr_json_result, "status");
      if(status == NULL)
        return -1;

      if(!strcmp(status, "valid"))
        return 0;
      if(!strcmp(status, "pending")) {
        sleep(1);
        continue;
      }
      return -1;
    }
  }
  return -1;
}

static char *
rsa_to_pem(RSA *rsa)
{
  char *out = NULL;
  size_t outlen = 0;
  FILE *fp = open_buffer(&out, &outlen);
  PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
  fwrite("", 1, 1, fp); // Write one extra byte to null terminate
  fclose(fp);
  return out;
}



static RSA *
rsa_from_private_pem(const char *pem)
{
  if(pem == NULL)
    return NULL;

  size_t pemlen = strlen(pem);
  BIO *bio = BIO_new_mem_buf((void *)pem, pemlen);
  RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return rsa;
}

static X509 *
x509_from_pem(const char *pem)
{
  if(pem == NULL)
    return NULL;

  size_t pemlen = strlen(pem);
  BIO *bio = BIO_new_mem_buf((void *)pem, pemlen);
  X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return x509;
}

static int
validate_cert(X509 *x509, RSA *rsa)
{
  if(x509 == NULL || rsa == NULL)
    return 0;
  int r = 0;
  ASN1_TIME *notAfter = X509_get_notAfter(x509);
  if(notAfter != NULL) {

    int day, sec;
    if(ASN1_TIME_diff(&day, &sec, NULL, notAfter)) {

      EVP_PKEY *pkey = EVP_PKEY_new();
      EVP_PKEY_set1_RSA(pkey, rsa);

      if(X509_check_private_key(x509, pkey) == 1) {
        r = day;
      }
      EVP_PKEY_free(pkey);
    }
  }
  return r;
}


static int
acme_request_finalize(const strvec_t *domains, const ntv_t *order,
                      const char *csr, const char *kid, char **nonce,
                      RSA *acme_key, RSA *cert_key,
                      ntv_t *storage)
{
  scoped_http_result(finalize);
  if(acme_POST(&finalize, ntv_get_str(order, "finalize"),
               ntv_map("csr", ntv_str(csr), NULL),
               kid, nonce, acme_key)) {
    return -1;
  }

  const char *cert_url = ntv_get_str(finalize.hcr_json_result, "certificate");
  if(cert_url == NULL) {
    return -1;
  }

  for(int i = 0; i < 10; i++) {
    char errbuf[512];
    scoped_http_result(cert_req);
    if(!http_client_request(&cert_req, cert_url,
                            HCR_ERRBUF(errbuf, sizeof(errbuf)),
                            HCR_FLAGS(HCR_ACCEPT_GZIP),
                            NULL)) {

      X509 *x509 = x509_from_pem(cert_req.hcr_body);
      if(x509 == NULL)
        return -1;

      int days = validate_cert(x509, cert_key);
      X509_free(x509);

      if(days < 1)
        return -1;

      scoped_char *pkey_pem = rsa_to_pem(cert_key);
      ntv_set(storage, "pkey", pkey_pem);
      ntv_set(storage, "cert", cert_req.hcr_body);

      scoped_char *joined_domains = strvec_join(domains, ",");
      trace(LOG_NOTICE, "ACME: New cert for %s expires in %d days",
            joined_domains, days);
      return 0;
    }

    trace(LOG_WARNING, "ACME: Unable to download cert from %s -- %s",
          cert_url, errbuf);
    sleep(i);
  }
  return -1;
}



static int
acme_request_cert_with_key(const acme_callbacks_t *callbacks, void *opaque,
                           const strvec_t *domains,
                           const char *contact, RSA *acme_key,
                           const char *directory_url,
                           ntv_t *storage, int keysize)
{
  char errbuf[512];
  scoped_http_result(dir_result);
  if(http_client_request(&dir_result, directory_url,
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON | HCR_ACCEPT_GZIP),
                         NULL)) {
    return -1;
  }

  const ntv_t *directory = dir_result.hcr_json_result;
  scoped_char *nonce = new_nonce(directory);
  scoped_http_result(new_account);
  if(acme_POST(&new_account, ntv_get_str(directory, "newAccount"),
               ntv_map("termsOfServiceAgreed", ntv_boolean(true),
                       "contact", ntv_list(ntv_str(contact), NULL),
                       NULL),
               NULL, &nonce, acme_key)) {
    return -1;
  }

  const char *kid = ntv_get_str(new_account.hcr_headers, "location");
  if(kid == NULL) {
    return -1;
  }

  ntv_t *identifiers = ntv_create_list();

  for(int i = 0; i < domains->count; i++) {
    ntv_set(identifiers, NULL,
            ntv_map("type", ntv_str("dns"),
                    "value", ntv_str(strvec_get(domains, i)),
                    NULL));
  }

  scoped_http_result(new_order);
  if(acme_POST(&new_order, ntv_get_str(directory, "newOrder"),
               ntv_map("identifiers", identifiers,
                       NULL),
               kid, &nonce, acme_key)) {
    return -1;
  }

  const ntv_t *authorizations = ntv_get_list(new_order.hcr_json_result,
                                             "authorizations");

  NTV_FOREACH_TYPE(f, authorizations, NTV_STRING) {
    if(acme_process_auth(callbacks, opaque, f->ntv_string,
                         kid, &nonce, acme_key)) {
      return -1;
    }
  }

  RSA *cert_key = RSA_generate_key(keysize, RSA_F4, NULL, NULL);
  scoped_char *csr = make_CSR(domains, cert_key);

  int r = acme_request_finalize(domains, new_order.hcr_json_result, csr,
                                kid, &nonce, acme_key, cert_key,
                                storage);
  RSA_free(cert_key);
  return r;
}


static int
acme_request_cert(const acme_callbacks_t *callbacks, void *opaque,
                  const strvec_t *domains, const char *contact,
                  const char *directory_url,
                  ntv_t *storage, int keysize)
{
  scoped_char *acme_pem = callbacks->account_key_get(opaque);
  RSA *acme_key = rsa_from_private_pem(acme_pem);

  scoped_char *new_account_pem = NULL;
  if(acme_key == NULL) {
    trace(LOG_INFO, "ACME: Generating new account private key");
    acme_key = RSA_generate_key(4096, RSA_F4, NULL, NULL);
    new_account_pem = rsa_to_pem(acme_key);
  }

  if(callbacks->account_key_set(opaque, new_account_pem)) {
    RSA_free(acme_key);
    return -1;
  }

  int r = acme_request_cert_with_key(callbacks, opaque, domains, contact,
                                     acme_key, directory_url, storage,
                                     keysize);
  RSA_free(acme_key);
  return r;
}



static int
is_cert_valid(const ntv_t *mc)
{
  X509 *x509 = x509_from_pem(ntv_get_str(mc, "cert"));
  RSA *rsa = rsa_from_private_pem(ntv_get_str(mc, "pkey"));
  const int r = validate_cert(x509, rsa);

  if(x509 != NULL)
    X509_free(x509);

  if(rsa != NULL)
    RSA_free(rsa);

  return r;
}



static int
verify_params(const ntv_t *cert,
              const strvec_t *domains, const char *contact,
              const char *directory_url)
{
  const char *c = ntv_get_str(cert, "contact");
  if(c == NULL || strcmp(c, contact))
    return 0;

  const char *d = ntv_get_str(cert, "directory_url");
  if(d == NULL || strcmp(d, directory_url))
    return 0;

  const ntv_t *dom = ntv_get_list(cert, "domains");
  if(domains->count != ntv_num_children(dom))
    return 0;

  for(int i = 0; i < domains->count; i++) {
    if(strcmp(strvec_get(domains, i), ntv_get_str(dom, NTV_INDEX(i)) ?: ""))
      return 0;
  }
  return 1;
}


static void
set_params(ntv_t *c,
           const strvec_t *domains, const char *contact,
           const char *directory_url)
{
  ntv_set(c, "contact", contact);
  ntv_set(c, "directory_url", directory_url);

  ntv_t *list = ntv_create_list();
  for(int i = 0; i < domains->count; i++) {
    ntv_set(list, NULL, strvec_get(domains, i));
  }

  ntv_set(c, "domains", list);
}




ntv_t *
acme_acquire_cert(const acme_callbacks_t *callbacks, void *opaque,
                  const strvec_t *domains, const char *contact,
                  const char *directory_url, int keysize)
{
  scoped_char *loaded_json = callbacks->load_cert(opaque);
  ntv_t *cert = loaded_json ? ntv_json_deserialize(loaded_json, NULL, 0) : NULL;

  if(cert != NULL  && !verify_params(cert, domains, contact, directory_url)) {
    ntv_release(cert);
    cert = NULL;
  }

  if(cert == NULL) {
    cert = ntv_create_map();
    set_params(cert, domains, contact, directory_url);
  }

  if(is_cert_valid(cert) >= 30)
    return cert;

  const time_t now = time(NULL);

  const time_t prev_attempt = ntv_get_int(cert, "attempt", 0);

  if(prev_attempt + 7200 < now) {
    acme_request_cert(callbacks, opaque, domains,
                      contact, directory_url, cert, keysize);
  }

  ntv_set_int64(cert, "attempt", now);

  scoped_char *saved_json =
    ntv_json_serialize_to_str(cert, NTV_JSON_F_PRETTY |
                              NTV_JSON_F_MINIMAL_ESCAPE);
  callbacks->save_cert(opaque, saved_json);

  if(is_cert_valid(cert) >= 1)
    return cert;

  ntv_release(cert);
  return NULL;
}
