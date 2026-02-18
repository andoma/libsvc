#include "hmac.h"

#include "BearSSL/inc/bearssl_hmac.h"
#include "BearSSL/inc/bearssl_hash.h"

void hmac256(const void *key, size_t keylen,
             const void *data, size_t datalen,
             uint8_t output[static 32])
{
  br_hmac_key_context kc;
  br_hmac_context ctx;

  br_hmac_key_init(&kc, &br_sha256_vtable, key, keylen);

  br_hmac_init(&ctx, &kc, 32);
  br_hmac_update(&ctx, data, datalen);
  br_hmac_out(&ctx, output);
}
