#include <string.h>
#include <time.h>
#include <stddef.h>

#include "azure.h"
#include "misc.h"
#include "trace.h"
#include <openssl/hmac.h>

char *
azure_sas_token(const char *resource, const char *sakey,
                int valid_duration, const char *keyname)
{
  scoped_char *canonical_resource =
    url_escape_alloc(resource, URL_ESCAPE_PARAM);

  time_t ttl = time(NULL) + valid_duration;
  scoped_char *to_sign = fmt("%s\n%ld", canonical_resource, (long)ttl);

  uint8_t key[256];
  int keylen = base64_decode(key, sakey, sizeof(key));

  uint8_t hmac[32];

  HMAC(EVP_sha256(), key, keylen, (const uint8_t *)to_sign,
       strlen(to_sign), hmac, NULL);

  scoped_char *b64_hmac = base64_encode_a(hmac, sizeof(hmac),
                                          BASE64_STANDARD);

  scoped_char *sig = url_escape_alloc(b64_hmac, URL_ESCAPE_PARAM);

  return fmt("SharedAccessSignature sr=%s&sig=%s&se=%ld%s%s",
             canonical_resource, sig, (long)ttl,
             keyname ? "&skn=" : "",
             keyname ?: "");
}
