#include <string.h>
#include <time.h>
#include <stddef.h>

#include "azure.h"
#include "misc.h"
#include "trace.h"
#include "ntv.h"
#include "http.h"
#include "http_client.h"

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


ntv_t *
azure_vm_get_machine_identity(void)
{
  char errbuf[512];
  const char *url = "http://169.254.169.254/metadata/instance?api-version=2018-02-01";

  scoped_http_result(hcr);

  http_client_request(&hcr, url,
                      HCR_TIMEOUT(2),
                      HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                      HCR_ERRBUF(errbuf, sizeof(errbuf)),
                      HCR_HEADER("Metadata", "true"),
                      NULL);


  ntv_t *result = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return result;
}


ntv_t *
azure_vm_get_machine_token(const char *aud)
{
  char errbuf[512];
  scoped_char *url = fmt("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=%s", aud);

  scoped_http_result(hcr);

  http_client_request(&hcr, url,
                      HCR_TIMEOUT(2),
                      HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                      HCR_ERRBUF(errbuf, sizeof(errbuf)),
                      HCR_HEADER("Metadata", "true"),
                      NULL);


  ntv_t *result = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return result;
}
