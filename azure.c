#include <string.h>
#include <stdlib.h>
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


char *
azure_cli_get_token(const char *resource)
{
  const char *home = getenv("HOME");
  if(home == NULL)
    return NULL;

  scoped_char *path = fmt("%s/.azure/msal_token_cache.json", home);
  scoped_char *json = readfile(path, NULL);
  if(json == NULL)
    return NULL;

  char errbuf[256];
  scoped_ntv_t *cache = ntv_json_deserialize(json, errbuf, sizeof(errbuf));
  if(cache == NULL)
    return NULL;

  const ntv_t *access_tokens = ntv_get_map(cache, "AccessToken");
  if(access_tokens == NULL)
    return NULL;

  time_t now = time(NULL);

  NTV_FOREACH(entry, access_tokens) {
    if(entry->ntv_type != NTV_MAP)
      continue;

    const char *secret      = ntv_get_str(entry, "secret");
    const char *target      = ntv_get_str(entry, "target");
    const char *expires_str = ntv_get_str(entry, "expires_on");

    if(secret == NULL || target == NULL || expires_str == NULL)
      continue;

    if((time_t)atoll(expires_str) < now + 60)
      continue;

    if(strstr(target, resource) == NULL)
      continue;

    return fmt("Bearer %s", secret);
  }

  return NULL;
}


ntv_t *
azure_vm_get_machine_identity(void)
{
  char errbuf[512];
  const char *url = "http://169.254.169.254/metadata/instance?api-version=2018-02-01";

  scoped_http_result(hcr);

  if(http_client_request(&hcr, url,
                         HCR_TIMEOUT(2),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_HEADER("Metadata", "true"),
                         NULL)) {
    trace(LOG_ERR, "Failed to get azure instance metadata from %s -- %s",
          url, errbuf);
    return NULL;
  }

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

  if(http_client_request(&hcr, url,
                         HCR_TIMEOUT(2),
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                         HCR_ERRBUF(errbuf, sizeof(errbuf)),
                         HCR_HEADER("Metadata", "true"),
                         NULL)) {
    trace(LOG_ERR, "Failed to get azure instance token for %s from %s -- %s",
          aud, url, errbuf);
    return NULL;
  }


  ntv_t *result = hcr.hcr_json_result;
  hcr.hcr_json_result = NULL;
  return result;
}
