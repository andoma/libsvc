#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "cfg.h"
#include "ntv.h"
#include "murmur3.h"
#include "misc.h"
#include "trace.h"
#include "http_client.h"
#include "gcp.h"

typedef struct token_pair {
  pthread_mutex_t mutex;
  char *refresh_token;
  char *access_token;
  time_t expire;
} token_pair_t;

#define TOKEN_CACHE_SIZE 512

static token_pair_t tokenpairs[TOKEN_CACHE_SIZE];

char *
gcp_get_access_token_from_refresh(const char *refresh_token, int force)
{
  cfg_root(pc);

  const char *clientid = cfg_get_str(pc, CFG("google", "clientid"), NULL);
  const char *secret = cfg_get_str(pc, CFG("google", "clientsecret"), NULL);

  if(clientid == NULL || secret == NULL) {
    return NULL;
  }

  const unsigned int hash =
    MurHash3_32(refresh_token, strlen(refresh_token), 0) &
    (TOKEN_CACHE_SIZE - 1);

  token_pair_t *tp = &tokenpairs[hash];
  time_t now = time(NULL);

  pthread_mutex_lock(&tp->mutex);

  if(!force && tp->refresh_token != NULL && tp->expire > now &&
     !strcmp(tp->refresh_token, refresh_token)) {
    char *r = strdup(tp->access_token);
    pthread_mutex_unlock(&tp->mutex);
    return r;
  }

  scoped_char *params = fmt("client_id=%s"
                            "&client_secret=%s"
                            "&refresh_token=%s"
                            "&grant_type=refresh_token",
                            clientid,
                            secret,
                            refresh_token);

  scoped_http_result(result);
  if(http_client_request(&result,
                         "https://www.googleapis.com/oauth2/v4/token",
                         HCR_FLAGS(HCR_DECODE_BODY_AS_JSON),
                         HCR_POSTFIELDS(params, strlen(params)),
                         HCR_TIMEOUT(10),
                         NULL)) {
    trace(LOG_ERR, "gcp: unable to refresh access token -- %s",
          result.hcr_transport_status);
    pthread_mutex_unlock(&tp->mutex);
    return NULL;
  }

  const char *at = ntv_get_str(result.hcr_json_result, "access_token");
  if(at != NULL) {
    int expire = ntv_get_int(result.hcr_json_result, "expires_in", 3600);
    tp->expire = now + expire - 1;
    free(tp->access_token);
    tp->access_token = strdup(at);
  }

  pthread_mutex_unlock(&tp->mutex);

  return strdup(at);
}



