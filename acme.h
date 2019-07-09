#pragma once



typedef struct acme_callbacks {

  char *(*account_key_get)(void *opaque);

  int (*account_key_set)(void *opaque, const char *pem);

  int (*present_http_01)(void *opaque, const char *domain,
                         const char *token, const char *payload);

  int (*present_dns_01)(void *opaque, const char *domain,
                        const char *payload);

  char *(*load_cert)(void *opaque);

  int (*save_cert)(void *opaque, const char *json);

} acme_callbacks_t;

struct ntv;
struct strvec;

ntv_t *acme_acquire_cert(const acme_callbacks_t *callbacks, void *opaque,
                         const strvec_t *domains, const char *contact,
                         const char *directory_url);
