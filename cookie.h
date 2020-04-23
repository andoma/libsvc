#pragma once

#include "ntv.h"

typedef struct cookie_engine cookie_engine_t;

cookie_engine_t *cookie_engine_create(const char *secret, const char *salt,
                                      int pbkdf2_rounds);

void cookie_engine_destroy(cookie_engine_t *ce);

char *cookie_encode(cookie_engine_t *ce, const ntv_t *msg);

ntv_t *cookie_decode(cookie_engine_t *ce, const char *str);

