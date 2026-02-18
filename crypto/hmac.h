#pragma once

#include <stddef.h>
#include <stdint.h>

void hmac256(const void *key, size_t keylen,
             const void *data, size_t datalen,
             uint8_t output[static 32]);
