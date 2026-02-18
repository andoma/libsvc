#pragma once

#include <stddef.h>
#include <stdint.h>

void sha1(const void *data, size_t len, uint8_t output[static 20]);

void sha256(const void *data, size_t len, uint8_t output[static 32]);

void sha512(const void *data, size_t len, uint8_t output[static 64]);

struct sha256_ctx;

struct sha256_ctx *sha256_create(void);

void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len);

void sha256_digest(struct sha256_ctx *ctx, uint8_t output[static 32]);

void sha256_destroy(struct sha256_ctx *ctx);
