#include "hash.h"

#include <stdlib.h>

#include "BearSSL/inc/bearssl_hash.h"

void
sha1(const void *data, size_t len, uint8_t output[static 20])
{
  br_sha1_context ctx;
  br_sha1_init(&ctx);
  br_sha1_update(&ctx, data, len);
  br_sha1_out(&ctx, output);
}

void
sha512(const void *data, size_t len, uint8_t output[static 64])
{
  br_sha512_context ctx;
  br_sha512_init(&ctx);
  br_sha512_update(&ctx, data, len);
  br_sha512_out(&ctx, output);
}

struct sha256_ctx {
  br_sha256_context ctx;
};

void
sha256(const void *data, size_t len, uint8_t output[static 32])
{
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, data, len);
  br_sha256_out(&ctx, output);
}


struct sha256_ctx *
sha256_create(void)
{
  struct sha256_ctx *ctx = malloc(sizeof(struct sha256_ctx));
  br_sha256_init(&ctx->ctx);
  return ctx;
}

void
sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
  br_sha256_update(&ctx->ctx, data, len);
}

void
sha256_digest(struct sha256_ctx *ctx, uint8_t output[static 32])
{
  br_sha256_out(&ctx->ctx, output);
}

void
sha256_destroy(struct sha256_ctx *ctx)
{
  free(ctx);
}
