#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "mbuf.h"

void
hexdump(const char *prefix, const void *data, int len)
{
}

static void
check_gzip(const void *input, size_t input_size)
{
  mbuf_t src;
  mbuf_t compressed;
  mbuf_init(&src);
  mbuf_init(&compressed);
  mbuf_set_chunk_size(&src, 1024 * 1024);
  mbuf_append(&src, input, input_size);

  assert(mbuf_gzip(&compressed, &src, 9) == 0);

  const size_t compressed_size = compressed.mq_size;
  uint8_t *compressed_data = malloc(compressed_size);
  assert(mbuf_read(&compressed, compressed_data, compressed_size) ==
         compressed_size);

  uint8_t *output = malloc(input_size + 1);
  z_stream z = {};
  assert(inflateInit2(&z, 31) == Z_OK);
  z.next_in = compressed_data;
  z.avail_in = compressed_size;
  z.next_out = output;
  z.avail_out = input_size + 1;
  assert(inflate(&z, Z_FINISH) == Z_STREAM_END);
  assert(z.total_out == input_size);
  assert(!memcmp(input, output, input_size));
  assert(inflateEnd(&z) == Z_OK);

  free(output);
  free(compressed_data);
  mbuf_clear(&compressed);
  mbuf_clear(&src);
}

int
main(void)
{
  check_gzip("", 0);

  const size_t input_size = 3 * 1024 * 1024 + 17;
  uint8_t *input = malloc(input_size);
  uint32_t state = 1;
  for(size_t i = 0; i < input_size; i++) {
    state = state * 1103515245 + 12345;
    input[i] = state >> 24;
  }
  check_gzip(input, input_size);
  free(input);
  return 0;
}
