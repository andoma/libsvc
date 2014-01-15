#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memstream.h"

#ifdef linux

FILE *
open_buffer(char **out, size_t *outlen)
{
  return open_memstream(out, outlen);
}

#else

/**
 *
 */
typedef struct bufhelper {
  char **out;
  size_t *outlen;
} bufhelper_t;


/**
 *
 */
static int
buf_write(void *aux, const char *data, int len)
{
  bufhelper_t *bh = aux;
  int needlen = *bh->outlen + len;
  *bh->out = realloc(*bh->out, needlen);
  memcpy(*bh->out, data, len);
  *bh->outlen = needlen;
  return len;
}


/**
 *
 */
static int
buf_close(void *aux)
{
  free(aux);
  return 0;
}

/**
 *
 */
FILE *
open_buffer(char **out, size_t *outlen)
{
  *outlen = 0;
  *out = NULL;
  bufhelper_t *bh = malloc(sizeof(bufhelper_t));
  bh->out = out;
  bh->outlen = outlen;
  return funopen(bh, NULL, buf_write, NULL, buf_close);
}

#endif
