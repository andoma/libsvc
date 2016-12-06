/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

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

FILE *
open_buffer_read(void *buf, size_t len)
{
  return fmemopen(buf, len, "rb");
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
  memcpy(*bh->out + *bh->outlen, data, len);
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


typedef struct readhelper {
  char *data;
  size_t size;
  off_t pos;
} readhelper_t;

/**
 *
 */
static int
buf_read(void *aux, char *data, int len)
{
  readhelper_t *rh = aux;

  if(rh->pos + len > rh->size)
    len = rh->size - rh->pos;

  memcpy(data, rh->data + rh->pos, len);
  rh->pos += len;
  return len;
}


FILE *
open_buffer_read(void *buf, size_t len)
{
  readhelper_t *rh = malloc(sizeof(readhelper_t));
  rh->data = buf;
  rh->size = len;
  rh->pos = 0;
  return funopen(rh, buf_read, NULL, NULL, buf_close);
}


#endif
