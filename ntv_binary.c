/******************************************************************************
* Copyright (C) 2008 - 2016 Andreas Smas
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ntv.h"
#include "mbuf.h"


// These values are selected based on bytes that must never occur in
// UTF8 strings. Just to accidentally avoid parsing text as NTV for
// whateer reason

#define NTV_BIN_MAP           0xc0
#define NTV_BIN_LIST          0xc1
#define NTV_BIN_END           0xf5
#define NTV_BIN_INTEGER       0xf6
#define NTV_BIN_STRING        0xf7
#define NTV_BIN_DOUBLE        0xf8
#define NTV_BIN_BINARY        0xf9
#define NTV_BIN_BOOLEAN_FALSE 0xfa
#define NTV_BIN_BOOLEAN_TRUE  0xfb
#define NTV_BIN_NULL          0xfc

static void
ntv_write_varint(mbuf_t *hq, uint64_t v)
{
  uint8_t tmp[10];
  int x = 0;
  do {
    tmp[x++] = (v & 0x7f) | (v > 0x7f ? 0x80 : 0);
    v >>= 7;
  } while(v);
  mbuf_append(hq, tmp, x);
}


static void
ntv_write_blob(mbuf_t *hq, const void *data, int len)
{
  ntv_write_varint(hq, len);
  mbuf_append(hq, data, len);
}


static void
ntv_write_string(mbuf_t *hq, const char *str)
{
  ntv_write_blob(hq, str, str ? strlen(str) : 0);
}

static void
ntv_write_byte(mbuf_t *hq, uint8_t c)
{
  mbuf_append(hq, &c, 1);
}


static uint64_t
zigzag_encode(int64_t x)
{
  return (x << 1) ^ (x >> 63);
}


static int64_t
zigzag_decode(uint64_t x)
{
  return (x >> 1) ^ -(x & 1);
}


/**
 *
 */
void
ntv_binary_serialize(const ntv_t *msg, mbuf_t *m)
{
  switch(msg->ntv_type) {
  case NTV_MAP:
    ntv_write_byte(m, NTV_BIN_MAP);
    NTV_FOREACH(f, msg) {
      ntv_binary_serialize(f, m);
      ntv_write_string(m, f->ntv_name);
    }
    ntv_write_byte(m, NTV_BIN_END);
    break;

  case NTV_LIST:
    ntv_write_byte(m, NTV_BIN_LIST);
    NTV_FOREACH(f, msg) {
      ntv_binary_serialize(f, m);
    }
    ntv_write_byte(m, NTV_BIN_END);
    break;

  case NTV_STRING:
    ntv_write_byte(m, NTV_BIN_STRING);
    ntv_write_string(m, msg->ntv_string);
    break;

  case NTV_BINARY:
    ntv_write_byte(m, NTV_BIN_BINARY);
    ntv_write_blob(m, msg->ntv_bin, msg->ntv_binsize);
    break;

  case NTV_INT:
    ntv_write_byte(m, NTV_BIN_INTEGER);
    ntv_write_varint(m, zigzag_encode(msg->ntv_s64));
    break;

  case NTV_DOUBLE:
    ntv_write_byte(m, NTV_BIN_DOUBLE);
    mbuf_append(m, &msg->ntv_double, sizeof(msg->ntv_double));
    break;

  case NTV_NULL:
    ntv_write_byte(m, NTV_BIN_NULL);
    break;

  case NTV_BOOLEAN:
    ntv_write_byte(m, msg->ntv_boolean ?
                   NTV_BIN_BOOLEAN_TRUE : NTV_BIN_BOOLEAN_FALSE);
    break;

  default:
    abort();
  }
}


static const uint8_t *
ntv_read_varint(const uint8_t *data, const uint8_t *dataend, uint64_t *vptr)
{
  int shift = 0;
  uint64_t v = 0;
  while(data < dataend) {
    uint8_t b = *data++;
    v |= (uint64_t)(b & 0x7f) << shift;
    shift += 7;
    if(!(b & 0x80)) {
      *vptr = v;
      return data;
    }
  }
  return NULL;
}


static const uint8_t *
ntv_read_length(const uint8_t *data, const uint8_t *dataend, uint64_t *len)
{
  uint64_t u64;
  data = ntv_read_varint(data, dataend, &u64);
  if(data == NULL)
    return NULL;

  // Avoid 'insane' string lengths
  if(u64 > (24 * 1024 * 1024))
    return NULL;

  if(u64 > dataend - data)
    return NULL;
  *len = u64;
  return data;
}

static const uint8_t *
ntv_read_string(const uint8_t *data, const uint8_t *dataend, char **res)
{
  uint64_t u64;
  data = ntv_read_length(data, dataend, &u64);
  if(data == NULL)
    return NULL;

  char *r = *res = malloc(u64 + 1);
  if(r == NULL)
    return NULL;

  memcpy(r, data, u64);
  r[u64] = 0;
  return data + u64;
}


static const uint8_t *
ntv_read_binary(const uint8_t *data, const uint8_t *dataend, void **res,
                size_t *lenp, int nocopy)
{
  uint64_t u64;
  data = ntv_read_length(data, dataend, &u64);
  if(data == NULL)
    return NULL;

  if(nocopy) {
    *res = (void *)data;
  } else {
    char *r = *res = malloc(u64);
    if(r == NULL)
      return NULL;
    memcpy(r, data, u64);
  }
  *lenp = u64;
  return data + u64;
}


static const uint8_t *
ntv_binary_deserialize0(const uint8_t *data, const uint8_t *dataend,
                        ntv_t **ret, int nocopy)
{
  uint64_t u64;
  ntv_t *f = NULL;
  const ptrdiff_t size = dataend - data;
  if(size < 1)
    return NULL;

  const uint8_t type = *data++;
  switch(type) {
  default:
    return NULL;

  case NTV_BIN_MAP:
    f = ntv_create(NTV_MAP);
    if(0)
  case NTV_BIN_LIST:
      f = ntv_create(NTV_LIST);

    while(1) {
      if(dataend - data < 1) {
        data = NULL;
        break;
      }

      if(*data == NTV_BIN_END) {
        data++;
        break;
      }

      ntv_t *sub;
      data = ntv_binary_deserialize0(data, dataend, &sub, nocopy);
      if(data == NULL)
        break;

      if(type == NTV_BIN_MAP) {
        data = ntv_read_string(data, dataend, &sub->ntv_name);
        if(data == NULL) {
          ntv_release(sub);
          break;
        }
      }
      TAILQ_INSERT_TAIL(&f->ntv_children, sub, ntv_link);
      sub->ntv_parent = f;
    }
    break;

  case NTV_BIN_NULL:
    f = ntv_create(NTV_NULL);
    break;

  case NTV_BIN_BOOLEAN_TRUE:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = true;
    break;

  case NTV_BIN_BOOLEAN_FALSE:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = false;
    break;

  case NTV_BIN_INTEGER:
    data =  ntv_read_varint(data, dataend, &u64);
    if(data != NULL) {
      f = ntv_create(NTV_INT);
      f->ntv_s64 = zigzag_decode(u64);
    }
    break;

  case NTV_BIN_STRING:
    f = ntv_create(NTV_STRING);
    data = ntv_read_string(data, dataend, &f->ntv_string);
    break;

  case NTV_BIN_DOUBLE:
    if(sizeof(double) > dataend - data) {
      data = NULL;
      break;
    }
    f = ntv_create(NTV_DOUBLE);
    memcpy(&f->ntv_double, data, sizeof(double));
    data += 8;
    break;

  case NTV_BIN_BINARY:
    f = ntv_create(NTV_BINARY);
    data = ntv_read_binary(data, dataend, &f->ntv_bin, &f->ntv_binsize, nocopy);
    if(nocopy)
      f->ntv_flags |= NTV_DONT_FREE;
    break;
  }

  if(data == NULL) {
    ntv_release(f);
  } else {
    *ret = f;
  }

  return data;
}


ntv_t *
ntv_binary_deserialize(const void *data, size_t length)
{
  ntv_t *r = NULL;
  ntv_binary_deserialize0(data, data + length, &r, 0);
  return r;
}

ntv_t *
ntv_binary_deserialize_nocopy(const void *data, size_t length)
{
  ntv_t *r = NULL;
  ntv_binary_deserialize0(data, data + length, &r, 1);
  return r;
}
