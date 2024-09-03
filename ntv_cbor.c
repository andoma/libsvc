/******************************************************************************
* Copyright (C) 2008 - 2016 Andreas Smas
* Copyright (c) 2017 Facebook Inc.
* Copyright (c) 2017 Georgia Institute of Technology
* Copyright 2019 Google LLC
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
#include "bytestream.h"
#include "misc.h"

static void
cbor_write_byte(mbuf_t *hq, uint8_t c)
{
  mbuf_append(hq, &c, 1);
}

static void
cbor_write_u16(mbuf_t *hq, uint16_t c)
{
  uint8_t data[2] = {c >> 8, c};
  mbuf_append(hq, data, 2);
}

static void
cbor_write_u32(mbuf_t *hq, uint32_t c)
{
  uint8_t data[4] = {c >> 24, c >> 16, c >> 8, c};
  mbuf_append(hq, data, 4);
}

static void
cbor_write_u64(mbuf_t *hq, uint64_t c)
{
  uint8_t data[8] = {c >> 56, c >> 48, c >> 40, c >> 32,
                     c >> 24, c >> 16, c >> 8,  c};
  mbuf_append(hq, data, 8);
}


/**
 *
 */
static void
cbor_write_unsigned_int(mbuf_t *m, uint64_t u64, uint8_t major)
{
  if(u64 < 24) {
    cbor_write_byte(m, major | u64);
  } else if(u64 < 256) {
    cbor_write_byte(m, major | 24);
    cbor_write_byte(m, u64);
  } else if(u64 < 65536) {
    cbor_write_byte(m, major | 25);
    cbor_write_u16(m, u64);
  } else if(u64 < 4294967296LL) {
    cbor_write_byte(m, major | 26);
    cbor_write_u32(m, u64);
  } else {
    cbor_write_byte(m, major | 27);
    cbor_write_u64(m, u64);
  }
}


/**
 *
 */
static void
cbor_write_int(mbuf_t *m, int64_t s64)
{
  if(s64 < 0) {
    cbor_write_unsigned_int(m, ~s64, 1 << 5);
  } else {
    cbor_write_unsigned_int(m, s64, 0);
  }
}




static void
cbor_write_string(mbuf_t *m, const char *str)
{
  size_t len = strlen(str);
  cbor_write_unsigned_int(m, len, 3 << 5);
  mbuf_append(m, str, len);
}

static void
cbor_write_bin(mbuf_t *m, const char *str, int len)
{
  cbor_write_unsigned_int(m, len, 2 << 5);
  mbuf_append(m, str, len);
}



/**
 *
 */
static void
cbor_write_double(mbuf_t *m, double d)
{
  union { double d; uint64_t u64; } u;
  u.d = d;
  cbor_write_byte(m, 7 << 5 | 27);
  cbor_write_u64(m, u.u64);
}


/**
 *
 */
void
ntv_cbor_serialize(const ntv_t *msg, mbuf_t *m)
{
  switch(msg->ntv_type) {
  case NTV_MAP:
    cbor_write_byte(m, 5 << 5 | 31);
    NTV_FOREACH(f, msg) {
      cbor_write_string(m, f->ntv_name);
      ntv_cbor_serialize(f, m);
    }
    cbor_write_byte(m, 0xff);
    break;

  case NTV_LIST:
    cbor_write_byte(m, 4 << 5 | 31);
    NTV_FOREACH(f, msg) {
      ntv_cbor_serialize(f, m);
    }
    cbor_write_byte(m, 0xff);
    break;

  case NTV_STRING:
    cbor_write_string(m, msg->ntv_string);
    break;

  case NTV_BINARY:
    cbor_write_bin(m, msg->ntv_bin, msg->ntv_binsize);
    break;

  case NTV_INT:
    cbor_write_int(m, msg->ntv_s64);
    break;

  case NTV_DOUBLE:
    cbor_write_double(m, msg->ntv_double);
    break;

  case NTV_NULL:
    cbor_write_byte(m, 7 << 5 | 22);
    break;

  case NTV_BOOLEAN:
    cbor_write_byte(m, 7 << 5 | (20 + !!msg->ntv_boolean));
    break;

  default:
    abort();
  }
}


typedef struct errctx {
  const void *ptr;
  char errmsg[128];
} errctx_t;


static const uint8_t *
cbor_err(const uint8_t *data, errctx_t *ctx, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(ctx->errmsg, sizeof(ctx->errmsg), fmt, ap);
  va_end(ap);
  ctx->ptr = data;
  return NULL;
}


#if 0
static const uint8_t *
cbor_read_data(const uint8_t *data, const uint8_t *dataend, void *res,
                  int length, errctx_t *ec)
{
  if(data == NULL)
    return NULL;
  if(length > dataend - data)
    return cbor_err(data, ec, "EOF, trying to read %d bytes", length);

  char *r = malloc_add(length, 1);
  if(r == NULL)
    return cbor_err(data, ec, "Out of memory");

  *(void **)res = r;

  memcpy(r, data, length);
  r[length] = 0;
  return data + length;
}
#endif

static const uint8_t *
cbor_decode_u64(const uint8_t *data, const uint8_t *dataend,
                uint64_t *out, uint8_t code, errctx_t *ec)
{
  code = code & 0x1f;

  if(code < 24) {
    *out = code;
    return data;
  }

  if(data == NULL)
    return NULL;

  const int bytes = 1 << (code - 24);

  if(bytes > dataend - data) {
    return cbor_err(data, ec, "EOF, trying to read %d bytes", bytes);
  }
  switch(bytes) {
  case 1:
    *out = (uint8_t)data[0];
    break;
  case 2:
    *out = (uint16_t)rd16_be(data);
    break;
  case 4:
    *out = (uint32_t)rd32_be(data);
    break;
  case 8:
    *out = rd64_be(data);
    break;
  }
  return data + bytes;
}


/**
 *
 */
static const uint8_t *
cbor_read_bin(const uint8_t *data, const uint8_t *dataend, ntv_t *f,
              uint8_t code, errctx_t *ec)
{
  uint64_t length;
  data = cbor_decode_u64(data, dataend, &length, code, ec);
  if(data == NULL)
    return NULL;

  if(length > dataend - data) {
    return cbor_err(data, ec, "EOF when reading binary field");
  }
  char *x = malloc(length);
  if(x == NULL) {
    return cbor_err(data, ec, "Out of memory when reading binary field");
  }
  f->ntv_bin = x;
  f->ntv_binsize = length;
  memcpy(f->ntv_bin, data, length);
  return data + length;
}



static const uint8_t *
cbor_read_string(const uint8_t *data, const uint8_t *dataend, char **str,
                 uint8_t code, errctx_t *ec)
{
  uint64_t length;
  data = cbor_decode_u64(data, dataend, &length, code, ec);
  if(data == NULL)
    return NULL;
  if(length > dataend - data)
    return cbor_err(data, ec, "EOF, trying to read %zd bytes", (size_t)length);

  char *s = malloc_add(length, 1);
  if(s == NULL) {
    return cbor_err(data, ec, "Out of memory when reading string field");
  }
  memcpy(s, data, length);
  s[length] = 0;
  *str = s;
  return data + length;
}


static const uint8_t *ntv_cbor_deserialize0(const uint8_t *data,
                                               const uint8_t *dataend,
                                               ntv_t **ret, int nocopy,
                                               errctx_t *ec);

static const uint8_t *
decode_sub(const uint8_t *data, const uint8_t *dataend,
           ntv_t **fp, uint8_t code, int nocopy, int havekeys, errctx_t *ec)
{
  uint64_t length;
  if((code & 0x1f) == 0x1f) {
    length = UINT64_MAX;
  } else {
    data = cbor_decode_u64(data, dataend, &length, code, ec);
    if(data == NULL)
      return NULL;
  }

  ntv_t *f = ntv_create(havekeys ? NTV_MAP : NTV_LIST);

  for(uint64_t i = 0; i < length; i++) {
    ntv_t *sub;
    char *key = NULL;
    const ptrdiff_t size = dataend - data;
    if(size < 1)
      return cbor_err(data, ec, "EOF when reading %s", havekeys ? "map":"list");


    if(*data == 0xff) {
      data++;
      break;
    }

    if(havekeys) {
      uint8_t code = *data++;
      data = cbor_read_string(data, dataend, &key, code, ec);
      if(data == NULL)
        return NULL;
    }

    data = ntv_cbor_deserialize0(data, dataend, &sub, nocopy, ec);
    if(data == NULL)
      return NULL;

    TAILQ_INSERT_TAIL(&f->ntv_children, sub, ntv_link);
    sub->ntv_parent = f;
    if(key != NULL)
      sub->ntv_name = key;
  }
  *fp = f;
  return data;
}


/**
 *
 */
static const uint8_t *
cbor_read_u64(const uint8_t *data, const uint8_t *dataend,
                 uint64_t *out, errctx_t *ec)
{
  if(sizeof(uint64_t) > dataend - data) {
    *out = 0;
    return cbor_err(data, ec, "EOF, trying to read u64");
  }
  *out = rd64_be(data);
  return data + sizeof(uint64_t);
}


/**
 *
 */
static const uint8_t *
cbor_read_u32(const uint8_t *data, const uint8_t *dataend,
                 uint32_t *out, errctx_t *ec)
{
  if(sizeof(uint32_t) > dataend - data) {
    *out = 0;
    return cbor_err(data, ec, "EOF, trying to read u32");
  }
  *out = rd32_be(data);
  return data + sizeof(uint32_t);
}


/**
 *
 */
static const uint8_t *
cbor_read_u16(const uint8_t *data, const uint8_t *dataend,
              uint16_t *out, errctx_t *ec)
{
  if(sizeof(uint16_t) > dataend - data) {
    *out = 0;
    return cbor_err(data, ec, "EOF, trying to read u16");
  }
  *out = rd16_be(data);
  return data + sizeof(uint16_t);
}



/**
 *
 */
static const uint8_t *
cbor_read_double(const uint8_t *data, const uint8_t *dataend,
                    double *out, errctx_t *ec)
{
  union { double d; uint64_t u64; } u;
  data = cbor_read_u64(data, dataend, &u.u64, ec);
  *out = u.d;
  return data;
}


/**
 *
 */
static const uint8_t *
cbor_read_float(const uint8_t *data, const uint8_t *dataend,
                   double *out, errctx_t *ec)
{
  union { float d; uint32_t u32; } u;
  data = cbor_read_u32(data, dataend, &u.u32, ec);
  *out = u.d;
  return data;
}

static inline uint32_t fp32_to_bits(float f) {
  union {
    float as_value;
    uint32_t as_bits;
  } fp32;
  fp32.as_value = f;
  return fp32.as_bits;
}


static inline float fp32_from_bits(uint32_t w) {
  union {
    uint32_t as_bits;
    float as_value;
  } fp32;
  fp32.as_bits = w;
  return fp32.as_value;
}

static float from_half(uint16_t h)
{
  const uint32_t w = (uint32_t) h << 16;
  const uint32_t sign = w & UINT32_C(0x80000000);
  const uint32_t two_w = w + w;

  const uint32_t exp_offset = UINT32_C(0xE0) << 23;
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) || defined(__GNUC__) && !defined(__STRICT_ANSI__)
  const float exp_scale = 0x1.0p-112f;
#else
  const float exp_scale = fp32_from_bits(UINT32_C(0x7800000));
#endif
  const float normalized_value = fp32_from_bits((two_w >> 4) + exp_offset) * exp_scale;

  const uint32_t magic_mask = UINT32_C(126) << 23;
  const float magic_bias = 0.5f;
  const float denormalized_value = fp32_from_bits((two_w >> 17) | magic_mask) - magic_bias;

  const uint32_t denormalized_cutoff = UINT32_C(1) << 27;
  const uint32_t result = sign |
    (two_w < denormalized_cutoff ? fp32_to_bits(denormalized_value) : fp32_to_bits(normalized_value));
  return fp32_from_bits(result);
}


/**
 *
 */
static const uint8_t *
cbor_read_half(const uint8_t *data, const uint8_t *dataend,
               double *out, errctx_t *ec)
{
  uint16_t u16;
  data = cbor_read_u16(data, dataend, &u16, ec);
  *out = from_half(u16);
  return data;
}


static const uint8_t *
ntv_cbor_deserialize0(const uint8_t *data, const uint8_t *dataend,
                         ntv_t **ret, int nocopy, errctx_t *ec)
{
  ntv_t *f = NULL;
  const ptrdiff_t size = dataend - data;
  if(size < 1)
    return cbor_err(data, ec, "EOF when reading type code");

  const uint8_t code = *data++;
  uint64_t u64;

  switch(code) {

  case 0 ... 27:
    f = ntv_create(NTV_INT);
    data = cbor_decode_u64(data, dataend, &u64, code, ec);
    f->ntv_s64 = u64;
    break;

  case (1 << 5) ... (1 << 5) + 27:
    f = ntv_create(NTV_INT);
    data = cbor_decode_u64(data, dataend, &u64, code, ec);
    f->ntv_s64 = ~u64;
    break;

  case (2 << 5) ... (2 << 5) + 27:
    f = ntv_create(NTV_BINARY);
    data = cbor_read_bin(data, dataend, f, code, ec);
    break;

  case (3 << 5) ... (3 << 5) + 27:
    f = ntv_create(NTV_STRING);
    data = cbor_read_string(data, dataend, &f->ntv_string, code, ec);
    break;

  case (4 << 5) ... (4 << 5) + 31:
    data = decode_sub(data, dataend, &f, code, nocopy, 0, ec);
    break;

  case (5 << 5) ... (5 << 5) + 31:
    data = decode_sub(data, dataend, &f, code, nocopy, 1, ec);
    break;

  case 7 << 5 | 20:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = false;
    break;

  case 7 << 5 | 21:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = true;
    break;

  case 7 << 5 | 22:
    f = ntv_create(NTV_NULL);
    break;

  case 7 << 5 | 25:
    f = ntv_create(NTV_DOUBLE);
    data = cbor_read_half(data, dataend, &f->ntv_double, ec);
    break;

  case 7 << 5 | 26:
    f = ntv_create(NTV_DOUBLE);
    data = cbor_read_float(data, dataend, &f->ntv_double, ec);
    break;

  case 7 << 5 | 27:
    f = ntv_create(NTV_DOUBLE);
    data = cbor_read_double(data, dataend, &f->ntv_double, ec);
    break;


  default:
    return cbor_err(data, ec, "Unable to handle type code 0x%x "
                    "(major:%d minor:%d)", code, code >> 5, code & 0x1f);
  }

  if(data == NULL) {
    ntv_release(f);
  } else {
    *ret = f;
  }

  return data;
}


ntv_t *
ntv_cbor_deserialize(const void *data, size_t length,
                        char *errmsg, size_t errlen)
{
  errctx_t ec;
  ntv_t *r = NULL;
  if(ntv_cbor_deserialize0(data, data + length, &r, 0, &ec) == NULL)
    snprintf(errmsg, errlen, "Error at position 0x%zx: %s",
             ec.ptr - data, ec.errmsg);
  return r;
}

ntv_t *
ntv_cbor_deserialize_nocopy(const void *data, size_t length,
                               char *errmsg, size_t errlen)
{
  errctx_t ec;
  ntv_t *r = NULL;
  if(ntv_cbor_deserialize0(data, data + length, &r, 1, &ec) == NULL)
    snprintf(errmsg, errlen, "Error at position 0x%zx: %s",
             ec.ptr - data, ec.errmsg);
  return r;
}
