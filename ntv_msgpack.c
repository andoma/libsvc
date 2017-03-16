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
#include "bytestream.h"

static void
msgpack_write_byte(mbuf_t *hq, uint8_t c)
{
  mbuf_append(hq, &c, 1);
}

static void
msgpack_write_u16(mbuf_t *hq, uint16_t c)
{
  uint8_t data[2] = {c >> 8, c};
  mbuf_append(hq, data, 2);
}

static void
msgpack_write_u32(mbuf_t *hq, uint32_t c)
{
  uint8_t data[4] = {c >> 24, c >> 16, c >> 8, c};
  mbuf_append(hq, data, 4);
}

static void
msgpack_write_u64(mbuf_t *hq, uint64_t c)
{
  uint8_t data[8] = {c >> 56, c >> 48, c >> 40, c >> 32,
                     c >> 24, c >> 16, c >> 8,  c};
  mbuf_append(hq, data, 8);
}


static void
msgpack_write_string(mbuf_t *m, const char *str)
{
  int len = strlen(str);
  if(len < 32) {
    msgpack_write_byte(m, 0xa0 + len);
  } else if(len < 256) {
    msgpack_write_byte(m, 0xd9);
    msgpack_write_byte(m, len);
  } else if(len < 65536) {
    msgpack_write_byte(m, 0xda);
    msgpack_write_u16(m, len);
  } else {
    msgpack_write_byte(m, 0xdb);
    msgpack_write_u32(m, len);
  }
  mbuf_append(m, str, len);
}

static void
msgpack_write_bin(mbuf_t *m, const char *str, int len)
{
  if(len < 256) {
    msgpack_write_byte(m, 0xc4);
    msgpack_write_byte(m, len);
  } else if(len < 65536) {
    msgpack_write_byte(m, 0xc5);
    msgpack_write_u16(m, len);
  } else {
    msgpack_write_byte(m, 0xc6);
    msgpack_write_u32(m, len);
  }
  mbuf_append(m, str, len);
}


/**
 *
 */
static void
msgpack_write_int(mbuf_t *m, int64_t s64)
{
  if(s64 >= 0) {
    if(s64 < 128) {
      msgpack_write_byte(m, s64);
    } else if(s64 < 256) {
      msgpack_write_byte(m, 0xcc);
      msgpack_write_byte(m, s64);
    } else if(s64 < 65536) {
      msgpack_write_byte(m, 0xcd);
      msgpack_write_u16(m, s64);
    } else if(s64 < 4294967296LL) {
      msgpack_write_byte(m, 0xce);
      msgpack_write_u32(m, s64);
    } else {
      msgpack_write_byte(m, 0xcf);
      msgpack_write_u64(m, s64);
    }
  } else {
    if(s64 > -32) {
      msgpack_write_byte(m, 0xe0 | -s64);
    } else if(s64 >= -128) {
      msgpack_write_byte(m, 0xd0);
      msgpack_write_byte(m, s64);
    } else if(s64 >= -32768) {
      msgpack_write_byte(m, 0xd1);
      msgpack_write_u16(m, s64);
    } else if(s64 >= -2147483648LL) {
      msgpack_write_byte(m, 0xd2);
      msgpack_write_u32(m, s64);
    } else  {
      msgpack_write_byte(m, 0xd3);
      msgpack_write_u64(m, s64);
    }
  }
}



/**
 *
 */
static void
msgpack_write_double(mbuf_t *m, double d)
{
  union { double d; uint64_t u64; } u;
  u.d = d;
  msgpack_write_byte(m, 0xcb);
  msgpack_write_u64(m, u.u64);
}


/**
 *
 */
void
ntv_msgpack_serialize(const ntv_t *msg, mbuf_t *m)
{
  int count;
  switch(msg->ntv_type) {
  case NTV_MAP:
    count = ntv_num_children(msg);
    if(count < 16) {
      msgpack_write_byte(m, 0x80 + count);
    } else if(count < 65536) {
      msgpack_write_byte(m, 0xde);
      msgpack_write_u16(m, count);
    } else {
      msgpack_write_byte(m, 0xdf);
      msgpack_write_u32(m, count);
    }
    NTV_FOREACH(f, msg) {
      msgpack_write_string(m, f->ntv_name);
      ntv_msgpack_serialize(f, m);
    }
    break;

  case NTV_LIST:
    count = ntv_num_children(msg);
    if(count < 16) {
      msgpack_write_byte(m, 0x90 + count);
    } else if(count < 65536) {
      msgpack_write_byte(m, 0xdc);
      msgpack_write_u16(m, count);
    } else {
      msgpack_write_byte(m, 0xdd);
      msgpack_write_u32(m, count);
    }
    NTV_FOREACH(f, msg) {
      ntv_msgpack_serialize(f, m);
    }
    break;

  case NTV_STRING:
    msgpack_write_string(m, msg->ntv_string);
    break;

  case NTV_BINARY:
    msgpack_write_bin(m, msg->ntv_bin, msg->ntv_binsize);
    break;

  case NTV_INT:
    msgpack_write_int(m, msg->ntv_s64);
    break;

  case NTV_DOUBLE:
    msgpack_write_double(m, msg->ntv_double);
    break;

  case NTV_NULL:
    msgpack_write_byte(m, 0xc0);
    break;

  case NTV_BOOLEAN:
    msgpack_write_byte(m, msg->ntv_boolean ? 0xc3 : 0xc2);
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
msgpack_err(const uint8_t *data, errctx_t *ctx, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(ctx->errmsg, sizeof(ctx->errmsg), fmt, ap);
  va_end(ap);
  ctx->ptr = data;
  return NULL;
}

static const uint8_t *
msgpack_read_data(const uint8_t *data, const uint8_t *dataend, void *res,
                  int length, errctx_t *ec)
{
  if(data == NULL)
    return NULL;
  if(length > dataend - data)
    return msgpack_err(data, ec, "EOF, trying to read %d bytes", length);

  char *r = malloc(length + 1);
  if(r == NULL)
    return msgpack_err(data, ec, "Out of memory");

  *(void **)res = r;

  memcpy(r, data, length);
  r[length] = 0;
  return data + length;
}


static const uint8_t *
msgpack_read_len(const uint8_t *data, const uint8_t *dataend, uint32_t *len,
                 int bytes, errctx_t *ec)
{
  if(data == NULL)
    return NULL;

  if(bytes > dataend - data)
    return msgpack_err(data, ec, "EOF, trying to read %d bytes", bytes);

  int r = 0;
  for(int i = 0; i < bytes; i++) {
    r = data[i] + (r << 8);
  }
  *len = r;
  return data + bytes;
}


static const uint8_t *
msgpack_read_mapkey(const uint8_t *data, const uint8_t *dataend, char **str,
                    errctx_t *ec)
{
  uint32_t len = 0;
  const ptrdiff_t size = dataend - data;
  if(size < 1)
    return msgpack_err(data, ec, "EOF when reading mapkey");

  const uint8_t code = *data++;

  switch(code) {
  case 0xa0 ... 0xbf:
    data = msgpack_read_data(data, dataend, str, code - 0xa0, ec);
    break;

  case 0xd9 ... 0xdb:
    data = msgpack_read_len(data, dataend, &len, 1 << (code - 0xd9), ec);
    if(data != NULL) {
      data = msgpack_read_data(data, dataend, str, len, ec);
    }
    break;

  default:
    return msgpack_err(data, ec, "Invalid mapkey type code 0x%x", code);
  }

  return data;
}




static const uint8_t *ntv_msgpack_deserialize0(const uint8_t *data,
                                               const uint8_t *dataend,
                                               ntv_t **ret, int nocopy,
                                               errctx_t *ec);

static const uint8_t *
decode_sub(const uint8_t *data, const uint8_t *dataend,
           ntv_t **fp, uint32_t num, int nocopy, int havekeys, errctx_t *ec)
{
  ntv_t *f = ntv_create(havekeys ? NTV_MAP : NTV_LIST);
  for(uint32_t i = 0; i < num; i++) {
    ntv_t *sub;
    char *key = NULL;
    if(havekeys) {
      data = msgpack_read_mapkey(data, dataend, &key, ec);
      if(data == NULL)
        return NULL;
    }

    data = ntv_msgpack_deserialize0(data, dataend, &sub, nocopy, ec);
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
msgpack_read_u64(const uint8_t *data, const uint8_t *dataend,
                 uint64_t *out, errctx_t *ec)
{
  if(sizeof(uint64_t) > dataend - data) {
    *out = 0;
    return msgpack_err(data, ec, "EOF, trying to read u64");
  }
  *out = rd64_be(data);
  return data + sizeof(uint64_t);
}


/**
 *
 */
static const uint8_t *
msgpack_read_u32(const uint8_t *data, const uint8_t *dataend,
                 uint32_t *out, errctx_t *ec)
{
  if(sizeof(uint32_t) > dataend - data) {
    *out = 0;
    return msgpack_err(data, ec, "EOF, trying to read u32");
  }
  *out = rd32_be(data);
  return data + sizeof(uint32_t);
}



/**
 *
 */
static const uint8_t *
msgpack_read_double(const uint8_t *data, const uint8_t *dataend,
                    double *out, errctx_t *ec)
{
  union { double d; uint64_t u64; } u;
  data = msgpack_read_u64(data, dataend, &u.u64, ec);
  *out = u.d;
  return data;
}


/**
 *
 */
static const uint8_t *
msgpack_read_float(const uint8_t *data, const uint8_t *dataend,
                   double *out, errctx_t *ec)
{
  union { float d; uint32_t u32; } u;
  data = msgpack_read_u32(data, dataend, &u.u32, ec);
  *out = u.d;
  return data;
}

static const uint8_t *
msgpack_read_uint(const uint8_t *data, const uint8_t *dataend,
                  int64_t *out, int bytes, errctx_t *ec)
{
  if(data == NULL)
    return NULL;

  if(bytes > dataend - data) {
    return msgpack_err(data, ec, "EOF, trying to read %d bytes", bytes);
  }
  uint64_t r = 0;
  for(int i = 0; i < bytes; i++) {
    r = data[i] + (r << 8);
  }
  *out = r;
  return data + bytes;
}


static const uint8_t *
msgpack_read_int(const uint8_t *data, const uint8_t *dataend,
                 int64_t *out, int bytes, errctx_t *ec)
{
  if(data == NULL)
    return NULL;

  if(bytes > dataend - data) {
    return msgpack_err(data, ec, "EOF, trying to read %d bytes", bytes);
  }
  switch(bytes) {
  case 1:
    *out = (int8_t)data[0];
    break;
  case 2:
    *out = (int16_t)rd16_be(data);
    break;
  case 4:
    *out = (int32_t)rd32_be(data);
    break;
  case 8:
    *out = rd64_be(data);
    break;
  }
  return data + bytes;
}


static const uint8_t *
ntv_msgpack_deserialize0(const uint8_t *data, const uint8_t *dataend,
                         ntv_t **ret, int nocopy, errctx_t *ec)
{
  uint32_t len = 0;
  ntv_t *f = NULL;
  const ptrdiff_t size = dataend - data;
  if(size < 1)
    return msgpack_err(data, ec, "EOF when reading type code");

  const uint8_t code = *data++;

  switch(code) {
  case 0x00 ... 0x7f:
    f = ntv_create(NTV_INT);
    f->ntv_s64 = code & 0x7f;
    break;

  case 0x80 ... 0x8f:
    data = decode_sub(data, dataend, &f, code - 0x80, nocopy, 1, ec);
    break;

  case 0x90 ... 0x9f:
    data = decode_sub(data, dataend, &f, code - 0x90, nocopy, 0, ec);
    break;

  case 0xa0 ... 0xbf:
    f = ntv_create(NTV_STRING);
    data = msgpack_read_data(data, dataend, &f->ntv_string, code - 0xa0, ec);
    break;

  case 0xc0:
    f = ntv_create(NTV_NULL);
    break;

  case 0xc2:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = false;
    break;

  case 0xc3:
    f = ntv_create(NTV_BOOLEAN);
    f->ntv_boolean = true;
    break;

  case 0xc4 ... 0xc6:
    data = msgpack_read_len(data, dataend, &len, 1 << (code - 0xc4), ec);
    if(data != NULL) {
      f = ntv_create(NTV_BINARY);
      f->ntv_binsize = len;
      data = msgpack_read_data(data, dataend, &f->ntv_bin, len, ec);
    }
    break;

  case 0xca:
    f = ntv_create(NTV_DOUBLE);
    data = msgpack_read_float(data, dataend, &f->ntv_double, ec);
    break;

  case 0xcb:
    f = ntv_create(NTV_DOUBLE);
    data = msgpack_read_double(data, dataend, &f->ntv_double, ec);
    break;

  case 0xcc ... 0xcf:
    f = ntv_create(NTV_INT);
    data = msgpack_read_uint(data, dataend, &f->ntv_s64, 1 << (code - 0xcc),ec);
    break;

  case 0xd0 ... 0xd3:
    f = ntv_create(NTV_INT);
    data = msgpack_read_int(data, dataend, &f->ntv_s64, 1 << (code - 0xd0), ec);
    break;


  case 0xd9 ... 0xdb:
    data = msgpack_read_len(data, dataend, &len, 1 << (code - 0xd9), ec);
    if(data != NULL) {
      f = ntv_create(NTV_STRING);
      data = msgpack_read_data(data, dataend, &f->ntv_string, len, ec);
    }
    break;

  case 0xdc ... 0xdd:
    data = msgpack_read_len(data, dataend, &len, 2 << (code - 0xdc), ec);
    if(data != NULL)
      data = decode_sub(data, dataend, &f, len, nocopy, 0, ec);
    break;

  case 0xde ... 0xdf:
    data = msgpack_read_len(data, dataend, &len, 2 << (code - 0xde), ec);
    if(data != NULL)
      data = decode_sub(data, dataend, &f, len, nocopy, 1, ec);
    break;

  case 0xe0 ... 0xff:
    f = ntv_create(NTV_INT);
    f->ntv_s64 = -(code - 0xe0);
    break;

  default:
    return msgpack_err(data, ec, "Unable to handle type code 0x%x", code);
  }

  if(data == NULL) {
    ntv_release(f);
  } else {
    *ret = f;
  }

  return data;
}


ntv_t *
ntv_msgpack_deserialize(const void *data, size_t length,
                        char *errmsg, size_t errlen)
{
  errctx_t ec;
  ntv_t *r = NULL;
  if(ntv_msgpack_deserialize0(data, data + length, &r, 0, &ec) == NULL)
    snprintf(errmsg, errlen, "Error at position 0x%zx: %s",
             ec.ptr - data, ec.errmsg);
  return r;
}

ntv_t *
ntv_msgpack_deserialize_nocopy(const void *data, size_t length,
                               char *errmsg, size_t errlen)
{
  errctx_t ec;
  ntv_t *r = NULL;
  if(ntv_msgpack_deserialize0(data, data + length, &r, 1, &ec) == NULL)
    snprintf(errmsg, errlen, "Error at position 0x%zx: %s",
             ec.ptr - data, ec.errmsg);
  return r;
}
