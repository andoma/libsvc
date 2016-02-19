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

#pragma once
#include <string.h>
#include <stdint.h>

static __inline void wr64_be(uint8_t *ptr, uint64_t val)
{
#if !defined(__BIG_ENDIAN__)
  val = __builtin_bswap64(val);
#endif
  memcpy(ptr, &val, 8);
}


static __inline void wr32_be(uint8_t *ptr, uint32_t val)
{
#if !defined(__BIG_ENDIAN__)
  val = __builtin_bswap32(val);
#endif
  memcpy(ptr, &val, 4);
}


static __inline void wr16_be(uint8_t *ptr, uint16_t val)
{
#if !defined(__BIG_ENDIAN__)
  val = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
#endif
  memcpy(ptr, &val, 2);
}



static __inline uint64_t rd64_be(const uint8_t *ptr)
{
  uint64_t val;
  memcpy(&val, ptr, 8);
#if !defined(__BIG_ENDIAN__)
  val = __builtin_bswap64(val);
#endif
  return val;
}


static __inline uint32_t rd32_be(const uint8_t *ptr)
{
  uint32_t val;
  memcpy(&val, ptr, 4);
#if !defined(__BIG_ENDIAN__)
  val = __builtin_bswap32(val);
#endif
  return val;
}



static __inline uint16_t rd16_be(const uint8_t *ptr)
{
  uint16_t val;
  memcpy(&val, ptr, 2);
#if !defined(__BIG_ENDIAN__)
  val = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
#endif
  return val;
}




static __inline void wr64_le(uint8_t *ptr, uint64_t val)
{
#if defined(__BIG_ENDIAN__)
  val = __builtin_bswap64(val);
#endif
  memcpy(ptr, &val, 8);
}


static __inline void wr32_le(uint8_t *ptr, uint32_t val)
{
#if defined(__BIG_ENDIAN__)
  val = __builtin_bswap32(val);
#endif
  memcpy(ptr, &val, 4);
}


static __inline void wr16_le(uint8_t *ptr, uint16_t val)
{
#if defined(__BIG_ENDIAN__)
  val = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
#endif
  memcpy(ptr, &val, 2);
}



static __inline uint64_t rd64_le(const uint8_t *ptr)
{
  uint64_t val;
  memcpy(&val, ptr, 8);
#if defined(__BIG_ENDIAN__)
  val = __builtin_bswap64(val);
#endif
  return val;
}


static __inline uint32_t rd32_le(const uint8_t *ptr)
{
  uint32_t val;
  memcpy(&val, ptr, 4);
#if defined(__BIG_ENDIAN__)
  val = __builtin_bswap32(val);
#endif
  return val;
}



static __inline uint16_t rd16_le(const uint8_t *ptr)
{
  uint16_t val;
  memcpy(&val, ptr, 2);
#if defined(__BIG_ENDIAN__)
  val = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
#endif
  return val;
}
