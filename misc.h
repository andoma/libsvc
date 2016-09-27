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

#include <alloca.h>

#include <stdint.h>
#include <sys/time.h>

#define URL_ESCAPE_PATH   1
#define URL_ESCAPE_PARAM  2

int url_escape(char *dst, const int size, const char *src, int how);

char *url_escape_tmp(const char *src, int how);

int base64_encode(char *out, int out_size, const uint8_t *in, int in_size);

int  base64_decode(uint8_t *out, const char *in, int out_size);

#define BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)

int dictcmp(const char *a, const char *b);

#define WRITEFILE_NO_CHANGE 1000000

int writefile(const char *path, const void *buf, int size);

char *readfile(const char *path, int *intptr, time_t *ts);

void url_split(char *proto, int proto_size,
               char *authorization, int authorization_size,
               char *hostname, int hostname_size,
               int *port_ptr,
               char *path, int path_size,
               const char *url);

int makedirs(const char *path);

int rm_rf(const char *path);

void get_random_bytes(void *out, size_t len);

typedef struct { uint32_t a; uint32_t b; uint32_t c; uint32_t d; } prng_t;

uint32_t prng_get(prng_t *x);

void prng_init(prng_t *x);


#define mystrdupa(n) ({ int my_l = strlen(n); \
  char *my_b = alloca(my_l + 1); \
  memcpy(my_b, n, my_l + 1); })


// Check if s1 begins with s2
static inline const char *mystrbegins(const char *s1, const char *s2)
{
  while(*s2)
    if(*s1++ != *s2++)
      return NULL;
  return s1;
}


static inline int64_t
get_ts(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}

void strset(char **p, const char *s);

int str_tokenize(char *buf, char **vec, int vecsize, int delimiter);

int hexnibble(char c);

int hex2bin(uint8_t *buf, size_t buflen, const char *str);

void bin2hex(char *dst, size_t dstlen, const uint8_t *src, size_t srclen);

const char *time_to_RFC_1123(time_t t);
#if 0
void strvec_addp(char ***str, const char *v);

void strvec_addpn(char ***str, const char *v, size_t len);

char **strvec_split(const char *str, char ch);

void strvec_free(char **s);

int strvec_len(char **s);

char **strvec_dup(char **s);
#endif

void http_deescape(char *s);

char *lp_get(char **lp);

#define LINEPARSE(out, src) for(char *lp = src, *out; (out = lp_get(&lp)) != NULL; )

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

