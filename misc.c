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
#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <pthread.h>
#include <dirent.h>
#include <stdarg.h>

#include "misc.h"
#include "utf8.h"
#include "threading.h"
#include "talloc.h"

#ifdef __linux__
#include <sys/syscall.h>
#include <linux/random.h>
#include <sys/prctl.h>
#endif

static const char hexchars[16] = "0123456789ABCDEF";

static const char url_escape_param[256] = {
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x00
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x10
  2,0,0,0, 0,0,0,0, 0,0,0,0, 0,1,1,0,   // 0x20
  1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,   // 0x30
  0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,   // 0x40
  1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,1,   // 0x50
  0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,   // 0x60
  1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,1,0,   // 0x70
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x80
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x90
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xa0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xb0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xc0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xd0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xe0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xf0
};



static const char url_escape_path[256] = {
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x00
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x10
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,1,1,1,   // 0x20
  1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,   // 0x30
  0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,   // 0x40
  1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,1,   // 0x50
  0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,   // 0x60
  1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,1,0,   // 0x70
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x80
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0x90
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xa0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xb0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xc0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xd0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xe0
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   // 0xf0
};

/**
 *
 */
int
url_escape(char *dst, const int size, const char *src, int how)
{
  unsigned char s;
  int r = 0;
  const char *table;

  if(how == URL_ESCAPE_PATH)
    table = url_escape_path;
  else
    table = url_escape_param;

  while((s = *src++) != 0) {
    switch(table[s]) {
    case 0:
      if(r < size - 3) {
        dst[r]   = '%';
        dst[r+1] = hexchars[(s >> 4) & 0xf];
        dst[r+2] = hexchars[s & 0xf];
      }
      r+= 3;
      break;

    case 2:
      s = '+';
      // FALLTHRU
    case 1:
      if(r < size - 1)
        dst[r] = s;
      r++;
      break;
    }
  }
  if(r < size)
    dst[r] = 0;
  return r+1;
}




static const char b64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char b64url[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const uint8_t b64_reverse[256] = {
  0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfd,0xfd,0xfd,0xfd,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3e,0xff,0x3e,0xff,0x3f,
  0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0xff,0xff,0xff,0xfe,0xff,0xff,
  0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
  0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xff,0xff,0xff,0xff,0x3f,
  0xff,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
  0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

/**
 *
 */
static int
base64_encode_mode(char *out, int out_size, const uint8_t *in, int in_size,
                   int mode)
{
  const char *table;

  switch(mode) {
  case BASE64_URL:
    table = b64url;
    break;
  default:
    table = b64;
    break;
  }

  if(BASE64_SIZE(in_size) > out_size)
    return -1;

  while(in_size >= 3) {
    *out++ = table[in[0] >> 2];
    *out++ = table[((in[0] << 4) | (in[1] >> 4)) & 0x3f];
    *out++ = table[((in[1] << 2) | (in[2] >> 6)) & 0x3f];
    *out++ = table[in[2] & 0x3f];
    in += 3;
    in_size -= 3;
  }

  switch(in_size) {
  case 0:
    break;

  case 2:
    *out++ = table[in[0] >> 2];
    *out++ = table[((in[0] << 4) | (in[1] >> 4)) & 0x3f];
    *out++ = table[(in[1] << 2) & 0x3f];
    *out++ = '=';
    break;

  case 1:
    *out++ = table[in[0] >> 2];
    *out++ = table[(in[0] << 4) & 0x3f];
    *out++ = '=';
    *out++ = '=';
    break;
  }
  *out = 0;
  return 0;
}

int
base64_encode(char *out, int out_size, const void *in, int in_size)
{
  return base64_encode_mode(out, out_size, in, in_size, 0);
}


char *
base64_encode_a(const void *in, int in_size, int mode)
{
  size_t out_size = BASE64_SIZE(in_size);
  char *out = malloc(out_size);
  base64_encode_mode(out, out_size, in, in_size, mode);
  return out;

}

/**
 *
 */
int
base64_decode(uint8_t *out, const char *in, int out_size)
{
  uint8_t *t = out;
  uint32_t acc = 0;
  int i;
  int j = 0;
  for(i = 0; ; i++) {
    uint8_t val = b64_reverse[(int)in[i]];
    if(val == 0xff)
      return -1;  // Bad symbol
    if(val == 0xfe)
      break;      // End (NUL or '=' char)
    if(val == 0xfd)
      continue;   // Ignore
    acc = (acc << 6) + val;
    if(j & 3) {
      if(t - out < out_size)
        *t++ = acc >> (6 - 2 * (j & 3));
    }
    j++;
  }
  return t - out;
}


/**
 *
 */
int
dictcmp(const char *a, const char *b)
{
  long int da, db;
  int ua, ub;

  while(1) {

    ua = utf8_get(&a, NULL);
    ub = utf8_get(&b, NULL);

    switch((ua >= '0' && ua <= '9' ? 1 : 0)|(ub >= '0' && ub <= '9' ? 2 : 0)) {
    case 0:  /* 0: a is not a digit, nor is b */

      if(ua != ub) {
        //        ua = unicode_casefold(ua);
        //        ub = unicode_casefold(ub);
        if(ua != ub)
          return ua - ub;
      }
      if(ua == 0)
        return 0;
      break;
    case 1:  /* 1: a is a digit,  b is not */
    case 2:  /* 2: a is not a digit,  b is */
      return ua - ub;
    case 3:  /* both are digits, switch to integer compare */
      da = ua - '0';
      db = ub - '0';

      while(*a >= '0' && *a <= '9')
        da = da * 10L + *a++ - '0';
      while(*b >= '0' && *b <= '9')
        db = db * 10L + *b++ - '0';
      if(da != db)
        return da - db;
      break;
    }
  }
}


/**
 *
 */
int
writefile(const char *path, const void *buf, int size, int checksame)
{
  int r, fd;

  if(checksame) {
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd != -1) {
      struct stat st;
      if(!fstat(fd, &st)) {
        if(st.st_size == size) {
          void *tmp = malloc(size);
          int r = read(fd, tmp, size);
          int same = r == size && !memcmp(tmp, buf, size);
          free(tmp);
          if(same) {
            close(fd);
            return WRITEFILE_NO_CHANGE;
          }
        }
      }
      close(fd);
    }
  }
  char pathtmp[PATH_MAX];
  snprintf(pathtmp, sizeof(pathtmp), "%s.tmp", path);

  fd = open(pathtmp, O_TRUNC | O_CREAT | O_WRONLY | O_CLOEXEC, 0664);
  if(fd == -1)
    return errno;

  if(write(fd, buf, size) != size)
    goto bad;

  close(fd);
  if(rename(pathtmp, path))
    return errno;

  return 0;

 bad:
  r = errno;
  close(fd);
  return r;
}


/**
 *
 */
char *
readfile(const char *path, time_t *tsp)
{
  struct stat st;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if(fd == -1) {
    return NULL;
  }

  if(fstat(fd, &st)) {
    const int errsave = errno;
    close(fd);
    errno = errsave;
    return NULL;
  }

  if(tsp != NULL)
    *tsp = st.st_mtime;

  char *mem = malloc_add(st.st_size, 1);
  mem[st.st_size] = 0;
  if(read(fd, mem, st.st_size) != st.st_size) {
    const int errsave = errno;
    free(mem);
    close(fd);
    errno = errsave;
    return NULL;
  }
  close(fd);
  return mem;
}


/**
 *
 */
void
get_random_bytes(void *out, size_t len)
{
  static int fd = -1;

  int r;
#if defined(__linux__) && defined(SYS_getrandom)
  while(len > 0) {
    r = syscall(SYS_getrandom, out, len, 0);
    if(r == -1) {
      if(errno == ENOSYS)
        goto fallback;
      if(errno == EINTR)
        continue;
      abort();
    }
    if(r == 0)
      abort();

    out += r;
    len -= r;
  }
  return;
 fallback:
#endif

  if(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(fd == -1)
      abort();
  }

  while(len > 0) {
    r = read(fd, out, len);
    if(r == -1) {
      if(errno == EINTR || errno == EAGAIN)
        continue;
      abort();
    }

    if(r == 0)
      abort();

    out += r;
    len -= r;
  }
}


/**
 *
 */
int
rm_rf(const char *path, int remove_self)
{
  struct dirent **namelist;
  char fullpath[PATH_MAX];
  int n = scandir(path, &namelist, NULL, alphasort);
  if(n < 0)
    return -1;

  int err = 0;
  while(n--) {
    const char *name = namelist[n]->d_name;
    if(strcmp(name, ".") && strcmp(name, "..")) {
      snprintf(fullpath, sizeof(fullpath), "%s/%s", path, name);
      int type = namelist[n]->d_type;
      if(type == DT_FIFO || type == DT_LNK || type == DT_REG || type == DT_SOCK) {
        if(unlink(fullpath)) {
          err |= 1;
        }
      }
      if(type == DT_DIR)
        err |= rm_rf(fullpath, 1);
    }
    free(namelist[n]);
  }
  free(namelist);
  if(remove_self) {
    if(rmdir(path)) {
      err |= 1;
    }
  }
  return err;
}


/**
 *
 */
int
mkdir_p(const char *path, int mode)
{
  if(*path == 0) {
    errno = EINVAL;
    return -1;
  }
  char *s = mystrdupa(path);

  for(char *p = s + 1; *p; p++) {
    if(*p == '/') {
      *p = 0;
      if(mkdir(s, mode) == -1 && errno != EEXIST)
        return -1;
      *p = '/';
    }
  }
  if(mkdir(s, mode) == -1 && errno != EEXIST)
    return -1;
  return 0;
}


/**
 *
 */
int
mkdir_chown_p(const char *path, uid_t uid, uid_t gid, int mode)
{
  if(*path == 0) {
    errno = EINVAL;
    return -1;
  }
  char *s = mystrdupa(path);

  for(char *p = s + 1; *p; p++) {
    if(*p == '/') {
      *p = 0;
      if(mkdir(s, mode) == -1 && errno != EEXIST)
        return -1;
      if(lchown(s, uid, gid) == -1)
        return -1;
      *p = '/';
    }
  }
  if(mkdir(s, mode) == -1 && errno != EEXIST)
    return -1;
  return lchown(s, uid, gid);
}


/**
 *
 */
void
mutex_unlock_ptr(pthread_mutex_t **p)
{
  pthread_mutex_unlock(*p);
}


/*
 * Split a string in components delimited by 'delimiter'
 */
int
str_tokenize(char *buf, char **vec, int vecsize, int delimiter)
{
  int n = 0;

  while(1) {
    while((*buf > 0 && *buf < 33) || *buf == delimiter)
      buf++;
    if(*buf == 0)
      break;
    vec[n++] = buf;
    if(n == vecsize)
      break;
    while(*buf > 32 && *buf != delimiter)
      buf++;
    if(*buf == 0)
      break;
    *buf = 0;
    buf++;
  }
  return n;
}


/**
 *
 */
int
hexnibble(char c)
{
  switch(c) {
  case '0' ... '9':    return c - '0';
  case 'a' ... 'f':    return c - 'a' + 10;
  case 'A' ... 'F':    return c - 'A' + 10;
  default:
    return -1;
  }
}


/**
 *
 */
int
hex2bin(uint8_t *buf, size_t buflen, const char *str)
{
  int hi, lo;
  size_t bl = buflen;
  while(*str) {
    if(buflen == 0)
      return -1;
    if((hi = hexnibble(*str++)) == -1)
      return -1;
    if((lo = hexnibble(*str++)) == -1)
      return -1;

    *buf++ = hi << 4 | lo;
    buflen--;
  }
  return bl - buflen;
}


/**
 *
 */
void
bin2hex(char *dst, size_t dstlen, const uint8_t *src, size_t srclen)
{
  while(dstlen > 2 && srclen > 0) {
    *dst++ = "0123456789abcdef"[*src >> 4];
    *dst++ = "0123456789abcdef"[*src & 0xf];
    src++;
    srclen--;
    dstlen -= 2;
  }
  *dst = 0;
}


/**
 *
 */
void
strset(char **p, const char *s)
{
  free(*p);
  *p = s ? strdup(s) : NULL;
}



static const char *days[7] = {
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *months[12] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
  "Dec"
};


/**
 *
 */
const char *
time_to_RFC_1123(time_t t)
{
  static __thread char rbuf[64];
  struct tm tm0, *tm;

  tm = gmtime_r(&t, &tm0);
  snprintf(rbuf, sizeof(rbuf),
           "%s, %02d %s %02d %02d:%02d:%02d +0000",
           days[tm->tm_wday], tm->tm_mday,
           months[tm->tm_mon], tm->tm_year + 1900,
           tm->tm_hour, tm->tm_min, tm->tm_sec);

  return rbuf;
}


/**
 *
 */
char *
url_escape_tmp(const char *src, int how)
{
  int len = url_escape(NULL, 0, src, how);
  char *r = talloc_malloc(len);
  url_escape(r, len, src, how);
  return r;
}

/**
 *
 */
char *
url_escape_alloc(const char *src, int how)
{
  int len = url_escape(NULL, 0, src, how);
  char *r = malloc(len);
  url_escape(r, len, src, how);
  return r;
}




/**
 *
 */
char *
lp_get(char **lp)
{
  char *r;
  do {
    if(*lp == NULL)
      return NULL;
    r = *lp;
    int l = strcspn(r, "\r\n");
     if(r[l] == 0) {
      *lp = NULL;
    } else {
      r[l] = 0;
      char *s = r + l + 1;
      while(*s == '\r' || *s == '\n')
        s++;
      *lp = s;
    }
  } while(*r == 0);
  return r;
}




// PRNG from http://burtleburtle.net/bob/rand/smallprng.html (Public Domain)

#define rot(x,k) (((x)<<(k))|((x)>>(32-(k))))
uint32_t
prng_get(prng_t *x)
{
    uint32_t e = x->a - rot(x->b, 27);
    x->a = x->b ^ rot(x->c, 17);
    x->b = x->c + x->d;
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}


void
prng_init(prng_t *x)
{
  get_random_bytes(x, sizeof(prng_t));
  x->a = 0xf1ea5eed;
  for(int i=0; i<20; i++) {
    prng_get(x);
  }
}


/**
 * De-escape HTTP query args
 */
void
http_deescape(char *s)
{
  char v, *d = s;

  while(*s) {
    if(*s == '+') {
      *d++ = ' ';
      s++;
    } else if(*s == '%') {
      s++;
      switch(*s) {
      case '0' ... '9':
	v = (*s - '0') << 4;
	break;
      case 'a' ... 'f':
	v = (*s - 'a' + 10) << 4;
	break;
      case 'A' ... 'F':
	v = (*s - 'A' + 10) << 4;
	break;
      default:
	*d = 0;
	return;
      }
      s++;
      switch(*s) {
      case '0' ... '9':
	v |= (*s - '0');
	break;
      case 'a' ... 'f':
	v |= (*s - 'a' + 10);
	break;
      case 'A' ... 'F':
	v |= (*s - 'A' + 10);
	break;
      default:
	*d = 0;
	return;
      }
      s++;

      *d++ = v;
    } else {
      *d++ = *s++;
    }
  }
  *d = 0;
}


size_t
html_enteties_escape(const char *src, char *dst)
{
  size_t olen = 0;
  const char *entity = NULL;
  for(;*src;src++) {
    switch(*src) {
    case 38:
      entity = "amp";
      break;
    case 60:
      entity = "lt";
      break;
    case 62:
      entity = "gt";
      break;
    default:
      if(dst) dst[olen] = *src;
      olen++;
      continue;
    }
    if(dst) {
      dst[olen++] = '&';
      while(*entity)
	dst[olen++] = *entity++;
      dst[olen++] = ';';
    } else {
      olen += 2 + strlen(entity);
    }
  }
  if(dst)
    dst[olen] = 0;
  olen++;
  return olen;
}


const char *
html_enteties_escape_tmp(const char *src)
{
  size_t len = html_enteties_escape(src, NULL);
  char *r = talloc_malloc(len);
  html_enteties_escape(src, r);
  return r;
}

char *
str_replace_tokens(char *str, const char *tokenprefix,
		   const char *tokenpostfix,
		   const char **tokens)
{
  const size_t prelen = strlen(tokenprefix);
  const size_t postlen = strlen(tokenpostfix);

  int tlen = strlen(str);
  char *curpos = str;
  int i;

  while(1) {
    char *a = strstr(curpos, tokenprefix);
    if(a == NULL)
      break;
    char *b = a + prelen;

    char *c = strstr(b, tokenpostfix);
    if(c == NULL)
      break;

    char *d = c + postlen;

    char save = *c;
    *c = 0; // replace token end with \0 so we can strcmp()

    for(i = 0; tokens[i] != NULL; i+=2) {
      if(!strcmp(tokens[i], b))
	break;
    }

    *c = save;
    if(tokens[i] == NULL) {
      // Lookup failed
      curpos = d;
      continue;
    }

    int replacelen = strlen(tokens[i + 1]);
    int newlen = tlen - (d - a) + replacelen;

    char *n = malloc_add(newlen, 1);
    memcpy(n, str, a - str);
    memcpy(n + (a - str), tokens[i + 1], replacelen);
    memcpy(n + (a - str) + replacelen, d, tlen - (d - str));
    n[newlen] = 0;

    curpos = n + (a - str) + replacelen;
    tlen = newlen;
    free(str);
    str = n;
  }
  return str;
}


char *
bin2str(const void *src, size_t len)
{
  char *r = malloc_add(len, 1);
  r[len] = 0;
  memcpy(r, src, len);
  return r;
}


void
freecharp(char **ptr)
{
  free(*ptr);
  *ptr = NULL;
}

void
freeuint8p(uint8_t **ptr)
{
  free(*ptr);
  *ptr = NULL;
}


char *
fmtv(const char *fmt, va_list ap)
{
  char *ret;
  if(vasprintf(&ret, fmt, ap) == -1)
    abort();
  return ret;
}

char *
fmt(const char *fmt, ...)
{
  va_list ap;
  char *ret;
  va_start(ap, fmt);
  ret = fmtv(fmt, ap);
  va_end(ap);
  return ret;
}



void
set_thread_namef(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  scoped_char *name = fmtv(fmt, ap);
  va_end(ap);
#if defined(__linux__)
  prctl(PR_SET_NAME, name, 0, 0, 0);
#elif defined(__APPLE__)
  pthread_setname_np(name);
#endif
}



int64_t
get_ts(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}


int64_t
get_ts_mono(void)
{
  struct timespec tv;
  clock_gettime(CLOCK_MONOTONIC, &tv);
  return (int64_t)tv.tv_sec * 1000000LL + (tv.tv_nsec / 1000);
}


void *
malloc_add(size_t a, size_t b)
{
#if !defined(__clang__) && __GNUC__ < 5
  if(a >= __SIZE_MAX__ / 2)
    return NULL;
  if(b >= __SIZE_MAX__ / 2)
    return NULL;
  return malloc(a + b);
#else
  size_t c;
  if(__builtin_add_overflow(a, b, &c))
    return NULL;
  return malloc(c);
#endif
}

void *
malloc_mul(size_t a, size_t b)
{
#if !defined(__clang__) && __GNUC__ < 5

#if __SIZEOF_SIZE_T__ == 4
  uint64_t c = a * b;
  if(c >= __SIZE_MAX__)
    return NULL;
  return malloc(c);
#else
  if(a >= 4294967295)
    return NULL;
  if(b >= 4294967295)
    return NULL;
  return malloc(a * b);
#endif
 

#else
  size_t c;
  if(__builtin_mul_overflow(a, b, &c))
    return NULL;
  return malloc(c);
#endif
}


static int digit(char s)
{
  return s >= '0' && s <= '9';
}

static int
parse_tz_offset(const char *s)
{
  if(strlen(s) == 4 &&
     digit(s[0]) &&
     digit(s[1]) &&
     digit(s[2]) &&
     digit(s[3])) {
    const int x = atoi(s);
    return (x / 100) * 3600 + (x % 100) * 60;
  }

  if(strlen(s) == 2 &&
     digit(s[0]) &&
     digit(s[1])) {
    return atoi(s) * 3600;
  }

  if(strlen(s) == 5 &&
     digit(s[0]) &&
     digit(s[1]) &&
     s[2] == ':' &&
     digit(s[3]) &&
     digit(s[4])) {

    const int h = atoi(s);
    const int m = atoi(s + 3);
    return h * 3600 + m * 60;
  }
  return 0;
}


int64_t
rfc3339_date_parse(const char *s, int roundup)
{
  struct tm tm = {};

  if(strlen(s) < 10)
    return INT64_MIN;

  if(s[4] != '-'  || s[7] != '-')
    return INT64_MIN;

  tm.tm_isdst = -1;
  tm.tm_year = atoi(s + 0) - 1900;
  tm.tm_mon  = atoi(s + 5) - 1;
  tm.tm_mday = atoi(s + 8);

  uint64_t us = 0;

  if(roundup) {
    tm.tm_hour = 23;
    tm.tm_min  = 59;
    tm.tm_sec  = 59;
    us = 999999;
  }

  int tz_offset = 0;

  if(s[10] == 0) {
    // Date only

  } else if(s[10] == 'T') {
    s += 11;
    tm.tm_hour = atoi(s);
    if(strlen(s) > 3 && s[2] == ':') {
      tm.tm_min  = atoi(s + 3);

      if(strlen(s) > 6 && s[5] == ':') {
        tm.tm_sec  = atoi(s + 6);

        if(strlen(s) > 8 && s[8] == '.') {
          s += 9;
          uint64_t fractions = atoi(s);
          int divisor = 1;
          while(*s >= '0' && *s <= '9') {
            divisor *= 10;
            s++;
          }
          us = fractions * 1000000 / divisor;
        }
      }
    }
    const char *plus = strchr(s, '+');
    if(plus != NULL) {
      tz_offset = parse_tz_offset(plus + 1);
    } else {
      const char *minus = strchr(s, '-');
      if(minus != NULL)
        tz_offset = -parse_tz_offset(minus + 1);
    }

  } else {
    return INT64_MIN;
  }

  const time_t datetime_1970 = timegm(&tm) - tz_offset;

  return datetime_1970 * (int64_t)1000000 + us;
}

