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

#include "misc.h"
#include "utf8.h"
#include "threading.h"
#include "talloc.h"

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

static const uint8_t b64_reverse[256] = {
  0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfd,0xfd,0xfd,0xfd,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3e,0xff,0xff,0xff,0x3f,
  0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0xff,0xff,0xff,0xfe,0xff,0xff,
  0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
  0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xff,0xff,0xff,0xff,0xff,
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
int
base64_encode(char *out, int out_size, const uint8_t *in, int in_size)
{
  if(BASE64_SIZE(in_size) > out_size)
    return -1;

  while(in_size >= 3) {
    *out++ = b64[in[0] >> 2];
    *out++ = b64[((in[0] << 4) | (in[1] >> 4)) & 0x3f];
    *out++ = b64[((in[1] << 2) | (in[2] >> 6)) & 0x3f];
    *out++ = b64[in[2] & 0x3f];
    in += 3;
    in_size -= 3;
  }

  switch(in_size) {
  case 0:
    break;

  case 2:
    *out++ = b64[in[0] >> 2];
    *out++ = b64[((in[0] << 4) | (in[1] >> 4)) & 0x3f];
    *out++ = b64[(in[1] << 2) & 0x3f];
    *out++ = '=';
    break;

  case 1:
    *out++ = b64[in[0] >> 2];
    *out++ = b64[(in[0] << 4) & 0x3f];
    *out++ = '=';
    *out++ = '=';
    break;
  }
  *out = 0;
  return 0;
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

    ua = utf8_get(&a);
    ub = utf8_get(&b);

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
writefile(const char *path, const void *buf, int size)
{
  int r, fd;

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
readfile(const char *path, int *errptr, time_t *tsp)
{
  struct stat st;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if(fd == -1) {
    if(errptr)
      *errptr = errno;
    return NULL;
  }

  if(fstat(fd, &st)) {
    if(errptr)
      *errptr = errno;
    close(fd);
    return NULL;
  }

  if(tsp != NULL)
    *tsp = st.st_mtime;

  char *mem = malloc(st.st_size + 1);
  mem[st.st_size] = 0;
  if(read(fd, mem, st.st_size) != st.st_size) {
    if(errptr)
      *errptr = errno;
    free(mem);
    mem = NULL;
  }
  close(fd);
  return mem;
}


/**
 *
 */
int
get_random_bytes(void *out, size_t len)
{
  static int fd = -1;
  if(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(fd == -1)
      return -1;
  }

  if(read(fd, out, len) != len)
    return -1;
  return 0;
}



/**
 *
 */
void 
url_split(char *proto, int proto_size,
          char *authorization, int authorization_size,
          char *hostname, int hostname_size,
          int *port_ptr,
          char *path, int path_size,
          const char *url)
{
  const char *p, *ls, *at, *col, *brk;

  if (port_ptr)               *port_ptr = -1;
  if (proto_size > 0)         proto[0] = 0;
  if (authorization_size > 0) authorization[0] = 0;
  if (hostname_size > 0)      hostname[0] = 0;
  if (path_size > 0)          path[0] = 0;

  /* parse protocol */
  if ((p = strchr(url, ':'))) {
    snprintf(proto, MIN(proto_size, p + 1 - url), "%s", url);
    p++; /* skip ':' */
    if (*p == '/') p++;
    if (*p == '/') p++;
  } else {
    /* no protocol means plain filename */
    snprintf(path, path_size, "%s", url);
    return;
  }

  /* separate path from hostname */
  ls = strchr(p, '/');
  if(!ls)
    ls = strchr(p, '?');
  if(ls)
    snprintf(path, path_size, "%s", ls);
  else
    ls = &p[strlen(p)]; // XXX

  /* the rest is hostname, use that to parse auth/port */
  if (ls != p) {
    /* authorization (user[:pass]@hostname) */
    if ((at = strchr(p, '@')) && at < ls) {
      snprintf(authorization, MIN(authorization_size, at + 1 - p), "%s", p);
      p = at + 1; /* skip '@' */
    }

    if (*p == '[' && (brk = strchr(p, ']')) && brk < ls) {
      /* [host]:port */
      snprintf(hostname, MIN(hostname_size, brk - p), "%s", p + 1);
      if (brk[1] == ':' && port_ptr)
        *port_ptr = atoi(brk + 2);
    } else if ((col = strchr(p, ':')) && col < ls) {
      snprintf(hostname, MIN(col + 1 - p, hostname_size), "%s", p);
      if (port_ptr) *port_ptr = atoi(col + 1);
    } else
      snprintf(hostname, MIN(ls + 1 - p, hostname_size), "%s", p);
  }
}


/**
 *
 */
int
rm_rf(const char *path)
{
  struct dirent **namelist;
  char fullpath[PATH_MAX];
  int n = scandir(path, &namelist, NULL, alphasort);
  if(n < 0)
    return -1;

  while(n--) {
    const char *name = namelist[n]->d_name;
    if(strcmp(name, ".") && strcmp(name, "..")) {
      snprintf(fullpath, sizeof(fullpath), "%s/%s", path, name);
      int type = namelist[n]->d_type;
      if(type == DT_FIFO || type == DT_LNK || type == DT_REG || type == DT_SOCK) {
        unlink(fullpath);
      }
      if(type == DT_DIR)
        rm_rf(fullpath);
    }
    free(namelist[n]);
  }
  free(namelist);
  rmdir(path);
  return 0;
}


/**
 *
 */
int
makedirs(const char *path)
{
  struct stat st;
  char *p;
  int l, r;

  if(path == NULL)
    return EINVAL;

  if(stat(path, &st) == 0 && S_ISDIR(st.st_mode))
    return 0; /* Dir already there */

  if(mkdir(path, 0777) == 0)
    return 0; /* Dir created ok */

  if(errno == ENOENT) {

    /* Parent does not exist, try to create it */
    /* Allocate new path buffer and strip off last directory component */

    l = strlen(path);
    p = alloca(l + 1);
    memcpy(p, path, l);
    p[l--] = 0;

    for(; l >= 0; l--)
      if(p[l] == '/')
        break;
    if(l == 0) {
      return ENOENT;
    }
    p[l] = 0;

    if((r = makedirs(p)) != 0)
      return r;

    /* Try again */
    if(mkdir(path, 0777) == 0)
      return 0; /* Dir created ok */
  }
  r = errno;
  return r;
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
char **
strvec_split(const char *str, char ch)
{
  const char *s;
  int c = 1, i;
  char **r;

  for(s = str; *s != 0; s++)
    if(*s == ch)
      c++;

  r = malloc(sizeof(char *) * (c + 1));
  for(i = 0; i < c; i++) {
    s = strchr(str, ch);
    if(s == NULL) {
      assert(i == c - 1);
      r[i] = strdup(str);
    } else {
      r[i] = malloc(s - str + 1);
      memcpy(r[i], str, s - str);
      r[i][s - str] = 0;
      str = s + 1;
    }
  }
  r[i] = NULL;
  return r;
}


/**
 *
 */
void
strvec_free(char **s)
{
  if(s == NULL)
    return;
  void *m = s;
  for(;*s != NULL; s++)
    free(*s);
  free(m);
}


/**
 *
 */
void 
strvec_addpn(char ***strvp, const char *v, size_t len)
{
  char **strv = *strvp;
  int i = 0;
  if(strv == NULL) {
    strv = malloc(sizeof(char *) * 2);
  } else {
    while(strv[i] != NULL)
      i++;
    strv = realloc(strv, sizeof(char *) * (i + 2));
  }
  strv[i] = memcpy(malloc(len + 1), v, len);
  strv[i][len] = 0;
  strv[i+1] = NULL;
  *strvp = strv;
}

/**
 *
 */
void 
strvec_addp(char ***strvp, const char *v)
{
  strvec_addpn(strvp, v, strlen(v));
}


/**
 *
 */
int
strvec_len(char **s)
{
  int len = 0;
  while(*s != NULL) {
    len++;
    s++;
  }
  return len;
}


/**
 *
 */
char **
strvec_dup(char **s)
{
  int i, len = strvec_len(s);
  char **ret;

  ret = malloc(sizeof(char *) * (len + 1));
  for(i = 0; i < len; i++)
    ret[i] = strdup(s[i]);
  ret[i] = NULL;
  return ret;
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
