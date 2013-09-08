#pragma once

#include <alloca.h>

#include <stdint.h>
#include <sys/time.h>

#define URL_ESCAPE_PATH   1
#define URL_ESCAPE_PARAM  2

int url_escape(char *dst, const int size, const char *src, int how);

char *base64_encode(char *out, int out_size, const uint8_t *in, int in_size);

int  base64_decode(uint8_t *out, const char *in, int out_size);

#define AV_BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)

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



#define mystrdupa(n) ({ int my_l = strlen(n); \
  char *my_b = alloca(my_l + 1); \
  memcpy(my_b, n, my_l + 1); })

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


int str_tokenize(char *buf, char **vec, int vecsize, int delimiter);

