#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "strvec.h"
#include "misc.h"

static void
strvec_inc(strvec_t *vec)
{
  if(vec->count + 1 >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 16;
    vec->v = realloc(vec->v, sizeof(vec->v[0]) * vec->capacity);
  }
}


void
strvec_push(strvec_t *vec, const char *value)
{
  strvec_inc(vec);
  vec->v[vec->count++] = value ? strdup(value) : NULL;
}

void
strvec_push_alloced(strvec_t *vec, char *value)
{
  strvec_inc(vec);
  vec->v[vec->count++] = value;
}


static void
strvec_pushl(strvec_t *vec, const char *value, size_t len)
{
  char *x = malloc(len + 1);
  memcpy(x, value, len);
  x[len] = 0;
  strvec_push_alloced(vec, x);
}


void
strvec_pushf(strvec_t *vec, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  strvec_push_alloced(vec, fmtv(fmt, ap));
  va_end(ap);
}

void
strvec_reset(strvec_t *vec)
{
  for(int i = 0; i < vec->count; i++)
    free(vec->v[i]);
  vec->count = 0;
  vec->capacity = 0;
  free(vec->v);
  vec->v = NULL;
}

void
strvec_insert(strvec_t *vec, unsigned int position, const char *value)
{
  if(position == vec->count)
    return strvec_push(vec, value);

  if(vec->count + 1 >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 16;
    vec->v = realloc(vec->v, sizeof(vec->v[0]) * vec->capacity);
  }

  memmove(vec->v + position + 1, vec->v + position,
          (vec->count - position) * sizeof(vec->v[0]));

  vec->v[position] = strdup(value);
  vec->count++;
}


void
strvec_delete(strvec_t *vec, unsigned int position)
{
  assert(position < vec->count);
  memmove(vec->v + position, vec->v + position + 1,
          (vec->count - position - 1) * sizeof(vec->v[0]));
  vec->count--;
}


static int
strvec_search(const strvec_t *vec, const char *value)
{
  int imin = 0;
  int imax = vec->count;

  while(imin < imax) {
    int imid = (imin + imax) >> 1;

    if(strcmp(vec->v[imid], value) < 0)
      imin = imid + 1;
    else
      imax = imid;
  }
  return imin;
}


void
strvec_insert_sorted(strvec_t *vec, const char *value)
{
  return strvec_insert(vec, strvec_search(vec, value), value);
}


int
strvec_find(const strvec_t *vec, const char *value)
{
  if(vec->count == 0)
    return -1;
  const int pos = strvec_search(vec, value);
  return pos < vec->count && !strcmp(vec->v[pos], value) ? pos : -1;
}


int
strvec_delete_value(strvec_t *vec, const char *value)
{
  if(vec->count == 0)
    return -1;
  const int pos = strvec_find(vec, value);
  if(pos >= 0)
    strvec_delete(vec, pos);
  return pos;
}

void
strvec_copy(strvec_t *dst, const strvec_t *src)
{
  // We trim the capacity down to the actual size here
  dst->count = dst->capacity = src->count;

  dst->v = malloc(dst->count * sizeof(dst->v[0]));
  for(int i = 0; i < dst->count; i++)
    dst->v[i] = src->v[i] ? strdup(src->v[i]) : NULL;
}


char *
strvec_join(const strvec_t *src, const char *sep)
{
  int totlen = 1;
  const int seplen = strlen(sep);
  for(int i = 0; i < src->count; i++) {
    if(src->v[i])
      totlen += strlen(src->v[i]) + (i ? seplen : 0);
  }

  char *r = malloc(totlen);
  int off = 0;
  for(int i = 0; i < src->count; i++) {
    if(src->v[i]) {
      if(i) {
        memcpy(r + off, sep, seplen);
        off += seplen;
      }
      const int len = strlen(src->v[i]);
      memcpy(r + off, src->v[i], len);
      off += len;
    }
  }
  r[off] = 0;
  return r;
}


void
strvec_split(strvec_t *dst, const char *str, const char *sep, int include_empty)
{
  size_t seplen = strlen(sep);
  while(str) {
    const char *next = strstr(str, sep);
    size_t len = next ? next - str : strlen(str);
    if(len > 0 || include_empty)
      strvec_pushl(dst, str, len);

    if(next)
      next += seplen;
    str = next;
  }

}
