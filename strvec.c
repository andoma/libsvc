#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "strvec.h"


void
strvec_push(strvec_t *vec, const char *value)
{
  if(vec->count + 1 >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 16;
    vec->v = realloc(vec->v, sizeof(vec->v[0]) * vec->capacity);
  }
  vec->v[vec->count++] = strdup(value);
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
strvec_insert(strvec_t *vec, int position, const char *value)
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

void
strvec_copy(strvec_t *dst, const strvec_t *src)
{
  // We trim the capacity down to the actual size here
  dst->count = dst->capacity = src->count;

  dst->v = malloc(dst->count * sizeof(dst->v[0]));
  for(int i = 0; i < dst->count; i++)
    dst->v[i] = strdup(src->v[i]);
}

