#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "intvec.h"


void
intvec_push(intvec_t *vec, int value)
{
  if(vec->count + 1 >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 16;
    vec->v = realloc(vec->v, sizeof(vec->v[0]) * vec->capacity);
  }
  vec->v[vec->count++] = value;
}

void
intvec_reset(intvec_t *vec)
{
  vec->count = 0;
  vec->capacity = 0;
  free(vec->v);
  vec->v = NULL;
}

void
intvec_insert(intvec_t *vec, int position, int value)
{
  if(position == vec->count)
    return intvec_push(vec, value);

  if(vec->count + 1 >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 16;
    vec->v = realloc(vec->v, sizeof(vec->v[0]) * vec->capacity);
  }

  memmove(vec->v + position + 1, vec->v + position,
          (vec->count - position) * sizeof(vec->v[0]));

  vec->v[position] = value;
  vec->count++;
}


static int
intvec_search(const intvec_t *vec, int value)
{
  int imin = 0;
  int imax = vec->count;

  while(imin < imax) {
    int imid = (imin + imax) >> 1;

    if(vec->v[imid] < value)
      imin = imid + 1;
    else
      imax = imid;
  }
  return imin;
}


void
intvec_insert_sorted(intvec_t *vec, int value)
{
  return intvec_insert(vec, intvec_search(vec, value), value);
}


int
intvec_find(const intvec_t *vec, int value)
{
  if(vec->count == 0)
    return -1;
  const int pos = intvec_search(vec, value);
  return pos < vec->count && vec->v[pos] == value ? pos : -1;
}

void
intvec_copy(intvec_t *dst, const intvec_t *src)
{
  // We trim the capacity down to the actual size here
  dst->count = dst->capacity = src->count;

  dst->v = malloc(dst->count * sizeof(dst->v[0]));
  memcpy(dst->v, src->v, dst->count * sizeof(dst->v[0]));
}


#ifdef TEST

static void
printvec(intvec_t *v)
{
  for(int i = 0; i < v->count; i++) {
    printf("%d ", v->v[i]);
  }
  printf("\n");
}


int main(void)
{
  intvec_t v = {};

  intvec_insert_sorted(&v, 5);
  printvec(&v);
  intvec_insert_sorted(&v, 3);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 1);
  printvec(&v);
  intvec_insert_sorted(&v, 11);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 7);
  printvec(&v);
  intvec_insert_sorted(&v, 1);
  printvec(&v);
  intvec_insert_sorted(&v, 1);
  printvec(&v);
  intvec_insert_sorted(&v, 1);
  printvec(&v);
  intvec_insert_sorted(&v, 1);
  printvec(&v);
  intvec_insert_sorted(&v, 0);
  printvec(&v);
  intvec_insert_sorted(&v, 11);
  printvec(&v);
  intvec_insert_sorted(&v, 12);
  printvec(&v);
  intvec_insert_sorted(&v, 13);
  printvec(&v);

  printf("Find %d = %d\n", 0, intvec_find(&v, 0));
  printf("Find %d = %d\n", 7, intvec_find(&v, 7));
  printf("Find %d = %d\n", 8, intvec_find(&v, 8));
  printf("Find %d = %d\n", 12, intvec_find(&v, 12));
  printf("Find %d = %d\n", 1200, intvec_find(&v, 1200));
  printf("Find %d = %d\n", -120, intvec_find(&v, -120));
  intvec_reset(&v);
}

#endif
