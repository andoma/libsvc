#pragma once

typedef struct intvec {
  size_t capacity;
  size_t count;
  int *v;
} intvec_t;


void intvec_push(intvec_t *vec, int value);

void intvec_reset(intvec_t *vec);

void intvec_insert(intvec_t *vec, int position, int value);

void intvec_delete(intvec_t *vec, unsigned int position);

int intvec_insert_sorted(intvec_t *vec, int value);

int intvec_find(const intvec_t *vec, int value);

void intvec_copy(intvec_t *dst, const intvec_t *src);

#define intvec_get(x, i) (x)->v[i]

#define scoped_intvec(x) intvec_t x __attribute__((cleanup(intvec_reset))) = {}

