#pragma once

typedef struct strvec {
  size_t capacity;
  size_t count;
  char **v;
} strvec_t;


void strvec_push(strvec_t *vec, const char *value);

void strvec_pushl(strvec_t *vec, const char *value, size_t len);

void strvec_pushf(strvec_t *vec, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

void strvec_push_alloced(strvec_t *vec, char *value);

void strvec_reset(strvec_t *vec);

void strvec_insert(strvec_t *vec, unsigned int position, const char *value);

void strvec_delete(strvec_t *vec, unsigned int position);

int strvec_delete_value(strvec_t *vec, const char *value);

void strvec_insert_sorted(strvec_t *vec, const char *value);

int strvec_find(const strvec_t *vec, const char *value);

void strvec_copy(strvec_t *dst, const strvec_t *src);

int strvec_eq(const strvec_t *a, const strvec_t *b);

char *strvec_join(const strvec_t *src, const char *sep);

void strvec_split(strvec_t *dst, const char *str,
                  const char *sep, int include_empty);

#define strvec_get(x, i) (x)->v[i]

#define scoped_strvec(x) strvec_t x __attribute__((cleanup(strvec_reset))) = {}

