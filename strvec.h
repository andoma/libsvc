#pragma once

typedef struct strvec {
  size_t capacity;
  size_t count;
  char **v;
} strvec_t;


void strvec_push(strvec_t *vec, const char *value);

void strvec_reset(strvec_t *vec);

void strvec_insert(strvec_t *vec, int position, const char *value);

void strvec_insert_sorted(strvec_t *vec, const char *value);

int strvec_find(const strvec_t *vec, const char *value);

void strvec_copy(strvec_t *dst, const strvec_t *src);

