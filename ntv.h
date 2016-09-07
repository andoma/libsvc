#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "queue.h"

TAILQ_HEAD(ntv_queue, ntv);

typedef struct ntv_namespace {
  int refcount;
  char *str;
} ntv_namespace;


typedef enum {
  NTV_XML_ATTRIBUTE = 0x1,

} ntv_flags;

typedef enum {
  NTV_NULL,
  NTV_BOOLEAN,
  NTV_STRING,
  NTV_INT,
  NTV_DOUBLE,
  NTV_BINARY,
  NTV_MAP,
  NTV_LIST,

} ntv_type;



typedef struct ntv {

  TAILQ_ENTRY(ntv) ntv_link;
  struct ntv *ntv_parent;

  char *ntv_name;
  ntv_flags ntv_flags;
  ntv_type ntv_type;

  ntv_namespace *ntv_namespace;

  union {
    int64_t ntv_s64;
    char *ntv_string;
    struct {
      void *ntv_bin;
      size_t ntv_binsize;
    };
    double ntv_double;
    bool ntv_boolean;
  };

  struct ntv_queue ntv_children;

} ntv;


// Misc toplevel functions

ntv *ntv_create_map(void);
ntv *ntv_create_list(void);

void ntv_release(ntv *ntv);
void ntv_print(ntv *ntv);

// Get operations on maps

int     ntv_get_int(const ntv *ntv, const char *key, int default_value);
int64_t ntv_get_int64(const ntv *ntv, const char *key, int64_t default_value);
double  ntv_get_double(const ntv *ntv, const char *key, double default_value);
const char *ntv_get_str(const ntv *ntv, const char *key);

const ntv  *ntv_get_map(const ntv *ntv, const char *key);
const ntv  *ntv_get_list(const ntv *ntv, const char *key);

// Get operations on lists

int     ntv_idx_int(const ntv *ntv, int idx, int default_value);
int64_t ntv_idx_int64(const ntv *ntv, int idx, int64_t default_value);
double  ntv_idx_double(const ntv *ntv, int idx, double default_value);
const char *ntv_idx_str(const ntv *ntv, int idx);

const ntv  *ntv_idx_map(const ntv *ntv, int idx);
const ntv  *ntv_idx_list(const ntv *ntv, int idx);

// Set operations on maps

void ntv_set_int(ntv *ntv, const char *key, int value);
void ntv_set_int64(ntv *ntv, const char *key, int64_t value);
void ntv_set_double(ntv *ntv, const char *key, double value);
void ntv_set_str(ntv *ntv, const char *key, const char *value);
void ntv_set_ntv(ntv *ntv, const char *key, struct ntv *sub);

// Set operations on lists

void ntv_set_idx_int(ntv *ntv, int key, int value);
void ntv_set_idx_int64(ntv *ntv, int key, int64_t value);
void ntv_set_idx_double(ntv *ntv, int key, double value);
void ntv_set_idx_str(ntv *ntv, int key, const char *value);
void ntv_set_idx_ntv(ntv *ntv, int key, struct ntv *sub);



#if __STDC_VERSION__ >= 201112L

#define ntv_set(ntv, key, val)                                          \
  _Generic((val),                                                       \
           double: ntv_set_double(ntv, key, val),                       \
           char *: ntv_set_str(ntv, key, val)                           \
           )
#endif
