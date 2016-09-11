/******************************************************************************
* Copyright (C) 2008 - 2016 Andreas Smas
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

} ntv_t;

#define NTV_FOREACH(field_, msg)                                \
  for(ntv_t *field_ = TAILQ_FIRST(&(msg)->ntv_children);        \
      field_ != NULL; field_ = TAILQ_NEXT(field_, ntv_link))

#define NTV_FOREACH_TYPE(field_, msg, type)                             \
  for(ntv_t *field_ = ({                                                \
        ntv_t *_x_ = TAILQ_FIRST(&(msg)->ntv_children);                 \
        while(_x_ && _x_->ntv_type != type)                             \
          _x_ = TAILQ_NEXT(_x_, ntv_link);                              \
        _x_;                                                            \
      }); field_ != NULL; ({                                            \
          field_ = TAILQ_NEXT(field_, ntv_link);                        \
          while(field_ && field_->ntv_type != type)                     \
            field_ = TAILQ_NEXT(field_, ntv_link);                      \
        }))

// Misc toplevel functions

ntv_t *ntv_create(ntv_type type);
ntv_t *ntv_create_map(void);
ntv_t *ntv_create_list(void);

void ntv_release(ntv_t *ntv);
void ntv_print(const ntv_t *ntv);
ntv_t *ntv_copy(const ntv_t *src);

// Get operations on maps

int     ntv_get_int(const ntv_t *ntv, const char *key, int default_value);
int64_t ntv_get_int64(const ntv_t *ntv, const char *key, int64_t default_value);
double  ntv_get_double(const ntv_t *ntv, const char *key, double default_value);
const char *ntv_get_str(const ntv_t *ntv, const char *key);

const ntv_t *ntv_get_map(const ntv_t *ntv, const char *key);
const ntv_t *ntv_get_list(const ntv_t *ntv, const char *key);

// Get operations on lists

int     ntv_idx_int(const ntv_t *ntv, int idx, int default_value);
int64_t ntv_idx_int64(const ntv_t *ntv, int idx, int64_t default_value);
double  ntv_idx_double(const ntv_t *ntv, int idx, double default_value);
const char *ntv_idx_str(const ntv_t *ntv, int idx);

const ntv_t *ntv_idx_map(const ntv_t *ntv, int idx);
const ntv_t *ntv_idx_list(const ntv_t *ntv, int idx);

// Set operations on maps

void ntv_set_int(ntv_t *ntv, const char *key, int value);
void ntv_set_int64(ntv_t *ntv, const char *key, int64_t value);
void ntv_set_double(ntv_t *ntv, const char *key, double value);
void ntv_set_null(ntv_t *ntv, const char *key);
void ntv_set_boolean(ntv_t *ntv, const char *key, bool value);
void ntv_set_str(ntv_t *ntv, const char *key, const char *value);
void ntv_set_strf(ntv_t *ntv, const char *key, const char *fmt, ...);
void ntv_set_ntv(ntv_t *ntv, const char *key, struct ntv *sub);

// Set operations on lists

void ntv_set_idx_int(ntv_t *ntv, int key, int value);
void ntv_set_idx_int64(ntv_t *ntv, int key, int64_t value);
void ntv_set_idx_double(ntv_t *ntv, int key, double value);
void ntv_set_idx_null(ntv_t *ntv, int key);
void ntv_set_idx_boolean(ntv_t *ntv, int key, bool value);
void ntv_set_idx_str(ntv_t *ntv, int key, const char *value);
void ntv_set_idx_ntv(ntv_t *ntv, int key, struct ntv *sub);



struct htsbuf_queue;
void ntv_json_serialize(ntv_t *msg, struct htsbuf_queue *hq, int pretty);
char *ntv_json_serialize_to_str(ntv_t *msg, int pretty);

ntv_t *ntv_json_deserialize(const char *src, char *errbuf, size_t errlen);

void ntv_binary_serialize(const ntv_t *msg, struct htsbuf_queue *hq);
ntv_t *ntv_binary_deserialize(const void *data, size_t length);


#if __STDC_VERSION__ >= 201112L

#define ntv_set(ntv, key, val)                                          \
  _Generic(val,                                                         \
           int64_t: ntv_set_int64,                                      \
           int: ntv_set_int,                                            \
           unsigned int: ntv_set_int,                                   \
           float: ntv_set_double,                                       \
           double: ntv_set_double,                                      \
           char *: ntv_set_str,                                         \
           const char *: ntv_set_str,                                   \
           ntv_t *: ntv_set_ntv                                         \
           )(ntv, key, val)
#endif
