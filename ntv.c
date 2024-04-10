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

#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/param.h>
#include "ntv.h"
#include "misc.h"
#include "dbl.h"

ntv_t *
ntv_create(ntv_type type)
{
  ntv_t *n = calloc(1, sizeof(struct ntv));
  n->ntv_type = type;
  TAILQ_INIT(&n->ntv_children);
  return n;
}


ntv_t *
ntv_create_map(void)
{
  return ntv_create(NTV_MAP);
}


ntv_t *
ntv_create_list(void)
{
  return ntv_create(NTV_LIST);
}

ntv_t *
ntv_nocase(ntv_t *ntv)
{
  ntv->ntv_flags |= NTV_NOCASE;
  return ntv;
}


static int
nocase_strcmp(const char *s1, const char *s2)
{
  for(; *s1 && *s2; s1++, s2++)
    if(!(*s1 == *s2 || (*s1 ^ 32) == *s2))
      break;

  if(*s1 == *s2)
    return 0;
  if((*s1 | 32) < (*s2 | 32))
    return -1;
  return 1;
}


static void
ntv_field_clear(ntv_t *f, ntv_type newtype)
{
  switch(f->ntv_type) {
  case NTV_NULL:
  case NTV_INT:
  case NTV_DOUBLE:
  case NTV_MAP:
  case NTV_LIST:
  case NTV_BOOLEAN:
    break;

  case NTV_STRING:
    if(!(f->ntv_flags & NTV_DONT_FREE))
      free(f->ntv_string);
    f->ntv_string = NULL;
    break;
  case NTV_BINARY:
    if(!(f->ntv_flags & NTV_DONT_FREE))
      free(f->ntv_bin);
    f->ntv_bin = NULL;
    break;
  }

  f->ntv_flags &= ~NTV_DONT_FREE;
  f->ntv_type = newtype;
}


static void
ntv_destroy(ntv_t *n)
{
  if(n->ntv_flags & NTV_REFCOUNTED) {
    assert(*n->ntv_refcount == 0);
    free(n->ntv_refcount);
  } else if(n->ntv_parent != NULL) {
    TAILQ_REMOVE(&n->ntv_parent->ntv_children, n, ntv_link);
  }

  free(n->ntv_name);
  ntv_field_clear(n, NTV_NULL);

  ntv_t *c;
  while((c = TAILQ_FIRST(&n->ntv_children)) != NULL)
    ntv_destroy(c);

  ntv_ns_release(n->ntv_namespace);
  free(n);
}


void
ntv_release(ntv_t *n)
{
  if(n == NULL)
    return;

  if(n->ntv_flags & NTV_REFCOUNTED && --(*n->ntv_refcount))
    return;

  ntv_destroy(n);
}


void
ntv_releasep(ntv_t **n)
{
  ntv_release(*n);
  *n = NULL;
}


ntv_t *
ntv_retain(ntv_t *n)
{
  if(n == NULL)
    return NULL;

  if(n->ntv_flags & NTV_REFCOUNTED) {
    (*n->ntv_refcount)++;
  } else {
    assert(n->ntv_parent == NULL);
    n->ntv_flags |= NTV_REFCOUNTED;
    n->ntv_refcount = malloc(sizeof(unsigned long));
    *n->ntv_refcount = 2;
  }
  return n;
}


static ntv_t *
ntv_field_name_find(const ntv_t *parent, const char *fieldname,
                    ntv_type type)
{
  ntv_t *sub;
  if(parent == NULL || fieldname == NULL)
    return NULL;

  if(-((unsigned long)(intptr_t)fieldname) < 4096) {
    unsigned int num = -(intptr_t)fieldname - 1;

    TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
      if((int)type != -1 && type != sub->ntv_type)
        continue;
      if(!num--)
	return sub;
    }
    return NULL;
  }

  if(parent->ntv_flags & NTV_NOCASE) {
    TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
      if(!nocase_strcmp(sub->ntv_name, fieldname) &&
         ((int)type == -1 || type == sub->ntv_type))
        return sub;
    }
  } else {
    TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
      if(!strcmp(sub->ntv_name, fieldname) &&
         ((int)type == -1 || type == sub->ntv_type))
        return sub;
    }
  }
  return NULL;
}


const ntv_t *
ntv_field_from_path(const ntv_t *n, const char **path)
{
  if(*path == NULL)
    return n;
  return ntv_field_from_path(ntv_field_name_find(n, *path, -1), path + 1);
}


void
ntv_delete_field(const ntv_t *parent, const char *fieldname)
{
  if(fieldname == NULL)
    return;
  ntv_t *f = ntv_field_name_find(parent, fieldname, -1);
  if(f != NULL)
    ntv_destroy(f);
}

ntv_t *
ntv_detach_field(ntv_t *parent, const char *key)
{
  ntv_t *f = ntv_field_name_find(parent, key, -1);
  if(f != NULL) {
    TAILQ_REMOVE(&parent->ntv_children, f, ntv_link);
    f->ntv_parent = NULL;
  }
  return f;
}


static ntv_t *
ntv_field_name_prep(ntv_t *parent, const char *fieldname, ntv_type type,
                    int replace)
{
  if(parent == NULL)
    return NULL;

  if(replace) {
    ntv_t *f = ntv_field_name_find(parent, fieldname, -1);
    if(f != NULL) {
      ntv_field_clear(f, type);
      return f;
    }
  }

  ntv_t *f = ntv_create(type);
  f->ntv_name = fieldname != NULL ? strdup(fieldname) : NULL;
  TAILQ_INSERT_TAIL(&parent->ntv_children, f, ntv_link);
  f->ntv_parent = parent;
  return f;
}

int
ntv_has_field(const ntv_t *n, const char *key)
{
  return ntv_field_name_find(n, key, -1) ? 1 : 0;
}

static int64_t
ntv_ret_int64(const ntv_t *f, int64_t default_value)
{
  if(f == NULL)
    return default_value;

  switch(f->ntv_type) {
  case NTV_INT:
    return f->ntv_s64;
  case NTV_BOOLEAN:
    return f->ntv_boolean;
  case NTV_DOUBLE:
    return f->ntv_double;
  case NTV_STRING:
    return strtoll(f->ntv_string, NULL, 0);
  default:
    return default_value;
  }
}


static double
ntv_ret_double(const ntv_t *f, double default_value)
{
  if(f == NULL)
    return default_value;

  switch(f->ntv_type) {
  case NTV_INT:
    return f->ntv_s64;
  case NTV_DOUBLE:
    return f->ntv_double;
  case NTV_BOOLEAN:
    return f->ntv_boolean;
  default:
    return default_value;
  }
}

static const ntv_t *
ntv_field_name_get(const ntv_t *parent, const char *fieldname, ntv_type type)
{
  return fieldname ? ntv_field_name_find(parent, fieldname, type) : parent;
}

const ntv_t *
ntv_get(const ntv_t *parent, const char *fieldname)
{
  return ntv_field_name_find(parent, fieldname, -1);
}

int64_t
ntv_get_int64(const ntv_t *n, const char *key, int64_t default_value)
{
  return ntv_ret_int64(ntv_field_name_get(n, key, -1), default_value);
}


int
ntv_get_int(const ntv_t *n, const char *key, int default_value)
{
  return ntv_ret_int64(ntv_field_name_get(n, key, -1), default_value);
}


double
ntv_get_double(const ntv_t *n, const char *key, double default_value)
{
  return ntv_ret_double(ntv_field_name_get(n, key, -1), default_value);
}


const char *
ntv_get_str(const ntv_t *n, const char *key)
{
  const ntv_t *f = ntv_field_name_get(n, key, NTV_STRING);
  return f ? f->ntv_string : NULL;
}

const void *
ntv_get_bin(const ntv_t *ntv, const char *key, size_t *sizep)
{
  const ntv_t *f = ntv_field_name_get(ntv, key, NTV_BINARY);
  if(sizep != NULL)
    *sizep = f ? f->ntv_binsize : 0;
  return f ? f->ntv_bin : NULL;
}

const ntv_t *
ntv_get_map(const ntv_t *n, const char *key)
{
  return ntv_field_name_get(n, key, NTV_MAP);
}

const ntv_t *
ntv_get_list(const ntv_t *n, const char *key)
{
  return ntv_field_name_get(n, key, NTV_LIST);
}

ntv_t *
ntv_get_mutable_map(ntv_t *n, const char *key)
{
  ntv_t *f = ntv_field_name_find(n, key, NTV_MAP);
  if(f == NULL) {
    f = ntv_create_map();
    ntv_set_ntv(n, key, f);
  }
  return f;
}

ntv_t *
ntv_get_mutable_list(ntv_t *n, const char *key)
{
  ntv_t *f = ntv_field_name_find(n, key, NTV_LIST);
  if(f == NULL) {
    f = ntv_create_list();
    ntv_set_ntv(n, key, f);
  }
  return f;
}

void
ntv_set_int(ntv_t *ntv, const char *key, int value)
{
  ntv_field_name_prep(ntv, key, NTV_INT, 1)->ntv_s64 = value;
}

void
ntv_set_int64(ntv_t *ntv, const char *key, int64_t value)
{
  ntv_field_name_prep(ntv, key, NTV_INT, 1)->ntv_s64 = value;
}

void
ntv_set_double(ntv_t *ntv, const char *key, double value)
{
  ntv_field_name_prep(ntv, key, NTV_DOUBLE, 1)->ntv_double = value;
}

void
ntv_set_null(ntv_t *ntv, const char *key)
{
  ntv_field_name_prep(ntv, key, NTV_NULL, 1);
}

void
ntv_set_boolean(ntv_t *ntv, const char *key, bool value)
{
  ntv_field_name_prep(ntv, key, NTV_BOOLEAN, 1)->ntv_boolean = value;
}

void
ntv_set_str(ntv_t *ntv, const char *key, const char *value)
{
  if(value == NULL)
    ntv_delete_field(ntv, key);
  else
    ntv_field_name_prep(ntv, key, NTV_STRING, 1)->ntv_string = strdup(value);
}

void
ntv_set_strf(ntv_t *m, const char *key, const char *fmt, ...)
{
  va_list ap;
  ntv_t *f = ntv_field_name_prep(m, key, NTV_STRING, 1);
  va_start(ap, fmt);
  if(vasprintf(&f->ntv_string, fmt, ap) == -1)
    f->ntv_type = NTV_NULL;
  va_end(ap);
}

void
ntv_set_bin(ntv_t *ntv, const char *key, const void *data, size_t datalen)
{
  if(data == NULL) {
    ntv_delete_field(ntv, key);
  } else {
    ntv_t *f = ntv_field_name_prep(ntv, key, NTV_BINARY, 1);
    f->ntv_bin = malloc(datalen);
    memcpy(f->ntv_bin, data, datalen);
    f->ntv_binsize = datalen;
  }
}


void
ntv_set_bin_prealloc(ntv_t *ntv, const char *key, void *data, size_t datalen)
{
  if(data == NULL) {
    ntv_delete_field(ntv, key);
  } else {
    ntv_t *f = ntv_field_name_prep(ntv, key, NTV_BINARY, 1);
    f->ntv_bin = data;
    f->ntv_binsize = datalen;
  }
}


void
ntv_set_ntv(ntv_t *n, const char *key, ntv_t *sub)
{
  ntv_delete_field(n, key);
  if(sub == NULL)
    return;
  free(sub->ntv_name);
  sub->ntv_name = key ? strdup(key) : NULL;

  TAILQ_INSERT_TAIL(&n->ntv_children, sub, ntv_link);
  sub->ntv_parent = n;
}




void
ntv_add_int(ntv_t *ntv, const char *key, int value)
{
  ntv_field_name_prep(ntv, key, NTV_INT, 0)->ntv_s64 = value;
}

void
ntv_add_int64(ntv_t *ntv, const char *key, int64_t value)
{
  ntv_field_name_prep(ntv, key, NTV_INT, 0)->ntv_s64 = value;
}

void
ntv_add_double(ntv_t *ntv, const char *key, double value)
{
  ntv_field_name_prep(ntv, key, NTV_DOUBLE, 0)->ntv_double = value;
}

void
ntv_add_null(ntv_t *ntv, const char *key)
{
  ntv_field_name_prep(ntv, key, NTV_NULL, 0);
}

void
ntv_add_boolean(ntv_t *ntv, const char *key, bool value)
{
  ntv_field_name_prep(ntv, key, NTV_BOOLEAN, 0)->ntv_boolean = value;
}

void
ntv_add_str(ntv_t *ntv, const char *key, const char *value)
{
  if(value != NULL)
    ntv_field_name_prep(ntv, key, NTV_STRING, 0)->ntv_string = strdup(value);
}

void
ntv_add_strf(ntv_t *m, const char *key, const char *fmt, ...)
{
  va_list ap;
  ntv_t *f = ntv_field_name_prep(m, key, NTV_STRING, 0);
  va_start(ap, fmt);
  if(vasprintf(&f->ntv_string, fmt, ap) == -1)
    f->ntv_type = NTV_NULL;
  va_end(ap);
}

void
ntv_add_str_prealloc(ntv_t *parent, char *key, char *value)
{
  if(parent == NULL)
    return;

  ntv_t *f = ntv_create(NTV_STRING);
  f->ntv_name = key;
  TAILQ_INSERT_TAIL(&parent->ntv_children, f, ntv_link);
  f->ntv_parent = parent;
  f->ntv_string = value;
}

void
ntv_add_bin(ntv_t *ntv, const char *key, const void *data, size_t datalen)
{
  if(data == NULL)
    return;

  ntv_t *f = ntv_field_name_prep(ntv, key, NTV_BINARY, 0);
  f->ntv_bin = malloc(datalen);
  memcpy(f->ntv_bin, data, datalen);
  f->ntv_binsize = datalen;
}


void
ntv_add_bin_prealloc(ntv_t *ntv, const char *key, void *data, size_t datalen)
{
  if(data == NULL)
    return;

  ntv_t *f = ntv_field_name_prep(ntv, key, NTV_BINARY, 0);
  f->ntv_bin = data;
  f->ntv_binsize = datalen;
}


void
ntv_add_ntv(ntv_t *n, const char *key, ntv_t *sub)
{
  if(sub == NULL)
    return;
  free(sub->ntv_name);
  sub->ntv_name = key ? strdup(key) : NULL;

  TAILQ_INSERT_TAIL(&n->ntv_children, sub, ntv_link);
  sub->ntv_parent = n;
}


ntv_t *
ntv_int(int64_t value)
{
  ntv_t *ntv = ntv_create(NTV_INT);
  ntv->ntv_s64 = value;
  return ntv;
}

ntv_t *
ntv_double(double value)
{
  ntv_t *ntv = ntv_create(NTV_DOUBLE);
  ntv->ntv_double = value;
  return ntv;
}


ntv_t *
ntv_boolean(int value)
{
  ntv_t *ntv = ntv_create(NTV_BOOLEAN);
  ntv->ntv_boolean = !!value;
  return ntv;
}


ntv_t *
ntv_null(void)
{
  return ntv_create(NTV_NULL);
}

ntv_t *
ntv_bin(const void *data, size_t len)
{
  ntv_t *ntv = ntv_create(NTV_BINARY);
  ntv->ntv_bin = malloc(len);
  memcpy(ntv->ntv_bin, data, len);
  ntv->ntv_binsize = len;
  return ntv;
}


ntv_t *
ntv_str(const char *str)
{
  if(str == NULL)
    return NULL;
  ntv_t *ntv = ntv_create(NTV_STRING);
  ntv->ntv_string = strdup(str);
  return ntv;
}

ntv_t *
ntv_strf(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  ntv_t *ntv = ntv_create(NTV_STRING);
  if(vasprintf(&ntv->ntv_string, fmt, ap) == -1)
    ntv->ntv_type = NTV_NULL;
  va_end(ap);
  return ntv;
}

ntv_t *
ntv_map(const char *key, ...)
{
  ntv_t *ntv = ntv_create_map();
  va_list ap;
  va_start(ap, key);

  while(key != NULL) {
    ntv_t *f = va_arg(ap, ntv_t *);

    if(f != NULL) {
      f->ntv_name = strdup(key);
      TAILQ_INSERT_TAIL(&ntv->ntv_children, f, ntv_link);
      f->ntv_parent = ntv;
    }
    key = va_arg(ap, const char *);
  }

  return ntv;
}



ntv_t *
ntv_list(ntv_t *f, ...)
{
  ntv_t *ntv = ntv_create_list();
  va_list ap;
  va_start(ap, f);

  while(f != NULL) {
    TAILQ_INSERT_TAIL(&ntv->ntv_children, f, ntv_link);
    f->ntv_parent = ntv;
    f = va_arg(ap, ntv_t *);
  }
  va_end(ap);
  return ntv;
}


static void
ntv_set_from_field(ntv_t *dst, const char *dstname, const ntv_t *f,
                   int recurse_in_map)
{
  switch(f->ntv_type) {
  case NTV_NULL:
    ntv_set_null(dst, dstname);
    break;
  case NTV_BOOLEAN:
    ntv_set_boolean(dst, dstname, f->ntv_boolean);
    break;
  case NTV_LIST:
    ntv_set_ntv(dst, dstname, ntv_copy(f));
    break;
  case NTV_MAP:
    if(recurse_in_map) {
      ntv_t *dstmap = ntv_field_name_find(dst, dstname, NTV_MAP);
      if(dstmap != NULL) {
        const ntv_t *f2;
        TAILQ_FOREACH(f2, &f->ntv_children, ntv_link) {
          ntv_set_from_field(dstmap, f2->ntv_name, f2, recurse_in_map);
        }
        break;
      }
    }
    ntv_set_ntv(dst, dstname, ntv_copy(f));
    break;

  case NTV_STRING:
    ntv_set_str(dst, dstname, f->ntv_string);
    break;
  case NTV_BINARY:
    ntv_set_bin(dst, dstname, f->ntv_bin, f->ntv_binsize);
    break;
  case NTV_INT:
    ntv_set_int64(dst, dstname, f->ntv_s64);
    break;
  case NTV_DOUBLE:
    ntv_set_double(dst, dstname, f->ntv_double);
    break;
  }
}


static void
ntv_add_from_field(ntv_t *dst, const char *dstname, const ntv_t *f)
{
  switch(f->ntv_type) {
  case NTV_NULL:
    ntv_add_null(dst, dstname);
    break;
  case NTV_BOOLEAN:
    ntv_add_boolean(dst, dstname, f->ntv_boolean);
    break;
  case NTV_MAP:
  case NTV_LIST:
    ntv_add_ntv(dst, dstname, ntv_copy(f));
    break;
  case NTV_STRING:
    ntv_add_str(dst, dstname, f->ntv_string);
    break;
  case NTV_BINARY:
    ntv_add_bin(dst, dstname, f->ntv_bin, f->ntv_binsize);
    break;
  case NTV_INT:
    ntv_add_int64(dst, dstname, f->ntv_s64);
    break;
  case NTV_DOUBLE:
    ntv_add_double(dst, dstname, f->ntv_double);
    break;
  }
}


void
ntv_merge_ex(ntv_t *dst, const ntv_t *src, int flags)
{
  if(src == NULL)
    return;

  const ntv_t *f;
  TAILQ_FOREACH(f, &src->ntv_children, ntv_link) {
    ntv_set_from_field(dst, f->ntv_name, f, !!(flags & NTV_MERGE_MAPS));
  }
}


void
ntv_merge(ntv_t *dst, const ntv_t *src)
{
  return ntv_merge_ex(dst, src, 0);
}


void
ntv_merge_add(ntv_t *dst, const ntv_t *src)
{
  if(src == NULL)
    return;

  const ntv_t *f;
  TAILQ_FOREACH(f, &src->ntv_children, ntv_link) {
    ntv_add_from_field(dst, f->ntv_name, f);
  }
}



ntv_t *
ntv_copy(const ntv_t *src)
{
  if(src == NULL)
    return NULL;

  ntv_t *dst = ntv_create(src->ntv_type);
  dst->ntv_flags |= src->ntv_flags & (NTV_NOCASE);

  switch(src->ntv_type) {
  case NTV_BOOLEAN:
    dst->ntv_boolean = src->ntv_boolean;
    break;
  case NTV_INT:
    dst->ntv_s64 = src->ntv_s64;
    break;
  case NTV_DOUBLE:
    dst->ntv_double = src->ntv_double;
    break;
  case NTV_NULL:
  case NTV_MAP:
  case NTV_LIST:
    break;
  case NTV_STRING:
    dst->ntv_string = strdup(src->ntv_string);
    break;
  case NTV_BINARY:
    dst->ntv_bin = malloc(src->ntv_binsize);
    memcpy(dst->ntv_bin, src->ntv_bin, src->ntv_binsize);
    dst->ntv_binsize = src->ntv_binsize;
    break;
  }

  const ntv_t *f;
  TAILQ_FOREACH(f, &src->ntv_children, ntv_link) {
    ntv_add_from_field(dst, f->ntv_name, f);
  }
  return dst;
}


int
ntv_copy_field(ntv_t *dst, const char *dstfieldname,
               const ntv_t *src, const char *srcfieldname)
{

  src = ntv_field_name_find(src, srcfieldname, -1);
  if(src == NULL) {
    ntv_delete_field(dst, dstfieldname);
    return 0;
  } else {
    ntv_set_from_field(dst, dstfieldname, src, 0);
    return 1;
  }
}


static int
ntv_sort_cmp(const void *A, const void *B)
{
  const ntv_t *a = *(const ntv_t **)A;
  const ntv_t *b = *(const ntv_t **)B;

  return strcmp(a->ntv_name, b->ntv_name);
}


static int
ntv_sort_nocase_cmp(const void *A, const void *B)
{
  const ntv_t *a = *(const ntv_t **)A;
  const ntv_t *b = *(const ntv_t **)B;

  return nocase_strcmp(a->ntv_name, b->ntv_name);
}

static int
ntv_cmp_map(const ntv_t *aa, const ntv_t *bb)
{
  const ntv_t **av, **bv;
  int num = 0, i, num_b = 0;

  NTV_FOREACH(a, aa) {
    if(a->ntv_name == NULL) {
      return 1;
    }
    num++;
  }
  NTV_FOREACH(b, bb) {
    if(b->ntv_name == NULL) {
      return 1;
    }
    num_b++;
  }

  if(num != num_b)
    return 1;

  if(num == 0)
    return 0;

  av = malloc_mul(num, sizeof(ntv_t *));
  bv = malloc_mul(num, sizeof(ntv_t *));

  i = 0;
  NTV_FOREACH(a, aa)
    av[i++] = a;

  i = 0;
  NTV_FOREACH(b, bb)
    bv[i++] = b;


  qsort(av, num, sizeof(ntv_t *),
        aa->ntv_flags & NTV_NOCASE ? ntv_sort_nocase_cmp : ntv_sort_cmp);
  qsort(bv, num, sizeof(ntv_t *),
        bb->ntv_flags & NTV_NOCASE ? ntv_sort_nocase_cmp : ntv_sort_cmp);

  const int nocase = (aa->ntv_flags | bb->ntv_flags) & NTV_NOCASE;

  for(i = 0; i < num; i++) {
    if(nocase ? nocase_strcmp(av[i]->ntv_name, bv[i]->ntv_name) :
       strcmp(av[i]->ntv_name, bv[i]->ntv_name))
      break;
    if(ntv_cmp(av[i], bv[i]))
      break;
  }

  free(av);
  free(bv);
  return i != num;
}

int
ntv_cmp(const ntv_t *src, const ntv_t *dst)
{
  const ntv_t *s, *d;

  if(src == NULL && dst == NULL)
    return 0;
  if(src == NULL || dst == NULL)
    return 1;

  if(src->ntv_type != dst->ntv_type)
    return 1;

  switch(src->ntv_type) {
  case NTV_NULL:
    return 0;

  case NTV_BOOLEAN:
    return src->ntv_boolean != dst->ntv_boolean;

  case NTV_MAP:
    return ntv_cmp_map(src, dst);

  case NTV_LIST:
    s = TAILQ_FIRST(&src->ntv_children);
    d = TAILQ_FIRST(&dst->ntv_children);

    while(!s == !d) {
      if(s == NULL)
        return 0;

      if(ntv_cmp(s, d))
        return 1;

      s = TAILQ_NEXT(s, ntv_link);
      d = TAILQ_NEXT(d, ntv_link);
    }
    return 1;

  case NTV_STRING:
    return strcmp(src->ntv_string, dst->ntv_string);

  case NTV_BINARY:
    return src->ntv_binsize != dst->ntv_binsize ||
      memcmp(src->ntv_bin, dst->ntv_bin, src->ntv_binsize);

  case NTV_INT:
    return src->ntv_s64 != dst->ntv_s64;

  case NTV_DOUBLE:
    return src->ntv_double != dst->ntv_double;
  default:
    return 1;
  }
}



void
ntv_delete_nulls(ntv_t *p)
{
  ntv_t *c, *next;
  for(c = TAILQ_FIRST(&p->ntv_children); c != NULL; c = next) {
    next = TAILQ_NEXT(c, ntv_link);

    switch(c->ntv_type) {
    case NTV_NULL:
      ntv_destroy(c);
      break;
    case NTV_MAP:
    case NTV_LIST:
      ntv_delete_nulls(c);
      break;
    default:
      break;
    }
  }
}


static void
ntv_print0(FILE *fp, const ntv_t *f, int indent)
{
  int i;
  fprintf(fp, "%*.s", indent, "");

  if(f->ntv_name)
    fprintf(fp, "%s: ", f->ntv_name);

  switch(f->ntv_type) {

  case NTV_NULL:
    fprintf(fp, "null\n");
    break;
  case NTV_BOOLEAN:
    fprintf(fp, "%s\n", f->ntv_boolean ? "true" : "false");
    break;

  case NTV_MAP:
    fprintf(fp, "{\n");
    NTV_FOREACH(c, f) {
      ntv_print0(fp, c, indent + 2);
    }
    fprintf(fp, "%*.s}\n", indent, "");
    break;

  case NTV_LIST:
    fprintf(fp, "[\n");
    NTV_FOREACH(c, f) {
      ntv_print0(fp, c, indent + 2);
    }
    fprintf(fp, "%*.s]\n", indent, "");
    break;

  case NTV_STRING:
    fprintf(fp, "\"%s\"\n", f->ntv_string);
    break;

  case NTV_BINARY:
    fprintf(fp, "(binary %zd bytes) = <", f->ntv_binsize);
    for(i = 0; i < MIN(16, f->ntv_binsize - 1); i++)
      fprintf(fp, "%02x.", ((uint8_t *)f->ntv_bin)[i]);
    fprintf(fp, "%s%02x>\n", i != f->ntv_binsize - 1 ? ".." : "",
            ((uint8_t *)f->ntv_bin)[f->ntv_binsize - 1]);
    break;

  case NTV_INT:
    fprintf(fp, "%"PRId64"\n", f->ntv_s64);
    break;

  case NTV_DOUBLE:
    printf("%f\n", f->ntv_double);
    break;
  }
}


void
ntv_print(const ntv_t *ntv)
{
  if(ntv != NULL)
    ntv_print0(stdout, ntv, 0);
}


int
ntv_is_empty(const ntv_t *ntv)
{
  return ntv == NULL || TAILQ_FIRST(&ntv->ntv_children) == NULL;
}

int
ntv_num_children(const ntv_t *ntv)
{
  const ntv_t *f;
  int r = 0;
  if(ntv == NULL)
    return 0;
  TAILQ_FOREACH(f, &ntv->ntv_children, ntv_link)
    r++;
  return r;
}


ntv_ns_t *
ntv_ns_create(const char *str)
{
  ntv_ns_t *ns = malloc(sizeof(ntv_ns_t));
  ns->refcount = 1;
  ns->str = strdup(str);
  return ns;
}


ntv_ns_t *
ntv_ns_retain(ntv_ns_t *ns)
{
  ns->refcount++;
  return ns;
}


void
ntv_ns_release(ntv_ns_t *ns)
{
  if(ns == NULL)
    return;

  ns->refcount--;
  if(ns->refcount == 0) {
    free(ns->str);
    free(ns);
  }
}



#ifdef TEST

int
main(void)
{
  ntv_t *x = ntv_create_map();
  ntv_set_str(x, "hej", "alpha");
  ntv_set_double(x, "hej", 4.5);
  ntv_set_str(x, "wat", "lol");


  ntv_t *sub = ntv_create_map();
  ntv_set_str(sub, "particleStream", "protons");
  ntv_set_double(sub, "effect", 2000000.0);
  ntv_set_ntv(x, "configuration", sub);
  
  ntv_print(x);
}



#endif
