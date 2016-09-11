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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "ntv.h"

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
    free(f->ntv_string);
    f->ntv_string = NULL;
    break;
  case NTV_BINARY:
    free(f->ntv_bin);
    f->ntv_bin = NULL;
    break;
  }

  f->ntv_type = newtype;
}


static void
ntv_destroy(ntv_t *n)
{
  if(n->ntv_parent != NULL)
    TAILQ_REMOVE(&n->ntv_parent->ntv_children, n, ntv_link);

  free(n->ntv_name);
  ntv_field_clear(n, NTV_NULL);

  ntv_t *c;
  while((c = TAILQ_FIRST(&n->ntv_children)) != NULL)
    ntv_destroy(c);
  free(n);
}


void
ntv_release(ntv_t *n)
{
  ntv_destroy(n);
}


static ntv_t *
ntv_field_name_find(const ntv_t *parent, const char *fieldname)
{
  ntv_t *sub;
  if(parent == NULL || fieldname == NULL)
    return NULL;

  TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
    if(!strcmp(sub->ntv_name, fieldname))
      return sub;
  }
  return NULL;
}


static void
ntv_field_name_destroy(const ntv_t *parent, const char *fieldname)
{
  ntv_t *f = ntv_field_name_find(parent, fieldname);
  if(f != NULL)
    ntv_destroy(f);
}




static ntv_t *
ntv_field_nametype_find(const ntv_t *parent, const char *fieldname,
                        ntv_type type)
{
  ntv_t *sub;
  TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
    if(sub->ntv_type == type && !strcmp(sub->ntv_name, fieldname))
      return sub;
  }
  return NULL;
}



static ntv_t *
ntv_field_name_prep(ntv_t *parent, const char *fieldname, ntv_type type)
{
  ntv_t *f = fieldname != NULL ? ntv_field_name_find(parent, fieldname) : NULL;
  if(f != NULL) {
    ntv_field_clear(f, type);
  } else {
    f = ntv_create(type);
    f->ntv_name = fieldname != NULL ? strdup(fieldname) : NULL;
    TAILQ_INSERT_TAIL(&parent->ntv_children, f, ntv_link);
    f->ntv_parent = parent;
  }
  return f;
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
#if 0
  case NTV_STRING:
    return strtoll(f->ntv_str, NULL, 0);
#endif
  default:
    return default_value;
  }
}

int64_t
ntv_get_int64(const ntv_t *n, const char *key, int64_t default_value)
{
  return ntv_ret_int64(ntv_field_name_find(n, key), default_value);
}


int
ntv_get_int(const ntv_t *n, const char *key, int default_value)
{
  return ntv_ret_int64(ntv_field_name_find(n, key), default_value);
}


double
ntv_get_double(const ntv_t *n, const char *key, double default_value)
{
  return ntv_ret_double(ntv_field_name_find(n, key), default_value);
}


const char *
ntv_get_str(const ntv_t *n, const char *key)
{
  ntv_t *f = ntv_field_nametype_find(n, key, NTV_STRING);
  return f ? f->ntv_string : NULL;
}


const ntv_t *
ntv_get_map(const ntv_t *n, const char *key)
{
  return ntv_field_nametype_find(n, key, NTV_MAP);
}

const ntv_t *
ntv_get_list(const ntv_t *n, const char *key)
{
  return ntv_field_nametype_find(n, key, NTV_LIST);
}


void
ntv_set_int(ntv_t *ntv, const char *key, int value)
{
  ntv_field_name_prep(ntv, key, NTV_INT)->ntv_s64 = value;
}

void
ntv_set_int64(ntv_t *ntv, const char *key, int64_t value)
{
  ntv_field_name_prep(ntv, key, NTV_INT)->ntv_s64 = value;
}

void
ntv_set_double(ntv_t *ntv, const char *key, double value)
{
  ntv_field_name_prep(ntv, key, NTV_DOUBLE)->ntv_double = value;
}

void
ntv_set_null(ntv_t *ntv, const char *key)
{
  ntv_field_name_prep(ntv, key, NTV_NULL);
}

void
ntv_set_boolean(ntv_t *ntv, const char *key, bool value)
{
  ntv_field_name_prep(ntv, key, NTV_BOOLEAN)->ntv_boolean = value;
}

void
ntv_set_str(ntv_t *ntv, const char *key, const char *value)
{
  if(value == NULL)
    ntv_field_name_destroy(ntv, key);
  else
    ntv_field_name_prep(ntv, key, NTV_STRING)->ntv_string = strdup(value);
}

void
ntv_set_strf(ntv_t *m, const char *key, const char *fmt, ...)
{
  va_list ap;
  ntv_t *f = ntv_field_name_prep(m, key, NTV_STRING);
  va_start(ap, fmt);
  if(vasprintf(&f->ntv_string, fmt, ap) == -1)
    f->ntv_type = NTV_NULL;
  va_end(ap);
}


void
ntv_set_ntv(ntv_t *n, const char *key, ntv_t *sub)
{
  ntv_field_name_destroy(n, key);

  free(sub->ntv_name);
  sub->ntv_name = key ? strdup(key) : NULL;

  TAILQ_INSERT_TAIL(&n->ntv_children, sub, ntv_link);
  sub->ntv_parent = n;
}


ntv_t *
ntv_copy(const ntv_t *src)
{
  const ntv_t *f;
  ntv_t *dst = ntv_create(src->ntv_type);

  TAILQ_FOREACH(f, &src->ntv_children, ntv_link) {
    switch(f->ntv_type) {
    case NTV_NULL:
      ntv_set_null(dst, f->ntv_name);
      break;
    case NTV_BOOLEAN:
      ntv_set_boolean(dst, f->ntv_name, f->ntv_boolean);
      break;

    case NTV_MAP:
    case NTV_LIST:
      ntv_set_ntv(dst, f->ntv_name, ntv_copy(f));
      break;

    case NTV_STRING:
      ntv_set_str(dst, f->ntv_name, f->ntv_string);
      break;

    case NTV_BINARY:
      abort();
      break;

    case NTV_INT:
      ntv_set_int64(dst, f->ntv_name, f->ntv_s64);
      break;

    case NTV_DOUBLE:
      ntv_set_double(dst, f->ntv_name, f->ntv_double);
      break;
    }
  }
  return dst;
}





static void
ntv_print0(FILE *fp, const struct ntv_queue *q, int indent)
{
  ntv_t *f;
  int i;

  TAILQ_FOREACH(f, q, ntv_link) {

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
      ntv_print0(fp, &f->ntv_children, indent + 2);
      fprintf(fp, "%*.s}\n", indent, "");
      break;

    case NTV_LIST:
      fprintf(fp, "[\n");
      ntv_print0(fp, &f->ntv_children, indent + 2);
      fprintf(fp, "%*.s]\n", indent, "");
      break;

    case NTV_STRING:
      fprintf(fp, "\"%s\"\n", f->ntv_string);
      break;

    case NTV_BINARY:
      fprintf(fp, "(binary) = <");
      for(i = 0; i < f->ntv_binsize - 1; i++)
	fprintf(fp, "%02x.", ((uint8_t *)f->ntv_bin)[i]);
      fprintf(fp, "%02x>\n", ((uint8_t *)f->ntv_bin)[i]);
      break;

    case NTV_INT:
      fprintf(fp, "%"PRId64"\n", f->ntv_s64);
      break;

    case NTV_DOUBLE:
      printf("%f\n", f->ntv_double);
      break;
    }
  }
}


void
ntv_print(const ntv_t *ntv)
{
  ntv_print0(stdout, &ntv->ntv_children, 0);
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