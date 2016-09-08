#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "ntv.h"

static ntv *
ntv_create(ntv_type type)
{
  ntv *n = calloc(1, sizeof(struct ntv));
  n->ntv_type = type;
  TAILQ_INIT(&n->ntv_children);
  return n;
}


ntv *
ntv_create_map(void)
{
  return ntv_create(NTV_MAP);
}


ntv *
ntv_create_list(void)
{
  return ntv_create(NTV_LIST);
}


static void
ntv_field_clear(ntv *f, ntv_type newtype)
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
ntv_destroy(ntv *n)
{
  if(n->ntv_parent != NULL)
    TAILQ_REMOVE(&n->ntv_parent->ntv_children, n, ntv_link);

  free(n->ntv_name);
  ntv_field_clear(n, NTV_NULL);

  ntv *c;
  while((c = TAILQ_FIRST(&n->ntv_children)) != NULL)
    ntv_destroy(n);
}


void
ntv_release(ntv *n)
{
  ntv_destroy(n);
}


static ntv *
ntv_field_name_find(const ntv *parent, const char *fieldname)
{
  ntv *sub;
  TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
    if(!strcmp(sub->ntv_name, fieldname))
      return sub;
  }
  return NULL;
}


static void
ntv_field_name_destroy(const ntv *parent, const char *fieldname)
{
  ntv *f = ntv_field_name_find(parent, fieldname);
  if(f != NULL)
    ntv_destroy(f);
}




static ntv *
ntv_field_nametype_find(const ntv *parent, const char *fieldname,
                        ntv_type type)
{
  ntv *sub;
  TAILQ_FOREACH(sub, &parent->ntv_children, ntv_link) {
    if(sub->ntv_type == type && !strcmp(sub->ntv_name, fieldname))
      return sub;
  }
  return NULL;
}



static ntv *
ntv_field_name_prep(ntv *parent, const char *fieldname, ntv_type type)
{
  ntv *f = fieldname != NULL ? ntv_field_name_find(parent, fieldname) : NULL;
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
ntv_ret_int64(const ntv *f, int64_t default_value)
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
ntv_ret_double(const ntv *f, double default_value)
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
ntv_get_int64(const ntv *n, const char *key, int64_t default_value)
{
  return ntv_ret_int64(ntv_field_name_find(n, key), default_value);
}


int
ntv_get_int(const ntv *n, const char *key, int default_value)
{
  return ntv_ret_int64(ntv_field_name_find(n, key), default_value);
}


double
ntv_get_double(const ntv *n, const char *key, double default_value)
{
  return ntv_ret_double(ntv_field_name_find(n, key), default_value);
}


const char *
ntv_get_str(const ntv *n, const char *key)
{
  ntv *f = ntv_field_nametype_find(n, key, NTV_STRING);
  return f ? f->ntv_string : NULL;
}


const ntv *
ntv_get_map(const ntv *n, const char *key)
{
  return ntv_field_nametype_find(n, key, NTV_MAP);
}

const ntv *
ntv_get_list(const ntv *n, const char *key)
{
  return ntv_field_nametype_find(n, key, NTV_LIST);
}


void
ntv_set_int(ntv *ntv, const char *key, int value)
{
  ntv_field_name_prep(ntv, key, NTV_INT)->ntv_s64 = value;
}

void
ntv_set_int64(ntv *ntv, const char *key, int64_t value)
{
  ntv_field_name_prep(ntv, key, NTV_INT)->ntv_s64 = value;
}

void
ntv_set_double(ntv *ntv, const char *key, double value)
{
  ntv_field_name_prep(ntv, key, NTV_DOUBLE)->ntv_double = value;
}

void
ntv_set_null(ntv *ntv, const char *key)
{
  ntv_field_name_prep(ntv, key, NTV_NULL);
}

void
ntv_set_boolean(ntv *ntv, const char *key, bool value)
{
  ntv_field_name_prep(ntv, key, NTV_NULL)->ntv_boolean = value;
}

void
ntv_set_str(ntv *ntv, const char *key, const char *value)
{
  ntv_field_name_prep(ntv, key, NTV_STRING)->ntv_string = strdup(value);
}


void
ntv_set_ntv(ntv *n, const char *key, ntv *sub)
{
  ntv_field_name_destroy(n, key);

  free(sub->ntv_name);
  sub->ntv_name = strdup(key);

  TAILQ_INSERT_TAIL(&n->ntv_children, sub, ntv_link);
  sub->ntv_parent = n;
}



static void
ntv_print0(FILE *fp, struct ntv_queue *q, int indent)
{
  ntv *f;
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
ntv_print(ntv *ntv)
{
  ntv_print0(stdout, &ntv->ntv_children, 0);
}

#ifdef TEST

int
main(void)
{
  ntv *x = ntv_create_map();
  ntv_set_str(x, "hej", "alpha");
  ntv_set_double(x, "hej", 4.5);
  ntv_set_str(x, "wat", "lol");


  ntv *sub = ntv_create_map();
  ntv_set_str(sub, "particleStream", "protons");
  ntv_set_double(sub, "effect", 2000000.0);
  ntv_set_ntv(x, "configuration", sub);
  
  ntv_print(x);
}



#endif
