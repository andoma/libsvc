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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ntv.h"
#include "htsbuf.h"
#include "dbl.h"
#include "json.h"


/**
 *
 */
static void
ntv_json_write(const ntv_t *msg, htsbuf_queue_t *hq, int indent, int pretty)
{
  ntv_t *f;
  char buf[100];
  const bool isarray = msg->ntv_type == NTV_LIST;

  htsbuf_append(hq, isarray ? "[" : "{", 1);

  TAILQ_FOREACH(f, &msg->ntv_children, ntv_link) {

    if(pretty)
      htsbuf_qprintf(hq, "%*.s", indent, "");

    if(!isarray) {
      htsbuf_append_and_escape_jsonstr(hq, f->ntv_name ?: "noname");
      htsbuf_append(hq, ": ", pretty ? 2 : 1);
    }

    switch(f->ntv_type) {
    case NTV_MAP:
      ntv_json_write(f, hq, indent + 1, pretty);
      break;

    case NTV_LIST:
      ntv_json_write(f, hq, indent + 1, pretty);
      break;

    case NTV_STRING:
      htsbuf_append_and_escape_jsonstr(hq, f->ntv_string);
      break;

    case NTV_BINARY:
      htsbuf_append_and_escape_jsonstr(hq, "binary");
      break;

    case NTV_INT:
      snprintf(buf, sizeof(buf), "%" PRId64, f->ntv_s64);
      htsbuf_append(hq, buf, strlen(buf));
      break;

    case NTV_DOUBLE:
      my_double2str(buf, sizeof(buf), f->ntv_double);
      htsbuf_append(hq, buf, strlen(buf));
      break;

    case NTV_NULL:
      htsbuf_append(hq, "null", 4);
      break;

    case NTV_BOOLEAN:
      if(f->ntv_boolean)
        htsbuf_append(hq, "true", 4);
      else
        htsbuf_append(hq, "false", 5);
      break;

    default:
      abort();
    }

    if(TAILQ_NEXT(f, ntv_link))
      htsbuf_append(hq, ",", 1);
  }

  if(pretty)
      htsbuf_qprintf(hq, "%*.s", indent-1, "");
  htsbuf_append(hq, isarray ? "]" : "}", 1);
}

/**
 *
 */
void
ntv_json_serialize(const ntv_t *msg, htsbuf_queue_t *hq, int pretty)
{
  ntv_json_write(msg, hq, 0, pretty);
  if(pretty)
    htsbuf_append(hq, "\n", 1);
}


/**
 *
 */
char *
ntv_json_serialize_to_str(const ntv_t *msg, int pretty)
{
  htsbuf_queue_t hq;
  char *str;
  htsbuf_queue_init(&hq, 0);
  ntv_json_serialize(msg, &hq, pretty);
  str = htsbuf_to_string(&hq);
  htsbuf_queue_flush(&hq);
  return str;
}

/**
 *
 */

static void *
create_map(void *opaque)
{
  return ntv_create_map();
}

static void *
create_list(void *opaque)
{
  return ntv_create_list();
}

static void
destroy_obj(void *opaque, void *obj)
{
  return ntv_release(obj);
}

static void
add_obj(void *opaque, void *parent, const char *name, void *child)
{
  ntv_set_ntv(parent, name, child);
}

static void
add_string(void *opaque, void *parent, const char *name,  char *str)
{
  ntv_set_str(parent, name, str);
  free(str);
}

static void
add_long(void *opaque, void *parent, const char *name, long v)
{
  ntv_set_int64(parent, name, v);
}

static void
add_double(void *opaque, void *parent, const char *name, double v)
{
  ntv_set_double(parent, name, v);
}

static void
add_bool(void *opaque, void *parent, const char *name, int v)
{
  ntv_set_boolean(parent, name, v);
}

static void
add_null(void *opaque, void *parent, const char *name)
{
  ntv_set_null(parent, name);
}

static void
add_comment(void *opaque, void *parent, const char *comment)
{
  //  ntv_add_comment(parent, comment);
}

/**
 *
 */
static const json_deserializer_t json_to_ntv = {
  .jd_create_map      = create_map,
  .jd_create_list     = create_list,
  .jd_destroy_obj     = destroy_obj,
  .jd_add_obj         = add_obj,
  .jd_add_string      = add_string,
  .jd_add_long        = add_long,
  .jd_add_double      = add_double,
  .jd_add_bool        = add_bool,
  .jd_add_null        = add_null,
  .jd_add_comment     = add_comment,
};


/**
 *
 */
ntv_t *
ntv_json_deserialize(const char *src, char *errbuf, size_t errlen)
{
  return json_deserialize(src, &json_to_ntv, NULL, errbuf, errlen);
}
