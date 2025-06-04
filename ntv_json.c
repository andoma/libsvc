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
#include <sys/param.h>
#include <math.h>
#include "ntv.h"
#include "mbuf.h"
#include "dbl.h"
#include "json.h"


static void
ntv_json_write_value(const ntv_t *f, mbuf_t *m, int indent, int flags,
                     int precision);

/**
 *
 */
static void
ntv_json_write(const ntv_t *msg, mbuf_t *m, int indent, int flags,
               int precision)
{
  ntv_t *f;
  const bool isarray = msg->ntv_type == NTV_LIST;
  const int escape_slash = !(flags & NTV_JSON_F_MINIMAL_ESCAPE);


  mbuf_append(m, isarray ? "[" : "{", 1);
  indent++;

  TAILQ_FOREACH(f, &msg->ntv_children, ntv_link) {

    if(flags & NTV_JSON_F_PRETTY) {
      const int spc = (flags & NTV_JSON_F_WIDE ? 3 : 1) * indent;
      mbuf_qprintf(m, "\n%*.s", spc, "");
    }

    if(!isarray) {
      mbuf_append_and_escape_jsonstr(m, f->ntv_name ?: "noname", escape_slash);
      mbuf_append(m, ": ", flags & NTV_JSON_F_PRETTY ? 2 : 1);
    }

    ntv_json_write_value(f, m, indent, flags, precision);

    if(TAILQ_NEXT(f, ntv_link))
      mbuf_append(m, ",", 1);
  }

  indent--;
  if(flags & NTV_JSON_F_PRETTY) {
    const int spc = (flags & NTV_JSON_F_WIDE ? 3 : 1) * indent;
    mbuf_qprintf(m, "\n%*.s", spc, "");
  }
  mbuf_append(m, isarray ? "]" : "}", 1);
}


static void
ntv_json_write_value(const ntv_t *f, mbuf_t *m, int indent, int flags,
                     int precision)
{
  char buf[100];
  const int escape_slash = !(flags & NTV_JSON_F_MINIMAL_ESCAPE);

  switch(f->ntv_type) {
  case NTV_MAP:
    ntv_json_write(f, m, indent, flags, precision);
    break;

  case NTV_LIST:
    ntv_json_write(f, m, indent, flags, precision);
    break;

  case NTV_STRING:
    mbuf_append_and_escape_jsonstr(m, f->ntv_string, escape_slash);
    break;

  case NTV_BINARY:
    mbuf_append_and_escape_jsonstr(m, "binary", 0);
    break;

  case NTV_INT:
    snprintf(buf, sizeof(buf), "%" PRId64, f->ntv_s64);
    mbuf_append(m, buf, strlen(buf));
    break;

  case NTV_DOUBLE:
    if((flags & NTV_JSON_F_ONLY_FINITE) && !isfinite(f->ntv_double)) {
      mbuf_append(m, "null", 4);
    } else {
      my_double2str(buf, sizeof(buf), f->ntv_double, precision,
                    DBL_TYPE_FLOAT);
      mbuf_append(m, buf, strlen(buf));
    }
    break;

  case NTV_NULL:
    mbuf_append(m, "null", 4);
    break;

  case NTV_BOOLEAN:
    if(f->ntv_boolean)
      mbuf_append(m, "true", 4);
    else
      mbuf_append(m, "false", 5);
    break;

  }
}

/**
 *
 */
void
ntv_json_serialize_ex(const ntv_t *msg, mbuf_t *m, int flags, int precision)
{
  ntv_json_write_value(msg, m, 0, flags, precision);
  if(flags & (NTV_JSON_F_PRETTY | NTV_JSON_F_TRAILING_LF))
    mbuf_append(m, "\n", 1);
}

/**
 *
 */
void
ntv_json_serialize(const ntv_t *msg, mbuf_t *m, int flags)
{
  ntv_json_serialize_ex(msg, m, flags, -1);
}


/**
 *
 */
char *
ntv_json_serialize_to_str_ex(const ntv_t *msg, int flags, int precision)
{
  if(msg == NULL)
    return NULL;

  mbuf_t m;
  mbuf_init(&m);
  ntv_json_serialize_ex(msg, &m, flags, precision);
  return mbuf_clear_to_string(&m);
}


/**
 *
 */
char *
ntv_json_serialize_to_str(const ntv_t *msg, int flags)
{
  return ntv_json_serialize_to_str_ex(msg, flags, -1);
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
