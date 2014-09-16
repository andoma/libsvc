/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
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

#include <assert.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "htsmsg_json.h"
#include "htsbuf.h"
#include "json.h"
#include "dbl.h"


/**
 *
 */
static void
htsmsg_json_write(htsmsg_t *msg, htsbuf_queue_t *hq, int isarray,
		  int indent, int pretty)
{
  htsmsg_field_t *f;
  char buf[100];
  static const char *indentor = "\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

  htsbuf_append(hq, isarray ? "[" : "{", 1);

  TAILQ_FOREACH(f, &msg->hm_fields, hmf_link) {

    if(pretty) {
      htsbuf_append(hq, indentor, indent < 16 ? indent : 16);

      if(f->hmf_type == HMF_COMMENT) {
        htsbuf_append(hq, "// ", 3);
        htsbuf_append(hq, f->hmf_str, strlen(f->hmf_str));
        htsbuf_append(hq, "\n", 1);
        continue;
      }
    } else {
      if(f->hmf_type == HMF_COMMENT)
        continue;
    }


    if(!isarray) {
      htsbuf_append_and_escape_jsonstr(hq, f->hmf_name ?: "noname");
      htsbuf_append(hq, ": ", 2);
    }

    switch(f->hmf_type) {
    case HMF_MAP:
      htsmsg_json_write(&f->hmf_msg, hq, 0, indent + 1, pretty);
      break;

    case HMF_LIST:
      htsmsg_json_write(&f->hmf_msg, hq, 1, indent + 1, pretty);
      break;

    case HMF_STR:
      htsbuf_append_and_escape_jsonstr(hq, f->hmf_str);
      break;

    case HMF_BIN:
      htsbuf_append_and_escape_jsonstr(hq, "binary");
      break;

    case HMF_S64:
      snprintf(buf, sizeof(buf), "%" PRId64, f->hmf_s64);
      htsbuf_append(hq, buf, strlen(buf));
      break;

    case HMF_DBL:
      my_double2str(buf, sizeof(buf), f->hmf_dbl);
      htsbuf_append(hq, buf, strlen(buf));
      break;

    default:
      abort();
    }

    if(TAILQ_NEXT(f, hmf_link))
      htsbuf_append(hq, ",", 1);
  }
  
  if(pretty) 
    htsbuf_append(hq, indentor, indent-1 < 16 ? indent-1 : 16);
  htsbuf_append(hq, isarray ? "]" : "}", 1);
}

/**
 *
 */
void
htsmsg_json_serialize(htsmsg_t *msg, htsbuf_queue_t *hq, int pretty)
{
  htsmsg_json_write(msg, hq, msg->hm_islist, 2, pretty);
  if(pretty) 
    htsbuf_append(hq, "\n", 1);
}


/**
 *
 */
char *
htsmsg_json_serialize_to_str(htsmsg_t *msg, int pretty)
{
  htsbuf_queue_t hq;
  char *str;
  htsbuf_queue_init(&hq, 0);
  htsmsg_json_serialize(msg, &hq, pretty);
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
  return htsmsg_create_map();
}

static void *
create_list(void *opaque)
{
  return htsmsg_create_list();
}

static void
destroy_obj(void *opaque, void *obj)
{
  return htsmsg_destroy(obj);
}

static void
add_obj(void *opaque, void *parent, const char *name, void *child)
{
  htsmsg_add_msg(parent, name, child);
}

static void 
add_string(void *opaque, void *parent, const char *name,  char *str)
{
  htsmsg_add_str(parent, name, str);
  free(str);
}

static void 
add_long(void *opaque, void *parent, const char *name, long v)
{
  htsmsg_add_s64(parent, name, v);
}

static void 
add_double(void *opaque, void *parent, const char *name, double v)
{
  htsmsg_add_dbl(parent, name, v);
}

static void 
add_bool(void *opaque, void *parent, const char *name, int v)
{
  htsmsg_add_u32(parent, name, v);
}

static void 
add_null(void *opaque, void *parent, const char *name)
{
}

static void 
add_comment(void *opaque, void *parent, const char *comment)
{
  htsmsg_add_comment(parent, comment);
}

/**
 *
 */
static const json_deserializer_t json_to_htsmsg = {
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
htsmsg_t *
htsmsg_json_deserialize(const char *src, char *errbuf, size_t errlen)
{
  return json_deserialize(src, &json_to_htsmsg, NULL, errbuf, errlen);
}
