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

#pragma once

typedef struct json_deserializer {
  void *(*jd_create_map)(void *jd_opaque);
  void *(*jd_create_list)(void *jd_opaque);

  void (*jd_destroy_obj)(void *jd_opaque, void *obj);

  void (*jd_add_obj)(void *jd_opaque, void *parent,
		     const char *name, void *child);

  // str must be free'd by callee
  void (*jd_add_string)(void *jd_opaque, void *parent,
			const char *name, char *str);

  void (*jd_add_long)(void *jd_opaque, void *parent,
		      const char *name, long v);

  void (*jd_add_double)(void *jd_opaque, void *parent,
			const char *name, double d);

  void (*jd_add_bool)(void *jd_opaque, void *parent,
		      const char *name, int v);

  void (*jd_add_null)(void *jd_opaque, void *parent,
		      const char *name);

  void (*jd_add_comment)(void *jd_opaque, void *parent,
                         const char *comment);

} json_deserializer_t;

void *json_deserialize(const char *src, const json_deserializer_t *jd,
		       void *opaque, char *errbuf, size_t errlen);
