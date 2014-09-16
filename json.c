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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include "json.h"
#include "utf8.h"
#include "dbl.h"

#define NOT_THIS_TYPE ((void *)-1)

static const char *json_parse_value(const char *s, void *parent, 
				    const char *name,
				    const json_deserializer_t *jd,
				    void *opaque,
				    const char **failp, const char **failmsg);



static const char *
skip_ws(const char *s, const json_deserializer_t *jd,
        void *opaque, void *parent)
{
 again:
  while(*s > 0 && *s < 33)
    s++;

  if(s[0] == '/' && s[1] == '/') {
    s += 2;

    const char *comment = s;

    while(*s != '\n' && *s != 0)
      s++;

    if(jd != NULL && jd->jd_add_comment != NULL) {

      size_t len = s - comment;
      char *buf = alloca(len + 1);
      memcpy(buf, comment, len);
      buf[len] = 0;
      jd->jd_add_comment(opaque, parent, buf);
    }
    if(*s == '\n')
      s++;
    goto again;
  }

  while(*s > 0 && *s < 33)
    s++;

  return s;
}

/**
 * Returns a newly allocated string
 */
static char *
json_parse_string(const char *s, const char **endp,
		  const char **failp, const char **failmsg)
{
  const char *start;
  char *r, *a, *b;
  int l, esc = 0;

  s = skip_ws(s, NULL, NULL, NULL);

  if(*s != '"')
    return NOT_THIS_TYPE;

  s++;
  start = s;

  while(1) {
    if(*s == 0) {
      *failmsg = "Unexpected end of JSON message";
      *failp = s;
      return NULL;
    }

    if(*s == '\\') {
      esc = 1;
    } else if(*s == '"' && s[-1] != '\\') {

      *endp = s + 1;

      /* End */
      l = s - start;
      r = malloc(l + 1);
      memcpy(r, start, l);
      r[l] = 0;

      if(esc) {
	/* Do deescaping inplace */

	a = b = r;

	while(*a) {
	  if(*a == '\\') {
	    a++;
	    if(*a == 'b')
	      *b++ = '\b';
	    else if(*a == 'f')
	      *b++ = '\f';
	    else if(*a == 'n')
	      *b++ = '\n';
	    else if(*a == 'r')
	      *b++ = '\r';
	    else if(*a == 't')
	      *b++ = '\t';
	    else if(*a == 'u') {
	      // Unicode character
	      int i, v = 0;

	      a++;
	      for(i = 0; i < 4; i++) {
		v = v << 4;
		switch(a[i]) {
		case '0' ... '9':
		  v |= a[i] - '0';
		  break;
		case 'a' ... 'f':
		  v |= a[i] - 'a' + 10;
		  break;
		case 'A' ... 'F':
		  v |= a[i] - 'F' + 10;
		  break;
		default:
		  free(r);
		  *failmsg = "Incorrect escape sequence";
		  *failp = (a - r) + start;
		  return NULL;
		}
	      }
	      a+=3;
	      b += utf8_put(b, v);
	    } else {
	      *b++ = *a;
	    }
	    a++;
	  } else {
	    *b++ = *a++;
	  }
	}
	*b = 0;
      }
      return r;
    }
    s++;
  }
}


/**
 *
 */
static void *
json_parse_map(const char *s, const char **endp, const json_deserializer_t *jd,
	       void *opaque, const char **failp, const char **failmsg)

{
  char *name;
  const char *s2;
  void *r;

  s = skip_ws(s, NULL, NULL, NULL);

  if(*s != '{')
    return NOT_THIS_TYPE;

  s++;

  r = jd->jd_create_map(opaque);

  s = skip_ws(s, jd, opaque, r);

  if(*s != '}') {

    while(1) {

      s = skip_ws(s, jd, opaque, r);
      if(*s == '}')
	break;

      name = json_parse_string(s, &s2, failp, failmsg);
      if(name == NOT_THIS_TYPE) {
	*failmsg = "Expected string";
	*failp = s;
	return NULL;
      }

      if(name == NULL)
	return NULL;

      s = s2;

      s = skip_ws(s, jd, opaque, r);

      if(*s != ':') {
	jd->jd_destroy_obj(opaque, r);
	free(name);
	*failmsg = "Expected ':'";
	*failp = s;
	return NULL;
      }
      s++;

      s2 = json_parse_value(s, r, name, jd, opaque, failp, failmsg);
      free(name);

      if(s2 == NULL) {
	jd->jd_destroy_obj(opaque, r);
	return NULL;
      }

      s = s2;

      s = skip_ws(s, jd, opaque, r);

      if(*s == '}')
	break;

      if(*s != ',') {
	jd->jd_destroy_obj(opaque, r);
	*failmsg = "Expected ','";
	*failp = s;
	return NULL;
      }
      s++;
    }
  }

  s++;
  *endp = s;
  return r;
}


/**
 *
 */
static void *
json_parse_list(const char *s, const char **endp, const json_deserializer_t *jd,
		void *opaque, const char **failp, const char **failmsg)
{
  const char *s2;
  void *r;

  s = skip_ws(s, NULL, NULL, NULL);

  if(*s != '[')
    return NOT_THIS_TYPE;

  s++;

  r = jd->jd_create_list(opaque);
  
  s = skip_ws(s, jd, opaque, r);

  if(*s != ']') {

    while(1) {

      s = skip_ws(s, jd, opaque, r);
      if(*s == ']')
	break;

      s2 = json_parse_value(s, r, NULL, jd, opaque, failp, failmsg);

      if(s2 == NULL) {
	jd->jd_destroy_obj(opaque, r);
	return NULL;
      }

      s = s2;

      s = skip_ws(s, jd, opaque, r);

      if(*s == ']')
	break;

      if(*s != ',') {
	jd->jd_destroy_obj(opaque, r);
	*failmsg = "Expected ','";
	*failp = s;
	return NULL;
      }
      s++;
    }
  }
  s++;
  *endp = s;
  return r;
}

/**
 *
 */
static const char *
json_parse_double(const char *s, double *dp)
{
  const char *ep;

  s = skip_ws(s, NULL, NULL, NULL);

  double d = my_str2double(s, &ep);

  if(ep == s)
    return NULL;

  *dp = d;
  return ep;
}


/**
 *
 */
static char *
json_parse_integer(const char *s, long *lp)
{
  char *ep;
  s = skip_ws(s, NULL, NULL, NULL);
  const char *s2 = s;
  if(*s2 == '-')
    s2++;
  while(*s2 >= '0' && *s2 <= '9')
    s2++;

  if(*s2 == 0)
    return NULL;
  if(s2[0] == '.' || s2[0] == 'e' || s2[0] == 'E')
    return NULL; // Is floating point

  long v = strtol(s, &ep, 10);
  if(v == LONG_MIN || v == LONG_MAX)
    return NULL;

  if(ep == s)
    return NULL;

  *lp = v;
  return ep;
}

/**
 *
 */
static const char *
json_parse_value(const char *s, void *parent, const char *name,
		 const json_deserializer_t *jd, void *opaque,
		 const char **failp, const char **failmsg)
{
  const char *s2;
  char *str;
  double d = 0;
  long l = 0;
  void *c;

  s = skip_ws(s, jd, opaque, parent);

  if((c = json_parse_map(s, &s2, jd, opaque, failp, failmsg)) == NULL)
    return NULL;

  if(c != NOT_THIS_TYPE) {
    jd->jd_add_obj(opaque, parent, name, c);
    return s2;
  }

  if((c = json_parse_list(s, &s2, jd, opaque, failp, failmsg)) == NULL)
    return NULL;
  
  if(c != NOT_THIS_TYPE) {
    jd->jd_add_obj(opaque, parent, name, c);
    return s2;
  }

  if((str = json_parse_string(s, &s2, failp, failmsg)) == NULL)
    return NULL;

  if(str != NOT_THIS_TYPE) {
    jd->jd_add_string(opaque, parent, name, str);
    return s2;
  }

  if((s2 = json_parse_integer(s, &l)) != NULL) {
    jd->jd_add_long(opaque, parent, name, l);
    return s2;
  } else if((s2 = json_parse_double(s, &d)) != NULL) {
    jd->jd_add_double(opaque, parent, name, d);
    return s2;
  }

  s = skip_ws(s, NULL, NULL, NULL);

  if(!strncmp(s, "true", 4)) {
    jd->jd_add_bool(opaque, parent, name, 1);
    return s + 4;
  }

  if(!strncmp(s, "false", 5)) {
    jd->jd_add_bool(opaque, parent, name, 0);
    return s + 5;
  }

  if(!strncmp(s, "null", 4)) {
    jd->jd_add_null(opaque, parent, name);
    return s + 4;
  }

  *failmsg = "Unknown token";
  *failp = s;
  return NULL;
}


/**
 *
 */
void *
json_deserialize(const char *src, const json_deserializer_t *jd, void *opaque,
		 char *errbuf, size_t errlen)
{
  const char *end;
  void *c;
  const char *errmsg;
  const char *errp;

  c = json_parse_map(src, &end, jd, opaque, &errp, &errmsg);
  if(c == NOT_THIS_TYPE)
    c = json_parse_list(src, &end, jd, opaque, &errp, &errmsg);

  if(c == NOT_THIS_TYPE) {
    snprintf(errbuf, errlen, "Invalid JSON, expected '{' or '['");
    return NULL;
  }

  if(c == NULL) {
    ssize_t offset = errp - src;
    int i;
    int line = 1;
    for(i = 0; i < offset; i++) {
      if(src[i] == '\n')
        line++;
    }
    snprintf(errbuf, errlen, "%s at line %d : %.20s", errmsg, line,
             src + offset);
  }
  return c;
}
