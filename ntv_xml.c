/******************************************************************************
* Copyright (C) 2008 - 2019 Andreas Smas
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


/**
 * XML parser, written according to this spec:
 *
 * http://www.w3.org/TR/2006/REC-xml-20060816/
 *
 * Parses of UTF-8 and ISO-8859-1 (Latin 1) encoded XML and output as
 * htsmsg's with UTF-8 encoded payloads
 *
 *  Supports:                             Example:
 *  
 *  Comments                              <!--  a comment               -->
 *  Processing Instructions               <?xml                          ?>
 *  CDATA                                 <![CDATA[  <litteraly copied> ]]>
 *  Label references                      &amp;
 *  Character references                  &#65;
 *  Empty tags                            <tagname/>
 *
 *
 *  Not supported:
 *
 *  UTF-16 (mandatory by standard)
 *  Intelligent parsing of <!DOCTYPE>
 *  Entity declarations
 *
 */


#include <assert.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "ntv.h"
#include "utf8.h"
#include "misc.h"

TAILQ_HEAD(cdata_content_queue, cdata_content);

LIST_HEAD(xmlns_list, xmlns);

typedef struct xmlns {
  LIST_ENTRY(xmlns) xmlns_global_link;
  LIST_ENTRY(xmlns) xmlns_scope_link;

  char *xmlns_prefix;
  unsigned int xmlns_prefix_len;

  ntv_ns_t *xmlns_ntv_namespace;

} xmlns_t;

typedef struct xmlparser {
  enum {
    XML_ENCODING_UTF8,
    XML_ENCODING_8859_1,
  } xp_encoding;

  char xp_errmsg[128];
  const char *xp_errpos;
  int xp_parser_err_line;

  char xp_trim_whitespace;

  struct xmlns_list xp_namespaces;

} xmlparser_t;

#define xmlerr2(xp, pos, fmt, ...) do {                                 \
    snprintf((xp)->xp_errmsg, sizeof((xp)->xp_errmsg), fmt, ##__VA_ARGS__); \
    (xp)->xp_errpos = pos;                                               \
    (xp)->xp_parser_err_line = __LINE__;                                \
  } while(0)


typedef struct cdata_content {
  TAILQ_ENTRY(cdata_content) cc_link;
  const char *cc_start, *cc_end; /* end points to byte AFTER last char */
  int cc_encoding;
  char cc_buf[0];
} cdata_content_t;

static const char *htsmsg_xml_parse_cd(xmlparser_t *xp, ntv_t *parent,
                                       ntv_t *parent_field, const char *src);

static int html_entity_lookup(const char *name);

static int
xml_is_cc_ws(const cdata_content_t *cc)
{
  const char *c = cc->cc_start;
  while(c != cc->cc_end) {
    if(*c > 32)
      return 0;
    c++;
  }
  return 1;
}


/**
 *
 */
static void
add_unicode(struct cdata_content_queue *ccq, int c)
{
  cdata_content_t *cc;
  char *q;

  cc = malloc(sizeof(cdata_content_t) + 6);
  cc->cc_encoding = XML_ENCODING_UTF8;
  q = cc->cc_buf;

  TAILQ_INSERT_TAIL(ccq, cc, cc_link);
  cc->cc_start = cc->cc_buf;

  q += utf8_put(q, c);
  cc->cc_end = q;
}

/**
 *
 */
static int
decode_character_reference(const char **src)
{
  int v = 0;
  char c;

  if(**src == 'x') {
    /* hexadecimal */
    (*src)++;

    /* decimal */
    while(1) {
      c = **src;
      if (c >= '0' && c <= '9')
	v = v * 0x10 + c - '0';
      else if (c >= 'a' && c <= 'f')
        v = v * 0x10 + c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        v = v * 0x10 + c - 'A' + 10;
      else if (c == ';') {
        (*src)++;
        return v;
      } else {
        return 0;
      }
      (*src)++;
    }

  } else {

    /* decimal */
    while(1) {
      c = **src;
      if (c >= '0' && c <= '9')
	v = v * 10 + c - '0';
      else if (c == ';') {
        (*src)++;
        return v;
      } else {
	return 0;
      }
    (*src)++;
    }
  }
}

/**
 *
 */
static __inline int
is_xmlws(char c)
{
  return c > 0 && c <= 32;
  //  return c == 32 || c == 9 || c = 10 || c = 13;
}


/**
 *
 */
static void
xmlns_destroy(xmlns_t *ns)
{
  LIST_REMOVE(ns, xmlns_global_link);
  LIST_REMOVE(ns, xmlns_scope_link);
  free(ns->xmlns_prefix);
  ntv_ns_release(ns->xmlns_ntv_namespace);
  free(ns);
}

/**
 *
 */
static ntv_t *
add_xml_field(xmlparser_t *xp, ntv_t *parent, const char *tagname,
              ntv_type type, ntv_flags flags)
{
  xmlns_t *ns;
  ntv_t *f = ntv_create(type);
  int i = strcspn(tagname, ":");
  if(tagname[i] && tagname[i + 1]) {
    LIST_FOREACH(ns, &xp->xp_namespaces, xmlns_global_link) {
      if(ns->xmlns_prefix_len == i &&
         !memcmp(ns->xmlns_prefix, tagname, ns->xmlns_prefix_len)) {


        tagname += i + 1;
        break;
      }
    }
  }
  ntv_add_ntv(parent, tagname, f);
  return f;
}


/**
 *
 */
static const char *
htsmsg_xml_parse_attrib(xmlparser_t *xp, ntv_t *msg, const char *src,
			struct xmlns_list *xmlns_scope_list)
{
  const char *attribname;
  const char *payload;
  int attriblen, payloadlen;
  char quote;

  attribname = src;
  /* Parse attribute name */
  while(1) {
    if(*src == 0) {
      xmlerr2(xp, src, "Unexpected end of file during attribute name parsing");
      return NULL;
    }

    if(is_xmlws(*src) || *src == '=')
      break;
    src++;
  }

  attriblen = src - attribname;
  if(attriblen < 1 || attriblen > 65535) {
    xmlerr2(xp, attribname, "Invalid attribute name");
    return NULL;
  }

  while(is_xmlws(*src))
    src++;

  if(*src != '=') {
    xmlerr2(xp, src, "Expected '=' in attribute parsing");
    return NULL;
  }
  src++;

  while(is_xmlws(*src))
    src++;

  /* Parse attribute payload */
  quote = *src++;
  if(quote != '"' && quote != '\'') {
    xmlerr2(xp, src - 1, "Expected ' or \" before attribute value");
    return NULL;
  }

  payload = src;
  while(1) {
    if(*src == 0) {
      xmlerr2(xp, src, "Unexpected end of file during attribute value parsing");
      return NULL;
    }
    if(*src == quote)
      break;
    src++;
  }

  payloadlen = src - payload;
  if(payloadlen < 0 || payloadlen > 65535) {
    xmlerr2(xp, payload, "Invalid attribute value");
    return NULL;
  }

  src++;
  while(is_xmlws(*src))
    src++;

  if(xmlns_scope_list != NULL &&
     attriblen > 6 && !memcmp(attribname, "xmlns:", 6)) {

    attribname += 6;
    attriblen  -= 6;

    xmlns_t *ns = malloc(sizeof(xmlns_t));

    ns->xmlns_prefix = malloc(attriblen + 1);
    memcpy(ns->xmlns_prefix, attribname, attriblen);
    ns->xmlns_prefix[attriblen] = 0;
    ns->xmlns_prefix_len = attriblen;


    ns->xmlns_ntv_namespace = malloc(sizeof(ntv_ns_t));
    ns->xmlns_ntv_namespace->refcount = 1;
    ns->xmlns_ntv_namespace->str = malloc(payloadlen + 1);
    memcpy(ns->xmlns_ntv_namespace->str, payload, payloadlen);
    ns->xmlns_ntv_namespace->str[payloadlen] = 0;

    LIST_INSERT_HEAD(&xp->xp_namespaces, ns, xmlns_global_link);
    LIST_INSERT_HEAD(xmlns_scope_list,   ns, xmlns_scope_link);
    return src;
  }

  char *a = mystrndupa(attribname, attriblen);

  ntv_t *f = add_xml_field(xp, msg, a, NTV_STRING, NTV_XML_ATTRIBUTE);

  f->ntv_string = malloc(payloadlen + 1);
  memcpy(f->ntv_string, payload, payloadlen);
  f->ntv_string[payloadlen] = 0;

  return src;
}

/**
 *
 */
static const char *
htsmsg_xml_parse_tag(xmlparser_t *xp, ntv_t *parent, const char *src)
{
  struct xmlns_list nslist;
  const char *tagname;
  int taglen, empty = 0;

  tagname = src;

  LIST_INIT(&nslist);

  ntv_t *m = ntv_create_map();

  while(1) {
    if(*src == 0) {
      xmlerr2(xp, src, "Unexpected end of file during tag name parsing");
      return NULL;
    }
    if(is_xmlws(*src) || *src == '>' || *src == '/')
      break;
    src++;
  }

  taglen = src - tagname;
  if(taglen < 1 || taglen > 65535) {
    xmlerr2(xp, tagname, "Invalid tag name");
    return NULL;
  }

  while(1) {

    while(is_xmlws(*src))
      src++;

    if(*src == 0) {
      xmlerr2(xp, src, "Unexpected end of file in tag");
      return NULL;
    }

    if(src[0] == '/' && src[1] == '>') {
      empty = 1;
      src += 2;
      break;
    }

    if(*src == '>') {
      src++;
      break;
    }

    if((src = htsmsg_xml_parse_attrib(xp, m, src, &nslist)) == NULL)
      return NULL;
  }

  char *t = mystrndupa(tagname, taglen);
  ntv_t *f = add_xml_field(xp, parent, t, NTV_MAP, 0);

  if(!empty)
    src = htsmsg_xml_parse_cd(xp, m, f, src);


  ntv_merge_add(f, m);
  ntv_release(m);

  if(TAILQ_FIRST(&f->ntv_children) == NULL)
    f->ntv_type = NTV_STRING;

  xmlns_t *ns;
  while((ns = LIST_FIRST(&nslist)) != NULL)
    xmlns_destroy(ns);
  return src;
}





/**
 *
 */
static const char *
htsmsg_xml_parse_pi(xmlparser_t *xp, ntv_t *parent, const char *src)
{
  ntv_t *attrs;
  const char *s = src;
  char *piname;
  int l;

  while(1) {
    if(*src == 0) {
      xmlerr2(xp, src, "Unexpected end of file during parsing of "
	     "Processing instructions");
      return NULL;
    }

    if(is_xmlws(*src) || *src == '?')
      break;
    src++;
  }

  l = src - s;
  if(l < 1 || l > 1024) {
    xmlerr2(xp, src, "Invalid 'Processing instructions' name");
    return NULL;
  }
  piname = alloca(l + 1);
  memcpy(piname, s, l);
  piname[l] = 0;

  attrs = ntv_create_map();

  while(1) {

    while(is_xmlws(*src))
      src++;

    if(*src == 0) {
      ntv_release(attrs);
      xmlerr2(xp, src, "Unexpected end of file during parsing of "
	     "Processing instructions");
      return NULL;
    }

    if(src[0] == '?' && src[1] == '>') {
      src += 2;
      break;
    }

    if((src = htsmsg_xml_parse_attrib(xp, attrs, src, NULL)) == NULL) {
      ntv_release(attrs);
      return NULL;
    }
  }

  if(ntv_is_empty(attrs)) {
    ntv_release(attrs);
  } else {
    ntv_set_ntv(parent, piname, attrs);
  }

  return src;
}


/**
 *
 */
static const char *
xml_parse_comment(xmlparser_t *xp, const char *src)
{
  const char *start = src;
  /* comment */
  while(1) {
    if(*src == 0) { /* EOF inside comment is invalid */
      xmlerr2(xp, start, "Unexpected end of file inside a comment");
      return NULL;
    }

    if(src[0] == '-' && src[1] == '-' && src[2] == '>')
      return src + 3;
    src++;
  }
}

/**
 *
 */
static const char *
decode_label_reference(xmlparser_t *xp,
		       struct cdata_content_queue *ccq, const char *src)
{
  const char *s = src;
  int l;
  char *label;
  int code;

  const char *start = src;
  while(*src != 0 && *src != ';')
    src++;
  if(*src == 0) {
    xmlerr2(xp, start,
            "Unexpected end of file during parsing of label reference");
    return NULL;
  }

  l = src - s;
  if(l < 1) {
    xmlerr2(xp, s, "Too short label reference");
    return NULL;
  }

  if(l > 1024) {
    xmlerr2(xp, s, "Too long label reference");
    return NULL;
  }

  label = alloca(l + 1);
  memcpy(label, s, l);
  label[l] = 0;
  src++;

  code = html_entity_lookup(label);
  if(code != -1)
    add_unicode(ccq, code);
  else {
    xmlerr2(xp, start, "Unknown label referense: \"&%s;\"\n", label);
    return NULL;
  }

  return src;
}

/**
 *
 */
static const char *
htsmsg_xml_parse_cd0(xmlparser_t *xp,
		     struct cdata_content_queue *ccq, ntv_t *tags,
		     ntv_t *pis, const char *src, int raw)
{
  cdata_content_t *cc = NULL;
  int c;

  while(src != NULL && *src != 0) {

    if(raw && src[0] == ']' && src[1] == ']' && src[2] == '>') {
      if(cc != NULL)
	cc->cc_end = src;
      cc = NULL;
      src += 3;
      break;
    }

    if(*src == '<' && !raw) {

      if(cc != NULL)
	cc->cc_end = src;
      cc = NULL;

      src++;
      if(*src == '?') {
	src++;
	src = htsmsg_xml_parse_pi(xp, pis, src);
	continue;
      }

      if(src[0] == '!') {

	src++;

	if(src[0] == '-' && src[1] == '-') {
	  src = xml_parse_comment(xp, src + 2);
	  continue;
	}

	if(!strncmp(src, "[CDATA[", 7)) {
	  src += 7;
	  src = htsmsg_xml_parse_cd0(xp, ccq, tags, pis, src, 1);
	  continue;
	}
	xmlerr2(xp, src, "Unknown syntatic element: <!%.10s", src);
	return NULL;
      }

      if(*src == '/') {
	/* End-tag */
	src++;
	while(*src != '>') {
	  if(*src == 0) { /* EOF inside endtag */
	    xmlerr2(xp, src, "Unexpected end of file inside close tag");
	    return NULL;
	  }
	  src++;
	}
	src++;
	break;
      }

      src = htsmsg_xml_parse_tag(xp, tags, src);
      continue;
    }

    if(*src == '&' && !raw) {
      if(cc != NULL)
	cc->cc_end = src;

      src++;

      if(*src == '#') {
        const char *start = src;
	src++;
	/* Character reference */
	if((c = decode_character_reference(&src)) != 0)
	  add_unicode(ccq, c);
	else {
	  xmlerr2(xp, start, "Invalid character reference");
	  return NULL;
	}
        cc = NULL;
      } else {
	/* Label references */
	const char *x = decode_label_reference(xp, ccq, src);

        if(x != NULL) {
          src = x;
          cc = NULL;
        } else {
          continue;
        }
      }
      continue;
    }

    if(cc == NULL) {
      if(*src < 32) {
	src++;
	continue;
      }
      cc = malloc(sizeof(cdata_content_t));
      cc->cc_encoding = xp->xp_encoding;
      TAILQ_INSERT_TAIL(ccq, cc, cc_link);
      cc->cc_start = src;
    }
    src++;
  }

  if(cc != NULL) {
    assert(src != NULL);
    cc->cc_end = src;
  }
  return src;
}

/**
 *
 */
static const char *
htsmsg_xml_parse_cd(xmlparser_t *xp, ntv_t *msg, ntv_t *field,
                    const char *src)
{
  struct cdata_content_queue ccq;
  cdata_content_t *cc;
  int c = 0, l;
  char *body;
  const char *x;
  TAILQ_INIT(&ccq);

  src = htsmsg_xml_parse_cd0(xp, &ccq, msg, NULL, src, 0);

  if(xp->xp_trim_whitespace) {
    // Trim whitespaces
    while((cc = TAILQ_FIRST(&ccq)) != NULL && xml_is_cc_ws(cc)) {
      TAILQ_REMOVE(&ccq, cc, cc_link);
      free(cc);
    }

    while((cc = TAILQ_LAST(&ccq, cdata_content_queue)) != NULL &&
          xml_is_cc_ws(cc)) {
      TAILQ_REMOVE(&ccq, cc, cc_link);
      free(cc);
    }
  }

  /* Assemble body */

  TAILQ_FOREACH(cc, &ccq, cc_link) {

    switch(cc->cc_encoding) {
    case XML_ENCODING_UTF8:
      c += cc->cc_end - cc->cc_start;
      break;

    case XML_ENCODING_8859_1:
      l = 0;
      for(x = cc->cc_start; x < cc->cc_end; x++)
	l += 1 + ((uint8_t)*x >= 0x80);

      c += l;
      break;
    }
  }

  cc = TAILQ_FIRST(&ccq);
  if(field != NULL && c > 1) {
    body = malloc(c + 1);
    c = 0;

    while((cc = TAILQ_FIRST(&ccq)) != NULL) {

      switch(cc->cc_encoding) {
      case XML_ENCODING_UTF8:
	l = cc->cc_end - cc->cc_start;
	memcpy(body + c, cc->cc_start, l);
	c += l;
	break;

      case XML_ENCODING_8859_1:
	for(x = cc->cc_start; x < cc->cc_end; x++)
	  c += utf8_put(body + c, *x);
	break;
      }

      TAILQ_REMOVE(&ccq, cc, cc_link);
      free(cc);
    }
    body[c] = 0;
    field->ntv_string = body;
    field->ntv_type = NTV_STRING;

  } else {

    while((cc = TAILQ_FIRST(&ccq)) != NULL) {
      TAILQ_REMOVE(&ccq, cc, cc_link);
      free(cc);
    }
  }
  return src;
}


/**
 *
 */
static const char *
htsmsg_parse_prolog(xmlparser_t *xp, const char *src)
{
  ntv_t *pis = ntv_create_map();
  const ntv_t *xmlpi;
  const char *encoding;

  while(1) {
    if(*src == 0)
      break;

    while(is_xmlws(*src))
      src++;

    if(!strncmp(src, "<?", 2)) {
      src += 2;
      src = htsmsg_xml_parse_pi(xp, pis, src);
      continue;
    }

    if(!strncmp(src, "<!--", 4)) {
      src = xml_parse_comment(xp, src + 4);
      continue;
    }

    if(!strncmp(src, "<!DOCTYPE", 9)) {
      int depth = 0;

      while(*src != 0) {
	if(*src == '<') {
          depth++;
        } else if(*src == '>') {
	  src++;
          depth--;
          if(depth == 0)
            break;
	}
	src++;
      }
      continue;
    }
    break;
  }

  if((xmlpi = ntv_get_map(pis, "xml")) != NULL) {

    if((encoding = ntv_get_str(xmlpi, "encoding")) != NULL) {
      if(!strcasecmp(encoding, "iso-8859-1") ||
	 !strcasecmp(encoding, "iso-8859_1") ||
	 !strcasecmp(encoding, "iso_8859-1") ||
	 !strcasecmp(encoding, "iso_8859_1")) {
	xp->xp_encoding = XML_ENCODING_8859_1;
      }
    }
  }

  ntv_release(pis);

  return src;
}


/**
 *
 */
static void
get_line_col(const char *str, int len, const char *pos, int *linep, int *colp)
{
  const char *end = str + len;
  int line = 1;
  int column = 0;

  while(str < end) {
    column++;
    if(*str == '\n') {
      column = 0;
      line++;
    } else if(*str == '\r') {
      column = 0;
    }

    if(str == pos)
      break;
    str++;
  }

  *linep = line;
  *colp  = column;
}


/**
 *
 */
ntv_t *
ntv_xml_deserialize(const char *src, char *errbuf, size_t errbufsize)
{
  ntv_t *m;
  xmlparser_t xp;
  int i;
  int line;
  int col;
  const char *start = src;
  xp.xp_errmsg[0] = 0;
  xp.xp_encoding = XML_ENCODING_UTF8;
  xp.xp_trim_whitespace = 1;
  xp.xp_parser_err_line = 0;

  LIST_INIT(&xp.xp_namespaces);

  if((src = htsmsg_parse_prolog(&xp, src)) == NULL)
    goto err;

  m = ntv_create_map();

  if(htsmsg_xml_parse_cd(&xp, m, NULL, src) == NULL) {
    ntv_release(m);
    goto err;
  }
  return m;

 err:

  get_line_col(start, strlen(start), xp.xp_errpos, &line, &col);

  snprintf(errbuf, errbufsize,
           "%s at line %d column %d (XML error %d at byte %d)",
           xp.xp_errmsg, line, col, xp.xp_parser_err_line,
           (int)((void *)xp.xp_errpos - (void *)start));

  /* Remove any odd chars inside of errmsg */
  for(i = 0; i < errbufsize; i++) {
    if(errbuf[i] < 32) {
      errbuf[i] = 0;
      break;
    }
  }
  return NULL;
}




/* table from w3 tidy entities.c */
static struct html_entity
{
  const char *name;
  int code;
} html_entities[] = {
  {"quot",    34},
  {"amp",     38},
  {"apos",    39},
  {"lt",      60},
  {"gt",      62},
  {"nbsp",   160},
  {"iexcl",  161},
  {"cent",   162},
  {"pound",  163},
  {"curren", 164},
  {"yen",    165},
  {"brvbar", 166},
  {"sect",   167},
  {"uml",    168},
  {"copy",   169},
  {"ordf",   170},
  {"laquo",  171},
  {"not",    172},
  {"shy",    173},
  {"reg",    174},
  {"macr",   175},
  {"deg",    176},
  {"plusmn", 177},
  {"sup2",   178},
  {"sup3",   179},
  {"acute",  180},
  {"micro",  181},
  {"para",   182},
  {"middot", 183},
  {"cedil",  184},
  {"sup1",   185},
  {"ordm",   186},
  {"raquo",  187},
  {"frac14", 188},
  {"frac12", 189},
  {"frac34", 190},
  {"iquest", 191},
  {"Agrave", 192},
  {"Aacute", 193},
  {"Acirc",  194},
  {"Atilde", 195},
  {"Auml",   196},
  {"Aring",  197},
  {"AElig",  198},
  {"Ccedil", 199},
  {"Egrave", 200},
  {"Eacute", 201},
  {"Ecirc",  202},
  {"Euml",   203},
  {"Igrave", 204},
  {"Iacute", 205},
  {"Icirc",  206},
  {"Iuml",   207},
  {"ETH",    208},
  {"Ntilde", 209},
  {"Ograve", 210},
  {"Oacute", 211},
  {"Ocirc",  212},
  {"Otilde", 213},
  {"Ouml",   214},
  {"times",  215},
  {"Oslash", 216},
  {"Ugrave", 217},
  {"Uacute", 218},
  {"Ucirc",  219},
  {"Uuml",   220},
  {"Yacute", 221},
  {"THORN",  222},
  {"szlig",  223},
  {"agrave", 224},
  {"aacute", 225},
  {"acirc",  226},
  {"atilde", 227},
  {"auml",   228},
  {"aring",  229},
  {"aelig",  230},
  {"ccedil", 231},
  {"egrave", 232},
  {"eacute", 233},
  {"ecirc",  234},
  {"euml",   235},
  {"igrave", 236},
  {"iacute", 237},
  {"icirc",  238},
  {"iuml",   239},
  {"eth",    240},
  {"ntilde", 241},
  {"ograve", 242},
  {"oacute", 243},
  {"ocirc",  244},
  {"otilde", 245},
  {"ouml",   246},
  {"divide", 247},
  {"oslash", 248},
  {"ugrave", 249},
  {"uacute", 250},
  {"ucirc",  251},
  {"uuml",   252},
  {"yacute", 253},
  {"thorn",  254},
  {"yuml",   255},
  {"fnof",     402},
  {"Alpha",    913},
  {"Beta",     914},
  {"Gamma",    915},
  {"Delta",    916},
  {"Epsilon",  917},
  {"Zeta",     918},
  {"Eta",      919},
  {"Theta",    920},
  {"Iota",     921},
  {"Kappa",    922},
  {"Lambda",   923},
  {"Mu",       924},
  {"Nu",       925},
  {"Xi",       926},
  {"Omicron",  927},
  {"Pi",       928},
  {"Rho",      929},
  {"Sigma",    931},
  {"Tau",      932},
  {"Upsilon",  933},
  {"Phi",      934},
  {"Chi",      935},
  {"Psi",      936},
  {"Omega",    937},
  {"alpha",    945},
  {"beta",     946},
  {"gamma",    947},
  {"delta",    948},
  {"epsilon",  949},
  {"zeta",     950},
  {"eta",      951},
  {"theta",    952},
  {"iota",     953},
  {"kappa",    954},
  {"lambda",   955},
  {"mu",       956},
  {"nu",       957},
  {"xi",       958},
  {"omicron",  959},
  {"pi",       960},
  {"rho",      961},
  {"sigmaf",   962},
  {"sigma",    963},
  {"tau",      964},
  {"upsilon",  965},
  {"phi",      966},
  {"chi",      967},
  {"psi",      968},
  {"omega",    969},
  {"thetasym", 977},
  {"upsih",    978},
  {"piv",      982},
  {"bull",     8226},
  {"hellip",   8230},
  {"prime",    8242},
  {"Prime",    8243},
  {"oline",    8254},
  {"frasl",    8260},
  {"weierp",   8472},
  {"image",    8465},
  {"real",     8476},
  {"trade",    8482},
  {"alefsym",  8501},
  {"larr",     8592},
  {"uarr",     8593},
  {"rarr",     8594},
  {"darr",     8595},
  {"harr",     8596},
  {"crarr",    8629},
  {"lArr",     8656},
  {"uArr",     8657},
  {"rArr",     8658},
  {"dArr",     8659},
  {"hArr",     8660},
  {"forall",   8704},
  {"part",     8706},
  {"exist",    8707},
  {"empty",    8709},
  {"nabla",    8711},
  {"isin",     8712},
  {"notin",    8713},
  {"ni",       8715},
  {"prod",     8719},
  {"sum",      8721},
  {"minus",    8722},
  {"lowast",   8727},
  {"radic",    8730},
  {"prop",     8733},
  {"infin",    8734},
  {"ang",      8736},
  {"and",      8743},
  {"or",       8744},
  {"cap",      8745},
  {"cup",      8746},
  {"int",      8747},
  {"there4",   8756},
  {"sim",      8764},
  {"cong",     8773},
  {"asymp",    8776},
  {"ne",       8800},
  {"equiv",    8801},
  {"le",       8804},
  {"ge",       8805},
  {"sub",      8834},
  {"sup",      8835},
  {"nsub",     8836},
  {"sube",     8838},
  {"supe",     8839},
  {"oplus",    8853},
  {"otimes",   8855},
  {"perp",     8869},
  {"sdot",     8901},
  {"lceil",    8968},
  {"rceil",    8969},
  {"lfloor",   8970},
  {"rfloor",   8971},
  {"lang",     9001},
  {"rang",     9002},
  {"loz",      9674},
  {"spades",   9824},
  {"clubs",    9827},
  {"hearts",   9829},
  {"diams",    9830},
  {"OElig",   338},
  {"oelig",   339},
  {"Scaron",  352},
  {"scaron",  353},
  {"Yuml",    376},
  {"circ",    710},
  {"tilde",   732},
  {"ensp",    8194},
  {"emsp",    8195},
  {"thinsp",  8201},
  {"zwnj",    8204},
  {"zwj",     8205},
  {"lrm",     8206},
  {"rlm",     8207},
  {"ndash",   8211},
  {"mdash",   8212},
  {"lsquo",   8216},
  {"rsquo",   8217},
  {"sbquo",   8218},
  {"ldquo",   8220},
  {"rdquo",   8221},
  {"bdquo",   8222},
  {"dagger",  8224},
  {"Dagger",  8225},
  {"permil",  8240},
  {"lsaquo",  8249},
  {"rsaquo",  8250},
  {"euro",    8364},
  {NULL, 0}
};

static int
html_entity_lookup(const char *name)
{
  struct html_entity *e;

  if(*name == '#') {
    if(name[1] == 'x')
      return strtol(name + 2, NULL, 16);
    return strtol(name + 1, NULL, 10);
  }

  for(e = &html_entities[0]; e->name != NULL; e++)
    if(strcmp(e->name, name) == 0)
      return e->code;

  return -1;
}
