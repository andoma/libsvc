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

#ifndef STRTAB_H_
#define STRTAB_H_

#include <strings.h>

struct strtab {
  const char *str;
  int val;
};

static int str2val0(const char *str, const struct strtab tab[], int l)
     __attribute((unused));

static int
str2val0(const char *str, const struct strtab tab[], int l)
{
  int i;
  for(i = 0; i < l; i++)
    if(!strcasecmp(str, tab[i].str))
      return tab[i].val;

  return -1;
}

#define str2val(str, tab) str2val0(str, tab, sizeof(tab) / sizeof(tab[0]))



static int str2val0_def(const char *str, const struct strtab tab[], int l, int def)
     __attribute((unused));

static int
str2val0_def(const char *str, const struct strtab tab[], int l, int def)
{
  int i;
  if(str) 
    for(i = 0; i < l; i++)
      if(!strcasecmp(str, tab[i].str))
	return tab[i].val;
  return def;
}

#define str2val_def(str, tab, def) \
 str2val0_def(str, tab, sizeof(tab) / sizeof(tab[0]), def)


static const char * val2str0(int val, const struct strtab tab[], int l)
     __attribute__((unused));

static const char *
val2str0(int val, const struct strtab tab[], int l)
{
  int i;
  for(i = 0; i < l; i++)
    if(tab[i].val == val)
      return tab[i].str;
  return NULL;
} 

#define val2str(val, tab) val2str0(val, tab, sizeof(tab) / sizeof(tab[0]))

#endif /* STRTAB_H_ */
