/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
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
#include "htsmsg.h"

typedef htsmsg_t cfg_t;

int cfg_load(const char *filename, char *errbuf, size_t errlen);

cfg_t *cfg_get_root(void);

void cfg_releasep(cfg_t **p);

#define cfg_root(x) cfg_t *x __attribute__((cleanup(cfg_releasep))) = cfg_get_root();

#define CFG(name...) (const char *[]){name, NULL}
#define CFGI(x) (const char *[]){HTSMSG_INDEX(x), NULL}
#define CFG_INDEX(x) HTSMSG_INDEX(x)

const char *cfg_get_str(cfg_t *c, const char **vec, const char *def);

int64_t cfg_get_s64(cfg_t *c, const char **path, int64_t def);

int cfg_get_int(cfg_t *c, const char **path, int def);

cfg_t *cfg_get_map(cfg_t *c, const char *id);

cfg_t *cfg_get_list(cfg_t *c, const char *id);

cfg_t *cfg_find_map(cfg_t *c, const char *key, const char *value);

int cfg_list_length(cfg_t *c);

void cfg_add_reload_cb(void (*fn)(void));
