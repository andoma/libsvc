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

#include <stdarg.h>
#include <syslog.h>

#define COLOR_OFF    "\017"
#define COLOR_BLUE   "\00302"
#define COLOR_GREEN  "\00303"
#define COLOR_RED    "\00304"
#define COLOR_BROWN  "\00305"
#define COLOR_PURPLE "\00306"
#define COLOR_ORANGE "\00307"
#define COLOR_YELLOW "\00308"

void decolorize(char *str);
void trace(int level, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void tracev(int level, const char *fmt, va_list ap);


void enable_syslog(const char *program, const char *facility);

void hexdump(const char *pfx, const void *data_, int len);

void trace_enable_stdout(void);
