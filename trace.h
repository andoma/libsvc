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
