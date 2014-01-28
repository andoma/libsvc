#pragma once

void *talloc_malloc(size_t s);

void *talloc_zalloc(size_t s);

void talloc_cleanup(void);

char *tstrdup(const char *str);

char *tsprintf(const char *fmt, ...);
