#pragma once

int utf8_put(char *out, int c);

int utf8_get(const char **s);

char *utf8_cleanup(const char *str);

void utf8_cleanup_inplace(char *str, size_t len);
