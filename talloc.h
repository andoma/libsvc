#pragma once

void *talloc_malloc(size_t s);

void *talloc_zalloc(size_t s);

void talloc_cleanup(void);
