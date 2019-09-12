#pragma once

#include <stdio.h>

typedef struct fpipe fpipe_t;

fpipe_t *fpipe(FILE **reader, FILE **writer);

void fpipe_set_error(fpipe_t *fp);
