#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include "filebundle.h"
#include "misc.h"

struct filebundle *filebundles;


int
filebundle_load(const char *p, void **ptr, int *len)
{
  const struct filebundle_entry *fe;
  const struct filebundle *fb;
  char *path = mystrdupa(p);

  char *x = strrchr(path, '/');
  if(x == NULL)
    return ENOTDIR;

  *x++ = 0;
  for(fb = filebundles; fb != NULL; fb = fb->next) {
    if(!strcmp(path, fb->prefix))
      break;
  }
  if(fb == NULL)
    return ENODEV;

  for(fe = fb->entries; fe->filename != NULL; fe++) {
    if(!strcmp(fe->filename, x))
      break;
  }

  if(fe->filename == NULL)
    return ENOENT;

  if(ptr)
    *ptr = (void *)fe->data;
  if(len)
    *len = fe->size;
  return 0;
}


void
filebundle_free(void *ptr)
{
  // NOP for embedded stuff
}
