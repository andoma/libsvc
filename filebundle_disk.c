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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include "filebundle.h"
#include "misc.h"


int
filebundle_load(const char *p, void **ptr, int *len)
{
  int fd = open(p, O_RDONLY);
  if(fd == -1)
    return errno;

  struct stat st;
  if(fstat(fd, &st)) {
    int err = errno;
    close(fd);
    return err;
  }

  if(ptr == NULL)
    return 0;

  void *mem = malloc(st.st_size);
  if(read(fd, mem, st.st_size) != st.st_size) {
    int err = errno;
    close(fd);
    free(mem);
    return err;
  }
  close(fd);

  *ptr = mem;
  if(len)
    *len = st.st_size;
  return 0;
}


void
filebundle_free(void *ptr)
{
  free(ptr);
}
