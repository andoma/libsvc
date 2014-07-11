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
