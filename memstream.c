#include <stdio.h>
#include "memstream.h"

#ifdef linux

FILE *
open_buffer(char **out, size_t *outlen)
{
  return open_memstream(out, outlen);
}

#else

FILE *
open_buffer(char **out, size_t *outlen)
{

}

#endif
