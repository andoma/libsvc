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
#include <errno.h>
#include <string.h>
#include "libsvc.h"
#include "tcp.h"
#include "misc.h"
#include "init.h"
#include "queue.h"
#include "trace.h"

#include <sys/resource.h>

#include <openssl/rand.h>

#ifdef WITH_MYSQL
#include "db.h"
#endif

#ifdef WITH_ASYNCIO
#include "asyncio.h"
#endif

#ifdef WITH_CURL
#include <curl/curl.h>
#endif


static LIST_HEAD(, inithelper) inithelpers;

typedef struct inithelper {
  void (*init)(void);
  void (*fini)(void);
  int prio;
  LIST_ENTRY(inithelper) link;
} inithelper_t;

/**
 *
 */
static int
ihcmp(const inithelper_t *a, const inithelper_t *b)
{
  return a->prio - b->prio;
}


void
inithelper_register(void (*init)(void), void (*fini)(void), int prio)
{
  inithelper_t *ih = malloc(sizeof(inithelper_t));
  ih->init = init;
  ih->fini = fini;
  ih->prio = prio;
  LIST_INSERT_SORTED(&inithelpers, ih, link, ihcmp);
}



void
libsvc_init(void)
{
  uint8_t randomness[32];
  get_random_bytes(randomness, sizeof(randomness));
  RAND_seed(randomness, sizeof(randomness));

#ifdef WITH_MYSQL
  db_init();
#endif

#ifdef WITH_ASYNCIO
  asyncio_init();
#endif

#ifdef WITH_CURL
  curl_global_init(CURL_GLOBAL_ALL);
#endif

#ifdef WITH_TCP_SERVER
  tcp_server_init();
#endif

  const inithelper_t *ih;
  LIST_FOREACH(ih, &inithelpers, link) {
    ih->init();
  }
}


void
libsvc_fini(void)
{
  inithelper_t *ih;

  LIST_HEAD(, inithelper) rev;
  LIST_INIT(&rev);
  while((ih = LIST_FIRST(&inithelpers)) != NULL) {
    LIST_REMOVE(ih, link);
    LIST_INSERT_HEAD(&rev, ih, link);
  }

  while((ih = LIST_FIRST(&rev)) != NULL) {
    LIST_REMOVE(ih, link);
    if(ih->fini != NULL)
      ih->fini();
    free(ih);
  }
}


void
libsvc_set_fdlimit(int num_fd)
{
  struct rlimit lim;


  if(getrlimit(RLIMIT_NOFILE, &lim) == -1) {
    trace(LOG_ERR, "Unable to get fdlimit  -- %s",
          strerror(errno));
  }

  lim.rlim_cur = num_fd < lim.rlim_max ? num_fd : lim.rlim_max;

  if(setrlimit(RLIMIT_NOFILE, &lim) == -1) {
    trace(LOG_ERR, "Unable to set fdlimit to %d -- %s",
          num_fd, strerror(errno));
    trace(LOG_INFO, "Current fdlimit %ld (max: %ld)",
          (long)lim.rlim_cur, (long)lim.rlim_max);
    exit(1);
  }

  trace(LOG_INFO, "Current fdlimit %ld (max: %ld)",
        (long)lim.rlim_cur, (long)lim.rlim_max);

}
