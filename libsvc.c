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
#include <stdlib.h>
#include <sys/resource.h>

#include "libsvc.h"
#include "tcp.h"
#include "misc.h"
#include "init.h"
#include "trace.h"
#include "vec.h"

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#endif

#ifdef WITH_MYSQL
#include "db.h"
#endif

#ifdef WITH_ASYNCIO
#include "asyncio.h"
#endif

#ifdef WITH_CURL
#include <curl/curl.h>
#endif


typedef struct {
  void (*init)(void);
  void (*term)(void);
  void (*fini)(void);
  int prio;
} inithelper_t;

static VEC_HEAD(, inithelper_t) inithelpers;

/**
 *
 */
static int
ihcmp(const inithelper_t *a, const inithelper_t *b)
{
  return a->prio - b->prio;
}


void
inithelper_register(void (*init)(void), void (*term)(void),
                    void (*fini)(void), int prio)
{
  VEC_PUSH_BACK(&inithelpers, ((const inithelper_t) {
        .init = init, .term = term, .fini = fini, .prio = prio}));
}


char *libsvc_app_version;
char *libsvc_app_version_only;


void
libsvc_set_app_version(const char *version)
{
  libsvc_app_version = fmt("%s-%s", PROGNAME, version);
  libsvc_app_version_only = strdup(version);
}




void
libsvc_init(void)
{
#ifdef WITH_OPENSSL
  uint8_t randomness[32];
  get_random_bytes(randomness, sizeof(randomness));
  RAND_seed(randomness, sizeof(randomness));
#endif

#ifdef WITH_MYSQL
  db_init();
#endif

#ifdef WITH_ASYNCIO
  asyncio_init();
#endif

  tcp_init();

#ifdef WITH_CURL
  curl_global_init(CURL_GLOBAL_ALL);
#endif

#ifdef WITH_TCP_SERVER
  tcp_server_init();
#endif

  VEC_SORT(&inithelpers, ihcmp);
  for(ssize_t i = 0; i < VEC_LEN(&inithelpers); i++) {
    if(VEC_ITEM(&inithelpers, i).init)
      VEC_ITEM(&inithelpers, i).init();
  }
}


void
libsvc_fini(void)
{
  for(ssize_t i = VEC_LEN(&inithelpers) - 1; i >= 0; i--) {
    if(VEC_ITEM(&inithelpers, i).fini)
      VEC_ITEM(&inithelpers, i).fini();
  }
}

void
libsvc_term(void)
{
  for(ssize_t i = VEC_LEN(&inithelpers) - 1; i >= 0; i--) {
    if(VEC_ITEM(&inithelpers, i).term)
      VEC_ITEM(&inithelpers, i).term();
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
