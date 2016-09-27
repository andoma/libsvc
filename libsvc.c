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

#include "libsvc.h"
#include "tcp.h"
#include "misc.h"

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

  tcp_init();  // Also does OpenSSL init

#ifdef WITH_CURL
  curl_global_init(0);
#endif

#ifdef WITH_TCP_SERVER
  tcp_server_init();
#endif
}
