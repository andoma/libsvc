#include "libsvc.h"
#include "tcp.h"

#ifdef WITH_MYSQL
#include "db.h"
#endif

#ifdef WITH_ASYNCIO
#include "asyncio.h"
#endif


void
libsvc_init(void)
{
#ifdef WITH_MYSQL
  db_init();
#endif

#ifdef WITH_ASYNCIO
  asyncio_init();
#endif

  tcp_init();
#ifdef WITH_TCP_SERVER
  tcp_server_init();
#endif
}
