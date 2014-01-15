#include "libsvc.h"
#include "tcp.h"

#ifdef WITH_MYSQL
#include "db.h"
#endif


void
libsvc_init(void)
{
#ifdef WITH_MYSQL
  mysql_library_init(0, NULL, NULL);
  db_init();
#endif

  tcp_init();
#ifdef WITH_TCP_SERVER
  tcp_server_init();
#endif
}
