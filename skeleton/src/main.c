#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "libsvc/libsvc.h"
#include "libsvc/cfg.h"
#include "libsvc/trace.h"

#ifdef WITH_HTTP_SERVER
#include "libsvc/http.h"
#endif

#ifdef WITH_CTRLSOCK
#include "libsvc/ctrlsock.h"
#endif


static int running = 1;
static int reload = 0;

/**
 *
 */
static void
handle_sigpipe(int x)
{
  return;
}


/**
 *
 */
static void
doexit(int x)
{
  running = 0;
}


/**
 *
 */
static void
doreload(int x)
{
  reload = 1;
}


#ifdef WITH_HTTP_SERVER
/**
 *
 */
static void
http_init(void)
{
  http_server_init(NULL);
}
#endif


/**
 *
 */
int
main(int argc, char **argv)
{
  char errbuf[512];
  int c;
  sigset_t set;
#ifdef WITH_CTRLSOCK
  const char *ctrlsockpath = "/tmp/"PROGNAME"ctrl";
#endif
  const char *cfgfile = PROGNAME".json";

  signal(SIGPIPE, handle_sigpipe);

  while((c = getopt(argc, argv, "c:s:")) != -1) {
    switch(c) {
    case 'c':
      cfgfile = optarg;
      break;
    case 's':
      enable_syslog(PROGNAME, optarg);
      break;
    }
  }

  sigfillset(&set);
  sigprocmask(SIG_BLOCK, &set, NULL);

  srand48(getpid() ^ time(NULL));

  if(cfg_load(cfgfile, errbuf, sizeof(errbuf))) {
    fprintf(stderr, "Unable to load config -- %s "
            "(check -c option). Giving up\n", errbuf);
    exit(1);
  }

  libsvc_init();

#ifdef WITH_CTRLSOCK
  ctrlsock_init(ctrlsockpath);
#endif

#ifdef WITH_HTTP_SERVER
  http_init();
#endif

  running = 1;
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGHUP);

  signal(SIGTERM, doexit);
  signal(SIGINT, doexit);
  signal(SIGHUP, doreload);

  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  while(running) {
    if(reload) {
      reload = 0;
      cfg_load(NULL, NULL, 0);
    }
    pause();
  }

  return 0;
}
