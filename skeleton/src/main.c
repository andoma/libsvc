#include <sys/stat.h>
#include <sys/wait.h>
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
int
main(int argc, char **argv)
{
  char errbuf[512];
  int c;
  sigset_t set;
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
  sigdelset(&set, SIGQUIT);
  sigdelset(&set, SIGILL);
  sigdelset(&set, SIGTRAP);
  sigdelset(&set, SIGABRT);
  sigdelset(&set, SIGFPE);
  sigdelset(&set, SIGBUS);
  sigdelset(&set, SIGSEGV);
  sigdelset(&set, SIGSYS);
  sigprocmask(SIG_BLOCK, &set, NULL);

  srand48(getpid() ^ time(NULL));

  if(cfg_load(cfgfile, errbuf, sizeof(errbuf))) {
    fprintf(stderr, "Unable to load config -- %s "
            "(check -c option). Giving up\n", errbuf);
    exit(1);
  }

  libsvc_init();


  trace(LOG_WARNING, "Running pid %d", getpid());
  while(1) {
    int delivered = 0;
    if(!sigwait(&set, &delivered)) {
      trace(LOG_DEBUG, "Main loop got signal %d", delivered);
      if(delivered == SIGTERM || delivered == SIGINT)
        break;

      if(delivered == SIGCHLD) {
        while(waitpid(-1, NULL, WNOHANG) > 0);
      }

      if(delivered == SIGHUP) {
	cfg_load(NULL, NULL, 0);
      }
    }
  }

  trace(LOG_WARNING, "Stopping");

  return 0;
}
